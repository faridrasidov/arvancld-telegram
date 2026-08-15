"""AsyncTeleBot handlers for guided ArvanCloud DNS administration."""

from __future__ import annotations

import copy
import html
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from arvancld import APIError, ArvanCloudError, DNSRecord, NetworkError
from telebot import types
from telebot.async_telebot import AsyncTeleBot

from arvancld_telegram.config import Settings
from arvancld_telegram.dns import (
    DEFAULT_TTL,
    RECORD_TYPES,
    DNSInputError,
    changed_fields,
    create_record,
    format_record_value,
    merge_record_value,
    parse_record_value,
    update_record,
    validate_record_name,
    validate_ttl,
    value_prompt,
)
from arvancld_telegram.gateway import (
    ArvanCloudGateway,
    AuthenticationBusyError,
    AuthenticationState,
    InteractiveAuthenticationRequired,
    OTPFlowExpiredError,
    OTPRejectedError,
    OTPSubmissionUncertainError,
    ProtectedRecordError,
    StaleRecordError,
)
from arvancld_telegram.state import (
    Confirmation,
    ConversationStore,
    Draft,
    UserState,
    callback_data,
    parse_callback,
)

logger = logging.getLogger(__name__)
PAGE_SIZE = 8


class BotController:
    """Coordinate Telegram navigation state and the ArvanCloud gateway."""

    def __init__(
        self,
        bot: AsyncTeleBot,
        settings: Settings,
        gateway: ArvanCloudGateway,
        store: ConversationStore | None = None,
    ) -> None:
        self.bot = bot
        self.settings = settings
        self.gateway = gateway
        self.store = store or ConversationStore()
        self._last_notified_challenge_revision = 0

    def register_handlers(self) -> None:
        self.bot.register_message_handler(self.handle_start, commands=["start", "domains"])
        self.bot.register_message_handler(self.handle_auth, commands=["auth"])
        self.bot.register_message_handler(self.handle_status, commands=["status"])
        self.bot.register_message_handler(self.handle_help, commands=["help"])
        self.bot.register_message_handler(self.handle_cancel, commands=["cancel"])
        self.bot.register_callback_query_handler(self.handle_callback, func=lambda call: True)
        self.bot.register_message_handler(
            self.handle_text,
            content_types=["text"],
            func=lambda message: True,
        )

    async def _authorized_message(
        self,
        message: Any,
        handler: Callable[[Any, UserState], Awaitable[None]],
    ) -> None:
        user_id = getattr(getattr(message, "from_user", None), "id", None)
        chat = getattr(message, "chat", None)
        chat_id = getattr(chat, "id", None)
        if not self.settings.is_authorized(user_id, getattr(chat, "type", None)):
            if chat_id is not None:
                await self.bot.send_message(
                    chat_id, "Not authorized. Use this bot in a private chat."
                )
            return

        assert user_id is not None
        async with self.store.lock(user_id):
            state = self.store.get(user_id)
            try:
                await handler(message, state)
            except InteractiveAuthenticationRequired:
                await self._request_authentication(chat_id, user_id, self.store.get(user_id))
            except Exception as exc:  # handlers must never terminate polling
                await self._report_error(chat_id, exc)

    async def notify_auth_required(self, *, exclude_chat_id: int | None = None) -> None:
        """Best-effort notify every configured administrator once per challenge."""

        revision = self.gateway.challenge_revision
        if not self.gateway.otp_required or revision <= self._last_notified_challenge_revision:
            return
        self._last_notified_challenge_revision = revision
        for admin_id in sorted(self.settings.telegram_admin_ids):
            if admin_id == exclude_chat_id:
                continue
            try:
                await self.bot.send_message(
                    admin_id,
                    "<b>ArvanCloud OTP required</b>\n"
                    "Run /auth in this private chat to complete account login.",
                )
            except Exception:
                logger.warning(
                    "auth event=telegram_otp_notification_failed attempt_id=%s "
                    "challenge_revision=%s actor_id=%s",
                    self.gateway.auth_attempt_id or "unavailable",
                    self.gateway.challenge_revision,
                    admin_id,
                )

    async def _request_authentication(
        self,
        chat_id: int,
        actor_id: int,
        state: UserState,
    ) -> bool:
        """Claim the current OTP challenge or perform non-TOTP login."""

        try:
            result = await self.gateway.begin_authentication(actor_id)
        except AuthenticationBusyError:
            await self.bot.send_message(
                chat_id, "Another administrator is completing ArvanCloud authentication."
            )
            return False

        if result is AuthenticationState.CONNECTED:
            state.clear_transient()
            await self.bot.send_message(chat_id, "ArvanCloud authentication is complete.")
            return True

        state.clear_transient()
        state.flow = "auth_totp"
        await self.notify_auth_required(exclude_chat_id=chat_id)
        await self.bot.send_message(
            chat_id,
            "<b>ArvanCloud OTP required</b>\n"
            "Send the current six-digit authenticator code. "
            "The bot will delete your message immediately.",
        )
        return False

    async def _report_error(self, chat_id: int | None, exc: Exception) -> None:
        if chat_id is None:
            return
        if isinstance(exc, DNSInputError):
            await self.bot.send_message(chat_id, f"Invalid input: {html.escape(str(exc))}")
            return
        if isinstance(exc, (StaleRecordError, ProtectedRecordError)):
            await self.bot.send_message(chat_id, html.escape(str(exc)))
            return
        if isinstance(exc, APIError):
            request = f", request ID {html.escape(exc.request_id)}" if exc.request_id else ""
            await self.bot.send_message(
                chat_id,
                f"ArvanCloud request failed (status {exc.status_code}{request}).",
            )
            return
        if isinstance(exc, ArvanCloudError):
            await self.bot.send_message(
                chat_id, "Could not reach ArvanCloud safely. Try again later."
            )
            return
        logger.exception("unexpected bot handler error")
        await self.bot.send_message(chat_id, "Unexpected error. No DNS change was retried.")

    async def handle_start(self, message: Any) -> None:
        async def start(inner: Any, _state: UserState) -> None:
            user_id = inner.from_user.id
            state = self.store.reset(user_id)
            if not self.gateway.connected and not await self._request_authentication(
                inner.chat.id, user_id, state
            ):
                return
            await self._show_domains(inner.chat.id, state, page=1)

        await self._authorized_message(message, start)

    async def handle_auth(self, message: Any) -> None:
        async def authenticate(inner: Any, state: UserState) -> None:
            if self.gateway.connected:
                state.touch()
                await self.bot.send_message(inner.chat.id, "ArvanCloud is already connected.")
                return
            await self._request_authentication(inner.chat.id, inner.from_user.id, state)

        await self._authorized_message(message, authenticate)

    async def handle_status(self, message: Any) -> None:
        async def status(inner: Any, state: UserState) -> None:
            state.touch()
            if not self.gateway.connected:
                await self.bot.send_message(
                    inner.chat.id,
                    "<b>Status</b>\n"
                    "Telegram: connected\n"
                    f"ArvanCloud: {html.escape(self.gateway.auth_status)}\n"
                    "Run /auth to complete account login.",
                )
                return

            page = await self.gateway.list_domains(page=1, per_page=1)
            await self.bot.send_message(
                inner.chat.id,
                "<b>Status</b>\n"
                "Telegram: connected\nArvanCloud: connected\n"
                f"Domains: {page.meta.total}",
            )

        await self._authorized_message(message, status)

    async def handle_help(self, message: Any) -> None:
        async def help_message(inner: Any, state: UserState) -> None:
            state.touch()
            await self.bot.send_message(
                inner.chat.id,
                "<b>ArvanCloud DNS Admin</b>\n"
                "/domains — browse domains and DNS records\n"
                "/auth — complete or restart ArvanCloud login\n"
                "/status — verify account connectivity\n"
                "/cancel — cancel the current input or confirmation\n\n"
                "Supported records: " + ", ".join(RECORD_TYPES) + "\n"
                "Every DNS mutation requires an explicit confirmation.",
            )

        await self._authorized_message(message, help_message)

    async def handle_cancel(self, message: Any) -> None:
        async def cancel(inner: Any, state: UserState) -> None:
            cancelling_auth = state.flow == "auth_totp"
            state.clear_transient()
            if cancelling_auth:
                await self.gateway.cancel_authentication(inner.from_user.id)
                await self.bot.send_message(
                    inner.chat.id, "Authentication cancelled. Run /auth to start a fresh login."
                )
                return
            await self.bot.send_message(inner.chat.id, "Cancelled.")
            if not self.gateway.connected:
                await self.bot.send_message(
                    inner.chat.id, "ArvanCloud is not connected. Run /auth to continue."
                )
                return
            if state.selected_record is not None:
                await self._show_record_detail(inner.chat.id, state, state.selected_record)
            elif state.selected_domain is not None:
                await self._show_records(inner.chat.id, state, page=state.record_page)
            else:
                await self._show_domains(inner.chat.id, state, page=state.domain_page)

        await self._authorized_message(message, cancel)

    async def handle_text(self, message: Any) -> None:
        await self._authorized_message(message, self._handle_text)

    async def _handle_text(self, message: Any, state: UserState) -> None:
        if state.flow == "auth_totp":
            await self._handle_totp(message, state)
            return

        text = (message.text or "").strip()
        if not state.flow:
            await self.bot.send_message(message.chat.id, "Use /domains to open the DNS menu.")
            return

        if state.flow == "search":
            state.search = validate_record_name(text)
            state.flow = None
            await self._show_records(message.chat.id, state, page=1)
            return

        draft = state.draft
        if draft is None:
            state.clear_transient()
            await self.bot.send_message(message.chat.id, "That input expired. Use /domains again.")
            return

        if state.flow == "create_name":
            draft.name = validate_record_name(text)
            state.flow = "create_value"
            await self._prompt(
                message.chat.id,
                state,
                f"<b>{draft.record_type} value</b>\n{value_prompt(draft.record_type or '')}",
            )
            return

        if state.flow in {"create_value", "edit_value", "edit_type_value"}:
            assert draft.record_type is not None
            parsed = parse_record_value(draft.record_type, message.text or "")
            base = draft.base_record
            draft.value = merge_record_value(
                draft.record_type,
                parsed,
                existing_type=base.type if base else None,
                existing_value=base.value if base else None,
            )
            if state.flow == "create_value":
                state.flow = "create_ttl"
                await self._prompt(
                    message.chat.id,
                    state,
                    f"Send a positive TTL, or <code>default</code> for {DEFAULT_TTL}.",
                )
            else:
                await self._prepare_update_confirmation(message.chat.id, state)
            return

        if state.flow == "create_ttl":
            draft.ttl = DEFAULT_TTL if text.lower() == "default" else validate_ttl(text)
            state.flow = None
            await self._show_cloud_choice(message.chat.id, state)
            return

        if state.flow == "edit_name":
            draft.name = validate_record_name(text)
            await self._prepare_update_confirmation(message.chat.id, state)
            return
        if state.flow == "edit_ttl":
            draft.ttl = validate_ttl(text)
            await self._prepare_update_confirmation(message.chat.id, state)
            return

        state.clear_transient()
        await self.bot.send_message(message.chat.id, "That input is no longer expected.")

    async def _handle_totp(self, message: Any, state: UserState) -> None:
        """Delete and submit one user-supplied OTP without retaining its value."""

        attempt_id = self.gateway.auth_attempt_id or "unavailable"
        revision = self.gateway.challenge_revision
        actor_id = message.from_user.id
        message_id = getattr(message, "message_id", None)
        logger.info(
            "auth event=telegram_otp_received attempt_id=%s challenge_revision=%s "
            "actor_id=%s message_id=%s",
            attempt_id,
            revision,
            actor_id,
            message_id,
        )
        try:
            await self.bot.delete_message(message.chat.id, message.message_id)
        except Exception:
            logger.warning(
                "auth event=telegram_otp_delete_failed attempt_id=%s "
                "challenge_revision=%s actor_id=%s message_id=%s",
                attempt_id,
                revision,
                actor_id,
                message_id,
            )
        else:
            logger.info(
                "auth event=telegram_otp_deleted attempt_id=%s challenge_revision=%s "
                "actor_id=%s message_id=%s",
                attempt_id,
                revision,
                actor_id,
                message_id,
            )

        code = (message.text or "").strip()
        if len(code) != 6 or not code.isascii() or not code.isdigit():
            logger.warning(
                "auth event=telegram_otp_format_rejected attempt_id=%s "
                "challenge_revision=%s actor_id=%s",
                attempt_id,
                revision,
                actor_id,
            )
            await self.bot.send_message(
                message.chat.id, "Invalid OTP format. Send exactly six ASCII digits."
            )
            return

        logger.info(
            "auth event=telegram_otp_format_accepted attempt_id=%s "
            "challenge_revision=%s actor_id=%s",
            attempt_id,
            revision,
            actor_id,
        )
        try:
            await self.gateway.submit_totp(actor_id, code)
        except ValueError:
            await self.bot.send_message(
                message.chat.id, "Invalid OTP format. Send exactly six ASCII digits."
            )
            return
        except OTPRejectedError:
            await self.bot.send_message(
                message.chat.id,
                "That OTP was rejected or expired. Send a new current six-digit code.",
            )
            return
        except (OTPFlowExpiredError, OTPSubmissionUncertainError):
            state.clear_transient()
            await self.bot.send_message(
                message.chat.id,
                "The OTP flow cannot be reused safely. Run /auth to start a fresh login.",
            )
            return

        state.clear_transient()
        await self.bot.send_message(
            message.chat.id,
            "ArvanCloud authentication succeeded. "
            "Use /domains or repeat the interrupted operation.",
        )

    async def handle_callback(self, call: Any) -> None:
        try:
            await self.bot.answer_callback_query(call.id)
        except Exception:
            logger.debug("could not answer callback query", exc_info=True)

        message = getattr(call, "message", None)
        user_id = getattr(getattr(call, "from_user", None), "id", None)
        chat = getattr(message, "chat", None)
        chat_id = getattr(chat, "id", None)
        if not self.settings.is_authorized(user_id, getattr(chat, "type", None)):
            if chat_id is not None:
                await self.bot.send_message(
                    chat_id, "Not authorized. Use this bot in a private chat."
                )
            return
        if message is None or user_id is None or chat_id is None:
            return

        async with self.store.lock(user_id):
            state = self.store.get(user_id)
            try:
                action, revision, argument = parse_callback(call.data)
                if revision != state.revision:
                    await self.bot.send_message(chat_id, "That menu expired. Open /domains again.")
                    return
                await self._dispatch_callback(call, state, action, argument)
            except InteractiveAuthenticationRequired:
                await self._request_authentication(chat_id, user_id, state)
            except Exception as exc:  # handlers must never terminate polling
                await self._report_error(chat_id, exc)

    async def _dispatch_callback(
        self,
        call: Any,
        state: UserState,
        action: str,
        argument: str | None,
    ) -> None:
        chat_id = call.message.chat.id
        message_id = call.message.message_id

        if action == "dp":
            await self._show_domains(
                chat_id, state, page=self._integer_argument(argument), message_id=message_id
            )
        elif action == "ds":
            index = self._integer_argument(argument)
            if index < 0 or index >= len(state.domains):
                raise ValueError("Stale domain selection")
            state.selected_domain = state.domains[index].domain
            state.search = None
            state.record_type_filter = None
            await self._show_records(chat_id, state, page=1, message_id=message_id)
        elif action == "rp":
            await self._show_records(
                chat_id, state, page=self._integer_argument(argument), message_id=message_id
            )
        elif action == "rs":
            index = self._integer_argument(argument)
            if index < 0 or index >= len(state.records):
                raise ValueError("Stale record selection")
            state.selected_record = state.records[index]
            await self._show_record_detail(
                chat_id, state, state.records[index], message_id=message_id
            )
        elif action == "rr":
            await self._show_records(chat_id, state, page=state.record_page, message_id=message_id)
        elif action == "bd":
            state.selected_domain = None
            state.selected_record = None
            await self._show_domains(chat_id, state, page=state.domain_page, message_id=message_id)
        elif action == "br":
            state.selected_record = None
            await self._show_records(chat_id, state, page=state.record_page, message_id=message_id)
        elif action == "se":
            state.flow = "search"
            state.draft = None
            state.confirmation = None
            await self._prompt(
                chat_id, state, "Send the exact zone-relative record name.", message_id
            )
        elif action == "sx":
            state.search = None
            await self._show_records(chat_id, state, page=1, message_id=message_id)
        elif action == "fm":
            await self._show_filter_menu(chat_id, state, message_id)
        elif action == "fv":
            index = self._integer_argument(argument)
            state.record_type_filter = None if index < 0 else RECORD_TYPES[index]
            await self._show_records(chat_id, state, page=1, message_id=message_id)
        elif action == "cr":
            state.draft = Draft(mode="create")
            state.flow = None
            await self._show_type_menu(chat_id, state, message_id)
        elif action == "ct":
            await self._select_create_type(
                chat_id, state, self._integer_argument(argument), message_id
            )
        elif action == "cc":
            await self._select_create_cloud(
                chat_id, state, self._integer_argument(argument), message_id
            )
        elif action in {"en", "ev", "el", "et"}:
            await self._begin_edit(chat_id, state, action, message_id)
        elif action == "ut":
            await self._select_update_type(
                chat_id, state, self._integer_argument(argument), message_id
            )
        elif action == "cl":
            await self._prepare_cloud_confirmation(chat_id, state, message_id)
        elif action == "de":
            await self._prepare_delete_confirmation(chat_id, state, message_id)
        elif action == "ok":
            await self._execute_confirmation(call, state, argument)
        elif action == "no":
            state.clear_transient()
            if state.selected_record is not None:
                await self._show_record_detail(
                    chat_id, state, state.selected_record, message_id=message_id
                )
            else:
                await self._show_records(
                    chat_id, state, page=state.record_page, message_id=message_id
                )
        else:
            raise ValueError("Unknown callback action")

    @staticmethod
    def _integer_argument(argument: str | None) -> int:
        try:
            return int(argument or "")
        except ValueError:
            raise ValueError("Invalid callback argument") from None

    async def _display(
        self,
        chat_id: int,
        text: str,
        markup: types.InlineKeyboardMarkup | None = None,
        message_id: int | None = None,
    ) -> None:
        if message_id is not None:
            try:
                await self.bot.edit_message_text(
                    text,
                    chat_id,
                    message_id,
                    reply_markup=markup,
                    parse_mode="HTML",
                )
                return
            except Exception:
                logger.debug("menu edit failed; sending a new message", exc_info=True)
        await self.bot.send_message(chat_id, text, reply_markup=markup, parse_mode="HTML")

    @staticmethod
    def _markup(rows: list[list[types.InlineKeyboardButton]]) -> types.InlineKeyboardMarkup:
        markup = types.InlineKeyboardMarkup()
        for row in rows:
            markup.row(*row)
        return markup

    @staticmethod
    def _button(
        label: str, action: str, state: UserState, argument: str | int | None = None
    ) -> types.InlineKeyboardButton:
        return types.InlineKeyboardButton(
            label,
            callback_data=callback_data(action, state.revision, argument),
        )

    async def _show_domains(
        self,
        chat_id: int,
        state: UserState,
        *,
        page: int,
        message_id: int | None = None,
    ) -> None:
        result = await self.gateway.list_domains(page=max(page, 1), per_page=PAGE_SIZE)
        state.domain_page = result.meta.current_page
        state.domain_last_page = max(result.meta.last_page, 1)
        state.domains = result.data
        state.selected_domain = None
        state.selected_record = None
        state.clear_transient()
        state.rotate_revision()
        rows = [
            [self._button(domain.domain[:60], "ds", state, index)]
            for index, domain in enumerate(result.data)
        ]
        navigation: list[types.InlineKeyboardButton] = []
        if state.domain_page > 1:
            navigation.append(self._button("< Previous", "dp", state, state.domain_page - 1))
        if state.domain_page < state.domain_last_page:
            navigation.append(self._button("Next >", "dp", state, state.domain_page + 1))
        if navigation:
            rows.append(navigation)
        rows.append([self._button("Refresh", "dp", state, state.domain_page)])
        text = (
            "<b>ArvanCloud domains</b>\n"
            f"Page {state.domain_page}/{state.domain_last_page} • Total {result.meta.total}"
        )
        if not result.data:
            text += "\n\nNo domains were returned for this account."
        await self._display(chat_id, text, self._markup(rows), message_id)

    async def _show_records(
        self,
        chat_id: int,
        state: UserState,
        *,
        page: int,
        message_id: int | None = None,
    ) -> None:
        domain = state.selected_domain
        if domain is None:
            await self._show_domains(chat_id, state, page=state.domain_page, message_id=message_id)
            return
        result = await self.gateway.list_records(
            domain,
            page=max(page, 1),
            per_page=PAGE_SIZE,
            record_type=state.record_type_filter,
            search=state.search,
        )
        state.record_page = result.meta.current_page
        state.record_last_page = max(result.meta.last_page, 1)
        state.records = result.data
        state.selected_record = None
        state.clear_transient()
        state.rotate_revision()
        rows = []
        for index, record in enumerate(result.data):
            marker = "🔒 " if record.is_protected else ""
            compact_value = format_record_value(record.value, compact=True)
            label = f"{marker}{record.type.upper()} {record.name} — {compact_value}"
            rows.append([self._button(label[:64], "rs", state, index)])
        navigation: list[types.InlineKeyboardButton] = []
        if state.record_page > 1:
            navigation.append(self._button("< Previous", "rp", state, state.record_page - 1))
        if state.record_page < state.record_last_page:
            navigation.append(self._button("Next >", "rp", state, state.record_page + 1))
        if navigation:
            rows.append(navigation)
        rows.append(
            [
                self._button("Search", "se", state),
                self._button("Filter", "fm", state),
                self._button("Refresh", "rr", state),
            ]
        )
        if state.search:
            rows.append([self._button("Clear search", "sx", state)])
        rows.append(
            [
                self._button("Create record", "cr", state),
                self._button("Back to domains", "bd", state),
            ]
        )
        filters = []
        if state.search:
            filters.append(f"name={html.escape(state.search)}")
        if state.record_type_filter:
            filters.append(f"type={state.record_type_filter}")
        text = (
            f"<b>{html.escape(domain)} DNS records</b>\n"
            f"Page {state.record_page}/{state.record_last_page} • Total {result.meta.total}"
        )
        if filters:
            text += "\nFilter: " + ", ".join(filters)
        if not result.data:
            text += "\n\nNo records match this view."
        await self._display(chat_id, text, self._markup(rows), message_id)

    async def _show_filter_menu(self, chat_id: int, state: UserState, message_id: int) -> None:
        state.rotate_revision()
        rows = [
            [
                self._button(record_type, "fv", state, index)
                for index, record_type in enumerate(RECORD_TYPES[start : start + 3], start=start)
            ]
            for start in range(0, len(RECORD_TYPES), 3)
        ]
        rows.append([self._button("Any type", "fv", state, -1)])
        await self._display(chat_id, "<b>Filter by record type</b>", self._markup(rows), message_id)

    async def _show_record_detail(
        self,
        chat_id: int,
        state: UserState,
        record: DNSRecord,
        *,
        message_id: int | None = None,
    ) -> None:
        state.selected_record = record
        state.clear_transient()
        state.rotate_revision()
        text = (
            f"<b>{html.escape(record.type.upper())} {html.escape(record.name)}</b>\n"
            f"Value: <code>{html.escape(format_record_value(record.value))}</code>\n"
            f"TTL: {record.ttl}\n"
            f"Cloud: {'on' if record.cloud else 'off'}\n"
            f"Protected: {'yes' if record.is_protected else 'no'}\n"
            f"Updated: {html.escape(record.updated_at.isoformat())}\n"
            f"ID: <code>{record.id}</code>"
        )
        rows: list[list[types.InlineKeyboardButton]] = []
        if not record.is_protected:
            rows.extend(
                [
                    [
                        self._button("Edit type", "et", state),
                        self._button("Edit name", "en", state),
                    ],
                    [
                        self._button("Edit value", "ev", state),
                        self._button("Edit TTL", "el", state),
                    ],
                    [
                        self._button("Toggle cloud", "cl", state),
                        self._button("Delete", "de", state),
                    ],
                ]
            )
        rows.append([self._button("Back to records", "br", state)])
        await self._display(chat_id, text, self._markup(rows), message_id)

    async def _prompt(
        self,
        chat_id: int,
        state: UserState,
        text: str,
        message_id: int | None = None,
    ) -> None:
        state.rotate_revision()
        markup = self._markup([[self._button("Cancel", "no", state)]])
        await self._display(chat_id, text, markup, message_id)

    async def _show_type_menu(self, chat_id: int, state: UserState, message_id: int) -> None:
        state.rotate_revision()
        action = "ct" if state.draft and state.draft.mode == "create" else "ut"
        rows = [
            [
                self._button(record_type, action, state, index)
                for index, record_type in enumerate(RECORD_TYPES[start : start + 3], start=start)
            ]
            for start in range(0, len(RECORD_TYPES), 3)
        ]
        rows.append([self._button("Cancel", "no", state)])
        await self._display(
            chat_id, "<b>Select a DNS record type</b>", self._markup(rows), message_id
        )

    async def _select_create_type(
        self, chat_id: int, state: UserState, index: int, message_id: int
    ) -> None:
        if (
            state.draft is None
            or state.draft.mode != "create"
            or index not in range(len(RECORD_TYPES))
        ):
            raise ValueError("Stale create flow")
        state.draft.record_type = RECORD_TYPES[index]
        state.flow = "create_name"
        await self._prompt(
            chat_id,
            state,
            "Send the zone-relative name, such as <code>@</code> or <code>www</code>.",
            message_id,
        )

    async def _show_cloud_choice(self, chat_id: int, state: UserState) -> None:
        state.rotate_revision()
        markup = self._markup(
            [
                [
                    self._button("Cloud off", "cc", state, 0),
                    self._button("Cloud on", "cc", state, 1),
                ],
                [self._button("Cancel", "no", state)],
            ]
        )
        await self._display(chat_id, "Select the ArvanCloud cloud status.", markup)

    async def _select_create_cloud(
        self, chat_id: int, state: UserState, enabled: int, message_id: int
    ) -> None:
        draft = state.draft
        if draft is None or draft.mode != "create" or enabled not in {0, 1}:
            raise ValueError("Stale create flow")
        if draft.record_type is None or draft.name is None or draft.value is None:
            raise ValueError("Incomplete create flow")
        draft.cloud = bool(enabled)
        payload = create_record(
            record_type=draft.record_type,
            name=draft.name,
            value=draft.value,
            ttl=draft.ttl,
            cloud=draft.cloud,
        )
        confirmation = Confirmation(
            kind="create",
            domain=state.selected_domain or "",
            create_payload=payload,
        )
        summary = (
            "<b>Confirm record creation</b>\n"
            f"Domain: {html.escape(confirmation.domain)}\n"
            f"Type: {html.escape(payload.type)}\n"
            f"Name: {html.escape(payload.name)}\n"
            f"Value: <code>{html.escape(format_record_value(payload.value))}</code>\n"
            f"TTL: {payload.ttl}\nCloud: {'on' if payload.cloud else 'off'}"
        )
        await self._show_confirmation(chat_id, state, confirmation, summary, message_id)

    @staticmethod
    def _draft_from_record(record: DNSRecord) -> Draft:
        return Draft(
            mode="update",
            record_type=record.type.upper(),
            name=record.name,
            value=copy.deepcopy(record.value),
            ttl=record.ttl,
            cloud=record.cloud,
            base_record=record,
        )

    async def _begin_edit(
        self, chat_id: int, state: UserState, action: str, message_id: int
    ) -> None:
        record = state.selected_record
        if record is None or record.is_protected:
            raise ProtectedRecordError("This DNS record is not editable")
        state.draft = self._draft_from_record(record)
        state.confirmation = None
        if action == "et":
            state.flow = None
            await self._show_type_menu(chat_id, state, message_id)
            return
        prompts = {
            "en": ("edit_name", "Send the new zone-relative record name."),
            "ev": ("edit_value", value_prompt(record.type)),
            "el": ("edit_ttl", "Send the new positive TTL."),
        }
        state.flow, prompt = prompts[action]
        await self._prompt(chat_id, state, prompt, message_id)

    async def _select_update_type(
        self, chat_id: int, state: UserState, index: int, message_id: int
    ) -> None:
        draft = state.draft
        if draft is None or draft.mode != "update" or index not in range(len(RECORD_TYPES)):
            raise ValueError("Stale update flow")
        selected = RECORD_TYPES[index]
        if selected != draft.record_type:
            draft.value = None
            draft.cloud = False
        draft.record_type = selected
        state.flow = "edit_type_value"
        await self._prompt(
            chat_id,
            state,
            f"<b>{selected} value</b>\n{value_prompt(selected)}\n"
            "Cloud will be reset to off when the type changes.",
            message_id,
        )

    async def _prepare_update_confirmation(self, chat_id: int, state: UserState) -> None:
        draft = state.draft
        if draft is None or draft.base_record is None or draft.value is None:
            raise ValueError("Incomplete update flow")
        payload = update_record(
            draft.base_record,
            record_type=draft.record_type,
            name=draft.name,
            value=draft.value,
            ttl=draft.ttl,
            cloud=draft.cloud,
        )
        changes = list(changed_fields(draft.base_record, payload))
        if not changes:
            state.clear_transient()
            await self.bot.send_message(chat_id, "No DNS fields changed.")
            await self._show_record_detail(chat_id, state, draft.base_record)
            return
        confirmation = Confirmation(
            kind="update",
            domain=state.selected_domain or "",
            update_payload=payload,
            record_id=str(draft.base_record.id),
            snapshot_updated_at=draft.base_record.updated_at,
        )
        rendered = "\n".join(html.escape(change) for change in changes)
        await self._show_confirmation(
            chat_id,
            state,
            confirmation,
            f"<b>Confirm DNS record update</b>\n<code>{rendered}</code>",
        )

    async def _prepare_cloud_confirmation(
        self, chat_id: int, state: UserState, message_id: int
    ) -> None:
        record = state.selected_record
        if record is None or record.is_protected:
            raise ProtectedRecordError("This DNS record is not editable")
        enabled = not record.cloud
        confirmation = Confirmation(
            kind="cloud",
            domain=state.selected_domain or "",
            record_id=str(record.id),
            snapshot_updated_at=record.updated_at,
            cloud=enabled,
        )
        await self._show_confirmation(
            chat_id,
            state,
            confirmation,
            f"<b>Confirm cloud status change</b>\n{html.escape(record.type.upper())} "
            f"{html.escape(record.name)}: {'off → on' if enabled else 'on → off'}",
            message_id,
        )

    async def _prepare_delete_confirmation(
        self, chat_id: int, state: UserState, message_id: int
    ) -> None:
        record = state.selected_record
        if record is None or record.is_protected:
            raise ProtectedRecordError("This DNS record cannot be deleted")
        confirmation = Confirmation(
            kind="delete",
            domain=state.selected_domain or "",
            record_id=str(record.id),
            snapshot_updated_at=record.updated_at,
        )
        await self._show_confirmation(
            chat_id,
            state,
            confirmation,
            "<b>Confirm permanent DNS record deletion</b>\n"
            f"{html.escape(record.type.upper())} {html.escape(record.name)}\n"
            f"<code>{html.escape(format_record_value(record.value))}</code>",
            message_id,
        )

    async def _show_confirmation(
        self,
        chat_id: int,
        state: UserState,
        confirmation: Confirmation,
        summary: str,
        message_id: int | None = None,
    ) -> None:
        state.flow = None
        state.confirmation = confirmation
        state.rotate_revision()
        markup = self._markup(
            [
                [
                    self._button("Confirm", "ok", state, confirmation.token),
                    self._button("Cancel", "no", state),
                ]
            ]
        )
        await self._display(chat_id, summary, markup, message_id)

    async def _execute_confirmation(self, call: Any, state: UserState, token: str | None) -> None:
        confirmation = state.confirmation
        if confirmation is None or token != confirmation.token or confirmation.is_expired():
            state.confirmation = None
            await self.bot.send_message(call.message.chat.id, "That confirmation expired.")
            return

        state.confirmation = None  # make every confirmation single-use before network I/O
        chat_id = call.message.chat.id
        actor_id = call.from_user.id
        try:
            result: DNSRecord | None = None
            if confirmation.kind == "create":
                assert confirmation.create_payload is not None
                result = await self.gateway.create_record(
                    confirmation.domain, confirmation.create_payload
                )
            else:
                assert confirmation.record_id is not None
                await self.gateway.require_current_record(
                    confirmation.domain,
                    confirmation.record_id,
                    confirmation.snapshot_updated_at,
                )
                if confirmation.kind == "update":
                    assert confirmation.update_payload is not None
                    result = await self.gateway.update_record(
                        confirmation.domain, confirmation.update_payload
                    )
                elif confirmation.kind == "cloud":
                    assert confirmation.cloud is not None
                    result = await self.gateway.set_cloud(
                        confirmation.domain,
                        confirmation.record_id,
                        cloud=confirmation.cloud,
                    )
                else:
                    await self.gateway.delete_record(confirmation.domain, confirmation.record_id)
            logger.info(
                "dns mutation actor_id=%s action=%s domain=%s record_id=%s outcome=success",
                actor_id,
                confirmation.kind,
                confirmation.domain,
                confirmation.record_id or (str(result.id) if result else None),
            )
        except InteractiveAuthenticationRequired:
            logger.info(
                "dns mutation actor_id=%s action=%s domain=%s record_id=%s "
                "outcome=authentication_required",
                actor_id,
                confirmation.kind,
                confirmation.domain,
                confirmation.record_id,
            )
            raise
        except NetworkError:
            logger.warning(
                "dns mutation actor_id=%s action=%s domain=%s record_id=%s outcome=unknown",
                actor_id,
                confirmation.kind,
                confirmation.domain,
                confirmation.record_id,
            )
            state.clear_transient()
            await self.bot.send_message(
                chat_id,
                "The network failed during the mutation, so its outcome is unknown. "
                "Refresh the record list before trying again.",
            )
            return
        except APIError as exc:
            logger.warning(
                "dns mutation actor_id=%s action=%s domain=%s record_id=%s "
                "outcome=failed status=%s request_id=%s",
                actor_id,
                confirmation.kind,
                confirmation.domain,
                confirmation.record_id,
                exc.status_code,
                exc.request_id,
            )
            raise

        state.clear_transient()
        if confirmation.kind == "delete":
            state.selected_record = None
            await self.bot.send_message(chat_id, "DNS record deleted.")
            await self._show_records(chat_id, state, page=state.record_page)
        else:
            assert result is not None
            state.selected_record = result
            await self.bot.send_message(chat_id, "DNS change applied successfully.")
            await self._show_record_detail(chat_id, state, result)
