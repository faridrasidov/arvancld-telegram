"""Focused handler tests using in-memory Telegram and gateway fakes."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from arvancld import NetworkError

from arvancld_telegram.config import Settings
from arvancld_telegram.controller import BotController
from arvancld_telegram.gateway import (
    AuthenticationBusyError,
    AuthenticationState,
    InteractiveAuthenticationRequired,
    OTPRejectedError,
    OTPSubmissionUncertainError,
)
from arvancld_telegram.state import Confirmation, ConversationStore, UserState


class FakeBot:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str, object]] = []
        self.edited: list[tuple[int, int, str, object]] = []
        self.deleted: list[tuple[int, int]] = []
        self.fail_send_ids: set[int] = set()
        self.fail_delete = False

    async def send_message(self, chat_id, text, reply_markup=None, **_kwargs):
        if chat_id in self.fail_send_ids:
            raise RuntimeError("synthetic Telegram failure")
        self.sent.append((chat_id, text, reply_markup))

    async def edit_message_text(self, text, chat_id, message_id, reply_markup=None, **_kwargs):
        self.edited.append((chat_id, message_id, text, reply_markup))

    async def answer_callback_query(self, _callback_id):
        return None

    async def delete_message(self, chat_id, message_id):
        if self.fail_delete:
            raise RuntimeError("synthetic delete failure")
        self.deleted.append((chat_id, message_id))


class FakeGateway:
    def __init__(self) -> None:
        self.connected = True
        self.otp_required = False
        self.auth_status = "connected"
        self.challenge_revision = 0
        self.auth_attempt_id = "attempt-test"
        self.begin_authentication = AsyncMock(return_value=AuthenticationState.CONNECTED)
        self.submit_totp = AsyncMock()
        self.cancel_authentication = AsyncMock(return_value=True)
        self.list_domains = AsyncMock()
        self.list_records = AsyncMock()
        self.require_current_record = AsyncMock()
        self.create_record = AsyncMock()
        self.update_record = AsyncMock()
        self.set_cloud = AsyncMock()
        self.delete_record = AsyncMock()


def settings() -> Settings:
    return Settings(
        telegram_bot_token="123:test",
        telegram_admin_ids=frozenset({1, 2}),
        arvancld_email="admin@example.test",
        arvancld_password="secret",
        arvancld_session_path=SimpleNamespace(),  # type: ignore[arg-type]
    )


def domain_page() -> SimpleNamespace:
    domains = [SimpleNamespace(domain=f"d{number}.example") for number in range(1, 9)]
    meta = SimpleNamespace(current_page=1, last_page=2, total=9)
    return SimpleNamespace(data=domains, meta=meta)


def message(*, user_id: int = 1, text: str | None = None, message_id: int = 20):
    return SimpleNamespace(
        from_user=SimpleNamespace(id=user_id),
        chat=SimpleNamespace(id=user_id, type="private"),
        text=text,
        message_id=message_id,
    )


async def test_domain_menu_uses_opaque_index_callbacks() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    gateway.list_domains.return_value = domain_page()
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    state = UserState()

    await controller._show_domains(10, state, page=1)

    _, _, markup = bot.sent[-1]
    callback_values = [button.callback_data for row in markup.keyboard for button in row]
    assert any(value.startswith(f"ds|{state.revision}|") for value in callback_values)
    assert all("example" not in value for value in callback_values)
    assert state.domain_last_page == 2


async def test_unauthorized_message_never_calls_gateway() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    message = SimpleNamespace(
        from_user=SimpleNamespace(id=999),
        chat=SimpleNamespace(id=10, type="private"),
    )

    await controller.handle_start(message)

    gateway.list_domains.assert_not_awaited()
    assert bot.sent[-1][1].startswith("Not authorized")


async def test_auth_claims_otp_and_notifies_other_admins() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    gateway.connected = False
    gateway.otp_required = True
    gateway.auth_status = "OTP required"
    gateway.challenge_revision = 1
    gateway.begin_authentication.return_value = AuthenticationState.OTP_REQUIRED
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]

    await controller.handle_auth(message())

    gateway.begin_authentication.assert_awaited_once_with(1)
    assert controller.store.get(1).flow == "auth_totp"
    assert any(chat_id == 2 and "OTP required" in text for chat_id, text, _ in bot.sent)
    assert any(chat_id == 1 and "six-digit" in text for chat_id, text, _ in bot.sent)


async def test_second_admin_cannot_claim_owned_otp() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    gateway.connected = False
    gateway.begin_authentication.side_effect = AuthenticationBusyError("busy")
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]

    await controller.handle_auth(message(user_id=2))

    assert controller.store.get(2).flow is None
    assert "Another administrator" in bot.sent[-1][1]


async def test_totp_message_is_deleted_and_submitted_once() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    state = controller.store.get(1)
    state.flow = "auth_totp"
    otp_message = message(text=" 246810 ", message_id=44)

    await controller.handle_text(otp_message)

    assert bot.deleted == [(1, 44)]
    gateway.submit_totp.assert_awaited_once_with(1, "246810")
    assert controller.store.get(1).flow is None
    assert all("246810" not in text for _, text, _ in bot.sent)


async def test_malformed_totp_is_deleted_logged_safely_and_not_submitted(caplog) -> None:
    caplog.set_level(logging.INFO, logger="arvancld_telegram.controller")
    bot = FakeBot()
    gateway = FakeGateway()
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    controller.store.get(1).flow = "auth_totp"

    await controller.handle_text(message(text="12secret", message_id=45))

    assert bot.deleted == [(1, 45)]
    gateway.submit_totp.assert_not_awaited()
    assert controller.store.get(1).flow == "auth_totp"
    assert "event=telegram_otp_received" in caplog.text
    assert "event=telegram_otp_format_rejected" in caplog.text
    assert "12secret" not in caplog.text


async def test_totp_submission_continues_when_message_deletion_fails(caplog) -> None:
    caplog.set_level(logging.INFO, logger="arvancld_telegram.controller")
    bot = FakeBot()
    bot.fail_delete = True
    gateway = FakeGateway()
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    controller.store.get(1).flow = "auth_totp"

    await controller.handle_text(message(text="246810"))

    gateway.submit_totp.assert_awaited_once_with(1, "246810")
    assert all("246810" not in text for _, text, _ in bot.sent)
    assert "event=telegram_otp_delete_failed" in caplog.text
    assert "event=telegram_otp_format_accepted" in caplog.text
    assert "246810" not in caplog.text


async def test_invalid_or_rejected_totp_keeps_prompt_without_leaking_code() -> None:
    for error in (ValueError("bad code 246810"), OTPRejectedError("bad code 246810")):
        bot = FakeBot()
        gateway = FakeGateway()
        gateway.submit_totp.side_effect = error
        controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
        controller.store.get(1).flow = "auth_totp"

        await controller.handle_text(message(text="246810"))

        assert controller.store.get(1).flow == "auth_totp"
        gateway.submit_totp.assert_awaited_once()
        assert all("246810" not in text for _, text, _ in bot.sent)


async def test_uncertain_totp_clears_prompt_and_requires_fresh_auth() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    gateway.submit_totp.side_effect = OTPSubmissionUncertainError("unknown")
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    controller.store.get(1).flow = "auth_totp"

    await controller.handle_text(message(text="246810"))

    assert controller.store.get(1).flow is None
    assert "fresh login" in bot.sent[-1][1]


async def test_cancel_releases_owned_otp_without_opening_dns_menu() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    gateway.connected = False
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    controller.store.get(1).flow = "auth_totp"

    await controller.handle_cancel(message())

    gateway.cancel_authentication.assert_awaited_once_with(1)
    gateway.list_domains.assert_not_awaited()
    assert controller.store.get(1).flow is None


async def test_pending_status_does_not_call_arvancloud() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    gateway.connected = False
    gateway.auth_status = "OTP required"
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]

    await controller.handle_status(message())

    gateway.list_domains.assert_not_awaited()
    assert "ArvanCloud: OTP required" in bot.sent[-1][1]


async def test_notification_failures_do_not_stop_other_admins() -> None:
    bot = FakeBot()
    bot.fail_send_ids.add(1)
    gateway = FakeGateway()
    gateway.connected = False
    gateway.otp_required = True
    gateway.challenge_revision = 1
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]

    await controller.notify_auth_required()

    assert any(chat_id == 2 for chat_id, _, _ in bot.sent)


async def test_interrupted_domain_request_switches_to_otp_without_replay() -> None:
    bot = FakeBot()
    gateway = FakeGateway()

    async def interrupt(*_args, **_kwargs):
        gateway.connected = False
        gateway.otp_required = True
        gateway.auth_status = "OTP required"
        gateway.challenge_revision = 1
        raise InteractiveAuthenticationRequired("OTP required")

    gateway.list_domains.side_effect = interrupt
    gateway.begin_authentication.return_value = AuthenticationState.OTP_REQUIRED
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]

    await controller.handle_start(message())

    assert gateway.list_domains.await_count == 1
    assert controller.store.get(1).flow == "auth_totp"


async def test_otp_network_error_text_is_never_exposed() -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    gateway.submit_totp.side_effect = NetworkError("request contained 246810")
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    controller.store.get(1).flow = "auth_totp"

    await controller.handle_text(message(text="246810"))

    assert all("246810" not in text for _, text, _ in bot.sent)


async def test_protected_record_detail_has_no_mutation_buttons(dns_record_factory) -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    record = dns_record_factory(is_protected=True)
    state = UserState(selected_domain="example.test")

    await controller._show_record_detail(10, state, record)

    _, _, markup = bot.sent[-1]
    labels = [button.text for row in markup.keyboard for button in row]
    assert labels == ["Back to records"]


async def test_confirmation_is_consumed_before_mutation(dns_record_factory) -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    record = dns_record_factory()
    gateway.require_current_record.return_value = record
    gateway.set_cloud.return_value = dns_record_factory(cloud=False)
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    state = UserState(selected_domain="example.test", selected_record=record)
    confirmation = Confirmation(
        kind="cloud",
        domain="example.test",
        record_id=str(record.id),
        snapshot_updated_at=record.updated_at,
        cloud=False,
    )
    state.confirmation = confirmation
    call = SimpleNamespace(
        from_user=SimpleNamespace(id=1),
        message=SimpleNamespace(chat=SimpleNamespace(id=10), message_id=20),
    )

    await controller._execute_confirmation(call, state, confirmation.token)
    await controller._execute_confirmation(call, state, confirmation.token)

    gateway.set_cloud.assert_awaited_once()
    assert any("expired" in text for _, text, _ in bot.sent)


async def test_confirmation_interrupted_by_otp_is_consumed_without_replay(
    dns_record_factory,
) -> None:
    bot = FakeBot()
    gateway = FakeGateway()
    record = dns_record_factory()
    gateway.create_record.side_effect = InteractiveAuthenticationRequired("OTP required")
    controller = BotController(bot, settings(), gateway)  # type: ignore[arg-type]
    state = UserState(selected_domain="example.test", selected_record=record)
    confirmation = Confirmation(
        kind="create",
        domain="example.test",
        create_payload=SimpleNamespace(),  # type: ignore[arg-type]
    )
    state.confirmation = confirmation
    call = SimpleNamespace(
        from_user=SimpleNamespace(id=1),
        message=SimpleNamespace(chat=SimpleNamespace(id=1), message_id=20),
    )

    with pytest.raises(InteractiveAuthenticationRequired):
        await controller._execute_confirmation(call, state, confirmation.token)
    await controller._execute_confirmation(call, state, confirmation.token)

    gateway.create_record.assert_awaited_once()
    assert state.confirmation is None


def test_conversation_store_keeps_admin_states_independent() -> None:
    store = ConversationStore()
    store.get(1).selected_domain = "one.example"
    store.get(2).selected_domain = "two.example"

    assert store.get(1).selected_domain == "one.example"
    assert store.get(2).selected_domain == "two.example"
