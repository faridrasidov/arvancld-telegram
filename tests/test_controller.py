"""Focused handler tests using in-memory Telegram and gateway fakes."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from arvancld_telegram.config import Settings
from arvancld_telegram.controller import BotController
from arvancld_telegram.state import Confirmation, ConversationStore, UserState


class FakeBot:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str, object]] = []
        self.edited: list[tuple[int, int, str, object]] = []

    async def send_message(self, chat_id, text, reply_markup=None, **_kwargs):
        self.sent.append((chat_id, text, reply_markup))

    async def edit_message_text(self, text, chat_id, message_id, reply_markup=None, **_kwargs):
        self.edited.append((chat_id, message_id, text, reply_markup))

    async def answer_callback_query(self, _callback_id):
        return None


class FakeGateway:
    connected = True

    def __init__(self) -> None:
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


def test_conversation_store_keeps_admin_states_independent() -> None:
    store = ConversationStore()
    store.get(1).selected_domain = "one.example"
    store.get(2).selected_domain = "two.example"

    assert store.get(1).selected_domain == "one.example"
    assert store.get(2).selected_domain == "two.example"
