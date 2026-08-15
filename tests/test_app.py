"""Polling bootstrap tests for interactive authentication mode."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from arvancld_telegram import app
from arvancld_telegram.config import Settings
from arvancld_telegram.gateway import AuthenticationState


async def test_handlers_and_otp_notification_are_ready_before_polling(
    tmp_path, monkeypatch
) -> None:
    events: list[str] = []
    bot = SimpleNamespace(
        get_me=AsyncMock(side_effect=lambda: events.append("telegram")),
        skip_updates=AsyncMock(side_effect=lambda: events.append("skip")),
        infinity_polling=AsyncMock(side_effect=lambda **_kwargs: events.append("poll")),
        close_session=AsyncMock(side_effect=lambda: events.append("close_bot")),
    )
    gateway = SimpleNamespace(
        start=AsyncMock(
            side_effect=lambda: (
                events.append("gateway"),
                AuthenticationState.OTP_REQUIRED,
            )[1]
        ),
        close=AsyncMock(side_effect=lambda: events.append("close_gateway")),
    )

    class FakeController:
        def __init__(self, *_args) -> None:
            pass

        def register_handlers(self) -> None:
            events.append("handlers")

        async def notify_auth_required(self) -> None:
            events.append("notify")

    monkeypatch.setattr(app, "AsyncTeleBot", lambda *_args, **_kwargs: bot)
    monkeypatch.setattr(app, "ArvanCloudGateway", lambda _settings: gateway)
    monkeypatch.setattr(app, "BotController", FakeController)
    settings = Settings(
        telegram_bot_token="123:test",
        telegram_admin_ids=frozenset({1}),
        arvancld_email="admin@example.test",
        arvancld_password="secret",
        arvancld_session_path=tmp_path / "session.json",
    )

    await app.run(settings)

    assert events == [
        "handlers",
        "telegram",
        "gateway",
        "skip",
        "poll",
        "notify",
        "close_gateway",
        "close_bot",
    ]
