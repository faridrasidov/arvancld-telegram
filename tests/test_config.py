"""Configuration and access-policy tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from arvancld_telegram.config import ConfigurationError, Settings


def valid_environment() -> dict[str, str]:
    return {
        "TELEGRAM_BOT_TOKEN": "123456:test-token",
        "TELEGRAM_ADMIN_IDS": "1001, 1002,1001",
        "ARVANCLD_EMAIL": "admin@example.test",
        "ARVANCLD_PASSWORD": "secret",
    }


def test_settings_parse_admins_and_defaults() -> None:
    settings = Settings.from_env(valid_environment())

    assert settings.telegram_admin_ids == frozenset({1001, 1002})
    assert settings.arvancld_session_path == Path("data/arvancld-session.json")
    assert settings.log_level == "INFO"
    assert settings.is_authorized(1001, "private")
    assert not settings.is_authorized(1001, "group")
    assert not settings.is_authorized(9999, "private")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("TELEGRAM_BOT_TOKEN", ""),
        ("TELEGRAM_ADMIN_IDS", "one"),
        ("TELEGRAM_ADMIN_IDS", "1,"),
        ("TELEGRAM_ADMIN_IDS", "-1"),
        ("ARVANCLD_EMAIL", " "),
        ("ARVANCLD_PASSWORD", ""),
        ("LOG_LEVEL", "LOUD"),
    ],
)
def test_settings_reject_invalid_environment(name: str, value: str) -> None:
    environment = valid_environment()
    environment[name] = value

    with pytest.raises(ConfigurationError):
        Settings.from_env(environment)
