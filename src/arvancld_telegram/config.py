"""Environment-backed application configuration."""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(ValueError):
    """Raised when required bot configuration is missing or invalid."""


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is required")
    return value


def _admin_ids(raw: str) -> frozenset[int]:
    values = [value.strip() for value in raw.split(",")]
    if not values or any(not value for value in values):
        raise ConfigurationError("TELEGRAM_ADMIN_IDS must be a comma-separated list")

    parsed: set[int] = set()
    for value in values:
        try:
            user_id = int(value)
        except ValueError:
            raise ConfigurationError("TELEGRAM_ADMIN_IDS must contain integers") from None
        if user_id <= 0:
            raise ConfigurationError("TELEGRAM_ADMIN_IDS must contain positive integers")
        parsed.add(user_id)
    return frozenset(parsed)


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated runtime settings."""

    telegram_bot_token: str
    telegram_admin_ids: frozenset[int]
    arvancld_email: str
    arvancld_password: str
    arvancld_session_path: Path
    log_level: str = "INFO"

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if environment is None else environment
        log_level = source.get("LOG_LEVEL", "INFO").strip().upper() or "INFO"
        if log_level not in logging.getLevelNamesMapping():
            raise ConfigurationError("LOG_LEVEL must be a standard Python logging level")

        return cls(
            telegram_bot_token=_required(source, "TELEGRAM_BOT_TOKEN"),
            telegram_admin_ids=_admin_ids(_required(source, "TELEGRAM_ADMIN_IDS")),
            arvancld_email=_required(source, "ARVANCLD_EMAIL"),
            arvancld_password=_required(source, "ARVANCLD_PASSWORD"),
            arvancld_session_path=Path(
                source.get("ARVANCLD_SESSION_PATH", "data/arvancld-session.json")
            ).expanduser(),
            log_level=log_level,
        )

    def is_authorized(self, user_id: int | None, chat_type: str | None) -> bool:
        """Return whether an update belongs to an allowed private-chat administrator."""

        return chat_type == "private" and user_id in self.telegram_admin_ids


def configure_logging(level: str) -> None:
    """Configure credential-safe stdout logging."""

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("telebot").setLevel(logging.INFO)
