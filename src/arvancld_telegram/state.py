"""Expiring per-administrator navigation and mutation state."""

from __future__ import annotations

import asyncio
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from arvancld import CDNDomain, DNSRecord, DNSRecordCreate, DNSRecordUpdate

STATE_TTL_SECONDS = 15 * 60
CONFIRMATION_TTL_SECONDS = 5 * 60


def new_revision() -> str:
    return secrets.token_hex(3)


def callback_data(action: str, revision: str, argument: str | int | None = None) -> str:
    parts = [action, revision]
    if argument is not None:
        parts.append(str(argument))
    encoded = "|".join(parts)
    if len(encoded.encode("utf-8")) > 64:
        raise ValueError("Telegram callback data exceeds 64 bytes")
    return encoded


def parse_callback(value: str | None) -> tuple[str, str, str | None]:
    if not value:
        raise ValueError("Missing callback data")
    parts = value.split("|", 2)
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError("Invalid callback data")
    return parts[0], parts[1], parts[2] if len(parts) == 3 else None


@dataclass(slots=True)
class Draft:
    mode: Literal["create", "update"]
    record_type: str | None = None
    name: str | None = None
    value: dict[str, Any] | list[dict[str, Any]] | None = None
    ttl: int = 120
    cloud: bool = False
    base_record: DNSRecord | None = None


@dataclass(slots=True)
class Confirmation:
    kind: Literal["create", "update", "cloud", "delete"]
    domain: str
    token: str = field(default_factory=lambda: secrets.token_hex(4))
    expires_at: float = field(default_factory=lambda: time.monotonic() + CONFIRMATION_TTL_SECONDS)
    snapshot_updated_at: datetime | None = None
    create_payload: DNSRecordCreate | None = None
    update_payload: DNSRecordUpdate | None = None
    record_id: str | None = None
    cloud: bool | None = None

    def is_expired(self, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        return current >= self.expires_at


@dataclass(slots=True)
class UserState:
    revision: str = field(default_factory=new_revision)
    touched_at: float = field(default_factory=time.monotonic)
    domain_page: int = 1
    domain_last_page: int = 1
    domains: list[CDNDomain] = field(default_factory=list)
    selected_domain: str | None = None
    record_page: int = 1
    record_last_page: int = 1
    records: list[DNSRecord] = field(default_factory=list)
    selected_record: DNSRecord | None = None
    search: str | None = None
    record_type_filter: str | None = None
    flow: str | None = None
    draft: Draft | None = None
    confirmation: Confirmation | None = None

    def touch(self) -> None:
        self.touched_at = time.monotonic()

    def rotate_revision(self) -> str:
        self.revision = new_revision()
        self.touch()
        return self.revision

    def clear_transient(self) -> None:
        self.flow = None
        self.draft = None
        self.confirmation = None
        self.touch()


class ConversationStore:
    """Store isolated user state and locks without persistent credentials."""

    def __init__(self, *, ttl_seconds: float = STATE_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._states: dict[int, UserState] = {}
        self._locks: defaultdict[int, asyncio.Lock] = defaultdict(asyncio.Lock)

    def lock(self, user_id: int) -> asyncio.Lock:
        return self._locks[user_id]

    def get(self, user_id: int, *, now: float | None = None) -> UserState:
        current = time.monotonic() if now is None else now
        state = self._states.get(user_id)
        if state is None or current - state.touched_at >= self._ttl_seconds:
            state = UserState(touched_at=current)
            self._states[user_id] = state
        else:
            state.touched_at = current
        return state

    def reset(self, user_id: int) -> UserState:
        state = UserState()
        self._states[user_id] = state
        return state
