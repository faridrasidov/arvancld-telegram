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
MENU_SNAPSHOT_TTL_SECONDS = 24 * 60 * 60
MAX_MENU_SNAPSHOTS_PER_USER = 32

MenuView = Literal["domains", "records", "record", "filter", "confirmation"]


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


@dataclass(frozen=True, slots=True)
class MenuSnapshot:
    """Bounded navigation context for callbacks rendered in earlier messages."""

    revision: str
    view: MenuView
    created_at: float
    domain_page: int = 1
    domain_names: tuple[str, ...] = ()
    selected_domain: str | None = None
    record_page: int = 1
    record_ids: tuple[str, ...] = ()
    selected_record_id: str | None = None
    search: str | None = None
    record_type_filter: str | None = None


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

    def restore_menu(self, snapshot: MenuSnapshot) -> None:
        """Restore navigation only; wizard and confirmation state is never revived."""

        self.revision = snapshot.revision
        self.domain_page = snapshot.domain_page
        self.domains = []
        self.selected_domain = snapshot.selected_domain
        self.record_page = snapshot.record_page
        self.records = []
        self.selected_record = None
        self.search = snapshot.search
        self.record_type_filter = snapshot.record_type_filter
        self.flow = None
        self.draft = None
        self.confirmation = None
        self.touch()


class ConversationStore:
    """Store isolated user state and locks without persistent credentials."""

    def __init__(
        self,
        *,
        ttl_seconds: float = STATE_TTL_SECONDS,
        menu_ttl_seconds: float = MENU_SNAPSHOT_TTL_SECONDS,
        max_menu_snapshots: int = MAX_MENU_SNAPSHOTS_PER_USER,
    ) -> None:
        self._ttl_seconds = ttl_seconds
        self._menu_ttl_seconds = menu_ttl_seconds
        self._max_menu_snapshots = max_menu_snapshots
        self._states: dict[int, UserState] = {}
        self._menu_snapshots: defaultdict[int, dict[str, MenuSnapshot]] = defaultdict(dict)
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

    def remember_menu(
        self,
        user_id: int,
        state: UserState,
        *,
        view: MenuView,
        selected_record_id: str | None = None,
        now: float | None = None,
    ) -> MenuSnapshot:
        current = time.monotonic() if now is None else now
        snapshots = self._menu_snapshots[user_id]
        self._prune_menus(snapshots, current)
        record_id = selected_record_id
        if record_id is None and state.selected_record is not None:
            record_id = str(state.selected_record.id)
        snapshot = MenuSnapshot(
            revision=state.revision,
            view=view,
            created_at=current,
            domain_page=state.domain_page,
            domain_names=(
                tuple(domain.domain for domain in state.domains) if view == "domains" else ()
            ),
            selected_domain=state.selected_domain,
            record_page=state.record_page,
            record_ids=(
                tuple(str(record.id) for record in state.records) if view == "records" else ()
            ),
            selected_record_id=record_id,
            search=state.search,
            record_type_filter=state.record_type_filter,
        )
        snapshots.pop(snapshot.revision, None)
        snapshots[snapshot.revision] = snapshot
        while len(snapshots) > self._max_menu_snapshots:
            del snapshots[next(iter(snapshots))]
        return snapshot

    def get_menu(
        self,
        user_id: int,
        revision: str,
        *,
        now: float | None = None,
    ) -> MenuSnapshot | None:
        current = time.monotonic() if now is None else now
        snapshots = self._menu_snapshots.get(user_id)
        if snapshots is None:
            return None
        self._prune_menus(snapshots, current)
        return snapshots.get(revision)

    def _prune_menus(self, snapshots: dict[str, MenuSnapshot], now: float) -> None:
        expired = [
            revision
            for revision, snapshot in snapshots.items()
            if now - snapshot.created_at >= self._menu_ttl_seconds
        ]
        for revision in expired:
            del snapshots[revision]
