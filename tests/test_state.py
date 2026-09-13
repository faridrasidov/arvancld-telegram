"""Conversation state and callback protocol tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from arvancld_telegram.state import (
    Confirmation,
    ConversationStore,
    Draft,
    callback_data,
    parse_callback,
)


def test_callback_round_trip_and_bound() -> None:
    encoded = callback_data("rs", "abcdef", 7)

    assert parse_callback(encoded) == ("rs", "abcdef", "7")
    assert len(encoded.encode()) <= 64


def test_callback_rejects_invalid_or_oversized_values() -> None:
    with pytest.raises(ValueError):
        parse_callback("")
    with pytest.raises(ValueError):
        callback_data("record", "abcdef", "x" * 64)


def test_state_is_isolated_and_expires() -> None:
    store = ConversationStore(ttl_seconds=10)
    first = store.get(1, now=100)
    second = store.get(2, now=100)
    first.selected_domain = "one.example"
    second.selected_domain = "two.example"

    assert store.get(1, now=105).selected_domain == "one.example"
    assert store.get(2, now=105).selected_domain == "two.example"
    assert store.get(1, now=116).selected_domain is None


def test_confirmation_expiry_can_be_evaluated_deterministically() -> None:
    confirmation = Confirmation(kind="delete", domain="example.test", expires_at=50)

    assert not confirmation.is_expired(now=49)
    assert confirmation.is_expired(now=50)


def test_menu_snapshot_outlives_transient_state_and_restores_navigation(
    dns_record_factory,
) -> None:
    store = ConversationStore(ttl_seconds=10, menu_ttl_seconds=100)
    state = store.get(1, now=0)
    state.revision = "menu01"
    state.domain_page = 3
    state.domains = [SimpleNamespace(domain="example.test")]
    state.selected_domain = "example.test"
    state.record_page = 4
    state.records = [dns_record_factory()]
    state.search = "www"
    state.record_type_filter = "A"
    snapshot = store.remember_menu(1, state, view="records", now=1)

    expired_state = store.get(1, now=11)

    assert expired_state.selected_domain is None
    assert store.get_menu(1, snapshot.revision, now=50) == snapshot
    expired_state.flow = "edit_ttl"
    expired_state.draft = Draft(mode="update")
    expired_state.confirmation = Confirmation(kind="delete", domain="example.test")
    expired_state.restore_menu(snapshot)
    assert expired_state.selected_domain == "example.test"
    assert expired_state.record_page == 4
    assert expired_state.search == "www"
    assert expired_state.record_type_filter == "A"
    assert expired_state.flow is None
    assert expired_state.draft is None
    assert expired_state.confirmation is None


def test_menu_snapshot_expires_at_configured_boundary() -> None:
    store = ConversationStore(menu_ttl_seconds=100)
    state = store.get(1, now=0)
    state.revision = "menu01"
    store.remember_menu(1, state, view="domains", now=1)

    assert store.get_menu(1, "menu01", now=100) is not None
    assert store.get_menu(1, "menu01", now=101) is None


def test_menu_snapshots_are_bounded_to_newest_32() -> None:
    store = ConversationStore(max_menu_snapshots=32)
    state = store.get(1, now=0)

    for index in range(33):
        state.revision = f"m{index:05d}"
        store.remember_menu(1, state, view="domains", now=index)

    assert store.get_menu(1, "m00000", now=33) is None
    assert store.get_menu(1, "m00001", now=33) is not None
    assert store.get_menu(1, "m00032", now=33) is not None


def test_menu_snapshots_are_isolated_by_administrator() -> None:
    store = ConversationStore()
    first = store.get(1, now=0)
    second = store.get(2, now=0)
    first.revision = second.revision = "shared"
    first.domains = [SimpleNamespace(domain="one.example")]
    second.domains = [SimpleNamespace(domain="two.example")]

    first_snapshot = store.remember_menu(1, first, view="domains", now=1)
    second_snapshot = store.remember_menu(2, second, view="domains", now=1)

    assert first_snapshot.domain_names == ("one.example",)
    assert second_snapshot.domain_names == ("two.example",)
    assert store.get_menu(1, "shared", now=2) == first_snapshot
    assert store.get_menu(2, "shared", now=2) == second_snapshot


def test_confirmation_snapshot_contains_navigation_but_no_mutation_token(
    dns_record_factory,
) -> None:
    store = ConversationStore()
    state = store.get(1, now=0)
    state.revision = "confirm"
    record = dns_record_factory()
    state.selected_domain = "example.test"
    state.selected_record = record
    state.confirmation = Confirmation(kind="delete", domain="example.test")

    snapshot = store.remember_menu(
        1,
        state,
        view="confirmation",
        selected_record_id=str(record.id),
        now=1,
    )

    assert snapshot.selected_domain == "example.test"
    assert snapshot.selected_record_id == str(record.id)
    assert not hasattr(snapshot, "token")
    assert not hasattr(snapshot, "confirmation")
