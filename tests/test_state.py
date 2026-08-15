"""Conversation state and callback protocol tests."""

from __future__ import annotations

import pytest

from arvancld_telegram.state import (
    Confirmation,
    ConversationStore,
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
