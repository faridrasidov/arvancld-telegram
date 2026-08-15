"""Authentication recovery and mutation-safety tests."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from arvancld import AuthenticationError, NetworkError

from arvancld_telegram.config import Settings
from arvancld_telegram.gateway import (
    ArvanCloudGateway,
    ProtectedRecordError,
    StaleRecordError,
)


def settings(tmp_path) -> Settings:
    return Settings(
        telegram_bot_token="123:test",
        telegram_admin_ids=frozenset({1}),
        arvancld_email="admin@example.test",
        arvancld_password="secret",
        arvancld_session_path=tmp_path / "session.json",
    )


def page() -> SimpleNamespace:
    return SimpleNamespace(data=[], meta=SimpleNamespace(last_page=1, total=0))


def fake_client() -> SimpleNamespace:
    auth = SimpleNamespace(
        tokens=object(),
        aload_session=AsyncMock(),
        asave_session=AsyncMock(),
        login=AsyncMock(),
        refresh=AsyncMock(),
    )
    dns_records = SimpleNamespace(
        list=AsyncMock(return_value=page()),
        create=AsyncMock(),
        update=AsyncMock(),
        set_cloud=AsyncMock(),
        delete=AsyncMock(),
    )
    domains = SimpleNamespace(list=AsyncMock(return_value=page()))
    return SimpleNamespace(
        auth=auth,
        cdn=SimpleNamespace(domains=domains, dns_records=dns_records),
        is_closed=False,
        close=AsyncMock(),
    )


async def test_start_uses_loaded_session_and_validates_access(tmp_path) -> None:
    client = fake_client()
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    await gateway.start()

    client.auth.aload_session.assert_awaited_once()
    client.auth.login.assert_not_awaited()
    client.cdn.domains.list.assert_awaited_once_with(page=1, per_page=1)


async def test_start_logs_in_when_session_is_missing(tmp_path) -> None:
    client = fake_client()
    client.auth.aload_session.side_effect = FileNotFoundError
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    await gateway.start()

    client.auth.login.assert_awaited_once_with("admin@example.test", "secret")
    client.auth.asave_session.assert_awaited_once()


async def test_authentication_failure_refreshes_and_retries_once(tmp_path) -> None:
    client = fake_client()
    response = page()
    client.cdn.domains.list.side_effect = [
        AuthenticationError(status_code=401),
        response,
    ]
    old_tokens = client.auth.tokens

    async def refresh() -> None:
        client.auth.tokens = object()

    client.auth.refresh.side_effect = refresh
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    assert await gateway.list_domains(page=1) is response
    assert client.auth.tokens is not old_tokens
    client.auth.refresh.assert_awaited_once()
    assert client.cdn.domains.list.await_count == 2


async def test_rejected_refresh_logs_in_once_then_retries(tmp_path) -> None:
    client = fake_client()
    response = page()
    client.cdn.domains.list.side_effect = [
        AuthenticationError(status_code=403),
        response,
    ]
    client.auth.refresh.side_effect = AuthenticationError(status_code=401)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    assert await gateway.list_domains(page=1) is response
    client.auth.refresh.assert_awaited_once()
    client.auth.login.assert_awaited_once()


async def test_network_failure_during_mutation_is_not_retried(tmp_path) -> None:
    client = fake_client()
    client.cdn.dns_records.create.side_effect = NetworkError("network failed")
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    with pytest.raises(NetworkError):
        await gateway.create_record("example.test", SimpleNamespace())

    client.cdn.dns_records.create.assert_awaited_once()
    client.auth.refresh.assert_not_awaited()


async def test_current_record_guard_rejects_stale_and_protected(
    tmp_path, dns_record_factory, monkeypatch
) -> None:
    client = fake_client()
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    record = dns_record_factory()
    monkeypatch.setattr(gateway, "find_record", AsyncMock(return_value=record))

    with pytest.raises(StaleRecordError):
        await gateway.require_current_record("example.test", str(record.id), object())

    protected = dns_record_factory(is_protected=True)
    monkeypatch.setattr(gateway, "find_record", AsyncMock(return_value=protected))
    with pytest.raises(ProtectedRecordError):
        await gateway.require_current_record(
            "example.test", str(protected.id), protected.updated_at
        )
