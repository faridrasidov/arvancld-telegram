"""Authentication recovery and mutation-safety tests."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from arvancld import (
    APIError,
    APIValidationIssue,
    AuthenticationError,
    InvalidResponseError,
    LoginResult,
    NetworkError,
    TOTPRequiredError,
)
from arvancld.auth import AsyncAuthService
from arvancld.auth.session import load_session_file, save_session_file
from arvancld.config import ClientConfig

from arvancld_telegram import gateway as gateway_module
from arvancld_telegram.config import Settings
from arvancld_telegram.gateway import (
    ArvanCloudGateway,
    AuthenticationBusyError,
    AuthenticationState,
    InteractiveAuthenticationRequired,
    OTPFlowExpiredError,
    OTPRejectedError,
    OTPSubmissionUncertainError,
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


def fake_client(*, authenticated: bool = True) -> SimpleNamespace:
    auth = SimpleNamespace(
        tokens=object() if authenticated else None,
        pending_totp=None,
        aload_session=AsyncMock(),
        asave_session=AsyncMock(),
        login=AsyncMock(),
        submit_totp=AsyncMock(),
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


def login_result(*, expires_in: timedelta, suffix: str = "old") -> LoginResult:
    return LoginResult(
        access_token=f"access-{suffix}",
        refresh_token=f"refresh-{suffix}",
        expires_at=datetime.now(UTC) + expires_in,
        default_account=UUID("00000000-0000-4000-8000-000000000002"),
        flow="ProvideCredential",
        next="RedirectToPanel",
    )


class AuthTransport:
    """Stand-in for the SDK transport behind a real AsyncAuthService."""

    def __init__(self, *, refresh_error: Exception | None = None) -> None:
        self.refresh_error = refresh_error
        self.paths: list[str] = []
        self.refresh_bodies: list[object] = []

    async def request_model(self, method, url, *, model, json=None, params=None, headers=None):
        path = urlsplit(url).path
        self.paths.append(path)
        if path.endswith("/refresh-token"):
            self.refresh_bodies.append(json)
            if self.refresh_error is not None:
                raise self.refresh_error
            renewed = login_result(expires_in=timedelta(hours=12), suffix="new")
            data = renewed.model_dump(mode="json", by_alias=True)
        else:
            data = {"flow": "f", "next": "ChallengeTOTPPossession", "flowToken": "t"}
        return model.model_validate({"data": data})


def sdk_auth_client(transport: AuthTransport) -> SimpleNamespace:
    client = fake_client(authenticated=False)
    client.auth = AsyncAuthService(transport, ClientConfig())
    return client


def require_totp(auth: SimpleNamespace):
    async def challenge(*_args) -> None:
        auth.pending_totp = object()
        raise TOTPRequiredError("OTP required")

    return challenge


def complete_totp(auth: SimpleNamespace):
    async def complete(_code: str) -> None:
        auth.pending_totp = None
        auth.tokens = object()

    return complete


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


async def test_start_enters_otp_mode_without_validating_domains(tmp_path) -> None:
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    result = await gateway.start()

    assert result is AuthenticationState.OTP_REQUIRED
    assert gateway.auth_status == "OTP required"
    assert gateway.challenge_revision == 1
    client.cdn.domains.list.assert_not_awaited()


async def test_start_enters_otp_mode_after_loaded_session_recovery(tmp_path) -> None:
    client = fake_client()
    client.cdn.domains.list.side_effect = AuthenticationError(status_code=401)
    client.auth.refresh.side_effect = AuthenticationError(status_code=401)
    client.auth.login.side_effect = require_totp(client.auth)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    result = await gateway.start()

    assert result is AuthenticationState.OTP_REQUIRED
    client.cdn.domains.list.assert_awaited_once()
    client.auth.refresh.assert_awaited_once()
    client.auth.login.assert_awaited_once()


async def test_start_refreshes_expired_saved_session_without_password_login(
    tmp_path, caplog
) -> None:
    caplog.set_level(logging.INFO, logger="arvancld_telegram.gateway")
    transport = AuthTransport()
    client = sdk_auth_client(transport)
    config = settings(tmp_path)
    save_session_file(config.arvancld_session_path, login_result(expires_in=timedelta(hours=-36)))
    gateway = ArvanCloudGateway(config, client=client)

    assert await gateway.start() is AuthenticationState.CONNECTED

    assert transport.paths == ["/v1/auth/refresh-token"]
    assert transport.refresh_bodies == [{"refreshToken": "refresh-old"}]
    saved = load_session_file(config.arvancld_session_path)
    assert saved.refresh_token == "refresh-new"
    assert saved.expires_at > datetime.now(UTC)
    client.cdn.domains.list.assert_awaited_once_with(page=1, per_page=1)
    assert gateway.challenge_revision == 0
    assert "refresh-old" not in caplog.text
    assert "refresh-new" not in caplog.text


@pytest.mark.parametrize(
    "refresh_error",
    [AuthenticationError(status_code=401), APIError(status_code=400)],
)
async def test_start_logs_in_when_expired_session_refresh_is_rejected(
    tmp_path, refresh_error
) -> None:
    transport = AuthTransport(refresh_error=refresh_error)
    client = sdk_auth_client(transport)
    config = settings(tmp_path)
    save_session_file(config.arvancld_session_path, login_result(expires_in=timedelta(hours=-1)))
    gateway = ArvanCloudGateway(config, client=client)

    assert await gateway.start() is AuthenticationState.OTP_REQUIRED

    assert transport.paths == ["/v1/auth/refresh-token", "/v1/auth/login"]
    assert client.auth.tokens is None
    assert client.auth.pending_totp is not None
    assert gateway.challenge_revision == 1


async def test_start_keeps_expired_session_when_refresh_cannot_reach_arvancloud(
    tmp_path,
) -> None:
    transport = AuthTransport(refresh_error=NetworkError("network failed"))
    client = sdk_auth_client(transport)
    config = settings(tmp_path)
    save_session_file(config.arvancld_session_path, login_result(expires_in=timedelta(hours=-1)))
    gateway = ArvanCloudGateway(config, client=client)

    with pytest.raises(NetworkError):
        await gateway.start()

    assert transport.paths == ["/v1/auth/refresh-token"]
    assert gateway.auth_state is AuthenticationState.UNAVAILABLE
    assert "refresh-old" in config.arvancld_session_path.read_text(encoding="utf-8")


async def test_valid_totp_saves_validates_and_connects(tmp_path, caplog) -> None:
    caplog.set_level(logging.INFO, logger="arvancld_telegram.gateway")
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    client.auth.submit_totp.side_effect = complete_totp(client.auth)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    await gateway.start()
    await gateway.begin_authentication(1)

    await gateway.submit_totp(1, "246810")

    assert gateway.connected
    client.auth.submit_totp.assert_awaited_once_with("246810")
    client.auth.asave_session.assert_awaited_once()
    client.cdn.domains.list.assert_awaited_once_with(page=1, per_page=1)
    events = [
        record.message.split("event=", 1)[1].split(" ", 1)[0]
        for record in caplog.records
        if "event=" in record.message
    ]
    assert events == [
        "password_login_started",
        "totp_required",
        "totp_claimed",
        "totp_sdk_submission_started",
        "totp_sdk_submission_accepted",
        "session_save_started",
        "session_saved",
        "cdn_validation_started",
        "cdn_validation_completed",
    ]
    attempt_ids = {
        part.split("=", 1)[1]
        for record in caplog.records
        for part in record.message.split()
        if part.startswith("attempt_id=")
    }
    assert len(attempt_ids) == 1
    assert "246810" not in caplog.text
    assert "secret" not in caplog.text


async def test_first_admin_owns_challenge_until_cancel(tmp_path) -> None:
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    await gateway.start()
    await gateway.begin_authentication(1)

    with pytest.raises(AuthenticationBusyError):
        await gateway.begin_authentication(2)

    assert await gateway.cancel_authentication(1)
    assert not await gateway.cancel_authentication(2)
    assert await gateway.begin_authentication(2) is AuthenticationState.OTP_REQUIRED
    assert client.auth.login.await_count == 2


async def test_otp_owner_expiry_requires_a_fresh_login(tmp_path) -> None:
    now = [100.0]
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client, clock=lambda: now[0])
    await gateway.start()
    await gateway.begin_authentication(1)
    now[0] += 301

    with pytest.raises(OTPFlowExpiredError):
        await gateway.submit_totp(1, "246810")

    assert await gateway.begin_authentication(2) is AuthenticationState.OTP_REQUIRED
    assert client.auth.login.await_count == 2


@pytest.mark.parametrize(
    "api_error",
    [
        APIError(status_code=400),
        AuthenticationError(status_code=401),
        AuthenticationError(status_code=403),
        APIError(status_code=422),
    ],
)
async def test_rejected_totp_is_single_attempt_and_keeps_owner(tmp_path, api_error) -> None:
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    client.auth.submit_totp.side_effect = api_error
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    await gateway.start()
    await gateway.begin_authentication(1)

    with pytest.raises(OTPRejectedError):
        await gateway.submit_totp(1, "246810")

    assert gateway.auth_state is AuthenticationState.OTP_REQUIRED
    client.auth.submit_totp.assert_awaited_once()
    with pytest.raises(AuthenticationBusyError):
        await gateway.begin_authentication(2)


async def test_422_totp_logs_only_safe_diagnostics_and_keeps_challenge(tmp_path, caplog) -> None:
    caplog.set_level(logging.DEBUG, logger="arvancld_telegram.gateway")
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    client.auth.submit_totp.side_effect = APIError(
        status_code=422,
        request_id="request-422",
        response_content_type="application/json",
        response_size=321,
        response_fields=("detail",),
        validation_issues=(APIValidationIssue(("body", "challenge", "code"), "missing"),),
    )
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    await gateway.start()
    await gateway.begin_authentication(1)

    with pytest.raises(OTPRejectedError):
        await gateway.submit_totp(1, "246810")

    assert gateway.auth_state is AuthenticationState.OTP_REQUIRED
    client.auth.submit_totp.assert_awaited_once_with("246810")
    assert "status=422" in caplog.text
    assert "request_id=request-422" in caplog.text
    assert "content_type=application/json" in caplog.text
    assert "body_size=321" in caplog.text
    assert "('body', 'challenge', 'code')" in caplog.text
    assert "missing" in caplog.text
    assert "246810" not in caplog.text
    assert "secret" not in caplog.text


async def test_uncertain_totp_is_not_retried_and_forces_fresh_login(tmp_path) -> None:
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    client.auth.submit_totp.side_effect = NetworkError("network failed")
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    await gateway.start()
    await gateway.begin_authentication(1)

    with pytest.raises(OTPSubmissionUncertainError):
        await gateway.submit_totp(1, "246810")
    with pytest.raises(OTPFlowExpiredError):
        await gateway.submit_totp(1, "246810")

    client.auth.submit_totp.assert_awaited_once()


async def test_invalid_success_response_is_logged_without_body_and_forces_fresh_login(
    tmp_path, caplog
) -> None:
    caplog.set_level(logging.INFO, logger="arvancld_telegram.gateway")
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    client.auth.submit_totp.side_effect = InvalidResponseError(
        "response contained 246810 provider-message-do-not-log"
    )
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    await gateway.start()
    await gateway.begin_authentication(1)

    with pytest.raises(OTPSubmissionUncertainError):
        await gateway.submit_totp(1, "246810")

    client.auth.submit_totp.assert_awaited_once_with("246810")
    assert "event=totp_sdk_submission_invalid_response" in caplog.text
    assert "246810" not in caplog.text
    assert "provider-message-do-not-log" not in caplog.text
    with pytest.raises(OTPFlowExpiredError):
        await gateway.submit_totp(1, "246810")


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


async def test_recovered_record_lookup_uses_existing_auth_refresh(
    tmp_path, dns_record_factory
) -> None:
    client = fake_client()
    record = dns_record_factory()
    response = SimpleNamespace(
        data=[record],
        meta=SimpleNamespace(last_page=1, total=1),
    )
    client.cdn.dns_records.list.side_effect = [
        AuthenticationError(status_code=401),
        response,
    ]
    old_tokens = client.auth.tokens

    async def refresh() -> None:
        client.auth.tokens = object()

    client.auth.refresh.side_effect = refresh
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    result = await gateway.find_record("example.test", str(record.id))

    assert result is record
    assert client.auth.tokens is not old_tokens
    client.auth.refresh.assert_awaited_once()
    assert client.cdn.dns_records.list.await_count == 2


@pytest.mark.parametrize(
    "refresh_error",
    [AuthenticationError(status_code=401), APIError(status_code=400)],
)
async def test_rejected_refresh_logs_in_once_then_retries(tmp_path, refresh_error) -> None:
    client = fake_client()
    response = page()
    client.cdn.domains.list.side_effect = [
        AuthenticationError(status_code=403),
        response,
    ]
    client.auth.refresh.side_effect = refresh_error
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


async def test_mutation_interrupted_by_totp_is_not_replayed(tmp_path) -> None:
    client = fake_client()
    client.cdn.dns_records.create.side_effect = AuthenticationError(status_code=401)
    client.auth.refresh.side_effect = AuthenticationError(status_code=401)
    client.auth.login.side_effect = require_totp(client.auth)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    with pytest.raises(InteractiveAuthenticationRequired):
        await gateway.create_record("example.test", SimpleNamespace())

    assert gateway.auth_state is AuthenticationState.OTP_REQUIRED
    client.cdn.dns_records.create.assert_awaited_once()
    client.auth.refresh.assert_awaited_once()
    client.auth.login.assert_awaited_once()


async def test_concurrent_auth_failures_share_one_totp_recovery(tmp_path) -> None:
    client = fake_client()
    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()
    client.cdn.domains.list.side_effect = AuthenticationError(status_code=401)

    async def rejected_refresh() -> None:
        refresh_started.set()
        await release_refresh.wait()
        raise AuthenticationError(status_code=401)

    client.auth.refresh.side_effect = rejected_refresh
    client.auth.login.side_effect = require_totp(client.auth)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)

    first = asyncio.create_task(gateway.list_domains(page=1))
    await refresh_started.wait()
    second = asyncio.create_task(gateway.list_domains(page=1))
    release_refresh.set()

    results = await asyncio.gather(first, second, return_exceptions=True)

    assert all(isinstance(result, InteractiveAuthenticationRequired) for result in results)
    client.auth.refresh.assert_awaited_once()
    client.auth.login.assert_awaited_once()


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


class StopRefresher(BaseException):
    """Ends the otherwise endless refresher loop from inside a fake sleep."""


def fake_sleeps(monkeypatch, *, stop_after: int) -> list[float]:
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) >= stop_after:
            raise StopRefresher

    monkeypatch.setattr(gateway_module.asyncio, "sleep", sleep)
    return sleeps


async def test_session_refresher_rotates_tokens_before_expiry(tmp_path, monkeypatch) -> None:
    client = fake_client()
    client.auth.tokens = login_result(expires_in=timedelta(minutes=10))

    async def refresh() -> None:
        client.auth.tokens = login_result(expires_in=timedelta(hours=12), suffix="new")

    client.auth.refresh.side_effect = refresh
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    sleeps = fake_sleeps(monkeypatch, stop_after=2)

    with pytest.raises(StopRefresher):
        await gateway.keep_session_fresh()

    assert sleeps == [0.0, gateway_module.TOKEN_REFRESH_MAX_SLEEP_SECONDS]
    client.auth.refresh.assert_awaited_once()
    client.auth.asave_session.assert_awaited_once()
    assert gateway.connected


async def test_session_refresher_waits_until_refresh_is_due(tmp_path, monkeypatch) -> None:
    client = fake_client()
    client.auth.tokens = login_result(expires_in=timedelta(minutes=33))
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    sleeps = fake_sleeps(monkeypatch, stop_after=1)

    with pytest.raises(StopRefresher):
        await gateway.keep_session_fresh()

    assert 0 < sleeps[0] <= 3 * 60
    client.auth.refresh.assert_not_awaited()


async def test_session_refresher_is_idle_while_otp_is_required(tmp_path, monkeypatch) -> None:
    client = fake_client(authenticated=False)
    client.auth.aload_session.side_effect = FileNotFoundError
    client.auth.login.side_effect = require_totp(client.auth)
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    await gateway.start()
    sleeps = fake_sleeps(monkeypatch, stop_after=3)

    with pytest.raises(StopRefresher):
        await gateway.keep_session_fresh()

    assert sleeps == [gateway_module.TOKEN_REFRESH_MAX_SLEEP_SECONDS] * 3
    client.auth.refresh.assert_not_awaited()


async def test_session_refresher_survives_failures_without_password_login(
    tmp_path, monkeypatch
) -> None:
    client = fake_client()
    client.auth.tokens = login_result(expires_in=timedelta(minutes=10))
    client.auth.refresh.side_effect = [
        NetworkError("network failed"),
        AuthenticationError(status_code=401),
    ]
    gateway = ArvanCloudGateway(settings(tmp_path), client=client)
    sleeps = fake_sleeps(monkeypatch, stop_after=5)

    with pytest.raises(StopRefresher):
        await gateway.keep_session_fresh()

    retry = gateway_module.TOKEN_REFRESH_RETRY_SECONDS
    assert sleeps == [0.0, retry, 0.0, retry, 0.0]
    assert client.auth.refresh.await_count == 2
    client.auth.login.assert_not_awaited()
    assert gateway.connected
