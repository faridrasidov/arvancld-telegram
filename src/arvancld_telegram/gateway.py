"""Authenticated ArvanCloud SDK gateway with interactive TOTP recovery."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from pathlib import Path
from typing import TypeVar

from arvancld import (
    APIError,
    AsyncArvanCloud,
    AuthenticationError,
    DNSRecord,
    DNSRecordCreate,
    DNSRecordDeleteResult,
    DNSRecordPage,
    DNSRecordUpdate,
    InvalidResponseError,
    InvalidSessionError,
    NetworkError,
    SessionExpiredError,
    TOTPRequiredError,
)
from arvancld.cdn.models import CDNDomainPage

from arvancld_telegram.config import Settings

logger = logging.getLogger(__name__)
ResultT = TypeVar("ResultT")
OTP_OWNER_TTL_SECONDS = 5 * 60


class AuthenticationState(str, Enum):
    """Account connectivity visible to Telegram administrators."""

    CONNECTED = "connected"
    OTP_REQUIRED = "OTP required"
    AUTHENTICATING = "authenticating"
    UNAVAILABLE = "unavailable"


class InteractiveAuthenticationRequired(RuntimeError):
    """Raised when an operation must stop for interactive account login."""


class AuthenticationBusyError(RuntimeError):
    """Raised when another administrator owns the current OTP prompt."""


class OTPFlowExpiredError(RuntimeError):
    """Raised when the administrator must start a fresh login challenge."""


class OTPRejectedError(RuntimeError):
    """Raised when ArvanCloud rejects a submitted OTP."""


class OTPSubmissionUncertainError(RuntimeError):
    """Raised when an OTP request has an unknown network outcome."""


class StaleRecordError(RuntimeError):
    """Raised when a record changed after it was selected for mutation."""


class ProtectedRecordError(RuntimeError):
    """Raised when a protected provider record is selected for mutation."""


class ArvanCloudGateway:
    """Expose bot operations while centralizing authentication recovery."""

    def __init__(
        self,
        settings: Settings,
        client: AsyncArvanCloud | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._client = client or AsyncArvanCloud()
        self._session_path = Path(settings.arvancld_session_path)
        self._auth_lock = asyncio.Lock()
        self._clock = clock
        self._auth_state = (
            AuthenticationState.CONNECTED
            if client is not None and client.auth.tokens is not None and not client.is_closed
            else AuthenticationState.UNAVAILABLE
        )
        self._otp_owner_id: int | None = None
        self._otp_owner_expires_at = 0.0
        self._otp_requires_restart = False
        self._challenge_revision = 0
        self._auth_attempt_id: str | None = None

    @property
    def auth_state(self) -> AuthenticationState:
        return self._auth_state

    @property
    def auth_status(self) -> str:
        return self._auth_state.value

    @property
    def challenge_revision(self) -> int:
        """Monotonic identifier used to avoid duplicate admin notifications."""

        return self._challenge_revision

    @property
    def auth_attempt_id(self) -> str | None:
        """Opaque correlation identifier for the current authentication attempt."""

        return self._auth_attempt_id

    @property
    def connected(self) -> bool:
        return (
            self._auth_state is AuthenticationState.CONNECTED
            and self._client.auth.tokens is not None
            and not self._client.is_closed
        )

    @property
    def otp_required(self) -> bool:
        return self._auth_state is AuthenticationState.OTP_REQUIRED

    async def start(self) -> AuthenticationState:
        """Restore or create a session and validate CDN access when possible."""

        self._auth_state = AuthenticationState.AUTHENTICATING
        try:
            try:
                await self._client.auth.aload_session(self._session_path)
                logger.info("loaded ArvanCloud session path=%s", self._session_path)
            except (FileNotFoundError, InvalidSessionError, SessionExpiredError):
                try:
                    await self._login_and_save()
                except TOTPRequiredError:
                    self._set_totp_required()
                    return self._auth_state

            try:
                self._log_validation_started()
                await self._call(
                    lambda: self._client.cdn.domains.list(page=1, per_page=1),
                    require_ready=False,
                )
                self._log_validation_completed()
            except InteractiveAuthenticationRequired:
                return self._auth_state
        except Exception:
            self._auth_state = AuthenticationState.UNAVAILABLE
            raise

        self._mark_connected()
        return self._auth_state

    async def close(self) -> None:
        await self._client.close()

    async def begin_authentication(self, actor_id: int) -> AuthenticationState:
        """Claim an existing challenge or initiate a fresh account login."""

        async with self._auth_lock:
            self._expire_otp_owner()
            if self.connected:
                return self._auth_state

            if self._active_otp_owner_is_other(actor_id):
                raise AuthenticationBusyError(
                    "Another administrator is completing ArvanCloud authentication"
                )

            pending = self._client.auth.pending_totp
            if self.otp_required and pending is not None and not self._otp_requires_restart:
                self._claim_otp(actor_id)
                return self._auth_state

            try:
                await self._login_and_save()
            except TOTPRequiredError:
                self._set_totp_required(owner_id=actor_id)
                return self._auth_state
            except Exception:
                self._auth_state = AuthenticationState.UNAVAILABLE
                self._clear_otp_owner()
                raise

            try:
                await self._validate_access_once()
            except Exception:
                self._auth_state = AuthenticationState.UNAVAILABLE
                self._clear_otp_owner()
                raise

            self._mark_connected()
            return self._auth_state

    async def submit_totp(self, actor_id: int, code: str) -> None:
        """Submit one OTP request, save its session, and validate CDN access."""

        async with self._auth_lock:
            self._expire_otp_owner()
            if self._otp_owner_id is None or self._otp_requires_restart:
                raise OTPFlowExpiredError("The OTP prompt expired; run /auth again")
            if self._otp_owner_id != actor_id:
                raise AuthenticationBusyError(
                    "Another administrator is completing ArvanCloud authentication"
                )
            if not self.otp_required or self._client.auth.pending_totp is None:
                raise OTPFlowExpiredError("The OTP prompt expired; run /auth again")

            attempt_id = self._attempt_id()
            revision = self._challenge_revision
            started_at = time.perf_counter()
            self._auth_state = AuthenticationState.AUTHENTICATING
            logger.info(
                "auth event=totp_sdk_submission_started attempt_id=%s "
                "challenge_revision=%s actor_id=%s",
                attempt_id,
                revision,
                actor_id,
            )
            try:
                await self._client.auth.submit_totp(code)
            except ValueError:
                self._auth_state = AuthenticationState.OTP_REQUIRED
                logger.warning(
                    "auth event=totp_sdk_submission_rejected attempt_id=%s "
                    "challenge_revision=%s actor_id=%s reason=format elapsed_ms=%s",
                    attempt_id,
                    revision,
                    actor_id,
                    self._elapsed_ms(started_at),
                )
                raise
            except AuthenticationError as exc:
                self._auth_state = AuthenticationState.OTP_REQUIRED
                self._log_api_rejection(exc, actor_id=actor_id, started_at=started_at)
                raise OTPRejectedError("The OTP was rejected or expired") from exc
            except APIError as exc:
                self._auth_state = AuthenticationState.OTP_REQUIRED
                self._log_api_rejection(exc, actor_id=actor_id, started_at=started_at)
                if exc.status_code in {400, 422}:
                    raise OTPRejectedError("The OTP was rejected or expired") from exc
                raise
            except InvalidResponseError as exc:
                logger.warning(
                    "auth event=totp_sdk_submission_invalid_response attempt_id=%s "
                    "challenge_revision=%s actor_id=%s elapsed_ms=%s",
                    attempt_id,
                    revision,
                    actor_id,
                    self._elapsed_ms(started_at),
                )
                self._abandon_otp_for_restart()
                raise OTPSubmissionUncertainError(
                    "The OTP response could not be validated; start a fresh login"
                ) from exc
            except NetworkError as exc:
                logger.warning(
                    "auth event=totp_sdk_submission_uncertain attempt_id=%s "
                    "challenge_revision=%s actor_id=%s elapsed_ms=%s",
                    attempt_id,
                    revision,
                    actor_id,
                    self._elapsed_ms(started_at),
                )
                self._abandon_otp_for_restart()
                raise OTPSubmissionUncertainError(
                    "The OTP result is unknown; start a fresh login"
                ) from exc

            logger.info(
                "auth event=totp_sdk_submission_accepted attempt_id=%s "
                "challenge_revision=%s actor_id=%s status=success "
                "request_id=unavailable elapsed_ms=%s",
                attempt_id,
                revision,
                actor_id,
                self._elapsed_ms(started_at),
            )

            try:
                await self._save_session()
                await self._validate_access_once()
            except Exception as exc:
                self._log_post_submission_failure(exc)
                self._auth_state = AuthenticationState.UNAVAILABLE
                self._clear_otp_owner()
                raise

            self._mark_connected()

    async def cancel_authentication(self, actor_id: int) -> bool:
        """Release an owned challenge and require a fresh login next time."""

        async with self._auth_lock:
            self._expire_otp_owner()
            if self._otp_owner_id != actor_id:
                return False
            logger.info(
                "auth event=totp_cancelled attempt_id=%s challenge_revision=%s actor_id=%s",
                self._attempt_id(),
                self._challenge_revision,
                actor_id,
            )
            self._abandon_otp_for_restart()
            return True

    async def _login_and_save(self) -> None:
        self._auth_state = AuthenticationState.AUTHENTICATING
        self._auth_attempt_id = secrets.token_hex(6)
        logger.info(
            "auth event=password_login_started attempt_id=%s",
            self._auth_attempt_id,
        )
        await self._client.auth.login(
            self._settings.arvancld_email,
            self._settings.arvancld_password,
        )
        logger.info(
            "auth event=password_login_accepted attempt_id=%s",
            self._auth_attempt_id,
        )
        await self._save_session()

    async def _save_session(self) -> None:
        logger.info(
            "auth event=session_save_started attempt_id=%s challenge_revision=%s",
            self._attempt_id(),
            self._challenge_revision,
        )
        await self._client.auth.asave_session(self._session_path)
        logger.info(
            "auth event=session_saved attempt_id=%s challenge_revision=%s",
            self._attempt_id(),
            self._challenge_revision,
        )

    async def _validate_access_once(self) -> None:
        self._log_validation_started()
        await self._client.cdn.domains.list(page=1, per_page=1)
        self._log_validation_completed()

    def _set_totp_required(self, owner_id: int | None = None) -> None:
        self._auth_state = AuthenticationState.OTP_REQUIRED
        self._otp_requires_restart = False
        self._challenge_revision += 1
        self._clear_otp_owner()
        logger.info(
            "auth event=totp_required attempt_id=%s challenge_revision=%s",
            self._attempt_id(),
            self._challenge_revision,
        )
        if owner_id is not None:
            self._claim_otp(owner_id)

    def _mark_connected(self) -> None:
        self._auth_state = AuthenticationState.CONNECTED
        self._otp_requires_restart = False
        self._clear_otp_owner()

    def _claim_otp(self, actor_id: int) -> None:
        self._otp_owner_id = actor_id
        self._otp_owner_expires_at = self._clock() + OTP_OWNER_TTL_SECONDS
        logger.info(
            "auth event=totp_claimed attempt_id=%s challenge_revision=%s "
            "actor_id=%s lease_seconds=%s",
            self._attempt_id(),
            self._challenge_revision,
            actor_id,
            OTP_OWNER_TTL_SECONDS,
        )

    def _clear_otp_owner(self) -> None:
        self._otp_owner_id = None
        self._otp_owner_expires_at = 0.0

    def _abandon_otp_for_restart(self) -> None:
        self._auth_state = AuthenticationState.OTP_REQUIRED
        self._otp_requires_restart = True
        self._clear_otp_owner()

    def _expire_otp_owner(self) -> None:
        if self._otp_owner_id is None or self._clock() < self._otp_owner_expires_at:
            return
        logger.warning(
            "auth event=totp_ownership_expired attempt_id=%s challenge_revision=%s actor_id=%s",
            self._attempt_id(),
            self._challenge_revision,
            self._otp_owner_id,
        )
        self._abandon_otp_for_restart()

    def _active_otp_owner_is_other(self, actor_id: int) -> bool:
        return self._otp_owner_id is not None and self._otp_owner_id != actor_id

    def _attempt_id(self) -> str:
        if self._auth_attempt_id is None:
            self._auth_attempt_id = secrets.token_hex(6)
        return self._auth_attempt_id

    @staticmethod
    def _elapsed_ms(started_at: float) -> int:
        return max(0, round((time.perf_counter() - started_at) * 1000))

    def _log_api_rejection(
        self,
        exc: APIError,
        *,
        actor_id: int,
        started_at: float,
    ) -> None:
        logger.warning(
            "auth event=totp_sdk_submission_rejected attempt_id=%s "
            "challenge_revision=%s actor_id=%s status=%s request_id=%s elapsed_ms=%s",
            self._attempt_id(),
            self._challenge_revision,
            actor_id,
            exc.status_code,
            exc.request_id or "unavailable",
            self._elapsed_ms(started_at),
        )
        logger.debug(
            "auth event=totp_sdk_submission_diagnostics attempt_id=%s "
            "challenge_revision=%s content_type=%s body_size=%s fields=%s issues=%s",
            self._attempt_id(),
            self._challenge_revision,
            exc.response_content_type or "unavailable",
            exc.response_size,
            exc.response_fields,
            tuple((issue.location, issue.error_type) for issue in exc.validation_issues),
        )

    def _log_post_submission_failure(self, exc: Exception) -> None:
        if isinstance(exc, APIError):
            logger.warning(
                "auth event=post_submission_failed attempt_id=%s challenge_revision=%s "
                "stage=session_or_cdn status=%s request_id=%s",
                self._attempt_id(),
                self._challenge_revision,
                exc.status_code,
                exc.request_id or "unavailable",
            )
            logger.debug(
                "auth event=post_submission_diagnostics attempt_id=%s "
                "challenge_revision=%s content_type=%s body_size=%s fields=%s issues=%s",
                self._attempt_id(),
                self._challenge_revision,
                exc.response_content_type or "unavailable",
                exc.response_size,
                exc.response_fields,
                tuple((issue.location, issue.error_type) for issue in exc.validation_issues),
            )
            return
        logger.warning(
            "auth event=post_submission_failed attempt_id=%s challenge_revision=%s "
            "stage=session_or_cdn error_type=%s",
            self._attempt_id(),
            self._challenge_revision,
            type(exc).__name__,
        )

    def _log_validation_started(self) -> None:
        logger.info(
            "auth event=cdn_validation_started attempt_id=%s challenge_revision=%s",
            self._attempt_id(),
            self._challenge_revision,
        )

    def _log_validation_completed(self) -> None:
        logger.info(
            "auth event=cdn_validation_completed attempt_id=%s challenge_revision=%s",
            self._attempt_id(),
            self._challenge_revision,
        )

    async def _recover_auth(self, failed_tokens: object) -> None:
        async with self._auth_lock:
            if self.otp_required and self._client.auth.pending_totp is not None:
                raise InteractiveAuthenticationRequired("ArvanCloud OTP is required")
            if (
                self._client.auth.tokens is not failed_tokens
                and self._client.auth.tokens is not None
                and self.connected
            ):
                return
            try:
                try:
                    self._auth_state = AuthenticationState.AUTHENTICATING
                    await self._client.auth.refresh()
                    await self._save_session()
                    self._mark_connected()
                    logger.info("refreshed ArvanCloud session")
                except AuthenticationError:
                    logger.info("ArvanCloud refresh rejected; logging in once")
                    try:
                        await self._login_and_save()
                    except TOTPRequiredError as exc:
                        self._set_totp_required()
                        raise InteractiveAuthenticationRequired(
                            "ArvanCloud OTP is required"
                        ) from exc
                    self._mark_connected()
            except InteractiveAuthenticationRequired:
                raise
            except Exception:
                self._auth_state = AuthenticationState.UNAVAILABLE
                raise

    async def _call(
        self,
        operation: Callable[[], Awaitable[ResultT]],
        *,
        require_ready: bool = True,
    ) -> ResultT:
        if require_ready and not self.connected:
            raise InteractiveAuthenticationRequired("ArvanCloud authentication is required")
        failed_tokens = self._client.auth.tokens
        try:
            return await operation()
        except AuthenticationError:
            await self._recover_auth(failed_tokens)
            try:
                return await operation()
            except AuthenticationError:
                self._auth_state = AuthenticationState.UNAVAILABLE
                raise

    async def list_domains(self, *, page: int, per_page: int = 8) -> CDNDomainPage:
        return await self._call(lambda: self._client.cdn.domains.list(page=page, per_page=per_page))

    async def list_records(
        self,
        domain: str,
        *,
        page: int,
        per_page: int = 8,
        record_type: str | None = None,
        search: str | None = None,
    ) -> DNSRecordPage:
        return await self._call(
            lambda: self._client.cdn.dns_records.list(
                domain,
                page=page,
                per_page=per_page,
                record_types=record_type,
                search=search,
                match_type="exact" if search else None,
            )
        )

    async def find_record(self, domain: str, record_id: str) -> DNSRecord | None:
        page_number = 1
        while True:
            page = await self.list_records(domain, page=page_number, per_page=100)
            for record in page.data:
                if str(record.id) == record_id:
                    return record
            if page_number >= page.meta.last_page:
                return None
            page_number += 1

    async def require_current_record(
        self,
        domain: str,
        record_id: str,
        updated_at: object,
    ) -> DNSRecord:
        current = await self.find_record(domain, record_id)
        if current is None or current.updated_at != updated_at:
            raise StaleRecordError("The DNS record changed; refresh it before trying again")
        if current.is_protected:
            raise ProtectedRecordError("This DNS record is protected by ArvanCloud")
        return current

    async def create_record(self, domain: str, payload: DNSRecordCreate) -> DNSRecord:
        return await self._call(lambda: self._client.cdn.dns_records.create(domain, payload))

    async def update_record(self, domain: str, payload: DNSRecordUpdate) -> DNSRecord:
        return await self._call(lambda: self._client.cdn.dns_records.update(domain, payload))

    async def set_cloud(self, domain: str, record_id: str, *, cloud: bool) -> DNSRecord:
        return await self._call(
            lambda: self._client.cdn.dns_records.set_cloud(domain, record_id, cloud=cloud)
        )

    async def delete_record(self, domain: str, record_id: str) -> DNSRecordDeleteResult:
        return await self._call(lambda: self._client.cdn.dns_records.delete(domain, record_id))
