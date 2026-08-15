"""Authenticated ArvanCloud SDK gateway with bounded session recovery."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar

from arvancld import (
    AsyncArvanCloud,
    AuthenticationError,
    DNSRecord,
    DNSRecordCreate,
    DNSRecordDeleteResult,
    DNSRecordPage,
    DNSRecordUpdate,
    InvalidSessionError,
    SessionExpiredError,
)
from arvancld.cdn.models import CDNDomainPage

from arvancld_telegram.config import Settings

logger = logging.getLogger(__name__)
ResultT = TypeVar("ResultT")


class StaleRecordError(RuntimeError):
    """Raised when a record changed after it was selected for mutation."""


class ProtectedRecordError(RuntimeError):
    """Raised when a protected provider record is selected for mutation."""


class ArvanCloudGateway:
    """Expose bot operations while centralizing authentication recovery."""

    def __init__(self, settings: Settings, client: AsyncArvanCloud | None = None) -> None:
        self._settings = settings
        self._client = client or AsyncArvanCloud()
        self._session_path = Path(settings.arvancld_session_path)
        self._auth_lock = asyncio.Lock()

    @property
    def connected(self) -> bool:
        return self._client.auth.tokens is not None and not self._client.is_closed

    async def start(self) -> None:
        """Restore or create a session, then validate CDN access."""

        try:
            await self._client.auth.aload_session(self._session_path)
            logger.info("loaded ArvanCloud session path=%s", self._session_path)
        except (FileNotFoundError, InvalidSessionError, SessionExpiredError):
            await self._login_and_save()
        await self.list_domains(page=1, per_page=1)

    async def close(self) -> None:
        await self._client.close()

    async def _login_and_save(self) -> None:
        await self._client.auth.login(
            self._settings.arvancld_email,
            self._settings.arvancld_password,
        )
        await self._client.auth.asave_session(self._session_path)
        logger.info("created ArvanCloud session path=%s", self._session_path)

    async def _recover_auth(self, failed_tokens: object) -> None:
        async with self._auth_lock:
            if (
                self._client.auth.tokens is not failed_tokens
                and self._client.auth.tokens is not None
            ):
                return
            try:
                await self._client.auth.refresh()
                await self._client.auth.asave_session(self._session_path)
                logger.info("refreshed ArvanCloud session")
            except AuthenticationError:
                logger.info("ArvanCloud refresh rejected; logging in once")
                await self._login_and_save()

    async def _call(self, operation: Callable[[], Awaitable[ResultT]]) -> ResultT:
        failed_tokens = self._client.auth.tokens
        try:
            return await operation()
        except AuthenticationError:
            await self._recover_auth(failed_tokens)
            return await operation()

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
