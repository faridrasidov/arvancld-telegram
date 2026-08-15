"""Shared model fixtures for bot tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from arvancld import DNSRecord


@pytest.fixture
def dns_record_factory():
    def factory(**overrides: Any) -> DNSRecord:
        payload: dict[str, Any] = {
            "id": UUID("00000000-0000-4000-8000-000000000001"),
            "type": "A",
            "name": "www",
            "value": [
                {
                    "ip": "192.0.2.10",
                    "port": 443,
                    "weight": 100,
                    "country": "IR",
                }
            ],
            "ttl": 120,
            "cloud": True,
            "upstream_https": "default",
            "ip_filter_mode": {
                "count": "single",
                "order": "none",
                "geo_filter": "none",
            },
            "is_protected": False,
            "usage": [],
            "created_at": datetime(2026, 8, 1, tzinfo=UTC),
            "updated_at": datetime(2026, 8, 2, tzinfo=UTC),
        }
        payload.update(overrides)
        return DNSRecord.model_validate(payload)

    return factory
