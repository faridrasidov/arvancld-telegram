"""DNS input mapping and preservation tests."""

from __future__ import annotations

import pytest

from arvancld_telegram.dns import (
    DNSInputError,
    create_record,
    format_record_value,
    merge_record_value,
    parse_record_value,
    update_record,
    validate_record_name,
)


@pytest.mark.parametrize(
    ("record_type", "text", "expected"),
    [
        (
            "A",
            "192.0.2.1\n198.51.100.2",
            [
                {"ip": "192.0.2.1", "port": None, "weight": None, "country": ""},
                {"ip": "198.51.100.2", "port": None, "weight": None, "country": ""},
            ],
        ),
        (
            "AAAA",
            "2001:db8::1",
            [{"ip": "2001:db8::1", "port": None, "weight": None, "country": ""}],
        ),
        ("ANAME", "origin.example.test", {"location": "origin.example.test"}),
        ("CNAME", "target.example.test.", {"host": "target.example.test."}),
        ("NS", "ns1.example.test.", {"host": "ns1.example.test."}),
        ("MX", "mail.example.test 10", {"host": "mail.example.test", "priority": 10}),
        (
            "SRV",
            "sip.example.test 5060 5 10",
            {"target": "sip.example.test", "port": 5060, "weight": 5, "priority": 10},
        ),
        ("TXT", "v=spf1 include:example.test -all", {"text": "v=spf1 include:example.test -all"}),
        ("PTR", "host.example.test.", {"domain": "host.example.test."}),
        ("CAA", "issue letsencrypt.org", {"tag": "issue", "value": "letsencrypt.org"}),
        (
            "TLSA",
            "3 1 1 AABBCCDD",
            {"usage": "3", "selector": "1", "matching_type": "1", "certificate": "aabbccdd"},
        ),
    ],
)
def test_parse_every_supported_record_type(record_type: str, text: str, expected: object) -> None:
    assert parse_record_value(record_type, text) == expected


@pytest.mark.parametrize(
    ("record_type", "text"),
    [
        ("A", "2001:db8::1"),
        ("AAAA", "192.0.2.1"),
        ("MX", "mail.example.test"),
        ("SRV", "target 443 5"),
        ("TLSA", "4 1 1 aabb"),
        ("TLSA", "3 1 1 not-hex"),
    ],
)
def test_parse_rejects_invalid_type_specific_values(record_type: str, text: str) -> None:
    with pytest.raises(DNSInputError):
        parse_record_value(record_type, text)


def test_record_name_accepts_dns_service_and_wildcard_labels() -> None:
    assert validate_record_name("_sip._tcp") == "_sip._tcp"
    assert validate_record_name("*.www") == "*.www"
    assert validate_record_name("@") == "@"


def test_ip_merge_preserves_metadata_for_unchanged_targets() -> None:
    parsed = parse_record_value("A", "192.0.2.10\n192.0.2.20")
    existing = [
        {"ip": "192.0.2.10", "port": 443, "weight": 100, "country": "IR"},
        {"ip": "192.0.2.99", "port": 80, "weight": 20, "country": "DE"},
    ]

    merged = merge_record_value(
        "A",
        parsed,
        existing_type="a",
        existing_value=existing,
    )

    assert merged[0] == existing[0]  # type: ignore[index]
    assert merged[1] == {  # type: ignore[index]
        "ip": "192.0.2.20",
        "port": None,
        "weight": None,
        "country": "",
    }


def test_dict_merge_preserves_unexposed_fields() -> None:
    merged = merge_record_value(
        "CNAME",
        {"host": "new.example.test"},
        existing_type="CNAME",
        existing_value={"host": "old.example.test", "host_header": "origin", "port": 8443},
    )

    assert merged == {
        "host": "new.example.test",
        "host_header": "origin",
        "port": 8443,
    }


def test_create_and_update_keep_provider_defaults(dns_record_factory) -> None:
    created = create_record(
        record_type="TXT",
        name="@",
        value={"text": "hello"},
        ttl=120,
        cloud=False,
    )
    original = dns_record_factory()
    updated = update_record(original, ttl=300)

    assert created.upstream_https == "default"
    assert created.ip_filter_mode.count == "single"
    assert updated.upstream_https == original.upstream_https
    assert updated.ip_filter_mode == original.ip_filter_mode
    assert updated.model_dump(mode="json")["value"] == original.model_dump(mode="json")["value"]


def test_format_value_handles_lists_and_dicts() -> None:
    assert format_record_value([{"ip": "192.0.2.1", "port": None}]) == "ip=192.0.2.1"
    assert format_record_value({"text": "hello"}) == "text=hello"
