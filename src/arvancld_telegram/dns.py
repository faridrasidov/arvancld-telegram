"""DNS record value parsing, validation, merging, and display."""

from __future__ import annotations

import ipaddress
import re
import string
from collections.abc import Iterable, Mapping
from typing import Any

from arvancld import DNSRecord, DNSRecordCreate, DNSRecordUpdate, IPFilterMode
from pydantic import BaseModel

RECORD_TYPES = ("A", "AAAA", "ANAME", "CNAME", "NS", "MX", "SRV", "TXT", "PTR", "CAA", "TLSA")
DEFAULT_TTL = 120
DEFAULT_IP_FILTER = IPFilterMode(count="single", order="none", geo_filter="none")

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.*@-]+(?:\.[A-Za-z0-9_*-]+)*\.?$")
_INTEGER_LIMIT = 65_535


class DNSInputError(ValueError):
    """Raised when a guided DNS value is invalid."""


def validate_record_type(value: str) -> str:
    record_type = value.strip().upper()
    if record_type not in RECORD_TYPES:
        raise DNSInputError("Unsupported DNS record type")
    return record_type


def validate_record_name(value: str) -> str:
    name = value.strip()
    if not name:
        raise DNSInputError("Record name must not be blank")
    if len(name) > 253 or any(len(label) > 63 for label in name.rstrip(".").split(".")):
        raise DNSInputError("Record name is too long")
    if not _NAME_PATTERN.fullmatch(name):
        raise DNSInputError("Use a zone-relative DNS name such as @, www, or _service._tcp")
    return name


def validate_ttl(value: str | int) -> int:
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        raise DNSInputError("TTL must be a positive integer") from None
    if ttl < 1:
        raise DNSInputError("TTL must be greater than zero")
    return ttl


def _target(value: str, label: str) -> str:
    candidate = value.strip()
    if not candidate or any(character.isspace() for character in candidate):
        raise DNSInputError(f"{label} must be one non-blank hostname or location")
    if len(candidate) > 253:
        raise DNSInputError(f"{label} is too long")
    return candidate


def _bounded_integer(value: str, label: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise DNSInputError(f"{label} must be an integer") from None
    if parsed < 0 or parsed > _INTEGER_LIMIT:
        raise DNSInputError(f"{label} must be between 0 and {_INTEGER_LIMIT}")
    return parsed


def _parts(value: str, expected: int, usage: str) -> list[str]:
    parts = value.split()
    if len(parts) != expected:
        raise DNSInputError(f"Expected: {usage}")
    return parts


def parse_record_value(record_type: str, text: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Parse a guided text value into the ArvanCloud wire shape."""

    kind = validate_record_type(record_type)
    raw = text.strip()
    if not raw:
        raise DNSInputError("Record value must not be blank")

    if kind in {"A", "AAAA"}:
        version = 4 if kind == "A" else 6
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                raise DNSInputError(f"{candidate!r} is not a valid IP address") from None
            if address.version != version:
                raise DNSInputError(f"{candidate!r} is not a valid {kind} address")
            normalized = str(address)
            if normalized not in seen:
                seen.add(normalized)
                entries.append({"ip": normalized, "port": None, "weight": None, "country": ""})
        if not entries:
            raise DNSInputError("Enter at least one IP address")
        return entries

    if kind == "ANAME":
        return {"location": _target(raw, "Location")}
    if kind in {"CNAME", "NS"}:
        return {"host": _target(raw, "Host")}
    if kind == "PTR":
        return {"domain": _target(raw, "Domain")}
    if kind == "TXT":
        return {"text": raw}
    if kind == "MX":
        host, priority = _parts(raw, 2, "host priority")
        return {"host": _target(host, "Host"), "priority": _bounded_integer(priority, "Priority")}
    if kind == "SRV":
        target, port, weight, priority = _parts(raw, 4, "target port weight priority")
        return {
            "target": _target(target, "Target"),
            "port": _bounded_integer(port, "Port"),
            "weight": _bounded_integer(weight, "Weight"),
            "priority": _bounded_integer(priority, "Priority"),
        }
    if kind == "CAA":
        parts = raw.split(maxsplit=1)
        if len(parts) != 2:
            raise DNSInputError("Expected: tag value")
        tag, value = parts
        if not value.strip():
            raise DNSInputError("CAA value must not be blank")
        return {"tag": tag, "value": value.strip()}

    usage, selector, matching_type, certificate = _parts(
        raw, 4, "usage selector matching_type certificate"
    )
    parsed_usage = _bounded_integer(usage, "Usage")
    parsed_selector = _bounded_integer(selector, "Selector")
    parsed_matching = _bounded_integer(matching_type, "Matching type")
    if parsed_usage > 3 or parsed_selector > 1 or parsed_matching > 2:
        raise DNSInputError("TLSA usage/selector/matching_type must be in ranges 0-3/0-1/0-2")
    if len(certificate) % 2 or any(character not in string.hexdigits for character in certificate):
        raise DNSInputError("TLSA certificate must be an even-length hexadecimal value")
    return {
        "usage": str(parsed_usage),
        "selector": str(parsed_selector),
        "matching_type": str(parsed_matching),
        "certificate": certificate.lower(),
    }


def value_prompt(record_type: str) -> str:
    """Return a concise type-specific input prompt."""

    prompts = {
        "A": "Send one IPv4 address per line.",
        "AAAA": "Send one IPv6 address per line.",
        "ANAME": "Send the ANAME location.",
        "CNAME": "Send the target host.",
        "NS": "Send the nameserver host.",
        "MX": "Send: <code>host priority</code>",
        "SRV": "Send: <code>target port weight priority</code>",
        "TXT": "Send the TXT content.",
        "PTR": "Send the target domain.",
        "CAA": "Send: <code>tag value</code>",
        "TLSA": "Send: <code>usage selector matching_type certificate</code>",
    }
    return prompts[validate_record_type(record_type)]


def merge_record_value(
    record_type: str,
    parsed: dict[str, Any] | list[dict[str, Any]],
    *,
    existing_type: str | None = None,
    existing_value: object = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    """Preserve unexposed provider fields when editing a value of the same type."""

    kind = validate_record_type(record_type)
    if existing_type is None or kind != existing_type.upper():
        return parsed

    if kind in {"A", "AAAA"} and isinstance(parsed, list):
        existing_by_ip = {
            str(item.get("ip")): dict(item)
            for item in existing_value
            if isinstance(existing_value, list) and isinstance(item, Mapping) and item.get("ip")
        }
        merged: list[dict[str, Any]] = []
        for item in parsed:
            base = existing_by_ip.get(str(item.get("ip")), {})
            if base:
                base["ip"] = item["ip"]
                merged.append(base)
            else:
                merged.append(item)
        return merged

    if isinstance(parsed, dict) and isinstance(existing_value, Mapping):
        merged_dict = dict(existing_value)
        merged_dict.update(parsed)
        return merged_dict
    return parsed


def create_record(
    *,
    record_type: str,
    name: str,
    value: dict[str, Any] | list[dict[str, Any]],
    ttl: int,
    cloud: bool,
) -> DNSRecordCreate:
    return DNSRecordCreate(
        type=validate_record_type(record_type),
        name=validate_record_name(name),
        value=value,
        ttl=validate_ttl(ttl),
        cloud=cloud,
        upstream_https="default",
        ip_filter_mode=DEFAULT_IP_FILTER,
    )


def update_record(
    record: DNSRecord,
    *,
    record_type: str | None = None,
    name: str | None = None,
    value: dict[str, Any] | list[dict[str, Any]] | None = None,
    ttl: int | None = None,
    cloud: bool | None = None,
) -> DNSRecordUpdate:
    return DNSRecordUpdate(
        id=record.id,
        type=validate_record_type(record_type or record.type),
        name=validate_record_name(name or record.name),
        value=record.value if value is None else value,
        ttl=record.ttl if ttl is None else validate_ttl(ttl),
        cloud=record.cloud if cloud is None else cloud,
        upstream_https=record.upstream_https,
        ip_filter_mode=record.ip_filter_mode,
    )


def _key_value_text(value: Mapping[str, Any]) -> str:
    return ", ".join(
        f"{key}={item}" for key, item in value.items() if item is not None and item != ""
    )


def format_record_value(value: object, *, compact: bool = False) -> str:
    """Format flexible ArvanCloud values without assuming one record shape."""

    if isinstance(value, list):
        rendered = []
        for item in value:
            if isinstance(item, BaseModel):
                rendered.append(_key_value_text(item.model_dump()))
            elif isinstance(item, Mapping):
                rendered.append(_key_value_text(item))
            else:
                rendered.append(str(item))
        text = "; ".join(part for part in rendered if part)
    elif isinstance(value, BaseModel):
        text = _key_value_text(value.model_dump())
    elif isinstance(value, Mapping):
        text = _key_value_text(value)
    else:
        text = str(value)
    if compact and len(text) > 32:
        return f"{text[:29]}..."
    return text or "(empty)"


def changed_fields(before: DNSRecord, after: DNSRecordUpdate) -> Iterable[str]:
    """Yield human-readable field changes for confirmation screens."""

    comparisons = (
        ("Type", before.type.upper(), after.type.upper()),
        ("Name", before.name, after.name),
        ("Value", format_record_value(before.value), format_record_value(after.value)),
        ("TTL", str(before.ttl), str(after.ttl)),
        ("Cloud", "on" if before.cloud else "off", "on" if after.cloud else "off"),
    )
    for label, old, new in comparisons:
        if old != new:
            yield f"{label}: {old} → {new}"
