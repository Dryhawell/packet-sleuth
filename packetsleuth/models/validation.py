"""Checks shared by the analysis models.

Validators reject impossible values and a few fields that would store
secrets. They do not decide whether traffic is malicious.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from ipaddress import ip_address
from typing import TypeVar

_ENUM = TypeVar("_ENUM", bound=Enum)

_MAX_EVIDENCE_DEPTH = 3
_MAX_EVIDENCE_STRING = 500
_MAX_EVIDENCE_ITEMS = 32
_FORBIDDEN_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "authorization",
    "credential",
)


class ModelValidationError(ValueError):
    """Raised when a model receives a value it cannot store honestly."""


def require_mapping(value: object, field_name: str) -> Mapping[str, object]:
    """Return ``value`` when it is a mapping with string keys."""
    if not isinstance(value, Mapping):
        raise ModelValidationError(f"{field_name} must be an object")
    invalid_keys = [key for key in value if not isinstance(key, str)]
    if invalid_keys:
        raise ModelValidationError(f"{field_name} keys must be strings")
    return value


def reject_unknown_fields(data: Mapping[str, object], allowed: set[str], field_name: str) -> None:
    """Fail when serialized input contains a field the model does not define."""
    unknown = sorted(set(data) - allowed)
    if unknown:
        names = ", ".join(unknown)
        raise ModelValidationError(f"{field_name} contains unknown fields: {names}")


def require_packet_number(value: object) -> int:
    """Return a packet number starting at 1."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError("packet_number must be an integer")
    if value < 1:
        raise ModelValidationError("packet_number must be 1 or greater")
    return value


def require_non_negative(value: object, field_name: str) -> int:
    """Return a zero-or-greater integer."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError(f"{field_name} must be an integer")
    if value < 0:
        raise ModelValidationError(f"{field_name} must be 0 or greater")
    return value


def require_port(value: object, field_name: str) -> int | None:
    """Return a TCP/UDP port, or ``None`` when the layer has no port."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError(f"{field_name} must be an integer or null")
    if value < 0 or value > 65535:
        raise ModelValidationError(f"{field_name} must be between 0 and 65535")
    return value


def require_ttl(value: object) -> int | None:
    """Return an IPv4 TTL or IPv6 hop limit."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError("ttl must be an integer or null")
    if value < 0 or value > 255:
        raise ModelValidationError("ttl must be between 0 and 255")
    return value


def require_aware_datetime(value: object, field_name: str) -> datetime:
    """Return a timezone-aware datetime."""
    if not isinstance(value, datetime):
        raise ModelValidationError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ModelValidationError(f"{field_name} must include a timezone")
    return value


def require_optional_datetime(value: object, field_name: str) -> datetime | None:
    """Return an aware datetime, or ``None`` when the capture has no timestamp."""
    if value is None:
        return None
    return require_aware_datetime(value, field_name)


def parse_datetime(value: object, field_name: str) -> datetime:
    """Parse an ISO 8601 timestamp that includes an offset."""
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{field_name} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ModelValidationError(f"{field_name} is not a valid timestamp") from exc
    return require_aware_datetime(parsed, field_name)


def parse_optional_datetime(value: object, field_name: str) -> datetime | None:
    """Parse a timestamp, keeping ``None`` when the field was absent."""
    if value is None:
        return None
    return parse_datetime(value, field_name)


def normalize_ip(value: object, field_name: str) -> str:
    """Return the canonical text form of an IPv4 or IPv6 address."""
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{field_name} must be an IP address")
    try:
        address = ip_address(value.strip())
    except ValueError as exc:
        raise ModelValidationError(f"{field_name} is not a valid IP address") from exc
    return str(address)


def normalize_optional_ip(value: object, field_name: str) -> str | None:
    """Return a canonical IP address, or ``None`` when the layer is absent."""
    if value is None:
        return None
    return normalize_ip(value, field_name)


def normalize_mac(value: object, field_name: str) -> str:
    """Return a MAC address as lowercase hex pairs separated by colons."""
    if not isinstance(value, str):
        raise ModelValidationError(f"{field_name} must be a MAC address")
    hex_chars = value.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if len(hex_chars) != 12 or any(char not in "0123456789abcdef" for char in hex_chars):
        raise ModelValidationError(f"{field_name} is not a valid MAC address")
    return ":".join(hex_chars[index : index + 2] for index in range(0, 12, 2))


def normalize_optional_mac(value: object, field_name: str) -> str | None:
    """Return a normalized MAC address, or ``None`` when it was not observed."""
    if value is None:
        return None
    return normalize_mac(value, field_name)


def require_text(
    value: object,
    field_name: str,
    *,
    max_length: int,
    allow_empty: bool = False,
) -> str:
    """Return stripped text within the field's size limit."""
    if not isinstance(value, str):
        raise ModelValidationError(f"{field_name} must be a string")
    text = value.strip()
    if not text and not allow_empty:
        raise ModelValidationError(f"{field_name} must not be empty")
    if len(text) > max_length:
        raise ModelValidationError(f"{field_name} must be at most {max_length} characters")
    return text


def require_optional_text(value: object, field_name: str, *, max_length: int) -> str | None:
    """Return stripped text, or ``None`` when the observation is absent.

    An empty string is rejected. Callers pass ``None`` for a missing value
    so an unknown field is not stored as a blank fact.
    """
    if value is None:
        return None
    return require_text(value, field_name, max_length=max_length)


def parse_enum(enum_type: type[_ENUM], value: object, field_name: str) -> _ENUM:
    """Return an enum member from the member itself or its string value."""
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value.strip())
        except ValueError:
            pass
    allowed = ", ".join(member.value for member in enum_type)
    raise ModelValidationError(f"{field_name} must be one of: {allowed}")


def require_evidence(value: object) -> dict[str, object]:
    """Return a JSON-sized evidence object without secret-bearing keys."""
    data = require_mapping(value, "evidence")
    if len(data) > _MAX_EVIDENCE_ITEMS:
        raise ModelValidationError("evidence contains too many fields")
    cleaned: dict[str, object] = {}
    for key, item in data.items():
        _reject_sensitive_key(key, "evidence")
        cleaned[key] = _clean_evidence_value(item, depth=1, path=f"evidence.{key}")
    return cleaned


def _reject_sensitive_key(key: str, path: str) -> None:
    normalized = key.lower().replace("-", "").replace("_", "")
    if any(part in normalized for part in _FORBIDDEN_KEY_PARTS):
        raise ModelValidationError(f"{path}.{key} is not allowed in stored evidence")


def _clean_evidence_value(value: object, *, depth: int, path: str) -> object:
    if depth > _MAX_EVIDENCE_DEPTH:
        raise ModelValidationError(f"{path} is nested too deeply")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ModelValidationError(f"{path} must be a finite number")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_EVIDENCE_STRING:
            raise ModelValidationError(
                f"{path} must be at most {_MAX_EVIDENCE_STRING} characters"
            )
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_EVIDENCE_ITEMS:
            raise ModelValidationError(f"{path} contains too many items")
        return [
            _clean_evidence_value(item, depth=depth + 1, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        if len(value) > _MAX_EVIDENCE_ITEMS:
            raise ModelValidationError(f"{path} contains too many fields")
        cleaned: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelValidationError(f"{path} keys must be strings")
            _reject_sensitive_key(key, path)
            cleaned[key] = _clean_evidence_value(item, depth=depth + 1, path=f"{path}.{key}")
        return cleaned
    raise ModelValidationError(f"{path} must be JSON data")
