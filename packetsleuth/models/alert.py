"""Alert records produced by later detection rules.

An alert explains an observation. Storing one does not prove the traffic
was malicious, and this module does not decide the severity on its own.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType

from packetsleuth.models.enums import Protocol, Severity
from packetsleuth.models.validation import (
    ModelValidationError,
    normalize_optional_ip,
    parse_enum,
    parse_datetime,
    reject_unknown_fields,
    require_aware_datetime,
    require_evidence,
    require_mapping,
    require_packet_number,
    require_text,
)

_ALERT_FIELDS = {
    "alert_id",
    "timestamp",
    "rule_id",
    "title",
    "severity",
    "description",
    "source_ip",
    "destination_ip",
    "affected_protocol",
    "evidence",
    "recommendation",
    "related_packet_numbers",
}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


@dataclass(frozen=True, slots=True)
class Alert:
    """One explainable detection result.

    ``description`` says what was observed. ``evidence`` holds the counts,
    addresses, and packet numbers that support that statement.
    ``recommendation`` says what a defender can check next. Severity is a
    label for triage, not a probability of compromise.
    """

    alert_id: str
    timestamp: datetime
    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    source_ip: str | None = None
    destination_ip: str | None = None
    affected_protocol: Protocol | None = None
    evidence: Mapping[str, object] = field(default_factory=dict)
    related_packet_numbers: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "alert_id", _require_identifier(self.alert_id, "alert_id"))
        object.__setattr__(self, "timestamp", require_aware_datetime(self.timestamp, "timestamp"))
        object.__setattr__(self, "rule_id", _require_identifier(self.rule_id, "rule_id"))
        object.__setattr__(self, "title", require_text(self.title, "title", max_length=200))
        object.__setattr__(self, "severity", parse_enum(Severity, self.severity, "severity"))
        object.__setattr__(
            self,
            "description",
            require_text(self.description, "description", max_length=2000),
        )
        object.__setattr__(
            self,
            "recommendation",
            require_text(self.recommendation, "recommendation", max_length=2000),
        )
        object.__setattr__(self, "source_ip", normalize_optional_ip(self.source_ip, "source_ip"))
        object.__setattr__(
            self,
            "destination_ip",
            normalize_optional_ip(self.destination_ip, "destination_ip"),
        )
        object.__setattr__(
            self,
            "affected_protocol",
            None
            if self.affected_protocol is None
            else parse_enum(Protocol, self.affected_protocol, "affected_protocol"),
        )
        object.__setattr__(self, "evidence", _freeze_json(require_evidence(self.evidence)))
        object.__setattr__(
            self,
            "related_packet_numbers",
            _unique_packet_numbers(self.related_packet_numbers),
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "affected_protocol": None
            if self.affected_protocol is None
            else self.affected_protocol.value,
            "evidence": _thaw_json(self.evidence),
            "recommendation": self.recommendation,
            "related_packet_numbers": list(self.related_packet_numbers),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Alert:
        """Build an alert from a dictionary produced by ``to_dict``."""
        payload = require_mapping(data, "alert")
        reject_unknown_fields(payload, _ALERT_FIELDS, "alert")
        for name in (
            "alert_id",
            "timestamp",
            "rule_id",
            "title",
            "severity",
            "description",
            "recommendation",
        ):
            if name not in payload:
                raise ModelValidationError(f"alert requires {name}")
        protocol = payload.get("affected_protocol")
        evidence = payload.get("evidence", {})
        if evidence is None:
            evidence = {}
        numbers = payload.get("related_packet_numbers", [])
        if numbers is None:
            numbers = []
        if isinstance(numbers, (str, bytes)) or not isinstance(numbers, Sequence):
            raise ModelValidationError("related_packet_numbers must be a list")
        return cls(
            alert_id=_require_text_value(payload, "alert_id"),
            timestamp=parse_datetime(payload["timestamp"], "timestamp"),
            rule_id=_require_text_value(payload, "rule_id"),
            title=_require_text_value(payload, "title"),
            severity=parse_enum(Severity, payload["severity"], "severity"),
            description=_require_text_value(payload, "description"),
            recommendation=_require_text_value(payload, "recommendation"),
            source_ip=_optional_string(payload, "source_ip"),
            destination_ip=_optional_string(payload, "destination_ip"),
            affected_protocol=None if protocol is None else parse_enum(Protocol, protocol, "affected_protocol"),
            evidence=evidence if isinstance(evidence, Mapping) else evidence,
            related_packet_numbers=tuple(numbers),
        )


def _require_identifier(value: object, field_name: str) -> str:
    text = require_text(value, field_name, max_length=64)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ModelValidationError(
            f"{field_name} must contain letters, numbers, dots, underscores, or hyphens"
        )
    return text


def _unique_packet_numbers(numbers: object) -> tuple[int, ...]:
    if isinstance(numbers, (str, bytes)) or not isinstance(numbers, Sequence):
        raise ModelValidationError("related_packet_numbers must be a sequence")
    ordered: list[int] = []
    seen: set[int] = set()
    for number in numbers:
        parsed = require_packet_number(number)
        if parsed not in seen:
            seen.add(parsed)
            ordered.append(parsed)
    return tuple(ordered)


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _require_text_value(payload: Mapping[str, object], field_name: str) -> str:
    value = payload[field_name]
    if not isinstance(value, str):
        raise ModelValidationError(f"{field_name} must be a string")
    return value


def _optional_string(payload: Mapping[str, object], field_name: str) -> str | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ModelValidationError(f"{field_name} must be a string or null")
    return value
