"""The complete result of one offline analysis run.

This object collects records produced by later phases. It does not read a
capture, score risk, or generate alerts by itself.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from packetsleuth.models.alert import Alert
from packetsleuth.models.connection import Connection
from packetsleuth.models.packet import Packet
from packetsleuth.models.validation import (
    ModelValidationError,
    parse_datetime,
    reject_unknown_fields,
    require_aware_datetime,
    require_mapping,
    require_optional_text,
    require_text,
)

_RESULT_FIELDS = {
    "source_file",
    "analyzed_at",
    "file_format",
    "packets",
    "connections",
    "alerts",
    "limitations",
    "parse_errors",
    "risk_score",
    "risk_explanation",
}
_FILE_FORMATS = {"pcap", "pcapng"}


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Normalized output for one capture.

    ``risk_score`` is reserved for the later scoring phase. When a score is
    present it must be accompanied by ``risk_explanation``. This model checks
    that pair. It does not calculate the score.

    Packets, connections, and alerts are stored by value. Raw packet payloads
    are not part of the result.
    """

    source_file: str
    analyzed_at: datetime
    packets: tuple[Packet, ...] = ()
    connections: tuple[Connection, ...] = ()
    alerts: tuple[Alert, ...] = ()
    file_format: str | None = None
    limitations: tuple[str, ...] = ()
    parse_errors: tuple[str, ...] = ()
    risk_score: int | None = None
    risk_explanation: str | None = None

    def __post_init__(self) -> None:
        packets = _require_instances(self.packets, Packet, "packets")
        connections = _require_instances(self.connections, Connection, "connections")
        alerts = _require_instances(self.alerts, Alert, "alerts")
        _require_unique(packets, "packet_number", "packets")
        _require_unique(connections, "key", "connections")
        _require_unique(alerts, "alert_id", "alerts")
        score = _require_score(self.risk_score)
        explanation = require_optional_text(self.risk_explanation, "risk_explanation", max_length=2000)
        if score is None and explanation is not None:
            raise ModelValidationError("risk_explanation requires risk_score")
        if score is not None and explanation is None:
            raise ModelValidationError("risk_score requires risk_explanation")
        object.__setattr__(self, "source_file", require_text(self.source_file, "source_file", max_length=4096))
        object.__setattr__(self, "analyzed_at", require_aware_datetime(self.analyzed_at, "analyzed_at"))
        object.__setattr__(self, "packets", packets)
        object.__setattr__(self, "connections", connections)
        object.__setattr__(self, "alerts", alerts)
        object.__setattr__(self, "file_format", _require_file_format(self.file_format))
        object.__setattr__(self, "limitations", _require_notes(self.limitations, "limitations"))
        object.__setattr__(self, "parse_errors", _require_notes(self.parse_errors, "parse_errors"))
        object.__setattr__(self, "risk_score", score)
        object.__setattr__(self, "risk_explanation", explanation)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready dictionary."""
        return {
            "source_file": self.source_file,
            "analyzed_at": self.analyzed_at.isoformat(),
            "file_format": self.file_format,
            "packets": [packet.to_dict() for packet in self.packets],
            "connections": [connection.to_dict() for connection in self.connections],
            "alerts": [alert.to_dict() for alert in self.alerts],
            "limitations": list(self.limitations),
            "parse_errors": list(self.parse_errors),
            "risk_score": self.risk_score,
            "risk_explanation": self.risk_explanation,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize the result to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> AnalysisResult:
        """Build a result from a dictionary produced by ``to_dict``."""
        payload = require_mapping(data, "analysis_result")
        reject_unknown_fields(payload, _RESULT_FIELDS, "analysis_result")
        if "source_file" not in payload or "analyzed_at" not in payload:
            raise ModelValidationError("analysis_result requires source_file and analyzed_at")
        return cls(
            source_file=_require_string(payload, "source_file"),
            analyzed_at=parse_datetime(payload["analyzed_at"], "analyzed_at"),
            file_format=_optional_string(payload, "file_format"),
            packets=tuple(Packet.from_dict(item) for item in _require_object_list(payload, "packets")),
            connections=tuple(
                Connection.from_dict(item) for item in _require_object_list(payload, "connections")
            ),
            alerts=tuple(Alert.from_dict(item) for item in _require_object_list(payload, "alerts")),
            limitations=tuple(_require_string_list(payload, "limitations")),
            parse_errors=tuple(_require_string_list(payload, "parse_errors")),
            risk_score=_optional_score(payload),
            risk_explanation=_optional_string(payload, "risk_explanation"),
        )

    @classmethod
    def from_json(cls, text: str) -> AnalysisResult:
        """Build a result from a JSON string produced by ``to_json``."""
        if not isinstance(text, str):
            raise ModelValidationError("analysis JSON must be a string")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ModelValidationError("analysis JSON is not valid") from exc
        if not isinstance(data, dict):
            raise ModelValidationError("analysis JSON must contain an object")
        return cls.from_dict(data)


def _require_instances(values: object, expected: type[object], field_name: str) -> tuple[object, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ModelValidationError(f"{field_name} must be a sequence")
    items = tuple(values)
    if any(not isinstance(item, expected) for item in items):
        raise ModelValidationError(f"{field_name} contains an unexpected value")
    return items


def _require_unique(values: Sequence[object], attribute: str, field_name: str) -> None:
    seen: set[object] = set()
    for item in values:
        identity = getattr(item, attribute)
        if identity in seen:
            raise ModelValidationError(f"{field_name} contains a duplicate {attribute}")
        seen.add(identity)


def _require_score(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError("risk_score must be an integer or null")
    if value < 0 or value > 100:
        raise ModelValidationError("risk_score must be between 0 and 100")
    return value


def _require_file_format(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ModelValidationError("file_format must be a string or null")
    normalized = value.strip().lower()
    if normalized not in _FILE_FORMATS:
        raise ModelValidationError("file_format must be pcap or pcapng")
    return normalized


def _require_notes(values: object, field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ModelValidationError(f"{field_name} must be a sequence")
    if len(values) > 100:
        raise ModelValidationError(f"{field_name} contains too many entries")
    return tuple(require_text(item, field_name, max_length=500) for item in values)


def _require_string(payload: Mapping[str, object], field_name: str) -> str:
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


def _optional_score(payload: Mapping[str, object]) -> int | None:
    if "risk_score" not in payload:
        return None
    return _require_score(payload["risk_score"])


def _require_object_list(payload: Mapping[str, object], field_name: str) -> list[Mapping[str, object]]:
    value = payload.get(field_name, [])
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ModelValidationError(f"{field_name} must be a list")
    items: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ModelValidationError(f"{field_name} must contain objects")
        items.append(item)
    return items


def _require_string_list(payload: Mapping[str, object], field_name: str) -> list[str]:
    value = payload.get(field_name, [])
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ModelValidationError(f"{field_name} must be a list")
    texts: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ModelValidationError(f"{field_name} must contain strings")
        texts.append(item)
    return texts
