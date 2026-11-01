"""Bidirectional flow records.

A flow groups two directions of the same conversation. TCP state is not
inferred here: a capture can start after the handshake and end before the
close. UDP flows use the same identity fields without becoming TCP sessions.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address

from packetsleuth.models.enums import Protocol, TcpFlag
from packetsleuth.models.validation import (
    ModelValidationError,
    normalize_ip,
    normalize_optional_ip,
    parse_enum,
    parse_optional_datetime,
    reject_unknown_fields,
    require_mapping,
    require_non_negative,
    require_optional_datetime,
    require_packet_number,
    require_port,
)

_FLOW_PROTOCOLS = frozenset({Protocol.TCP, Protocol.UDP})
_CONNECTION_FIELDS = {
    "protocol",
    "endpoint_a_ip",
    "endpoint_a_port",
    "endpoint_b_ip",
    "endpoint_b_port",
    "packets_a_to_b",
    "packets_b_to_a",
    "bytes_a_to_b",
    "bytes_b_to_a",
    "packet_count",
    "bytes_transferred",
    "first_seen",
    "last_seen",
    "duration_seconds",
    "tcp_flags",
    "packet_numbers",
    "originator_ip",
    "originator_port",
    "key",
}


def canonicalize_endpoints(
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
) -> tuple[tuple[str, int], tuple[str, int]]:
    """Order two endpoints so either packet direction produces the same pair.

    The lower address comes first. When the addresses are equal, the lower
    port comes first. This is an identity rule, not a guess about who started
    the conversation.
    """
    left = (
        normalize_ip(source_ip, "source_ip"),
        _require_flow_port(source_port, "source_port"),
    )
    right = (
        normalize_ip(destination_ip, "destination_ip"),
        _require_flow_port(destination_port, "destination_port"),
    )
    if _endpoint_sort_key(left) <= _endpoint_sort_key(right):
        return left, right
    return right, left


def flow_key(
    protocol: Protocol,
    endpoint_a_ip: str,
    endpoint_a_port: int,
    endpoint_b_ip: str,
    endpoint_b_port: int,
) -> str:
    """Return the stable text identity of a canonical flow."""
    return (
        f"{protocol.value}|{endpoint_a_ip}|{endpoint_a_port}|"
        f"{endpoint_b_ip}|{endpoint_b_port}"
    )


@dataclass(frozen=True, slots=True)
class Connection:
    """Counters and timing for one bidirectional TCP or UDP flow.

    Endpoint A and endpoint B are stored in canonical order. Directional
    counters stay attached to those endpoints, so reversing the input does
    not create a second flow.

    ``originator_ip`` is set only when the capture shows which side sent
    the first observed packet. It stays empty when the capture begins in
    the middle of a conversation.
    """

    protocol: Protocol
    endpoint_a_ip: str
    endpoint_a_port: int
    endpoint_b_ip: str
    endpoint_b_port: int
    packets_a_to_b: int
    packets_b_to_a: int
    bytes_a_to_b: int
    bytes_b_to_a: int
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tcp_flags: frozenset[TcpFlag] = field(default_factory=frozenset)
    packet_numbers: tuple[int, ...] = ()
    originator_ip: str | None = None
    originator_port: int | None = None

    def __post_init__(self) -> None:
        protocol = parse_enum(Protocol, self.protocol, "protocol")
        if protocol not in _FLOW_PROTOCOLS:
            raise ModelValidationError("a flow protocol must be tcp or udp")
        endpoint_a_ip = normalize_ip(self.endpoint_a_ip, "endpoint_a_ip")
        endpoint_b_ip = normalize_ip(self.endpoint_b_ip, "endpoint_b_ip")
        endpoint_a_port = _require_flow_port(self.endpoint_a_port, "endpoint_a_port")
        endpoint_b_port = _require_flow_port(self.endpoint_b_port, "endpoint_b_port")
        canonical = canonicalize_endpoints(
            endpoint_a_ip,
            endpoint_a_port,
            endpoint_b_ip,
            endpoint_b_port,
        )
        if canonical != (
            (endpoint_a_ip, endpoint_a_port),
            (endpoint_b_ip, endpoint_b_port),
        ):
            raise ModelValidationError(
                "endpoints are not in canonical order; use Connection.create"
            )
        flags = _normalize_flow_flags(self.tcp_flags, protocol)
        numbers = _normalize_packet_numbers(self.packet_numbers)
        first_seen = require_optional_datetime(self.first_seen, "first_seen")
        last_seen = require_optional_datetime(self.last_seen, "last_seen")
        if first_seen is not None and last_seen is not None and last_seen < first_seen:
            raise ModelValidationError("last_seen cannot be earlier than first_seen")
        packets_a_to_b = require_non_negative(self.packets_a_to_b, "packets_a_to_b")
        packets_b_to_a = require_non_negative(self.packets_b_to_a, "packets_b_to_a")
        if packets_a_to_b + packets_b_to_a < 1:
            raise ModelValidationError("a flow must contain at least one packet")
        originator_ip = normalize_optional_ip(self.originator_ip, "originator_ip")
        originator_port = require_port(self.originator_port, "originator_port")
        _require_originator(
            originator_ip,
            originator_port,
            endpoint_a_ip,
            endpoint_a_port,
            endpoint_b_ip,
            endpoint_b_port,
        )
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "endpoint_a_ip", endpoint_a_ip)
        object.__setattr__(self, "endpoint_a_port", endpoint_a_port)
        object.__setattr__(self, "endpoint_b_ip", endpoint_b_ip)
        object.__setattr__(self, "endpoint_b_port", endpoint_b_port)
        object.__setattr__(self, "packets_a_to_b", packets_a_to_b)
        object.__setattr__(self, "packets_b_to_a", packets_b_to_a)
        object.__setattr__(self, "bytes_a_to_b", require_non_negative(self.bytes_a_to_b, "bytes_a_to_b"))
        object.__setattr__(self, "bytes_b_to_a", require_non_negative(self.bytes_b_to_a, "bytes_b_to_a"))
        object.__setattr__(self, "first_seen", first_seen)
        object.__setattr__(self, "last_seen", last_seen)
        object.__setattr__(self, "tcp_flags", flags)
        object.__setattr__(self, "packet_numbers", numbers)
        object.__setattr__(self, "originator_ip", originator_ip)
        object.__setattr__(self, "originator_port", originator_port)

    @classmethod
    def create(
        cls,
        *,
        protocol: Protocol,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        packets_source_to_destination: int,
        packets_destination_to_source: int,
        bytes_source_to_destination: int,
        bytes_destination_to_source: int,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        tcp_flags: frozenset[TcpFlag] | Sequence[TcpFlag] | None = None,
        packet_numbers: Sequence[int] = (),
        originator_ip: str | None = None,
        originator_port: int | None = None,
    ) -> Connection:
        """Build a flow from one observed direction and reorder it if needed.

        Directional counters are swapped when the source endpoint sorts after
        the destination. The packet observations themselves do not change.
        """
        source = (normalize_ip(source_ip, "source_ip"), _require_flow_port(source_port, "source_port"))
        destination = (
            normalize_ip(destination_ip, "destination_ip"),
            _require_flow_port(destination_port, "destination_port"),
        )
        endpoint_a, endpoint_b = canonicalize_endpoints(
            source[0],
            source[1],
            destination[0],
            destination[1],
        )
        if endpoint_a == source:
            packets_a_to_b = packets_source_to_destination
            packets_b_to_a = packets_destination_to_source
            bytes_a_to_b = bytes_source_to_destination
            bytes_b_to_a = bytes_destination_to_source
        else:
            packets_a_to_b = packets_destination_to_source
            packets_b_to_a = packets_source_to_destination
            bytes_a_to_b = bytes_destination_to_source
            bytes_b_to_a = bytes_source_to_destination
        return cls(
            protocol=protocol,
            endpoint_a_ip=endpoint_a[0],
            endpoint_a_port=endpoint_a[1],
            endpoint_b_ip=endpoint_b[0],
            endpoint_b_port=endpoint_b[1],
            packets_a_to_b=packets_a_to_b,
            packets_b_to_a=packets_b_to_a,
            bytes_a_to_b=bytes_a_to_b,
            bytes_b_to_a=bytes_b_to_a,
            first_seen=first_seen,
            last_seen=last_seen,
            tcp_flags=frozenset() if tcp_flags is None else tcp_flags,
            packet_numbers=tuple(packet_numbers),
            originator_ip=originator_ip,
            originator_port=originator_port,
        )

    @property
    def packet_count(self) -> int:
        """Return packets observed in both directions."""
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def bytes_transferred(self) -> int:
        """Return bytes observed in both directions."""
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def duration_seconds(self) -> float | None:
        """Return the span between the first and last timestamps.

        The result is ``None`` when either timestamp is missing. A missing
        timestamp is not replaced with the current time.
        """
        if self.first_seen is None or self.last_seen is None:
            return None
        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def key(self) -> str:
        """Return the identity shared by both directions of this flow."""
        return flow_key(
            self.protocol,
            self.endpoint_a_ip,
            self.endpoint_a_port,
            self.endpoint_b_ip,
            self.endpoint_b_port,
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready dictionary, including derived totals."""
        return {
            "protocol": self.protocol.value,
            "endpoint_a_ip": self.endpoint_a_ip,
            "endpoint_a_port": self.endpoint_a_port,
            "endpoint_b_ip": self.endpoint_b_ip,
            "endpoint_b_port": self.endpoint_b_port,
            "packets_a_to_b": self.packets_a_to_b,
            "packets_b_to_a": self.packets_b_to_a,
            "bytes_a_to_b": self.bytes_a_to_b,
            "bytes_b_to_a": self.bytes_b_to_a,
            "packet_count": self.packet_count,
            "bytes_transferred": self.bytes_transferred,
            "first_seen": None if self.first_seen is None else self.first_seen.isoformat(),
            "last_seen": None if self.last_seen is None else self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "tcp_flags": [flag.value for flag in sorted(self.tcp_flags, key=lambda item: item.value)],
            "packet_numbers": list(self.packet_numbers),
            "originator_ip": self.originator_ip,
            "originator_port": self.originator_port,
            "key": self.key,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Connection:
        """Build a flow from a dictionary produced by ``to_dict``."""
        payload = require_mapping(data, "connection")
        reject_unknown_fields(payload, _CONNECTION_FIELDS, "connection")
        for name in (
            "protocol",
            "endpoint_a_ip",
            "endpoint_a_port",
            "endpoint_b_ip",
            "endpoint_b_port",
            "packets_a_to_b",
            "packets_b_to_a",
            "bytes_a_to_b",
            "bytes_b_to_a",
        ):
            if name not in payload:
                raise ModelValidationError(f"connection requires {name}")
        flags = payload.get("tcp_flags", [])
        if flags is None:
            flags = []
        if isinstance(flags, (str, bytes)) or not isinstance(flags, Sequence):
            raise ModelValidationError("tcp_flags must be a list")
        connection = cls(
            protocol=parse_enum(Protocol, payload["protocol"], "protocol"),
            endpoint_a_ip=_require_string(payload, "endpoint_a_ip"),
            endpoint_a_port=_require_int(payload, "endpoint_a_port"),
            endpoint_b_ip=_require_string(payload, "endpoint_b_ip"),
            endpoint_b_port=_require_int(payload, "endpoint_b_port"),
            packets_a_to_b=_require_int(payload, "packets_a_to_b"),
            packets_b_to_a=_require_int(payload, "packets_b_to_a"),
            bytes_a_to_b=_require_int(payload, "bytes_a_to_b"),
            bytes_b_to_a=_require_int(payload, "bytes_b_to_a"),
            first_seen=parse_optional_datetime(payload.get("first_seen"), "first_seen"),
            last_seen=parse_optional_datetime(payload.get("last_seen"), "last_seen"),
            tcp_flags=frozenset(flags),
            packet_numbers=tuple(_packet_numbers_from_payload(payload)),
            originator_ip=_optional_string(payload, "originator_ip"),
            originator_port=_optional_int(payload, "originator_port"),
        )
        _require_matching_derived(payload, "packet_count", connection.packet_count)
        _require_matching_derived(payload, "bytes_transferred", connection.bytes_transferred)
        _require_matching_derived(payload, "key", connection.key)
        _require_matching_duration(payload, connection.duration_seconds)
        return connection


def _endpoint_sort_key(endpoint: tuple[str, int]) -> tuple[int, int]:
    return (int(ip_address(endpoint[0])), endpoint[1])


def _require_flow_port(value: object, field_name: str) -> int:
    port = require_port(value, field_name)
    if port is None:
        raise ModelValidationError(f"{field_name} is required for a TCP or UDP flow")
    return port


def _normalize_flow_flags(flags: object, protocol: Protocol) -> frozenset[TcpFlag]:
    if flags is None:
        flags = ()
    if isinstance(flags, (str, bytes, Mapping)) or not isinstance(flags, Collection):
        raise ModelValidationError("tcp_flags must be a sequence of flags")
    parsed = frozenset(parse_enum(TcpFlag, flag, "tcp_flags") for flag in flags)
    if protocol is Protocol.UDP and parsed:
        raise ModelValidationError("a UDP flow cannot carry TCP flags")
    return parsed


def _normalize_packet_numbers(numbers: object) -> tuple[int, ...]:
    if isinstance(numbers, (str, bytes)) or not isinstance(numbers, Sequence):
        raise ModelValidationError("packet_numbers must be a sequence")
    ordered: list[int] = []
    seen: set[int] = set()
    for number in numbers:
        parsed = require_packet_number(number)
        if parsed not in seen:
            seen.add(parsed)
            ordered.append(parsed)
    return tuple(ordered)


def _require_originator(
    originator_ip: str | None,
    originator_port: int | None,
    endpoint_a_ip: str,
    endpoint_a_port: int,
    endpoint_b_ip: str,
    endpoint_b_port: int,
) -> None:
    if originator_ip is None and originator_port is None:
        return
    if originator_ip is None or originator_port is None:
        raise ModelValidationError("originator_ip and originator_port must be set together")
    originator = (originator_ip, originator_port)
    endpoints = {
        (endpoint_a_ip, endpoint_a_port),
        (endpoint_b_ip, endpoint_b_port),
    }
    if originator not in endpoints:
        raise ModelValidationError("originator must be one of the flow endpoints")


def _require_string(payload: Mapping[str, object], field_name: str) -> str:
    value = payload[field_name]
    if not isinstance(value, str):
        raise ModelValidationError(f"{field_name} must be a string")
    return value


def _require_int(payload: Mapping[str, object], field_name: str) -> int:
    value = payload[field_name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError(f"{field_name} must be an integer")
    return value


def _optional_string(payload: Mapping[str, object], field_name: str) -> str | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ModelValidationError(f"{field_name} must be a string or null")
    return value


def _optional_int(payload: Mapping[str, object], field_name: str) -> int | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError(f"{field_name} must be an integer or null")
    return value


def _packet_numbers_from_payload(payload: Mapping[str, object]) -> list[object]:
    value = payload.get("packet_numbers", [])
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ModelValidationError("packet_numbers must be a list")
    return list(value)


def _require_matching_derived(payload: Mapping[str, object], field_name: str, actual: object) -> None:
    if field_name not in payload or payload[field_name] is None:
        return
    if payload[field_name] != actual:
        raise ModelValidationError(f"{field_name} does not match the flow")


def _require_matching_duration(payload: Mapping[str, object], actual: float | None) -> None:
    if "duration_seconds" not in payload or payload["duration_seconds"] is None:
        return
    supplied = payload["duration_seconds"]
    if actual is None or isinstance(supplied, bool) or not isinstance(supplied, (int, float)):
        raise ModelValidationError("duration_seconds does not match the flow timestamps")
    if abs(float(supplied) - actual) > 0.001:
        raise ModelValidationError("duration_seconds does not match the flow timestamps")
