"""Normalized packet records.

A ``Packet`` stores facts extracted from one captured frame. It does not
store the original Scapy object or the packet payload.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from packetsleuth.models.enums import Protocol, TcpFlag
from packetsleuth.models.validation import (
    ModelValidationError,
    normalize_optional_ip,
    normalize_optional_mac,
    parse_enum,
    parse_optional_datetime,
    reject_unknown_fields,
    require_mapping,
    require_non_negative,
    require_optional_datetime,
    require_optional_text,
    require_packet_number,
    require_port,
    require_ttl,
)

_EXCLUSIVE_LAYERS = (
    frozenset({Protocol.IPV4, Protocol.IPV6}),
    frozenset({Protocol.TCP, Protocol.UDP}),
    frozenset({Protocol.ICMP, Protocol.ICMPV6}),
    frozenset({Protocol.DNS, Protocol.HTTP, Protocol.TLS}),
)
_LAYER_RANK = {
    Protocol.UNKNOWN: 0,
    Protocol.ETHERNET: 2,
    Protocol.ARP: 2,
    Protocol.IPV4: 3,
    Protocol.IPV6: 3,
    Protocol.ICMP: 3,
    Protocol.ICMPV6: 3,
    Protocol.TCP: 4,
    Protocol.UDP: 4,
    Protocol.DNS: 7,
    Protocol.HTTP: 7,
    Protocol.TLS: 7,
    Protocol.OTHER: 8,
}
_PACKET_FIELDS = {
    "packet_number",
    "timestamp",
    "layers",
    "protocol",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "packet_length",
    "ttl",
    "tcp_flags",
    "dns_query",
    "dns_response",
    "http_method",
    "http_host",
    "http_path",
    "tls_metadata",
    "source_mac",
    "destination_mac",
}


@dataclass(frozen=True, slots=True)
class TlsMetadata:
    """Handshake facts that remain visible without decrypting TLS.

    Missing fields stay ``None``. A missing SNI or version is not a finding.
    """

    version: str | None = None
    sni: str | None = None
    handshake_type: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "version",
            require_optional_text(self.version, "tls_metadata.version", max_length=32),
        )
        object.__setattr__(
            self,
            "sni",
            require_optional_text(self.sni, "tls_metadata.sni", max_length=2048),
        )
        object.__setattr__(
            self,
            "handshake_type",
            require_optional_text(
                self.handshake_type,
                "tls_metadata.handshake_type",
                max_length=64,
            ),
        )

    def to_dict(self) -> dict[str, str | None]:
        """Return a JSON-ready dictionary."""
        return {
            "version": self.version,
            "sni": self.sni,
            "handshake_type": self.handshake_type,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> TlsMetadata:
        """Build TLS metadata from a dictionary."""
        payload = require_mapping(data, "tls_metadata")
        reject_unknown_fields(
            payload,
            {"version", "sni", "handshake_type"},
            "tls_metadata",
        )
        return cls(
            version=_optional_string(payload, "version"),
            sni=_optional_string(payload, "sni"),
            handshake_type=_optional_string(payload, "handshake_type"),
        )


@dataclass(frozen=True, slots=True)
class Packet:
    """One observed frame, reduced to analysis fields.

    ``layers`` is ordered from the lower layer to the higher layer. The
    ``protocol`` property is the highest identified layer. Ports, DNS, HTTP,
    and TLS fields stay empty unless that information was present.

    Attributes:
        packet_number: Position in the capture, starting at 1.
        packet_length: Observed length in bytes.
        timestamp: Capture time. ``None`` when the file has no timestamp.
        layers: Protocol layers actually identified.
        source_ip: IPv4 or IPv6 source. ``None`` when the frame has no IP layer.
        destination_ip: IPv4 or IPv6 destination.
        source_port: Transport source port.
        destination_port: Transport destination port.
        ttl: IPv4 TTL or IPv6 hop limit.
        tcp_flags: Flags on a TCP packet. ``None`` when the packet is not TCP
            or the flags could not be read. An empty set means TCP with no
            control flags set.
        dns_query: DNS query name, preserving the observed letter case.
        dns_response: Short DNS response summary, such as an address or code.
        http_method: Plaintext HTTP method.
        http_host: Host header or equivalent observed host.
        http_path: Request target without a body or userinfo.
        tls_metadata: Visible handshake metadata.
        source_mac: Link-layer source, when Ethernet addressing is present.
        destination_mac: Link-layer destination.
    """

    packet_number: int
    packet_length: int
    timestamp: datetime | None = None
    layers: tuple[Protocol, ...] = ()
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    ttl: int | None = None
    tcp_flags: frozenset[TcpFlag] | None = None
    dns_query: str | None = None
    dns_response: str | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    tls_metadata: TlsMetadata | None = None
    source_mac: str | None = None
    destination_mac: str | None = None

    def __post_init__(self) -> None:
        layers = _normalize_layers(self.layers)
        flags = _normalize_tcp_flags(self.tcp_flags, layers)
        http_method = _normalize_http_method(self.http_method)
        http_path = _normalize_http_path(self.http_path)
        object.__setattr__(self, "packet_number", require_packet_number(self.packet_number))
        object.__setattr__(self, "packet_length", require_non_negative(self.packet_length, "packet_length"))
        object.__setattr__(self, "timestamp", require_optional_datetime(self.timestamp, "timestamp"))
        object.__setattr__(self, "layers", layers)
        object.__setattr__(self, "source_ip", normalize_optional_ip(self.source_ip, "source_ip"))
        object.__setattr__(
            self,
            "destination_ip",
            normalize_optional_ip(self.destination_ip, "destination_ip"),
        )
        object.__setattr__(self, "source_port", require_port(self.source_port, "source_port"))
        object.__setattr__(
            self,
            "destination_port",
            require_port(self.destination_port, "destination_port"),
        )
        object.__setattr__(self, "ttl", require_ttl(self.ttl))
        object.__setattr__(self, "tcp_flags", flags)
        object.__setattr__(
            self,
            "dns_query",
            require_optional_text(self.dns_query, "dns_query", max_length=4096),
        )
        object.__setattr__(
            self,
            "dns_response",
            require_optional_text(self.dns_response, "dns_response", max_length=500),
        )
        object.__setattr__(self, "http_method", http_method)
        object.__setattr__(
            self,
            "http_host",
            require_optional_text(self.http_host, "http_host", max_length=2048),
        )
        object.__setattr__(self, "http_path", http_path)
        object.__setattr__(self, "source_mac", normalize_optional_mac(self.source_mac, "source_mac"))
        object.__setattr__(
            self,
            "destination_mac",
            normalize_optional_mac(self.destination_mac, "destination_mac"),
        )
        if self.tls_metadata is not None and not isinstance(self.tls_metadata, TlsMetadata):
            raise ModelValidationError("tls_metadata must be a TlsMetadata value")
        _require_transport_for_ports(layers, self.source_port, self.destination_port)
        _require_ip_for_ttl(layers, self.ttl, self.source_ip, self.destination_ip)

    @property
    def protocol(self) -> Protocol:
        """Return the highest identified layer, or ``UNKNOWN``."""
        if not self.layers:
            return Protocol.UNKNOWN
        return self.layers[-1]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready dictionary. Derived ``protocol`` is included."""
        return {
            "packet_number": self.packet_number,
            "timestamp": None if self.timestamp is None else self.timestamp.isoformat(),
            "layers": [layer.value for layer in self.layers],
            "protocol": self.protocol.value,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "packet_length": self.packet_length,
            "ttl": self.ttl,
            "tcp_flags": None
            if self.tcp_flags is None
            else [flag.value for flag in sorted(self.tcp_flags, key=lambda item: item.value)],
            "dns_query": self.dns_query,
            "dns_response": self.dns_response,
            "http_method": self.http_method,
            "http_host": self.http_host,
            "http_path": self.http_path,
            "tls_metadata": None if self.tls_metadata is None else self.tls_metadata.to_dict(),
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Packet:
        """Build a packet from a dictionary produced by ``to_dict``."""
        payload = require_mapping(data, "packet")
        reject_unknown_fields(payload, _PACKET_FIELDS, "packet")
        if "packet_number" not in payload or "packet_length" not in payload:
            raise ModelValidationError("packet requires packet_number and packet_length")
        layers = _layers_from_payload(payload)
        tls_value = payload.get("tls_metadata")
        tls_metadata = None
        if tls_value is not None:
            if not isinstance(tls_value, Mapping):
                raise ModelValidationError("tls_metadata must be an object or null")
            tls_metadata = TlsMetadata.from_dict(tls_value)
        timestamp = payload.get("timestamp")
        parsed_timestamp = None
        if timestamp is not None:
            parsed_timestamp = parse_optional_datetime(timestamp, "timestamp")
        return cls(
            packet_number=_required_value(payload, "packet_number"),
            packet_length=_required_value(payload, "packet_length"),
            timestamp=parsed_timestamp,
            layers=layers,
            source_ip=_optional_string(payload, "source_ip"),
            destination_ip=_optional_string(payload, "destination_ip"),
            source_port=_optional_port(payload, "source_port"),
            destination_port=_optional_port(payload, "destination_port"),
            ttl=_optional_port(payload, "ttl"),
            tcp_flags=_flags_from_payload(payload),
            dns_query=_optional_string(payload, "dns_query"),
            dns_response=_optional_string(payload, "dns_response"),
            http_method=_optional_string(payload, "http_method"),
            http_host=_optional_string(payload, "http_host"),
            http_path=_optional_string(payload, "http_path"),
            tls_metadata=tls_metadata,
            source_mac=_optional_string(payload, "source_mac"),
            destination_mac=_optional_string(payload, "destination_mac"),
        )


def _required_value(payload: Mapping[str, object], field_name: str) -> object:
    if field_name not in payload:
        raise ModelValidationError(f"packet requires {field_name}")
    return payload[field_name]


def _optional_string(payload: Mapping[str, object], field_name: str) -> str | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ModelValidationError(f"{field_name} must be a string or null")
    return value


def _optional_port(payload: Mapping[str, object], field_name: str) -> int | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError(f"{field_name} must be an integer or null")
    return value


def _normalize_layers(layers: Sequence[Protocol] | Sequence[str]) -> tuple[Protocol, ...]:
    if isinstance(layers, (str, bytes)) or not isinstance(layers, Sequence):
        raise ModelValidationError("layers must be a sequence of protocols")
    parsed = tuple(parse_enum(Protocol, layer, "layers") for layer in layers)
    if len(set(parsed)) != len(parsed):
        raise ModelValidationError("layers contains a duplicate protocol")
    if Protocol.UNKNOWN in parsed and len(parsed) > 1:
        raise ModelValidationError("unknown cannot be combined with another protocol")
    has_icmp = Protocol.ICMP in parsed or Protocol.ICMPV6 in parsed
    has_transport = Protocol.TCP in parsed or Protocol.UDP in parsed
    if has_icmp and has_transport:
        raise ModelValidationError("ICMP and a transport protocol cannot share a packet")
    for group in _EXCLUSIVE_LAYERS:
        found = [layer.value for layer in parsed if layer in group]
        if len(found) > 1:
            names = " and ".join(found)
            raise ModelValidationError(f"a packet cannot contain both {names}")
    ranks = [_LAYER_RANK[layer] for layer in parsed]
    if ranks != sorted(ranks):
        raise ModelValidationError("layers must run from the lower layer to the higher layer")
    return parsed


def _normalize_tcp_flags(
    flags: frozenset[TcpFlag] | Sequence[TcpFlag] | Sequence[str] | None,
    layers: Sequence[Protocol],
) -> frozenset[TcpFlag] | None:
    if flags is None:
        return None
    if isinstance(flags, (str, bytes, Mapping)) or not isinstance(flags, Collection):
        raise ModelValidationError("tcp_flags must be a set of TCP flags or null")
    parsed = frozenset(parse_enum(TcpFlag, flag, "tcp_flags") for flag in flags)
    if Protocol.TCP not in layers:
        raise ModelValidationError("tcp_flags requires a TCP layer")
    return parsed


def _normalize_http_method(value: str | None) -> str | None:
    method = require_optional_text(value, "http_method", max_length=20)
    if method is None:
        return None
    if not method.replace("-", "").isalnum() or not method[0].isalpha():
        raise ModelValidationError("http_method must be an HTTP method token")
    return method.upper()


def _normalize_http_path(value: str | None) -> str | None:
    path = require_optional_text(value, "http_path", max_length=2048)
    if path is None:
        return None
    if "://" in path or "@" in path:
        raise ModelValidationError("http_path must not contain a URL userinfo or scheme")
    if path != "*" and not path.startswith("/"):
        raise ModelValidationError("http_path must start with / or be *")
    return path


def _require_transport_for_ports(
    layers: Sequence[Protocol],
    source_port: int | None,
    destination_port: int | None,
) -> None:
    if source_port is None and destination_port is None:
        return
    if Protocol.TCP not in layers and Protocol.UDP not in layers:
        raise ModelValidationError("ports require a TCP or UDP layer")


def _require_ip_for_ttl(
    layers: Sequence[Protocol],
    ttl: int | None,
    source_ip: str | None,
    destination_ip: str | None,
) -> None:
    if ttl is None:
        return
    has_ip_layer = Protocol.IPV4 in layers or Protocol.IPV6 in layers
    if not has_ip_layer and source_ip is None and destination_ip is None:
        raise ModelValidationError("ttl requires an IPv4 or IPv6 observation")


def _layers_from_payload(payload: Mapping[str, object]) -> tuple[Protocol, ...]:
    raw_layers = payload.get("layers", ())
    if raw_layers is None:
        raw_layers = ()
    if isinstance(raw_layers, (str, bytes)) or not isinstance(raw_layers, Sequence):
        raise ModelValidationError("layers must be a list of protocols")
    layers = _normalize_layers(tuple(raw_layers))
    if "protocol" not in payload or payload["protocol"] is None:
        return layers
    protocol = parse_enum(Protocol, payload["protocol"], "protocol")
    highest = Protocol.UNKNOWN if not layers else layers[-1]
    if protocol != highest:
        raise ModelValidationError("protocol does not match the highest layer")
    return layers


def _flags_from_payload(payload: Mapping[str, object]) -> frozenset[TcpFlag] | None:
    if "tcp_flags" not in payload or payload["tcp_flags"] is None:
        return None
    raw_flags = payload["tcp_flags"]
    if isinstance(raw_flags, (str, bytes)) or not isinstance(raw_flags, Sequence):
        raise ModelValidationError("tcp_flags must be a list or null")
    return frozenset(raw_flags)

