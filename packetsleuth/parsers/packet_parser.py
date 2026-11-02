"""Normalize one captured frame into a PacketSleuth ``Packet``.

Application fields are filled only from a DNS message, an HTTP start line,
or a TLS record in this frame. Ports do not select those protocols.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator

from scapy.layers.inet import TCP
from scapy.packet import NoPayload, Packet as ScapyPacket

from packetsleuth.capture.pcap_reader import CapturedFrame
from packetsleuth.models.enums import Protocol, TcpFlag
from packetsleuth.models.packet import Packet
from packetsleuth.models.validation import (
    ModelValidationError,
    normalize_optional_ip,
    normalize_optional_mac,
    require_port,
    require_ttl,
)
from packetsleuth.parsers.dns_parser import parse_dns_metadata
from packetsleuth.parsers.http_parser import parse_http_metadata
from packetsleuth.parsers.protocol_parser import LayerView, inspect_layers
from packetsleuth.parsers.tls_parser import parse_tls_metadata

logger = logging.getLogger("packetsleuth.parsers")

_TCP_FLAG_BITS = (
    ("F", TcpFlag.FIN),
    ("S", TcpFlag.SYN),
    ("R", TcpFlag.RST),
    ("P", TcpFlag.PSH),
    ("A", TcpFlag.ACK),
    ("U", TcpFlag.URG),
)


def parse_frame(frame: CapturedFrame) -> Packet:
    """Convert one raw frame into a normalized packet.

    A frame that cannot be interpreted still produces a packet record.
    Unknown fields stay empty instead of being guessed. ``packet_number``
    and ``timestamp`` are taken from the reader, not invented here.

    Args:
        frame: One item yielded by ``CaptureReader``.

    Returns:
        A validated ``Packet``.
    """
    length = _observed_length(frame.packet)
    view = _safe_view(frame)
    try:
        return Packet(
            packet_number=frame.packet_number,
            packet_length=length,
            timestamp=frame.timestamp,
            **_fields_from_view(view),
        )
    except ModelValidationError:
        logger.warning(
            "Packet %s contained inconsistent header fields and was stored without them",
            frame.packet_number,
        )
        return Packet(
            packet_number=frame.packet_number,
            packet_length=length,
            timestamp=frame.timestamp,
        )


def parse_frames(frames: Iterable[CapturedFrame]) -> Iterator[Packet]:
    """Normalize frames one at a time, in capture order."""
    for frame in frames:
        yield parse_frame(frame)


def _safe_view(frame: CapturedFrame) -> LayerView:
    try:
        return inspect_layers(frame.packet)
    except Exception:
        logger.warning("Packet %s could not be inspected", frame.packet_number)
        return LayerView(layers=())


def _fields_from_view(view: LayerView) -> dict[str, object]:
    source_mac, destination_mac = _mac_addresses(view)
    source_ip, destination_ip, ttl = _network_fields(view)
    source_port, destination_port, tcp_flags = _transport_fields(view)
    layers, application = _application_fields(view)
    return {
        "layers": layers,
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "ttl": ttl,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        **application,
    }


def _mac_addresses(view: LayerView) -> tuple[str | None, str | None]:
    if view.ethernet is not None:
        return _optional_mac(_attr(view.ethernet, "src")), _optional_mac(_attr(view.ethernet, "dst"))
    if view.arp is not None:
        return _optional_mac(_attr(view.arp, "hwsrc")), _optional_mac(_attr(view.arp, "hwdst"))
    return None, None


def _network_fields(view: LayerView) -> tuple[str | None, str | None, int | None]:
    if view.ipv4 is not None:
        return (
            _optional_ip(_attr(view.ipv4, "src")),
            _optional_ip(_attr(view.ipv4, "dst")),
            _optional_ttl(_attr(view.ipv4, "ttl")),
        )
    if view.ipv6 is not None:
        return (
            _optional_ip(_attr(view.ipv6, "src")),
            _optional_ip(_attr(view.ipv6, "dst")),
            _optional_ttl(_attr(view.ipv6, "hlim")),
        )
    if view.arp is not None:
        return _optional_ip(_attr(view.arp, "psrc")), _optional_ip(_attr(view.arp, "pdst")), None
    return None, None, None


def _transport_fields(
    view: LayerView,
) -> tuple[int | None, int | None, frozenset[TcpFlag] | None]:
    transport = view.tcp if view.tcp is not None else view.udp
    if transport is None:
        return None, None, None
    flags = _tcp_flags(view.tcp) if view.tcp is not None else None
    return _optional_port(_attr(transport, "sport")), _optional_port(_attr(transport, "dport")), flags


def _attr(layer: object, name: str) -> object:
    """Read one Scapy field. A missing interface or route becomes ``None``."""
    try:
        return getattr(layer, name)
    except Exception:
        return None


def _application_fields(view: LayerView) -> tuple[tuple[Protocol, ...], dict[str, object]]:
    """Add at most one application protocol found in this frame's payload."""
    transport = view.tcp if view.tcp is not None else view.udp
    if transport is None:
        return view.layers, {}
    payload = _payload_bytes(transport)
    if view.tcp is not None:
        http = parse_http_metadata(payload)
        if http is not None:
            return (*view.layers, Protocol.HTTP), {
                "http_method": http.method,
                "http_host": http.host,
                "http_path": http.path,
            }
        tls = parse_tls_metadata(payload)
        if tls is not None:
            return (*view.layers, Protocol.TLS), {"tls_metadata": tls}
    dns = parse_dns_metadata(payload, length_prefixed=view.tcp is not None)
    if dns is not None:
        return (*view.layers, Protocol.DNS), {
            "dns_query": dns.query_name,
            "dns_response": dns.response_summary,
        }
    return view.layers, {}


def _payload_bytes(transport: object) -> bytes:
    payload = getattr(transport, "payload", None)
    if payload is None or isinstance(payload, NoPayload):
        return b""
    original = getattr(payload, "original", b"")
    if isinstance(original, (bytes, bytearray)) and original:
        return bytes(original)
    try:
        return bytes(payload)
    except Exception:
        return b""


def _tcp_flags(tcp: TCP) -> frozenset[TcpFlag] | None:
    raw_flags = _attr(tcp, "flags")
    if raw_flags is None:
        return None
    observed: list[TcpFlag] = []
    for letter, flag in _TCP_FLAG_BITS:
        try:
            present = letter in raw_flags
        except Exception:
            return None
        if present:
            observed.append(flag)
    return frozenset(observed)


def _observed_length(packet: object) -> int:
    wirelen = getattr(packet, "wirelen", None)
    if isinstance(wirelen, int) and not isinstance(wirelen, bool) and wirelen >= 0:
        return wirelen
    if isinstance(packet, ScapyPacket):
        try:
            return len(packet)
        except Exception:
            return 0
    return 0


def _optional_mac(value: object) -> str | None:
    try:
        return normalize_optional_mac(value if isinstance(value, str) else None, "mac")
    except ModelValidationError:
        return None


def _optional_ip(value: object) -> str | None:
    try:
        return normalize_optional_ip(value if isinstance(value, str) else None, "ip")
    except ModelValidationError:
        return None


def _optional_port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return require_port(value, "port")
    except ModelValidationError:
        return None


def _optional_ttl(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return require_ttl(value)
    except ModelValidationError:
        return None
