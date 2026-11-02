"""Classify IP addresses and summarize what the capture actually showed.

Classification describes how an address is allocated. It does not decide
whether the traffic is safe or hostile, and it does not look up a location
or a reputation service.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address, ip_network

from packetsleuth.models.enums import Protocol
from packetsleuth.models.packet import Packet
from packetsleuth.models.validation import ModelValidationError, normalize_ip

_PRIVATE_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("fc00::/7"),
)
_DOCUMENTATION_NETWORKS = (
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
    ip_network("2001:db8::/32"),
)
_SHARED_NETWORKS = (ip_network("100.64.0.0/10"),)

ADDRESS_CLASS_NOTE = (
    "Address class describes allocation, not intent. "
    "A private address is not evidence of safety, and a public address is not evidence of malice."
)
TTL_NOTE = (
    "TTL and hop limit decrease by one at each router. "
    "The observed value is not by itself an operating-system identification."
)


class AddressClass(Enum):
    """One allocation label for an IP address."""

    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    RESERVED = "reserved"


@dataclass(frozen=True, slots=True)
class IpAddressSummary:
    """How often one IP address appeared as a source or a destination."""

    address: str
    version: int
    classification: AddressClass
    source_packets: int
    destination_packets: int

    @property
    def packet_count(self) -> int:
        """Return the number of IP headers in which this address appeared."""
        return self.source_packets + self.destination_packets


@dataclass(frozen=True, slots=True)
class TtlObservation:
    """One observed TTL or hop-limit value and how many IP packets had it."""

    value: int
    packet_count: int


@dataclass(frozen=True, slots=True)
class IpAnalysis:
    """IP-header facts computed from normalized packets."""

    ipv4_packets: int
    ipv6_packets: int
    non_ip_packets: int
    fragmented_packets: int
    addresses: tuple[IpAddressSummary, ...]
    ttl_values: tuple[TtlObservation, ...]
    minimum_ttl: int | None
    maximum_ttl: int | None
    most_common_ttl: int | None
    address_note: str = ADDRESS_CLASS_NOTE
    ttl_note: str = TTL_NOTE


def classify_ip(value: str) -> AddressClass:
    """Classify an IP address by allocation.

    Documentation ranges such as ``192.0.2.0/24`` and ``2001:db8::/32`` are
    reserved, not private. Python's ``is_private`` flag groups some of those
    ranges with private addresses, so this function uses a fixed order instead.

    Args:
        value: An IPv4 or IPv6 address.

    Raises:
        ModelValidationError: ``value`` is not an IP address.
    """
    address = ip_address(normalize_ip(value, "ip"))
    if address.is_unspecified:
        return AddressClass.RESERVED
    if address.is_loopback:
        return AddressClass.LOOPBACK
    if address.is_link_local:
        return AddressClass.LINK_LOCAL
    if address.is_multicast:
        return AddressClass.MULTICAST
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return AddressClass.RESERVED
    if any(address in network for network in _PRIVATE_NETWORKS):
        return AddressClass.PRIVATE
    if address.is_reserved or any(address in network for network in _SHARED_NETWORKS):
        return AddressClass.RESERVED
    if address.is_global:
        return AddressClass.PUBLIC
    return AddressClass.RESERVED


def analyze_ips(packets: tuple[Packet, ...] | list[Packet]) -> IpAnalysis:
    """Summarize IP versions, addresses, fragments, and TTL values.

    ARP protocol addresses are not counted as IP packets. Only an IPv4 or
    IPv6 header contributes to the address and TTL summaries.
    """
    if not isinstance(packets, (tuple, list)) or any(not isinstance(packet, Packet) for packet in packets):
        raise ModelValidationError("IP analysis requires Packet records")

    ipv4_packets = 0
    ipv6_packets = 0
    non_ip_packets = 0
    fragmented_packets = 0
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    ttl_counts: Counter[int] = Counter()

    for packet in packets:
        version = _ip_version(packet)
        if version == 4:
            ipv4_packets += 1
        elif version == 6:
            ipv6_packets += 1
        else:
            non_ip_packets += 1
            continue
        if _is_fragment(packet):
            fragmented_packets += 1
        if packet.source_ip is not None:
            source_counts[packet.source_ip] += 1
        if packet.destination_ip is not None:
            destination_counts[packet.destination_ip] += 1
        if packet.ttl is not None:
            ttl_counts[packet.ttl] += 1

    addresses = tuple(
        _address_summary(address, source_counts[address], destination_counts[address])
        for address in sorted(
            set(source_counts) | set(destination_counts),
            key=lambda item: (-(source_counts[item] + destination_counts[item]), item),
        )
    )
    ttl_values = tuple(
        TtlObservation(value=value, packet_count=ttl_counts[value]) for value in sorted(ttl_counts)
    )
    most_common = None
    if ttl_counts:
        most_common = min(ttl_counts, key=lambda value: (-ttl_counts[value], value))
    return IpAnalysis(
        ipv4_packets=ipv4_packets,
        ipv6_packets=ipv6_packets,
        non_ip_packets=non_ip_packets,
        fragmented_packets=fragmented_packets,
        addresses=addresses,
        ttl_values=ttl_values,
        minimum_ttl=min(ttl_counts) if ttl_counts else None,
        maximum_ttl=max(ttl_counts) if ttl_counts else None,
        most_common_ttl=most_common,
    )


def _ip_version(packet: Packet) -> int | None:
    if Protocol.IPV4 in packet.layers:
        return 4
    if Protocol.IPV6 in packet.layers:
        return 6
    return None


def _is_fragment(packet: Packet) -> bool:
    if packet.fragment_offset is None and packet.more_fragments is None:
        return False
    return bool(packet.more_fragments) or (packet.fragment_offset or 0) > 0


def _address_summary(address: str, source_packets: int, destination_packets: int) -> IpAddressSummary:
    parsed = ip_address(address)
    return IpAddressSummary(
        address=address,
        version=parsed.version,
        classification=classify_ip(address),
        source_packets=source_packets,
        destination_packets=destination_packets,
    )
