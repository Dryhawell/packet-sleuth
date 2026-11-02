"""Identify link, network, and transport layers that are actually present.

A port number is not a protocol. This module only names a layer when Scapy
has decoded that header on the frame being inspected. Headers quoted inside
an ICMP error belong to the cited packet, so they are not added here.
"""

from __future__ import annotations

from dataclasses import dataclass

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import NoPayload, Packet as ScapyPacket

from packetsleuth.models.enums import Protocol


@dataclass(frozen=True, slots=True)
class LayerView:
    """The headers that belong to one frame, outside quoted payloads.

    Only the first network header is kept. An IP packet that carries another
    IP packet is not described as both versions at once.
    """

    layers: tuple[Protocol, ...]
    ethernet: Ether | None = None
    arp: ARP | None = None
    ipv4: IP | None = None
    ipv6: IPv6 | None = None
    icmp: ICMP | None = None
    tcp: TCP | None = None
    udp: UDP | None = None


def inspect_layers(packet: ScapyPacket) -> LayerView:
    """Return the decoded headers that describe this frame.

    Args:
        packet: Raw packet object produced by the capture reader.

    Returns:
        An empty view when ``packet`` is not a Scapy packet.
    """
    if not isinstance(packet, ScapyPacket):
        return LayerView(layers=())

    layers: list[Protocol] = []
    ethernet: Ether | None = None
    arp: ARP | None = None
    ipv4: IP | None = None
    ipv6: IPv6 | None = None
    icmp: ICMP | None = None
    tcp: TCP | None = None
    udp: UDP | None = None
    seen_network = False
    current: ScapyPacket | NoPayload = packet

    while not isinstance(current, NoPayload):
        if isinstance(current, Ether):
            if Protocol.ETHERNET not in layers:
                layers.append(Protocol.ETHERNET)
                ethernet = current
        elif isinstance(current, ARP):
            layers.append(Protocol.ARP)
            arp = current
            break
        elif isinstance(current, IP):
            if seen_network:
                break
            layers.append(Protocol.IPV4)
            ipv4 = current
            seen_network = True
        elif isinstance(current, IPv6):
            if seen_network:
                break
            layers.append(Protocol.IPV6)
            ipv6 = current
            seen_network = True
        elif isinstance(current, ICMP):
            layers.append(Protocol.ICMP)
            icmp = current
            break
        elif isinstance(current, _ICMPv6):
            layers.append(Protocol.ICMPV6)
            break
        elif isinstance(current, TCP):
            layers.append(Protocol.TCP)
            tcp = current
            break
        elif isinstance(current, UDP):
            layers.append(Protocol.UDP)
            udp = current
            break

        nxt = current.payload
        if nxt is current:
            break
        current = nxt

    return LayerView(
        layers=tuple(layers),
        ethernet=ethernet,
        arp=arp,
        ipv4=ipv4,
        ipv6=ipv6,
        icmp=icmp,
        tcp=tcp,
        udp=udp,
    )
