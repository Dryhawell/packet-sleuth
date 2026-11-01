"""Shared enumerations for normalized analysis records.

These values name what a later parser actually observed. They are not guesses
based on port numbers.
"""

from __future__ import annotations

from enum import Enum


class Protocol(Enum):
    """A protocol layer PacketSleuth knows how to name.

    Members follow the stack from the link layer toward the application.
    ``UNKNOWN`` means the layer was not identified. ``OTHER`` means a layer
    was present but is not one of the named protocols.
    """

    ETHERNET = "ethernet"
    ARP = "arp"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    OTHER = "other"
    UNKNOWN = "unknown"


class TcpFlag(Enum):
    """A TCP control flag observed on a packet or summarized on a flow.

    Flag letters are the ones used in ordinary packet analysis. A set of
    flags describes one packet. A flow stores the union of flags it saw.
    """

    FIN = "FIN"
    SYN = "SYN"
    RST = "RST"
    PSH = "PSH"
    ACK = "ACK"
    URG = "URG"


class Severity(Enum):
    """How urgently a human should look at an alert.

    Severity is an analyst aid. It does not prove that an attack succeeded.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
