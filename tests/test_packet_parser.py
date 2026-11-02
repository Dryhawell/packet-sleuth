"""Tests for link, network, and transport normalization."""

from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetsleuth.capture import CaptureReader
from packetsleuth.capture.pcap_reader import CapturedFrame
from packetsleuth.models import Packet, Protocol, TcpFlag
from packetsleuth.parsers import parse_frame, parse_frames

WHEN = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
SOURCE_MAC = "aa:bb:cc:dd:ee:01"
DEST_MAC = "aa:bb:cc:dd:ee:02"


def _frame(packet: object, number: int = 1) -> CapturedFrame:
    return CapturedFrame(packet_number=number, timestamp=WHEN, packet=packet)  # type: ignore[arg-type]


def test_ethernet_ipv4_tcp_extracts_header_fields_without_guessing_http() -> None:
    raw = (
        Ether(src=SOURCE_MAC, dst=DEST_MAC)
        / IP(src="192.0.2.10", dst="192.0.2.20", ttl=64)
        / TCP(sport=12345, dport=80, flags="S")
    )
    packet = parse_frame(_frame(raw))

    assert packet.layers == (Protocol.ETHERNET, Protocol.IPV4, Protocol.TCP)
    assert packet.protocol is Protocol.TCP
    assert packet.source_mac == SOURCE_MAC
    assert packet.destination_mac == DEST_MAC
    assert packet.source_ip == "192.0.2.10"
    assert packet.destination_ip == "192.0.2.20"
    assert packet.source_port == 12345
    assert packet.destination_port == 80
    assert packet.ttl == 64
    assert packet.tcp_flags == frozenset({TcpFlag.SYN})
    assert packet.http_method is None
    assert packet.timestamp == WHEN
    assert packet.packet_length > 0


def test_udp_port_53_is_not_labeled_dns() -> None:
    raw = Ether() / IP(src="192.0.2.10", dst="192.0.2.53", ttl=32) / UDP(sport=41000, dport=53)
    packet = parse_frame(_frame(raw))

    assert packet.protocol is Protocol.UDP
    assert Protocol.DNS not in packet.layers
    assert packet.destination_port == 53
    assert packet.dns_query is None
    assert packet.tcp_flags is None


def test_icmp_error_does_not_adopt_the_quoted_tcp_header() -> None:
    quoted = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=12345, dport=443, flags="S")
    raw = Ether() / IP(src="192.0.2.1", dst="192.0.2.10", ttl=54) / ICMP(type=11, code=0) / quoted
    packet = parse_frame(_frame(raw))

    assert packet.layers == (Protocol.ETHERNET, Protocol.IPV4, Protocol.ICMP)
    assert packet.protocol is Protocol.ICMP
    assert packet.source_ip == "192.0.2.1"
    assert packet.destination_ip == "192.0.2.10"
    assert packet.source_port is None
    assert packet.tcp_flags is None


def test_arp_keeps_protocol_addresses_separate_from_ipv4() -> None:
    raw = Ether(src=SOURCE_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc=SOURCE_MAC,
        psrc="192.0.2.10",
        hwdst="00:00:00:00:00:00",
        pdst="192.0.2.20",
    )
    packet = parse_frame(_frame(raw))

    assert packet.layers == (Protocol.ETHERNET, Protocol.ARP)
    assert packet.protocol is Protocol.ARP
    assert Protocol.IPV4 not in packet.layers
    assert packet.source_ip == "192.0.2.10"
    assert packet.destination_ip == "192.0.2.20"
    assert packet.ttl is None
    assert packet.source_port is None


def test_ipv6_udp_and_icmpv6_use_the_hop_limit() -> None:
    udp = (
        Ether(src=SOURCE_MAC, dst=DEST_MAC)
        / IPv6(src="2001:db8::10", dst="2001:db8::20", hlim=32)
        / UDP(sport=12345, dport=53)
    )
    echo = (
        Ether(src=SOURCE_MAC, dst=DEST_MAC)
        / IPv6(src="2001:db8::10", dst="2001:db8::20", hlim=64)
        / ICMPv6EchoRequest()
    )

    udp_packet = parse_frame(_frame(udp))
    echo_packet = parse_frame(_frame(echo, number=2))

    assert udp_packet.layers == (Protocol.ETHERNET, Protocol.IPV6, Protocol.UDP)
    assert udp_packet.source_ip == "2001:db8::10"
    assert udp_packet.ttl == 32
    assert udp_packet.dns_query is None
    assert echo_packet.layers == (Protocol.ETHERNET, Protocol.IPV6, Protocol.ICMPV6)
    assert echo_packet.protocol is Protocol.ICMPV6
    assert echo_packet.source_port is None
    assert echo_packet.ttl == 64


def test_outer_ip_tunnel_does_not_claim_the_inner_transport() -> None:
    raw = IP(src="192.0.2.10", dst="192.0.2.20", ttl=16) / IPv6(
        src="2001:db8::10", dst="2001:db8::20"
    ) / UDP(sport=1, dport=2)
    packet = parse_frame(_frame(raw))

    assert packet.layers == (Protocol.IPV4,)
    assert packet.protocol is Protocol.IPV4
    assert packet.source_port is None
    assert packet.ttl == 16


def test_unknown_and_unreadable_frames_still_produce_records() -> None:
    raw_packet = parse_frame(_frame(Raw(load=b"abc")))
    blank = parse_frame(_frame(object(), number=2))

    assert raw_packet.protocol is Protocol.UNKNOWN
    assert raw_packet.layers == ()
    assert raw_packet.source_ip is None
    assert raw_packet.packet_length == 3
    assert isinstance(blank, Packet)
    assert blank.protocol is Protocol.UNKNOWN
    assert blank.packet_number == 2
    assert blank.timestamp == WHEN


def test_reader_and_parser_share_packet_numbers(tmp_path: Path) -> None:
    path = tmp_path / "two.pcap"
    first = Ether(src=SOURCE_MAC, dst=DEST_MAC) / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
        sport=40000, dport=443, flags="PA"
    )
    second = Ether() / IP(src="192.0.2.20", dst="192.0.2.10") / TCP(sport=443, dport=40000, flags="A")
    first.time = 1_700_000_000
    second.time = 1_700_000_002
    wrpcap(str(path), [first, second])

    with CaptureReader(path) as reader:
        packets = list(parse_frames(reader))

    assert [packet.packet_number for packet in packets] == [1, 2]
    assert packets[0].tcp_flags == frozenset({TcpFlag.PSH, TcpFlag.ACK})
    assert packets[1].tcp_flags == frozenset({TcpFlag.ACK})
    assert packets[0].timestamp == datetime.fromtimestamp(1_700_000_000, tz=timezone.utc)
    assert packets[0].destination_port == 443
    assert packets[0].tls_metadata is None
