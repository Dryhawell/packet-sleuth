"""Tests for IP classification, version counts, TTL, and fragments."""

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from packetsleuth.analysis import AddressClass, analyze_ips, classify_ip
from packetsleuth.models import Packet, Protocol
from packetsleuth.parsers import parse_frame
from tests.test_packet_parser import SOURCE_MAC, DEST_MAC, _frame


def _ip_packet(source: str, destination: str, ttl: int, version: int = 4) -> Packet:
    if version == 6:
        raw = Ether(src=SOURCE_MAC, dst=DEST_MAC) / IPv6(src=source, dst=destination, hlim=ttl) / TCP(
            sport=12345, dport=80, flags="S"
        )
    else:
        raw = Ether(src=SOURCE_MAC, dst=DEST_MAC) / IP(src=source, dst=destination, ttl=ttl) / TCP(
            sport=12345, dport=80, flags="S"
        )
    return parse_frame(_frame(raw))


def test_address_classes_follow_allocation_not_reputation() -> None:
    assert classify_ip("10.1.2.3") is AddressClass.PRIVATE
    assert classify_ip("192.168.1.10") is AddressClass.PRIVATE
    assert classify_ip("fd00::1") is AddressClass.PRIVATE
    assert classify_ip("127.0.0.1") is AddressClass.LOOPBACK
    assert classify_ip("::1") is AddressClass.LOOPBACK
    assert classify_ip("169.254.10.10") is AddressClass.LINK_LOCAL
    assert classify_ip("fe80::1") is AddressClass.LINK_LOCAL
    assert classify_ip("224.0.0.1") is AddressClass.MULTICAST
    assert classify_ip("ff02::1") is AddressClass.MULTICAST
    assert classify_ip("192.0.2.10") is AddressClass.RESERVED
    assert classify_ip("198.51.100.5") is AddressClass.RESERVED
    assert classify_ip("203.0.113.9") is AddressClass.RESERVED
    assert classify_ip("2001:db8::1") is AddressClass.RESERVED
    assert classify_ip("100.64.0.1") is AddressClass.RESERVED
    assert classify_ip("8.8.8.8") is AddressClass.PUBLIC


def test_ip_summary_counts_versions_addresses_and_ttl() -> None:
    packets = [
        _ip_packet("192.0.2.10", "10.0.0.1", 64),
        _ip_packet("192.0.2.10", "10.0.0.1", 64),
        _ip_packet("2001:db8::10", "2001:db8::20", 128, version=6),
        parse_frame(
            _frame(
                Ether(src=SOURCE_MAC, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=1, hwsrc=SOURCE_MAC, psrc="192.0.2.10", hwdst="00:00:00:00:00:00", pdst="192.0.2.20")
            )
        ),
    ]
    summary = analyze_ips(packets)

    assert summary.ipv4_packets == 2
    assert summary.ipv6_packets == 1
    assert summary.non_ip_packets == 1
    assert summary.fragmented_packets == 0
    assert summary.minimum_ttl == 64
    assert summary.maximum_ttl == 128
    assert summary.most_common_ttl == 64
    by_address = {item.address: item for item in summary.addresses}
    assert Protocol.IPV4 not in packets[3].layers
    assert "192.0.2.20" not in by_address
    assert by_address["192.0.2.10"].classification is AddressClass.RESERVED
    assert by_address["192.0.2.10"].source_packets == 2
    assert by_address["10.0.0.1"].classification is AddressClass.PRIVATE
    assert by_address["10.0.0.1"].destination_packets == 2
    assert by_address["2001:db8::10"].version == 6
    assert "not evidence of safety" in summary.address_note
    assert "operating-system" in summary.ttl_note


def test_equal_ttl_counts_choose_the_lower_value() -> None:
    packets = [
        _ip_packet("192.0.2.10", "192.0.2.20", 128),
        _ip_packet("192.0.2.10", "192.0.2.20", 64),
    ]
    summary = analyze_ips(packets)

    assert summary.most_common_ttl == 64
    assert [item.value for item in summary.ttl_values] == [64, 128]


def test_ipv4_and_ipv6_fragments_are_counted() -> None:
    first = parse_frame(
        _frame(
            Ether(src=SOURCE_MAC, dst=DEST_MAC)
            / IP(src="192.0.2.10", dst="192.0.2.20", ttl=64, flags="MF", frag=0)
            / Raw(b"abcd")
        )
    )
    later = parse_frame(
        _frame(
            Ether(src=SOURCE_MAC, dst=DEST_MAC)
            / IP(src="192.0.2.10", dst="192.0.2.20", ttl=64, frag=1)
            / Raw(b"efgh"),
            number=2,
        )
    )
    ipv6 = parse_frame(
        _frame(
            Ether(src=SOURCE_MAC, dst=DEST_MAC)
            / IPv6(src="2001:db8::10", dst="2001:db8::20", hlim=64)
            / IPv6ExtHdrFragment(offset=1, m=1)
            / Raw(b"ijkl"),
            number=3,
        )
    )

    assert first.fragment_offset == 0
    assert first.more_fragments is True
    assert later.fragment_offset == 8
    assert later.more_fragments is False
    assert ipv6.fragment_offset == 8
    assert ipv6.more_fragments is True
    assert analyze_ips([first, later, ipv6]).fragmented_packets == 3


def test_empty_capture_has_no_invented_ttl() -> None:
    summary = analyze_ips([])

    assert summary.ipv4_packets == 0
    assert summary.addresses == ()
    assert summary.minimum_ttl is None
    assert summary.most_common_ttl is None
