"""Tests for DNS recognition that does not trust the port number."""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from packetsleuth.models import Protocol
from packetsleuth.parsers import parse_frame
from tests.test_packet_parser import WHEN, _frame


def test_dns_query_on_a_high_port_keeps_the_question_name() -> None:
    raw = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=41000, dport=5353)
        / DNS(rd=1, qd=DNSQR(qname="Example.Test", qtype="A"))
    )
    packet = parse_frame(_frame(raw))

    assert packet.protocol is Protocol.DNS
    assert packet.dns_query == "Example.Test."
    assert packet.dns_response is None
    assert packet.destination_port == 5353


def test_dns_response_summarizes_the_address_and_rcode() -> None:
    raw = (
        Ether()
        / IP(src="192.0.2.53", dst="192.0.2.10")
        / UDP(sport=53, dport=41000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.test", qtype="A"),
            an=DNSRR(rrname="example.test", type="A", rdata="192.0.2.80"),
        )
    )
    packet = parse_frame(_frame(raw))

    assert packet.dns_query == "example.test."
    assert packet.dns_response is not None
    assert "NOERROR" in packet.dns_response
    assert "192.0.2.80" in packet.dns_response


def test_nxdomain_does_not_invent_an_address() -> None:
    raw = (
        Ether()
        / IP(src="192.0.2.53", dst="192.0.2.10")
        / UDP(sport=53, dport=41000)
        / DNS(qr=1, rcode=3, qd=DNSQR(qname="missing.example", qtype="A"))
    )
    packet = parse_frame(_frame(raw))

    assert packet.dns_response == "NXDOMAIN"
    assert packet.dns_query == "missing.example."


def test_port_53_without_a_dns_message_is_only_udp() -> None:
    raw = Ether() / IP(src="192.0.2.10", dst="192.0.2.53") / UDP(sport=41000, dport=53) / b"hello world!!"
    packet = parse_frame(_frame(raw, number=4))

    assert packet.protocol is Protocol.UDP
    assert packet.dns_query is None
    assert packet.dns_response is None
    assert packet.timestamp == WHEN
