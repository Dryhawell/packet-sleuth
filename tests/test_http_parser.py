"""Tests for plaintext HTTP metadata and its privacy boundary."""

import struct

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from packetsleuth.models import Protocol, TcpFlag
from packetsleuth.parsers import parse_frame
from tests.test_packet_parser import _frame

SECRET = "session-secret-value"


def _tcp(payload: bytes, dport: int = 8080, flags: str = "PA") -> Ether:
    return Ether() / IP(src="192.0.2.10", dst="192.0.2.20", ttl=64) / TCP(
        sport=40000, dport=dport, flags=flags
    ) / payload


def test_http_request_keeps_method_host_and_path_but_not_secrets() -> None:
    payload = (
        "GET /reports/index.html HTTP/1.1\r\n"
        "Host: files.example\r\n"
        f"Cookie: session={SECRET}\r\n"
        f"Authorization: Bearer {SECRET}\r\n"
        "\r\n"
    ).encode("ascii")
    packet = parse_frame(_frame(_tcp(payload, dport=4444)))

    assert packet.protocol is Protocol.HTTP
    assert packet.http_method == "GET"
    assert packet.http_host == "files.example"
    assert packet.http_path == "/reports/index.html"
    assert packet.destination_port == 4444
    assert packet.tcp_flags == frozenset({TcpFlag.PSH, TcpFlag.ACK})
    stored = " ".join(
        value
        for value in (packet.http_method, packet.http_host, packet.http_path, packet.dns_query)
        if value
    )
    assert SECRET not in stored


def test_http_userinfo_is_not_stored() -> None:
    payload = b"GET http://analyst:s3cret@files.example/a HTTP/1.1\r\nHost: files.example\r\n\r\n"
    packet = parse_frame(_frame(_tcp(payload)))

    assert packet.http_method == "GET"
    assert packet.http_path is None
    assert packet.http_host == "files.example"
    assert "s3cret" not in (packet.http_host or "")
    assert "s3cret" not in (packet.http_path or "")


def test_port_80_without_an_http_start_line_is_only_tcp() -> None:
    packet = parse_frame(_frame(_tcp(b"\x00\x01\x02\x03not-http", dport=80)))

    assert packet.protocol is Protocol.TCP
    assert packet.http_method is None
    assert packet.tls_metadata is None


def test_http_response_is_recognized_without_inventing_a_method() -> None:
    packet = parse_frame(_frame(_tcp(b"HTTP/1.1 204 No Content\r\n\r\n")))

    assert packet.protocol is Protocol.HTTP
    assert packet.http_method is None
    assert packet.http_path is None


def _client_hello(sni: str, *, tls13: bool = False) -> bytes:
    version = b"\x03\x03"
    random = b"\x11" * 32
    session = b"\x00"
    cipher_suites = b"\x00\x02\x00\x2f"
    compression = b"\x01\x00"
    name = sni.encode("ascii")
    sni_body = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0, len(sni_body)) + sni_body
    if tls13:
        supported = b"\x02\x03\x04"
        extensions += struct.pack("!HH", 43, len(supported)) + supported
    extension_block = struct.pack("!H", len(extensions)) + extensions
    body = version + random + session + cipher_suites + compression + extension_block
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def test_tls_client_hello_exposes_sni_on_any_port() -> None:
    packet = parse_frame(_frame(_tcp(_client_hello("www.example.test"), dport=8443)))

    assert packet.protocol is Protocol.TLS
    assert packet.tls_metadata is not None
    assert packet.tls_metadata.version == "TLS 1.2"
    assert packet.tls_metadata.handshake_type == "client_hello"
    assert packet.tls_metadata.sni == "www.example.test"
    assert packet.http_method is None


def test_tls_supported_versions_can_show_tls_1_3() -> None:
    packet = parse_frame(_frame(_tcp(_client_hello("www.example.test", tls13=True), dport=443)))

    assert packet.tls_metadata is not None
    assert packet.tls_metadata.version == "TLS 1.3"
    assert packet.tls_metadata.sni == "www.example.test"


def test_port_443_without_a_tls_record_is_only_tcp() -> None:
    packet = parse_frame(_frame(_tcp(b"GET / HTTP/1.0\r\n\r\n", dport=443)))

    assert packet.protocol is Protocol.HTTP
    assert packet.tls_metadata is None


def test_tls_application_data_has_no_decrypted_http() -> None:
    payload = b"\x17\x03\x03\x00\x05hello"
    packet = parse_frame(_frame(_tcp(payload, dport=443)))

    assert packet.protocol is Protocol.TLS
    assert packet.tls_metadata is not None
    assert packet.tls_metadata.handshake_type is None
    assert packet.tls_metadata.sni is None
    assert packet.http_method is None
    assert "hello" not in (packet.tls_metadata.version or "")
