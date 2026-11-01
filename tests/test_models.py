"""Tests for the Phase 2 data models."""

from datetime import datetime, timedelta, timezone

import pytest

from packetsleuth.models import (
    Alert,
    AnalysisResult,
    Connection,
    ModelValidationError,
    Packet,
    Protocol,
    Severity,
    TcpFlag,
    TlsMetadata,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _packet(**overrides: object) -> Packet:
    values: dict[str, object] = {
        "packet_number": 1,
        "packet_length": 60,
        "timestamp": NOW,
        "layers": (Protocol.ETHERNET, Protocol.IPV4, Protocol.TCP),
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "source_port": 12345,
        "destination_port": 80,
        "ttl": 64,
        "tcp_flags": frozenset({TcpFlag.SYN}),
    }
    values.update(overrides)
    return Packet(**values)  # type: ignore[arg-type]


def _connection(**overrides: object) -> Connection:
    values: dict[str, object] = {
        "protocol": Protocol.TCP,
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "source_port": 12345,
        "destination_port": 80,
        "packets_source_to_destination": 2,
        "packets_destination_to_source": 1,
        "bytes_source_to_destination": 120,
        "bytes_destination_to_source": 60,
        "first_seen": NOW,
        "last_seen": NOW + timedelta(seconds=3),
        "tcp_flags": frozenset({TcpFlag.SYN, TcpFlag.ACK}),
        "packet_numbers": (1, 2, 3),
    }
    values.update(overrides)
    return Connection.create(**values)  # type: ignore[arg-type]


def _alert(**overrides: object) -> Alert:
    values: dict[str, object] = {
        "alert_id": "alert-1",
        "timestamp": NOW,
        "rule_id": "PS-DEMO-001",
        "title": "Possible port probing",
        "severity": Severity.MEDIUM,
        "description": "One source contacted 15 destination ports within 30 seconds.",
        "recommendation": "Check whether the source is authorized to perform discovery.",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "affected_protocol": Protocol.TCP,
        "evidence": {"unique_ports": 15, "window_seconds": 30},
        "related_packet_numbers": (4, 5, 5),
    }
    values.update(overrides)
    return Alert(**values)  # type: ignore[arg-type]


def test_packet_without_ip_keeps_missing_fields_empty() -> None:
    packet = Packet(packet_number=1, packet_length=42, layers=(Protocol.ETHERNET, Protocol.ARP))

    assert packet.source_ip is None
    assert packet.destination_ip is None
    assert packet.source_port is None
    assert packet.tcp_flags is None
    assert packet.timestamp is None
    assert packet.protocol is Protocol.ARP
    assert "payload" not in Packet.__dataclass_fields__


def test_packet_rejects_naive_timestamp_and_invalid_ip() -> None:
    with pytest.raises(ModelValidationError, match="timezone"):
        _packet(timestamp=datetime(2026, 1, 1, 12, 0))
    with pytest.raises(ModelValidationError, match="source_ip"):
        _packet(source_ip="not-an-ip")


def test_packet_rejects_contradictory_layers_and_flags() -> None:
    with pytest.raises(ModelValidationError, match="ipv4 and ipv6"):
        _packet(layers=(Protocol.IPV4, Protocol.IPV6))
    with pytest.raises(ModelValidationError, match="TCP layer"):
        Packet(
            packet_number=1,
            packet_length=40,
            layers=(Protocol.IPV4, Protocol.UDP),
            tcp_flags=frozenset({TcpFlag.SYN}),
        )


def test_packet_preserves_long_dns_name_case_and_normalizes_mac() -> None:
    name = "Unusual-Label." + ("a" * 80) + ".example"
    packet = Packet(
        packet_number=2,
        packet_length=90,
        layers=(Protocol.ETHERNET, Protocol.IPV4, Protocol.UDP, Protocol.DNS),
        source_ip="2001:db8::10",
        destination_ip="2001:db8::53",
        source_port=53000,
        destination_port=53,
        dns_query=name,
        source_mac="AA-BB-CC-DD-EE-FF",
    )

    assert packet.dns_query == name
    assert packet.source_mac == "aa:bb:cc:dd:ee:ff"
    assert packet.protocol is Protocol.DNS
    restored = Packet.from_dict(packet.to_dict())
    assert restored == packet


def test_http_and_tls_metadata_reject_secrets_in_the_path() -> None:
    packet = _packet(
        layers=(Protocol.ETHERNET, Protocol.IPV4, Protocol.TCP, Protocol.HTTP),
        tcp_flags=frozenset({TcpFlag.PSH, TcpFlag.ACK}),
        destination_port=80,
        http_method="get",
        http_host="example.test",
        http_path="/index.html",
        tls_metadata=None,
    )
    assert packet.http_method == "GET"

    with pytest.raises(ModelValidationError, match="http_path"):
        _packet(http_path="http://user:secret@example.test/")

    metadata = TlsMetadata(version="TLS 1.2", sni="www.example.test", handshake_type="client_hello")
    assert metadata.to_dict()["sni"] == "www.example.test"


def test_connection_normalizes_both_directions_to_one_key() -> None:
    forward = _connection()
    reverse = _connection(
        source_ip="192.0.2.20",
        destination_ip="192.0.2.10",
        source_port=80,
        destination_port=12345,
        packets_source_to_destination=1,
        packets_destination_to_source=2,
        bytes_source_to_destination=60,
        bytes_destination_to_source=120,
    )

    assert forward.key == reverse.key
    assert forward.endpoint_a_ip == "192.0.2.10"
    assert forward.packets_a_to_b == 2
    assert reverse.packets_a_to_b == 2
    assert forward.packet_count == 3
    assert forward.duration_seconds == 3
    assert Connection.from_dict(forward.to_dict()) == forward


def test_udp_flow_has_no_tcp_session_flags_and_partial_time_has_no_duration() -> None:
    flow = _connection(
        protocol=Protocol.UDP,
        tcp_flags=frozenset(),
        first_seen=NOW,
        last_seen=None,
    )

    assert flow.duration_seconds is None
    assert flow.tcp_flags == frozenset()
    with pytest.raises(ModelValidationError, match="UDP"):
        _connection(protocol=Protocol.UDP, tcp_flags=frozenset({TcpFlag.SYN}))
    with pytest.raises(ModelValidationError, match="canonical order"):
        Connection(
            protocol=Protocol.TCP,
            endpoint_a_ip="192.0.2.20",
            endpoint_a_port=80,
            endpoint_b_ip="192.0.2.10",
            endpoint_b_port=12345,
            packets_a_to_b=1,
            packets_b_to_a=0,
            bytes_a_to_b=40,
            bytes_b_to_a=0,
        )


def test_alert_requires_an_explanation_and_blocks_secret_evidence() -> None:
    alert = _alert()

    assert alert.related_packet_numbers == (4, 5)
    assert alert.severity is Severity.MEDIUM
    with pytest.raises(TypeError):
        alert.evidence["unique_ports"] = 99  # type: ignore[index]
    with pytest.raises(ModelValidationError, match="recommendation"):
        _alert(recommendation="  ")
    with pytest.raises(ModelValidationError, match="cookie"):
        _alert(evidence={"session_cookie": "abc"})


def test_analysis_result_round_trip_and_duplicate_protection() -> None:
    result = AnalysisResult(
        source_file="sample.pcap",
        analyzed_at=NOW,
        file_format="PCAP",
        packets=(_packet(),),
        connections=(_connection(),),
        alerts=(_alert(severity=Severity.CRITICAL),),
        limitations=("The capture may start after a handshake.",),
        risk_score=40,
        risk_explanation="One medium indicator contributed to this heuristic score.",
    )

    assert result.file_format == "pcap"
    restored = AnalysisResult.from_json(result.to_json())
    assert restored == result
    with pytest.raises(ModelValidationError, match="duplicate packet_number"):
        AnalysisResult(
            source_file="sample.pcap",
            analyzed_at=NOW,
            packets=(_packet(), _packet()),
        )
    with pytest.raises(ModelValidationError, match="risk_explanation"):
        AnalysisResult(source_file="sample.pcap", analyzed_at=NOW, risk_score=90)
