"""Tests for offline PCAP and PCAPNG reading."""

import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap, wrpcapng

from packetsleuth.capture import (
    CaptureReader,
    FileValidationError,
    PcapReadError,
)
from packetsleuth.models import Packet

WHEN = 1_700_000_000.0


def _write_packets(path: Path, *, pcapng: bool, times: tuple[float, ...]) -> None:
    packets = []
    for moment in times:
        packet = Ether() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=40000, dport=80)
        packet.time = moment
        packets.append(packet)
    if pcapng:
        wrpcapng(str(path), packets)
    else:
        wrpcap(str(path), packets)


def _pcap_header() -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def test_pcap_reader_yields_numbered_frames_and_keeps_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "normal.pcap"
    _write_packets(path, pcapng=False, times=(WHEN, WHEN + 2))
    original = path.read_bytes()
    modified = path.stat().st_mtime_ns

    with CaptureReader(path) as reader:
        frames = list(reader)

    assert reader.file_format == "pcap"
    assert reader.packet_count == 2
    assert [frame.packet_number for frame in frames] == [1, 2]
    assert frames[0].timestamp == datetime.fromtimestamp(WHEN, tz=timezone.utc)
    assert frames[1].timestamp == datetime.fromtimestamp(WHEN + 2, tz=timezone.utc)
    assert all(frame.timestamp is not None and frame.timestamp.tzinfo is not None for frame in frames)
    assert not isinstance(frames[0].packet, Packet)
    assert reader.issues == ()
    assert path.read_bytes() == original
    assert path.stat().st_mtime_ns == modified


def test_pcapng_reader_uses_the_header_not_only_the_extension(tmp_path: Path) -> None:
    disguised = tmp_path / "actually-pcapng.pcap"
    _write_packets(disguised, pcapng=True, times=(WHEN,))

    with CaptureReader(disguised) as reader:
        frames = list(reader)

    assert reader.file_format == "pcapng"
    assert reader.packet_count == 1
    assert frames[0].packet_number == 1
    assert any("does not match" in issue.message for issue in reader.issues)


def test_header_only_pcap_is_valid_and_empty(tmp_path: Path) -> None:
    path = tmp_path / "empty-capture.pcap"
    path.write_bytes(_pcap_header())

    with CaptureReader(path) as reader:
        frames = list(reader)

    assert frames == []
    assert reader.packet_count == 0
    assert reader.issues == ()


def test_invalid_paths_are_rejected_before_packet_iteration(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pcap"
    directory = tmp_path / "folder.pcap"
    directory.mkdir()
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    text = tmp_path / "notes.pcap"
    text.write_bytes(b"this is not a capture")
    wrong_extension = tmp_path / "sample.txt"
    wrong_extension.write_bytes(_pcap_header())
    tiny = tmp_path / "tiny.pcap"
    tiny.write_bytes(_pcap_header()[:8])
    compressed = tmp_path / "sample.pcap"
    compressed.write_bytes(bytes.fromhex("1f8b0800") + b"rest-of-header")

    with pytest.raises(FileValidationError, match="does not exist"):
        CaptureReader(missing)
    with pytest.raises(FileValidationError, match="not a file"):
        CaptureReader(directory)
    with pytest.raises(FileValidationError, match="empty"):
        CaptureReader(empty)
    with pytest.raises(FileValidationError, match="not valid PCAP"):
        CaptureReader(text)
    with pytest.raises(FileValidationError, match="extension"):
        CaptureReader(wrong_extension)
    with pytest.raises(FileValidationError, match="incomplete"):
        CaptureReader(tiny)
    with pytest.raises(FileValidationError, match="Compressed"):
        CaptureReader(compressed)


def test_malformed_pcapng_header_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "broken.pcapng"
    path.write_bytes(bytes.fromhex("0a0d0d0a") + b"\x00" * 24)

    with pytest.raises(PcapReadError, match="pcapng"):
        with CaptureReader(path) as reader:
            list(reader)

    path.unlink()


def test_reader_can_be_iterated_once_and_releases_the_file(tmp_path: Path) -> None:
    path = tmp_path / "once.pcap"
    _write_packets(path, pcapng=False, times=(WHEN,))

    with CaptureReader(path) as reader:
        assert len(list(reader)) == 1
        with pytest.raises(PcapReadError, match="already been used"):
            list(reader)

    path.unlink()
    assert not path.exists()
