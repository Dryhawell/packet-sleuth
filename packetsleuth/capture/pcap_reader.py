"""Iterate packets in a PCAP or PCAPNG file.

The reader yields raw Scapy packets one at a time. It does not convert
them into PacketSleuth's normalized Packet model, and it never writes the
source file.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from scapy.packet import Packet as ScapyPacket
from scapy.utils import PcapNgReader, PcapReader

from packetsleuth.capture.file_validator import validate_capture_file

logger = logging.getLogger("packetsleuth.capture")

_READERS = {
    "pcap": PcapReader,
    "pcapng": PcapNgReader,
}


class PcapReadError(RuntimeError):
    """The capture header was accepted, but Scapy could not open the file."""


@dataclass(frozen=True, slots=True)
class CaptureIssue:
    """A problem noticed while reading, short enough to show to a person.

    ``packet_number`` is empty when the problem applies to the whole file.
    Packet numbers use the same 1-based sequence as successfully read frames.
    """

    message: str
    packet_number: int | None = None


@dataclass(frozen=True, slots=True)
class CapturedFrame:
    """One raw frame plus the metadata needed by the next phase.

    ``packet`` is a Scapy object. Fields such as IP addresses and TCP flags
    are not extracted here. ``timestamp`` is timezone-aware UTC when the
    capture provides a usable time, and ``None`` when it does not.
    """

    packet_number: int
    timestamp: datetime | None
    packet: ScapyPacket


class CaptureReader:
    """Single-pass reader for one offline capture file.

    Use it as a context manager. Each instance can be iterated once. After
    the loop, ``packet_count`` and ``issues`` describe what happened.

    A packet Scapy cannot dissect is still returned, usually as raw bytes
    inside the Scapy packet. If reading itself fails, the failure is stored
    in ``issues`` and iteration stops. The exception is not raised to the
    caller.
    """

    def __init__(self, path: str | Path) -> None:
        info = validate_capture_file(path)
        self.path = info.path
        self.file_format = info.file_format
        self.size_bytes = info.size_bytes
        self._issues: list[CaptureIssue] = []
        self.packet_count = 0
        self._reader: PcapReader | PcapNgReader | None = None
        self._started = False
        if not info.extension_matches_format:
            self._record_issue(
                f"Extension {info.extension} does not match the {info.file_format} "
                "header. The header decides which reader is used."
            )

    def __enter__(self) -> CaptureReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        self.close()

    def __iter__(self) -> Iterator[CapturedFrame]:
        if self._started:
            raise PcapReadError("This capture reader has already been used.")
        self._started = True
        self._reader = _open_reader(self.path, self.file_format)
        logger.info("Opened %s as %s", self.path.name, self.file_format)
        return self

    def __next__(self) -> CapturedFrame:
        if self._reader is None:
            raise StopIteration
        try:
            raw_packet = self._reader.read_packet()
        except EOFError:
            self.close()
            raise StopIteration
        except Exception as exc:
            next_number = self.packet_count + 1
            self._record_issue(
                f"Reading stopped near packet {next_number}: {_short_error(exc)}",
                packet_number=next_number,
            )
            self.close()
            raise StopIteration from None

        self.packet_count += 1
        timestamp, unusable_timestamp = _frame_timestamp(raw_packet)
        if unusable_timestamp:
            self._record_issue(
                f"Packet {self.packet_count} has no usable timestamp.",
                packet_number=self.packet_count,
            )
        return CapturedFrame(
            packet_number=self.packet_count,
            timestamp=timestamp,
            packet=raw_packet,
        )

    @property
    def issues(self) -> tuple[CaptureIssue, ...]:
        """Return the issues recorded so far, in read order."""
        return tuple(self._issues)

    def close(self) -> None:
        """Close the underlying capture if it is open."""
        reader = self._reader
        self._reader = None
        if reader is not None:
            reader.close()

    def _record_issue(self, message: str, packet_number: int | None = None) -> None:
        self._issues.append(CaptureIssue(message=message, packet_number=packet_number))
        logger.warning("%s: %s", self.path.name, message)


def _open_reader(path: Path, file_format: str) -> PcapReader | PcapNgReader:
    """Open the Scapy reader selected from the validated header.

    The file object belongs to Scapy after a successful open. On failure it
    is closed here so a malformed capture does not keep a handle alive.
    """
    handle = path.open("rb")
    reader_type = _READERS[file_format]
    try:
        return reader_type(handle)
    except Exception as exc:
        handle.close()
        raise PcapReadError(
            f"Could not open {path.name} as {file_format}: {_short_error(exc)}"
        ) from exc


def _frame_timestamp(packet: ScapyPacket) -> tuple[datetime | None, bool]:
    """Return a UTC timestamp when the capture itself stored one.

    Scapy puts the file timestamp in an ``EDecimal``. A plain float is the
    clock time Scapy assigns while building a packet object, so it is not
    treated as a capture timestamp. The second value is true when a file
    timestamp was present but could not be converted.
    """
    raw_time = getattr(packet, "time", None)
    if not isinstance(raw_time, Decimal):
        return None, False
    try:
        seconds = float(raw_time)
    except (TypeError, ValueError):
        return None, True
    if not math.isfinite(seconds):
        return None, True
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc), False
    except (OSError, OverflowError, ValueError):
        return None, True


def _short_error(exc: Exception) -> str:
    text = str(exc).strip().replace("\n", " ")
    if not text:
        text = exc.__class__.__name__
    if len(text) > 300:
        return text[:300] + "..."
    return text
