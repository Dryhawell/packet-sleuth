"""Checks that a path is safe to open as an offline capture.

Validation looks at the path, the extension, and the first bytes of the
file. It does not iterate packets and it does not write to the file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_PCAP_MAGICS = frozenset(
    {
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("4d3cb2a1"),
        bytes.fromhex("a1b23c4d"),
    }
)
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_GZIP_MAGIC = bytes.fromhex("1f8b")
_PCAP_HEADER_BYTES = 24
_PCAPNG_HEADER_BYTES = 28
_ALLOWED_EXTENSIONS = {".pcap": "pcap", ".pcapng": "pcapng"}


class FileValidationError(ValueError):
    """The path cannot be accepted as a PCAP or PCAPNG capture."""


@dataclass(frozen=True, slots=True)
class CaptureFileInfo:
    """Facts known about a capture before any packet is read.

    ``file_format`` comes from the file header, not from the extension.
    """

    path: Path
    file_format: str
    extension: str
    size_bytes: int

    @property
    def extension_matches_format(self) -> bool:
        """Return whether the suffix agrees with the detected header."""
        expected = ".pcap" if self.file_format == "pcap" else ".pcapng"
        return self.extension == expected


def validate_capture_file(path: str | Path) -> CaptureFileInfo:
    """Validate a capture path and detect PCAP versus PCAPNG.

    Args:
        path: Filesystem path chosen by the caller.

    Returns:
        Information needed to select a reader.

    Raises:
        FileValidationError: The path is missing, empty, compressed,
            incomplete, or not a supported capture.
    """
    candidate = _require_path(path)
    if not candidate.exists():
        raise FileValidationError(f"Capture file does not exist: {candidate}")
    if not candidate.is_file():
        raise FileValidationError(f"Capture path is not a file: {candidate}")

    extension = candidate.suffix.lower()
    if extension not in _ALLOWED_EXTENSIONS:
        raise FileValidationError(
            "Capture file must use a .pcap or .pcapng extension: "
            f"{candidate.name}"
        )

    try:
        size_bytes = candidate.stat().st_size
    except OSError as exc:
        raise FileValidationError(f"Capture file could not be read: {candidate}") from exc
    if size_bytes == 0:
        raise FileValidationError(f"Capture file is empty: {candidate.name}")

    try:
        with candidate.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        raise FileValidationError(f"Capture file could not be read: {candidate}") from exc

    file_format = _detect_format(magic, candidate.name)
    minimum = _PCAP_HEADER_BYTES if file_format == "pcap" else _PCAPNG_HEADER_BYTES
    if size_bytes < minimum:
        raise FileValidationError(
            f"Capture file has an incomplete {file_format} header: {candidate.name}"
        )
    return CaptureFileInfo(
        path=candidate,
        file_format=file_format,
        extension=extension,
        size_bytes=size_bytes,
    )


def _require_path(path: str | Path) -> Path:
    if isinstance(path, Path):
        return path
    if isinstance(path, str) and path.strip():
        return Path(path)
    raise FileValidationError("Capture path must be a non-empty file path.")


def _detect_format(magic: bytes, file_name: str) -> str:
    if magic.startswith(_GZIP_MAGIC):
        raise FileValidationError(
            "Compressed captures are not supported. Decompress the file "
            f"and save it as .pcap or .pcapng: {file_name}"
        )
    if magic in _PCAP_MAGICS:
        return "pcap"
    if magic == _PCAPNG_MAGIC:
        return "pcapng"
    raise FileValidationError(
        "Capture file is not valid PCAP or PCAPNG data. "
        f"The header {magic.hex() or 'is empty'} is not a known capture format: "
        f"{file_name}"
    )
