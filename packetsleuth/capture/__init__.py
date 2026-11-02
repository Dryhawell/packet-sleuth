"""Offline PCAP and PCAPNG reading.

Raw Scapy packets stay inside this package until a later phase normalizes
them. Nothing here sends traffic or modifies the source capture.
"""

from packetsleuth.capture.file_validator import (
    CaptureFileInfo,
    FileValidationError,
    validate_capture_file,
)
from packetsleuth.capture.pcap_reader import (
    CaptureIssue,
    CaptureReader,
    CapturedFrame,
    PcapReadError,
)

__all__ = [
    "CaptureFileInfo",
    "CaptureIssue",
    "CaptureReader",
    "CapturedFrame",
    "FileValidationError",
    "PcapReadError",
    "validate_capture_file",
]
