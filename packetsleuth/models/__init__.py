"""Normalized records used by every later PacketSleuth stage.

Import these types instead of passing raw packet objects between modules.
Missing observations stay ``None``. Nothing in this package opens a capture
or decides that traffic is malicious.
"""

from packetsleuth.models.alert import Alert
from packetsleuth.models.analysis_result import AnalysisResult
from packetsleuth.models.connection import Connection, canonicalize_endpoints, flow_key
from packetsleuth.models.enums import Protocol, Severity, TcpFlag
from packetsleuth.models.packet import Packet, TlsMetadata
from packetsleuth.models.validation import ModelValidationError

__all__ = [
    "Alert",
    "AnalysisResult",
    "Connection",
    "ModelValidationError",
    "Packet",
    "Protocol",
    "Severity",
    "TcpFlag",
    "TlsMetadata",
    "canonicalize_endpoints",
    "flow_key",
]
