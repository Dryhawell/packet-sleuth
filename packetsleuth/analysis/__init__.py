"""Analysis built from normalized packets.

Phase 6 summarizes IP headers. Traffic-wide statistics come later.
"""

from packetsleuth.analysis.ip_analyzer import (
    ADDRESS_CLASS_NOTE,
    TTL_NOTE,
    AddressClass,
    IpAddressSummary,
    IpAnalysis,
    TtlObservation,
    analyze_ips,
    classify_ip,
)

__all__ = [
    "ADDRESS_CLASS_NOTE",
    "TTL_NOTE",
    "AddressClass",
    "IpAddressSummary",
    "IpAnalysis",
    "TtlObservation",
    "analyze_ips",
    "classify_ip",
]
