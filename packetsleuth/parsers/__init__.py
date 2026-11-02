"""Parsers that turn raw frames into normalized records.

Link, network, and transport headers are read from decoded layers.
DNS, plaintext HTTP, and TLS metadata are read from the payload.
"""

from packetsleuth.parsers.packet_parser import parse_frame, parse_frames
from packetsleuth.parsers.protocol_parser import LayerView, inspect_layers

__all__ = [
    "LayerView",
    "inspect_layers",
    "parse_frame",
    "parse_frames",
]
