"""Read a DNS message carried in a UDP datagram or a TCP segment.

Recognition uses the DNS header and a readable question or answer. The
destination port is ignored. This module does not query a resolver, and it
does not keep TXT contents, which can hold tokens or other private data.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

_HEADER = struct.Struct("!HHHHHH")
_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}
_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


@dataclass(frozen=True, slots=True)
class DnsMetadata:
    """The question name and a short response summary from one DNS message."""

    query_name: str | None
    response_summary: str | None


def parse_dns_metadata(payload: bytes, *, length_prefixed: bool) -> DnsMetadata | None:
    """Return DNS metadata when ``payload`` contains a readable DNS message.

    TCP DNS messages begin with a 2-byte length. UDP messages do not.
    A payload that fails these checks is left unrecognized, even on port 53.
    """
    if not isinstance(payload, (bytes, bytearray)):
        return None
    message = _message_bytes(bytes(payload), length_prefixed=length_prefixed)
    if message is None:
        return None
    return _parse_message(message)


def _message_bytes(payload: bytes, *, length_prefixed: bool) -> bytes | None:
    if not length_prefixed:
        return payload if len(payload) >= 12 else None
    if len(payload) < 14:
        return None
    declared = int.from_bytes(payload[:2], "big")
    if declared < 12 or declared > 65535:
        return None
    return payload[2 : 2 + declared]


def _parse_message(message: bytes) -> DnsMetadata | None:
    if len(message) < 12:
        return None
    _, flags, questions, answers, authorities, additional = _HEADER.unpack_from(message)
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F
    is_response = flags & 0x8000 != 0
    if opcode > 5 or questions > 5 or answers > 20 or authorities > 20 or additional > 20:
        return None

    offset = 12
    query_name: str | None = None
    query_type: int | None = None
    for _ in range(questions):
        name, offset = _read_name(message, offset)
        if name is None or offset + 4 > len(message):
            return None
        if query_name is None:
            query_name = name
            query_type = int.from_bytes(message[offset : offset + 2], "big")
        offset += 4

    answer_summary: str | None = None
    if is_response and answers:
        answer_summary, offset = _first_answer(message, offset)
        if answer_summary is None and query_name is None:
            return None

    if query_name is None and answer_summary is None:
        return None

    summary = None
    if is_response:
        summary = _response_summary(rcode, query_type, answer_summary)
    return DnsMetadata(query_name=query_name, response_summary=summary)


def _response_summary(rcode: int, query_type: int | None, answer: str | None) -> str:
    label = _RCODES.get(rcode, f"RCODE{rcode}")
    if answer is not None:
        text = f"{label} {answer}"
    elif query_type is not None and rcode == 0:
        text = f"{label} {_TYPES.get(query_type, f'TYPE{query_type}')}"
    else:
        text = label
    return text[:500]


def _first_answer(message: bytes, offset: int) -> tuple[str | None, int]:
    name, offset = _read_name(message, offset)
    if name is None or offset + 10 > len(message):
        return None, offset
    rtype, _rclass, _ttl, length = struct.unpack_from("!HHIH", message, offset)
    offset += 10
    if length > len(message) - offset:
        return None, offset
    rdata = message[offset : offset + length]
    offset += length
    rendered = _render_rdata(rtype, rdata, message)
    if rendered is None:
        return _TYPES.get(rtype, f"TYPE{rtype}"), offset
    return rendered, offset


def _render_rdata(rtype: int, rdata: bytes, message: bytes) -> str | None:
    if rtype == 1 and len(rdata) == 4:
        return f"A {IPv4Address(rdata)}"
    if rtype == 28 and len(rdata) == 16:
        return f"AAAA {IPv6Address(rdata)}"
    if rtype in {2, 5, 12}:
        name = _name_in_rdata(message, rdata)
        if name is None:
            return _TYPES[rtype]
        return f"{_TYPES[rtype]} {name}"
    if rtype == 15 and len(rdata) >= 2:
        preference = int.from_bytes(rdata[:2], "big")
        return f"MX {preference}"
    if rtype == 16:
        return "TXT"
    return None


def _name_in_rdata(message: bytes, rdata: bytes) -> str | None:
    if len(rdata) >= 2 and rdata[0] & 0xC0 == 0xC0:
        pointer = ((rdata[0] & 0x3F) << 8) | rdata[1]
        name, _ = _read_name(message, pointer)
        return name
    name, _ = _read_name(rdata, 0)
    return name


def _read_name(message: bytes, offset: int, depth: int = 0) -> tuple[str | None, int]:
    if depth > 8 or offset < 0 or offset >= len(message):
        return None, offset
    labels: list[str] = []
    cursor = offset
    end = offset
    jumped = False
    for _ in range(128):
        if cursor >= len(message):
            return None, end
        length = message[cursor]
        if length == 0:
            if not jumped:
                end = cursor + 1
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                return None, end
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message):
                return None, end
            if not jumped:
                end = cursor + 2
            target, _ = _read_name(message, pointer, depth + 1)
            if target is None:
                return None, end
            labels.append(target[:-1] if target.endswith(".") else target)
            jumped = True
            break
        if length > 63 or cursor + 1 + length > len(message):
            return None, end
        try:
            labels.append(message[cursor + 1 : cursor + 1 + length].decode("ascii"))
        except UnicodeDecodeError:
            return None, end
        cursor += 1 + length
        if not jumped:
            end = cursor
    else:
        return None, end
    if not labels:
        return ".", end
    return ".".join(labels) + ".", end
