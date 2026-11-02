"""Read plaintext HTTP request metadata from one TCP payload.

A packet is HTTP only when its payload begins with an HTTP start line.
Port 80 is not evidence. Cookie, Authorization, and message bodies are not
stored. A request split across several TCP packets is not reassembled here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_REQUEST_LINE = re.compile(r"([A-Za-z][A-Za-z0-9-]{0,19}) (\S+) HTTP/\d\.\d\Z")
_RESPONSE_LINE = re.compile(r"HTTP/\d\.\d \d{3}(?: [\x20-\x7e]*)?\Z")
_MAX_LINE = 2048
_MAX_HEADER_LINES = 40


@dataclass(frozen=True, slots=True)
class HttpMetadata:
    """Request fields visible in this one TCP payload."""

    method: str | None = None
    host: str | None = None
    path: str | None = None


def parse_http_metadata(payload: bytes) -> HttpMetadata | None:
    """Return HTTP metadata, or ``None`` when the payload is not plaintext HTTP.

    An HTTP response is recognized so the packet can be labeled HTTP. Status
    codes are not stored yet. They have no field on the current packet model.
    """
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        return None
    text_line, rest = _first_line(bytes(payload))
    if text_line is None:
        return None
    request = _REQUEST_LINE.fullmatch(text_line)
    if request is None:
        if _RESPONSE_LINE.fullmatch(text_line):
            return HttpMetadata()
        return None
    method = request.group(1).upper()
    path, url_host = _request_target(request.group(2))
    host = _host_header(rest) or url_host
    return HttpMetadata(method=method, host=host, path=path)


def _first_line(payload: bytes) -> tuple[str | None, bytes]:
    raw_line, _, rest = payload.partition(b"\n")
    raw_line = raw_line.rstrip(b"\r")
    if not raw_line or len(raw_line) > _MAX_LINE or not raw_line.isascii():
        return None, b""
    return raw_line.decode("ascii"), rest


def _request_target(target: str) -> tuple[str | None, str | None]:
    if target == "*" or (target.startswith("/") and "://" not in target and "@" not in target):
        return _bounded(target), None
    if not target.startswith(("http://", "https://")):
        return None, None
    parts = urlsplit(target)
    if parts.username or parts.password or not parts.hostname:
        return None, None
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    host = parts.hostname
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return _bounded(path), _bounded(host)


def _host_header(rest: bytes) -> str | None:
    for index, raw_line in enumerate(rest.split(b"\n", _MAX_HEADER_LINES)):
        if index >= _MAX_HEADER_LINES:
            break
        line = raw_line.rstrip(b"\r")
        if line == b"":
            break
        name, separator, value = line.partition(b":")
        if separator != b":" or name.strip().lower() != b"host":
            continue
        host = value.strip()
        if not host.isascii() or len(host) > 2048:
            return None
        return host.decode("ascii")
    return None


def _bounded(value: str | None) -> str | None:
    if value is None or not value or len(value) > 2048 or "://" in value or "@" in value:
        return None
    return value
