"""Read visible TLS handshake metadata from one TCP payload.

The payload is TLS when it begins with a TLS record header. Port 443 is not
evidence. Record payloads are not decrypted, and certificate or application
bytes are not stored. A missing SNI only means this packet did not contain a
ClientHello. It is not a vulnerability.
"""

from __future__ import annotations

from packetsleuth.models.packet import TlsMetadata

_CONTENT_TYPES = {20, 21, 22, 23}
_VERSIONS = {
    b"\x03\x01": "TLS 1.0",
    b"\x03\x02": "TLS 1.1",
    b"\x03\x03": "TLS 1.2",
    b"\x03\x04": "TLS 1.3",
}
_HANDSHAKES = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
}
_MAX_RECORD = 18432
_SNI_EXTENSION = 0
_SUPPORTED_VERSIONS = 43


def parse_tls_metadata(payload: bytes) -> TlsMetadata | None:
    """Return handshake metadata visible in ``payload``.

    The version is the version advertised in this record or handshake. It is
    not proof of the version the peers eventually negotiated. TLS 1.3 often
    still shows 1.2 in the record header. ``supported_versions`` is used when
    that extension is present and fully readable.
    """
    if not isinstance(payload, (bytes, bytearray)):
        return None
    data = bytes(payload)
    if len(data) < 5 or data[0] not in _CONTENT_TYPES:
        return None
    version_bytes = data[1:3]
    if version_bytes not in _VERSIONS:
        return None
    record_length = int.from_bytes(data[3:5], "big")
    if record_length < 1 or record_length > _MAX_RECORD:
        return None
    version = _VERSIONS[version_bytes]
    handshake_type: str | None = None
    sni: str | None = None
    if data[0] == 22:
        if len(data) < 6 or data[5] not in _HANDSHAKES:
            return None
        handshake_type = _HANDSHAKES[data[5]]
        handshake_length = int.from_bytes(data[6:9], "big") if len(data) >= 9 else 0
        handshake = data[9 : 9 + handshake_length]
        if data[5] in {1, 2} and len(handshake) >= 2 and handshake[:2] in _VERSIONS:
            version = _VERSIONS[handshake[:2]]
        if data[5] == 1:
            advertised = _supported_version(handshake)
            if advertised is not None:
                version = advertised
            sni = _client_hello_sni(handshake)
    try:
        return TlsMetadata(version=version, sni=sni, handshake_type=handshake_type)
    except ValueError:
        return TlsMetadata(version=version, sni=None, handshake_type=handshake_type)


def _client_hello_sni(handshake: bytes) -> str | None:
    extensions = _extensions(handshake)
    if extensions is None:
        return None
    for ext_type, ext_data in extensions:
        if ext_type != _SNI_EXTENSION or len(ext_data) < 5:
            continue
        list_length = int.from_bytes(ext_data[:2], "big")
        if list_length + 2 > len(ext_data) or ext_data[2] != 0:
            return None
        name_length = int.from_bytes(ext_data[3:5], "big")
        name = ext_data[5 : 5 + name_length]
        if len(name) != name_length or not name.isascii() or not name:
            return None
        return name.decode("ascii")
    return None


def _supported_version(handshake: bytes) -> str | None:
    extensions = _extensions(handshake)
    if extensions is None:
        return None
    for ext_type, ext_data in extensions:
        if ext_type != _SUPPORTED_VERSIONS or not ext_data:
            continue
        list_length = ext_data[0]
        values = ext_data[1 : 1 + list_length]
        if len(values) != list_length or len(values) % 2:
            return None
        if b"\x03\x04" in _pairs(values):
            return "TLS 1.3"
    return None


def _extensions(handshake: bytes) -> list[tuple[int, bytes]] | None:
    offset = 34  # legacy version + random
    if len(handshake) <= offset:
        return None
    session_length = handshake[offset]
    offset += 1 + session_length
    if offset + 2 > len(handshake):
        return None
    cipher_length = int.from_bytes(handshake[offset : offset + 2], "big")
    offset += 2 + cipher_length
    if offset >= len(handshake):
        return None
    compression_length = handshake[offset]
    offset += 1 + compression_length
    if offset + 2 > len(handshake):
        return None
    extensions_length = int.from_bytes(handshake[offset : offset + 2], "big")
    offset += 2
    blob = handshake[offset : offset + extensions_length]
    if len(blob) != extensions_length:
        return None
    found: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor + 4 <= len(blob):
        ext_type = int.from_bytes(blob[cursor : cursor + 2], "big")
        ext_length = int.from_bytes(blob[cursor + 2 : cursor + 4], "big")
        cursor += 4
        if cursor + ext_length > len(blob):
            return None
        found.append((ext_type, blob[cursor : cursor + ext_length]))
        cursor += ext_length
    return found


def _pairs(values: bytes) -> list[bytes]:
    return [values[index : index + 2] for index in range(0, len(values), 2)]
