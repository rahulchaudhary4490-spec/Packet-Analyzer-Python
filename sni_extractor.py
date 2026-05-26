"""
sni_extractor.py - Extract domain names from TLS Client Hello and HTTP Host headers
Mirrors: sni_extractor.h / sni_extractor.cpp

TLS Client Hello structure:
  Byte 0:     Content Type = 0x16 (Handshake)
  Byte 5:     Handshake Type = 0x01 (Client Hello)
  → Skip Session ID, Cipher Suites, Compression
  → Find Extension Type 0x0000 (SNI)
  → Extract hostname string

Even HTTPS traffic leaks the destination domain in the first TLS packet!
"""

import struct
from typing import Optional


def extract_sni(payload: bytes) -> Optional[str]:
    """
    Extract SNI (Server Name Indication) from a TLS Client Hello.
    Returns the hostname string or None if not found.
    """
    if len(payload) < 6:
        return None

    # Check TLS record: Content Type must be 0x16 (Handshake)
    if payload[0] != 0x16:
        return None

    # Handshake type at byte 5 must be 0x01 (Client Hello)
    if payload[5] != 0x01:
        return None

    try:
        offset = 43  # Skip: version(2) + random(32) + session_id_len(1) = 43 bytes into handshake body

        # The handshake body starts at byte 9 (after TLS record header 5B + handshake header 4B)
        base = 9
        offset = base + 34  # version(2) + random(32)

        if offset >= len(payload):
            return None

        # Skip Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(payload):
            return None

        # Skip Cipher Suites
        cipher_suites_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + cipher_suites_len

        if offset + 1 > len(payload):
            return None

        # Skip Compression Methods
        compression_len = payload[offset]
        offset += 1 + compression_len

        if offset + 2 > len(payload):
            return None

        # Extensions total length
        extensions_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2

        ext_end = offset + extensions_len

        # Walk through extensions to find SNI (type 0x0000)
        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_len  = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI extension
                # SNI list length (2B) + SNI type (1B) + SNI name length (2B) + name
                if offset + 5 > len(payload):
                    return None
                # sni_list_len = struct.unpack("!H", payload[offset:offset+2])[0]
                # sni_type = payload[offset+2]  # 0x00 = hostname
                sni_name_len = struct.unpack("!H", payload[offset + 3:offset + 5])[0]
                sni_start = offset + 5
                sni_end = sni_start + sni_name_len
                if sni_end > len(payload):
                    return None
                return payload[sni_start:sni_end].decode("utf-8", errors="ignore")

            offset += ext_len

    except (struct.error, IndexError):
        return None

    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    """
    Extract Host header from an HTTP request.
    Looks for 'Host: <value>' in the payload.
    """
    try:
        text = payload.decode("utf-8", errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None
