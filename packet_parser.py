"""
packet_parser.py - Parse Ethernet, IP, TCP, UDP headers from raw bytes
Mirrors: packet_parser.h / packet_parser.cpp

Packet structure (Russian nesting doll):
  [Ethernet 14B] → [IP 20B] → [TCP/UDP 20B/8B] → [Payload]
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedPacket:
    # Ethernet
    src_mac: str = ""
    dst_mac: str = ""
    ether_type: int = 0

    # IP
    src_ip: str = ""
    dst_ip: str = ""
    protocol: int = 0   # 6=TCP, 17=UDP
    ttl: int = 0

    # TCP / UDP
    src_port: int = 0
    dst_port: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    tcp_flags: int = 0
    seq_num: int = 0
    ack_num: int = 0

    # Payload (application data)
    payload: bytes = field(default_factory=bytes)


def _parse_mac(data: bytes, offset: int) -> str:
    return ":".join(f"{b:02x}" for b in data[offset:offset + 6])


def _parse_ip(data: bytes, offset: int) -> str:
    return ".".join(str(b) for b in data[offset:offset + 4])


def parse_packet(data: bytes) -> Optional[ParsedPacket]:
    """
    Parse raw bytes → ParsedPacket.
    Returns None if data is too short or unsupported EtherType.
    """
    if len(data) < 14:
        return None

    pkt = ParsedPacket()

    # --- Ethernet Header (14 bytes) ---
    pkt.dst_mac = _parse_mac(data, 0)
    pkt.src_mac = _parse_mac(data, 6)
    pkt.ether_type = struct.unpack("!H", data[12:14])[0]

    if pkt.ether_type != 0x0800:  # Only IPv4 supported
        return None

    # --- IPv4 Header (min 20 bytes) ---
    if len(data) < 34:
        return None

    ip_offset = 14
    version_ihl = data[ip_offset]
    ip_header_len = (version_ihl & 0x0F) * 4   # IHL field × 4

    pkt.ttl = data[ip_offset + 8]
    pkt.protocol = data[ip_offset + 9]
    pkt.src_ip = _parse_ip(data, ip_offset + 12)
    pkt.dst_ip = _parse_ip(data, ip_offset + 16)

    transport_offset = ip_offset + ip_header_len

    # --- TCP Header (min 20 bytes) ---
    if pkt.protocol == 6:
        if len(data) < transport_offset + 20:
            return pkt
        pkt.has_tcp = True
        pkt.src_port = struct.unpack("!H", data[transport_offset:transport_offset + 2])[0]
        pkt.dst_port = struct.unpack("!H", data[transport_offset + 2:transport_offset + 4])[0]
        pkt.seq_num  = struct.unpack("!I", data[transport_offset + 4:transport_offset + 8])[0]
        pkt.ack_num  = struct.unpack("!I", data[transport_offset + 8:transport_offset + 12])[0]
        tcp_data_offset = (data[transport_offset + 12] >> 4) * 4
        pkt.tcp_flags = data[transport_offset + 13]
        payload_start = transport_offset + tcp_data_offset
        pkt.payload = data[payload_start:]

    # --- UDP Header (8 bytes) ---
    elif pkt.protocol == 17:
        if len(data) < transport_offset + 8:
            return pkt
        pkt.has_udp = True
        pkt.src_port = struct.unpack("!H", data[transport_offset:transport_offset + 2])[0]
        pkt.dst_port = struct.unpack("!H", data[transport_offset + 2:transport_offset + 4])[0]
        pkt.payload = data[transport_offset + 8:]

    return pkt
