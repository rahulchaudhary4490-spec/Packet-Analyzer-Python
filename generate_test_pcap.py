"""
generate_test_pcap.py - Generate a test PCAP file with various traffic types
Python equivalent of the original generate_test_pcap.py in the C++ repo

Creates packets for:
  - YouTube HTTPS (TLS Client Hello with SNI)
  - Facebook HTTPS
  - Google HTTPS
  - GitHub HTTPS
  - HTTP (plain text with Host header)
  - DNS UDP packets
  - Generic TCP traffic

Usage:
    python generate_test_pcap.py [output_file]
    Default output: test_dpi.pcap
"""

import sys
import struct
import socket
import random
import time


PCAP_MAGIC       = 0xa1b2c3d4
PCAP_GLOBAL_FMT  = "<IHHiIII"
PCAP_PACKET_FMT  = "<IIII"


def pcap_global_header() -> bytes:
    return struct.pack(PCAP_GLOBAL_FMT, PCAP_MAGIC, 2, 4, 0, 0, 65535, 1)


def pcap_packet_header(data: bytes, ts: float) -> bytes:
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack(PCAP_PACKET_FMT, ts_sec, ts_usec, len(data), len(data))


def eth_header(src_mac: bytes, dst_mac: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00"  # EtherType IPv4


def ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    ver_ihl    = 0x45        # IPv4, IHL=5 (20 bytes)
    tos        = 0
    total_len  = 20 + payload_len
    ident      = random.randint(0, 65535)
    flags_frag = 0x4000      # Don't fragment
    ttl        = 64
    checksum   = 0
    src        = socket.inet_aton(src_ip)
    dst        = socket.inet_aton(dst_ip)
    header     = struct.pack("!BBHHHBBH4s4s",
                             ver_ihl, tos, total_len, ident,
                             flags_frag, ttl, proto, checksum, src, dst)
    return header


def tcp_header(src_port: int, dst_port: int, seq: int = 1000, ack: int = 0,
               flags: int = 0x002, payload_len: int = 0) -> bytes:
    data_offset = 5 << 4    # 20 bytes, no options
    window      = 65535
    checksum    = 0
    urgent      = 0
    return struct.pack("!HHIIBBHHH",
                       src_port, dst_port, seq, ack,
                       data_offset, flags, window, checksum, urgent)


def udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    length   = 8 + payload_len
    checksum = 0
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)


def make_tls_client_hello(sni: str) -> bytes:
    """Construct a minimal TLS 1.2 Client Hello with SNI extension."""
    sni_bytes = sni.encode()
    sni_len   = len(sni_bytes)

    # SNI extension
    sni_ext = (
        struct.pack("!HBH", sni_len + 3, 0x00, sni_len)  # list_len, type=hostname, name_len
        + sni_bytes
    )
    sni_extension = struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext

    # Minimal extensions block
    extensions = sni_extension
    extensions_block = struct.pack("!H", len(extensions)) + extensions

    # Cipher suites (just one)
    cipher_suites = struct.pack("!HH", 2, 0xC02B)  # len=2, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

    # Compression methods
    compression = b"\x01\x00"  # 1 method: null

    # Client Hello body
    random_bytes = b"\x00" * 32
    session_id   = b"\x00"     # length=0
    client_hello_body = (
        b"\x03\x03"            # version TLS 1.2
        + random_bytes
        + session_id
        + cipher_suites
        + compression
        + extensions_block
    )

    # Handshake header
    handshake = (
        b"\x01"                # Client Hello type
        + struct.pack("!I", len(client_hello_body))[1:]  # 3-byte length
        + client_hello_body
    )

    # TLS record layer
    record = (
        b"\x16"                # Content Type: Handshake
        + b"\x03\x01"          # TLS 1.0 record version
        + struct.pack("!H", len(handshake))
        + handshake
    )
    return record


def make_http_request(host: str, path: str = "/") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()


def make_dns_query(domain: str) -> bytes:
    """Minimal DNS query packet."""
    txid   = random.randint(0, 65535)
    flags  = 0x0100  # Standard query
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname  = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def build_packet(src_ip, dst_ip, src_port, dst_port, proto, payload,
                 src_mac=b"\x00\x11\x22\x33\x44\x55",
                 dst_mac=b"\xaa\xbb\xcc\xdd\xee\xff") -> bytes:
    """Build full Ethernet+IP+TCP/UDP packet."""
    if proto == 6:
        transport = tcp_header(src_port, dst_port, payload_len=len(payload))
    else:
        transport = udp_header(src_port, dst_port, len(payload))

    ip = ip_header(src_ip, dst_ip, proto, len(transport) + len(payload))
    eth = eth_header(src_mac, dst_mac)
    return eth + ip + transport + payload


def write_pcap(filename: str, packets: list[bytes]):
    with open(filename, "wb") as f:
        f.write(pcap_global_header())
        ts = time.time()
        for pkt in packets:
            ts += 0.001
            f.write(pcap_packet_header(pkt, ts))
            f.write(pkt)
    print(f"[+] Written {len(packets)} packets to '{filename}'")


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "test_dpi.pcap"

    packets = []

    # --- HTTPS traffic with TLS Client Hello (SNI visible) ---
    tls_sites = [
        ("192.168.1.100", "172.217.14.206", "www.youtube.com"),
        ("192.168.1.100", "172.217.14.207", "www.youtube.com"),
        ("192.168.1.101", "31.13.64.35",    "www.facebook.com"),
        ("192.168.1.102", "140.82.121.3",   "github.com"),
        ("192.168.1.103", "142.250.185.78", "www.google.com"),
        ("192.168.1.104", "151.101.1.140",  "www.reddit.com"),
        ("192.168.1.105", "13.107.42.14",   "www.microsoft.com"),
        ("192.168.1.106", "157.240.22.35",  "www.instagram.com"),
    ]

    for src_ip, dst_ip, sni in tls_sites:
        src_port = random.randint(49152, 65535)
        # SYN packet (no payload)
        packets.append(build_packet(src_ip, dst_ip, src_port, 443, 6, b""))
        # Client Hello packet
        tls_payload = make_tls_client_hello(sni)
        packets.append(build_packet(src_ip, dst_ip, src_port, 443, 6, tls_payload))
        # Follow-up data packet (generic)
        packets.append(build_packet(src_ip, dst_ip, src_port, 443, 6, b"\x17\x03\x03" + b"\x00" * 20))

    # --- HTTP traffic (Host header visible) ---
    http_sites = [
        ("192.168.1.107", "93.184.216.34", "example.com", "/index.html"),
        ("192.168.1.108", "104.21.33.128", "httpbin.org", "/get"),
    ]
    for src_ip, dst_ip, host, path in http_sites:
        src_port = random.randint(49152, 65535)
        http_payload = make_http_request(host, path)
        packets.append(build_packet(src_ip, dst_ip, src_port, 80, 6, http_payload))

    # --- DNS queries (UDP) ---
    dns_queries = [
        ("192.168.1.100", "8.8.8.8", "www.youtube.com"),
        ("192.168.1.101", "8.8.8.8", "www.facebook.com"),
        ("192.168.1.109", "1.1.1.1", "api.github.com"),
    ]
    for src_ip, dst_ip, domain in dns_queries:
        dns_payload = make_dns_query(domain)
        packets.append(build_packet(src_ip, dst_ip, random.randint(49152, 65535), 53, 17, dns_payload))

    # --- Generic/Unknown TCP traffic ---
    for i in range(5):
        src_ip = f"192.168.1.{110 + i}"
        dst_ip = f"10.0.0.{i + 1}"
        packets.append(build_packet(src_ip, dst_ip, 12345, 8080, 6, b"GENERIC_PAYLOAD"))

    write_pcap(output, packets)


if __name__ == "__main__":
    main()
