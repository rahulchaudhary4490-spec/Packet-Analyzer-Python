"""
pcap_io.py - PCAP file reader and writer (no external libs needed for basic reading)
Mirrors: pcap_reader.h / pcap_reader.cpp
"""

import struct
from dataclasses import dataclass


# PCAP Global Header: magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network
PCAP_GLOBAL_HEADER_FMT = "<IHHiIII"
PCAP_GLOBAL_HEADER_SIZE = struct.calcsize(PCAP_GLOBAL_HEADER_FMT)
PCAP_MAGIC = 0xa1b2c3d4

# PCAP Packet Header: ts_sec, ts_usec, incl_len, orig_len
PCAP_PKT_HEADER_FMT = "<IIII"
PCAP_PKT_HEADER_SIZE = struct.calcsize(PCAP_PKT_HEADER_FMT)


@dataclass
class RawPacket:
    ts_sec: int
    ts_usec: int
    orig_len: int
    data: bytes


class PcapReader:
    def __init__(self, filename: str):
        self._f = open(filename, "rb")
        header_data = self._f.read(PCAP_GLOBAL_HEADER_SIZE)
        if len(header_data) < PCAP_GLOBAL_HEADER_SIZE:
            raise ValueError("File too small to be a valid PCAP.")
        magic, major, minor, _, _, self.snaplen, self.network = \
            struct.unpack(PCAP_GLOBAL_HEADER_FMT, header_data)
        if magic != PCAP_MAGIC:
            raise ValueError(f"Not a valid PCAP file (magic={hex(magic)})")
        self._header_raw = header_data

    def read_packets(self):
        while True:
            pkt_hdr = self._f.read(PCAP_PKT_HEADER_SIZE)
            if not pkt_hdr or len(pkt_hdr) < PCAP_PKT_HEADER_SIZE:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(PCAP_PKT_HEADER_FMT, pkt_hdr)
            data = self._f.read(incl_len)
            if len(data) < incl_len:
                break
            yield RawPacket(ts_sec=ts_sec, ts_usec=ts_usec, orig_len=orig_len, data=data)
            self._last_pkt_hdr = pkt_hdr  # store for writer

    def close(self):
        self._f.close()


class PcapWriter:
    def __init__(self, filename: str):
        self._f = open(filename, "wb")
        # Write global header (standard values)
        global_header = struct.pack(
            PCAP_GLOBAL_HEADER_FMT,
            PCAP_MAGIC,   # magic
            2, 4,         # version
            0,            # timezone
            0,            # sig figs
            65535,        # snaplen
            1             # network (Ethernet)
        )
        self._f.write(global_header)

    def write_packet(self, pkt: RawPacket):
        pkt_header = struct.pack(
            PCAP_PKT_HEADER_FMT,
            pkt.ts_sec,
            pkt.ts_usec,
            len(pkt.data),
            pkt.orig_len
        )
        self._f.write(pkt_header)
        self._f.write(pkt.data)

    def close(self):
        self._f.close()
