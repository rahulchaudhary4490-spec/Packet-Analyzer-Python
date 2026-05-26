"""
DPI Engine - Deep Packet Inspection System
Python port of: https://github.com/perryvegehan/Packet_analyzer

Usage:
    python dpi_engine.py <input.pcap> <output.pcap> [options]

Options:
    --block-app <AppName>     Block all traffic for an app (e.g. YouTube)
    --block-ip  <IP>          Block all traffic from an IP
    --block-domain <domain>   Block any SNI containing this string

Example:
    python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --block-domain tiktok
"""

import sys
import argparse
from packet_parser import parse_packet
from sni_extractor import extract_sni, extract_http_host
from types_dpi import AppType, sni_to_app_type, FiveTuple, Flow
from rule_manager import RuleManager
from pcap_io import PcapReader, PcapWriter
from report import print_report


def run_dpi(input_file: str, output_file: str, rules: RuleManager):
    reader = PcapReader(input_file)
    writer = PcapWriter(output_file)

    flows: dict[FiveTuple, Flow] = {}

    total = 0
    forwarded = 0
    dropped = 0
    tcp_count = 0
    udp_count = 0
    total_bytes = 0

    print(f"\n[Reader] Processing packets from '{input_file}'...\n")

    for raw_packet in reader.read_packets():
        total += 1
        total_bytes += len(raw_packet.data)

        parsed = parse_packet(raw_packet.data)
        if parsed is None:
            writer.write_packet(raw_packet)
            forwarded += 1
            continue

        if parsed.protocol == 6:
            tcp_count += 1
        elif parsed.protocol == 17:
            udp_count += 1

        key = FiveTuple(
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
            src_port=parsed.src_port,
            dst_port=parsed.dst_port,
            protocol=parsed.protocol
        )

        if key not in flows:
            flows[key] = Flow()

        flow = flows[key]

        # --- Deep Packet Inspection ---
        if not flow.sni and parsed.payload:
            # TLS SNI extraction (HTTPS port 443)
            if parsed.dst_port == 443 or parsed.src_port == 443:
                sni = extract_sni(parsed.payload)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)

            # HTTP Host header extraction (port 80)
            elif parsed.dst_port == 80 or parsed.src_port == 80:
                host = extract_http_host(parsed.payload)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

            # DNS detection (port 53)
            if parsed.dst_port == 53 or parsed.src_port == 53:
                flow.app_type = AppType.DNS

        # --- Blocking ---
        if not flow.blocked:
            flow.blocked = rules.is_blocked(
                src_ip=parsed.src_ip,
                app_type=flow.app_type,
                sni=flow.sni
            )

        if flow.blocked:
            dropped += 1
        else:
            writer.write_packet(raw_packet)
            forwarded += 1

    reader.close()
    writer.close()

    print_report(
        total=total,
        forwarded=forwarded,
        dropped=dropped,
        tcp_count=tcp_count,
        udp_count=udp_count,
        total_bytes=total_bytes,
        flows=flows,
        rules=rules
    )


def main():
    parser = argparse.ArgumentParser(description="DPI Engine - Deep Packet Inspection")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--block-app", action="append", default=[], metavar="APP",
                        help="Block an application (e.g. YouTube, Facebook)")
    parser.add_argument("--block-ip", action="append", default=[], metavar="IP",
                        help="Block a source IP address")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN",
                        help="Block a domain substring (e.g. tiktok)")
    args = parser.parse_args()

    rules = RuleManager()
    for app in args.block_app:
        rules.add_blocked_app(app)
        print(f"[Rules] Blocking app: {app}")
    for ip in args.block_ip:
        rules.add_blocked_ip(ip)
        print(f"[Rules] Blocking IP: {ip}")
    for domain in args.block_domain:
        rules.add_blocked_domain(domain)
        print(f"[Rules] Blocking domain: {domain}")

    run_dpi(args.input, args.output, rules)


if __name__ == "__main__":
    main()
