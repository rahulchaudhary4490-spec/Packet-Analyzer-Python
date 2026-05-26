# DPI Engine - Deep Packet Inspection System (Python)

Python port of [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer)

Reads `.pcap` files, performs deep packet inspection, classifies traffic by application (YouTube, Facebook, etc.), applies blocking rules, and outputs a filtered `.pcap` with a detailed report.

---

## Features

- **PCAP I/O** — reads and writes standard `.pcap` files (no Wireshark needed)
- **Protocol Parsing** — Ethernet → IPv4 → TCP/UDP header parsing
- **TLS SNI Extraction** — detects destination domain from TLS Client Hello (works even on HTTPS!)
- **HTTP Host Extraction** — reads `Host:` header from plain HTTP
- **App Classification** — maps domains to apps: YouTube, Facebook, Netflix, Discord, GitHub, etc.
- **Traffic Blocking** — block by IP address, app type, or domain substring
- **Traffic Report** — app breakdown, packet counts, detected SNIs

---

## Project Structure

```
dpi_engine/
├── dpi_engine.py          ← Main entry point (CLI)
├── pcap_io.py             ← PCAP file reader & writer
├── packet_parser.py       ← Ethernet / IP / TCP / UDP parsing
├── sni_extractor.py       ← TLS SNI + HTTP Host extraction
├── types_dpi.py           ← FiveTuple, Flow, AppType
├── rule_manager.py        ← Blocking rules engine
├── report.py              ← Traffic report generator
├── generate_test_pcap.py  ← Creates test .pcap with sample traffic
└── README.md
```

---

## Requirements

```
Python 3.8+
No external libraries required!
```

---

## Usage

### 1. Generate test data

```bash
python generate_test_pcap.py
# Creates test_dpi.pcap
```

### 2. Run the DPI engine

```bash
# Basic (no blocking)
python dpi_engine.py test_dpi.pcap output.pcap

# Block YouTube and TikTok
python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok

# Block a specific IP
python dpi_engine.py test_dpi.pcap output.pcap --block-ip 192.168.1.50

# Block by domain substring
python dpi_engine.py test_dpi.pcap output.pcap --block-domain facebook

# Combine multiple rules
python dpi_engine.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-ip 192.168.1.50 \
    --block-domain tiktok
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║                    PROCESSING REPORT                         ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:           77                                  ║
║ Total Bytes:          5,738                                  ║
║ TCP Packets:             73                                  ║
║ UDP Packets:              4                                  ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:               69                                  ║
║ Dropped:                  8                                  ║
╠══════════════════════════════════════════════════════════════╣
║ APPLICATION BREAKDOWN                                        ║
╠══════════════════════════════════════════════════════════════╣
║ YOUTUBE        8  22.2%  ####  (BLOCKED)                    ║
║ HTTPS          7  19.4%  ###                                 ║
║ FACEBOOK       3   8.3%  #                                   ║
║ DNS            3   8.3%  #                                   ║
╠══════════════════════════════════════════════════════════════╣
║ DETECTED DOMAINS / SNIs                                      ║
╠══════════════════════════════════════════════════════════════╣
║   www.facebook.com  →  FACEBOOK                              ║
║   www.youtube.com   →  YOUTUBE                               ║
║   github.com        →  GITHUB                                ║
╚══════════════════════════════════════════════════════════════╝
```

---

## How It Works

### Packet Structure (Russian nesting doll)

```
[Ethernet 14B] → [IP 20B] → [TCP 20B] → [TLS Client Hello]
                                              └── SNI: "www.youtube.com"
```

### TLS SNI Extraction

Even HTTPS is "encrypted", the **TLS Client Hello** (first packet) sends the destination domain in **plaintext**. We parse the extension type `0x0000` to extract it.

### Flow-Based Blocking

```
Packet 1 (SYN)          → No SNI yet → FORWARD
Packet 3 (Client Hello) → SNI: www.youtube.com → BLOCKED
Packet 4+ (Data)        → Flow is blocked → DROP
```

### Five-Tuple Flow Tracking

Every connection is identified by: `(src_ip, dst_ip, src_port, dst_port, protocol)`. Once a flow is classified or blocked, all future packets in that flow get the same treatment.

---

## Supported Apps

`YOUTUBE`, `FACEBOOK`, `INSTAGRAM`, `TWITTER`, `TIKTOK`, `NETFLIX`, `AMAZON`, `GITHUB`, `REDDIT`, `LINKEDIN`, `TWITCH`, `DISCORD`, `WHATSAPP`, `TELEGRAM`, `ZOOM`, `MICROSOFT`, `APPLE`, `CLOUDFLARE`, `GOOGLE`, `DNS`, `HTTP`, `HTTPS`

---

## Original C++ Project

This is a Python reimplementation of:  
https://github.com/perryvegehan/Packet_analyzer
