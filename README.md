# Packet Analyzer — Deep Packet Inspection Engine (Python)

Python reimplementation of [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer) (originally in C++), with added multi-threading, CSV export, and cleaner modular structure.

---

## What is Deep Packet Inspection (DPI)?

**Deep Packet Inspection** examines the *contents* of network packets — not just where they're going, but *what application* is sending them.

Real-world uses:
- ISPs throttle BitTorrent traffic
- Offices block social media
- Parental controls block inappropriate sites
- Security systems detect malware

### What This Engine Does

```
Input PCAP file → [DPI Engine] → Filtered PCAP + Report + CSV
                        ↓
               - Parses Ethernet/IP/TCP/UDP headers
               - Extracts TLS SNI (identifies HTTPS apps)
               - Classifies traffic (YouTube, Facebook, etc.)
               - Blocks by IP, app, or domain
               - Exports results to CSV
```

---

## How a Packet is Structured

Every network packet is like a **Russian nesting doll** — headers inside headers:

```
┌──────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                   │
│ ┌──────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                     │ │
│ │ ┌──────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                │ │ │
│ │ │ ┌──────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)       │ │ │ │
│ │ │ │ e.g. TLS Client Hello with SNI   │ │ │ │
│ │ │ └──────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

---

## How SNI Extraction Works (The Key Idea)

When you visit `https://www.youtube.com`, your browser sends a **TLS Client Hello** — and the destination domain is visible in **plaintext** before encryption starts:

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension (type 0x0000):
        └── Server Name: "www.youtube.com"  ← We extract THIS
```

This is how the engine identifies apps even on HTTPS traffic — by reading the SNI before the connection is encrypted.

---

## Multi-Threaded Architecture

Same pipeline as the original C++ project:

```
        Reader Thread (main)
               │
       hash(5-tuple) % num_lbs
               │
       ┌───────┴───────┐
       ▼               ▼
   LB0 Thread      LB1 Thread       ← Load Balancers
       │               │
  hash % fps       hash % fps
       │               │
  ┌────┴────┐     ┌────┴────┐
  ▼         ▼     ▼         ▼
 FP0       FP1   FP2       FP3      ← Fast Path (DPI workers)
  │         │     │         │
  └────┬────┴─────┴────┬────┘
       ▼               ▼
      Output Queue (thread-safe)
               │
               ▼
        Writer Thread → output.pcap
```

### Why Consistent Hashing?

All packets of the **same connection** must go to the **same Fast Path thread** — otherwise flow state (like "is this YouTube?") would be split across threads.

```
Connection: 192.168.1.100:54321 → youtube.com:443
  Packet 1 (SYN)          → hash → FP2
  Packet 2 (Client Hello) → hash → FP2  ← same FP, SNI extracted here
  Packet 3 (Data)         → hash → FP2  ← blocking applied correctly
```

---

## Five-Tuple Flow Tracking

A connection is uniquely identified by 5 values:

| Field | Example |
|---|---|
| Source IP | 192.168.1.100 |
| Destination IP | 172.217.14.206 |
| Source Port | 54321 |
| Destination Port | 443 |
| Protocol | TCP (6) |

All packets with the same 5-tuple belong to the same flow. Once a flow is classified or blocked, all future packets get the same treatment.

---

## Project Structure

```
Packet-Analyzer-Python/
├── dpi_engine.py          ← Main entry point + multi-threaded pipeline
├── packet_parser.py       ← Ethernet / IP / TCP / UDP header parsing
├── sni_extractor.py       ← TLS SNI + HTTP Host extraction
├── types_dpi.py           ← FiveTuple, Flow, AppType definitions
├── rule_manager.py        ← Blocking rules (IP, app, domain)
├── pcap_io.py             ← PCAP file reader & writer
├── thread_safe_queue.py   ← Thread-safe queue for inter-thread communication
├── load_balancer.py       ← Load Balancer thread
├── fast_path.py           ← Fast Path DPI worker thread
├── report.py              ← Terminal report + CSV export
├── generate_test_pcap.py  ← Generates sample test.pcap
└── README.md
```

---

## Requirements

```
Python 3.8+
No external libraries required
```

---

## Usage

### Step 1 — Generate test data
```bash
python generate_test_pcap.py
```

### Step 2 — Run the engine
```bash
# Basic
python dpi_engine.py test_dpi.pcap output.pcap

# Block YouTube
python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube

# Block multiple
python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok --block-domain facebook

# Block by IP
python dpi_engine.py test_dpi.pcap output.pcap --block-ip 192.168.1.50

# Custom thread count
python dpi_engine.py test_dpi.pcap output.pcap --lbs 2 --fps 2
```

---

## Sample Output

```
==============================================================
  DPI ENGINE v2.0 (Multi-threaded)
  Load Balancers: 2  |  FPs per LB: 2  |  Total FPs: 4
==============================================================

[Reader] Processing packets from 'test_dpi.pcap'...
[Reader] Done — 34 packets dispatched.

--- Thread Statistics ---
  LB0 dispatched: 14
  LB1 dispatched: 20
  FP0 processed:  14
  FP3 processed:  20

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:           34                                  ║
║ Forwarded:               30                                  ║
║ Dropped:                  4                                  ║
╠══════════════════════════════════════════════════════════════╣
║ YOUTUBE           2   11.1%  ## (BLOCKED)                    ║
║ FACEBOOK          1    5.6%  #                               ║
║ GITHUB            1    5.6%  #                               ║
╠══════════════════════════════════════════════════════════════╣
║ DETECTED DOMAINS / SNIs                                      ║
╠══════════════════════════════════════════════════════════════╣
║   www.youtube.com  →  YOUTUBE                                ║
║   www.facebook.com  →  FACEBOOK                              ║
╚══════════════════════════════════════════════════════════════╝

[CSV] Exported: summary.csv | app_breakdown.csv | detected_domains.csv
```

---

## CSV Export

Every run automatically generates 3 CSV files:

| File | Contains |
|---|---|
| `summary.csv` | Total packets, forwarded, dropped, TCP/UDP counts |
| `app_breakdown.csv` | Per-app traffic with % and blocked status |
| `detected_domains.csv` | All SNIs/domains detected with app classification |

---

## Supported Applications

`YOUTUBE` `FACEBOOK` `INSTAGRAM` `TWITTER` `TIKTOK` `NETFLIX`
`AMAZON` `GITHUB` `REDDIT` `LINKEDIN` `TWITCH` `DISCORD`
`WHATSAPP` `TELEGRAM` `ZOOM` `MICROSOFT` `APPLE` `CLOUDFLARE` `GOOGLE`

---

## Original C++ Project

Python reimplementation of:
https://github.com/perryvegehan/Packet_analyzer