"""
report.py - Generate traffic analysis report after DPI processing
Mirrors the report output from dpi_mt.cpp
 
Also exports results to CSV:
  - summary.csv      → packet counts, forwarded, dropped
  - app_breakdown.csv → per-app traffic stats
  - detected_domains.csv → all SNIs/domains found
"""
 
import csv
import os
from collections import Counter
from types_dpi import AppType, Flow, FiveTuple
from rule_manager import RuleManager
 
 
def print_report(
    total: int,
    forwarded: int,
    dropped: int,
    tcp_count: int,
    udp_count: int,
    total_bytes: int,
    flows: dict,
    rules: RuleManager
):
    width = 62
 
    def box_line(text="", fill="═"):
        return f"╠{'═' * width}╣" if text == "---" else f"║ {text:<{width - 2}} ║"
 
    def top():    return f"╔{'═' * width}╗"
    def bottom(): return f"╚{'═' * width}╝"
    def divider(): return f"╠{'═' * width}╣"
 
    print("\n" + top())
    print(box_line("PROCESSING REPORT".center(width - 2)))
    print(divider())
    print(box_line(f"Total Packets:   {total:>10}"))
    print(box_line(f"Total Bytes:     {total_bytes:>10,}"))
    print(box_line(f"TCP Packets:     {tcp_count:>10}"))
    print(box_line(f"UDP Packets:     {udp_count:>10}"))
    print(divider())
    print(box_line(f"Forwarded:       {forwarded:>10}"))
    print(box_line(f"Dropped:         {dropped:>10}"))
    print(divider())
 
    # App breakdown
    app_counts = Counter()
    sni_map: dict[str, AppType] = {}
 
    for key, flow in flows.items():
        app_counts[flow.app_type] += 1
        if flow.sni:
            sni_map[flow.sni] = flow.app_type
 
    print(box_line("APPLICATION BREAKDOWN"))
    print(divider())
 
    total_flows = sum(app_counts.values()) or 1
    for app, count in app_counts.most_common():
        pct = count / total_flows * 100
        bar = "#" * int(pct / 5)
        blocked_tag = " (BLOCKED)" if app in rules.blocked_apps else ""
        line = f"{app.name:<14} {count:>4}  {pct:5.1f}%  {bar}{blocked_tag}"
        print(box_line(line))
 
    print(divider())
    print(box_line("DETECTED DOMAINS / SNIs"))
    print(divider())
 
    if sni_map:
        for sni, app in sorted(sni_map.items()):
            print(box_line(f"  {sni}  →  {app.name}"))
    else:
        print(box_line("  (none detected)"))
 
    print(bottom())
    print()
 
    # Export to CSV
    export_csv(
        total=total, forwarded=forwarded, dropped=dropped,
        tcp_count=tcp_count, udp_count=udp_count, total_bytes=total_bytes,
        app_counts=app_counts, sni_map=sni_map, rules=rules
    )
 
 
def export_csv(total, forwarded, dropped, tcp_count, udp_count,
               total_bytes, app_counts, sni_map, rules, output_dir="."):
    """
    Export DPI results to 3 CSV files:
      - summary.csv
      - app_breakdown.csv
      - detected_domains.csv
    """
 
    # 1. summary.csv
    summary_path = os.path.join(output_dir, "summary.csv")
    with open(summary_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Packets", total])
        writer.writerow(["Total Bytes", total_bytes])
        writer.writerow(["TCP Packets", tcp_count])
        writer.writerow(["UDP Packets", udp_count])
        writer.writerow(["Forwarded", forwarded])
        writer.writerow(["Dropped", dropped])
 
    # 2. app_breakdown.csv
    app_path = os.path.join(output_dir, "app_breakdown.csv")
    total_flows = sum(app_counts.values()) or 1
    with open(app_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Application", "Flow Count", "Percentage", "Blocked"])
        for app, count in app_counts.most_common():
            pct = round(count / total_flows * 100, 2)
            blocked = "Yes" if app in rules.blocked_apps else "No"
            writer.writerow([app.name, count, pct, blocked])
 
    # 3. detected_domains.csv
    domains_path = os.path.join(output_dir, "detected_domains.csv")
    with open(domains_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain / SNI", "Application"])
        for sni, app in sorted(sni_map.items()):
            writer.writerow([sni, app.name])
 
    print(f"[CSV] Exported: summary.csv | app_breakdown.csv | detected_domains.csv")