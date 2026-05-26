"""
report.py - Generate traffic analysis report after DPI processing
Mirrors the report output from dpi_mt.cpp
"""

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
