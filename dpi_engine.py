"""
DPI Engine - Deep Packet Inspection System (Multi-threaded)
Python port of: https://github.com/perryvegehan/Packet_analyzer
 
Architecture (same as C++ dpi_mt.cpp):
 
    Reader Thread
         │
         ├── hash(5-tuple) % num_lbs
         ▼
    LB0  LB1  ...         (Load Balancer threads)
     │    │
     ├─ hash % num_fps
     ▼
    FP0  FP1  FP2  FP3    (Fast Path threads - do actual DPI)
         │
         ▼
    Output Queue
         │
         ▼
    Writer Thread          (writes filtered PCAP)
 
Usage:
    python dpi_engine.py <input.pcap> <output.pcap> [options]
 
Options:
    --block-app <App>      Block app (e.g. YouTube, Facebook)
    --block-ip  <IP>       Block source IP
    --block-domain <dom>   Block domain substring
    --lbs <N>              Number of Load Balancer threads (default: 2)
    --fps <N>              Number of Fast Path threads per LB (default: 2)
 
Example:
    python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --lbs 2 --fps 2
"""
 
import threading
import argparse
import hashlib
from packet_parser import parse_packet
from types_dpi import FiveTuple, Flow
from rule_manager import RuleManager
from pcap_io import PcapReader, PcapWriter, RawPacket
from thread_safe_queue import ThreadSafeQueue
from load_balancer import LoadBalancer
from fast_path import FastPath
from report import print_report
 
 
def output_writer_thread(output_queue: ThreadSafeQueue, writer: PcapWriter,
                         num_fps_total: int, done_event: threading.Event):
    """
    Collects allowed packets from all FPs via output queue and writes to PCAP.
    Stops after receiving `num_fps_total` sentinel values (one per FP).
    """
    sentinels_received = 0
    while sentinels_received < num_fps_total:
        item = output_queue.get()
        if item is None:
            sentinels_received += 1
            continue
        writer.write_packet(item)
    done_event.set()
 
 
def run_dpi_mt(input_file: str, output_file: str, rules: RuleManager,
               num_lbs: int = 2, num_fps_per_lb: int = 2):
 
    num_fps_total = num_lbs * num_fps_per_lb
 
    print(f"\n{'='*62}")
    print(f"  DPI ENGINE v2.0 (Multi-threaded)")
    print(f"  Load Balancers: {num_lbs}  |  FPs per LB: {num_fps_per_lb}  |  Total FPs: {num_fps_total}")
    print(f"{'='*62}\n")
 
    # --- Create queues ---
    # One input queue per LB
    lb_queues = [ThreadSafeQueue(maxsize=500) for _ in range(num_lbs)]
 
    # One input queue per FP (num_lbs * num_fps_per_lb total)
    fp_queues = [[ThreadSafeQueue(maxsize=500) for _ in range(num_fps_per_lb)]
                 for _ in range(num_lbs)]
 
    # Single shared output queue (all FPs → writer)
    output_queue = ThreadSafeQueue(maxsize=1000)
 
    # --- Create Fast Path threads ---
    fps = []
    for lb_idx in range(num_lbs):
        for fp_idx in range(num_fps_per_lb):
            fp_id = lb_idx * num_fps_per_lb + fp_idx
            fp = FastPath(
                fp_id=fp_id,
                input_queue=fp_queues[lb_idx][fp_idx],
                output_queue=output_queue,
                rules=rules
            )
            fps.append(fp)
 
    # --- Create Load Balancer threads ---
    lbs = []
    for lb_idx in range(num_lbs):
        lb = LoadBalancer(
            lb_id=lb_idx,
            input_queue=lb_queues[lb_idx],
            fp_queues=fp_queues[lb_idx]
        )
        lbs.append(lb)
 
    # --- Output writer thread ---
    writer = PcapWriter(output_file)
    done_event = threading.Event()
    writer_thread = threading.Thread(
        target=output_writer_thread,
        args=(output_queue, writer, num_fps_total, done_event),
        daemon=True
    )
 
    # --- Start all threads ---
    for fp in fps:
        fp.start()
    for lb in lbs:
        lb.start()
    writer_thread.start()
 
    # --- Reader (main thread) ---
    reader = PcapReader(input_file)
    total = 0
    total_bytes = 0
 
    print(f"[Reader] Processing packets from '{input_file}'...")
 
    for raw_packet in reader.read_packets():
        total += 1
        total_bytes += len(raw_packet.data)
 
        parsed = parse_packet(raw_packet.data)
 
        # Hash 5-tuple → pick Load Balancer
        if parsed is not None:
            key = f"{parsed.src_ip}:{parsed.src_port}-{parsed.dst_ip}:{parsed.dst_port}-{parsed.protocol}"
            lb_idx = int(hashlib.md5(key.encode()).hexdigest(), 16) % num_lbs
        else:
            lb_idx = total % num_lbs
 
        lb_queues[lb_idx].put((raw_packet, parsed))
 
    reader.close()
    print(f"[Reader] Done — {total} packets dispatched.\n")
 
    # Send sentinel to each LB to signal shutdown
    for lb_q in lb_queues:
        lb_q.put_sentinel()
 
    # Wait for all threads to finish
    for lb in lbs:
        lb.join()
    for fp in fps:
        fp.join()
    done_event.wait()
    writer.close()
 
    # --- Collect stats across all FPs ---
    total_forwarded = sum(fp.forwarded for fp in fps)
    total_dropped   = sum(fp.dropped   for fp in fps)
    total_tcp       = sum(fp.tcp_count for fp in fps)
    total_udp       = sum(fp.udp_count for fp in fps)
 
    # Merge flow tables from all FPs
    all_flows = {}
    for fp in fps:
        all_flows.update(fp.flows)
 
    # Thread stats
    print("\n--- Thread Statistics ---")
    for lb in lbs:
        print(f"  LB{lb.lb_id} dispatched: {lb.dispatched}")
    for fp in fps:
        print(f"  FP{fp.fp_id} processed:  {fp.processed}")
 
    print_report(
        total=total,
        forwarded=total_forwarded,
        dropped=total_dropped,
        tcp_count=total_tcp,
        udp_count=total_udp,
        total_bytes=total_bytes,
        flows=all_flows,
        rules=rules
    )
 
 
def main():
    parser = argparse.ArgumentParser(description="DPI Engine - Multi-threaded Deep Packet Inspection")
    parser.add_argument("input",  help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--block-app",    action="append", default=[], metavar="APP")
    parser.add_argument("--block-ip",     action="append", default=[], metavar="IP")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN")
    parser.add_argument("--lbs", type=int, default=2, help="Number of Load Balancer threads")
    parser.add_argument("--fps", type=int, default=2, help="Number of Fast Path threads per LB")
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
 
    run_dpi_mt(args.input, args.output, rules,
               num_lbs=args.lbs, num_fps_per_lb=args.fps)
 
 
if __name__ == "__main__":
    main()