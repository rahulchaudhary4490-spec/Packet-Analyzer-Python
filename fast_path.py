"""
fast_path.py - Fast Path (FP) worker thread
Mirrors: fast_path.h / FastPath class from C++ project
 
Each FP thread:
  - Has its OWN flow table (no locking needed for flow state)
  - Receives packets from its input queue (fed by Load Balancer)
  - Performs DPI: SNI extraction, app classification, blocking
  - Forwards allowed packets to the shared output queue
  - Drops blocked packets
 
Why each FP has its own flow table:
  Consistent hashing ensures the same 5-tuple ALWAYS goes to the same FP.
  So FP0's flow table only ever sees FP0's flows — no race conditions.
"""
 
import threading
from packet_parser import parse_packet
from sni_extractor import extract_sni, extract_http_host
from types_dpi import AppType, FiveTuple, Flow, sni_to_app_type
from rule_manager import RuleManager
from thread_safe_queue import ThreadSafeQueue
 
 
class FastPath(threading.Thread):
    def __init__(self, fp_id: int, input_queue: ThreadSafeQueue,
                 output_queue: ThreadSafeQueue, rules: RuleManager):
        super().__init__(daemon=True)
        self.fp_id = fp_id
        self._input_queue = input_queue
        self._output_queue = output_queue
        self._rules = rules
 
        # Each FP owns its flow table — no locking needed
        self._flows: dict[FiveTuple, Flow] = {}
 
        # Stats
        self.processed = 0
        self.forwarded = 0
        self.dropped = 0
        self.tcp_count = 0
        self.udp_count = 0
 
    def run(self):
        while True:
            item = self._input_queue.get()
            if item is None:  # Sentinel — shutdown signal
                # Forward sentinel to output queue
                self._output_queue.put_sentinel()
                break
 
            raw_packet, parsed = item
            self.processed += 1
 
            if parsed is None:
                self._output_queue.put(raw_packet)
                self.forwarded += 1
                continue
 
            if parsed.protocol == 6:
                self.tcp_count += 1
            elif parsed.protocol == 17:
                self.udp_count += 1
 
            key = FiveTuple(
                src_ip=parsed.src_ip,
                dst_ip=parsed.dst_ip,
                src_port=parsed.src_port,
                dst_port=parsed.dst_port,
                protocol=parsed.protocol
            )
 
            if key not in self._flows:
                self._flows[key] = Flow()
 
            flow = self._flows[key]
 
            # --- Deep Packet Inspection ---
            if not flow.sni and parsed.payload:
                if parsed.dst_port == 443 or parsed.src_port == 443:
                    sni = extract_sni(parsed.payload)
                    if sni:
                        flow.sni = sni
                        flow.app_type = sni_to_app_type(sni)
                elif parsed.dst_port == 80 or parsed.src_port == 80:
                    host = extract_http_host(parsed.payload)
                    if host:
                        flow.sni = host
                        flow.app_type = sni_to_app_type(host)
                if parsed.dst_port == 53 or parsed.src_port == 53:
                    flow.app_type = AppType.DNS
 
            # --- Blocking check ---
            if not flow.blocked:
                flow.blocked = self._rules.is_blocked(
                    src_ip=parsed.src_ip,
                    app_type=flow.app_type,
                    sni=flow.sni
                )
 
            if flow.blocked:
                self.dropped += 1
            else:
                self._output_queue.put(raw_packet)
                self.forwarded += 1
 
    @property
    def flows(self) -> dict:
        return self._flows