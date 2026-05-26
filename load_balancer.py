"""
load_balancer.py - Load Balancer (LB) thread
Mirrors: load_balancer.h / LoadBalancer class from C++ project
 
Each LB thread:
  - Receives packets from the reader thread
  - Hashes the 5-tuple to pick which Fast Path thread gets the packet
  - Pushes to that FP's input queue
 
Why consistent hashing matters:
  All packets of the SAME connection (same 5-tuple) must go to the SAME FP.
  Otherwise two FPs would each have incomplete flow state for that connection.
 
  Connection A: 192.168.1.100:54321 → 443
    Packet 1 (SYN)          → hash → FP2
    Packet 2 (Client Hello) → hash → FP2  ← same FP, flow state intact!
    Packet 3 (Data)         → hash → FP2  ← correct blocking applied
"""
 
import threading
import hashlib
from thread_safe_queue import ThreadSafeQueue
 
 
def _hash_tuple(src_ip: str, dst_ip: str, src_port: int,
                dst_port: int, protocol: int) -> int:
    """Consistent hash of a 5-tuple → integer."""
    key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    return int(hashlib.md5(key.encode()).hexdigest(), 16)
 
 
class LoadBalancer(threading.Thread):
    def __init__(self, lb_id: int, input_queue: ThreadSafeQueue,
                 fp_queues: list[ThreadSafeQueue]):
        super().__init__(daemon=True)
        self.lb_id = lb_id
        self._input_queue = input_queue
        self._fp_queues = fp_queues
        self.dispatched = 0
 
    def run(self):
        num_fps = len(self._fp_queues)
 
        while True:
            item = self._input_queue.get()
            if item is None:  # Sentinel — shutdown
                # Forward sentinel to ALL fast paths
                for fp_q in self._fp_queues:
                    fp_q.put_sentinel()
                break
 
            raw_packet, parsed = item
            self.dispatched += 1
 
            if parsed is not None:
                # Consistent hash → pick FP
                h = _hash_tuple(
                    parsed.src_ip, parsed.dst_ip,
                    parsed.src_port, parsed.dst_port,
                    parsed.protocol
                )
                fp_idx = h % num_fps
            else:
                # Unknown packet — round-robin fallback
                fp_idx = self.dispatched % num_fps
 
            self._fp_queues[fp_idx].put((raw_packet, parsed))