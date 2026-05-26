"""
thread_safe_queue.py - Thread-safe queue for inter-thread communication
Mirrors: thread_safe_queue.h from C++ project
 
Uses Python's queue.Queue which is already thread-safe.
Producer calls put(), consumer calls get().
Sentinel value (None) signals shutdown to consumers.
"""
 
import queue
 
 
class ThreadSafeQueue:
    def __init__(self, maxsize: int = 1000):
        self._q = queue.Queue(maxsize=maxsize)
 
    def put(self, item):
        """Block if queue is full (backpressure)."""
        self._q.put(item)
 
    def get(self):
        """Block until item is available."""
        return self._q.get()
 
    def put_sentinel(self):
        """Signal consumer thread to stop."""
        self._q.put(None)
 
    def size(self):
        return self._q.qsize()
 
    def task_done(self):
        self._q.task_done()