import asyncio
import json
import threading
from typing import Any, Dict, Set, Tuple


class SecurityEventBroadcaster:
    """
    Thread-safe broadcaster for PostgreSQL security events.

    Each connected WebSocket has its own bounded queue.
    If a client is too slow, the oldest queued event is
    discarded so newer events can still be delivered.
    """

    def __init__(self, max_queue_size: int = 500):
        self.max_queue_size = max_queue_size
        self._clients: Set[
            Tuple[asyncio.AbstractEventLoop, asyncio.Queue]
        ] = set()
        self._lock = threading.Lock()
        self._dropped_events = 0

    def subscribe(self):
        loop = asyncio.get_running_loop()
        queue = asyncio.Queue(maxsize=self.max_queue_size)

        with self._lock:
            self._clients.add((loop, queue))

        return queue

    def unsubscribe(self, queue):
        with self._lock:
            self._clients = {
                (loop, client_queue)
                for loop, client_queue in self._clients
                if client_queue is not queue
            }

    def _enqueue(self, queue, payload):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass

            try:
                queue.put_nowait(payload)
                with self._lock:
                    self._dropped_events += 1
            except asyncio.QueueFull:
                with self._lock:
                    self._dropped_events += 1

    def publish(self, event: Dict[str, Any]) -> None:
        payload = json.dumps(event, default=str)

        with self._lock:
            clients = list(self._clients)

        for loop, queue in clients:
            if loop.is_closed():
                self.unsubscribe(queue)
                continue

            try:
                loop.call_soon_threadsafe(
                    self._enqueue,
                    queue,
                    payload,
                )
            except RuntimeError:
                self.unsubscribe(queue)

    def stats(self):
        with self._lock:
            return {
                "connected_clients": len(self._clients),
                "dropped_events": self._dropped_events,
                "queue_limit": self.max_queue_size,
            }


security_event_broadcaster = SecurityEventBroadcaster()
