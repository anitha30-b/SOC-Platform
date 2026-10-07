import asyncio
import json
from typing import Any, Dict, Set, Tuple


class SecurityEventBroadcaster:
    def __init__(self):
        self._clients: Set[Tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = set()

    def subscribe(self):
        loop = asyncio.get_running_loop()
        queue = asyncio.Queue()

        self._clients.add((loop, queue))

        return queue

    def unsubscribe(self, queue):
        self._clients = {
            (loop, client_queue)
            for loop, client_queue in self._clients
            if client_queue is not queue
        }

    def publish(self, event: Dict[str, Any]) -> None:
        payload = json.dumps(event, default=str)

        for loop, queue in list(self._clients):

            if loop.is_closed():
                self._clients.discard((loop, queue))
                continue

            def enqueue(
                target_queue=queue,
                target_payload=payload,
            ):
                try:
                    target_queue.put_nowait(target_payload)
                except asyncio.QueueFull:
                    pass

            loop.call_soon_threadsafe(enqueue)


security_event_broadcaster = SecurityEventBroadcaster()