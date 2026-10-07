import asyncio
import json
from typing import Any, Dict, Set, Tuple


class UserNotificationBroadcaster:
    def __init__(self):
        self._clients: Set[
            Tuple[int, asyncio.AbstractEventLoop, asyncio.Queue]
        ] = set()

    def subscribe(self, user_id: int):
        loop = asyncio.get_running_loop()
        queue = asyncio.Queue()
        self._clients.add((int(user_id), loop, queue))
        return queue

    def unsubscribe(self, user_id: int, queue):
        self._clients = {
            (client_user_id, loop, client_queue)
            for client_user_id, loop, client_queue in self._clients
            if not (
                client_user_id == int(user_id)
                and client_queue is queue
            )
        }

    def publish(
        self,
        user_id: int,
        notification: Dict[str, Any],
    ) -> None:
        payload = json.dumps(
            notification,
            default=str,
        )

        for client_user_id, loop, queue in list(self._clients):
            if client_user_id != int(user_id):
                continue

            if loop.is_closed():
                self._clients.discard(
                    (client_user_id, loop, queue)
                )
                continue

            def enqueue(
                target_queue=queue,
                target_payload=payload,
            ):
                try:
                    target_queue.put_nowait(
                        target_payload
                    )
                except asyncio.QueueFull:
                    pass

            loop.call_soon_threadsafe(enqueue)


user_notification_broadcaster = UserNotificationBroadcaster()
