import asyncio
import json
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import client_realtime_events
import realtime_router
from models import SecurityEvent, User
from security import create_access_token


class FakeQuery:
    def __init__(self, result, on_first=None):
        self.result = result
        self.on_first = on_first

    def filter(self, *args):
        return self

    def first(self):
        if self.on_first:
            self.on_first()
        return self.result


class FakeDB:
    def __init__(self, query_results=None, on_event_result=None):
        self.query_results = iter(query_results or [])
        self.query_count = 0
        self.on_event_result = on_event_result

    def query(self, *args):
        result = next(self.query_results)
        self.query_count += 1
        callback = (
            self.on_event_result
            if self.query_count % 2 == 0
            else None
        )
        return FakeQuery(result, callback)

    def close(self):
        pass


class FakeBroadcaster:
    def __init__(self, signal):
        self.queue = asyncio.Queue()
        self.queue.put_nowait(json.dumps(signal))

    def subscribe(self):
        return self.queue

    def unsubscribe(self, queue):
        pass


class FakeWebSocket:
    def __init__(self, token):
        self.query_params = {"token": token}
        self.disconnect_event = asyncio.Event()
        self.sent_messages = []

    async def accept(self):
        pass

    async def receive_text(self):
        await self.disconnect_event.wait()
        raise WebSocketDisconnect(code=1000)

    async def send_json(self, data):
        self.sent_messages.append(data)
        self.disconnect_event.set()

    async def close(self, code=1000, reason=None):
        self.disconnect_event.set()


class SIEMWebSocketTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = FastAPI()
        cls.app.include_router(realtime_router.router)
        cls.app.include_router(client_realtime_events.router)

    def test_old_global_websocket_is_rejected(self):
        with TestClient(self.app) as client:
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect("/ws/security-events"):
                    pass

    def test_siem_websocket_rejects_missing_token(self):
        with TestClient(self.app) as client:
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect("/ws/client/siem-events"):
                    pass

    def test_siem_websocket_rejects_invalid_token(self):
        fake_db = FakeDB()

        with patch.object(
            client_realtime_events,
            "SessionLocal",
            return_value=fake_db,
        ), patch.object(
            client_realtime_events,
            "decode_access_token",
            return_value=None,
        ):
            with TestClient(self.app) as client:
                with self.assertRaises(WebSocketDisconnect):
                    with client.websocket_connect(
                        "/ws/client/siem-events?token=invalid-token"
                    ):
                        pass

    def run_siem_route_test(self, event_result):
        async def run():
            user = User(id=101, role_id=1)
            token = create_access_token({"sub": "101", "role_id": 1})

            auth_db = FakeDB([user])
            event_db = FakeDB(
                [user, event_result],
                on_event_result=lambda: websocket.disconnect_event.set(),
            )

            broadcaster = FakeBroadcaster({
                "event_id": "tenant-test-event",
                "message": "Private event contents",
            })
            websocket = FakeWebSocket(token)

            with patch.object(
                client_realtime_events,
                "SessionLocal",
                side_effect=[auth_db, event_db],
            ), patch.object(
                client_realtime_events,
                "owned_security_event_filter",
                return_value=(SecurityEvent.id > 0),
            ), patch.object(
                client_realtime_events,
                "client_siem_event_broadcaster",
                broadcaster,
            ):
                await client_realtime_events.client_siem_events_websocket(
                    websocket
                )

            return websocket.sent_messages

        return asyncio.run(run())

    def test_unauthorized_event_sends_no_refresh_signal(self):
        messages = self.run_siem_route_test(event_result=None)
        self.assertEqual(messages, [])

    def test_authorized_event_sends_only_minimal_refresh_signal(self):
        messages = self.run_siem_route_test(event_result=object())
        self.assertEqual(messages, [{"type": "siem_refresh"}])


if __name__ == "__main__":
    unittest.main(verbosity=2)
