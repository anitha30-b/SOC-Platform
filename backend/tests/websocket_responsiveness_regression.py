"""Check that slow WebSocket database I/O does not block the event loop."""
import asyncio
import os
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["DATABASE_URL"] = "sqlite://"

import client_realtime_events as realtime


class FakeWebSocket:
    query_params = {"token": "test-token"}

    def __init__(self):
        self.accepted = asyncio.Event()
        self.sent = asyncio.Event()

    async def accept(self):
        self.accepted.set()

    async def close(self, code=1000):
        pass

    async def receive_text(self):
        await asyncio.Future()

    async def send_json(self, payload):
        self.sent.set()


class ResponsivenessTests(unittest.IsolatedAsyncioTestCase):
    async def check_route(self, route_name, broadcaster_name, phase):
        main_thread = threading.get_ident()
        entered = threading.Event()
        release = threading.Event()
        expired = threading.Event()
        query_threads = []
        session_threads = []
        sessions = []
        target_session = 1 if phase == "authentication" else 2

        class Query:
            def __init__(self, entity):
                self.entity = entity

            def filter(self, *args):
                return self

            def join(self, *args):
                return self

            def first(self):
                if self.entity is realtime.User:
                    return SimpleNamespace(id=7, role_id=1, client_id=None)
                return (7,)

        class DB:
            def __init__(self):
                sessions.append(self)
                self.number = len(sessions)
                self.creator = threading.get_ident()
                self.first_query = True
                self.closed = False

            def query(self, entity):
                query_threads.append(threading.get_ident())
                if self.first_query and self.number == target_session:
                    self.first_query = False
                    entered.set()
                    # Finite guard prevents a broken implementation hanging tests.
                    if not release.wait(timeout=1):
                        expired.set()
                return Query(entity)

            def close(self):
                session_threads.append(
                    (self.creator, threading.get_ident())
                )
                self.closed = True

        async def wait_for_worker():
            while not entered.is_set():
                await asyncio.sleep(0.005)

        ws = FakeWebSocket()
        route = getattr(realtime, route_name)
        broadcaster = getattr(realtime, broadcaster_name)

        with (
            patch.object(realtime, "SessionLocal", DB),
            patch.object(
                realtime, "decode_access_token",
                return_value={"sub": "7"},
            ),
            patch.object(
                realtime, "owned_security_event_filter",
                return_value=True,
            ),
        ):
            task = asyncio.create_task(route(ws))
            try:
                if phase == "signal":
                    await asyncio.wait_for(ws.accepted.wait(), timeout=2)
                    broadcaster.publish({
                        "event_id": "responsiveness-test",
                        "endpoint_asset_id": 7,
                    })

                await asyncio.wait_for(wait_for_worker(), timeout=2)

                # This coroutine must run while the query is still waiting.
                self.assertFalse(
                    expired.is_set(),
                    "Database wait blocked event-loop progress",
                )
                self.assertTrue(query_threads)
                self.assertTrue(
                    all(t != main_thread for t in query_threads),
                    "Database query ran on the event-loop thread",
                )

                release.set()
                completion = (
                    ws.accepted if phase == "authentication" else ws.sent
                )
                await asyncio.wait_for(completion.wait(), timeout=2)
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        self.assertTrue(sessions)
        self.assertTrue(all(session.closed for session in sessions))
        self.assertTrue(
            all(created == closed for created, closed in session_threads),
            "Database session crossed worker threads",
        )

    async def test_endpoint_authentication_keeps_loop_responsive(self):
        await self.check_route(
            "client_security_events_websocket",
            "client_security_event_broadcaster",
            "authentication",
        )

    async def test_endpoint_revalidation_keeps_loop_responsive(self):
        await self.check_route(
            "client_security_events_websocket",
            "client_security_event_broadcaster",
            "signal",
        )

    async def test_siem_authentication_keeps_loop_responsive(self):
        await self.check_route(
            "client_siem_events_websocket",
            "client_siem_event_broadcaster",
            "authentication",
        )

    async def test_siem_revalidation_keeps_loop_responsive(self):
        await self.check_route(
            "client_siem_events_websocket",
            "client_siem_event_broadcaster",
            "signal",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
