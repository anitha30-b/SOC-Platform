"""Role boundaries and session revocation for the combined dashboard APIs.

Uses an isolated SQLite engine and overridden HTTP identity. WebSocket tests
use real token validation with fake database sessions, never PostgreSQL.
"""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite://"
os.environ.setdefault("JWT_SECRET_KEY", "isolated-merge-regression-only-key")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import asset_registration_regression as support
import models
import rbac
import security_events_router as user_events
import admin_security_events_router as admin_events
import realtime_router
from security import create_access_token
from fastapi import FastAPI, WebSocketDisconnect
from fastapi.testclient import TestClient

for model in (models.Assessment, models.SecurityEvent):
    model.__table__.create(support.engine, checkfirst=True)


class RoleBoundaryTests(unittest.TestCase):
    def setUp(self):
        with support.Factory() as db:
            db.query(models.SecurityEvent).delete()
            db.query(models.Assessment).delete()
            for model in reversed(support.TABLE_MODELS):
                db.query(model).delete()
            for uid, role in ((1, 1), (2, 1), (20, 2), (30, 3), (99, 9)):
                db.add(support.fixture(models.User, id=uid, role_id=role, client_id=None))
            for eid, owner, message in ((1, 1, "first-tenant-message"), (2, 2, "second-tenant-message")):
                db.add(support.fixture(
                    models.SecurityEvent, id=eid, event_id=f"merge-event-{eid}",
                    owner_user_id=owner, client_id=None, assessment_id=None,
                    telemetry_source_id=None, endpoint_asset_id=None,
                    source="snort", event_type=f"merge-type-{eid}",
                    message=message, severity="HIGH", alert_status="ACTIVE",
                    timestamp=datetime(2026, 1, 1),
                    raw_event=json.dumps({"alert": "test", "correlation": {"count": 2}}),
                ))
            db.commit()
        self.app = FastAPI()
        self.app.include_router(user_events.router)
        self.app.include_router(admin_events.router)
        self.app.dependency_overrides[user_events.get_db] = support.get_db
        self.select_user(1)
        self.app.dependency_overrides[rbac.get_current_user] = lambda: self.identity
        self.client = TestClient(self.app)

    def tearDown(self):
        self.client.close()

    def select_user(self, uid):
        with support.Factory() as db:
            self.identity = db.get(models.User, uid)
            db.expunge(self.identity)

    def test_user_reads_only_its_events(self):
        response = self.client.get("/security-events")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([row["event_id"] for row in response.json()], ["merge-event-1"])

    def test_client_cannot_read_global_admin_events(self):
        self.assertEqual(self.client.get("/admin/security-events").status_code, 403)
        self.assertEqual(self.client.get("/admin/security-events/stats/techniques").status_code, 403)

    def test_admin_reads_global_events(self):
        self.select_user(30)
        response = self.client.get("/admin/security-events")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual({row["event_id"] for row in response.json()}, {"merge-event-1", "merge-event-2"})

    def test_analyst_reads_global_events(self):
        self.select_user(20)
        response = self.client.get("/admin/security-events")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(response.json()), 2)

    def test_soc_roles_do_not_replace_client_role(self):
        for uid in (20, 30):
            self.select_user(uid)
            self.assertEqual(self.client.get("/security-events").status_code, 403)

    def test_unknown_role_is_denied_by_both_namespaces(self):
        self.select_user(99)
        for path in ("/security-events", "/admin/security-events"):
            self.assertEqual(self.client.get(path).status_code, 403)

    def test_admin_search_and_event_type_filters(self):
        self.select_user(30)
        response = self.client.get("/admin/security-events", params={"search": "second-tenant-message"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([row["event_id"] for row in response.json()], ["merge-event-2"])
        response = self.client.get("/admin/security-events", params={"event_type": "merge-type-1"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([row["event_id"] for row in response.json()], ["merge-event-1"])

    def test_snort_evidence_survives_in_both_serializers(self):
        response = self.client.get("/security-events")
        self.assertEqual(response.json()[0]["correlation"], {"count": 2})
        self.assertIn("detection", response.json()[0])
        self.select_user(30)
        response = self.client.get("/admin/security-events")
        self.assertEqual(response.json()[0]["raw_event"]["alert"], "test")

    def test_client_cannot_use_admin_mutation(self):
        response = self.client.patch("/admin/security-events/merge-event-2/acknowledge")
        self.assertEqual(response.status_code, 403)
        with support.Factory() as db:
            self.assertEqual(db.get(models.SecurityEvent, 2).alert_status, "ACTIVE")

    def test_admin_mutation_does_not_enable_foreign_client_mutation(self):
        self.select_user(30)
        response = self.client.patch("/admin/security-events/merge-event-2/acknowledge")
        self.assertEqual(response.status_code, 200, response.text)
        self.select_user(1)
        response = self.client.patch("/security-events/merge-event-2/resolve")
        self.assertEqual(response.status_code, 404, response.text)


class FakeQuery:
    def __init__(self, value):
        self.value = value
    def filter(self, *args):
        return self
    def first(self):
        return self.value


class AdminWebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, role=3, revoked=False, revoke_after_first=False, include_jti=True):
        user = models.User(id=30, role_id=role)
        session = SimpleNamespace(
            revoked_at=datetime.now(timezone.utc) if revoked else None,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            role_id=role,
        )
        claims = {"sub": "30"}
        if include_jti:
            claims["jti"] = "merge-test-session"
        token = create_access_token(claims)
        queue = asyncio.Queue()
        queue.put_nowait(json.dumps({"event_id": "admin-visible-event"}))

        class DB:
            def query(self, entity):
                return FakeQuery(user if entity is models.User else session)
            def close(self):
                pass

        class Socket:
            query_params = {"token": token}
            def __init__(self):
                self.sent = []
                self.close_code = None
                self.closed = asyncio.Event()
            async def accept(self):
                pass
            async def close(self, code=1000, reason=None):
                self.close_code = code
                self.closed.set()
            async def receive_text(self):
                await self.closed.wait()
                raise WebSocketDisconnect(code=1000)
            async def send_text(self, payload):
                self.sent.append(json.loads(payload))
                if revoke_after_first:
                    session.revoked_at = datetime.now(timezone.utc)
                    queue.put_nowait(json.dumps({"event_id": "must-not-send"}))
                else:
                    self.closed.set()

        socket = Socket()
        broadcaster = SimpleNamespace(subscribe=lambda: queue, unsubscribe=lambda q: None)
        with patch.object(realtime_router, "SessionLocal", DB), patch.object(
            realtime_router, "security_event_broadcaster", broadcaster
        ):
            await asyncio.wait_for(realtime_router.security_events_websocket(socket), timeout=3)
        return socket

    async def test_admin_session_receives_event(self):
        socket = await self.exercise()
        self.assertEqual(socket.sent, [{"event_id": "admin-visible-event"}])

    async def test_client_is_rejected_by_global_socket(self):
        socket = await self.exercise(role=1)
        self.assertEqual(socket.close_code, 1008)
        self.assertEqual(socket.sent, [])

    async def test_missing_session_jti_is_rejected(self):
        socket = await self.exercise(include_jti=False)
        self.assertEqual(socket.close_code, 1008)
        self.assertEqual(socket.sent, [])

    async def test_revoked_session_is_rejected(self):
        socket = await self.exercise(revoked=True)
        self.assertEqual(socket.close_code, 1008)
        self.assertEqual(socket.sent, [])

    async def test_revocation_stops_existing_stream(self):
        socket = await self.exercise(revoke_after_first=True)
        self.assertEqual(socket.close_code, 1008)
        self.assertEqual(socket.sent, [{"event_id": "admin-visible-event"}])


if __name__ == "__main__":
    unittest.main(verbosity=2)
