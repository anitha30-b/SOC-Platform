"""Isolated notification HTTP ownership and broadcaster tests."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import asyncio
    import json
    import unittest
    from datetime import datetime, timezone, timedelta
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    import database

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    database.engine.dispose()
    database.engine = engine
    assert engine.url.get_backend_name() == "sqlite"

    import models
    import rbac
    import user_notifications_router as notifications
    from user_notification_broadcaster import UserNotificationBroadcaster

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(notifications.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[database.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    class NotificationTests(unittest.TestCase):
        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, role_id=role, client_id=client, username=f"user-{uid}",
            )

        def setUp(self):
            models.Notification.__table__.create(engine, checkfirst=True)
            with engine.begin() as connection:
                connection.execute(text("DELETE FROM notifications"))
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            with Session() as db:
                rows = [(5, index) for index in range(1, 106)]
                rows += [(owner, 1) for owner in (6, 10, 11, 20)]
                rows += [(None, 1)]
                for owner, index in rows:
                    db.add(models.Notification(
                        notification_id=f"N{owner}-{index}",
                        user_id=owner,
                        assessment_id=100 if index % 2 == 0 else 200,
                        source="Synthetic-A" if index % 2 == 0 else "Synthetic-B",
                        event_type="synthetic",
                        severity="HIGH" if index % 2 == 0 else "LOW",
                        title="Synthetic notification", message="Test data only",
                        is_read=owner == 5 and index == 1,
                        read_at=now if owner == 5 and index == 1 else None,
                        created_at=now + timedelta(seconds=index),
                    ))
                db.commit()
            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def count(self):
            response = self.client.get("/notifications/unread-count")
            self.assertEqual(response.status_code, 200)
            return response.json()["unread_count"]

        def test_personal_list_excludes_other_and_unowned_records(self):
            response = self.client.get("/notifications", params={"limit": 500})
            self.assertEqual(response.status_code, 200)
            rows = response.json()["notifications"]
            self.assertEqual(len(rows), 105)
            self.assertTrue(all(row["notification_id"].startswith("N5-") for row in rows))

        def test_default_list_is_bounded_but_unread_total_is_full(self):
            response = self.client.get("/notifications")
            self.assertEqual(len(response.json()["notifications"]), 100)
            self.assertEqual(self.count(), 104)

        def test_same_client_does_not_share_notifications(self):
            self.login(10, 100)
            response = self.client.get("/notifications")
            self.assertEqual(
                [row["notification_id"] for row in response.json()["notifications"]],
                ["N10-1"],
            )
            self.assertEqual(self.count(), 1)

        def test_other_user_unread_count_is_scoped(self):
            self.login(20, 200)
            self.assertEqual(self.count(), 1)

        def test_read_and_unread_are_idempotent(self):
            for _ in range(2):
                response = self.client.patch("/notifications/N5-2/read")
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.json()["is_read"])
                self.assertIsNotNone(response.json()["read_at"])
            self.assertEqual(self.count(), 103)
            for _ in range(2):
                response = self.client.patch("/notifications/N5-2/unread")
                self.assertEqual(response.status_code, 200)
            self.assertEqual(self.count(), 104)

        def test_other_owner_cannot_be_marked_read_or_unread(self):
            for suffix in ("read", "unread"):
                response = self.client.patch(f"/notifications/N6-1/{suffix}")
                self.assertEqual(response.status_code, 404)
            self.login(6)
            self.assertEqual(self.count(), 1)

        def test_same_client_cannot_mutate_peer(self):
            self.login(10, 100)
            self.assertEqual(
                self.client.patch("/notifications/N11-1/read").status_code, 404
            )
            self.assertEqual(
                self.client.delete("/notifications/N11-1").status_code, 404
            )

        def test_mark_all_read_only_affects_owner(self):
            response = self.client.patch("/notifications/read-all")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["updated"], 104)
            self.assertEqual(self.count(), 0)
            self.login(6)
            self.assertEqual(self.count(), 1)

        def test_delete_own_notification(self):
            self.assertEqual(
                self.client.delete("/notifications/N5-2").status_code, 200
            )
            self.assertEqual(self.count(), 103)
            self.assertEqual(
                self.client.delete("/notifications/N5-2").status_code, 404
            )

        def test_delete_other_notification_is_denied(self):
            self.assertEqual(
                self.client.delete("/notifications/N6-1").status_code, 404
            )
            self.login(6)
            self.assertEqual(self.count(), 1)

        def test_filters_remain_owner_scoped(self):
            response = self.client.get("/notifications", params={
                "limit": 500, "unread_only": True, "severity": "HIGH",
                "source": "Synthetic-A", "assessment_id": 100,
            })
            self.assertEqual(response.status_code, 200)
            rows = response.json()["notifications"]
            self.assertEqual(len(rows), 52)
            self.assertTrue(all(
                row["notification_id"].startswith("N5-")
                and not row["is_read"] and row["severity"] == "HIGH"
                for row in rows
            ))

        def test_invalid_limit_rejected(self):
            for limit in (0, 501):
                self.assertEqual(
                    self.client.get("/notifications", params={"limit": limit}).status_code,
                    422,
                )

        def test_wrong_role_is_denied(self):
            self.login(role=3)
            for method, path in (
                ("get", "/notifications"),
                ("get", "/notifications/unread-count"),
                ("patch", "/notifications/N5-2/read"),
                ("patch", "/notifications/N5-2/unread"),
                ("patch", "/notifications/read-all"),
                ("delete", "/notifications/N5-2"),
            ):
                self.assertEqual(getattr(self.client, method)(path).status_code, 403)

    class BroadcasterTests(unittest.IsolatedAsyncioTestCase):
        async def test_publish_only_reaches_intended_user(self):
            broadcaster = UserNotificationBroadcaster()
            own = broadcaster.subscribe(5)
            other = broadcaster.subscribe(6)
            broadcaster.publish(5, {"type": "notification", "notification_id": "SYNTHETIC"})
            await asyncio.sleep(0)
            self.assertEqual(json.loads(own.get_nowait())["notification_id"], "SYNTHETIC")
            self.assertTrue(other.empty())

        async def test_unsubscribe_preserves_other_subscriptions(self):
            broadcaster = UserNotificationBroadcaster()
            removed = broadcaster.subscribe(5)
            kept = broadcaster.subscribe(5)
            broadcaster.unsubscribe(5, removed)
            broadcaster.publish(5, {"type": "notification"})
            await asyncio.sleep(0)
            self.assertTrue(removed.empty())
            self.assertFalse(kept.empty())

    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(NotificationTests),
        unittest.defaultTestLoader.loadTestsFromTestCase(BroadcasterTests),
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
