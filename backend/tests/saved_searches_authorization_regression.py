"""Saved-search HTTP tests using the actual router and model."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import unittest
    from datetime import datetime, timedelta
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, Integer
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    import database

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    database.engine.dispose()
    database.engine = engine
    assert engine.url.get_backend_name() == "sqlite"

    import models
    import rbac
    import saved_searches_router as searches

    # SQLite requires INTEGER for automatic primary-key allocation.
    # This changes only this isolated process's test metadata.
    models.SavedSearch.__table__.c.id.type = Integer()
    models.SavedSearch.__table__.create(engine)

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(searches.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[searches.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    class SavedSearchTests(unittest.TestCase):
        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, client_id=client, role_id=role,
                username=f"user-{uid}",
            )

        def setUp(self):
            with engine.begin() as connection:
                connection.execute(models.SavedSearch.__table__.delete())

            now = datetime(2026, 1, 1)
            with Session() as db:
                for uid, client in (
                    (5, None), (6, None), (10, 100),
                    (11, 100), (20, 200),
                ):
                    db.add(models.SavedSearch(
                        id=uid, owner_user_id=uid, client_id=client,
                        name=f"Search {uid}",
                        search_text=f"owner-{uid}",
                        severity="all", source="all", event_type="all",
                        created_at=now,
                        updated_at=now + timedelta(seconds=uid),
                    ))
                # A former tenant search must not become personal merely
                # because its creator now has no client.
                db.add(models.SavedSearch(
                    id=50, owner_user_id=5, client_id=200,
                    name="Tenant-scoped former search",
                    search_text="", severity="all",
                    source="all", event_type="all",
                    created_at=now, updated_at=now,
                ))
                db.commit()

            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def payload(self, **changes):
            body = {
                "name": "Test saved search",
                "search_text": "127.0.0.1",
                "severity": "HIGH",
                "source": "all",
                "event_type": "network_detection",
            }
            body.update(changes)
            return body

        def list_rows(self):
            response = self.client.get("/saved-searches")
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        def test_personal_list_excludes_other_and_tenant_records(self):
            self.assertEqual(
                [row["id"] for row in self.list_rows()], [5]
            )

        def test_same_client_can_list_shared_searches(self):
            self.login(10, 100)
            self.assertEqual(
                {row["id"] for row in self.list_rows()}, {10, 11}
            )
            self.login(11, 100)
            self.assertEqual(
                {row["id"] for row in self.list_rows()}, {10, 11}
            )

        def test_other_client_only_lists_its_tenant(self):
            self.login(20, 200)
            self.assertEqual(
                {row["id"] for row in self.list_rows()}, {20, 50}
            )

        def test_create_personal_search_uses_authenticated_owner(self):
            response = self.client.post(
                "/saved-searches", json=self.payload(
                    owner_user_id=6, client_id=200,
                )
            )
            self.assertEqual(response.status_code, 201, response.text)
            with Session() as db:
                item = db.get(models.SavedSearch, response.json()["id"])
                self.assertEqual(item.owner_user_id, 5)
                self.assertIsNone(item.client_id)
                self.assertEqual(item.event_type, "network_detection")

        def test_create_client_search_is_shared_only_with_that_client(self):
            self.login(10, 100)
            response = self.client.post(
                "/saved-searches", json=self.payload()
            )
            self.assertEqual(response.status_code, 201, response.text)
            search_id = response.json()["id"]

            self.login(11, 100)
            self.assertIn(search_id, {row["id"] for row in self.list_rows()})
            self.login(20, 200)
            self.assertNotIn(search_id, {row["id"] for row in self.list_rows()})

        def test_owner_can_update_search(self):
            response = self.client.put(
                "/saved-searches/5",
                json=self.payload(name="Updated"),
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["name"], "Updated")
            self.assertEqual(response.json()["severity"], "HIGH")
            self.assertEqual(response.json()["event_type"], "network_detection")

        def test_same_client_can_update_shared_search(self):
            self.login(10, 100)
            response = self.client.put(
                "/saved-searches/11",
                json=self.payload(name="Shared update"),
            )
            self.assertEqual(response.status_code, 200, response.text)
            with Session() as db:
                item = db.get(models.SavedSearch, 11)
                self.assertEqual(item.owner_user_id, 11)
                self.assertEqual(item.client_id, 100)

        def test_foreign_update_and_delete_are_denied(self):
            for search_id in (6, 10, 11, 20, 50):
                with self.subTest(search_id=search_id):
                    response = self.client.put(
                        f"/saved-searches/{search_id}",
                        json=self.payload(),
                    )
                    self.assertEqual(response.status_code, 404, response.text)
                    response = self.client.delete(
                        f"/saved-searches/{search_id}"
                    )
                    self.assertEqual(response.status_code, 404, response.text)
            with Session() as db:
                self.assertEqual(db.query(models.SavedSearch).count(), 6)

        def test_cross_client_update_and_delete_are_denied(self):
            self.login(10, 100)
            self.assertEqual(
                self.client.put(
                    "/saved-searches/20", json=self.payload()
                ).status_code,
                404,
            )
            self.assertEqual(
                self.client.delete("/saved-searches/20").status_code,
                404,
            )

        def test_owner_can_delete_search(self):
            response = self.client.delete("/saved-searches/5")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()["deleted"])
            self.assertEqual(self.list_rows(), [])
            self.assertEqual(
                self.client.delete("/saved-searches/5").status_code, 404
            )

        def test_same_client_can_delete_shared_search(self):
            self.login(10, 100)
            response = self.client.delete("/saved-searches/11")
            self.assertEqual(response.status_code, 200, response.text)
            self.login(11, 100)
            self.assertNotIn(11, {row["id"] for row in self.list_rows()})

        def test_blank_fields_and_invalid_severity_are_rejected(self):
            for changes in (
                {"name": "   "},
                {"source": "   "},
                {"event_type": "   "},
                {"severity": "UNSUPPORTED"},
            ):
                with self.subTest(changes=changes):
                    for method, path in (
                        ("post", "/saved-searches"),
                        ("put", "/saved-searches/5"),
                    ):
                        response = getattr(self.client, method)(
                            path, json=self.payload(**changes)
                        )
                        self.assertEqual(response.status_code, 422, response.text)

        def test_search_length_matches_event_api(self):
            accepted = self.client.post(
                "/saved-searches",
                json=self.payload(search_text="x" * 200),
            )
            self.assertEqual(accepted.status_code, 201, accepted.text)
            rejected = self.client.post(
                "/saved-searches",
                json=self.payload(search_text="x" * 201),
            )
            self.assertEqual(rejected.status_code, 422, rejected.text)

        def test_name_and_filter_whitespace_is_trimmed(self):
            response = self.client.post(
                "/saved-searches",
                json=self.payload(
                    name=" Trimmed name ",
                    search_text=" query ",
                    source=" Collector-A ",
                    event_type=" network_detection ",
                ),
            )
            self.assertEqual(response.status_code, 201, response.text)
            body = response.json()
            self.assertEqual(body["name"], "Trimmed name")
            self.assertEqual(body["search_text"], "query")
            self.assertEqual(body["source"], "Collector-A")
            self.assertEqual(body["event_type"], "network_detection")

        def test_wrong_role_is_denied(self):
            self.login(role=3)
            self.assertEqual(
                self.client.get("/saved-searches").status_code, 403
            )
            self.assertEqual(
                self.client.post(
                    "/saved-searches", json=self.payload()
                ).status_code,
                403,
            )
            self.assertEqual(
                self.client.put(
                    "/saved-searches/5", json=self.payload()
                ).status_code,
                403,
            )
            self.assertEqual(
                self.client.delete("/saved-searches/5").status_code, 403
            )

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SavedSearchTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
