"""Support HTTP ownership tests using actual routes and models."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import unittest
    from datetime import datetime
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text
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
    import support

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(support.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[support.get_db] = test_db
    app.dependency_overrides[support.get_current_user] = lambda: identity["user"]

    # Only these tables are needed. SQLite FK enforcement is off in this
    # isolated fixture; production foreign-key constraints are not tested here.
    for model in (
        models.Assessment,
        models.SupportTicket,
        models.SupportTicketMessage,
    ):
        model.__table__.create(engine, checkfirst=True)

    class SupportTests(unittest.TestCase):
        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, role_id=role, client_id=client,
                username=f"user-{uid}",
            )

        def setUp(self):
            with engine.begin() as connection:
                connection.execute(text("DELETE FROM support_ticket_messages"))
                connection.execute(text("DELETE FROM support_tickets"))
                connection.execute(text("DELETE FROM assessments"))

                # Insert only identifiers and required values. Derive any
                # additional required assessment columns from their SQL types.
                table = models.Assessment.__table__
                for uid in (5, 6, 10, 11, 20):
                    values = {"id": uid * 100, "user_id": uid}
                    for column in table.columns:
                        if (
                            column.name in values
                            or column.nullable
                            or column.default is not None
                            or column.server_default is not None
                            or column.primary_key
                        ):
                            continue
                        try:
                            kind = column.type.python_type
                        except (AttributeError, NotImplementedError):
                            raise AssertionError(
                                f"Add an explicit test fixture for {column.name}"
                            )
                        defaults = {
                            str: "synthetic-test",
                            int: 0,
                            float: 0.0,
                            bool: False,
                            datetime: datetime(2026, 1, 1),
                        }
                        if kind not in defaults:
                            raise AssertionError(
                                f"Add an explicit test fixture for {column.name}"
                            )
                        values[column.name] = defaults[kind]
                    connection.execute(table.insert().values(**values))

            with Session() as db:
                for uid in (5, 6, 10, 11, 20):
                    ticket = models.SupportTicket(
                        id=uid,
                        ticket_id=f"TEST-{uid}",
                        user_id=uid,
                        assessment_id=uid * 100,
                        category="Other",
                        subject=f"Owner {uid} ticket",
                        description="Synthetic test description",
                        priority="LOW",
                        status="OPEN",
                        assignment_status="NOT_ASSIGNED",
                        admin_notes=f"PRIVATE-NOTE-{uid}",
                        resolution=None,
                        final_admin_message=None,
                    )
                    db.add(ticket)
                    db.add(models.SupportTicketMessage(
                        ticket_id=uid,
                        sender_type="USER",
                        sender_name=f"user-{uid}",
                        message=f"Owner {uid} initial message",
                    ))
                db.commit()
            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def payload(self, **changes):
            body = {
                "category": "Other",
                "subject": "Ownership test",
                "description": "Synthetic support request",
                "priority": "LOW",
            }
            body.update(changes)
            return body

        def test_list_is_personal(self):
            response = self.client.get("/support/tickets")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(
                [row["ticket_id"] for row in response.json()],
                ["TEST-5"],
            )
            self.assertNotIn("admin_notes", response.json()[0])

        def test_same_client_does_not_share_tickets(self):
            self.login(10, 100)
            response = self.client.get("/support/tickets")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(
                [row["ticket_id"] for row in response.json()],
                ["TEST-10"],
            )

        def test_owner_can_read_details_without_internal_notes(self):
            response = self.client.get("/support/tickets/5")
            self.assertEqual(response.status_code, 200, response.text)
            body = response.json()
            self.assertNotIn("admin_notes", body)
            self.assertNotIn("PRIVATE-NOTE", response.text)
            self.assertEqual(len(body["messages"]), 1)
            self.assertEqual(
                body["messages"][0]["message"], "Owner 5 initial message"
            )

        def test_other_owner_cannot_read_or_reply(self):
            self.assertEqual(
                self.client.get("/support/tickets/6").status_code, 404
            )
            self.assertEqual(
                self.client.post(
                    "/support/tickets/6/messages",
                    json={"message": "Unauthorized reply"},
                ).status_code,
                404,
            )
            with Session() as db:
                count = db.query(models.SupportTicketMessage).filter_by(
                    ticket_id=6
                ).count()
                self.assertEqual(count, 1)

        def test_same_client_cannot_read_or_reply_to_peer(self):
            self.login(10, 100)
            self.assertEqual(
                self.client.get("/support/tickets/11").status_code, 404
            )
            self.assertEqual(
                self.client.post(
                    "/support/tickets/11/messages",
                    json={"message": "Unauthorized peer reply"},
                ).status_code,
                404,
            )

        def test_foreign_assessment_cannot_be_attached(self):
            response = self.client.post(
                "/support/tickets",
                json=self.payload(assessment_id=600),
            )
            self.assertEqual(response.status_code, 404, response.text)
            with Session() as db:
                self.assertEqual(
                    db.query(models.SupportTicket).filter_by(user_id=5).count(),
                    1,
                )

        def test_same_client_assessment_cannot_be_attached(self):
            self.login(10, 100)
            response = self.client.post(
                "/support/tickets",
                json=self.payload(assessment_id=1100),
            )
            self.assertEqual(response.status_code, 404, response.text)

        def test_create_with_owned_assessment_and_initial_message(self):
            response = self.client.post(
                "/support/tickets",
                json=self.payload(assessment_id=500),
            )
            self.assertEqual(response.status_code, 200, response.text)
            ticket = response.json()
            self.assertEqual(ticket["user_id"], 5)
            self.assertEqual(ticket["assessment_id"], 500)
            self.assertNotIn("admin_notes", ticket)
            detail = self.client.get(
                f"/support/tickets/{ticket['id']}"
            ).json()
            self.assertEqual(len(detail["messages"]), 1)
            self.assertEqual(
                detail["messages"][0]["message"],
                "Synthetic support request",
            )

        def test_create_without_assessment(self):
            response = self.client.post(
                "/support/tickets", json=self.payload()
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIsNone(response.json()["assessment_id"])

        def test_owner_reply_is_saved_once(self):
            response = self.client.post(
                "/support/tickets/5/messages",
                json={"message": " Follow-up "},
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["message"], "Follow-up")
            detail = self.client.get("/support/tickets/5").json()
            self.assertEqual(len(detail["messages"]), 2)
            self.assertEqual(
                sum(m["message"] == "Follow-up" for m in detail["messages"]),
                1,
            )

        def test_waiting_for_user_reply_changes_status(self):
            with Session() as db:
                db.query(models.SupportTicket).filter_by(id=5).one().status = (
                    "WAITING_FOR_USER"
                )
                db.commit()
            response = self.client.post(
                "/support/tickets/5/messages",
                json={"message": "Requested information"},
            )
            self.assertEqual(response.status_code, 200, response.text)
            detail = self.client.get("/support/tickets/5").json()
            self.assertEqual(detail["status"], "IN_PROGRESS")

        def test_closed_states_reject_replies(self):
            for status in ("RESOLVED", "CLOSED"):
                with self.subTest(status=status):
                    with Session() as db:
                        db.query(models.SupportTicket).filter_by(id=5).one().status = status
                        db.commit()
                    response = self.client.post(
                        "/support/tickets/5/messages",
                        json={"message": "Cannot reply"},
                    )
                    self.assertEqual(response.status_code, 400, response.text)

        def test_whitespace_input_rejected(self):
            for field in ("category", "subject", "description"):
                response = self.client.post(
                    "/support/tickets",
                    json=self.payload(**{field: "   "}),
                )
                self.assertEqual(response.status_code, 422, response.text)
            response = self.client.post(
                "/support/tickets/5/messages", json={"message": "   "}
            )
            self.assertEqual(response.status_code, 422, response.text)

        def test_wrong_role_cannot_use_user_endpoints(self):
            self.login(role=3)
            responses = [
                self.client.get("/support/tickets"),
                self.client.get("/support/tickets/5"),
                self.client.post("/support/tickets", json=self.payload()),
                self.client.post(
                    "/support/tickets/5/messages", json={"message": "Denied"}
                ),
            ]
            for response in responses:
                self.assertEqual(response.status_code, 403, response.text)

        def test_user_cannot_use_admin_endpoints(self):
            self.assertEqual(
                self.client.get("/support/admin/tickets").status_code, 403
            )
            self.assertEqual(
                self.client.get("/support/admin/tickets/5").status_code, 403
            )
            self.assertEqual(
                self.client.put(
                    "/support/admin/tickets/5",
                    json={"status": "IN_PROGRESS"},
                ).status_code,
                403,
            )
            self.assertEqual(
                self.client.post(
                    "/support/admin/tickets/5/messages",
                    json={"message": "Denied"},
                ).status_code,
                403,
            )

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SupportTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
