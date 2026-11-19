"""Isolated tests of actual support functions and schemas; no production DB."""
import ast
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock

from fastapi import HTTPException
from pydantic import BaseModel, Field
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]


def load_definitions(path, names, namespace):
    tree = ast.parse(path.read_text())
    nodes = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
    ]
    if {node.name for node in nodes} != set(names):
        raise AssertionError("Expected source definitions are missing")
    for node in nodes:
        node.decorator_list = []
    module = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(path), "exec"), namespace)


class SupportTests(unittest.TestCase):
    def setUp(self):
        self.ns = {
            "BaseModel": BaseModel, "Field": Field, "Optional": Optional,
            "datetime": datetime,
        }
        load_definitions(
            ROOT / "schemas.py",
            [
                "SupportTicketCreate", "SupportTicketMessageCreate",
                "SupportTicketMessageResponse", "SupportTicketResponse",
                "SupportTicketDetailResponse", "UserSupportTicketResponse",
                "UserSupportTicketDetailResponse",
            ],
            self.ns,
        )
        self.db = MagicMock()
        self.user = SimpleNamespace(id=5, role_id=1, username="owner")
        self.tickets = []

        def make_ticket(**values):
            ticket = SimpleNamespace(id=101, **values)
            self.tickets.append(ticket)
            return ticket

        self.ns.update({
            "HTTPException": HTTPException,
            "Depends": lambda dependency: None,
            "Session": object, "User": object,
            "get_db": lambda: None, "get_current_user": lambda: None,
            "SupportTicket": make_ticket,
            "SupportTicketMessage": lambda **values: SimpleNamespace(**values),
            "Assessment": SimpleNamespace(),
            "generate_ticket_id": lambda db: "SOC-TEST",
        })
        load_definitions(
            ROOT / "support.py",
            ["require_user", "create_ticket", "add_user_message"],
            self.ns,
        )
        self.ns["get_user_ticket"] = MagicMock()

    def request(self, **changes):
        values = dict(category="Other", subject="Help", description="Details")
        values.update(changes)
        return self.ns["SupportTicketCreate"](**values)

    def create(self, request):
        return self.ns["create_ticket"](request, self.db, self.user)

    def test_user_schemas_exclude_internal_notes(self):
        for name in ("UserSupportTicketResponse", "UserSupportTicketDetailResponse"):
            self.assertNotIn("admin_notes", self.ns[name].model_fields)

    def test_admin_schemas_retain_internal_notes(self):
        for name in ("SupportTicketResponse", "SupportTicketDetailResponse"):
            self.assertIn("admin_notes", self.ns[name].model_fields)

    def test_blank_create_fields_are_rejected(self):
        for field in ("category", "subject", "description"):
            with self.subTest(field=field):
                with self.assertRaises(HTTPException) as result:
                    self.create(self.request(**{field: "   "}))
                self.assertEqual(result.exception.status_code, 422)
        self.db.add.assert_not_called()

    def test_nonpositive_assessment_is_rejected(self):
        for value in (0, -1):
            with self.assertRaises(HTTPException) as result:
                self.create(self.request(assessment_id=value))
            self.assertEqual(result.exception.status_code, 422)
        self.db.query.assert_not_called()

    def test_create_commits_once_and_uses_authenticated_owner(self):
        ticket = self.create(self.request(subject=" Help ", description=" Details "))
        self.assertEqual(ticket.user_id, self.user.id)
        self.assertEqual(ticket.subject, "Help")
        self.db.flush.assert_called_once()
        self.db.commit.assert_called_once()
        self.assertEqual(self.db.add.call_count, 2)
        first_message = self.db.add.call_args_list[1].args[0]
        self.assertEqual(first_message.ticket_id, ticket.id)
        self.assertEqual(first_message.message, "Details")
        self.assertEqual(first_message.sender_name, self.user.username)

    def test_message_failure_rolls_back_without_commit(self):
        self.db.add.side_effect = [None, RuntimeError("simulated write failure")]
        with self.assertRaises(RuntimeError):
            self.create(self.request())
        self.db.rollback.assert_called_once()
        self.db.commit.assert_not_called()

    def test_blank_reply_is_rejected(self):
        request = self.ns["SupportTicketMessageCreate"](message="   ")
        with self.assertRaises(HTTPException) as result:
            self.ns["add_user_message"](101, request, self.db, self.user)
        self.assertEqual(result.exception.status_code, 422)
        self.db.add.assert_not_called()

    def test_resolved_and_closed_tickets_reject_replies(self):
        for status in ("RESOLVED", "CLOSED"):
            self.ns["get_user_ticket"].return_value = SimpleNamespace(
                id=101, status=status
            )
            with self.assertRaises(HTTPException) as result:
                self.ns["add_user_message"](
                    101, self.ns["SupportTicketMessageCreate"](message="Hello"),
                    self.db, self.user,
                )
            self.assertEqual(result.exception.status_code, 400)
        self.db.add.assert_not_called()

    def test_waiting_ticket_reply_returns_to_in_progress(self):
        ticket = SimpleNamespace(id=101, status="WAITING_FOR_USER")
        self.ns["get_user_ticket"].return_value = ticket
        self.ns["add_user_message"](
            101, self.ns["SupportTicketMessageCreate"](message=" Update "),
            self.db, self.user,
        )
        self.assertEqual(ticket.status, "IN_PROGRESS")
        self.assertEqual(self.db.add.call_args.args[0].message, "Update")

    def test_wrong_role_is_denied(self):
        self.user.role_id = 3
        with self.assertRaises(HTTPException) as result:
            self.create(self.request())
        self.assertEqual(result.exception.status_code, 403)
        self.db.add.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
