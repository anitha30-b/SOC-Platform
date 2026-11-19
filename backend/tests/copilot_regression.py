import ast
import json
import math
import re
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, load_only, sessionmaker
from sqlalchemy.pool import StaticPool

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    role_id = Column(Integer)


class Assessment(Base):
    __tablename__ = "assessments"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    overall_status = Column(String)
    vapt_status = Column(String)
    qa_status = Column(String)
    monitoring_status = Column(String)
    report_status = Column(String)


class SecurityFinding(Base):
    __tablename__ = "security_findings"
    id = Column(Integer, primary_key=True)
    finding_id = Column(String)
    user_id = Column(Integer)
    assessment_id = Column(Integer)
    title = Column(String)
    severity = Column(String)
    cvss_score = Column(Float)
    cve_id = Column(String)
    cwe_id = Column(String)
    owasp_category = Column(String)
    description = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    affected_asset = Column(String)
    affected_url = Column(String)
    affected_endpoint = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class SupportTicket(Base):
    __tablename__ = "support_tickets"
    id = Column(Integer, primary_key=True)
    ticket_id = Column(String)
    user_id = Column(Integer)
    assessment_id = Column(Integer)
    category = Column(String)
    subject = Column(String(200))
    description = Column(Text)
    priority = Column(String)
    status = Column(String)
    assignment_channel = Column(String)
    assignment_status = Column(String)
    admin_notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class SupportTicketMessage(Base):
    __tablename__ = "support_ticket_messages"
    id = Column(Integer, primary_key=True)
    ticket_id = Column(Integer)
    sender_type = Column(String)
    sender_name = Column(String)
    message = Column(Text)


class VAPTReportRun(Base):
    __tablename__ = "vapt_report_runs"
    id = Column(Integer, primary_key=True)
    report_run_id = Column(String)
    user_id = Column(Integer)
    assessment_id = Column(Integer)
    status = Column(String)
    report_type = Column(String)
    canonical_data = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Sessions = sessionmaker(bind=engine)


def get_db():
    with Sessions() as db:
        yield db


def get_current_user(x_test_user: str | None = Header(default=None)):
    # Test identities only; production authentication is not replaced.
    if x_test_user not in {"1", "2", "3"}:
        raise HTTPException(401, "Authentication required")
    return type("Identity", (), {
        "id": int(x_test_user),
        "username": f"user{x_test_user}",
        "role_id": 3 if x_test_user == "3" else 1,
    })()


# Execute actual Copilot schemas, helpers and decorated routes.
# Replace external imports with the isolated dependencies above.
source_path = Path(__file__).resolve().parents[1] / "copilot.py"
tree = ast.parse(source_path.read_text())
tree.body = [
    node for node in tree.body
    if not isinstance(node, (ast.Import, ast.ImportFrom))
]
namespace = dict(globals())
exec(compile(tree, str(source_path), "exec"), namespace)

app = FastAPI()
app.include_router(namespace["router"])


class CopilotTests(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        self.client = TestClient(app)
        with Sessions() as db:
            db.add_all([
                Assessment(id=10, user_id=1),
                Assessment(id=20, user_id=2),
                SecurityFinding(
                    finding_id="F-1", user_id=1, assessment_id=10,
                    title="Owner finding", severity="HIGH",
                ),
                SecurityFinding(
                    finding_id="F-2", user_id=2, assessment_id=20,
                    title="Peer private finding", severity="CRITICAL",
                ),
                SupportTicket(
                    ticket_id="PEER-TICKET", user_id=2,
                    assessment_id=20, category="Other",
                    subject="Peer private ticket", description="Private",
                    status="OPEN",
                ),
                VAPTReportRun(
                    report_run_id="OWNER-REPORT", user_id=1,
                    assessment_id=10, status="COMPLETED",
                    report_type="COMPLETE",
                    canonical_data=json.dumps({"findings": [
                        {"severity": "LOW", "cvss_score": None},
                        {"severity": "MEDIUM", "cvss_score": 0},
                    ]}),
                ),
                VAPTReportRun(
                    report_run_id="PEER-REPORT", user_id=2,
                    assessment_id=20, status="COMPLETED",
                    report_type="COMPLETE",
                    canonical_data='{"findings":[]}',
                ),
            ])
            db.commit()

    def tearDown(self):
        self.client.close()

    def post(self, route, payload, user="1"):
        headers = {"X-Test-User": user} if user else {}
        return self.client.post("/copilot/" + route, json=payload, headers=headers)

    def chat(self, message, user="1"):
        return self.post("chat", {"message": message}, user)

    def test_authentication_required(self):
        for route, payload in (
            ("chat", {"message": "Help"}),
            ("support-ticket", {"finding_id": "F-1"}),
        ):
            self.assertEqual(self.post(route, payload, None).status_code, 401)

    def test_wrong_role_denied(self):
        self.assertEqual(self.chat("Help", "3").status_code, 403)
        self.assertEqual(
            self.post("support-ticket", {"finding_id": "F-1"}, "3").status_code,
            403,
        )

    def test_context_only_counts_owner_records(self):
        response = self.chat("How many findings do I have?")
        self.assertEqual(response.status_code, 200, response.text)
        context = response.json()["context"]
        self.assertEqual(context["total_findings"], 1)
        self.assertEqual(context["severity_counts"]["CRITICAL"], 0)
        self.assertEqual(context["total_assessments"], 1)
        self.assertEqual(context["total_support_tickets"], 0)
        self.assertEqual(context["total_reports"], 1)

    def test_report_uses_saved_snapshot_and_preserves_zero(self):
        answer = self.chat("Summarize my latest report.").json()["answer"]
        self.assertIn("OWNER-REPORT", answer)
        self.assertNotIn("PEER-REPORT", answer)
        self.assertIn("2 finding(s)", answer)
        self.assertIn("0 High", answer)
        self.assertIn("1 Medium", answer)
        self.assertIn("Average CVSS: 0.00", answer)

    def test_missing_scores_are_unavailable(self):
        with Sessions() as db:
            report = db.query(VAPTReportRun).filter_by(user_id=1).one()
            report.canonical_data = '{"findings":[{"severity":"LOW"}]}'
            db.commit()
        answer = self.chat("Summarize my latest report").json()["answer"]
        self.assertIn("CVSS scores are not available", answer)

    def test_invalid_snapshot_is_handled(self):
        with Sessions() as db:
            db.query(VAPTReportRun).filter_by(user_id=1).one().canonical_data = "invalid"
            db.commit()
        answer = self.chat("Summarize my latest report").json()["answer"]
        self.assertIn("stored report content is unavailable", answer)

    def test_unfinished_report_does_not_claim_completed_snapshot(self):
        with Sessions() as db:
            db.query(VAPTReportRun).filter_by(user_id=1).one().status = "RUNNING"
            db.commit()
        answer = self.chat("Summarize my latest report").json()["answer"]
        self.assertIn("Status: RUNNING", answer)
        self.assertNotIn("saved snapshot contains", answer)

    def test_foreign_finding_cannot_create_ticket(self):
        response = self.post("support-ticket", {"finding_id": "F-2"})
        self.assertEqual(response.status_code, 404)
        with Sessions() as db:
            self.assertEqual(db.query(SupportTicket).filter_by(user_id=1).count(), 0)

    def test_ticket_saves_initial_conversation_and_reuses_active_ticket(self):
        first = self.post("support-ticket", {"finding_id": "F-1"})
        self.assertEqual(first.status_code, 200, first.text)
        second = self.post("support-ticket", {"finding_id": "F-1"})
        self.assertEqual(first.json()["ticket_id"], second.json()["ticket_id"])
        with Sessions() as db:
            ticket = db.query(SupportTicket).filter_by(user_id=1).one()
            message = db.query(SupportTicketMessage).filter_by(ticket_id=ticket.id).one()
            self.assertEqual(message.sender_name, "user1")
            self.assertEqual(message.message, ticket.description)

    def test_finding_prefix_does_not_match_another_ticket(self):
        with Sessions() as db:
            db.add(SupportTicket(
                ticket_id="PREFIX-TICKET", user_id=1,
                assessment_id=10, category="SECURITY_FINDING",
                subject="Different finding",
                description="Finding ID: F-10", status="OPEN",
            ))
            db.commit()
        response = self.post("support-ticket", {"finding_id": "F-1"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotEqual(response.json()["ticket_id"], "PREFIX-TICKET")

    def test_long_title_and_unrecognized_priority(self):
        with Sessions() as db:
            finding = db.query(SecurityFinding).filter_by(user_id=1).one()
            finding.title = "X" * 400
            finding.severity = "NONE"
            db.commit()
        response = self.post("support-ticket", {"finding_id": "F-1"})
        self.assertEqual(response.status_code, 200, response.text)
        with Sessions() as db:
            ticket = db.query(SupportTicket).filter_by(user_id=1).one()
            self.assertLessEqual(len(ticket.subject), 200)
            self.assertEqual(ticket.priority, "MEDIUM")

    def test_blank_chat_rejected(self):
        self.assertEqual(self.chat("   ").status_code, 400)

    def test_cve_definition(self):
        answer = self.chat("What does CVE mean?").json()["answer"]
        self.assertIn("Common Vulnerabilities and Exposures", answer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
