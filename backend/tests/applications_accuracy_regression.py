"""Applications API regression tests using isolated SQLite.
Authentication identity is overridden; PostgreSQL is not accessed.
"""
import ast
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import asset_registration_regression as support
import models
import rbac

from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func
from sqlalchemy.orm import Session

Factory = support.Factory
fixture = support.fixture

for model in (models.Assessment, models.SecurityFinding):
    model.__table__.create(support.engine, checkfirst=True)

namespace = {
    "__name__": "isolated_applications",
    "router": APIRouter(prefix="/client"),
    "Depends": Depends,
    "Session": Session,
    "get_db": support.get_db,
    "require_role": rbac.require_role,
    "User": models.User,
    "Assessment": models.Assessment,
    "SecurityFinding": models.SecurityFinding,
    "func": func,
    "urlparse": urlparse,
}
tree = ast.parse((ROOT / "client_portal.py").read_text())
nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef)
    and node.name == "client_applications"
]
if len(nodes) != 1:
    raise RuntimeError("Applications handler not found")
exec(
    compile(ast.Module(body=nodes, type_ignores=[]), "client_portal.py", "exec"),
    namespace,
)
app = FastAPI()
app.include_router(namespace["router"])


class ApplicationsTests(unittest.TestCase):
    def setUp(self):
        with Factory() as db:
            db.query(models.SecurityFinding).delete()
            db.query(models.Assessment).delete()
            for model in reversed(support.TABLE_MODELS):
                db.query(model).delete()

            for cid in (100, 200):
                db.add(fixture(models.Client, id=cid))
            for uid, cid in [
                (1, None), (2, None), (10, 100),
                (11, 100), (20, 200), (99, None),
            ]:
                db.add(fixture(
                    models.User, id=uid, client_id=cid, role_id=1,
                ))

            for aid, uid, target in [
                (1, 1, "https://app.example/login?view=1"),
                (2, 1, "http://192.0.2.10:8080/"),
                (9, 2, "https://foreign.example/"),
                (10, 10, "https://client.example/"),
                (11, 11, "https://peer.example/"),
                (20, 20, "https://other-client.example/"),
                (21, 1, "https://app.example/login?view=1"),
            ]:
                self.add_assessment(db, aid, uid, target)

            invalid = [
                "bare.example",
                "192.0.2.50",
                "code://project",
                "ftp://files.example/",
                "https://app.example:bad/",
                "https://[broken/",
                "https://app.example:65536/",
                "https://app.example:0/",
                "https:///missing-host",
                "https://user:secret@app.example/",
                "https://bad host.example/",
                "https://app.example/\tpath",
                "",
            ]
            for aid, target in enumerate(invalid, 100):
                self.add_assessment(db, aid, 1, target)

            for fid, uid, aid in [
                (1, 1, 1), (2, 1, 1),
                (3, 2, 1),  # Foreign-owned finding must not inflate count.
                (4, 2, 9), (5, 10, 10), (6, 11, 11),
            ]:
                db.add(fixture(
                    models.SecurityFinding,
                    id=fid, user_id=uid, assessment_id=aid,
                ))
            db.commit()

        self.select_user(1)
        app.dependency_overrides[rbac.get_current_user] = lambda: self.current
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()

    def add_assessment(self, db, aid, uid, target):
        db.add(fixture(
            models.Assessment,
            id=aid,
            user_id=uid,
            target=target,
            vapt_findings_count=77,
            updated_at=datetime(2026, 1, 1) + timedelta(minutes=aid),
        ))

    def select_user(self, uid):
        with Factory() as db:
            self.current = db.get(models.User, uid)
            db.expunge(self.current)

    def result(self):
        response = self.client.get("/client/applications")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(
            body["application_count"], len(body["applications"])
        )
        return body

    def test_only_explicit_valid_web_targets_are_listed(self):
        body = self.result()
        self.assertEqual(body["scope"], "personal")
        self.assertEqual(
            {row["assessment_id"] for row in body["applications"]},
            {1, 2, 21},
        )

    def test_personal_scope_excludes_other_users(self):
        self.assertEqual(
            {row["user_id"] for row in self.result()["applications"]},
            {1},
        )

    def test_same_client_sharing_is_preserved(self):
        for uid in (10, 11):
            with self.subTest(user=uid):
                self.select_user(uid)
                body = self.result()
                self.assertEqual(body["scope"], "client")
                self.assertEqual(
                    {row["user_id"] for row in body["applications"]},
                    {10, 11},
                )

    def test_other_client_is_isolated(self):
        self.select_user(20)
        rows = self.result()["applications"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["user_id"], 20)

    def test_empty_account_returns_zero(self):
        self.select_user(99)
        self.assertEqual(self.result()["applications"], [])

    def test_finding_count_uses_owned_records(self):
        row = next(
            row for row in self.result()["applications"]
            if row["assessment_id"] == 1
        )
        self.assertEqual(row["finding_count"], 2)
        self.assertEqual(row["vapt_findings_count"], 77)

    def test_duplicate_urls_remain_distinct_assessment_rows(self):
        body = self.result()
        self.assertEqual(body["application_count"], 3)
        self.assertEqual(
            sum(
                row["target"] == "https://app.example/login?view=1"
                for row in body["applications"]
            ),
            2,
        )

    def test_uppercase_scheme_and_encoded_path(self):
        with Factory() as db:
            self.add_assessment(
                db, 40, 1, " HTTPS://APP.EXAMPLE:8443/a%20b "
            )
            db.commit()
        row = next(
            row for row in self.result()["applications"]
            if row["assessment_id"] == 40
        )
        self.assertEqual(row["scheme"], "https")
        self.assertEqual(row["hostname"], "app.example")
        self.assertEqual(row["port"], 8443)
        self.assertEqual(row["path"], "/a%20b")

    def test_ipv6_web_url(self):
        with Factory() as db:
            self.add_assessment(
                db, 41, 1, "http://[2001:db8::1]:8080/status"
            )
            db.commit()
        row = next(
            row for row in self.result()["applications"]
            if row["assessment_id"] == 41
        )
        self.assertEqual(row["hostname"], "2001:db8::1")
        self.assertEqual(row["port"], 8080)
        self.assertEqual(row["path"], "/status")

    def test_listing_does_not_modify_stored_targets(self):
        with Factory() as db:
            before = db.query(
                models.Assessment.id, models.Assessment.target
            ).order_by(models.Assessment.id).all()
        self.result()
        with Factory() as db:
            after = db.query(
                models.Assessment.id, models.Assessment.target
            ).order_by(models.Assessment.id).all()
        self.assertEqual(before, after)

    def test_wrong_role_is_denied(self):
        self.current.role_id = 3
        response = self.client.get("/client/applications")
        self.assertEqual(response.status_code, 403, response.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
