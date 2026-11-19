"""Actual asset listing handlers/models with isolated fixtures.

Reuses the isolated database setup from asset_registration_regression.
Production authentication and PostgreSQL foreign keys are not tested here.
"""
import ast
import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import asset_registration_regression as setup
import models
import rbac

from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func
from sqlalchemy.orm import Session

SPECS = [
    ("/servers", "client_servers", models.ServerAsset,
     "servers", "server_count"),
    ("/endpoints", "client_endpoints", models.EndpointAsset,
     "endpoints", "endpoint_count"),
    ("/network-devices", "client_network_devices", models.NetworkDeviceAsset,
     "network_devices", "network_device_count"),
    ("/databases", "client_databases", models.DatabaseAsset,
     "databases", "database_count"),
]

models.ServerAsset.__table__.create(setup.engine, checkfirst=True)

namespace = {
    "__name__": "isolated_asset_listing",
    "router": APIRouter(prefix="/client"),
    "Depends": Depends,
    "Session": Session,
    "get_db": setup.get_db,
    "require_role": rbac.require_role,
    "User": models.User,
    "ServerAsset": models.ServerAsset,
    "EndpointAsset": models.EndpointAsset,
    "NetworkDeviceAsset": models.NetworkDeviceAsset,
    "DatabaseAsset": models.DatabaseAsset,
    "json": json,
    "func": func,
}
wanted = {spec[1] for spec in SPECS}
tree = ast.parse((ROOT / "client_portal.py").read_text())
nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name in wanted
]
if {node.name for node in nodes} != wanted:
    raise RuntimeError("Expected asset listing handlers not found")
exec(
    compile(ast.Module(body=nodes, type_ignores=[]), "client_portal.py", "exec"),
    namespace,
)

app = FastAPI()
app.include_router(namespace["router"])

class AssetListingTests(unittest.TestCase):
    def setUp(self):
        with setup.Factory() as db:
            db.query(models.ServerAsset).delete()
            for model in reversed(setup.TABLE_MODELS):
                db.query(model).delete()

            for cid in (100, 200):
                db.add(setup.fixture(models.Client, id=cid))

            for uid, cid in [
                (1, None), (2, None),
                (10, 100), (11, 100), (20, 200), (99, None),
            ]:
                db.add(setup.fixture(
                    models.User, id=uid, client_id=cid, role_id=1
                ))

            for _, _, model, _, _ in SPECS:
                for uid, number

Migration 017 is now committed, with a readable backup archive created first.

Next, verify that the **Servers, Endpoints, Network Devices, and Databases list APIs** return the correct records and counts for personal and client scopes. These tests use an isolated database and the actual list handlers; they do not change PostgreSQL.

Run:

```bash
cd /home/anitha/SOC-Platform

cat > backend/tests/asset_list_scope_regression.py <<'PY'
"""Actual asset-list handlers and models against isolated SQLite.

Authentication identity is overridden; production JWT validation and
PostgreSQL foreign-key behavior are outside this suite.
"""
import ast
import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Reuse the isolated engine and real-model fixture helper.
import asset_registration_regression as support
import models
import rbac

from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

Factory = support.Factory
engine = support.engine
fixture = support.fixture

models.ServerAsset.__table__.create(engine, checkfirst=True)

SPECS = [
    ("/servers", "client_servers", models.ServerAsset,
     "servers", "server_count"),
    ("/endpoints", "client_endpoints", models.EndpointAsset,
     "endpoints", "endpoint_count"),
    ("/network-devices", "client_network_devices",
     models.NetworkDeviceAsset, "network_devices", "network_device_count"),
    ("/databases", "client_databases", models.DatabaseAsset,
     "databases", "database_count"),
]

namespace = {
    "__name__": "isolated_asset_lists",
    "router": APIRouter(prefix="/client"),
    "Depends": Depends,
    "Session": Session,
    "get_db": support.get_db,
    "require_role": rbac.require_role,
    "User": models.User,
    "ServerAsset": models.ServerAsset,
    "EndpointAsset": models.EndpointAsset,
    "NetworkDeviceAsset": models.NetworkDeviceAsset,
    "DatabaseAsset": models.DatabaseAsset,
    "json": json,
}
wanted = {spec[1] for spec in SPECS}
tree = ast.parse((ROOT / "client_portal.py").read_text())
nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name in wanted
]
if {node.name for node in nodes} != wanted:
    raise RuntimeError("Required asset-list handlers not found")

exec(
    compile(ast.Module(body=nodes, type_ignores=[]), "client_portal.py", "exec"),
    namespace,
)
app = FastAPI()
app.include_router(namespace["router"])

class AssetListTests(unittest.TestCase):
    def setUp(self):
        self.old = datetime(2026, 1, 1)
        with Factory() as db:
            db.query(models.ServerAsset).delete()
            for model in reversed(support.TABLE_MODELS):
                db.query(model).delete()

            for client_id in (100, 200):
                db.add(fixture(models.Client, id=client_id))
            for uid, client_id in [
                (1, None), (2, None), (10, 100),
                (11, 100), (20, 200), (99, None),
            ]:
                db.add(fixture(
                    models.User, id=uid,
                    client_id=client_id, role_id=1,
                ))

            for _, _, model, _, _ in SPECS:
                for asset_id, owner in [
                    (1, 1), (2, 1), (3, 2),
                    (4, 10), (5, 11), (6, 20),
                ]:
                    values = {
                        "id": asset_id,
                        "user_id": owner,
                        "hostname": f"owner-{owner}-asset-{asset_id}",
                        "last_seen": self.old + timedelta(minutes=asset_id),
                    }
                    if model is models.ServerAsset:
                        values.update(
                            assessment_id=asset_id,
                            discovery_run_id=asset_id,
                            target=f"host-{asset_id}.example",
                            host_status="up",
                            open_port_count=2,
                            services_data='[{"port": 443}]',
                        )
                    else:
                        values["status"] = "ONLINE"
                        identifier = {
                            models.EndpointAsset: "endpoint_id",
                            models.NetworkDeviceAsset: "device_id",
                            models.DatabaseAsset: "database_id",
                        }[model]
                        values[identifier] = f"asset-{asset_id}"
                    db.add(fixture(model, **values))
            db.commit()

        self.select_user(1)
        app.dependency_overrides[rbac.get_current_user] = lambda: self.current
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()

    def select_user(self, uid):
        with Factory() as db:
            self.current = db.get(models.User, uid)
            db.expunge(self.current)

    def result(self, spec):
        response = self.client.get("/client" + spec[0])
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body[spec[4]], len(body[spec[3]]))
        return body, body[spec[3]]

    def test_personal_lists_and_counts_exclude_other_owners(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                body, rows = self.result(spec)
                self.assertEqual(body["scope"], "personal")
                self.assertEqual(len(rows), 2)
                self.assertEqual({row["user_id"] for row in rows}, {1})

    def test_same_client_sharing_is_preserved(self):
        self.select_user(10)
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                body, rows = self.result(spec)
                self.assertEqual(body["scope"], "client")
                self.assertEqual(len(rows), 2)
                self.assertEqual({row["user_id"] for row in rows}, {10, 11})

    def test_other_client_sees_only_its_records(self):
        self.select_user(20)
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                _, rows = self.result(spec)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["user_id"], 20)

    def test_empty_account_returns_zero(self):
        self.select_user(99)
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                _, rows = self.result(spec)
                self.assertEqual(rows, [])

    def test_latest_observations_are_returned_first(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                _, rows = self.result(spec)
                self.assertEqual([row["id"] for row in rows], [2, 1])

    def test_read_does_not_refresh_old_observations_or_status(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                self.result(spec)
                with Factory() as db:
                    row = db.get(spec[2], 1)
                    self.assertEqual(
                        row.last_seen, self.old + timedelta(minutes=1)
                    )
                    status = (
                        row.host_status if spec[2] is models.ServerAsset
                        else row.status
                    )
                    self.assertEqual(
                        status,
                        "up" if spec[2] is models.ServerAsset else "ONLINE",
                    )

    def test_missing_observation_timestamp_is_not_invented(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                with Factory() as db:
                    db.get(spec[2], 1).last_seen = None
                    db.commit()
                _, rows = self.result(spec)
                row = next(row for row in rows if row["id"] == 1)
                self.assertIsNone(row["last_seen"])

    def test_wrong_role_is_denied(self):
        self.current.role_id = 3
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                response = self.client.get("/client" + spec[0])
                self.assertEqual(response.status_code, 403, response.text)

    def test_malformed_server_service_json_does_not_break_list(self):
        with Factory() as db:
            db.get(models.ServerAsset, 1).services_data = "not-json"
            db.commit()
        _, rows = self.result(SPECS[0])
        row = next(row for row in rows if row["id"] == 1)
        self.assertIsNone(row["services"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
