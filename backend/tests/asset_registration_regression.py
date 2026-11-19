"""Isolated tests of actual registration schemas, handlers, and asset models.

Does not import the production application or connect to PostgreSQL.
API-key hashing is replaced with a test-only identity function.
SQLite foreign-key and PostgreSQL migration behavior are not certified here.
"""
import ast
import os
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATABASE_URL"] = "sqlite://"

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.testclient import TestClient
from fastapi import FastAPI
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean, DateTime, Integer, Numeric, String, Text, create_engine,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
import models

SPECS = [
    (
        "/endpoints/register",
        models.EndpointAsset,
        "endpoint_id",
        "ClientEndpointRegistrationRequest",
        "register_endpoint",
    ),
    (
        "/network-devices/register",
        models.NetworkDeviceAsset,
        "device_id",
        "ClientNetworkDeviceRegistrationRequest",
        "register_network_device",
    ),
    (
        "/databases/register",
        models.DatabaseAsset,
        "database_id",
        "ClientDatabaseRegistrationRequest",
        "register_database",
    ),
]

engine = create_engine(
    "sqlite://",
    poolclass=StaticPool,
    connect_args={"check_same_thread": False},
)
Factory = sessionmaker(bind=engine)

TABLE_MODELS = [
    models.Client, models.User, models.TelemetrySource,
    models.EndpointAsset, models.NetworkDeviceAsset, models.DatabaseAsset,
]
for model in TABLE_MODELS:
    model.__table__.create(engine)

def get_db():
    with Factory() as db:
        yield db

namespace = {
    "__name__": "isolated_asset_registration",
    "APIRouter": APIRouter,
    "Depends": Depends,
    "Header": Header,
    "HTTPException": HTTPException,
    "BaseModel": BaseModel,
    "Field": Field,
    "Session": Session,
    "datetime": datetime,
    "IntegrityError": IntegrityError,
    "get_db": get_db,
    "_hash_token": lambda token: token,
    "router": APIRouter(prefix="/client"),
    "User": models.User,
    "TelemetrySource": models.TelemetrySource,
    "EndpointAsset": models.EndpointAsset,
    "NetworkDeviceAsset": models.NetworkDeviceAsset,
    "DatabaseAsset": models.DatabaseAsset,
}
wanted = {item[3] for item in SPECS} | {item[4] for item in SPECS}
tree = ast.parse((ROOT / "client_portal.py").read_text())
nodes = [
    node for node in tree.body
    if isinstance(node, (ast.ClassDef, ast.FunctionDef))
    and node.name in wanted
]
if {node.name for node in nodes} != wanted:
    raise RuntimeError("Required registration schemas or handlers not found")
exec(
    compile(ast.Module(body=nodes, type_ignores=[]), "client_portal.py", "exec"),
    namespace,
)
app = FastAPI()
app.include_router(namespace["router"])

def fixture(model, **values):
    """Fill unrelated required columns; ownership fields stay explicit."""
    for column in model.__table__.columns:
        if (
            column.name in values or column.nullable
            or column.default is not None
            or column.server_default is not None
        ):
            continue
        if isinstance(column.type, Boolean):
            values[column.name] = True
        elif isinstance(column.type, DateTime):
            values[column.name] = datetime(2026, 1, 1)
        elif isinstance(column.type, (Integer, Numeric)):
            values[column.name] = 1
        elif isinstance(column.type, (String, Text)):
            values[column.name] = f"fixture-{values.get('id', 1)}-{column.name}"
        else:
            raise RuntimeError(
                f"Provide fixture value for {model.__name__}.{column.name}"
            )
    return model(**values)

class RegistrationTests(unittest.TestCase):
    def setUp(self):
        with Factory() as db:
            for model in reversed(TABLE_MODELS):
                db.query(model).delete()
            db.add(fixture(models.Client, id=100))
            for uid, client_id in [(1, None), (2, None), (10, 100), (11, 100)]:
                db.add(fixture(models.User, id=uid, client_id=client_id))
            for sid, owner, client, enabled in [
                (1, 1, None, True),
                (2, 2, None, True),
                (3, 1, None, True),
                (4, 1, None, False),
                (5, None, None, True),
                (6, None, 100, True),
            ]:
                db.add(fixture(
                    models.TelemetrySource,
                    id=sid,
                    owner_user_id=owner,
                    client_id=client,
                    enabled=enabled,
                    token_hash=f"key-{sid}",
                    created_by=1,
                    last_seen_at=None,
                ))
            db.commit()
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()

    def post(self, spec, key="key-1", identifier="shared-id", **extra):
        path, _, field, _, _ = spec
        headers = {} if key is None else {"X-API-Key": key}
        return self.client.post(
            "/client" + path,
            headers=headers,
            json={field: identifier, **extra},
        )

    def test_same_identifier_isolated_between_owners_and_sources(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                self.assertEqual(self.post(spec).status_code, 200)
                self.assertEqual(self.post(spec, key="key-2").status_code, 200)
                with Factory() as db:
                    rows = db.query(spec[1]).all()
                    self.assertEqual(len(rows), 2)
                    self.assertEqual({row.user_id for row in rows}, {1, 2})
                    self.assertEqual(
                        {row.telemetry_source_id for row in rows}, {1, 2}
                    )

    def test_repeat_registration_updates_same_row_and_timestamp(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                self.assertEqual(self.post(spec).status_code, 200)
                with Factory() as db:
                    asset = db.query(spec[1]).one()
                    original_id = asset.id
                    old = datetime.utcnow() - timedelta(days=20)
                    asset.last_seen = old
                    db.get(models.TelemetrySource, 1).last_seen_at = old
                    db.commit()
                response = self.post(spec, hostname="updated-host")
                self.assertEqual(response.status_code, 200, response.text)
                with Factory() as db:
                    asset = db.query(spec[1]).one()
                    self.assertEqual(asset.id, original_id)
                    self.assertEqual(asset.hostname, "updated-host")
                    self.assertGreater(asset.last_seen, old)
                    self.assertGreater(
                        db.get(models.TelemetrySource, 1).last_seen_at, old
                    )

    def test_same_owner_other_source_cannot_take_over(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                self.assertEqual(self.post(spec).status_code, 200)
                response = self.post(spec, key="key-3", hostname="takeover")
                self.assertEqual(response.status_code, 409, response.text)
                with Factory() as db:
                    asset = db.query(spec[1]).one()
                    self.assertEqual(asset.telemetry_source_id, 1)
                    self.assertNotEqual(asset.hostname, "takeover")

    def test_changed_source_owner_cannot_take_over(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                identifier = "changed-owner-" + spec[2]
                self.assertEqual(
                    self.post(spec, identifier=identifier).status_code, 200
                )
                with Factory() as db:
                    db.get(models.TelemetrySource, 1).owner_user_id = 2
                    db.commit()
                response = self.post(spec, identifier=identifier)
                self.assertEqual(response.status_code, 409, response.text)
                with Factory() as db:
                    self.assertEqual(db.query(spec[1]).one().user_id, 1)
                    db.get(models.TelemetrySource, 1).owner_user_id = 1
                    db.commit()

    def test_invalid_disabled_and_unowned_keys_create_nothing(self):
        for spec in SPECS:
            for key, expected in [
                ("invalid", 401), ("key-4", 401), ("key-5", 403),
            ]:
                with self.subTest(route=spec[0], key=key):
                    response = self.post(spec, key=key)
                    self.assertEqual(response.status_code, expected, response.text)
            with Factory() as db:
                self.assertEqual(db.query(spec[1]).count(), 0)

    def test_payload_cannot_choose_owner_or_source(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                response = self.post(
                    spec, user_id=2, telemetry_source_id=2
                )
                self.assertEqual(response.status_code, 422, response.text)
                with Factory() as db:
                    self.assertEqual(db.query(spec[1]).count(), 0)

    def test_client_source_resolves_owner_from_database(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                response = self.post(spec, key="key-6")
                self.assertEqual(response.status_code, 200, response.text)
                with Factory() as db:
                    asset = db.query(spec[1]).one()
                    self.assertEqual(asset.user_id, 10)
                    self.assertEqual(asset.telemetry_source_id, 6)

    def test_database_constraints_block_duplicate_owner_or_source(self):
        for spec in SPECS:
            with self.subTest(route=spec[0]):
                self.assertEqual(self.post(spec).status_code, 200)
                for owner, source in [(1, 3), (2, 1)]:
                    with Factory() as db:
                        db.add(spec[1](**{
                            "user_id": owner,
                            "telemetry_source_id": source,
                            spec[2]: "shared-id",
                            "status": "UNKNOWN",
                        }))
                        with self.assertRaises(IntegrityError):
                            db.commit()
                        db.rollback()
                        self.assertEqual(db.query(spec[1]).count(), 1)


    def test_whitespace_fields_are_rejected(self):
        for spec in SPECS:
            fields = [spec[2], "status"]
            if spec[2] == "device_id":
                fields.append("device_type")
            elif spec[2] == "database_id":
                fields.append("database_type")

            for field in fields:
                with self.subTest(route=spec[0], field=field):
                    payload = {spec[2]: "valid-id", field: "   "}
                    response = self.client.post(
                        "/client" + spec[0],
                        headers={"X-API-Key": "key-1"},
                        json=payload,
                    )
                    self.assertEqual(
                        response.status_code, 422, response.text
                    )
                    with Factory() as db:
                        self.assertEqual(db.query(spec[1]).count(), 0)
                        self.assertIsNone(
                            db.get(models.TelemetrySource, 1).last_seen_at
                        )

if __name__ == "__main__":
    unittest.main(verbosity=2)
