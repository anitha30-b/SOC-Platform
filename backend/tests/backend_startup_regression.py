"""Import and exercise the complete application against a disposable database.

Defaults to a new temporary SQLite file. The clean-startup runner supplies an
isolated PostgreSQL cluster through SOC_STARTUP_TEST_DATABASE_URL on Linux.
Never reads the developer/company DATABASE_URL or logs in as a real account.
"""
import asyncio
import atexit
from contextlib import ExitStack
import inspect as python_inspect
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
temporary = tempfile.TemporaryDirectory(prefix="soc-startup-db-")
os.environ["DATABASE_URL"] = os.environ.get("SOC_STARTUP_TEST_DATABASE_URL") or (
    "sqlite:///" + str(Path(temporary.name) / "startup.sqlite3").replace("\\", "/")
)
os.environ["JWT_SECRET_KEY"] = "disposable-startup-test-secret-never-for-deployment"
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
from startup_settings import STARTUP_VARIABLES, StartupSettings
for name in STARTUP_VARIABLES.values():
    os.environ[name] = "false"

from database import Base, engine
atexit.register(engine.dispose)
from sqlalchemy import inspect

# A successful import must not rely on an already-created developer database.
assert not inspect(engine).get_table_names(), "Startup test requires a new empty database"
with patch.object(engine, "begin", side_effect=AssertionError("Import attempted database DDL")), patch(
    "subprocess.Popen", side_effect=AssertionError("Import launched a process")
), patch("threading.Thread.start", side_effect=AssertionError("Import launched a listener")):
    import main

import client_portal
from models import AssetGroupMember
from schema_initialization import initialize_database, register_models, verify_database_schema
from fastapi.testclient import TestClient


class BackendStartupTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        engine.dispose()
        temporary.cleanup()

    def test_01_member_annotation_resolves_to_the_owned_model(self):
        self.assertIs(python_inspect.signature(client_portal._asset_group_member_details).parameters["member"].annotation, AssetGroupMember)

    def test_02_empty_schema_has_an_actionable_error(self):
        with self.assertRaisesRegex(RuntimeError, "initialize_database.py"):
            verify_database_schema()

    def test_03_bootstrap_registers_and_creates_all_tables_idempotently(self):
        metadata = register_models()
        initialize_database()
        initialize_database()
        verify_database_schema()
        self.assertEqual(set(metadata.tables), set(inspect(engine).get_table_names()))
        for name in ("roles", "users", "asset_groups", "asset_group_members", "soc_assets", "soc_asset_groups", "soc_asset_group_members", "soc_server_monitor_results", "soc_security_agents", "incidents"):
            self.assertIn(name, metadata.tables)
        with engine.begin() as connection:
            connection.execute(Base.metadata.tables["roles"].insert().values(id=991, name="Startup sentinel"))
        initialize_database()
        with engine.connect() as connection:
            self.assertEqual(connection.execute(Base.metadata.tables["roles"].select()).scalar(), 991)

    def test_04_complete_application_starts_and_serves_routes_with_host_services_disabled(self):
        with ExitStack() as stack:
            for target in (
                "main.postgres_event_listener.start", "main.client_security_event_listener.start",
                "main.start_realtime_journal_listener", "main.monitor_servers_once",
                "main.siem_ingestion_loop", "main.snort_journal_listener_loop",
                "siem_response._run_iptables", "subprocess.Popen",
            ):
                stack.enter_context(patch(target, side_effect=AssertionError("Disabled startup service ran: " + target)))
            stack.enter_context(patch.object(main, "STARTUP_SETTINGS", StartupSettings()))
            with TestClient(main.app) as client:
                self.assertEqual(client.get("/").status_code, 200)
                self.assertEqual(client.get("/health").json()["status"], "healthy")
                schema = client.get("/openapi.json")
                self.assertEqual(schema.status_code, 200)
                self.assertGreater(len(schema.json()["paths"]), 100)
                self.assertIn(client.get("/admin/users").status_code, (401, 403))
        self.assertIsNone(main._siem_ingestion_task)
        self.assertIsNone(main._snort_journal_task)
        self.assertIsNone(main._server_monitor_task)

    def test_05_enabled_database_listeners_are_started_and_stopped(self):
        with patch.object(main, "STARTUP_SETTINGS", StartupSettings(postgres_listeners=True)), patch.object(
            main.postgres_event_listener, "start"
        ) as admin_start, patch.object(main.postgres_event_listener, "stop") as admin_stop, patch.object(
            main.client_security_event_listener, "start"
        ) as user_start, patch.object(main.client_security_event_listener, "stop") as user_stop, patch.object(
            main, "start_realtime_journal_listener"
        ) as host_start:
            main.start_postgres_event_listener()
            main.stop_postgres_event_listener()
            for item in (admin_start, admin_stop, user_start, user_stop):
                item.assert_called_once()
            host_start.assert_not_called()

    def test_06_enabled_async_services_start_once_and_cancel_cleanly(self):
        async def exercise():
            entered = set()
            async def loop(name):
                entered.add(name)
                await asyncio.Event().wait()
            with patch.object(main, "STARTUP_SETTINGS", StartupSettings(siem_ingestion=True, snort_collector=True, server_monitor=True)), patch.object(
                main, "siem_ingestion_loop", new=lambda: loop("siem")
            ), patch.object(main, "snort_journal_listener_loop", new=lambda: loop("snort")), patch.object(
                main, "server_monitor_loop", new=lambda: loop("monitor")
            ):
                try:
                    for _ in range(2):
                        await main.start_siem_ingestion()
                        await main.start_snort_journal_listener()
                        await main.start_server_monitor()
                    await asyncio.sleep(0)
                    self.assertEqual(entered, {"siem", "snort", "monitor"})
                finally:
                    await main.stop_siem_ingestion()
                    await main.stop_snort_journal_listener()
                    await main.stop_server_monitor()
        asyncio.run(exercise())

    def test_07_failed_startup_cleans_up_already_started_tasks(self):
        async def exercise():
            async def pending():
                await asyncio.Event().wait()
            with patch.object(main, "STARTUP_SETTINGS", StartupSettings(siem_ingestion=True)), patch.object(
                main, "prepare_database"
            ), patch.object(main, "siem_ingestion_loop", new=pending), patch.object(
                main, "start_postgres_event_listener", side_effect=RuntimeError("synthetic startup failure")
            ):
                with self.assertRaisesRegex(RuntimeError, "synthetic startup failure"):
                    async with main.application_lifespan(main.app):
                        self.fail("Application became ready after startup failed")
                self.assertIsNone(main._siem_ingestion_task)
        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main(verbosity=2)
