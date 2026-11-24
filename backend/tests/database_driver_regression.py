"""PostgreSQL URL/driver checks without a database connection or credentials."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import create_engine
from psycopg2.extensions import parse_dsn
from database_urls import psycopg2_url, sqlalchemy_url


class DatabaseDriverTests(unittest.TestCase):
    def test_plain_and_explicit_postgres_urls_use_the_installed_driver(self):
        for scheme in ("postgresql", "postgres", "postgresql+psycopg2"):
            engine = create_engine(sqlalchemy_url(scheme + "://test:test@127.0.0.1:1/disposable"))
            try:
                self.assertEqual(engine.dialect.driver, "psycopg2")
                self.assertEqual(engine.dialect.dbapi.__name__, "psycopg2")
            finally:
                engine.dispose()

    def test_encoded_password_and_connection_options_are_preserved(self):
        value = "postgresql+psycopg2://user:p%40ss%2F%25@127.0.0.1:1/test?sslmode=require&application_name=soc-test"
        orm = sqlalchemy_url(value)
        native = parse_dsn(psycopg2_url(value))
        self.assertEqual(orm.password, "p@ss/%")
        self.assertEqual(native["password"], orm.password)
        self.assertEqual(native["host"], orm.host)
        self.assertEqual(native["port"], str(orm.port))
        self.assertEqual(native["dbname"], orm.database)
        self.assertEqual(native["sslmode"], "require")
        self.assertEqual(native["application_name"], "soc-test")

    def test_libpq_conversion_does_not_replace_text_inside_credentials(self):
        value = "postgresql+psycopg2://user:postgresql%2Bpsycopg2%3A%2F%2F@host/test"
        self.assertEqual(psycopg2_url(value), "postgresql://" + value.split("://", 1)[1])

    def test_sqlite_tests_keep_their_original_dialect(self):
        for value in ("sqlite://", "sqlite:///isolated.sqlite3"):
            self.assertEqual(sqlalchemy_url(value).drivername, "sqlite")
            self.assertEqual(psycopg2_url(value), value)

    def test_explicit_alternative_driver_is_not_silently_changed(self):
        self.assertEqual(sqlalchemy_url("postgresql+psycopg://user@host/test").drivername, "postgresql+psycopg")

    def test_actual_database_module_imports_without_connecting(self):
        source = '''from unittest.mock import patch
import psycopg2
with patch.object(psycopg2, "connect", side_effect=AssertionError("Import opened a database connection")):
    import database
    assert database.engine.dialect.driver == "psycopg2"
    assert database.engine.dialect.dbapi.__name__ == "psycopg2"
    assert database.DATABASE_URL.startswith("postgresql://")
    database.engine.dispose()
'''
        for scheme in ("postgresql", "postgresql+psycopg2"):
            env = os.environ.copy()
            env.update(DATABASE_URL=scheme + "://test:test@127.0.0.1:1/disposable", PYTHON_DOTENV_DISABLED="1")
            result = subprocess.run([sys.executable, "-c", source], cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
