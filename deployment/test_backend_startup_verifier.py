"""Offline checks for disposable PostgreSQL configuration and failure diagnostics."""
from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import verify_backend_startup as verifier


class VerifierTests(unittest.TestCase):
    def test_cluster_uses_tcp_without_a_system_unix_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "postgresql.conf").write_text("# Existing generated configuration\n")
            verifier.configure_private_cluster(root)
            content = (root / "postgresql.conf").read_text()
            self.assertIn("# Existing generated configuration", content)
            self.assertIn("unix_socket_directories = ''", content)

    def test_failure_logs_survive_and_redact_the_disposable_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "temporary-postgres.log"
            log.write_text("FATAL: synthetic-detail temporary-secret", encoding="utf-8")
            saved = root / "saved"
            with redirect_stderr(io.StringIO()) as output:
                verifier.preserve_logs((("postgres", log),), "temporary-secret", saved)
            log.unlink()
            self.assertIn("synthetic-detail", (saved / "postgres.log").read_text())
            self.assertNotIn("temporary-secret", output.getvalue())
            self.assertIn("[test-secret]", output.getvalue())

    def test_failed_pg_ctl_preserves_actual_server_error_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            (binary / ("initdb.exe" if os.name == "nt" else "initdb")).touch()
            diagnostics = root / "diagnostics"
            args = SimpleNamespace(postgres_bin=binary, diagnostics_dir=diagnostics)
            clusters = []

            def execute(command, **kwargs):
                self.assertNotEqual(kwargs["env"]["DATABASE_URL"], "company-database-must-not-be-used")
                data = Path(command[command.index("-D") + 1])
                if Path(command[0]).name.startswith("initdb"):
                    data.mkdir()
                    (data / "postgresql.conf").touch()
                    clusters.append(data.parent)
                    return subprocess.CompletedProcess(command, 0)
                self.assertIn("unix_socket_directories = ''", (data / "postgresql.conf").read_text())
                log = Path(command[command.index("-l") + 1])
                log.write_text("FATAL: synthetic server permission detail", encoding="utf-8")
                raise subprocess.CalledProcessError(1, command)

            with patch.object(verifier.os, "geteuid", return_value=1000, create=True), patch.object(verifier.argparse.ArgumentParser, "parse_args", return_value=args), patch.object(
                verifier.subprocess, "run", side_effect=execute
            ), patch.dict(os.environ, {"DATABASE_URL": "company-database-must-not-be-used"}), redirect_stderr(
                io.StringIO()
            ), redirect_stdout(io.StringIO()):
                with self.assertRaises(subprocess.CalledProcessError):
                    verifier.main()
            self.assertIn("synthetic server permission detail", (diagnostics / "postgres.log").read_text())
            self.assertTrue(all(not path.exists() for path in clusters))


if __name__ == "__main__":
    unittest.main(verbosity=2)
