"""Complete backend startup against a new, private local PostgreSQL cluster.

Use a newly installed virtual environment. This program never loads a company
.env or connects to an existing database. Requires initdb/pg_ctl on this host.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-bin", type=Path, help="Directory containing initdb and pg_ctl")
    args = parser.parse_args()
    suffix = ".exe" if os.name == "nt" else ""
    binary = args.postgres_bin.resolve() if args.postgres_bin else None
    if binary is None:
        executable = shutil.which("initdb")
        if executable:
            binary = Path(executable).parent
        else:
            candidates = sorted(Path("/usr/lib/postgresql").glob("*/bin/initdb"))
            if candidates:
                binary = candidates[-1].parent
    if binary is None or not (binary / ("initdb" + suffix)).is_file():
        raise SystemExit("PostgreSQL test binaries not found. Install PostgreSQL tools, then use --postgres-bin. No existing database was used.")
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SystemExit("Run this disposable PostgreSQL check as a normal service/deployment user, not root.")

    # The verifier supplies every connection value. No inherited company URL,
    # secrets or startup flags are used by either the tests or the API process.
    env = {key: value for key, value in os.environ.items() if not key.startswith("SOC_")}
    env["PYTHON_DOTENV_DISABLED"] = "1"
    env["JWT_SECRET_KEY"] = secrets.token_hex(32)
    env["ZAP_URL"] = "http://127.0.0.1:1"
    env["ZAP_API_KEY"] = ""
    for key in ("DATABASE_URL", "PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGSERVICEFILE"):
        env.pop(key, None)
    for key in (
        "SOC_INITIALIZE_DATABASE_ON_STARTUP", "SOC_ENABLE_FIREWALL_OPERATIONS",
        "SOC_ENABLE_SIEM_INGESTION", "SOC_ENABLE_SNORT_COLLECTOR",
        "SOC_ENABLE_HOST_COLLECTORS", "SOC_ENABLE_SERVER_MONITOR", "SOC_ENABLE_POSTGRES_LISTENERS",
    ):
        env[key] = "false"
    with tempfile.TemporaryDirectory(prefix="soc-pg-startup-") as directory:
        temp = Path(directory)
        data = temp / "database"
        password_file = temp / "password"
        password = secrets.token_hex(24)
        password_file.write_text(password + "\n", encoding="utf-8")
        password_file.chmod(0o600)
        pg_port, api_port = available_port(), available_port()
        pg_started = False
        api = None
        pg_log = temp / "postgres.log"
        api_log = temp / "api.log"
        url = f"postgresql://soc_startup:{password}@127.0.0.1:{pg_port}/postgres"
        env["DATABASE_URL"] = url
        env["SOC_STARTUP_TEST_DATABASE_URL"] = url
        try:
            print("Creating disposable PostgreSQL cluster...", flush=True)
            subprocess.run([
                str(binary / ("initdb" + suffix)), "-D", str(data), "-U", "soc_startup",
                "--no-sync", *(["-c", "max_connections=10", "-c", "shared_buffers=16MB", "-c", "dynamic_shared_memory_type=mmap"] if os.name == "nt" else []),
                "--encoding=UTF8", "--locale=C", "--auth-local=scram-sha-256",
                "--auth-host=scram-sha-256", "--pwfile=" + str(password_file),
            ], env=env, check=True, stdout=None, stderr=subprocess.STDOUT, timeout=180)
            subprocess.run([
                str(binary / ("pg_ctl" + suffix)), "-D", str(data), "-l", str(pg_log),
                "-o", f"-h 127.0.0.1 -p {pg_port} -F", "-w", "-t", "30", "start",
            ], env=env, check=True, stdout=None, stderr=subprocess.STDOUT, timeout=45)
            pg_started = True
            print("Disposable PostgreSQL cluster ready; running startup regressions...", flush=True)
            for name in ("startup_controls_regression.py", "backend_startup_regression.py"):
                subprocess.run([sys.executable, str(ROOT / "backend/tests" / name)], env=env, cwd=ROOT, check=True, timeout=180)
            env.pop("SOC_STARTUP_TEST_DATABASE_URL")
            with api_log.open("w", encoding="utf-8") as log:
                api = subprocess.Popen([
                    sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
                    "--port", str(api_port), "--workers", "1",
                ], env=env, cwd=ROOT / "backend", stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    if api.poll() is not None:
                        raise RuntimeError("Uvicorn exited before becoming ready")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{api_port}/health", timeout=2) as response:
                            if json.load(response).get("status") == "healthy":
                                break
                    except (urllib.error.URLError, TimeoutError):
                        time.sleep(0.25)
                else:
                    raise RuntimeError("Uvicorn startup timed out")
                for route in ("/", "/health", "/openapi.json"):
                    with urllib.request.urlopen(f"http://127.0.0.1:{api_port}{route}", timeout=10) as response:
                        assert response.status == 200
                print("POSTGRESQL_SCHEMA_AND_FULL_ASGI_LIFECYCLE: PASS", flush=True)
                print("UVICORN_REAL_HTTP_STARTUP: PASS", flush=True)
                print("FIREWALL_COLLECTORS_AND_MONITORING_DISABLED: PASS", flush=True)
        except Exception:
            if api_log.is_file():
                print(api_log.read_text(encoding="utf-8", errors="replace").replace(password, "[test-secret]"), file=sys.stderr)
            raise
        finally:
            if api is not None and api.poll() is None:
                api.terminate()
                try:
                    api.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    api.kill()
                    api.wait(timeout=5)
            if pg_started or (data / "postmaster.pid").is_file():
                subprocess.run([
                    str(binary / ("pg_ctl" + suffix)), "-D", str(data), "-m", "fast", "-w", "-t", "30", "stop",
                ], env=env, check=True, stdout=None, stderr=subprocess.STDOUT, timeout=40)
    print("Temporary API/database stopped and removed. No company database, scan or system service was used.")


if __name__ == "__main__":
    main()
