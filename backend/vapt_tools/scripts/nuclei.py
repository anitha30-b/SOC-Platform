import json
import shutil
import subprocess
from typing import Any


NUCLEI_EXECUTABLE = "nuclei"


class NucleiError(Exception):
    """Raised when Nuclei cannot be executed successfully."""


def check_nuclei() -> str:
    """
    Return the resolved Nuclei executable path.

    Raises:
        NucleiError: If Nuclei is not installed.
    """
    executable = shutil.which(NUCLEI_EXECUTABLE)

    if not executable:
        raise NucleiError(
            "Nuclei executable was not found on the system."
        )

    return executable


def validate_target(target: str) -> str:
    """
    Validate the initial Nuclei target format.

    The VAPT UI currently supplies HTTP/HTTPS targets.
    Only those schemes are accepted here.
    """
    target = str(target or "").strip()

    if not target:
        raise NucleiError("Nuclei target cannot be empty.")

    if not (
        target.startswith("http://")
        or target.startswith("https://")
    ):
        raise NucleiError(
            "Nuclei integration currently requires an HTTP or HTTPS target."
        )

    return target


def parse_jsonl(output: str) -> list[dict[str, Any]]:
    """
    Parse Nuclei JSONL output safely.

    Invalid/non-JSON lines are ignored so that informational
    output does not break the result parser.
    """
    findings: list[dict[str, Any]] = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(item, dict):
            findings.append(item)

    return findings


def normalize_finding(item: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a raw Nuclei result into a stable SOC/VAPT finding shape.
    """
    info = item.get("info") or {}

    classification = info.get("classification") or {}

    return {
        "template_id": item.get("template-id"),
        "template_path": item.get("template-path"),
        "name": info.get("name"),
        "severity": str(info.get("severity") or "info").upper(),
        "type": item.get("type"),
        "host": item.get("host"),
        "matched_at": item.get("matched-at"),
        "url": item.get("url"),
        "ip": item.get("ip"),
        "port": item.get("port"),
        "protocol": item.get("protocol"),
        "curl_command": item.get("curl-command"),
        "description": info.get("description"),
        "reference": info.get("reference"),
        "tags": info.get("tags"),
        "cwe": classification.get("cwe-id"),
        "cve": classification.get("cve-id"),
        "raw": item,
    }


def run_nuclei(
    target: str,
    *,
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    """
    Execute Nuclei against an authorized HTTP/HTTPS target.

    Machine-readable JSONL output is captured from stdout.
    Interactsh/OAST templates are disabled for the initial integration.
    """
    executable = check_nuclei()
    target = validate_target(target)

    command = [
        executable,
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-no-interactsh",
        "-pt",
        "http",
        "-s",
        "info,low,medium,high,critical",
        "-c",
        "100",
        "-rl",
        "300",
        "-timeout",
        "3",
        "-retries",
        "0",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NucleiError(
            f"Nuclei scan timed out after {timeout_seconds} seconds."
        ) from exc
    except OSError as exc:
        raise NucleiError(
            f"Unable to execute Nuclei: {exc}"
        ) from exc

    findings = [
        normalize_finding(item)
        for item in parse_jsonl(completed.stdout)
    ]

    return {
        "tool": "nuclei",
        "target": target,
        "status": "completed" if completed.returncode == 0 else "completed_with_errors",
        "return_code": completed.returncode,
        "finding_count": len(findings),
        "findings": findings,
        "stderr": completed.stderr.strip(),
        "command": command,
    }
