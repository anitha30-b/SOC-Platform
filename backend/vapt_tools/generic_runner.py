import json
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable


class GenericToolError(Exception):
    """Raised when a registry tool cannot be executed safely."""


def resolve_executable(executable: str) -> str:
    path = shutil.which(executable)

    if not path:
        raise GenericToolError(
            f"Executable '{executable}' was not found on the system."
        )

    return path


def build_command(
    *,
    tool_id: str,
    executable: str,
    target: str,
) -> list[str]:
    """
    Build an allowlisted command for registry tools.

    The target is always passed as a subprocess argument and is never
    interpreted through a shell.
    """
    resolved = resolve_executable(executable)
    target = str(target).strip()

    if tool_id == "ping":
        return [
            resolved,
            "-c",
            "4",
            target,
        ]

    if tool_id == "dig":
        return [
            resolved,
            target,
        ]

    if tool_id == "nslookup":
        return [
            resolved,
            target,
        ]

    if tool_id == "whois":
        return [
            resolved,
            target,
        ]

    if tool_id == "dns-recon":
        return [
            resolved,
            "-d",
            target,
            "-a",
        ]

    if tool_id == "subdomain-discovery":
        return [
            resolved,
            "-d",
            target,
            "-t",
            "brt",
            "-D",
            "/usr/share/dnsrecon/dnsrecon/data/subdomains-top1mil-5000.txt",
        ]

    if tool_id == "masscan":
        masscan_target = target
        try:
            if not target.replace(".", "").isdigit():
                masscan_target = socket.gethostbyname(target)
        except socket.gaierror as exc:
            raise GenericToolError(
                f"Unable to resolve Masscan target '{target}': {exc}"
            ) from exc

        return [
            resolved,
            masscan_target,
            "-p80,443",
            "--rate",
            "1000",
        ]

    if tool_id == "hping3":
        return [
            resolved,
            "-S",
            "-p",
            "80",
            "-c",
            "3",
            target,
        ]

    if tool_id in {
        "hydra",
        "john",
        "metasploit",
        "snort",
        "tshark",
        "wireshark",
        "owasp-zap",
    }:
        raise GenericToolError(
            f"{tool_id} requires a dedicated workflow or additional input."
        )

    raise GenericToolError(
        f"No safe generic adapter is configured for '{tool_id}'."
    )


def run_generic_tool(
    *,
    tool_id: str,
    tool_name: str,
    executable: str,
    target: str,
    execution_type: str,
    timeout_seconds: int = 300,
    progress_callback: Callable[[int, str, str], None] | None = None,
) -> dict[str, Any]:
    """
    Execute an allowlisted registry tool.

    This runner intentionally does not invoke a shell and does not
    accept arbitrary command-line arguments from the frontend.
    """
    if not executable:
        raise GenericToolError(
            f"{tool_name} does not have a command-line executable."
        )

    if not target or not str(target).strip():
        raise GenericToolError("A target is required.")

    if execution_type not in {
        "scanner",
        "credential_audit",
        "validator",
        "sensor",
        "analyzer",
    }:
        raise GenericToolError(
            f"Execution type '{execution_type}' requires a dedicated workflow."
        )

    command = build_command(
        tool_id=tool_id,
        executable=executable,
        target=target,
    )

    json_output_path = None

    if tool_id == "subdomain-discovery":
        json_file = tempfile.NamedTemporaryFile(
            prefix="dnsrecon-subdomain-",
            suffix=".json",
            delete=False,
        )
        json_output_path = json_file.name
        json_file.close()
        command.extend(["-j", json_output_path])

    if progress_callback:
        progress_callback(
            35,
            "Executing",
            f"Running {tool_name}.",
        )

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        timed_out = False

        try:
            stdout, stderr = process.communicate(
                timeout=max(1, int(timeout_seconds))
            )
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate()

            timeout_message = (
                f"{tool_name} timed out after "
                f"{max(1, int(timeout_seconds))} seconds."
            )
            stderr = (
                f"{stderr or ''}{timeout_message}\n"
            )

        return_code = process.returncode
        stdout_lines = [stdout or ""]
        stderr_lines = [stderr or ""]

    except OSError as exc:
        raise GenericToolError(
            f"Unable to execute {tool_name}: {exc}"
        ) from exc

    if progress_callback:
        progress_callback(
            80,
            "Processing",
            f"Processing {tool_name} output.",
        )

    result = {
        "tool": tool_id,
        "tool_name": tool_name,
        "execution_type": execution_type,
        "target": target,
        "status": (
            "timeout"
            if timed_out
            else (
                "completed"
                if return_code == 0
                else "completed_with_errors"
            )
        ),
        "return_code": return_code,
        "stdout": "".join(stdout_lines),
        "stderr": "".join(stderr_lines),
        "command": command,
    }

    if json_output_path:
        try:
            with open(json_output_path, "r", encoding="utf-8") as json_file:
                result["json_output"] = json.load(json_file)
        except (OSError, json.JSONDecodeError) as exc:
            result["json_output_error"] = str(exc)
            if result["status"] == "completed":
                result["status"] = "completed_with_errors"
        finally:
            try:
                Path(json_output_path).unlink(missing_ok=True)
            except OSError:
                pass

    return result
