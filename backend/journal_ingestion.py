import subprocess
from typing import List, Optional, Tuple

from journal_state import load_cursor


def read_new_journal_events(
    cursor: Optional[str] = None,
) -> Tuple[List[str], Optional[str]]:
    """
    Read new SSH journal events after the supplied cursor.

    The ingestion source is explicitly restricted to
    the SSH systemd service so authentication events
    are reliably captured.
    """

    cursor = cursor or load_cursor()

    command = [
        "journalctl",
        "--no-pager",
        "--output",
        "short-iso",
        "--show-cursor",
        "-u",
        "ssh.service",
    ]

    if cursor:
        command.append(
            f"--after-cursor={cursor}"
        )

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=10,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "journalctl failed"
        )

    events = []
    latest_cursor = None

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        if line == "-- No entries --":
            continue

        if line.startswith("-- cursor:"):
            latest_cursor = line.replace(
                "-- cursor:",
                "",
                1,
            ).strip()
            continue

        events.append(line)

    return events, latest_cursor
    