import json
from pathlib import Path
from typing import Optional


STATE_DIR = (
    Path(__file__).resolve().parent
    / "runtime_state"
)

CURSOR_FILE = STATE_DIR / "journal.cursor"


def load_cursor() -> Optional[str]:
    """
    Load the last processed journal cursor.
    """

    if not CURSOR_FILE.exists():
        return None

    try:
        data = json.loads(
            CURSOR_FILE.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        return None

    cursor = data.get("cursor")

    if not cursor:
        return None

    return str(cursor)


def save_cursor(cursor: str) -> None:
    """
    Persist the latest processed journal cursor.
    """

    if not cursor:
        return

    STATE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_file = CURSOR_FILE.with_suffix(
        ".tmp"
    )

    temporary_file.write_text(
        json.dumps(
            {
                "cursor": cursor,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    temporary_file.replace(CURSOR_FILE)
