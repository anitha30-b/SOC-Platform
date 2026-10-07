import subprocess


def read_after_cursor(cursor=None):
    command = [
        "sudo",
        "journalctl",
        "--no-pager",
        "--output",
        "short-iso",
        "--show-cursor",
    ]

    if cursor:
        command.insert(
            3,
            f"--after-cursor={cursor}",
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
        )

    lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    latest_cursor = None
    events = []

    for line in lines:
        if line.startswith("-- cursor:"):
            latest_cursor = line.replace(
                "-- cursor:",
                "",
                1,
            ).strip()
        else:
            events.append(line)

    return events, latest_cursor


events, cursor = read_after_cursor()

print("Events:", len(events))
print("Cursor:", cursor)

if events:
    print()
    print("First event:")
    print(events[0])

if cursor:
    print()
    print("Testing resume from cursor...")

    new_events, new_cursor = read_after_cursor(
        cursor
    )

    print("Events after cursor:", len(new_events))
    print("New cursor:", new_cursor)
