import time

from postgres_event_listener import (
    postgres_event_listener,
)


postgres_event_listener.start()

print(
    "[TEST] PostgreSQL event listener started.",
    flush=True,
)

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print(
        "\n[TEST] Stopping listener.",
        flush=True,
    )

    postgres_event_listener.stop()