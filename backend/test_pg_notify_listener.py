import psycopg2
import select

from database import DATABASE_URL


conn = psycopg2.connect(DATABASE_URL)
conn.set_isolation_level(
    psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT
)

cursor = conn.cursor()

cursor.execute(
    "LISTEN security_events;"
)

print(
    "LISTENER: Waiting for PostgreSQL notification...",
    flush=True,
)

while True:
    ready = select.select(
        [conn],
        [],
        [],
        30,
    )

    if not ready[0]:
        print(
            "LISTENER: Still waiting...",
            flush=True,
        )
        continue

    conn.poll()

    while conn.notifies:
        notification = conn.notifies.pop(0)

        print(
            "NOTIFICATION RECEIVED:",
            notification.payload,
            flush=True,
        )

        conn.close()
        raise SystemExit(0)
