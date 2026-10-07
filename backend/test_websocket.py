import asyncio
import threading
import time

import uvicorn
from fastapi.testclient import TestClient

from main import app
from realtime_broadcaster import security_event_broadcaster


def run_test_server():
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8765,
        log_level="error",
    )


async def main():
    server_thread = threading.Thread(
        target=run_test_server,
        daemon=True,
    )

    server_thread.start()

    time.sleep(2)

    client = TestClient(app)

    with client.websocket_connect(
        "/ws/security-events"
    ) as websocket:

        event = {
            "event_id": "websocket-test-1",
            "severity": "ERROR",
            "message": "Real-time SOC WebSocket test event",
        }

        security_event_broadcaster.publish(event)

        received = websocket.receive_text()

        print(
            "WEBSOCKET RECEIVED:",
            received,
        )


asyncio.run(main())