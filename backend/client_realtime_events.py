import asyncio
import json
import select
import threading
import time

import psycopg2
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from database import DATABASE_URL, SessionLocal
from models import EndpointAsset, SecurityEvent, User
from security import decode_access_token
from security_event_scope import owned_security_event_filter

router = APIRouter(tags=["Client Real-Time Security Events"])


class ClientSecurityEventBroadcaster:
    def __init__(self):
        self._clients = set()

    def subscribe(self):
        loop = asyncio.get_running_loop()
        queue = asyncio.Queue(maxsize=100)
        self._clients.add((loop, queue))
        return queue

    def unsubscribe(self, queue):
        self._clients = {
            (loop, client_queue)
            for loop, client_queue in self._clients
            if client_queue is not queue
        }

    def publish(self, event):
        payload = json.dumps(event, default=str)
        for loop, queue in list(self._clients):
            if loop.is_closed():
                self._clients.discard((loop, queue))
                continue

            def enqueue(q=queue, p=payload):
                try:
                    q.put_nowait(p)
                except asyncio.QueueFull:
                    pass

            loop.call_soon_threadsafe(enqueue)


client_security_event_broadcaster = ClientSecurityEventBroadcaster()

# Separate minimal refresh signals for tenant-scoped SIEM events.
client_siem_event_broadcaster = ClientSecurityEventBroadcaster()


def notify_client_security_event(event):
    """Publish a minimal refresh signal for a persisted endpoint event."""
    endpoint_id = event.get("endpoint_asset_id")
    if endpoint_id is None:
        return False

    payload = json.dumps({
        "event_id": str(event.get("event_id") or ""),
        "endpoint_asset_id": int(endpoint_id),
    })

    connection = psycopg2.connect(DATABASE_URL)
    try:
        connection.autocommit = True
        cursor = connection.cursor()
        cursor.execute(
            "SELECT pg_notify(%s, %s)",
            ("client_security_events", payload),
        )
        cursor.close()
    finally:
        connection.close()

    return True


class ClientPostgreSQLEventListener:
    def __init__(self):
        self.connection = None
        self.thread = None
        self.running = False

    def run(self):
        while self.running:
            try:
                self.connection = psycopg2.connect(DATABASE_URL, connect_timeout=5)
                self.connection.autocommit = True
                cursor = self.connection.cursor()
                cursor.execute("LISTEN client_security_events;")
                cursor.close()

                print(
                    "[SOC CLIENT PG LISTENER] Listening on client_security_events...",
                    flush=True,
                )

                while self.running:
                    ready = select.select([self.connection], [], [], 1)
                    if not ready[0]:
                        continue

                    self.connection.poll()
                    while self.connection.notifies:
                        notification = self.connection.notifies.pop(0)
                        try:
                            event = json.loads(notification.payload)
                            if event.get("endpoint_asset_id") is not None:
                                client_security_event_broadcaster.publish(event)
                        except (json.JSONDecodeError, TypeError, ValueError) as exc:
                            print(
                                f"[SOC CLIENT PG LISTENER] Invalid payload: {exc}",
                                flush=True,
                            )

            except Exception as exc:
                if self.running:
                    print(
                        f"[SOC CLIENT PG LISTENER] Connection error: {exc}",
                        flush=True,
                    )
                    time.sleep(2)
            finally:
                if self.connection is not None:
                    try:
                        self.connection.close()
                    except Exception:
                        pass
                    self.connection = None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception:
                pass
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(timeout=6)


client_security_event_listener = ClientPostgreSQLEventListener()



# WS_DATABASE_WORKER_ISOLATION
# Each worker creates and closes its own database session.
def _client_ws_user_exists(user_id):
    db = SessionLocal()
    try:
        return db.query(User.id).filter(
            User.id == user_id,
            User.role_id == 1,
        ).first() is not None
    finally:
        db.close()


def _client_ws_endpoint_authorized(user_id, endpoint_id):
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == user_id,
            User.role_id == 1,
        ).first()
        if user is None:
            return None

        query = (
            db.query(EndpointAsset.id)
            .join(User, User.id == EndpointAsset.user_id)
            .filter(EndpointAsset.id == endpoint_id)
        )
        if user.client_id is not None:
            query = query.filter(User.client_id == user.client_id)
        else:
            query = query.filter(EndpointAsset.user_id == user.id)
        return query.first() is not None
    finally:
        db.close()


def _client_ws_siem_authorized(user_id, event_id):
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == user_id,
            User.role_id == 1,
        ).first()
        if user is None:
            return None

        return db.query(SecurityEvent.id).filter(
            SecurityEvent.event_id == event_id,
            owned_security_event_filter(db, user),
        ).first() is not None
    finally:
        db.close()


@router.websocket("/ws/client/security-events")
async def client_security_events_websocket(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    try:
        payload = decode_access_token(token)
        user_id_value = payload.get("sub") if payload else None
        if not user_id_value:
            await websocket.close(code=1008)
            return

        user_id = int(user_id_value)
        if not await asyncio.to_thread(_client_ws_user_exists, user_id):
            await websocket.close(code=1008)
            return
    except Exception:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    queue = client_security_event_broadcaster.subscribe()

    try:
        while True:
            event_task = asyncio.create_task(queue.get())
            receive_task = asyncio.create_task(websocket.receive_text())

            done, pending = await asyncio.wait(
                {event_task, receive_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

            if receive_task in done:
                receive_task.result()

            if event_task not in done:
                continue

            try:
                event = json.loads(event_task.result())
                endpoint_id = int(event.get("endpoint_asset_id"))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue

            # Revalidate user role and endpoint ownership for every signal.
            authorized = await asyncio.to_thread(
                _client_ws_endpoint_authorized, user_id, endpoint_id
            )
            if authorized is None:
                await websocket.close(code=1008)
                return

            if authorized:
                await websocket.send_json({
                    "type": "security_event",
                    "event_id": event.get("event_id"),
                    "endpoint_asset_id": endpoint_id,
                })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        print(f"[SOC CLIENT WS ERROR] {exc}", flush=True)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        client_security_event_broadcaster.unsubscribe(queue)


@router.websocket("/ws/client/siem-events")
async def client_siem_events_websocket(websocket: WebSocket):
    """Authenticated SIEM refresh stream with persisted tenant ownership checks."""
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    try:
        payload = decode_access_token(token)
        user_id_value = payload.get("sub") if payload else None
        if not user_id_value:
            await websocket.close(code=1008)
            return

        user_id = int(user_id_value)
        if not await asyncio.to_thread(_client_ws_user_exists, user_id):
            await websocket.close(code=1008)
            return
    except Exception:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    queue = client_siem_event_broadcaster.subscribe()

    try:
        while True:
            event_task = asyncio.create_task(queue.get())
            receive_task = asyncio.create_task(websocket.receive_text())

            done, pending = await asyncio.wait(
                {event_task, receive_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

            if receive_task in done:
                receive_task.result()

            if event_task not in done:
                continue

            try:
                signal = json.loads(event_task.result())
                event_id = str(signal.get("event_id") or "").strip()
            except (json.JSONDecodeError, TypeError, ValueError):
                continue

            if not event_id:
                continue

            # Revalidate the user and persisted event ownership for every signal.
            authorized = await asyncio.to_thread(
                _client_ws_siem_authorized, user_id, event_id
            )
            if authorized is None:
                await websocket.close(code=1008)
                return

            if authorized:
                # Never send event contents over this WebSocket.
                await websocket.send_json({
                    "type": "siem_refresh",
                })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        print(f"[SOC SIEM WS ERROR] {exc}", flush=True)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        client_siem_event_broadcaster.unsubscribe(queue)
