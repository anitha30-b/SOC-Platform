import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "runtime_logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

ACCESS_LOG_FILE = LOG_DIR / "access.log"

logger = logging.getLogger("soc_access")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    handler = logging.FileHandler(ACCESS_LOG_FILE, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


class AccessLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            client_ip = request.client.host if request.client else None

            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "client_ip": client_ip,
            }

            try:
                logger.info(json.dumps(record, separators=(",", ":")))
            except Exception:
                pass

            # Persist normal API activity without recursively logging audit reads.
            path = request.url.path
            excluded_paths = {
                "/audit/logs",
                "/audit/my-activity",
                "/audit/log",
            }
            if path not in excluded_paths and path != "/":
                db = None
                try:
                    from database import SessionLocal
                    from models import AuditLog
                    from security import decode_access_token

                    user_id = None
                    username = None
                    authorization = request.headers.get("authorization", "")
                    if authorization.lower().startswith("bearer "):
                        token = authorization.split(" ", 1)[1].strip()
                        payload = decode_access_token(token) if token else None
                        if payload:
                            subject = payload.get("sub")
                            try:
                                user_id = int(subject) if subject is not None else None
                            except (TypeError, ValueError):
                                user_id = None
                            username = payload.get("username")

                    db = SessionLocal()
                    method = request.method.upper()
                    status = "SUCCESS" if status_code < 400 else "FAILED"

                    db.add(AuditLog(
                        user_id=user_id,
                        username=str(username)[:100] if username else None,
                        action=f"API request: {method} {path}"[:255],
                        module="API Activity",
                        ip_address=client_ip,
                        status=status,
                        details=(
                            f"method={method}; endpoint={path}; "
                            f"status_code={status_code}; duration_ms={duration_ms}"
                        ),
                    ))
                    db.commit()
                except Exception:
                    if db is not None:
                        db.rollback()
                    logger.exception("Could not persist API activity to audit database")
                finally:
                    if db is not None:
                        db.close()
