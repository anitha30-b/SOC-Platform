import platform
import time
from datetime import datetime, timezone

import psutil
from fastapi import APIRouter, Depends
from sqlalchemy import text

from database import engine
from postgres_event_listener import postgres_event_listener
from rbac import require_role

router = APIRouter(prefix="/system", tags=["System Health"])


def _component(status, message, **extra):
    return {
        "status": status,
        "message": message,
        **extra,
    }


@router.get("/health")
def system_health(current_user=Depends(require_role(3))):
    checked_at = datetime.now(timezone.utc).isoformat()

    # API process
    api = _component(
        "HEALTHY",
        "SOC Platform API process is responding.",
    )

    # PostgreSQL
    db_start = time.perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        db_latency_ms = round((time.perf_counter() - db_start) * 1000, 2)
        database = _component(
            "HEALTHY",
            "PostgreSQL connection is healthy.",
            latency_ms=db_latency_ms,
        )
    except Exception as exc:
        database = _component(
            "CRITICAL",
            "PostgreSQL connection failed.",
            error=type(exc).__name__,
        )

    # PostgreSQL real-time event listener
    listener_running = bool(postgres_event_listener.running)
    listener_thread_alive = bool(
        postgres_event_listener.thread
        and postgres_event_listener.thread.is_alive()
    )
    listener_connected = bool(postgres_event_listener.connection)

    if listener_running and listener_thread_alive and listener_connected:
        listener = _component(
            "HEALTHY",
            "PostgreSQL real-time event listener is running.",
        )
    else:
        listener = _component(
            "CRITICAL",
            "PostgreSQL real-time event listener is not healthy.",
            running=listener_running,
            thread_alive=listener_thread_alive,
            connected=listener_connected,
        )

    # System resources
    cpu = psutil.cpu_percent(interval=0.2)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    resources_status = "HEALTHY"
    if cpu >= 90 or memory.percent >= 90 or disk.percent >= 95:
        resources_status = "CRITICAL"
    elif cpu >= 75 or memory.percent >= 75 or disk.percent >= 85:
        resources_status = "WARNING"

    resources = {
        "status": resources_status,
        "cpu_usage_percent": round(cpu, 2),
        "memory_usage_percent": round(memory.percent, 2),
        "disk_usage_percent": round(disk.percent, 2),
        "memory_total_gb": round(memory.total / (1024 ** 3), 2),
        "memory_used_gb": round(memory.used / (1024 ** 3), 2),
        "disk_total_gb": round(disk.total / (1024 ** 3), 2),
        "disk_used_gb": round(disk.used / (1024 ** 3), 2),
        "disk_free_gb": round(disk.free / (1024 ** 3), 2),
    }

    # Host uptime
    uptime_seconds = int(time.time() - psutil.boot_time())

    critical_components = [
        api["status"],
        database["status"],
        listener["status"],
        resources["status"],
    ]

    if "CRITICAL" in critical_components:
        overall_status = "CRITICAL"
    elif "WARNING" in critical_components:
        overall_status = "WARNING"
    else:
        overall_status = "HEALTHY"

    return {
        "status": overall_status,
        "checked_at": checked_at,
        "service": "SOC Platform",
        "api": api,
        "database": database,
        "postgres_event_listener": listener,
        "resources": resources,
        "host": {
            "hostname": platform.node(),
            "operating_system": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "uptime_seconds": uptime_seconds,
        },
    }

@router.get("/search-index-metrics")
def search_index_metrics(current_user=Depends(require_role(3))):
    """Read-only PostgreSQL SIEM search and index statistics for administrators."""
    checked_at = datetime.now(timezone.utc).isoformat()

    with engine.connect() as connection:
        table_row = connection.execute(text("""
            SELECT n_live_tup, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch
            FROM pg_stat_user_tables
            WHERE relid = 'public.security_events'::regclass
        """)).mappings().first()

        index_rows = connection.execute(text("""
            SELECT indexrelname, idx_scan, idx_tup_read, idx_tup_fetch,
                   pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
            FROM pg_stat_user_indexes
            WHERE relid = 'public.security_events'::regclass
              AND indexrelname IN (
                'ix_security_events_source_trgm',
                'ix_security_events_event_type_trgm',
                'ix_security_events_message_trgm',
                'ix_security_events_target_trgm',
                'ix_security_events_mitre_technique_id_trgm',
                'ix_security_events_mitre_technique_name_trgm',
                'ix_security_events_mitre_tactic_trgm',
                'ix_security_events_alert_status'
              )
            ORDER BY indexrelname
        """)).mappings().all()

        query_stats = {
            "available": True,
            "query_count": 0,
            "queries": [],
        }
        try:
            query_rows = connection.execute(text("""
                SELECT queryid::text AS queryid, calls,
                       round(total_exec_time::numeric, 2) AS total_exec_ms,
                       round(mean_exec_time::numeric, 3) AS mean_exec_ms,
                       rows, shared_blks_hit, shared_blks_read,
                       left(query, 300) AS query
                FROM pg_stat_statements
                WHERE dbid = (
                    SELECT oid FROM pg_database
                    WHERE datname = current_database()
                )
                  AND query ILIKE '%security_events%'
                  AND query ILIKE '%ILIKE%'
                  AND query NOT ILIKE '%pg_stat_statements%'
                  AND query NOT ILIKE 'EXPLAIN %'
                ORDER BY total_exec_time DESC
                LIMIT 10
            """)).mappings().all()

            query_stats["query_count"] = len(query_rows)
            query_stats["queries"] = [
                {
                    "queryid": row["queryid"],
                    "calls": int(row["calls"] or 0),
                    "total_exec_ms": float(row["total_exec_ms"] or 0),
                    "mean_exec_ms": float(row["mean_exec_ms"] or 0),
                    "rows": int(row["rows"] or 0),
                    "shared_blks_hit": int(row["shared_blks_hit"] or 0),
                    "shared_blks_read": int(row["shared_blks_read"] or 0),
                    "query": row["query"],
                }
                for row in query_rows
            ]
        except Exception as exc:
            connection.rollback()
            query_stats = {
                "available": False,
                "message": type(exc).__name__,
                "query_count": 0,
                "queries": [],
            }

    return {
        "checked_at": checked_at,
        "table": "public.security_events",
        "counter_scope": (
            "Cumulative PostgreSQL statistics; counters can reset when "
            "PostgreSQL statistics are reset."
        ),
        "table_activity": dict(table_row) if table_row else {},
        "indexes": [
            {
                "name": row["indexrelname"],
                "scans": int(row["idx_scan"] or 0),
                "tuples_read": int(row["idx_tup_read"] or 0),
                "tuples_fetched": int(row["idx_tup_fetch"] or 0),
                "size": row["index_size"],
            }
            for row in index_rows
        ],
        "search_query_statistics": query_stats,
    }
