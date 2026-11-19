"""Read-only intelligence from the configured local ATT&CK snapshot."""
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query
from mitre import MITRE_DATA_PATH, load_mitre_data, get_attack_id
from rbac import require_role

router = APIRouter(prefix="/threat-knowledge", tags=["Threat Knowledge"])
Category = Literal["actors", "campaigns", "malware"]
TYPES = {
    "actors": "intrusion-set",
    "campaigns": "campaign",
    "malware": "malware",
}


@lru_cache(maxsize=1)
def _snapshot(modified_ns, size):
    data = load_mitre_data()
    return tuple(
        item for item in data.get("objects", [])
        if not item.get("revoked") and not item.get("x_mitre_deprecated")
    )


def _objects():
    try:
        stat = MITRE_DATA_PATH.stat()
        return _snapshot(stat.st_mtime_ns, stat.st_size)
    except (OSError, ValueError):
        raise HTTPException(
            status_code=503, detail="Local intelligence dataset is unavailable."
        )


def _summary(item):
    return {
        "id": get_attack_id(item),
        "stix_id": item.get("id"),
        "name": item.get("name", ""),
        "aliases": item.get("aliases") or [],
        "modified": item.get("modified"),
        "version": item.get("x_mitre_version"),
    }


def _metadata():
    return {
        "source": "Local Enterprise ATT&CK snapshot",
        "dataset_file": MITRE_DATA_PATH.name,
        "scope_note": (
            "Reference intelligence only; these records do not establish "
            "activity in your environment."
        ),
    }


@router.get("/{category}")
def list_knowledge(
    category: Category,
    search: str = Query(default="", max_length=200),
    offset: int = Query(default=0, ge=0),
    page_size: int = Query(default=25, ge=1, le=100),
    current_user=Depends(require_role(1)),
):
    records = [
        item for item in _objects()
        if item.get("type") == TYPES[category]
    ]
    overall_total = len(records)
    term = search.strip().casefold()
    if term:
        records = [
            item for item in records
            if term in " ".join([
                get_attack_id(item) or "",
                item.get("name") or "",
                *(item.get("aliases") or []),
            ]).casefold()
        ]
    records.sort(key=lambda item: (
        (item.get("name") or "").casefold(),
        get_attack_id(item) or "",
        item.get("id") or "",
    ))
    total = len(records)
    page = records[offset:offset + page_size]
    return {
        **_metadata(),
        "category": category,
        "overall_total": overall_total,
        "total": total,
        "count": len(page),
        "offset": offset,
        "next_offset": offset + len(page) if offset + len(page) < total else None,
        "records": [_summary(item) for item in page],
    }


@router.get("/{category}/{record_id}")
def knowledge_detail(
    category: Category,
    record_id: str,
    current_user=Depends(require_role(1)),
):
    record_id = record_id.strip().upper()
    item = next((
        obj for obj in _objects()
        if obj.get("type") == TYPES[category]
        and get_attack_id(obj) == record_id
    ), None)
    if item is None:
        raise HTTPException(status_code=404, detail="Knowledge record not found.")

    references = []
    for ref in item.get("external_references", []):
        url = ref.get("url")
        if isinstance(url, str):
            try:
                parsed = urlsplit(url)
                if parsed.scheme in {"http", "https"} and parsed.hostname:
                    references.append({
                        "source": ref.get("source_name"),
                        "url": url,
                    })
            except ValueError:
                continue

    return {
        **_metadata(),
        "record": {
            **_summary(item),
            "description": item.get("description") or "",
            "created": item.get("created"),
            "references": references,
        },
    }
