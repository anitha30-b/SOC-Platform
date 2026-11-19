from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import SavedSearch, User
from rbac import require_role

router = APIRouter(
    prefix="/saved-searches",
    tags=["Saved SIEM Searches"],
)

ALLOWED_SEVERITIES = {
    "all", "INFO", "LOW", "MEDIUM", "HIGH",
    "CRITICAL", "ERROR", "WARNING",
}


class SavedSearchInput(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    search_text: str = Field(default="", max_length=200)
    severity: str = Field(default="all", max_length=20)
    source: str = Field(default="all", max_length=255)
    event_type: str = Field(default="all", max_length=100)


def _owned_searches(db: Session, user: User):
    query = db.query(SavedSearch)

    if user.client_id is not None:
        return query.filter(SavedSearch.client_id == user.client_id)

    return query.filter(
        SavedSearch.owner_user_id == user.id,
        SavedSearch.client_id.is_(None),
    )


def _validate_payload(payload: SavedSearchInput):
    if not payload.name.strip():
        raise HTTPException(status_code=422, detail="Search name cannot be blank")

    if payload.severity not in ALLOWED_SEVERITIES:
        raise HTTPException(status_code=422, detail="Unsupported severity value")

    if not payload.source.strip() or not payload.event_type.strip():
        raise HTTPException(
            status_code=422,
            detail="Source and event type cannot be blank",
        )


def _response(item: SavedSearch):
    return {
        "id": item.id,
        "name": item.name,
        "search_text": item.search_text,
        "severity": item.severity,
        "source": item.source,
        "event_type": item.event_type,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


@router.get("")
def list_saved_searches(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    items = (
        _owned_searches(db, current_user)
        .order_by(SavedSearch.updated_at.desc(), SavedSearch.id.desc())
        .all()
    )
    return [_response(item) for item in items]


@router.post("", status_code=201)
def create_saved_search(
    payload: SavedSearchInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    _validate_payload(payload)

    item = SavedSearch(
        name=payload.name.strip(),
        search_text=payload.search_text.strip(),
        severity=payload.severity,
        source=payload.source.strip(),
        event_type=payload.event_type.strip(),
        owner_user_id=current_user.id,
        client_id=current_user.client_id,
    )

    try:
        db.add(item)
        db.commit()
        db.refresh(item)
    except Exception:
        db.rollback()
        raise

    return _response(item)


@router.put("/{search_id}")
def update_saved_search(
    search_id: int,
    payload: SavedSearchInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    _validate_payload(payload)

    item = _owned_searches(db, current_user).filter(
        SavedSearch.id == search_id
    ).first()

    if item is None:
        raise HTTPException(status_code=404, detail="Saved search not found")

    item.name = payload.name.strip()
    item.search_text = payload.search_text.strip()
    item.severity = payload.severity
    item.source = payload.source.strip()
    item.event_type = payload.event_type.strip()
    item.updated_at = datetime.utcnow()

    try:
        db.commit()
        db.refresh(item)
    except Exception:
        db.rollback()
        raise

    return _response(item)


@router.delete("/{search_id}")
def delete_saved_search(
    search_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    item = _owned_searches(db, current_user).filter(
        SavedSearch.id == search_id
    ).first()

    if item is None:
        raise HTTPException(status_code=404, detail="Saved search not found")

    try:
        db.delete(item)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {"deleted": True, "id": search_id}
