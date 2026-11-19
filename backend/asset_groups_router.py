from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Session

from database import Base, get_db
from models import User
from rbac import require_role
from assets_router import Asset, asset_dict

router = APIRouter(prefix="/asset-groups", tags=["Asset Groups"])


class AdminAssetGroup(Base):
    __tablename__ = "soc_asset_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class AdminAssetGroupMember(Base):
    __tablename__ = "soc_asset_group_members"
    __table_args__ = (
        UniqueConstraint("group_id", "asset_id", name="uq_soc_asset_group_member"),
    )

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(
        Integer,
        ForeignKey("soc_asset_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id = Column(
        Integer,
        ForeignKey("soc_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class GroupInput(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str | None = None


class MembershipInput(BaseModel):
    asset_id: int = Field(gt=0)


def group_dict(db: Session, group: AdminAssetGroup):
    memberships = (
        db.query(AdminAssetGroupMember)
        .filter(AdminAssetGroupMember.group_id == group.id)
        .all()
    )
    asset_ids = [membership.asset_id for membership in memberships]
    assets = (
        db.query(Asset)
        .filter(Asset.id.in_(asset_ids))
        .order_by(Asset.name.asc())
        .all()
        if asset_ids
        else []
    )

    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "created_at": group.created_at.isoformat() if group.created_at else None,
        "updated_at": group.updated_at.isoformat() if group.updated_at else None,
        "asset_count": len(assets),
        "assets": [asset_dict(asset) for asset in assets],
    }


@router.get("")
def list_groups(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    groups = db.query(AdminAssetGroup).order_by(AdminAssetGroup.name.asc()).all()
    return {
        "total": len(groups),
        "groups": [group_dict(db, group) for group in groups],
    }


@router.post("", status_code=201)
def create_group(
    data: GroupInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Group name cannot be blank")

    existing = (
        db.query(AdminAssetGroup)
        .filter(AdminAssetGroup.name.ilike(name))
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="An asset group with this name already exists")

    group = AdminAssetGroup(name=name, description=data.description)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group_dict(db, group)


@router.put("/{group_id}")
def update_group(
    group_id: int,
    data: GroupInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    group = db.query(AdminAssetGroup).filter(AdminAssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Asset group not found")

    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Group name cannot be blank")

    duplicate = (
        db.query(AdminAssetGroup)
        .filter(AdminAssetGroup.name.ilike(name), AdminAssetGroup.id != group_id)
        .first()
    )
    if duplicate:
        raise HTTPException(status_code=409, detail="Another asset group already uses this name")

    group.name = name
    group.description = data.description
    db.commit()
    db.refresh(group)
    return group_dict(db, group)


@router.delete("/{group_id}")
def delete_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    group = db.query(AdminAssetGroup).filter(AdminAssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Asset group not found")

    db.query(AdminAssetGroupMember).filter(
        AdminAssetGroupMember.group_id == group_id
    ).delete(synchronize_session=False)

    db.delete(group)
    db.commit()
    return {"message": "Asset group deleted", "id": group_id}


@router.post("/{group_id}/members", status_code=201)
def add_member(
    group_id: int,
    data: MembershipInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    group = db.query(AdminAssetGroup).filter(AdminAssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Asset group not found")

    asset = db.query(Asset).filter(Asset.id == data.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    existing = (
        db.query(AdminAssetGroupMember)
        .filter(
            AdminAssetGroupMember.group_id == group_id,
            AdminAssetGroupMember.asset_id == data.asset_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Asset is already in this group")

    membership = AdminAssetGroupMember(group_id=group_id, asset_id=data.asset_id)
    db.add(membership)
    db.commit()
    return group_dict(db, group)


@router.delete("/{group_id}/members/{asset_id}")
def remove_member(
    group_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    group = db.query(AdminAssetGroup).filter(AdminAssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Asset group not found")

    membership = (
        db.query(AdminAssetGroupMember)
        .filter(
            AdminAssetGroupMember.group_id == group_id,
            AdminAssetGroupMember.asset_id == asset_id,
        )
        .first()
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Asset is not a member of this group")

    db.delete(membership)
    db.commit()
    return group_dict(db, group)
