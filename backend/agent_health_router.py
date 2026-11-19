import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import Session

from database import Base, get_db
from models import User
from rbac import require_role

router = APIRouter(prefix="/agent-health", tags=["Agent Health"])

HEARTBEAT_TIMEOUT_SECONDS = 90


class SecurityAgent(Base):
    __tablename__ = "soc_security_agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_key_hash = Column(String(64), nullable=False, unique=True)
    name = Column(String(150), nullable=False)
    hostname = Column(String(255), nullable=False)
    operating_system = Column(String(100), nullable=False)
    agent_version = Column(String(50), nullable=True)
    status = Column(String(30), nullable=False, default="registered")
    last_seen = Column(DateTime, nullable=True)
    registered_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    notes = Column(Text, nullable=True)


class AgentRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    hostname: str = Field(min_length=1, max_length=255)
    operating_system: str = Field(min_length=1, max_length=100)
    agent_version: str | None = Field(default=None, max_length=50)
    notes: str | None = Field(default=None, max_length=2000)


class AgentHeartbeat(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    operating_system: str = Field(min_length=1, max_length=100)
    agent_version: str | None = Field(default=None, max_length=50)


def agent_status(agent):
    if agent.last_seen is None:
        return "NEVER_CONNECTED"

    cutoff = datetime.utcnow() - timedelta(
        seconds=HEARTBEAT_TIMEOUT_SECONDS
    )

    if agent.last_seen < cutoff:
        return "OFFLINE"

    return "ONLINE"


def agent_dict(agent):
    return {
        "id": agent.id,
        "name": agent.name,
        "hostname": agent.hostname,
        "operating_system": agent.operating_system,
        "agent_version": agent.agent_version,
        "status": agent_status(agent),
        "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
        "registered_at": agent.registered_at.isoformat(),
        "notes": agent.notes,
    }


@router.get("")
def list_agents(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    agents = db.query(SecurityAgent).order_by(
        SecurityAgent.id.desc()
    ).all()

    results = [agent_dict(agent) for agent in agents]

    return {
        "total": len(results),
        "online": sum(a["status"] == "ONLINE" for a in results),
        "offline": sum(a["status"] == "OFFLINE" for a in results),
        "never_connected": sum(
            a["status"] == "NEVER_CONNECTED" for a in results
        ),
        "agents": results,
        "heartbeat_timeout_seconds": HEARTBEAT_TIMEOUT_SECONDS,
    }


@router.post("/register", status_code=201)
def register_agent(
    data: AgentRegistration,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    # Return the credential only once, at registration.
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    agent = SecurityAgent(
        agent_key_hash=key_hash,
        name=data.name.strip(),
        hostname=data.hostname.strip(),
        operating_system=data.operating_system.strip(),
        agent_version=data.agent_version,
        notes=data.notes,
    )

    db.add(agent)
    db.commit()
    db.refresh(agent)

    return {
        "agent": agent_dict(agent),
        "agent_key": raw_key,
        "warning": "Save this key securely; it cannot be retrieved later.",
    }


@router.post("/{agent_id}/heartbeat")
def receive_heartbeat(
    agent_id: int,
    data: AgentHeartbeat,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
    db: Session = Depends(get_db),
):
    key_hash = hashlib.sha256(x_agent_key.encode()).hexdigest()

    agent = db.query(SecurityAgent).filter(
        SecurityAgent.id == agent_id,
        SecurityAgent.agent_key_hash == key_hash,
    ).first()

    if agent is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid agent ID or credential.",
        )

    agent.hostname = data.hostname.strip()
    agent.operating_system = data.operating_system.strip()
    agent.agent_version = data.agent_version
    agent.last_seen = datetime.utcnow()
    agent.status = "registered"

    db.commit()

    return {
        "accepted": True,
        "agent_id": agent.id,
        "last_seen": agent.last_seen.isoformat(),
    }

@router.post("/{agent_id}/reset-key")
def reset_agent_key(
    agent_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    agent = db.query(SecurityAgent).filter(
        SecurityAgent.id == agent_id
    ).first()

    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found.")

    raw_key = secrets.token_urlsafe(32)
    agent.agent_key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db.commit()

    return {
        "agent_id": agent.id,
        "agent_key": raw_key,
        "warning": "Save this key securely. It will not be shown again."
    }

