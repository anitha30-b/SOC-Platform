from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from models import Client, User, AuditLog
from schemas import ClientCreate
from rbac import require_role

router = APIRouter(
    prefix="/admin/clients",
    tags=["Client Management"]
)


@router.post("/")
def create_client(
    client_data: ClientCreate,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db)
):
    existing_client = db.query(Client).filter(
        Client.email == client_data.email
    ).first()

    if existing_client:
        raise HTTPException(
            status_code=400,
            detail="Client email already exists"
        )

    new_client = Client(
        name=client_data.name,
        email=client_data.email,
        organization=client_data.organization
    )

    db.add(new_client)
    db.commit()
    db.refresh(new_client)

    try:
        db.add(AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Client created",
            module="Client Management",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=f"Created client id={new_client.id}, name={new_client.name}",
        ))
        db.commit()
    except Exception:
        db.rollback()

    return {
        "message": "Client created successfully",
        "client": {
            "id": new_client.id,
            "name": new_client.name,
            "email": new_client.email,
            "organization": new_client.organization
        }
    }


@router.get("/")
def get_all_clients(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db)
):
    clients = db.query(Client).all()

    return {
        "total_clients": len(clients),
        "clients": [
            {
                "id": client.id,
                "name": client.name,
                "email": client.email,
                "organization": client.organization
            }
            for client in clients
        ]
    }