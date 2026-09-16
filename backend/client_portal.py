from fastapi import APIRouter, Depends
from models import User
from rbac import require_role

router = APIRouter(
    prefix="/client",
    tags=["Client Portal"]
)


@router.get("/dashboard")
def client_dashboard(
    current_user: User = Depends(require_role(1))
):
    return {
        "message": "Welcome to the Client Dashboard",
        "user": current_user.username,
        "email": current_user.email,
        "client_id": current_user.client_id,
        "role": "Client"
    }