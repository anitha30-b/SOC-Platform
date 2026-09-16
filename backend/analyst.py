from fastapi import APIRouter, Depends

from models import User
from rbac import require_role


router = APIRouter(
    prefix="/analyst",
    tags=["Security Analyst"]
)


@router.get("/dashboard")
def analyst_dashboard(
    current_user: User = Depends(require_role(2))
):
    return {
        "message": "Welcome to the Security Analyst Dashboard",
        "user": current_user.username,
        "role": "Security Analyst"
    }