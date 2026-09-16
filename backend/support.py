import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Assessment, SupportTicket, SupportTicketMessage, User
from schemas import (
    SupportTicketCreate,
    SupportTicketDetailResponse,
    SupportTicketMessageCreate,
    SupportTicketMessageResponse,
    SupportTicketResponse,
    SupportTicketUpdate,
)
from auth import get_current_user


router = APIRouter(
    prefix="/support",
    tags=["Support Tickets"],
)


# ============================================================
# HELPERS
# ============================================================

def generate_ticket_id(db: Session) -> str:
    """
    Generate a readable ticket ID such as:

    SOC-20260910-AB12CD
    """

    while True:
        date_part = datetime.utcnow().strftime("%Y%m%d")
        random_part = uuid.uuid4().hex[:6].upper()

        ticket_id = f"SOC-{date_part}-{random_part}"

        existing = (
            db.query(SupportTicket)
            .filter(SupportTicket.ticket_id == ticket_id)
            .first()
        )

        if not existing:
            return ticket_id


def require_user(current_user: User):
    """
    Role 1 = User / Client
    """

    if current_user.role_id != 1:
        raise HTTPException(
            status_code=403,
            detail="Only users can access this endpoint",
        )


def require_admin(current_user: User):
    """
    Role 3 = Admin
    """

    if current_user.role_id != 3:
        raise HTTPException(
            status_code=403,
            detail="Only admins can access this endpoint",
        )


def get_user_ticket(
    db: Session,
    ticket_id: int,
    current_user: User,
):
    ticket = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.id == ticket_id,
            SupportTicket.user_id == current_user.id,
        )
        .first()
    )

    if not ticket:
        raise HTTPException(
            status_code=404,
            detail="Ticket not found",
        )

    return ticket


# ============================================================
# USER — CREATE TICKET
# ============================================================

@router.post(
    "/tickets",
    response_model=SupportTicketResponse,
)
def create_ticket(
    request: SupportTicketCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_user(current_user)

    # --------------------------------------------------------
    # Validate assessment when supplied
    # --------------------------------------------------------

    if request.assessment_id is not None:

        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id == current_user.id,
            )
            .first()
        )

        if not assessment:
            raise HTTPException(
                status_code=404,
                detail="Assessment not found",
            )

    # --------------------------------------------------------
    # Generate ticket ID
    # --------------------------------------------------------

    ticket_id = generate_ticket_id(db)

    ticket = SupportTicket(
        ticket_id=ticket_id,
        user_id=current_user.id,
        assessment_id=request.assessment_id,
        category=request.category.strip(),
        subject=request.subject.strip(),
        description=request.description.strip(),
        priority=request.priority,
        status="OPEN",
        assigned_to=None,
        assignment_channel=None,
        assignment_status="NOT_ASSIGNED",
        admin_notes=None,
        resolution=None,
        final_admin_message=None,
    )

    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    # --------------------------------------------------------
    # Automatically create first ticket message
    # --------------------------------------------------------

    first_message = SupportTicketMessage(
        ticket_id=ticket.id,
        sender_type="USER",
        sender_name=current_user.username,
        message=request.description.strip(),
    )

    db.add(first_message)
    db.commit()

    return ticket


# ============================================================
# USER — LIST OWN TICKETS
# ============================================================

@router.get(
    "/tickets",
    response_model=list[SupportTicketResponse],
)
def get_my_tickets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_user(current_user)

    tickets = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.user_id == current_user.id
        )
        .order_by(
            SupportTicket.created_at.desc()
        )
        .all()
    )

    return tickets


# ============================================================
# USER — VIEW OWN TICKET
# ============================================================

@router.get(
    "/tickets/{ticket_id}",
    response_model=SupportTicketDetailResponse,
)
def get_my_ticket(
    ticket_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_user(current_user)

    ticket = get_user_ticket(
        db,
        ticket_id,
        current_user,
    )

    messages = (
        db.query(SupportTicketMessage)
        .filter(
            SupportTicketMessage.ticket_id == ticket.id
        )
        .order_by(
            SupportTicketMessage.created_at.asc()
        )
        .all()
    )

    return {
        **ticket.__dict__,
        "messages": messages,
    }


# ============================================================
# USER — ADD MESSAGE
# ============================================================

@router.post(
    "/tickets/{ticket_id}/messages",
    response_model=SupportTicketMessageResponse,
)
def add_user_message(
    ticket_id: int,
    request: SupportTicketMessageCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_user(current_user)

    ticket = get_user_ticket(
        db,
        ticket_id,
        current_user,
    )

    if ticket.status in ["RESOLVED", "CLOSED"]:
        raise HTTPException(
            status_code=400,
            detail="This ticket is already closed",
        )

    message = SupportTicketMessage(
        ticket_id=ticket.id,
        sender_type="USER",
        sender_name=current_user.username,
        message=request.message.strip(),
    )

    # If user replies while waiting for user,
    # return ticket to in-progress.
    if ticket.status == "WAITING_FOR_USER":
        ticket.status = "IN_PROGRESS"

    ticket.updated_at = datetime.utcnow()

    db.add(message)
    db.commit()
    db.refresh(message)

    return message


# ============================================================
# ADMIN — LIST ALL TICKETS
# ============================================================

@router.get(
    "/admin/tickets",
    response_model=list[SupportTicketResponse],
)
def admin_get_tickets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_admin(current_user)

    tickets = (
        db.query(SupportTicket)
        .order_by(
            SupportTicket.created_at.desc()
        )
        .all()
    )

    return tickets


# ============================================================
# ADMIN — VIEW TICKET
# ============================================================

@router.get(
    "/admin/tickets/{ticket_id}",
    response_model=SupportTicketDetailResponse,
)
def admin_get_ticket(
    ticket_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_admin(current_user)

    ticket = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.id == ticket_id
        )
        .first()
    )

    if not ticket:
        raise HTTPException(
            status_code=404,
            detail="Ticket not found",
        )

    messages = (
        db.query(SupportTicketMessage)
        .filter(
            SupportTicketMessage.ticket_id == ticket.id
        )
        .order_by(
            SupportTicketMessage.created_at.asc()
        )
        .all()
    )

    return {
        **ticket.__dict__,
        "messages": messages,
    }


# ============================================================
# ADMIN — UPDATE / ASSIGN / RESOLVE
# ============================================================

@router.put(
    "/admin/tickets/{ticket_id}",
    response_model=SupportTicketResponse,
)
def admin_update_ticket(
    ticket_id: int,
    request: SupportTicketUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_admin(current_user)

    ticket = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.id == ticket_id
        )
        .first()
    )

    if not ticket:
        raise HTTPException(
            status_code=404,
            detail="Ticket not found",
        )

    # --------------------------------------------------------
    # Update fields only when supplied
    # --------------------------------------------------------

    if request.status is not None:
        ticket.status = request.status

    if request.priority is not None:
        ticket.priority = request.priority

    if request.assigned_to is not None:
        ticket.assigned_to = request.assigned_to

    if request.assignment_channel is not None:
        ticket.assignment_channel = request.assignment_channel

    if request.assignment_status is not None:
        ticket.assignment_status = request.assignment_status

    if request.admin_notes is not None:
        ticket.admin_notes = request.admin_notes

    if request.resolution is not None:
        ticket.resolution = request.resolution

    if request.final_admin_message is not None:
        ticket.final_admin_message = request.final_admin_message

    # --------------------------------------------------------
    # Automatic assignment status handling
    # --------------------------------------------------------

    if request.assigned_to:
        if request.assignment_status is None:
            ticket.assignment_status = "ASSIGNED"

    # --------------------------------------------------------
    # Automatic status handling
    # --------------------------------------------------------

    if request.assignment_status == "WORKING":
        ticket.status = "IN_PROGRESS"

    elif request.assignment_status == "COMPLETED":
        ticket.status = "IN_PROGRESS"

    # --------------------------------------------------------
    # Resolve ticket
    # --------------------------------------------------------

    if ticket.status == "RESOLVED":

        if not ticket.resolution:
            raise HTTPException(
                status_code=400,
                detail="Resolution message is required before resolving",
            )

        ticket.resolved_at = datetime.utcnow()

    else:

        ticket.resolved_at = None

    ticket.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(ticket)

    return ticket


# ============================================================
# ADMIN — ADD MESSAGE TO TICKET
# ============================================================

@router.post(
    "/admin/tickets/{ticket_id}/messages",
    response_model=SupportTicketMessageResponse,
)
def admin_add_message(
    ticket_id: int,
    request: SupportTicketMessageCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_admin(current_user)

    ticket = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.id == ticket_id
        )
        .first()
    )

    if not ticket:
        raise HTTPException(
            status_code=404,
            detail="Ticket not found",
        )

    message = SupportTicketMessage(
        ticket_id=ticket.id,
        sender_type="ADMIN",
        sender_name=current_user.username,
        message=request.message.strip(),
    )

    ticket.updated_at = datetime.utcnow()

    db.add(message)
    db.commit()
    db.refresh(message)

    return message