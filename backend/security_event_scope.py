"""Shared tenant ownership rules for persisted security events."""

from sqlalchemy import or_

from models import Assessment, SecurityEvent, TelemetrySource, User


def owned_assessment_ids_query(db, current_user):
    """Return assessments belonging to the authenticated user or client."""
    query = db.query(Assessment.id)

    if current_user.client_id is not None:
        query = (
            query.join(User, Assessment.user_id == User.id)
            .filter(User.client_id == current_user.client_id)
        )
    else:
        query = query.filter(Assessment.user_id == current_user.id)

    return query


def owned_security_event_filter(db, current_user):
    """Allow explicitly owned assessment events or registered source events."""
    ownership_conditions = [
        SecurityEvent.assessment_id.in_(
            owned_assessment_ids_query(db, current_user)
        ),
        SecurityEvent.owner_user_id == current_user.id,
    ]

    if current_user.client_id is not None:
        ownership_conditions.append(
            SecurityEvent.client_id == current_user.client_id
        )
        source_ids = db.query(TelemetrySource.id).filter(
            TelemetrySource.client_id == current_user.client_id
        )
    else:
        source_ids = db.query(TelemetrySource.id).filter(
            TelemetrySource.owner_user_id == current_user.id
        )

    ownership_conditions.append(
        SecurityEvent.telemetry_source_id.in_(source_ids)
    )

    return or_(*ownership_conditions)
