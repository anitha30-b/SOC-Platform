"""Validate server-captured scan ownership before saving findings."""
from models import User


def resolve_scan_event_owner(db, user_id, client_id):
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise ValueError('A valid initiating user is required to save scan findings.')
    if client_id is not None and (
        isinstance(client_id, bool) or not isinstance(client_id, int) or client_id <= 0
    ):
        raise ValueError('Invalid captured scan client scope.')
    user = db.get(User, user_id)
    if user is None or user.client_id != client_id:
        raise ValueError('Scan ownership changed or the initiating account no longer exists.')
    return {'owner_user_id': user.id, 'client_id': client_id}
