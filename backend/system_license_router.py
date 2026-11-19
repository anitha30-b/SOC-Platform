import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from models import User, AuditLog
from database import SessionLocal
from fastapi import Request
from rbac import require_role

router = APIRouter(prefix="/system/license", tags=["Admin License"])

LICENSE_FILE = Path(__file__).resolve().parent / "runtime_license.json"


class LicenseUpdate(BaseModel):
    organization: str = Field(default="SOC Platform", min_length=1, max_length=150)
    edition: str = Field(default="Community", min_length=1, max_length=80)
    license_key: str = Field(default="", max_length=250)
    expires_at: str | None = None


def read_license():
    if not LICENSE_FILE.exists():
        return {
            "organization": "SOC Platform",
            "edition": "Community",
            "license_key": "",
            "activated_at": None,
            "expires_at": None,
        }

    try:
        data = json.loads(LICENSE_FILE.read_text())
        if not isinstance(data, dict):
            raise ValueError("Invalid license configuration")
        return data
    except (OSError, json.JSONDecodeError, ValueError):
        raise HTTPException(
            status_code=500,
            detail="License configuration is unreadable.",
        )


def license_status(data):
    if not data.get("license_key"):
        return "Not Activated"

    expiry = data.get("expires_at")
    if expiry:
        try:
            expiry_date = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if expiry_date.tzinfo is None:
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            if expiry_date < datetime.now(timezone.utc):
                return "Expired"
        except (ValueError, TypeError):
            return "Invalid Configuration"

    return "Active"


@router.get("")
def get_license(current_user: User = Depends(require_role(3))):
    data = read_license()
    key = data.get("license_key", "")
    return {
        "organization": data.get("organization", "SOC Platform"),
        "edition": data.get("edition", "Community"),
        "license_key": (
            f"{'*' * max(0, len(key) - 4)}{key[-4:]}" if key else ""
        ),
        "activated_at": data.get("activated_at"),
        "expires_at": data.get("expires_at"),
        "status": license_status(data),
        "product_version": "1.0.0",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.put("")
def update_license(
    payload: LicenseUpdate,
    request: Request,
    current_user: User = Depends(require_role(3)),
):
    key = payload.license_key.strip()
    expires_at = payload.expires_at.strip() if payload.expires_at else None

    if expires_at:
        try:
            datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Expiry must be a valid ISO date or datetime.",
            )

    if key and not expires_at:
        raise HTTPException(
            status_code=400,
            detail="Provide an expiry date for an activated license.",
        )

    existing = read_license()
    data = {
        "organization": payload.organization.strip(),
        "edition": payload.edition.strip(),
        "license_key": key,
        "activated_at": (
            existing.get("activated_at") or datetime.now(timezone.utc).isoformat()
            if key else None
        ),
        "expires_at": expires_at,
    }

    if not data["organization"] or not data["edition"]:
        raise HTTPException(
            status_code=400,
            detail="Organization and edition cannot be empty.",
        )

    temporary = LICENSE_FILE.with_suffix(".tmp")
    try:
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(json.dumps(data, indent=2))
        os.chmod(temporary, 0o600)
        os.replace(temporary, LICENSE_FILE)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail="Unable to save license configuration.",
        )

    # Record the successful configuration change without storing the license key.
    audit_db = SessionLocal()
    try:
        audit_db.add(AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action="System license configuration updated",
            module="Configuration Changes",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=(
                f"Organization={data['organization']}; "
                f"edition={data['edition']}; "
                f"expiry={data['expires_at'] or 'None'}; "
                f"license_status={license_status(data)}; "
                f"license_key_configured={'yes' if key else 'no'}"
            ),
        ))
        audit_db.commit()
    except Exception:
        audit_db.rollback()
        # Do not expose sensitive configuration or break a saved license update.
        import logging
        logging.getLogger("soc_configuration_audit").exception(
            "Failed to save configuration audit record"
        )
    finally:
        audit_db.close()

    return {
        "message": "License configuration saved.",
        "status": license_status(data),
        "license_key": (
            f"{'*' * max(0, len(key) - 4)}{key[-4:]}" if key else ""
        ),
    }


@router.post("/validate")
def validate_license(current_user: User = Depends(require_role(3))):
    data = read_license()
    status = license_status(data)
    return {
        "valid": status == "Active",
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "message": (
            "The configured license is active."
            if status == "Active"
            else "No valid active license is configured."
        ),
    }
