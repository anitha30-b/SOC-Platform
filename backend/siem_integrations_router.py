import json
import os
from datetime import datetime
from urllib.parse import urlparse, urlunparse

import requests
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session

from database import get_db
from models import User, SIEMIntegration
from rbac import require_role


load_dotenv()

router = APIRouter(
    prefix="/admin/siem-integrations",
    tags=["SIEM Integrations"],
)

SUPPORTED_PROVIDERS = set()  # External Splunk/Elastic integrations are retired.


def get_cipher():
    key = os.getenv("SIEM_ENCRYPTION_KEY")

    if not key:
        raise HTTPException(
            status_code=500,
            detail="SIEM encryption key is not configured.",
        )

    try:
        return Fernet(key.encode())
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="SIEM encryption configuration is invalid.",
        )


def encrypt_credentials(credentials):
    if not isinstance(credentials, dict):
        raise HTTPException(
            status_code=400,
            detail="Credentials must be supplied as an object.",
        )

    serialized = json.dumps(credentials).encode()
    return get_cipher().encrypt(serialized).decode()


def decrypt_credentials(integration):
    if not integration.encrypted_credentials:
        return {}

    try:
        decrypted = get_cipher().decrypt(
            integration.encrypted_credentials.encode()
        )
        return json.loads(decrypted.decode())
    except (InvalidToken, ValueError, json.JSONDecodeError):
        raise HTTPException(
            status_code=500,
            detail="Stored SIEM credentials could not be decrypted.",
        )


def validate_base_url(value):
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail="Invalid SIEM URL.")

    value = value.strip().rstrip("/")
    parsed = urlparse(value)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid HTTP or HTTPS SIEM base URL.",
        )

    return value


def serialize_integration(item):
    return {
        "id": item.id,
        "name": item.name,
        "provider": item.provider,
        "base_url": item.base_url,
        "enabled": item.enabled,
        "status": item.status,
        "has_credentials": bool(item.encrypted_credentials),
        "last_tested_at": (
            item.last_tested_at.isoformat()
            if item.last_tested_at else None
        ),
        "last_error": item.last_error,
        "created_at": item.created_at.isoformat(),
        "updated_at": item.updated_at.isoformat(),
    }


def validate_credentials(provider, credentials):
    if not isinstance(credentials, dict):
        raise HTTPException(status_code=400, detail="Invalid credentials.")

    if provider == "splunk":
        valid = bool(
            credentials.get("token")
            or (
                credentials.get("username")
                and credentials.get("password")
            )
        )
        if not valid:
            raise HTTPException(
                status_code=400,
                detail="Splunk requires a token or username and password.",
            )

    elif provider == "elastic":
        valid = bool(
            credentials.get("api_key")
            or (
                credentials.get("username")
                and credentials.get("password")
            )
        )
        if not valid:
            raise HTTPException(
                status_code=400,
                detail="Elastic requires an API key or username and password.",
            )


@router.get("")
def list_integrations(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    items = (
        db.query(SIEMIntegration)
        .order_by(SIEMIntegration.created_at.desc())
        .all()
    )

    return {
        "integrations": [serialize_integration(item) for item in items],
        "total": len(items),
    }


@router.post("")
def create_integration(
    data: dict = Body(...),
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    provider = str(data.get("provider", "")).lower().strip()
    name = str(data.get("name", "")).strip()
    base_url = validate_base_url(data.get("base_url", ""))
    credentials = data.get("credentials", {})

    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail="External SIEM providers are disabled. Use the local Snort sensor.",
        )

    if not name or len(name) > 150:
        raise HTTPException(
            status_code=400,
            detail="Integration name is required and must be under 150 characters.",
        )

    validate_credentials(provider, credentials)

    existing = db.query(SIEMIntegration).filter(
        SIEMIntegration.provider == provider,
        SIEMIntegration.name == name,
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="An integration with this provider and name already exists.",
        )

    item = SIEMIntegration(
        name=name,
        provider=provider,
        base_url=base_url,
        encrypted_credentials=encrypt_credentials(credentials),
        enabled=True,
        status="PENDING",
        created_by=current_user.id,
    )

    db.add(item)
    db.commit()
    db.refresh(item)

    return {
        "message": "SIEM integration created.",
        "integration": serialize_integration(item),
    }


@router.put("/{integration_id}")
def update_integration(
    integration_id: int,
    data: dict = Body(...),
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    item = db.query(SIEMIntegration).filter(
        SIEMIntegration.id == integration_id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail="Integration not found.")

    name = str(data.get("name", item.name)).strip()
    base_url = validate_base_url(data.get("base_url", item.base_url))

    if not name or len(name) > 150:
        raise HTTPException(status_code=400, detail="Invalid integration name.")

    duplicate = db.query(SIEMIntegration).filter(
        SIEMIntegration.provider == item.provider,
        SIEMIntegration.name == name,
        SIEMIntegration.id != integration_id,
    ).first()

    if duplicate:
        raise HTTPException(status_code=409, detail="Integration name already exists.")

    item.name = name
    item.base_url = base_url

    credentials = data.get("credentials")

    if credentials:
        validate_credentials(item.provider, credentials)
        item.encrypted_credentials = encrypt_credentials(credentials)

    item.status = "PENDING"
    item.last_error = None
    item.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(item)

    return {
        "message": "SIEM integration updated.",
        "integration": serialize_integration(item),
    }


@router.patch("/{integration_id}/status")
def update_integration_status(
    integration_id: int,
    data: dict = Body(...),
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    item = db.query(SIEMIntegration).filter(
        SIEMIntegration.id == integration_id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail="Integration not found.")

    enabled = data.get("enabled")

    if not isinstance(enabled, bool):
        raise HTTPException(status_code=400, detail="Enabled must be true or false.")

    item.enabled = enabled
    item.updated_at = datetime.utcnow()

    if not enabled:
        item.status = "DISABLED"
    else:
        item.status = "PENDING"

    db.commit()

    return {
        "message": "Integration status updated.",
        "integration": serialize_integration(item),
    }


@router.delete("/{integration_id}")
def delete_integration(
    integration_id: int,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    item = db.query(SIEMIntegration).filter(
        SIEMIntegration.id == integration_id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail="Integration not found.")

    db.delete(item)
    db.commit()

    return {"message": "SIEM integration deleted."}


@router.post("/{integration_id}/test")
def test_integration(
    integration_id: int,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    item = db.query(SIEMIntegration).filter(
        SIEMIntegration.id == integration_id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail="Integration not found.")

    if not item.enabled:
        raise HTTPException(
            status_code=400,
            detail="Enable this integration before testing it.",
        )

    if item.provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=410,
            detail="External SIEM connection tests are retired. Use the local Snort sensor.",
        )

    credentials = decrypt_credentials(item)

    try:
        if item.provider == "splunk":
            endpoint = (
                item.base_url.rstrip("/")
                + "/services/server/info?output_mode=json"
            )

            headers = {}

            if credentials.get("token"):
                headers["Authorization"] = (
                    "Bearer " + credentials["token"]
                )
                response = requests.get(
                    endpoint,
                    headers=headers,
                    timeout=12,
                    verify=True,
                    allow_redirects=False,
                )
            else:
                response = requests.get(
                    endpoint,
                    auth=(
                        credentials["username"],
                        credentials["password"],
                    ),
                    timeout=12,
                    verify=True,
                    allow_redirects=False,
                )

        elif item.provider == "elastic":
            endpoint = item.base_url.rstrip("/") + "/"

            headers = {}
            auth = None

            if credentials.get("api_key"):
                headers["Authorization"] = (
                    "ApiKey " + credentials["api_key"]
                )
            else:
                auth = (
                    credentials["username"],
                    credentials["password"],
                )

            response = requests.get(
                endpoint,
                headers=headers,
                auth=auth,
                timeout=12,
                verify=True,
                allow_redirects=False,
            )

        else:
            raise ValueError("Unsupported SIEM provider.")

        if response.is_redirect:
            raise ValueError("SIEM server returned a redirect; verify the configured URL.")

        response.raise_for_status()

        item.status = "CONNECTED"
        item.last_error = None
        success = True
        message = "Connection successful. The SIEM server responded."

    except requests.exceptions.SSLError:
        item.status = "ERROR"
        item.last_error = "TLS certificate verification failed."
        success = False
        message = item.last_error

    except requests.exceptions.Timeout:
        item.status = "ERROR"
        item.last_error = "Connection timed out."
        success = False
        message = item.last_error

    except requests.exceptions.HTTPError as exc:
        item.status = "ERROR"
        item.last_error = f"SIEM returned HTTP {exc.response.status_code}."
        success = False
        message = item.last_error

    except requests.exceptions.RequestException:
        item.status = "ERROR"
        item.last_error = "Could not reach the SIEM server."
        success = False
        message = item.last_error

    except Exception as exc:
        item.status = "ERROR"
        item.last_error = str(exc)[:500]
        success = False
        message = item.last_error

    item.last_tested_at = datetime.utcnow()
    item.updated_at = datetime.utcnow()

    db.commit()

    return {
        "success": success,
        "status": item.status,
        "message": message,
        "integration": serialize_integration(item),
    }


@router.get("/{integration_id}/ingestion-status")
def get_ingestion_status(
    integration_id: int,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    from models import SIEMIngestionState

    item = db.query(SIEMIntegration).filter(
        SIEMIntegration.id == integration_id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail="Integration not found.")

    state = db.query(SIEMIngestionState).filter(
        SIEMIngestionState.integration_id == integration_id
    ).first()

    return {
        "integration_id": integration_id,
        "provider": item.provider,
        "enabled": item.enabled,
        "status": item.status,
        "last_success_at": (
            state.last_success_at.isoformat()
            if state and state.last_success_at else None
        ),
        "last_ingested_at": (
            state.last_ingested_at.isoformat()
            if state and state.last_ingested_at else None
        ),
        "total_events": state.total_events if state else 0,
        "last_error": (
            state.last_error if state and state.last_error
            else item.last_error
        ),
    }
