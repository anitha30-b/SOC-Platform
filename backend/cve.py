import os
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import User
from rbac import require_role


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/cve",
    tags=["CVE Intelligence"],
)


# ============================================================
# NVD API
# ============================================================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_API_KEY = os.getenv("NVD_API_KEY")


# ============================================================
# CVE VALIDATION
# ============================================================

def normalize_cve_id(cve_id: str) -> str:
    """
    Normalize and validate a CVE identifier.
    Example:
        cve-2021-44228 -> CVE-2021-44228
    """

    clean_cve = str(cve_id or "").strip().upper()

    if not clean_cve.startswith("CVE-"):
        raise ValueError(
            "Invalid CVE format. Example: CVE-2021-44228"
        )

    return clean_cve


# ============================================================
# NVD CVE FETCHER
# ============================================================

def fetch_cve_information(cve_id: str) -> dict:
    """
    Fetch CVE intelligence from the NVD API.

    This function is reusable by:
    - Security Findings
    - VAPT scanner integrations
    - Vulnerability importers
    - Other backend services
    """

    try:
        clean_cve = normalize_cve_id(cve_id)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    headers = {}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "cveId": clean_cve,
    }

    # ========================================================
    # REQUEST NVD
    # ========================================================

    try:
        response = httpx.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=20,
        )

        response.raise_for_status()

    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                f"NVD API returned HTTP "
                f"{exc.response.status_code}."
            ),
        )

    except httpx.RequestError:
        raise HTTPException(
            status_code=502,
            detail="Unable to connect to the NVD API.",
        )

    # ========================================================
    # PARSE RESPONSE
    # ========================================================

    data = response.json()

    vulnerabilities = data.get(
        "vulnerabilities",
        [],
    )

    if not vulnerabilities:
        raise HTTPException(
            status_code=404,
            detail=(
                f"{clean_cve} was not found "
                "in the NVD response."
            ),
        )

    cve_data = vulnerabilities[0].get(
        "cve",
        {},
    )

    # ========================================================
    # DESCRIPTION
    # ========================================================

    description: Optional[str] = None

    for item in cve_data.get(
        "descriptions",
        [],
    ):
        if item.get("lang") == "en":
            description = item.get("value")
            break

    # ========================================================
    # CWE
    # ========================================================

    cwe_ids = []

    for weakness in cve_data.get(
        "weaknesses",
        [],
    ):
        for description_item in weakness.get(
            "description",
            [],
        ):
            value = description_item.get("value")

            if value and value.startswith("CWE-"):
                cwe_ids.append(value)

    cwe_ids = list(
        dict.fromkeys(cwe_ids)
    )

    # ========================================================
    # CVSS
    # ========================================================

    cvss_version = None
    cvss_score = None
    cvss_vector = None
    cvss_severity = None

    metrics = cve_data.get(
        "metrics",
        {},
    )

    # --------------------------------------------------------
    # Prefer CVSS v4
    # --------------------------------------------------------

    if metrics.get("cvssMetricV40"):

        metric = metrics["cvssMetricV40"][0]

        cvss_data = metric.get(
            "cvssData",
            {},
        )

        cvss_version = cvss_data.get(
            "version"
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        cvss_vector = cvss_data.get(
            "vectorString"
        )

        cvss_severity = cvss_data.get(
            "baseSeverity"
        )

    # --------------------------------------------------------
    # Then CVSS v3.1
    # --------------------------------------------------------

    elif metrics.get("cvssMetricV31"):

        metric = metrics["cvssMetricV31"][0]

        cvss_data = metric.get(
            "cvssData",
            {},
        )

        cvss_version = cvss_data.get(
            "version"
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        cvss_vector = cvss_data.get(
            "vectorString"
        )

        cvss_severity = cvss_data.get(
            "baseSeverity"
        )

    # --------------------------------------------------------
    # Then CVSS v3.0
    # --------------------------------------------------------

    elif metrics.get("cvssMetricV30"):

        metric = metrics["cvssMetricV30"][0]

        cvss_data = metric.get(
            "cvssData",
            {},
        )

        cvss_version = cvss_data.get(
            "version"
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        cvss_vector = cvss_data.get(
            "vectorString"
        )

        cvss_severity = cvss_data.get(
            "baseSeverity"
        )

    # ========================================================
    # AFFECTED PRODUCTS
    # ========================================================

    affected_products = []

    for configuration in cve_data.get(
        "configurations",
        [],
    ):
        for node in configuration.get(
            "nodes",
            [],
        ):
            for match in node.get(
                "cpeMatch",
                [],
            ):
                criteria = match.get(
                    "criteria"
                )

                if criteria:
                    affected_products.append(
                        criteria
                    )

    affected_products = list(
        dict.fromkeys(affected_products)
    )[:50]

    # ========================================================
    # REFERENCES
    # ========================================================

    references = []

    for reference in cve_data.get(
        "references",
        [],
    ):
        url = reference.get("url")

        if url:
            references.append(url)

    references = list(
        dict.fromkeys(references)
    )[:50]

    # ========================================================
    # DATES
    # ========================================================

    published = cve_data.get(
        "published"
    )

    last_modified = cve_data.get(
        "lastModified"
    )

    # ========================================================
    # RETURN NORMALIZED CVE INTELLIGENCE
    # ========================================================

    return {
        "cve_id": clean_cve,

        "description": description,

        "cwe": cwe_ids,

        "cvss": {
            "version": cvss_version,
            "score": cvss_score,
            "severity": cvss_severity,
            "vector": cvss_vector,
        },

        "affected_products": affected_products,

        "references": references,

        "published": published,

        "last_modified": last_modified,

        "source": "NVD",
    }


# ============================================================
# CVE LOOKUP ENDPOINT
# ============================================================

@router.get("/{cve_id}")
def get_cve_information(
    cve_id: str,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Look up a CVE from the NVD API.

    Example:
        GET /cve/CVE-2021-44228
    """

    return fetch_cve_information(cve_id)