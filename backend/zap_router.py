from __future__ import annotations



import asyncio

from datetime import datetime

from urllib.parse import urlparse



import httpx

from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from sqlalchemy.orm import Session



from database import get_db

from models import Assessment, SecurityFinding, SecurityTool, User

from rbac import require_role

from security_findings import (

    calculate_risk_level,

    generate_finding_id,

    seed_security_tools,

)





router = APIRouter(

    prefix="/vapt/zap",

    tags=["OWASP ZAP"],

)





ZAP_URL = "http://127.0.0.1:8080"

ZAP_API_KEY = "soc-zap-key"



# Development/single-process job store.

# For production this should eventually move to Redis/database.

ZAP_JOBS: dict[str, dict] = {}





class ZapScanRequest(BaseModel):
    target: str
    scanPolicyName: str = "Dev CICD"
    recurse: bool = True
    inScopeOnly: bool = False
    followRedirects: bool = True





async def zap_get(

    path: str,

    params: dict | None = None,

):

    query = {"apikey": ZAP_API_KEY}



    if params:

        query.update(params)



    async with httpx.AsyncClient(

        timeout=30.0

    ) as client:

        response = await client.get(

            f"{ZAP_URL}{path}",

            params=query,

        )

        response.raise_for_status()

        return response.json()





def validate_target(target: str) -> str:

    target = target.strip()



    parsed = urlparse(target)



    if parsed.scheme not in {"http", "https"}:

        raise HTTPException(

            status_code=400,

            detail="ZAP target must be a full HTTP/HTTPS URL",

        )



    if not parsed.hostname:

        raise HTTPException(

            status_code=400,

            detail="ZAP target must contain a valid hostname",

        )



    return target.rstrip("/")





def get_or_create_assessment(

    db: Session,

    current_user: User,

    target: str,

) -> Assessment:

    assessment = (

        db.query(Assessment)

        .filter(

            Assessment.user_id == current_user.id,

            Assessment.target == target,

        )

        .order_by(

            Assessment.created_at.desc()

        )

        .first()

    )



    if assessment is None:

        assessment = Assessment(

            user_id=current_user.id,

            target=target,

            vapt_status="running",

            vapt_findings_count=0,

            qa_status="not_started",

            qa_score=None,

            monitoring_status="not_started",

            report_status="not_generated",

            overall_status="active",

        )



        db.add(assessment)

        db.commit()

        db.refresh(assessment)



    return assessment





def zap_risk_to_severity(risk: str) -> str:

    risk = (risk or "").upper()



    if risk == "HIGH":

        return "HIGH"



    if risk == "MEDIUM":

        return "MEDIUM"



    if risk == "LOW":

        return "LOW"



    # ZAP Informational does not have a direct equivalent

    # in the existing SecurityFinding severity model.

    return "LOW"





def zap_owasp_category(alert: dict) -> str | None:

    tags = alert.get("tags") or {}



    for key, value in tags.items():

        if key.startswith("OWASP_2025_"):

            return key



    for key, value in tags.items():

        if key.startswith("OWASP_2021_"):

            return key



    for key, value in tags.items():

        if key.startswith("OWASP_2017_"):

            return key



    return None





def alert_identity(alert: dict) -> str:

    return "|".join(

        [

            str(alert.get("pluginId") or ""),

            str(alert.get("name") or alert.get("alert") or ""),

            str(alert.get("url") or ""),

            str(alert.get("param") or ""),

            str(alert.get("evidence") or ""),

        ]

    )





def sync_zap_findings(

    db: Session,

    current_user: User,

    assessment: Assessment,

    alerts: list[dict],

) -> list[SecurityFinding]:



    seed_security_tools(db)



    tool = (

        db.query(SecurityTool)

        .filter(

            SecurityTool.name == "OWASP ZAP"

        )

        .first()

    )



    if tool is None:

        raise HTTPException(

            status_code=500,

            detail="OWASP ZAP is not registered in the security tool catalog",

        )



    created_or_existing: list[SecurityFinding] = []



    for alert in alerts:

        # ZAP Informational alerts are useful in raw scan results,
        # but they are not vulnerability findings and must not affect
        # SecurityFinding severity/risk/report statistics.
        zap_risk = (alert.get("risk") or "").strip().upper()
        if zap_risk == "INFORMATIONAL":
            continue

        title = (

            alert.get("alert")

            or alert.get("name")

            or "OWASP ZAP Finding"

        )



        affected_url = alert.get("url")

        parameter = alert.get("param") or None

        evidence = alert.get("evidence") or None

        description = alert.get("description") or None

        remediation = alert.get("solution") or None

        references = alert.get("reference") or None



        cwe_id = alert.get("cweid")

        if cwe_id in {None, "", "-1"}:

            cwe_id = None

        elif not str(cwe_id).upper().startswith("CWE-"):

            cwe_id = f"CWE-{cwe_id}"



        owasp_category = zap_owasp_category(alert)



        severity = zap_risk_to_severity(

            alert.get("risk")

        )



        risk_level = calculate_risk_level(

            severity

        )



        # Prevent duplicate ZAP findings when the

        # results endpoint is requested more than once.

        existing_findings = (

            db.query(SecurityFinding)

            .filter(

                SecurityFinding.assessment_id

                == assessment.id,



                SecurityFinding.user_id

                == current_user.id,



                SecurityFinding.tool_name

                == tool.name,



                SecurityFinding.title

                == title,



                SecurityFinding.affected_url

                == affected_url,



                SecurityFinding.parameter

                == parameter,

            )

            .all()

        )



        existing = None



        for item in existing_findings:

            if (

                (item.evidence or "")

                == (evidence or "")

            ):

                existing = item

                break



        now = datetime.utcnow()



        if existing:

            existing.description = description

            existing.cwe_id = cwe_id

            existing.severity = severity

            existing.risk_level = risk_level

            existing.owasp_category = owasp_category

            existing.evidence = evidence

            existing.remediation = remediation

            existing.references = references

            existing.updated_at = now



            created_or_existing.append(existing)

            continue



        finding = SecurityFinding(

            finding_id=generate_finding_id(db),



            user_id=current_user.id,

            assessment_id=assessment.id,



            tool_name=tool.name,

            tool_category=(

                tool.category

                or "Web Application Security"

            ),



            title=title,

            vulnerability=title,

            description=description,



            owasp_category=owasp_category,

            owasp_api_category=None,



            cve_id=None,

            cwe_id=cwe_id,



            cvss_score=None,

            severity=severity,

            risk_level=risk_level,



            affected_asset=affected_url,

            affected_url=affected_url,



            endpoint=affected_url,

            parameter=parameter,



            evidence=evidence,

            request_data=None,

            response_data=None,



            impact=(

                f"ZAP risk: {alert.get('risk')}"

                if alert.get("risk")

                else None

            ),



            remediation=remediation,

            references=references,



            status="OPEN",



            detected_at=now,

            created_at=now,

            updated_at=now,

        )



        db.add(finding)

        db.flush()



        created_or_existing.append(finding)



    assessment.vapt_status = "completed"

    assessment.vapt_findings_count = (

        db.query(SecurityFinding)

        .filter(

            SecurityFinding.assessment_id

            == assessment.id

        )

        .count()

    )

    assessment.overall_status = "active"



    db.commit()



    for finding in created_or_existing:

        db.refresh(finding)



    return created_or_existing





@router.get("/status")

async def zap_status():

    try:

        version = await zap_get(

            "/JSON/core/view/version/"

        )



        return {

            "status": "running",

            "version": version.get("version"),

            "url": ZAP_URL,

        }



    except Exception as exc:

        return {

            "status": "offline",

            "url": ZAP_URL,

            "error": str(exc),

        }





# ============================================================

# COMPLETE ZAP SCAN START

# ============================================================



@router.post("/scan")

async def start_zap_scan(

    request: ZapScanRequest,

    current_user: User = Depends(

        require_role(1)

    ),

    db: Session = Depends(get_db),

):

    target = validate_target(

        request.target

    )



    try:

        # ----------------------------------------------------

        # 1. Access the target through ZAP.

        # This puts the target into ZAP's Sites Tree.

        # ----------------------------------------------------



        access_result = await zap_get(

            "/JSON/core/action/accessUrl/",

            {

                "url": target,

                "followRedirects": str(request.followRedirects).lower(),

            },

        )



        # ----------------------------------------------------

        # 2. Start the active scan.

        # ----------------------------------------------------



        scan_result = await zap_get(

            "/JSON/ascan/action/scan/",

            {

                "url": target,

                "recurse": str(request.recurse).lower(),
                "inScopeOnly": str(request.inScopeOnly).lower(),
                "scanPolicyName": request.scanPolicyName or "Dev CICD",

            },

        )



        scan_id = scan_result.get("scan")



        if scan_id is None:

            raise HTTPException(

                status_code=502,

                detail={

                    "message": "ZAP did not return a scan ID",

                    "zap_response": scan_result,

                },

            )



        assessment = get_or_create_assessment(

            db,

            current_user,

            target,

        )



        ZAP_JOBS[str(scan_id)] = {

            "scan_id": str(scan_id),

            "target": target,

            "user_id": current_user.id,

            "assessment_id": assessment.id,

            "status": "running",

            "access_result": access_result,

            "created_at": datetime.utcnow().isoformat(),

            "results_synced": False,

        }



        return {

            "status": "started",

            "target": target,

            "scan_id": str(scan_id),

            "assessment_id": assessment.id,

        }



    except HTTPException:

        raise



    except Exception as exc:

        raise HTTPException(

            status_code=502,

            detail=f"Unable to start ZAP scan: {exc}",

        )





# ============================================================

# SCAN PROGRESS

# ============================================================



@router.get(

    "/scan/{scan_id}/progress"

)

async def zap_scan_progress(

    scan_id: str,

    current_user: User = Depends(

        require_role(1)

    ),

):

    job = ZAP_JOBS.get(str(scan_id))



    if job and job["user_id"] != current_user.id:

        raise HTTPException(

            status_code=403,

            detail="You do not have access to this ZAP scan",

        )



    try:

        result = await zap_get(

            "/JSON/ascan/view/status/",

            {

                "scanId": scan_id,

            },

        )



        status = int(

            result.get("status", 0)

        )



        if job:

            if status >= 100:

                job["status"] = "completed"

            else:

                job["status"] = "running"



        return {

            "scan_id": str(scan_id),

            "status": status,

            "state": (

                "completed"

                if status >= 100

                else "running"

            ),

        }



    except Exception as exc:

        raise HTTPException(

            status_code=502,

            detail=f"Unable to read ZAP scan progress: {exc}",

        )





# ============================================================

# ============================================================
# SCAN CANCEL
# ============================================================


@router.post("/scan/{scan_id}/cancel")
async def cancel_zap_scan(
    scan_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = ZAP_JOBS.get(str(scan_id))

    if job and job["user_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You do not have access to this ZAP scan",
        )

    try:
        result = await zap_get(
            "/JSON/ascan/action/stop/",
            {"scanId": scan_id},
        )
        if job:
            job["status"] = "cancelled"
            job["cancelled_at"] = datetime.utcnow().isoformat()
        return {
            "status": "cancelled",
            "scan_id": str(scan_id),
            "zap_response": result,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Unable to cancel ZAP scan: {exc}",
        )


# SCAN RESULTS + SECURITY FINDING SYNC

# ============================================================



@router.get(

    "/scan/{scan_id}/results"

)

async def zap_scan_results(

    scan_id: str,

    current_user: User = Depends(

        require_role(1)

    ),

    db: Session = Depends(get_db),

):

    job = ZAP_JOBS.get(str(scan_id))



    if not job:

        raise HTTPException(

            status_code=404,

            detail=(

                "ZAP scan was not found in the "

                "current backend session"

            ),

        )



    if job["user_id"] != current_user.id:

        raise HTTPException(

            status_code=403,

            detail="You do not have access to this ZAP scan",

        )



    try:

        progress = await zap_get(

            "/JSON/ascan/view/status/",

            {

                "scanId": scan_id,

            },

        )



        status = int(

            progress.get("status", 0)

        )



        if status < 100:

            return {

                "status": "running",

                "scan_id": str(scan_id),

                "progress": status,

                "target": job["target"],

                "alerts": [],

            }



        alert_result = await zap_get(

            "/JSON/core/view/alerts/",

            {

                "start": "0",

                "count": "9999",

                "baseurl": job["target"],

            },

        )



        alerts = alert_result.get(

            "alerts",

            [],

        )



        assessment = (

            db.query(Assessment)

            .filter(

                Assessment.id

                == job["assessment_id"],



                Assessment.user_id

                == current_user.id,

            )

            .first()

        )



        if not assessment:

            raise HTTPException(

                status_code=404,

                detail="ZAP assessment not found",

            )



        findings = sync_zap_findings(

            db,

            current_user,

            assessment,

            alerts,

        )



        job["status"] = "completed"

        job["results_synced"] = True



        return {

            "status": "completed",

            "scan_id": str(scan_id),

            "target": job["target"],

            "assessment_id": assessment.id,

            "progress": 100,

            "total_alerts": len(alerts),

            "total_findings": len(findings),

            "alerts": alerts,

            "findings": [

                {

                    "id": finding.id,

                    "finding_id": finding.finding_id,

                    "title": finding.title,

                    "severity": finding.severity,

                    "risk_level": finding.risk_level,

                    "tool_name": finding.tool_name,

                    "cwe_id": finding.cwe_id,

                    "affected_url": finding.affected_url,

                    "parameter": finding.parameter,

                    "evidence": finding.evidence,

                    "description": finding.description,

                    "remediation": finding.remediation,

                    "owasp_category": finding.owasp_category,

                    "status": finding.status,

                }

                for finding in findings

            ],

        }



    except HTTPException:

        raise



    except Exception as exc:

        raise HTTPException(

            status_code=502,

            detail=f"Unable to retrieve ZAP results: {exc}",

        )





# ============================================================

# EXISTING COMPATIBILITY ENDPOINTS

# ============================================================



@router.post("/active-scan")

async def start_zap_active_scan(

    request: ZapScanRequest,

):

    target = validate_target(

        request.target

    )



    try:

        result = await zap_get(

            "/JSON/ascan/action/scan/",

            {

                "url": target,

                "recurse": "true",

                "inScopeOnly": "false",

                "scanPolicyName": "Dev CICD",

            },

        )



        return {

            "status": "started",

            "target": target,

            "scan_id": result.get("scan"),

        }



    except Exception as exc:

        raise HTTPException(

            status_code=502,

            detail=f"Unable to start ZAP active scan: {exc}",

        )





@router.get(

    "/active-scan/{scan_id}/progress"

)

async def zap_active_progress(

    scan_id: str,

):

    return await zap_get(

        "/JSON/ascan/view/status/",

        {

            "scanId": scan_id,

        },

    )





@router.get("/alerts")

async def zap_alerts(

    target: str | None = None,

):

    params = {

        "start": "0",

        "count": "9999",

    }



    if target:

        params["baseurl"] = target



    return await zap_get(

        "/JSON/core/view/alerts/",

        params,

    )





@router.post(

    "/active-scan/{scan_id}/stop"

)

async def stop_zap_active_scan(

    scan_id: str,

):

    return await zap_get(

        "/JSON/ascan/action/stop/",

        {

            "scanId": scan_id,

        },

    )





# Legacy spider endpoints retained for compatibility.



@router.post("/spider")

async def start_zap_spider(

    request: ZapScanRequest,

):

    target = validate_target(

        request.target

    )



    try:

        result = await zap_get(

            "/JSON/spider/action/scan/",

            {

                "url": target,

                "recurse": "true",

            },

        )



        return {

            "status": "started",

            "target": target,

            "spider_id": result.get("scan"),

        }



    except Exception as exc:
        raise HTTPException(

            status_code=502,

            detail=f"Unable to start ZAP spider: {exc}",

        )
@router.get(

    "/spider/{scan_id}/progress"

)

async def zap_spider_progress(

    scan_id: str,

):

    return await zap_get(

        "/JSON/spider/view/status/",

        {

            "scanId": scan_id,

        },

    )
