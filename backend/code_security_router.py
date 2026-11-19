from __future__ import annotations

import asyncio
from datetime import datetime
import json
import shutil
import stat
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from database import SessionLocal, get_db
from models import Assessment, SecurityFinding, SecurityTool, User
from rbac import require_role
from security_findings import calculate_risk_level, calculate_severity, generate_finding_id


router = APIRouter(
    prefix="/code-security",
    tags=["Code Security"],
)


# Semgrep is deliberately kept outside the backend venv.
SEMGREP_BIN = Path.home() / "SOC-Platform" / "semgrep-venv" / "bin" / "semgrep"
GITLEAKS_BIN = shutil.which("gitleaks") or "/usr/bin/gitleaks"
TRIVY_BIN = shutil.which("trivy") or "/usr/bin/trivy"

MAX_UPLOAD_SIZE = 50 * 1024 * 1024
MAX_EXTRACTED_SIZE = 200 * 1024 * 1024

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".go": "go",
    ".rb": "ruby",
    ".kt": "kotlin",
    ".swift": "swift",
    ".rs": "rust",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
}

CODE_EXTENSIONS = set(LANGUAGE_EXTENSIONS)


# In-process job store, following the existing VAPT job pattern.
CODE_SECURITY_JOBS: dict[str, dict[str, Any]] = {}


def _new_job(user_id: int, filename: str) -> str:
    job_id = str(uuid.uuid4())

    CODE_SECURITY_JOBS[job_id] = {
        "job_id": job_id,
        "user_id": user_id,
        "filename": filename,
        "status": "queued",
        "progress": 0,
        "stage": "Queued",
        "message": "Code security scan queued",
        "result": None,
        "error": None,
        "created_at": time.time(),
        "updated_at": time.time(),
    }

    return job_id


def _update_job(
    job_id: str,
    *,
    status: str | None = None,
    progress: int | None = None,
    stage: str | None = None,
    message: str | None = None,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    job = CODE_SECURITY_JOBS.get(job_id)

    if not job:
        return

    if status is not None:
        job["status"] = status

    if progress is not None:
        job["progress"] = max(0, min(100, int(progress)))

    if stage is not None:
        job["stage"] = stage

    if message is not None:
        job["message"] = message

    if result is not None:
        job["result"] = result

    if error is not None:
        job["error"] = error

    job["updated_at"] = time.time()


def _safe_extract(zip_path: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()

    with zipfile.ZipFile(zip_path) as archive:
        total_size = 0

        for member in archive.infolist():
            filename = member.filename

            # Reject absolute paths and traversal before resolving.
            member_path = Path(filename)
            if member_path.is_absolute():
                raise ValueError("Unsafe absolute ZIP path detected")

            # ZIP symlinks can escape the extraction directory after
            # extraction. Reject them instead of following them.
            mode = (member.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ValueError("Unsafe ZIP symlink detected")

            if member.is_dir():
                target_dir = (destination / filename).resolve()
                if (
                    target_dir != destination_resolved
                    and destination_resolved not in target_dir.parents
                ):
                    raise ValueError("Unsafe ZIP path detected")
                continue

            total_size += member.file_size

            if total_size > MAX_EXTRACTED_SIZE:
                raise ValueError("Extracted project exceeds the 200 MB limit")

            target = (destination / filename).resolve()

            if (
                target != destination_resolved
                and destination_resolved not in target.parents
            ):
                raise ValueError("Unsafe ZIP path detected")

            target.parent.mkdir(parents=True, exist_ok=True)

            with archive.open(member, "r") as source, target.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)


def _detect_languages(root: Path) -> dict[str, int]:
    languages: dict[str, int] = {}

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        language = LANGUAGE_EXTENSIONS.get(path.suffix.lower())

        if language:
            languages[language] = languages.get(language, 0) + 1

    return languages


def _relative_code_path(path_value: str, project_dir: Path) -> str:
    """Return a safe project-relative path for a scanner result."""
    try:
        return str(
            Path(path_value).resolve().relative_to(project_dir.resolve())
        )
    except (ValueError, OSError):
        return Path(path_value).name


def _get_or_create_code_assessment(
    db: Session,
    user_id: int,
    original_filename: str,
) -> Assessment:
    target = f"code://{Path(original_filename).name}"

    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.user_id == user_id,
            Assessment.target == target,
        )
        .order_by(Assessment.created_at.desc())
        .first()
    )

    if assessment is None:
        now = datetime.utcnow()

        assessment = Assessment(
            user_id=user_id,
            target=target,
            vapt_status="running",
            vapt_findings_count=0,
            qa_status="not_started",
            qa_score=None,
            monitoring_status="not_started",
            report_status="not_generated",
            overall_status="active",
            created_at=now,
            updated_at=now,
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

    return assessment


def _persist_code_findings(
    db: Session,
    user_id: int,
    assessment: Assessment,
    project_dir: Path,
    semgrep_results: list[dict[str, Any]],
    gitleaks_results: list[dict[str, Any]],
    trivy_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []

    def add_finding(
        *,
        tool_name: str,
        title: str,
        vulnerability: str,
        description: str,
        severity: str,
        affected_asset: str,
        endpoint: str | None,
        evidence: dict[str, Any],
        remediation: str,
        impact: str,
        owasp_category: str | None = None,
        cwe_id: str | None = None,
        cve_id: str | None = None,
        references: str | None = None,
        cvss_score: float | None = None,
    ) -> None:
        risk_level = calculate_risk_level(severity)

        safe_evidence = json.dumps(
            evidence,
            ensure_ascii=False,
        )

        existing = (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.user_id == user_id,
                SecurityFinding.assessment_id == assessment.id,
                SecurityFinding.tool_name == tool_name,
                SecurityFinding.affected_asset == affected_asset,
                SecurityFinding.endpoint == endpoint,
                SecurityFinding.title == title,
            )
            .first()
        )

        now = datetime.utcnow()

        if existing:
            existing.description = description
            existing.vulnerability = vulnerability
            existing.severity = severity
            existing.risk_level = risk_level
            existing.cvss_score = cvss_score
            existing.evidence = safe_evidence
            existing.impact = impact
            existing.remediation = remediation
            existing.owasp_category = owasp_category
            existing.cwe_id = cwe_id
            existing.cve_id = cve_id
            existing.references = references
            existing.updated_at = now
            finding_id = existing.finding_id
        else:
            finding = SecurityFinding(
                finding_id=f"FIND-PENDING-{uuid.uuid4().hex}",
                user_id=user_id,
                assessment_id=assessment.id,
                tool_name=tool_name,
                tool_category="Code Security",
                title=title[:500],
                vulnerability=vulnerability[:500],
                description=description,
                owasp_category=owasp_category,
                cve_id=cve_id,
                cwe_id=cwe_id,
                cvss_score=cvss_score,
                severity=severity,
                risk_level=risk_level,
                affected_asset=affected_asset,
                affected_url=None,
                endpoint=endpoint,
                parameter=None,
                evidence=safe_evidence,
                request_data=None,
                response_data=None,
                impact=impact,
                remediation=remediation,
                references=references,
                status="OPEN",
                detected_at=now,
                created_at=now,
                updated_at=now,
            )
            db.add(finding)
            db.flush()

            # PostgreSQL assigns the authoritative integer primary key.
            # Derive the public finding ID from that committed-row identity
            # instead of querying the latest row while multiple findings are
            # still pending in the same transaction.
            finding.finding_id = f"FIND-{finding.id:06d}"
            finding_id = finding.finding_id

        normalized.append(
            {
                "finding_id": finding_id,
                "tool_name": tool_name,
                "title": title,
                "severity": severity,
                "risk_level": risk_level,
                "affected_asset": affected_asset,
                "endpoint": endpoint,
            }
        )

    for item in semgrep_results:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}

        path_value = str(item.get("path") or "")
        relative_path = _relative_code_path(
            path_value,
            project_dir,
        )

        start = item.get("start") or {}
        line = start.get("line")

        check_id = str(
            item.get("check_id")
            or "semgrep-finding"
        )

        message = str(
            extra.get("message")
            or check_id
        ).strip()

        tool_severity = str(
            extra.get("severity")
            or "WARNING"
        ).upper()

        severity_map = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }
        severity = severity_map.get(
            tool_severity,
            "MEDIUM",
        )

        owasp = metadata.get("owasp")
        if isinstance(owasp, list):
            owasp = ", ".join(str(value) for value in owasp)
        elif owasp is not None:
            owasp = str(owasp)

        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(str(value) for value in cwe)
        elif cwe is not None:
            cwe = str(cwe)

        cve = metadata.get("cve")
        if isinstance(cve, list):
            cve = ", ".join(str(value) for value in cve)
        elif cve is not None:
            cve = str(cve)

        references = metadata.get("references")
        if isinstance(references, list):
            references = "\n".join(str(value) for value in references)
        elif references is not None:
            references = str(references)

        endpoint = (
            f"{relative_path}:{line}"
            if line is not None
            else relative_path
        )

        code_snippet = extra.get("lines")
        if not isinstance(code_snippet, str) or not code_snippet.strip():
            code_snippet = (
                "Source snippet was not provided by the Semgrep result."
            )
        elif code_snippet.strip().lower() in {
            "requires login",
            "requires authentication",
        }:
            code_snippet = (
                "Source snippet was not provided by the Semgrep result."
            )

        evidence = {
            "file_path": relative_path,
            "line_start": start.get("line"),
            "line_end": (item.get("end") or {}).get("line"),
            "language": LANGUAGE_EXTENSIONS.get(
                Path(relative_path).suffix.lower()
            ),
            "rule_id": check_id,
            "code_snippet": code_snippet,
        }

        semgrep_fix = extra.get("fix")
        if not isinstance(semgrep_fix, str) or not semgrep_fix.strip():
            semgrep_fix = metadata.get("fix")

        if (
            not isinstance(semgrep_fix, str)
            or not semgrep_fix.strip()
            or semgrep_fix.strip().lower() in {"false", "none", "null"}
        ):
            semgrep_fix = (
                "Review the Semgrep finding and apply a secure coding fix."
            )

        semgrep_impact = metadata.get("impact")
        if (
            not isinstance(semgrep_impact, str)
            or not semgrep_impact.strip()
            or semgrep_impact.strip().upper() in {
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
                "WARNING",
                "ERROR",
                "INFO",
            }
        ):
            semgrep_impact = (
                "The identified code pattern may introduce a security weakness."
            )

        add_finding(
            tool_name="Semgrep",
            title=message.splitlines()[0][:500],
            vulnerability=check_id,
            description=message,
            severity=severity,
            affected_asset=relative_path,
            endpoint=endpoint,
            evidence=evidence,
            remediation=semgrep_fix,
            impact=semgrep_impact,
            owasp_category=owasp,
            cwe_id=cwe,
            cve_id=cve,
            references=references,
        )

    for item in gitleaks_results:
        file_value = str(item.get("File") or "")
        relative_path = _relative_code_path(
            file_value,
            project_dir,
        )

        start_line = item.get("StartLine")
        end_line = item.get("EndLine")

        rule_id = str(
            item.get("RuleID")
            or "secret-exposure"
        )

        description = str(
            item.get("Description")
            or "Potential exposed secret detected"
        )

        endpoint = (
            f"{relative_path}:{start_line}"
            if start_line is not None
            else relative_path
        )

        # Never persist the actual secret or Match value.
        evidence = {
            "file_path": relative_path,
            "line_start": start_line,
            "line_end": end_line,
            "rule_id": rule_id,
            "description": description,
            "secret_value_stored": False,
        }

        add_finding(
            tool_name="Gitleaks",
            title=description[:500],
            vulnerability="Secret Exposure",
            description=description,
            severity="HIGH",
            affected_asset=relative_path,
            endpoint=endpoint,
            evidence=evidence,
            remediation=(
                "Rotate/revoke the exposed secret, remove it from source "
                "history, and use a managed secret store."
            ),
            impact=(
                "An exposed credential or secret may allow unauthorized "
                "access to systems or services."
            ),
        )

    for item in trivy_results:
        vulnerability_id = str(
            item.get("VulnerabilityID") or "dependency-vulnerability"
        )
        package_name = str(
            item.get("PkgName") or item.get("PkgID") or "unknown-package"
        )
        installed_version = str(
            item.get("InstalledVersion") or "unknown"
        )
        fixed_version = str(
            item.get("FixedVersion") or ""
        )

        trivy_severity = str(
            item.get("Severity") or "MEDIUM"
        ).upper()

        cvss_score = None
        cvss_data = item.get("CVSS") or {}

        for source_data in cvss_data.values():
            if not isinstance(source_data, dict):
                continue

            for key in ("V3Score", "V40Score"):
                value = source_data.get(key)
                if isinstance(value, (int, float)):
                    cvss_score = float(value)
                    break

            if cvss_score is not None:
                break

        if cvss_score is not None:
            severity = calculate_severity(cvss_score)
        else:
            severity_map = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
                "UNKNOWN": "LOW",
            }
            severity = severity_map.get(trivy_severity, "MEDIUM")

        title = str(
            item.get("Title")
            or f"{vulnerability_id}: {package_name}"
        ).splitlines()[0][:500]

        description = str(
            item.get("Description")
            or title
        )

        references_value = item.get("References") or []
        if isinstance(references_value, list):
            references = "\n".join(
                str(value) for value in references_value
            )
        else:
            references = str(references_value)

        cwe_ids = item.get("CweIDs") or []
        if isinstance(cwe_ids, list):
            cwe_id = ", ".join(str(value) for value in cwe_ids)
        else:
            cwe_id = str(cwe_ids) if cwe_ids else None

        cve_id = (
            vulnerability_id
            if vulnerability_id.upper().startswith("CVE-")
            else None
        )

        manifest_path = str(
            item.get("Target")
            or item.get("Class")
            or "dependency-manifest"
        )

        endpoint = f"{package_name}@{installed_version}"

        evidence = {
            "manifest": manifest_path,
            "package": package_name,
            "installed_version": installed_version,
            "fixed_version": fixed_version or None,
            "vulnerability_id": vulnerability_id,
            "trivy_severity": trivy_severity,
            "cvss_score": cvss_score,
            "status": item.get("Status"),
            "primary_url": item.get("PrimaryURL"),
        }

        remediation = (
            f"Upgrade {package_name} from {installed_version} "
            f"to {fixed_version} or later."
            if fixed_version
            else (
                f"Review and remediate {package_name}@"
                f"{installed_version} using the advisory guidance."
            )
        )

        impact = (
            f"The vulnerable dependency {package_name}@"
            f"{installed_version} is affected by {vulnerability_id}."
        )

        add_finding(
            tool_name="Trivy",
            title=title,
            vulnerability=vulnerability_id,
            description=description,
            severity=severity,
            affected_asset=manifest_path,
            endpoint=endpoint,
            evidence=evidence,
            remediation=remediation,
            impact=impact,
            cwe_id=cwe_id,
            cve_id=cve_id,
            references=references or None,
            cvss_score=cvss_score,
        )

    db.flush()

    assessment.vapt_findings_count = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.assessment_id == assessment.id
        )
        .count()
    )

    assessment.vapt_status = "completed"
    assessment.overall_status = "active"
    assessment.updated_at = datetime.utcnow()

    db.commit()

    return normalized


async def _run_code_security_job(
    job_id: str,
    user_id: int,
    upload_path: Path,
    original_filename: str,
) -> None:
    try:
        _update_job(
            job_id,
            status="running",
            progress=5,
            stage="VALIDATING",
            message="Validating uploaded project",
        )

        with tempfile.TemporaryDirectory(
            prefix=f"soc-code-{user_id}-"
        ) as temp_dir:
            workspace = Path(temp_dir)
            project_dir = workspace / "project"
            project_dir.mkdir()

            if upload_path.suffix.lower() == ".zip":
                _safe_extract(upload_path, project_dir)
            else:
                target_file = project_dir / Path(original_filename).name
                shutil.copy2(upload_path, target_file)

            _update_job(
                job_id,
                progress=20,
                stage="LANGUAGE DETECTION",
                message="Detecting supported source files",
            )

            languages = _detect_languages(project_dir)

            if not languages:
                raise ValueError(
                    "No supported source files were found in the upload"
                )

            _update_job(
                job_id,
                progress=30,
                stage="SAST",
                message="Running Semgrep static analysis",
            )

            semgrep_results: list[dict[str, Any]] = []

            if SEMGREP_BIN.exists():
                semgrep_configs = {
                    "python": "p/python",
                    "javascript": "p/javascript",
                    "typescript": "p/typescript",
                }

                for language in sorted(languages):
                    config = semgrep_configs.get(language)

                    if not config:
                        continue

                    output_file = workspace / f"semgrep-{language}.json"

                    command = [
                        str(SEMGREP_BIN),
                        "scan",
                        "--config",
                        config,
                        "--json",
                        "--output",
                        str(output_file),
                        str(project_dir),
                    ]

                    process = await asyncio.create_subprocess_exec(
                        *command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

                    _, stderr = await process.communicate()

                    if output_file.exists():
                        try:
                            parsed = json.loads(
                                output_file.read_text(
                                    encoding="utf-8",
                                    errors="replace",
                                )
                            )
                            semgrep_results.extend(
                                parsed.get("results", [])
                            )
                        except json.JSONDecodeError:
                            pass

                    if process.returncode not in (0, 1, 2):
                        raise RuntimeError(
                            f"Semgrep failed for {language}: "
                            f"{stderr.decode(errors='replace')[:500]}"
                        )

            _update_job(
                job_id,
                progress=50,
                stage="DEPENDENCY SCAN",
                message="Scanning project dependencies for known vulnerabilities",
            )

            trivy_results: list[dict[str, Any]] = []

            if Path(TRIVY_BIN).exists():
                trivy_output = workspace / "trivy.json"

                command = [
                    TRIVY_BIN,
                    "fs",
                    "--scanners",
                    "vuln",
                    "--format",
                    "json",
                    "--output",
                    str(trivy_output),
                    "--exit-code",
                    "0",
                    "--skip-db-update",
                    str(project_dir),
                ]

                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await process.communicate()

                if process.returncode != 0:
                    raise RuntimeError(
                        "Trivy dependency scan failed: "
                        f"{stderr.decode(errors='replace')[:500]}"
                    )

                if trivy_output.exists():
                    try:
                        parsed = json.loads(
                            trivy_output.read_text(
                                encoding="utf-8",
                                errors="replace",
                            )
                        )

                        for result_item in parsed.get("Results", []):
                            vulnerabilities = (
                                result_item.get("Vulnerabilities") or []
                            )

                            target = result_item.get("Target")

                            for vulnerability in vulnerabilities:
                                if target:
                                    vulnerability = dict(vulnerability)
                                    vulnerability["Target"] = target

                                trivy_results.append(vulnerability)

                    except json.JSONDecodeError as exc:
                        raise RuntimeError(
                            f"Invalid Trivy JSON output: {exc}"
                        ) from exc

            _update_job(
                job_id,
                progress=65,
                stage="SECRET SCAN",
                message="Scanning for exposed secrets",
            )

            gitleaks_results: list[dict[str, Any]] = []

            if shutil.which("gitleaks"):
                gitleaks_output = workspace / "gitleaks.json"

                command = [
                    GITLEAKS_BIN,
                    "dir",
                    str(project_dir),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(gitleaks_output),
                    "--exit-code",
                    "0",
                ]

                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                await process.communicate()

                if gitleaks_output.exists():
                    try:
                        parsed = json.loads(
                            gitleaks_output.read_text(
                                encoding="utf-8",
                                errors="replace",
                            )
                        )

                        if isinstance(parsed, list):
                            gitleaks_results = parsed
                    except json.JSONDecodeError:
                        gitleaks_results = []

            _update_job(
                job_id,
                progress=85,
                stage="NORMALIZING",
                message="Normalizing security findings",
            )

            db = SessionLocal()

            try:
                assessment = _get_or_create_code_assessment(
                    db=db,
                    user_id=user_id,
                    original_filename=original_filename,
                )

                normalized_findings = _persist_code_findings(
                    db=db,
                    user_id=user_id,
                    assessment=assessment,
                    project_dir=project_dir,
                    semgrep_results=semgrep_results,
                    gitleaks_results=gitleaks_results,
                    trivy_results=trivy_results,
                )

                result = {
                    "filename": original_filename,
                    "assessment_id": assessment.id,
                    "languages": languages,
                    "findings": normalized_findings,
                    "finding_count": len(normalized_findings),
                    "persisted_findings_count": assessment.vapt_findings_count,
                }

            finally:
                db.close()

            _update_job(
                job_id,
                status="completed",
                progress=100,
                stage="COMPLETED",
                message="Code security scan completed",
                result=result,
            )

    except Exception as exc:
        _update_job(
            job_id,
            status="failed",
            progress=100,
            stage="FAILED",
            message="Code security scan failed",
            error=str(exc),
        )

    finally:
        try:
            upload_path.unlink(missing_ok=True)
        except Exception:
            pass


@router.post("/scan")
async def start_code_security_scan(
    file: UploadFile = File(...),
    current_user: User = Depends(require_role(1)),
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="A file is required",
        )

    suffix = Path(file.filename).suffix.lower()

    if suffix not in CODE_EXTENSIONS and suffix != ".zip":
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. Upload a supported source file "
                "or a ZIP project."
            ),
        )

    upload_dir = Path(
        tempfile.mkdtemp(prefix=f"soc-upload-{current_user.id}-")
    )

    upload_path = upload_dir / Path(file.filename).name

    try:
        size = 0

        with upload_path.open("wb") as destination:
            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                size += len(chunk)

                if size > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Upload exceeds the 50 MB limit",
                    )

                destination.write(chunk)

        job_id = _new_job(
            current_user.id,
            file.filename,
        )

        asyncio.create_task(
            _run_code_security_job(
                job_id,
                current_user.id,
                upload_path,
                file.filename,
            )
        )

        return {
            "job_id": job_id,
            "status": "queued",
            "progress": 0,
            "stage": "Queued",
        }

    except HTTPException:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise

    except Exception as exc:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(
            status_code=500,
            detail=f"Unable to start code security scan: {exc}",
        )


@router.get("/progress/{job_id}")
async def get_code_security_progress(
    job_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = CODE_SECURITY_JOBS.get(job_id)

    if not job or job["user_id"] != current_user.id:
        raise HTTPException(
            status_code=404,
            detail="Code security job not found",
        )

    return job


@router.get("/secrets-registry")
def secrets_registry(
    category: str = "all",
    search: str = "",
    offset: int = 0,
    page_size: int = 25,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Personal-user-scoped Gitleaks metadata; no raw finding evidence returned."""
    from sqlalchemy import func
    from secrets_metadata import CATEGORIES, secret_metadata

    if category not in ("all", *CATEGORIES):
        raise HTTPException(status_code=422, detail="Unsupported secret category")
    if len(search) > 200 or offset < 0 or not 1 <= page_size <= 100:
        raise HTTPException(status_code=422, detail="Invalid search or pagination")

    query = db.query(
        SecurityFinding.id,
        SecurityFinding.assessment_id,
        SecurityFinding.evidence,
        SecurityFinding.severity,
        SecurityFinding.status,
    ).filter(
        SecurityFinding.user_id == current_user.id,
        func.lower(SecurityFinding.tool_name) == "gitleaks",
    ).order_by(SecurityFinding.id.desc())

    totals = {name: 0 for name in CATEGORIES}
    total = 0
    matched = 0
    high_critical = 0
    page = []
    needle = search.strip().casefold()

    for item in query.yield_per(200):
        row = secret_metadata(item)
        total += 1
        totals[row["category"]] += 1
        high_critical += row["severity"] in {"HIGH", "CRITICAL"}

        if category != "all" and row["category"] != category:
            continue
        if needle and needle not in json.dumps(row, ensure_ascii=False).casefold():
            continue

        if offset <= matched < offset + page_size:
            page.append(row)
        matched += 1

    return {
        "scope": "personal",
        "total": total,
        "high_critical": high_critical,
        "by_category": totals,
        "matched_total": matched,
        "offset": offset,
        "next_offset": (
            offset + page_size if offset + page_size < matched else None
        ),
        "findings": page,
    }
