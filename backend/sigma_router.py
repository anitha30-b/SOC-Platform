from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query

from rbac import require_role
from sigma_evaluator import get_rule_execution_support

router = APIRouter(prefix="/sigma", tags=["Sigma Rules"])

RULE_DIR = Path(__file__).resolve().parent / "sigma_rules"
REQUIRED_FIELDS = {
    "title", "id", "status", "description",
    "logsource", "detection", "level",
}
VALID_LEVELS = {
    "informational", "low", "medium", "high", "critical",
}


def validate_rule(rule):
    errors = []

    if not isinstance(rule, dict):
        return ["YAML document must contain a mapping/object."]

    missing = REQUIRED_FIELDS - rule.keys()
    if missing:
        errors.append(f"Missing required fields: {', '.join(sorted(missing))}")

    for field in ("title", "id", "status", "description"):
        if field in rule and (
            not isinstance(rule[field], str) or not rule[field].strip()
        ):
            errors.append(f"{field} must be a non-empty string.")

    if "logsource" in rule and not isinstance(rule["logsource"], dict):
        errors.append("logsource must be a mapping/object.")

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        errors.append("detection must be a mapping/object.")
    else:
        if not isinstance(detection.get("condition"), str) or not detection["condition"].strip():
            errors.append("detection.condition must be a non-empty string.")
        selectors = [key for key in detection if key != "condition"]
        if not selectors:
            errors.append("detection must contain at least one selector.")

    level = rule.get("level")
    if isinstance(level, str) and level.lower() not in VALID_LEVELS:
        errors.append(f"Unsupported level: {level}")

    if "tags" in rule and not isinstance(rule["tags"], list):
        errors.append("tags must be a list when provided.")

    return errors


def read_rule_file(path):
    try:
        content = path.read_text(encoding="utf-8")
        rule = yaml.safe_load(content)
        errors = validate_rule(rule)
    except (OSError, yaml.YAMLError) as exc:
        content = ""
        rule = None
        errors = [f"Unable to read or parse YAML: {exc}"]

    return content, rule, errors


def list_rule_records():
    records = []
    if not RULE_DIR.is_dir():
        return records

    paths = sorted(
        list(RULE_DIR.glob("*.yml")) + list(RULE_DIR.glob("*.yaml"))
    )

    seen_ids = set()
    for path in paths:
        content, rule, errors = read_rule_file(path)
        rule_id = rule.get("id") if isinstance(rule, dict) else None

        if not isinstance(rule_id, str) or not rule_id.strip():
            rule_id = path.stem

        if rule_id in seen_ids:
            errors.append("Duplicate rule ID in the Sigma library.")
        seen_ids.add(rule_id)

        records.append({
            "rule_id": rule_id,
            "title": rule.get("title", path.stem) if isinstance(rule, dict) else path.stem,
            "description": rule.get("description", "") if isinstance(rule, dict) else "",
            "status": rule.get("status", "unknown") if isinstance(rule, dict) else "invalid",
            "level": rule.get("level", "unknown") if isinstance(rule, dict) else "unknown",
            "logsource": rule.get("logsource", {}) if isinstance(rule, dict) else {},
            "tags": rule.get("tags", []) if isinstance(rule, dict) else [],
            "filename": path.name,
            "validation_status": "VALID" if not errors else "INVALID",
            "validation_errors": errors,
            "integration_status": "LIBRARY_ONLY",
            "live_detection_enabled": False,
        })

    # Detect duplicate IDs in all records, including the first duplicate.
    id_counts = {}
    for record in records:
        id_counts[record["rule_id"]] = id_counts.get(record["rule_id"], 0) + 1
    for record in records:
        if id_counts[record["rule_id"]] > 1:
            record["validation_status"] = "INVALID"
            if "Duplicate rule ID in the Sigma library." not in record["validation_errors"]:
                record["validation_errors"].append(
                    "Duplicate rule ID in the Sigma library."
                )

    # Derive execution status only after validation and duplicate-ID checks.
    for record in records:
        _, rule, _ = read_rule_file(RULE_DIR / record["filename"])
        support = get_rule_execution_support(rule)
        enabled = (
            record["validation_status"] == "VALID"
            and support["supported"]
        )
        record["execution_supported"] = support["supported"]
        record["execution_note"] = support["reason"]
        record["live_detection_enabled"] = enabled

        if record["validation_status"] != "VALID":
            record["integration_status"] = "INVALID"
        elif enabled:
            record["integration_status"] = "LIVE_ENABLED"
        else:
            record["integration_status"] = "LIBRARY_ONLY"

    return records


@router.get("/rules")
def get_sigma_rules(
    search: str | None = Query(None, max_length=200),
    severity: str | None = Query(None, max_length=30),
    status: str | None = Query(None, max_length=30),
    current_user=Depends(require_role(1)),
):
    """List stored Sigma rules and their validation/integration status."""
    all_records = list_rule_records()
    live_enabled_rule_count = sum(
        1 for record in all_records if record["live_detection_enabled"]
    )
    total_rule_count = len(all_records)
    records = all_records

    if search and search.strip():
        term = search.strip().casefold()
        records = [
            record for record in records
            if term in " ".join((
                record["rule_id"],
                record["title"],
                record["description"],
                record["filename"],
                str(record["logsource"]),
                " ".join(map(str, record["tags"])),
            )).casefold()
        ]

    if severity and severity.strip().upper() not in {"ALL", "ANY"}:
        selected = severity.strip().casefold()
        records = [
            record for record in records
            if str(record["level"]).casefold() == selected
        ]

    if status and status.strip().upper() not in {"ALL", "ANY"}:
        selected = status.strip().upper()
        records = [
            record for record in records
            if record["validation_status"] == selected
        ]

    return {
        "count": len(records),
        "rules": records,
        "execution_mode": (
            "LIVE_EVALUATION"
            if live_enabled_rule_count == total_rule_count and total_rule_count > 0
            else "PARTIAL_LIVE"
            if live_enabled_rule_count > 0
            else "LIBRARY_ONLY"
        ),
        "live_detection_enabled": live_enabled_rule_count > 0,
        "live_enabled_rule_count": live_enabled_rule_count,
        "total_rule_count": total_rule_count,
    }


@router.get("/rules/{rule_id}")
def get_sigma_rule(
    rule_id: str,
    current_user=Depends(require_role(1)),
):
    """Return a stored Sigma rule and its YAML source."""
    for path in RULE_DIR.glob("*.yml"):
        content, rule, errors = read_rule_file(path)
        if isinstance(rule, dict) and rule.get("id") == rule_id:
            execution_record = next(
                (
                    record for record in list_rule_records()
                    if record["rule_id"] == rule_id
                ),
                None,
            )
            return {
                "rule": rule,
                "filename": path.name,
                "yaml": content,
                "validation_status": (
                    execution_record["validation_status"]
                    if execution_record else "INVALID"
                ),
                "validation_errors": (
                    execution_record["validation_errors"]
                    if execution_record else errors
                ),
                "integration_status": (
                    execution_record["integration_status"]
                    if execution_record else "LIBRARY_ONLY"
                ),
                "live_detection_enabled": bool(
                    execution_record and execution_record["live_detection_enabled"]
                ),
                "execution_note": (
                    execution_record.get("execution_note", "")
                    if execution_record else "Execution metadata unavailable."
                ),
            }

    for path in RULE_DIR.glob("*.yaml"):
        content, rule, errors = read_rule_file(path)
        if isinstance(rule, dict) and rule.get("id") == rule_id:
            execution_record = next(
                (
                    record for record in list_rule_records()
                    if record["rule_id"] == rule_id
                ),
                None,
            )
            return {
                "rule": rule,
                "filename": path.name,
                "yaml": content,
                "validation_status": (
                    execution_record["validation_status"]
                    if execution_record else "INVALID"
                ),
                "validation_errors": (
                    execution_record["validation_errors"]
                    if execution_record else errors
                ),
                "integration_status": (
                    execution_record["integration_status"]
                    if execution_record else "LIBRARY_ONLY"
                ),
                "live_detection_enabled": bool(
                    execution_record and execution_record["live_detection_enabled"]
                ),
                "execution_note": (
                    execution_record.get("execution_note", "")
                    if execution_record else "Execution metadata unavailable."
                ),
            }

    raise HTTPException(status_code=404, detail="Sigma rule not found.")
