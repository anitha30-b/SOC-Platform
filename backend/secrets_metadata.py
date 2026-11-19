"""Allowlisted metadata projection for persisted Gitleaks findings."""
import json
import re

# Explicit rule IDs only. Other scanner rules remain unclassified.
RULE_CATEGORIES = {
    "generic-api-key": "api_keys",
    "aws-access-token": "api_keys",
    "gcp-api-key": "api_keys",
    "google-api-key": "api_keys",
    "sendgrid-api-token": "api_keys",
    "stripe-access-token": "api_keys",
    "github-pat": "tokens",
    "github-fine-grained-pat": "tokens",
    "github-oauth": "tokens",
    "gitlab-pat": "tokens",
    "gitlab-pat-v2": "tokens",
    "slack-bot-token": "tokens",
    "slack-user-token": "tokens",
    "jwt": "tokens",
    "private-key": "credentials",
    "generic-password": "credentials",
}
CATEGORIES = ("api_keys", "tokens", "credentials", "unclassified")


def secret_metadata(item):
    try:
        evidence = json.loads(item.evidence or "{}")
    except (ValueError, TypeError):
        evidence = {}
    if not isinstance(evidence, dict):
        evidence = {}

    rule = evidence.get("rule_id")
    rule = rule if (
        isinstance(rule, str)
        and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,119}", rule)
    ) else None

    path = evidence.get("file_path")
    if not isinstance(path, str) or "\n" in path or "\r" in path:
        path = None
    elif len(path) > 500:
        path = path[:500]

    def line(key):
        value = evidence.get(key)
        return value if type(value) is int and 0 < value <= 100000000 else None

    severity = str(item.severity or "").upper()
    status = str(item.status or "").upper()

    return {
        "id": item.id,
        "assessment_id": item.assessment_id,
        "tool": "Gitleaks",
        "rule_id": rule,
        "category": RULE_CATEGORIES.get(rule, "unclassified"),
        "severity": severity if severity in {
            "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
        } else "UNKNOWN",
        "status": status if status in {
            "OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED",
            "FALSE_POSITIVE", "ACCEPTED_RISK", "MITIGATED"
        } else "OTHER",
        "file_path": path,
        "line_start": line("line_start"),
        "line_end": line("line_end"),
        "secret_value_included": False,
        "remediation_guidance": (
            "Review the finding. If exposure is confirmed, revoke or rotate "
            "the credential, remove it from source and applicable history, "
            "and use a managed secret store."
        ),
    }
