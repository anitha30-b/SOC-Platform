"""CVSS summary for findings captured in a report."""
import math


def report_cvss_summary(findings):
    values = []
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            raw = finding.get("cvss_score")
            if raw is None or isinstance(raw, bool):
                continue
            if not isinstance(raw, (str, int, float)):
                continue
            try:
                value = float(raw)
            except (ValueError, TypeError, OverflowError):
                continue
            if math.isfinite(value) and 0 <= value <= 10:
                values.append(value)

    return {
        "scored_count": len(values),
        "average": sum(values) / len(values) if values else None,
        "highest": max(values) if values else None,
    }
