"""Reject reports that mix current findings with an obsolete risk snapshot."""
import json

from report_cvss import report_cvss_summary


def validate_report_snapshot(risk_run, findings):
    message = 'Findings changed or the risk snapshot is invalid. Run Stage 08 Risk Assessment again before generating the report.'
    try:
        snapshot = json.loads(risk_run.findings_snapshot)
        if not isinstance(snapshot, list):
            raise ValueError(message)
        saved = {}
        for row in snapshot:
            if not isinstance(row, dict) or not row.get('finding_id') or row['finding_id'] in saved:
                raise ValueError(message)
            saved[row['finding_id']] = row
        current = {f.finding_id: f for f in findings}
        if len(current) != len(findings) or set(current) != set(saved):
            raise ValueError(message)
        if risk_run.total_findings != len(findings):
            raise ValueError(message)
        fields = ('title', 'vulnerability', 'tool_name', 'tool_category', 'status',
                  'affected_asset', 'affected_url', 'endpoint', 'cve_id', 'cwe_id', 'owasp_category')
        for ident, finding in current.items():
            row = saved[ident]
            for field in fields:
                if field not in row or row[field] != getattr(finding, field):
                    raise ValueError(message)
            score = float(finding.cvss_score) if finding.cvss_score is not None else None
            if 'cvss_score' not in row or row['cvss_score'] != score:
                raise ValueError(message)
            for field in ('severity', 'risk_level'):
                value = getattr(finding, field) or row.get('calculated_' + field)
                if field not in row or row[field] != value:
                    raise ValueError(message)
    except (TypeError, KeyError, AttributeError, ValueError, OverflowError) as exc:
        raise ValueError(message) from exc


def canonical_report_cvss(findings):
    return report_cvss_summary([{'cvss_score': f.cvss_score} for f in findings])
