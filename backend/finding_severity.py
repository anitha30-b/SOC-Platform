"""Keep every stored finding represented in severity summaries."""
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'INFO', 'UNRATED')


def normalize_severity(value):
    value = str(value or '').strip().upper()
    if value == 'INFORMATIONAL':
        value = 'INFO'
    return value if value in SEVERITIES else 'UNRATED'


def severity_counts(rows):
    counts = dict.fromkeys(SEVERITIES, 0)
    for severity, count in rows:
        counts[normalize_severity(severity)] += int(count)
    return counts
