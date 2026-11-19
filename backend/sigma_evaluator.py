"""Safe evaluator for the supported subset of local Sigma rules.

Supported:
- Linux log sources with service auth or sudo
- message|contains selectors with strings or string lists
- Boolean selector conditions using AND, OR, and parentheses

Other Sigma features remain unsupported until explicitly implemented.
"""
from pathlib import Path
import re
import threading

import yaml


RULE_DIR = Path(__file__).resolve().parent / "sigma_rules"
_TOKEN_RE = re.compile(
    r"\s*(\(|\)|(?i:and|or)\b|[A-Za-z_][A-Za-z0-9_]*)"
)
_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
_IGNORED_STATUSES = {"disabled", "deprecated", "unsupported"}

_cache_lock = threading.Lock()
_cache_signature = None
_cache_rules = []


def _parse_condition(condition, selector_names):
    """Parse a restricted Boolean expression without eval()."""
    if not isinstance(condition, str) or not condition.strip():
        raise ValueError("Condition must be a non-empty string.")

    tokens = []
    position = 0

    while position < len(condition):
        match = _TOKEN_RE.match(condition, position)
        if not match:
            if condition[position:].strip() == "":
                break
            raise ValueError("Condition contains unsupported syntax.")
        tokens.append(match.group(1))
        position = match.end()

    if not tokens:
        raise ValueError("Condition contains no selectors.")

    index = 0

    def parse_primary():
        nonlocal index
        if index >= len(tokens):
            raise ValueError("Condition ends unexpectedly.")

        token = tokens[index]

        if token == "(":
            index += 1
            node = parse_or()
            if index >= len(tokens) or tokens[index] != ")":
                raise ValueError("Unbalanced parentheses in condition.")
            index += 1
            return node

        if token == ")" or token.casefold() in {"and", "or"}:
            raise ValueError("Expected a selector in condition.")

        index += 1
        if token not in selector_names:
            raise ValueError(f"Condition references unknown selector: {token}")
        return ("selector", token)

    def parse_and():
        nonlocal index
        node = parse_primary()
        while index < len(tokens) and tokens[index].casefold() == "and":
            index += 1
            node = ("and", node, parse_primary())
        return node

    def parse_or():
        nonlocal index
        node = parse_and()
        while index < len(tokens) and tokens[index].casefold() == "or":
            index += 1
            node = ("or", node, parse_and())
        return node

    tree = parse_or()
    if index != len(tokens):
        raise ValueError("Condition contains unexpected tokens.")
    return tree


def _analyze_rule(rule):
    """Return support information and a prepared selector/condition pair."""
    if not isinstance(rule, dict):
        return False, "Rule YAML must be a mapping.", {}, None

    for field in ("title", "id", "level", "logsource", "detection"):
        if field not in rule:
            return False, f"Required field is missing: {field}", {}, None

    if not isinstance(rule.get("title"), str) or not rule["title"].strip():
        return False, "Rule title must be a non-empty string.", {}, None

    if not isinstance(rule.get("id"), str) or not rule["id"].strip():
        return False, "Rule ID must be a non-empty string.", {}, None

    if str(rule.get("level", "")).casefold() not in _VALID_LEVELS:
        return False, "Rule severity level is unsupported.", {}, None

    status = str(rule.get("status", "")).casefold()
    if status in _IGNORED_STATUSES:
        return False, f"Rule status '{status}' is not enabled for execution.", {}, None

    logsource = rule.get("logsource")
    if not isinstance(logsource, dict):
        return False, "logsource must be a mapping.", {}, None

    if str(logsource.get("product", "")).casefold() != "linux":
        return False, "Only Linux log sources are supported.", {}, None

    service = str(logsource.get("service", "")).casefold()
    if service not in {"auth", "sudo"}:
        return False, "Only Linux auth and sudo services are supported.", {}, None

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return False, "detection must be a mapping.", {}, None

    condition = detection.get("condition")
    selectors = {}

    for name, definition in detection.items():
        if name == "condition":
            continue
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return False, "Selector name contains unsupported syntax.", {}, None
        if not isinstance(definition, dict) or set(definition) != {"message|contains"}:
            return (
                False,
                f"Selector '{name}' is unsupported; only message|contains is implemented.",
                {},
                None,
            )

        values = definition["message|contains"]
        if isinstance(values, str):
            values = [values]
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value for value in values)
        ):
            return (
                False,
                f"Selector '{name}' must contain a non-empty string or list of strings.",
                {},
                None,
            )
        selectors[name] = [value.casefold() for value in values]

    if not selectors:
        return False, "Rule has no supported selectors.", {}, None

    try:
        condition_tree = _parse_condition(condition, set(selectors))
    except ValueError as exc:
        return False, str(exc), {}, None

    return True, "Supported Linux message|contains subset.", selectors, condition_tree


def get_rule_execution_support(rule):
    """Expose whether a parsed YAML rule is executable by this evaluator."""
    supported, reason, _, _ = _analyze_rule(rule)
    return {"supported": supported, "reason": reason}


def _rule_paths():
    if not RULE_DIR.is_dir():
        return []
    return sorted(
        list(RULE_DIR.glob("*.yml")) + list(RULE_DIR.glob("*.yaml"))
    )


def _load_supported_rules():
    """Cache parsed rules until a library file is added, removed, or changed."""
    global _cache_signature, _cache_rules

    paths = _rule_paths()
    try:
        signature = tuple(
            (path.name, path.stat().st_mtime_ns, path.stat().st_size)
            for path in paths
        )
    except OSError:
        signature = None

    with _cache_lock:
        if signature == _cache_signature:
            return list(_cache_rules)

        entries = []
        for path in paths:
            try:
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
                supported, reason, selectors, condition_tree = _analyze_rule(rule)
                entries.append({
                    "rule": rule,
                    "supported": supported,
                    "reason": reason,
                    "selectors": selectors,
                    "condition_tree": condition_tree,
                    "filename": path.name,
                })
            except (OSError, yaml.YAMLError) as exc:
                entries.append({
                    "rule": None,
                    "supported": False,
                    "reason": f"Unable to load YAML: {exc}",
                    "selectors": {},
                    "condition_tree": None,
                    "filename": path.name,
                })

        id_counts = {}
        for entry in entries:
            rule = entry["rule"]
            rule_id = rule.get("id") if isinstance(rule, dict) else None
            if isinstance(rule_id, str):
                id_counts[rule_id] = id_counts.get(rule_id, 0) + 1

        active = []
        for entry in entries:
            rule = entry["rule"]
            if not entry["supported"] or not isinstance(rule, dict):
                continue
            if id_counts.get(rule.get("id"), 0) != 1:
                continue
            active.append(entry)

        _cache_signature = signature
        _cache_rules = active
        return list(active)


def _evaluate_condition(tree, selector_matches):
    operation = tree[0]
    if operation == "selector":
        return selector_matches.get(tree[1], False)
    if operation == "and":
        return (
            _evaluate_condition(tree[1], selector_matches)
            and _evaluate_condition(tree[2], selector_matches)
        )
    if operation == "or":
        return (
            _evaluate_condition(tree[1], selector_matches)
            or _evaluate_condition(tree[2], selector_matches)
        )
    return False


def _event_message(event):
    """Read the normalized message and common message fields from raw evidence."""
    values = []
    message = event.get("message")
    if isinstance(message, str):
        values.append(message)

    raw = event.get("raw_event")
    if isinstance(raw, dict):
        for key in ("message", "event", "MESSAGE", "MESSAGE_TEXT"):
            value = raw.get(key)
            if isinstance(value, str):
                values.append(value)

    return "\n".join(dict.fromkeys(values)).casefold()


def _matches_logsource(rule, event):
    source = str(event.get("source") or "").casefold()
    event_type = str(event.get("event_type") or "").casefold()
    logsource = rule.get("logsource") or {}
    service = str(logsource.get("service") or "").casefold()

    if source != "systemd-journald":
        return False

    if service == "auth":
        return event_type in {
            "authentication",
            "authentication_failure",
            "invalid_user",
        }

    if service == "sudo":
        return event_type == "privileged_command"

    return False


def evaluate_sigma_event(event):
    """Return supported Sigma rule matches for one normalized Linux event."""
    if not isinstance(event, dict) or not _event_message(event):
        return []

    message = _event_message(event)
    matches = []

    for entry in _load_supported_rules():
        rule = entry["rule"]
        if not _matches_logsource(rule, event):
            continue

        selector_matches = {
            name: any(value in message for value in values)
            for name, values in entry["selectors"].items()
        }

        if not _evaluate_condition(entry["condition_tree"], selector_matches):
            continue

        matches.append({
            "rule": rule,
            "filename": entry["filename"],
            "matched_selectors": [
                name for name, matched in selector_matches.items() if matched
            ],
            "evidence": str(event.get("message") or "")[:4000],
        })

    return matches
