from typing import Any, Dict, List

from mitre import (
    get_attack_id,
    get_attack_pattern_by_id,
    get_tactics,
)


def build_mapping(
    technique_id: str,
    event: Dict[str, Any],
    *,
    confidence: str = "low",
) -> Dict[str, Any] | None:

    technique = get_attack_pattern_by_id(
        technique_id
    )

    if technique is None:
        return None

    return {
        "technique_id": get_attack_id(technique),
        "technique_name": technique.get(
            "name",
            "",
        ),
        "tactics": get_tactics(technique),
        "mapping_source": "rule",
        "confidence": confidence,
        "mapping_reason": (
            "Security event matched a defined "
            "MITRE ATT&CK mapping rule."
        ),
        "evidence": event.get(
            "message",
            "",
        ),
    }


def build_detection_mapping(
    technique_id: str,
    detection: Dict[str, Any],
    event: Dict[str, Any],
    *,
    confidence: str = "medium",
) -> Dict[str, Any] | None:

    technique = get_attack_pattern_by_id(
        technique_id
    )

    if technique is None:
        return None

    detection_type = detection.get(
        "detection_type"
    )

    reason = (
        f"Authentication correlation detected "
        f"{detection_type.replace('_', ' ')} "
        f"behavior and mapped it to the corresponding "
        f"MITRE ATT&CK sub-technique."
        if detection_type
        else (
            "Authentication correlation rule matched "
            "a MITRE ATT&CK sub-technique."
        )
    )

    return {
        "technique_id": get_attack_id(
            technique
        ),
        "technique_name": technique.get(
            "name",
            "",
        ),
        "tactics": get_tactics(
            technique
        ),
        "mapping_source": "correlation_rule",
        "confidence": confidence,
        "mapping_reason": reason,
        "evidence": event.get(
            "message",
            "",
        ),
        "detection_type": detection_type,
        "detection": detection,
    }


def map_detection_to_t1110(
    detection: Dict[str, Any],
    event: Dict[str, Any],
) -> Dict[str, Any] | None:
    """
    Maps authentication detections to the
    appropriate MITRE ATT&CK T1110 sub-technique.
    """

    detection_type = detection.get(
        "detection_type"
    )

    if detection_type == "brute_force":
        technique_id = "T1110.001"
        confidence = "high"

    elif detection_type == "password_spraying":
        technique_id = "T1110.003"
        confidence = "high"

    elif detection_type == "credential_stuffing":
        technique_id = "T1110.004"
        confidence = "high"

    else:
        return None

    return build_detection_mapping(
        technique_id,
        detection,
        event,
        confidence=confidence,
    )


def map_security_event(
    event: Dict[str, Any],
) -> List[Dict[str, Any]]:

    mappings: List[Dict[str, Any]] = []

    message = str(
        event.get(
            "message",
            "",
        )
    ).lower()

    source = str(
        event.get(
            "source",
            "",
        )
    ).lower()

    event_type = str(event.get("event_type", "")).lower()
    raw_event = event.get("raw_event")

    if (
        event_type == "dns_detection"
        and isinstance(raw_event, dict)
        and raw_event.get("rule") == "DNS-001"
    ):
        mapping = build_mapping(
            "T1071.004",
            event,
            confidence="low",
        )
        if mapping:
            evidence_items = raw_event.get("evidence")
            if not isinstance(evidence_items, list):
                evidence_items = []

            query_names = sorted({
                str(item.get("dns_query_name", "")).lower().rstrip(".")
                for item in evidence_items
                if isinstance(item, dict) and item.get("dns_query_name")
            })

            threshold = raw_event.get("threshold", 30)
            window_seconds = raw_event.get("window_seconds", 60)
            mapping["mapping_source"] = "heuristic_dns_burst"
            mapping["mapping_reason"] = (
                "A burst of unique DNS names is a heuristic signal "
                "requiring investigation; it does not prove command-and-control."
            )

            evidence_text = (
                f"DNS-001 correlated {len(evidence_items)} DNS events "
                f"within {window_seconds} seconds (threshold: {threshold})."
            )
            if query_names:
                evidence_text += (
                    " Sample query names: "
                    + ", ".join(query_names[:3])
                    + "."
                )
            evidence_text += (
                " Low-confidence heuristic; not proof of command-and-control."
            )
            mapping["evidence"] = evidence_text
            mappings.append(mapping)

        return mappings

    if source == "snort":
        raw_event = event.get("raw_event") or {}
        alert = str(raw_event.get("alert", "")).upper()

        # Snort SID 621 detects TCP FIN scan activity.
        if "[1:621:" in alert and "SCAN FIN" in alert:
            mapping = build_mapping(
                "T1046",
                event,
                confidence="medium",
            )

            if mapping:
                mapping["mapping_source"] = "snort_signature"
                mapping["mapping_reason"] = (
                    "Snort SID 621 detected TCP FIN scan activity, "
                    "which is consistent with Network Service Discovery."
                )
                mappings.append(mapping)

        # Snort SID 1000001 detects TCP SYN port scan activity.
        elif "[1:1000001:" in alert and "CUSTOM SYN PORT SCAN DETECTED" in alert:
            mapping = build_mapping(
                "T1046",
                event,
                confidence="medium",
            )

            if mapping:
                mapping["mapping_source"] = "snort_signature"
                mapping["mapping_reason"] = (
                    "Snort SID 1000001 detected TCP SYN port scan activity, "
                    "which is consistent with Network Service Discovery."
                )
                mappings.append(mapping)

    elif source == "systemd-journald":

        if "failed password" in message:
            # A single failed password is not
            # automatically mapped to brute force.
            pass

        elif "invalid user" in message:
            # An invalid username alone does not
            # establish an ATT&CK technique.
            pass

    return mappings


def get_primary_tactic_for_technique(
    technique_id: str,
) -> str | None:

    technique = get_attack_pattern_by_id(
        technique_id
    )

    if technique is None:
        return None

    tactics = get_tactics(technique)

    if not tactics:
        return None

    return tactics[0]