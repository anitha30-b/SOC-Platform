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

    if source == "systemd-journald":

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