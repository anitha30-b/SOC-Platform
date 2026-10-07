import json
from pathlib import Path


MITRE_DATA_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "mitre"
    / "enterprise-attack-19.2.json"
)


def load_mitre_data():
    with MITRE_DATA_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_all_objects():
    data = load_mitre_data()
    return data.get("objects", [])


def get_attack_patterns():
    return [
        obj
        for obj in get_all_objects()
        if obj.get("type") == "attack-pattern"
    ]


def get_attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def get_attack_pattern_by_id(technique_id):
    technique_id = technique_id.upper()

    for obj in get_attack_patterns():
        if get_attack_id(obj) == technique_id:
            return obj

    return None


def clean_description(description):
    if not description:
        return ""

    return description.strip()


def get_tactics(obj):
    return [
        phase.get("phase_name")
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def get_relationships_for_target(target_stix_id):
    return [
        obj
        for obj in get_all_objects()
        if (
            obj.get("type") == "relationship"
            and obj.get("target_ref") == target_stix_id
        )
    ]


def get_procedure_examples(technique_stix_id):
    objects = get_all_objects()
    procedures = []

    for relationship in objects:
        if (
            relationship.get("type") != "relationship"
            or relationship.get("relationship_type") != "uses"
            or relationship.get("target_ref") != technique_stix_id
        ):
            continue

        description = relationship.get("description")

        if not description:
            continue

        procedures.append({
            "source_ref": relationship.get("source_ref"),
            "description": clean_description(description),
        })

    return procedures


def get_detection_relationships(technique_stix_id):
    objects = get_all_objects()
    detections = []

    for relationship in objects:
        if (
            relationship.get("type") != "relationship"
            or relationship.get("relationship_type") != "detects"
            or relationship.get("target_ref") != technique_stix_id
        ):
            continue

        detections.append({
            "source_ref": relationship.get("source_ref"),
            "description": clean_description(
                relationship.get("description")
            ),
        })

    return detections


def get_mitigation_relationships(technique_stix_id):
    objects = get_all_objects()
    mitigations = []

    for relationship in objects:
        if (
            relationship.get("type") != "relationship"
            or relationship.get("relationship_type") != "mitigates"
            or relationship.get("target_ref") != technique_stix_id
        ):
            continue

        mitigations.append({
            "source_ref": relationship.get("source_ref"),
            "description": clean_description(
                relationship.get("description")
            ),
        })

    return mitigations