from fastapi import Depends
from rbac import require_role
from fastapi import APIRouter, HTTPException

from mitre import (
    get_all_objects,
    get_attack_id,
    get_attack_pattern_by_id,
    get_attack_patterns,
    get_detection_relationships,
    get_mitigation_relationships,
    get_procedure_examples,
    get_tactics,
)

router = APIRouter(
    prefix="/mitre",
    tags=["MITRE ATT&CK"],
)


@router.get("/techniques")
def get_techniques():
    techniques = []

    for obj in get_attack_patterns():
        attack_id = get_attack_id(obj)

        if not attack_id:
            continue

        techniques.append({
            "id": attack_id,
            "name": obj.get("name", ""),
            "description": (
                obj.get("description") or ""
            ).strip(),
            "is_subtechnique": bool(
                obj.get("x_mitre_is_subtechnique")
            ),
            "version": obj.get("x_mitre_version"),
            "tactics": get_tactics(obj),
        })

    techniques.sort(
        key=lambda item: item["id"]
    )

    return {
        "framework": "Enterprise",
        "version": "19.2",
        "count": len(techniques),
        "techniques": techniques,
    }


@router.get("/techniques/{technique_id}")
def get_technique(technique_id: str):
    technique_id = technique_id.upper()

    obj = get_attack_pattern_by_id(
        technique_id
    )

    if not obj:
        raise HTTPException(
            status_code=404,
            detail=(
                f"MITRE technique "
                f"{technique_id} not found"
            ),
        )

    stix_id = obj.get("id")

    # -------------------------------------------------
    # Related MITRE techniques
    # -------------------------------------------------

    all_objects = get_all_objects()

    parent_technique = None
    sibling_techniques = []

    # Find parent technique for a sub-technique.
    parent_relationships = [
        relationship
        for relationship in all_objects
        if (
            relationship.get("type")
            == "relationship"
            and relationship.get("relationship_type")
            == "subtechnique-of"
            and relationship.get("source_ref")
            == stix_id
        )
    ]

    if parent_relationships:
        parent_stix_id = parent_relationships[0].get(
            "target_ref"
        )

        for attack_pattern in get_attack_patterns():
            if attack_pattern.get("id") != parent_stix_id:
                continue

            parent_attack_id = get_attack_id(
                attack_pattern
            )

            if parent_attack_id:
                parent_technique = {
                    "id": parent_attack_id,
                    "name": attack_pattern.get(
                        "name",
                        "",
                    ),
                    "is_subtechnique": False,
                }

            break

        # Find sibling sub-techniques.
        if parent_stix_id:
            for relationship in all_objects:
                if (
                    relationship.get("type")
                    != "relationship"
                    or relationship.get(
                        "relationship_type"
                    )
                    != "subtechnique-of"
                    or relationship.get(
                        "target_ref"
                    )
                    != parent_stix_id
                ):
                    continue

                sibling_stix_id = relationship.get(
                    "source_ref"
                )

                if sibling_stix_id == stix_id:
                    continue

                for attack_pattern in get_attack_patterns():
                    if (
                        attack_pattern.get("id")
                        != sibling_stix_id
                    ):
                        continue

                    sibling_attack_id = get_attack_id(
                        attack_pattern
                    )

                    if sibling_attack_id:
                        sibling_techniques.append({
                            "id": sibling_attack_id,
                            "name": attack_pattern.get(
                                "name",
                                "",
                            ),
                            "is_subtechnique": True,
                        })

                    break

    sibling_techniques.sort(
        key=lambda item: item["id"]
    )

    related_techniques = []

    if parent_technique:
        related_techniques.append(
            parent_technique
        )

    related_techniques.extend(
        sibling_techniques
    )

    return {
        "id": technique_id,
        "name": obj.get("name", ""),
        "description": (
            obj.get("description") or ""
        ).strip(),
        "is_subtechnique": bool(
            obj.get("x_mitre_is_subtechnique")
        ),
        "version": obj.get("x_mitre_version"),
        "tactics": get_tactics(obj),

        "related_techniques": related_techniques,

        "procedures": get_procedure_examples(
            stix_id
        ),
        "detections": get_detection_relationships(
            stix_id
        ),
        "mitigations": get_mitigation_relationships(
            stix_id
        ),
    }

@router.get("/reference-catalogue")
def get_reference_catalogue(
    current_user=Depends(require_role(1)),
):
    """Active reference records from the local Enterprise ATT&CK snapshot."""
    from mitre import MITRE_DATA_PATH

    objects = [
        obj for obj in get_all_objects()
        if not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    ]

    techniques = [
        obj for obj in objects
        if obj.get("type") == "attack-pattern"
        and get_attack_id(obj)
    ]

    def record(obj):
        references = [
            {
                "name": str(ref.get("source_name") or "Reference"),
                "url": ref["url"],
            }
            for ref in obj.get("external_references", [])
            if isinstance(ref, dict)
            and isinstance(ref.get("url"), str)
            and ref["url"].lower().startswith(("https://", "http://"))
        ]

        return {
            "id": get_attack_id(obj) or obj.get("id"),
            "stix_id": obj.get("id"),
            "name": obj.get("name") or "",
            "type": obj.get("type"),
            "description": obj.get("description") or "",
            "aliases": obj.get("aliases") or [],
            "modified": obj.get("modified"),
            "version": obj.get("x_mitre_version"),
            "tactics": get_tactics(obj),
            "is_subtechnique": bool(
                obj.get("x_mitre_is_subtechnique")
            ),
            "references": references,
        }

    rows = []

    for obj in objects:
        kind = obj.get("type")
        if kind not in {
            "x-mitre-tactic",
            "attack-pattern",
            "intrusion-set",
            "malware",
            "tool",
        }:
            continue

        if not get_attack_id(obj):
            continue

        item = record(obj)

        if kind == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname")
            related = [
                technique for technique in techniques
                if shortname
                and shortname in get_tactics(technique)
            ]

            item["shortname"] = shortname
            item["technique_count"] = sum(
                not technique.get("x_mitre_is_subtechnique")
                for technique in related
            )
            item["subtechnique_count"] = sum(
                bool(technique.get("x_mitre_is_subtechnique"))
                for technique in related
            )

        rows.append(item)

    rows.sort(
        key=lambda item: (
            item["id"],
            item["stix_id"] or "",
        )
    )

    return {
        "dataset": MITRE_DATA_PATH.name,
        "active_only": True,
        "count": len(rows),
        "records": rows,
    }
