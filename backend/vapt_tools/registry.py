"""Stage-aware VAPT tool registry.

The registry discovers JSON manifests from the local manifests directory.
Adding a new manifest is enough to make a tool discoverable; no React or
existing SOC module needs to be edited for registry discovery.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
MANIFEST_DIR = BASE_DIR / "manifests"

STAGE_ORDER = [
    "01 Reconnaissance",
    "02 Scanning & Enumeration",
    "03 Vulnerability Discovery",
    "04 Network Security Testing",
    "05 Validation / Exploitation",
    "06 Credential Testing",
    "07 Post-Exploitation",
    "08 Risk Assessment",
    "09 Reporting",
]


def _load_manifest(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    required = ("id", "name", "stage", "category", "execution_type")
    if any(not data.get(key) for key in required):
        return None

    data.setdefault("enabled", True)
    data.setdefault("integrated", False)
    data.setdefault("target_types", [])
    data.setdefault("executable", None)
    data.setdefault("description", "")
    data["manifest"] = path.name
    return data


def build_registry() -> Dict[str, Any]:
    """Return the complete stage-aware registry."""
    tools: List[Dict[str, Any]] = []

    for path in sorted(MANIFEST_DIR.glob("*.json")):
        manifest = _load_manifest(path)
        if manifest is not None:
            tools.append(manifest)

    stage_rank = {stage: index for index, stage in enumerate(STAGE_ORDER)}
    tools.sort(
        key=lambda item: (
            stage_rank.get(str(item.get("stage")), 999),
            str(item.get("name", "")).lower(),
        )
    )

    stages: List[Dict[str, Any]] = []
    for stage in STAGE_ORDER:
        stage_tools = [tool for tool in tools if tool.get("stage") == stage]
        stages.append(
            {
                "stage": stage,
                "tools": stage_tools,
                "tool_count": len(stage_tools),
            }
        )

    return {
        "version": 1,
        "stage_count": len(STAGE_ORDER),
        "tool_count": len(tools),
        "stages": stages,
        "tools": tools,
    }


def list_tools(*, stage: Optional[str] = None, enabled_only: bool = False) -> List[Dict[str, Any]]:
    registry = build_registry()
    tools = registry["tools"]

    if stage:
        tools = [tool for tool in tools if tool.get("stage") == stage]

    if enabled_only:
        tools = [tool for tool in tools if bool(tool.get("enabled"))]

    return tools


def list_stages() -> List[Dict[str, Any]]:
    return build_registry()["stages"]


def get_tool(tool_id: str) -> Optional[Dict[str, Any]]:
    normalized = str(tool_id or "").strip().lower()
    for tool in build_registry()["tools"]:
        if str(tool.get("id", "")).lower() == normalized:
            return tool
    return None


def main() -> None:
    print(json.dumps(build_registry(), indent=2))


if __name__ == "__main__":
    main()
