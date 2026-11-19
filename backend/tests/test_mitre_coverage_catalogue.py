"""Coverage catalogue regression tests; no database or network access."""
import ast
import re
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace


class Expression:
    def __getattr__(self, name):
        return self

    def __call__(self, *args, **kwargs):
        return self


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args):
        return self

    def group_by(self, *args):
        return self

    def all(self):
        return self.rows


class FakeDB:
    def __init__(self, rows):
        self.rows = rows

    def query(self, *args):
        return FakeQuery(self.rows)


def load_coverage_function(patterns, observations, rules):
    source = (
        Path(__file__).resolve().parents[1]
        / "security_events_router.py"
    ).read_text()
    tree = ast.parse(source)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "get_mitre_coverage"
    )
    function.decorator_list = []

    def attack_id(obj):
        return obj.get("attack_id")

    namespace = {
        "Session": object,
        "Depends": lambda dependency: None,
        "get_db": lambda: None,
        "require_role": lambda role: lambda: None,
        "defaultdict": defaultdict,
        "re": re,
        "get_attack_patterns": lambda: patterns,
        "get_attack_id": attack_id,
        "get_tactics": lambda obj: obj.get("tactics", []),
        "list_rule_records": lambda: rules,
        "SIEM_RULES": [],
        "SecurityEvent": Expression(),
        "func": Expression(),
        "owned_security_event_filter": lambda db, user: True,
    }
    module = ast.Module(body=[function], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), "<coverage-test>", "exec"),
         namespace)
    return namespace["get_mitre_coverage"](
        db=FakeDB(observations),
        current_user=SimpleNamespace(id=5, client_id=None),
    )


class MitreCoverageCatalogueTests(unittest.TestCase):
    def setUp(self):
        self.patterns = [
            {"attack_id": "T1001", "name": "Active"},
            {
                "attack_id": "T1001.001",
                "name": "Active sub-technique",
                "x_mitre_is_subtechnique": True,
            },
            {
                "attack_id": "T1002",
                "name": "Revoked",
                "revoked": True,
            },
            {
                "attack_id": "T1003",
                "name": "Deprecated",
                "x_mitre_deprecated": True,
            },
        ]
        self.rules = [{
            "rule_id": "synthetic-rule",
            "title": "Synthetic rule",
            "validation_status": "VALID",
            "tags": ["attack.t1001", "attack.t1002"],
            "integration_status": "UNKNOWN",
        }]
        self.observations = [
            ("T1001", 2),
            ("T1002", 3),
            ("T1003", 4),
            ("T9999", 1),
        ]

    def result(self):
        return load_coverage_function(
            self.patterns, self.observations, self.rules
        )

    def test_only_active_catalogue_records_are_returned(self):
        data = self.result()
        self.assertTrue(data["catalogue_active_only"])
        self.assertEqual(data["catalogue_technique_count"], 2)
        self.assertEqual(
            {row["technique_id"] for row in data["techniques"]},
            {"T1001", "T1001.001"},
        )

    def test_historical_observation_total_is_preserved(self):
        data = self.result()
        self.assertEqual(data["observed_event_count"], 10)
        self.assertEqual(
            data["observed_techniques_outside_catalogue"],
            ["T1002", "T1003", "T9999"],
        )

    def test_configured_count_excludes_inactive_tags(self):
        data = self.result()
        self.assertEqual(data["configured_technique_count"], 1)
        self.assertEqual(data["configured_mapping_count"], 1)

    def test_active_observed_mapping_status(self):
        data = self.result()
        row = next(
            row for row in data["techniques"]
            if row["technique_id"] == "T1001"
        )
        self.assertEqual(row["coverage_status"], "CONFIGURED_AND_OBSERVED")
        self.assertEqual(row["observed_event_count"], 2)
        self.assertEqual(data["observed_catalogue_technique_count"], 1)

    def test_unobserved_subtechnique_is_retained(self):
        data = self.result()
        row = next(
            row for row in data["techniques"]
            if row["technique_id"] == "T1001.001"
        )
        self.assertTrue(row["is_subtechnique"])
        self.assertEqual(row["coverage_status"], "NOT_CONFIGURED_OR_OBSERVED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
