"""Check Nmap profile commands without importing the backend or running scans."""
import ast
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "vapt.py"


def command_for(profile):
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "_execute_nmap_command"
    )
    for branch in ast.walk(function):
        if not isinstance(branch, ast.If):
            continue
        condition = branch.test
        if not (
            isinstance(condition, ast.Compare)
            and isinstance(condition.left, ast.Name)
            and condition.left.id == "scan_type"
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], ast.Eq)
            and len(condition.comparators) == 1
            and isinstance(condition.comparators[0], ast.Constant)
            and condition.comparators[0].value == profile
        ):
            continue

        assignment = next(
            node for node in branch.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "command"
                    for target in node.targets)
        )
        if not isinstance(assignment.value, ast.List):
            raise AssertionError("Unexpected command builder.")

        result = []
        for item in assignment.value.elts:
            if isinstance(item, ast.Constant):
                result.append(item.value)
            elif isinstance(item, ast.Name) and item.id in {"NMAP_PATH", "target"}:
                result.append({"NMAP_PATH": "nmap", "target": "127.0.0.1"}[item.id])
            elif (
                isinstance(item, ast.Starred)
                and isinstance(item.value, ast.Call)
                and isinstance(item.value.func, ast.Name)
                and item.value.func.id == "_nmap_rate_args"
                and not item.value.args and not item.value.keywords
            ):
                # Rate settings do not select service detection or NSE.
                continue
            else:
                raise AssertionError("Command structure changed; inspect the profile.")
        return result
    raise AssertionError(f"Profile not found: {profile}")


class ProfileTests(unittest.TestCase):
    def test_port_profile_uses_top_1000_tcp_ports(self):
        command = command_for("quick")
        self.assertIn("-sT", command)
        self.assertEqual(command[command.index("--top-ports") + 1], "1000")

    def test_port_profile_has_no_service_os_or_script_probes(self):
        command = command_for("quick")
        for flag in ("-sV", "-sC", "-A", "-O", "--script", "--version-light"):
            self.assertNotIn(flag, command)

    def test_service_profile_runs_version_detection_and_default_scripts(self):
        command = command_for("service")
        self.assertIn("-sV", command)
        self.assertIn("-sC", command)
        self.assertIn("--version-light", command)
        self.assertEqual(command[command.index("--top-ports") + 1], "1000")


if __name__ == "__main__":
    unittest.main(verbosity=2)
