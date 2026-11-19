"""Test URL matcher functions without app or database imports."""
import ast
import ipaddress
import re
import unittest
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def load_matcher():
    source = Path(__file__).resolve().parents[1] / "ioc_router.py"
    tree = ast.parse(source.read_text())
    names = {"normalize_http_url", "url_candidate_matches", "_URL_RE"}
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in names
            for target in node.targets
        ):
            nodes.append(node)
    namespace = {
        "ipaddress": ipaddress, "re": re,
        "urlsplit": urlsplit, "urlunsplit": urlunsplit,
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]),
                 "isolated_ioc_matcher", "exec"), namespace)
    return namespace["url_candidate_matches"]


class IOCURLMatchingTests(unittest.TestCase):
    def setUp(self):
        self.match = load_matcher()

    def test_exact_url(self):
        self.assertTrue(self.match(
            "https://example.com/", "Visited https://example.com/"
        ))

    def test_hostname_containing_s(self):
        self.assertTrue(self.match(
            "https://secuzity.com/", "Visited https://secuzity.com/"
        ))

    def test_whitespace_boundary(self):
        self.assertTrue(self.match(
            "https://example.com/", "https://example.com/ next"
        ))

    def test_different_hostname(self):
        self.assertFalse(self.match(
            "https://example.com/", "https://example.com.evil.invalid/"
        ))

    def test_different_path(self):
        self.assertFalse(self.match(
            "https://example.com/a", "https://example.com/ab"
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
