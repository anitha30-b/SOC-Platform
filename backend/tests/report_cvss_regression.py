"""CVSS calculation and actual PDF-rendering tests; no database imports."""
import ast
import sys
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from report_cvss import report_cvss_summary


class CVSSTests(unittest.TestCase):
    def test_missing_scores_are_unavailable(self):
        result = report_cvss_summary([{}, {"cvss_score": None}])
        self.assertEqual(result["scored_count"], 0)
        self.assertIsNone(result["average"])
        self.assertIsNone(result["highest"])

    def test_genuine_zero_is_scored(self):
        result = report_cvss_summary([{"cvss_score": 0.0}])
        self.assertEqual(result["scored_count"], 1)
        self.assertEqual(result["average"], 0.0)
        self.assertEqual(result["highest"], 0.0)

    def test_mixed_findings_exclude_missing_scores(self):
        result = report_cvss_summary([
            {"cvss_score": None}, {"cvss_score": 0},
            {"cvss_score": 7.5}, {"cvss_score": "10.0"},
        ])
        self.assertEqual(result["scored_count"], 3)
        self.assertAlmostEqual(result["average"], 17.5 / 3)
        self.assertEqual(result["highest"], 10.0)

    def test_invalid_values_are_excluded(self):
        result = report_cvss_summary([
            {"cvss_score": value}
            for value in (True, False, "", "N/A", "NaN", "inf", -1, 11, [], {})
        ])
        self.assertEqual(result["scored_count"], 0)

    def test_empty_findings_are_unavailable(self):
        self.assertIsNone(report_cvss_summary([])["average"])

    def render_summary(self, findings):
        # Extract only the renderer, avoiding application and database startup.
        tree = ast.parse(
            (BACKEND / "vapt_reporting_router.py").read_text(encoding="utf-8")
        )
        renderer = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_build_canonical_pdf"
        )
        namespace = {"BytesIO": BytesIO}
        module = ast.Module(body=[renderer], type_ignores=[])
        exec(compile(module, "<isolated-pdf-renderer>", "exec"), namespace)

        from reportlab.platypus import Table
        captured = []

        def capture(data, *args, **kwargs):
            if data and data[0] == ["Metric", "Value"]:
                captured.extend(data[1:])
            return Table(data, *args, **kwargs)

        canonical = {
            "report_metadata": {"assessment_id": 1, "target": "example.invalid"},
            "risk_assessment": {
                "average_cvss": 0.0, "highest_cvss": 0.0,
                "total_findings": len(findings),
            },
            "findings": findings,
        }
        with patch("reportlab.platypus.Table", side_effect=capture):
            pdf = namespace["_build_canonical_pdf"](canonical)
        self.assertTrue(pdf.getvalue().startswith(b"%PDF"))
        return dict(captured)

    def test_pdf_displays_unavailable_for_unscored_findings(self):
        rows = self.render_summary([{"title": "Synthetic", "cvss_score": None}])
        self.assertEqual(rows["Average CVSS"], "Not available")
        self.assertEqual(rows["Highest CVSS"], "Not available")
        self.assertEqual(rows["Scored Report Findings"], "0")

    def test_pdf_preserves_valid_zero(self):
        rows = self.render_summary([{"title": "Synthetic", "cvss_score": 0.0}])
        self.assertEqual(rows["Average CVSS"], "0.00")
        self.assertEqual(rows["Highest CVSS"], "0.0")
        self.assertEqual(rows["Scored Report Findings"], "1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
