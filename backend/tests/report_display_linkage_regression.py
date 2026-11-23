"""Actual report workers and scoped severity handlers with isolated SQLite."""
import ast
import __future__
import asyncio
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

import nuclei_report_contract_regression as base
from sqlalchemy import func


def handler(name):
    tree = ast.parse((base.ROOT/'security_findings.py').read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    node.args.defaults = [ast.Constant(None) for _ in node.args.defaults]
    namespace = {'SecurityFinding': base.models.SecurityFinding, 'func': func}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                 'security_findings.py', 'exec', flags=__future__.annotations.compiler_flag), namespace)
    return namespace[name]


class ReportDisplayTests(base.NucleiReportContractTests):
    def assert_report(self, evidence, score):
        super().assert_report(evidence, score)
        with base.support.Factory() as db:
            report = db.query(base.models.VAPTReportRun).filter_by(job_id='report-contract').one()
            assessment = db.query(base.models.Assessment).filter_by(id=report.assessment_id).one()
            self.assertEqual(assessment.report_status, 'completed')

    def totals(self, owner, assessment=None):
        with base.support.Factory() as db:
            chart = handler('get_findings_by_severity')(assessment_id=assessment,
                current_user=NS(id=owner), db=db)
            summary = handler('get_security_finding_statistics')(assessment_id=assessment,
                current_user=NS(id=owner), db=db)
        self.assertEqual(sum(row['findings'] for row in chart['severities']), chart['total_findings'])
        self.assertEqual(sum(summary['severity'].values()), summary['total_findings'])
        return {row['severity']: row['findings'] for row in chart['severities']}, summary

    def test_info_and_unknown_findings_are_visible_in_both_summaries(self):
        a, _ = self.persist(self.evidence('INFO'), job='info')
        self.persist(self.evidence('unknown'), job='unrated')
        chart, summary = self.totals(1)
        self.assertEqual((chart['INFO'], chart['UNRATED'], summary['total_findings']), (1, 1, 2))
        self.assertEqual((summary['severity']['info'], summary['severity']['unrated']), (1, 1))
        chart, summary = self.totals(1, a['assessment_id'])
        self.assertEqual((chart['INFO'], chart['UNRATED'], summary['total_findings']), (1, 0, 1))

    def test_normalized_groups_sum_without_exposing_other_owners(self):
        for i, severity in enumerate(('info', 'INFO', ' informational ', 'odd')):
            summary, _ = self.persist(self.evidence(), job='group-'+str(i))
            with base.support.Factory() as db:
                finding = db.query(base.models.SecurityFinding).filter_by(assessment_id=summary['assessment_id']).one()
                finding.severity = severity
                db.commit()
        self.persist(self.evidence('CRITICAL'), owner=2, client=20, job='foreign')
        chart, summary = self.totals(1)
        self.assertEqual((chart['INFO'], chart['UNRATED'], chart['CRITICAL']), (3, 1, 0))
        self.assertEqual(summary['total_findings'], 4)
        chart, summary = self.totals(2)
        self.assertEqual((chart['CRITICAL'], summary['total_findings']), (1, 1))

    def test_empty_summary_retains_zero_categories(self):
        chart, summary = self.totals(3)
        self.assertEqual(sum(chart.values()), 0)
        self.assertIn('INFO', chart)
        self.assertIn('UNRATED', chart)
        self.assertEqual(summary['total_findings'], 0)

    def test_failed_report_does_not_mark_assessment_completed(self):
        summary, _ = self.persist()
        base.reporting.REPORT_JOBS['no-risk'] = {}
        with patch.object(base.database, 'SessionLocal', base.support.Factory):
            asyncio.run(base.reporting._run_report('no-risk', NS(assessment_id=summary['assessment_id'],
                report_type='COMPLETE'), 1))
        self.assertEqual(base.reporting.REPORT_JOBS['no-risk']['status'], 'failed')
        with base.support.Factory() as db:
            self.assertNotEqual(db.query(base.models.Assessment).filter_by(id=summary['assessment_id']).one().report_status,
                                'completed')
            self.assertEqual(db.query(base.models.VAPTReportRun).count(), 0)

    def test_report_storage_failure_rolls_back_status_together_with_report(self):
        self.assert_report(self.evidence('INFO', None), None)
        with base.support.Factory() as db:
            assessment = db.query(base.models.Assessment).one()
            assessment_id = assessment.id
            assessment.report_status = 'not_generated'
            db.commit()
        failing_db = base.support.Factory()
        base.reporting.REPORT_JOBS['storage-failure'] = {}
        with patch.object(base.database, 'SessionLocal', return_value=failing_db), \
             patch.object(failing_db, 'commit', side_effect=RuntimeError('synthetic commit failure')):
            asyncio.run(base.reporting._run_report('storage-failure', NS(assessment_id=assessment_id,
                report_type='COMPLETE'), 1))
        self.assertEqual(base.reporting.REPORT_JOBS['storage-failure']['status'], 'failed')
        with base.support.Factory() as db:
            self.assertEqual(db.query(base.models.Assessment).filter_by(id=assessment_id).one().report_status,
                             'not_generated')
            self.assertEqual(db.query(base.models.VAPTReportRun).count(), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
