"""Nuclei persistence through the actual risk and report workers, without live scanning."""
import ast
import asyncio
from copy import deepcopy
from datetime import datetime
import __future__
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import time
import unittest
from unittest.mock import patch
import uuid

os.environ['DATABASE_URL']='sqlite://'
os.environ['JWT_SECRET_KEY']='isolated-nuclei-report-contract-test'
ROOT=Path(os.environ.get('SOC_TOOL_AUDIT_BACKEND',Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
import nuclei_assessment_linkage_regression as fixtures
import nuclei_workflow as workflow
import models
import database
import vapt_reporting_router as reporting
import server_report_snapshot_regression as report_fixtures

support=fixtures.fixtures.support
EXTRA=(models.PostExploitationValidation,models.RiskAssessmentRun,models.VAPTReportRun)
for model in EXTRA:
    model.__table__.create(support.engine,checkfirst=True)


class NucleiReportContractTests(unittest.TestCase):
    def setUp(self):
        with support.Factory() as db:
            for model in reversed(EXTRA):
                db.query(model).delete()
            db.commit()
        self.fixture=fixtures.NucleiAssessmentLinkageTests()
        self.fixture.setUp()
        reporting.REPORT_JOBS.clear()

    def tearDown(self):
        reporting.REPORT_JOBS.clear()
        self.fixture.tearDown()

    def evidence(self,severity='MEDIUM',score=None):
        result=self.fixture.fixture.result('nuclei')
        result['findings'][0]['severity']=severity
        result['findings'][0]['raw']={'info':{'classification':{'cvss-score':score}}}
        return result

    def persist(self,result=None,owner=1,client=10,job='contract-scan'):
        with support.Factory() as db:
            summary,notifications=workflow.persist_nuclei_result(db,result or self.evidence(),owner,client,job)
            db.commit()
            return summary,notifications

    def test_completed_scan_can_generate_actual_risk_and_report(self):
        self.assert_report(self.evidence('HIGH',8.1),8.1)

    def test_informational_unscored_scan_can_generate_actual_report(self):
        self.assert_report(self.evidence('INFO',None),None)

    def test_genuine_zero_is_not_dropped_from_report(self):
        self.assert_report(self.evidence('INFO',0),0)

    def test_unknown_severity_remains_unrated(self):
        self.assert_report(self.evidence('unknown',None),None)

    def test_zero_finding_scan_can_generate_report(self):
        evidence=self.evidence()
        evidence['findings']=[]
        self.assert_report(evidence,None)

    def assert_report(self,evidence,score):
        summary,_=self.persist(evidence)
        helpers=report_fixtures.snapshot_function()
        namespace=dict(helpers,datetime=datetime,json=json,time=time,uuid=uuid,asyncio=asyncio,
            RISK_ASSESSMENT_JOBS={'risk-contract':{'cancel_requested':False}},
            Assessment=models.Assessment,SecurityFinding=models.SecurityFinding,
            RiskAssessmentRun=models.RiskAssessmentRun,PostExploitationValidation=models.PostExploitationValidation,
            get_db=lambda:iter([support.Factory()]))
        names={'_now','_serialize_run','_finding_snapshot','_run_risk_assessment'}
        nodes=[n for n in ast.parse((ROOT/'risk_assessment_router.py').read_text(encoding='utf-8')).body
               if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in names]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'risk_assessment_router.py','exec',
                     flags=__future__.annotations.compiler_flag),namespace)
        asyncio.run(namespace['_run_risk_assessment']('risk-contract',NS(assessment_id=summary['assessment_id']),1))
        risk_job=namespace['RISK_ASSESSMENT_JOBS']['risk-contract']
        self.assertEqual(risk_job['status'],'completed',risk_job)
        reporting.REPORT_JOBS['report-contract']={}
        with patch.object(database,'SessionLocal',support.Factory):
            asyncio.run(reporting._run_report('report-contract',NS(assessment_id=summary['assessment_id'],report_type='COMPLETE'),1))
        job=reporting.REPORT_JOBS['report-contract']
        self.assertEqual(job['status'],'completed',job)
        canonical=job['result']['canonical_data']
        self.assertEqual(canonical['risk_assessment']['total_findings'],len(evidence['findings']))
        self.assertEqual(len(canonical['findings']),len(evidence['findings']))
        self.assertEqual(canonical['risk_assessment']['average_cvss'],score)
        if evidence['findings']:
            self.assertEqual(canonical['findings'][0]['tool_name'],'Nuclei')
            self.assertEqual(canonical['findings'][0]['cvss_score'],score)
        if evidence['findings'] and evidence['findings'][0]['severity']=='unknown':
            self.assertEqual(canonical['findings'][0]['severity'],'UNRATED')
            self.assertEqual(canonical['risk_assessment']['overall_risk'],'UNRATED')

    def test_same_job_replay_preserves_one_assessment_and_finding(self):
        a,_=self.persist()
        b,notices=self.persist()
        self.assertEqual(a['assessment_id'],b['assessment_id'])
        self.assertTrue(b['replayed'])
        self.assertEqual(notices,[])
        with support.Factory() as db:
            self.assertEqual(db.query(models.Assessment).count(),1)
            self.assertEqual(db.query(models.SecurityFinding).count(),1)

    def test_new_scan_keeps_new_history_even_when_findings_are_identical(self):
        a,_=self.persist(job='first-scan')
        b,_=self.persist(job='second-scan')
        self.assertNotEqual(a['assessment_id'],b['assessment_id'])
        with support.Factory() as db:
            self.assertEqual(db.query(models.SecurityFinding).count(),2)

    def test_background_storage_id_fits_existing_36_character_schema(self):
        job='57f6da9a-7784-4ff0-8eab-70fdde449da7'
        self.persist(job=job)
        with support.Factory() as db:
            record=db.query(models.BackgroundJob).one()
            self.assertEqual(len(record.job_id),36)
            self.assertEqual(uuid.UUID(record.job_id).version,5)


    def test_completed_result_can_be_loaded_without_in_memory_job(self):
        summary,_=self.persist(job='stored-scan')
        with support.Factory() as db:
            loaded=workflow.load_saved_nuclei_job(db,'stored-scan',1,10)
        self.assertEqual(loaded['result']['assessment_id'],summary['assessment_id'])
        self.assertEqual(loaded['result']['persistence']['status'],'saved')


    def test_stored_result_is_not_visible_to_other_owner(self):
        self.persist(job='stored-scan')
        with support.Factory() as db:
            self.assertIsNone(workflow.load_saved_nuclei_job(db,'stored-scan',2,20))
            self.assertIsNone(workflow.load_saved_nuclei_job(db,'stored-scan',4,10))


    def test_stored_result_cannot_follow_changed_client_scope(self):
        self.persist(job='stored-scan')
        with support.Factory() as db:
            db.get(models.User,1).client_id=20
            db.commit()
            self.assertIsNone(workflow.load_saved_nuclei_job(db,'stored-scan',1,20))


    def test_two_owners_do_not_share_findings_or_events(self):
        self.persist(owner=1,client=10,job='owner-1')
        self.persist(owner=2,client=20,job='owner-2')
        with support.Factory() as db:
            self.assertEqual({row.user_id for row in db.query(models.SecurityFinding).all()},{1,2})
            self.assertEqual({row.owner_user_id for row in db.query(models.SecurityEvent).all()},{1,2})

    def test_legacy_replay_identity_separates_owners(self):
        a,_=self.persist(owner=1,client=10,job=None)
        b,_=self.persist(owner=2,client=20,job=None)
        repeated,notices=self.persist(owner=1,client=10,job=None)
        self.assertNotEqual(a['assessment_id'],b['assessment_id'])
        self.assertEqual(a['assessment_id'],repeated['assessment_id'])
        self.assertTrue(repeated['replayed'])
        self.assertEqual(notices,[])

    def test_legacy_replay_identity_separates_initiators_within_client(self):
        a,_=self.persist(owner=1,client=10,job=None)
        b,_=self.persist(owner=4,client=10,job=None)
        self.assertNotEqual(a['assessment_id'],b['assessment_id'])

    def test_changed_captured_scope_rejects_even_empty_scan(self):
        evidence=self.evidence()
        evidence['findings']=[]
        with self.assertRaises(ValueError):
            self.persist(evidence,owner=1,client=20)
        with support.Factory() as db:
            self.assertEqual(db.query(models.Assessment).count(),0)

    def test_duplicate_reported_match_is_counted_once(self):
        evidence=self.evidence()
        evidence['findings'].append(deepcopy(evidence['findings'][0]))
        summary,notices=self.persist(evidence)
        self.assertEqual(summary['finding_count'],1)
        self.assertEqual(len(notices),1)

    def test_failed_event_storage_rolls_back_canonical_finding_and_assessment(self):
        with patch.object(workflow,'store_security_event',side_effect=RuntimeError('synthetic failure')):
            with self.assertRaises(RuntimeError):
                self.persist()
        with support.Factory() as db:
            for model in (models.Assessment,models.SecurityFinding,models.SecurityEvent,models.BackgroundJob):
                self.assertEqual(db.query(model).count(),0)

    def test_payload_cannot_override_owner_or_assessment(self):
        evidence=self.evidence()
        evidence.update(user_id=2,owner_user_id=2,client_id=20,assessment_id=999)
        summary,notices=self.persist(evidence)
        self.assertNotEqual(summary['assessment_id'],999)
        self.assertEqual((notices[0]['owner_user_id'],notices[0]['client_id']),(1,10))

    def test_missing_score_and_invalid_values_are_not_invented(self):
        for value in (None,True,'bad',-1,11,float('nan')):
            self.assertIsNone(workflow.cvss_value(self.evidence(score=value)['findings'][0]))
        self.assertEqual(workflow.cvss_value(self.evidence(score=0)['findings'][0]),0)


if __name__=='__main__':
    unittest.main(verbosity=2)
