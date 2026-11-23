"""Check Nuclei's assessment/report contract with actual persistence and a mocked runner."""
import ast
import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import time
import unittest

os.environ['DATABASE_URL']='sqlite://'
os.environ['JWT_SECRET_KEY']='isolated-nuclei-assessment-contract-test'
ROOT=Path(os.environ.get('SOC_TOOL_AUDIT_BACKEND',Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
import tool_event_ownership_regression as fixtures
import models
from security_events import generate_event_id,create_security_event
from security_event_store import store_security_event

for model in (models.Assessment,models.SecurityFinding):
    model.__table__.create(fixtures.support.engine,checkfirst=True)


class NucleiAssessmentLinkageTests(unittest.TestCase):
    def setUp(self):
        with fixtures.support.Factory() as db:
            db.query(models.SecurityFinding).delete()
            db.query(models.Assessment).delete()
            db.commit()
        self.fixture=fixtures.ToolEventOwnershipTests()
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def test_nuclei_event_and_report_finding_share_owned_assessment(self):
        self.fixture.persist('nuclei',1)
        with fixtures.support.Factory() as db:
            event=db.query(models.SecurityEvent).filter(models.SecurityEvent.source=='nuclei').one()
            self.assertIsNotNone(event.assessment_id,'Nuclei event has no shared assessment link.')
            assessment=db.get(models.Assessment,event.assessment_id)
            self.assertIsNotNone(assessment)
            self.assertEqual(assessment.user_id,1)
            findings=db.query(models.SecurityFinding).filter(models.SecurityFinding.assessment_id==assessment.id).all()
            self.assertEqual(len(findings),1,'Reported Nuclei finding is missing from the canonical report findings table.')
            self.assertEqual(findings[0].user_id,1)
            self.assertEqual(findings[0].tool_name,'Nuclei')

    def test_valid_zero_finding_scan_retains_an_assessment_record(self):
        evidence=self.fixture.result('nuclei')
        evidence['findings']=[]
        self.fixture.persist('nuclei',1,evidence)
        with fixtures.support.Factory() as db:
            assessments=db.query(models.Assessment).filter(models.Assessment.user_id==1).all()
            self.assertEqual(len(assessments),1,'A completed zero-finding Nuclei scan has no assessment history.')
            self.assertEqual(assessments[0].vapt_findings_count,0)

    def test_zero_finding_result_still_validates_captured_owner(self):
        evidence=self.fixture.result('nuclei')
        evidence['findings']=[]
        with self.assertRaises(ValueError):
            self.fixture.functions['nuclei'](evidence,user_id=999,client_id=10)

    def test_storage_failure_is_not_clean_job_completion(self):
        path=ROOT/'vapt_registry_router.py'
        node=next(n for n in ast.parse(path.read_text(encoding='utf-8')).body
                  if isinstance(n,ast.AsyncFunctionDef) and n.name=='_run_nuclei_job')
        job={'job_id':'fixture-job','user_id':1,'client_id':10}
        def fail(*args,**kwargs):
            raise RuntimeError('synthetic persistence failure')
        namespace={'NUCLEI_JOBS':{'fixture-job':job},'asyncio':asyncio,'time':time,
                   'run_nuclei':lambda *args,**kwargs:deepcopy(self.fixture.result('nuclei')),
                   '_persist_nuclei_security_events':fail}
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),namespace)
        asyncio.run(namespace['_run_nuclei_job']('fixture-job','https://synthetic.invalid'))
        self.assertNotEqual(job['status'],'completed','Nuclei reports clean completion even though saving its result failed.')


if __name__=='__main__':
    unittest.main(verbosity=2)
