"""Actual Nmap persistence and view handlers, isolated from PostgreSQL/scanners."""
import ast
import asyncio
import copy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

os.environ['DATABASE_URL']='sqlite://'
os.environ['JWT_SECRET_KEY']='isolated-nmap-workflow-test-not-for-deployment'
ROOT=Path(os.environ.get('SOC_NMAP_AUDIT_BACKEND',Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
import asset_registration_regression as support
import models
import nmap_workflow as workflow
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

TABLES=(models.Assessment,models.AssetDiscoveryRun,models.ServerAsset,models.SecurityEvent,models.SecurityFinding)
for model in TABLES:
    model.__table__.create(support.engine,checkfirst=True)


def handler(filename,name):
    node=next(n for n in ast.parse((ROOT/filename).read_text(encoding='utf-8')).body
              if isinstance(n,ast.FunctionDef) and n.name==name)
    namespace={'router':APIRouter(),'Depends':Depends,'Session':Session,'User':models.User,
               'Assessment':models.Assessment,'ServerAsset':models.ServerAsset,'SecurityFinding':models.SecurityFinding,
               'get_db':support.get_db,'require_role':lambda *args:lambda:None,'json':json,'func':func}
    exec(compile(ast.Module(body=[node],type_ignores=[]),filename,'exec'),namespace)
    return namespace[name]


def result(status='completed'):
    return {'tool':'Nmap','target':'192.0.2.10','scan_type':'quick','status':status,
            'results':{'hosts':[{'addresses':[{'type':'mac','address':'00:00:00:00:00:01'},
                {'type':'ipv4','address':'192.0.2.10'}], 'status':'up','hostnames':[{'name':'fixture'}],
                'ports':[{'port':443,'protocol':'tcp','state':'open','service':{'name':'https'}},
                         {'port':22,'protocol':'tcp','state':'closed'}]}]}}


class NmapOwnedInventoryTests(unittest.TestCase):
    def setUp(self):
        with support.Factory() as db:
            for model in reversed(TABLES):
                db.query(model).delete()
            for model in reversed(support.TABLE_MODELS):
                db.query(model).delete()
            for cid in (100,200):
                db.add(support.fixture(models.Client,id=cid))
            for uid,cid in ((1,None),(2,None),(10,100),(11,100),(20,200)):
                db.add(support.fixture(models.User,id=uid,role_id=1,client_id=cid))
            db.commit()
        self.detector=patch('detection_engine.evaluate_event',return_value={'detections_matched':0,'alerts_generated':0})
        self.evaluate=self.detector.start()

    def tearDown(self):
        self.detector.stop()

    def save(self,owner=10,client=100,job='fixture-job',evidence=None):
        with support.Factory() as db:
            summary,notice=workflow.persist_nmap_completion(db,evidence or result(),owner,client,job)
            db.commit()
            return summary,notice

    def counts(self):
        with support.Factory() as db:
            return tuple(db.query(model).count() for model in TABLES)

    def test_assessment_inventory_and_event_have_one_owned_link(self):
        summary,notice=self.save()
        with support.Factory() as db:
            asset=db.query(models.ServerAsset).one()
            event=db.query(models.SecurityEvent).one()
            run=db.query(models.AssetDiscoveryRun).one()
            self.assertEqual((asset.user_id,run.user_id,event.owner_user_id,event.client_id),(10,10,10,100))
            self.assertEqual((asset.assessment_id,run.assessment_id,event.assessment_id),(summary['assessment_id'],)*3)
            self.assertEqual(asset.open_port_count,1)
            self.assertEqual(asset.ip_address,'192.0.2.10')
            self.assertEqual(db.query(models.SecurityFinding).count(),0)
        self.assertEqual((notice['owner_user_id'],notice['client_id']),(10,100))
        self.assertEqual(self.evaluate.call_count,1)

    def test_different_clients_same_ip_have_distinct_records(self):
        a,first=self.save()
        b,second=self.save(owner=20,client=200,job='other-job')
        self.assertNotEqual(a['assessment_id'],b['assessment_id'])
        self.assertNotEqual(first['event_id'],second['event_id'])
        self.assertEqual(self.counts(),(2,2,2,2,0))

    def test_same_client_initiators_keep_separate_jobs(self):
        _,first=self.save()
        _,second=self.save(owner=11,client=100,job='same-client-job')
        self.assertNotEqual(first['event_id'],second['event_id'])
        self.assertEqual(self.counts(),(2,2,2,2,0))

    def test_personal_accounts_remain_separate(self):
        _,a=self.save(owner=1,client=None)
        _,b=self.save(owner=2,client=None,job='personal-other')
        self.assertNotEqual(a['event_id'],b['event_id'])
        self.assertIsNone(a['client_id'])

    def test_job_replay_does_not_duplicate_evidence_or_detection(self):
        first,a=self.save()
        second,b=self.save()
        self.assertEqual(first['assessment_id'],second['assessment_id'])
        self.assertEqual(a['event_id'],b['event_id'])
        self.assertTrue(second['replayed'])
        self.assertEqual(self.counts(),(1,1,1,1,0))
        self.assertEqual(self.evaluate.call_count,1)

    def test_job_id_cannot_be_taken_by_another_owner(self):
        self.save()
        with self.assertRaises(ValueError):
            self.save(owner=20,client=200)
        self.assertEqual(self.counts(),(1,1,1,1,0))

    def test_replay_cannot_replace_saved_evidence(self):
        self.save()
        changed=result()
        changed['results']['hosts'][0]['ports'].append({'port':80,'protocol':'tcp','state':'open'})
        with self.assertRaises(ValueError):
            self.save(evidence=changed)
        self.assertEqual(self.counts(),(1,1,1,1,0))

    def test_changed_or_missing_owner_creates_nothing(self):
        for owner,client in ((10,200),(999,100),(None,100),(True,100)):
            with self.assertRaises(ValueError):
                self.save(owner=owner,client=client)
        self.assertEqual(self.counts(),(0,0,0,0,0))

    def test_payload_cannot_select_another_owner(self):
        evidence=result()
        evidence.update(owner_user_id=20,client_id=200,assessment_id=999)
        _,notice=self.save(evidence=evidence)
        self.assertEqual((notice['owner_user_id'],notice['client_id']),(10,100))
        self.assertNotEqual(notice['assessment_id'],999)

    def test_partial_scan_keeps_warning_and_observations(self):
        _,notice=self.save(evidence=result('completed_with_errors'))
        self.assertIn('warnings',notice['message'])
        self.assertEqual(notice['severity'],'WARNING')
        with support.Factory() as db:
            self.assertEqual(db.query(models.AssetDiscoveryRun).one().status,'COMPLETED_WITH_ERRORS')
            self.assertEqual(db.query(models.ServerAsset).one().open_port_count,1)

    def test_event_failure_rolls_back_inventory_and_assessment(self):
        with patch.object(workflow,'store_security_event',side_effect=RuntimeError('synthetic storage failure')):
            with self.assertRaises(RuntimeError):
                self.save()
        self.assertEqual(self.counts(),(0,0,0,0,0))

    def test_real_customer_and_admin_handlers_share_assessment_ids(self):
        summary,_=self.save()
        self.save(owner=20,client=200,job='foreign')
        user=NS(id=10,client_id=100,role_id=1)
        with support.Factory() as db:
            user_inventory=handler('client_portal.py','client_asset_inventory')(current_user=user,db=db)
            servers=handler('client_portal.py','client_servers')(current_user=user,db=db)
            admin=handler('admin.py','get_all_assessments')(current_user=NS(id=99,role_id=2),db=db)
        self.assertEqual([row['assessment_id'] for row in user_inventory['assets']],[summary['assessment_id']])
        self.assertEqual([row['assessment_id'] for row in servers['servers']],[summary['assessment_id']])
        self.assertIn(summary['assessment_id'],[row['id'] for row in admin['assessments']])

    def test_worker_keeps_result_when_persistence_fails_and_persists_failure(self):
        import time
        path=ROOT/'vapt.py'
        node=next(n for n in ast.parse(path.read_text(encoding='utf-8')).body
                  if isinstance(n,ast.AsyncFunctionDef) and n.name=='_run_nmap_job')
        saved=[]
        job={'user_id':10,'client_id':100,'job_id':'worker-job'}
        async def execute(**kwargs):
            return result()
        def fail(*args):
            raise RuntimeError('synthetic persistence failure')
        ns={'NMAP_JOBS':{'worker-job':job},'asyncio':asyncio,'time':time,
            '_execute_nmap_command':execute,'_save_nmap_hosts_to_asset_inventory':fail,
            '_persist_background_job':lambda row,tool:saved.append(row.copy()),'notify_security_event':lambda event:None}
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),ns)
        asyncio.run(ns['_run_nmap_job']('worker-job','192.0.2.10','quick'))
        self.assertEqual(job['status'],'failed')
        self.assertEqual(job['result']['results']['hosts'][0]['status'],'up')
        self.assertEqual(saved[-1]['status'],'failed')

    def test_actual_worker_commits_before_scoped_notification(self):
        import time
        path=ROOT/'vapt.py'
        names={'_run_nmap_job','_save_nmap_hosts_to_asset_inventory'}
        nodes=[n for n in ast.parse(path.read_text(encoding='utf-8')).body
               if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in names]
        notices=[]
        job={'user_id':10,'client_id':100,'job_id':'worker-success'}
        async def execute(**kwargs):
            return result('completed_with_errors')
        def notify(event):
            # A separate DB session must already see committed evidence.
            self.assertEqual(self.counts(),(1,1,1,1,0))
            notices.append(event)
        ns={'NMAP_JOBS':{'worker-success':job},'asyncio':asyncio,'time':time,
            '_execute_nmap_command':execute,'SessionLocal':support.Factory,
            '_persist_background_job':lambda *args:None,'notify_security_event':notify}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns)
        asyncio.run(ns['_run_nmap_job']('worker-success','192.0.2.10','quick'))
        self.assertEqual(job['status'],'completed_with_errors',job)
        self.assertEqual(len(notices),1)
        self.assertEqual((notices[0]['owner_user_id'],notices[0]['client_id']),(10,100))
        self.assertEqual(job['result']['assessment_id'],notices[0]['assessment_id'])
        self.assertIn('warnings',notices[0]['message'])


if __name__=='__main__':
    unittest.main(verbosity=2)
