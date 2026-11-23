"""Exercise discovery HTTP authorization, latest observations and pagination in SQLite."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest

os.environ['DATABASE_URL']='sqlite://'
os.environ['JWT_SECRET_KEY']='isolated-admin-discovery-test-not-for-deployment'
ROOT=Path(os.environ.get('SOC_NMAP_AUDIT_BACKEND',Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
import nmap_owned_inventory_regression as fixtures
import admin_discovered_servers as discovery
import rbac
from fastapi import FastAPI
from fastapi.testclient import TestClient


class AdminDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.NmapOwnedInventoryTests()
        self.fixture.setUp()
        self.identity=NS(id=99,role_id=3,client_id=None)
        app=FastAPI()
        app.include_router(discovery.router,prefix='/assets')
        app.dependency_overrides[discovery.get_db]=fixtures.support.get_db
        app.dependency_overrides[rbac.get_current_user]=lambda:self.identity
        self.client=TestClient(app)

    def tearDown(self):
        self.client.close()
        self.fixture.tearDown()

    def test_admin_reads_the_exact_owned_observation(self):
        summary,_=self.fixture.save()
        response=self.client.get('/assets/discovered-servers')
        self.assertEqual(response.status_code,200,response.text)
        data=response.json()
        self.assertEqual(data['total'],1)
        row=data['servers'][0]
        self.assertEqual((row['owner_user_id'],row['client_id']),(10,100))
        self.assertEqual(row['assessment_id'],summary['assessment_id'])
        self.assertEqual(row['open_port_count'],1)
        self.assertTrue(data['read_only'])

    def test_customer_role_cannot_read_global_discoveries(self):
        self.fixture.save()
        self.identity=NS(id=10,role_id=1,client_id=100)
        self.assertEqual(self.client.get('/assets/discovered-servers').status_code,403)

    def test_latest_scan_does_not_inflate_observation_count(self):
        self.fixture.save()
        latest,_=self.fixture.save(job='second-job')
        data=self.client.get('/assets/discovered-servers').json()
        self.assertEqual(data['total'],1)
        self.assertEqual(data['servers'][0]['assessment_id'],latest['assessment_id'])
        self.assertEqual(self.fixture.counts(),(2,2,2,2,0))

    def test_same_address_keeps_customer_and_owner_boundaries(self):
        self.fixture.save()
        self.fixture.save(owner=11,client=100,job='colleague')
        self.fixture.save(owner=20,client=200,job='other-customer')
        all_data=self.client.get('/assets/discovered-servers').json()
        self.assertEqual(all_data['total'],3)
        data=self.client.get('/assets/discovered-servers',params={'client_id':100}).json()
        self.assertEqual({row['owner_user_id'] for row in data['servers']},{10,11})
        owner=self.client.get('/assets/discovered-servers',params={'user_id':20}).json()
        self.assertEqual({row['owner_user_id'] for row in owner['servers']},{20})

    def test_search_happens_before_pagination(self):
        self.fixture.save()
        self.fixture.save(owner=20,client=200,job='newer')
        data=self.client.get('/assets/discovered-servers',params={'q':'fixture-10-username','limit':1}).json()
        self.assertEqual(data['total'],1)
        self.assertEqual(data['servers'][0]['owner_user_id'],10)
        self.assertEqual(self.client.get('/assets/discovered-servers',params={'limit':1,'offset':1}).json()['total'],2)

    def test_invalid_limits_and_identifiers_are_rejected(self):
        for params in ({'limit':0},{'limit':201},{'offset':-1},{'user_id':0},{'client_id':-1}):
            self.assertEqual(self.client.get('/assets/discovered-servers',params=params).status_code,422)

    def test_partial_scan_is_not_reported_as_clean_completion(self):
        self.fixture.save(evidence=fixtures.result('completed_with_errors'))
        row=self.client.get('/assets/discovered-servers').json()['servers'][0]
        self.assertEqual(row['scan_status'],'COMPLETED_WITH_ERRORS')

    def test_discovery_view_does_not_mutate_scan_history(self):
        self.fixture.save()
        before=self.fixture.counts()
        self.assertEqual(self.client.post('/assets/discovered-servers',json={}).status_code,405)
        self.assertEqual(self.client.get('/assets/discovered-servers').status_code,200)
        self.assertEqual(self.fixture.counts(),before)


if __name__=='__main__':
    unittest.main(verbosity=2)
