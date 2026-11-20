"""Execute real Nmap orchestration using recorded XML and a fake process runner.

No application imports, subprocesses, network requests or database access.
"""
import ast
import asyncio
from copy import deepcopy
import os
from pathlib import Path
import sys
import time
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(os.environ.get('SOC_SCAN_AUDIT_BACKEND', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))
PROFILES = ('api', 'detailed', 'comprehensive')


def xml_fixture(ports=(22, 443), script=None, host_script=None):
    root = ET.Element('nmaprun')
    if ports is not None:
        host = ET.SubElement(root, 'host')
        ET.SubElement(host, 'status', state='up')
        ET.SubElement(host, 'address', addr='192.0.2.10', addrtype='ipv4')
        container = ET.SubElement(host, 'ports')
        for number in ports:
            port = ET.SubElement(container, 'port', protocol='tcp', portid=str(number))
            ET.SubElement(port, 'state', state='open')
            if number == 443:
                ET.SubElement(port, 'service', name='https', product='FixtureServer', version='1.2')
                if script:
                    ET.SubElement(port, 'script', id=script, output=f'Synthetic {script} evidence')
        if host_script:
            scripts = ET.SubElement(host, 'hostscript')
            ET.SubElement(scripts, 'script', id=host_script, output=f'Synthetic {host_script} evidence')
    stats = ET.SubElement(root, 'runstats')
    ET.SubElement(stats, 'finished', exit='success', elapsed='1')
    ET.SubElement(stats, 'hosts', up='0' if ports is None else '1', down='0', total='1')
    return ET.tostring(root, encoding='unicode')


class NmapMultiPassTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'vapt.py'
        wanted = {'_parse_nmap_script', 'parse_nmap_xml', '_extract_open_ports', '_execute_nmap_command'}
        nodes = [node for node in ast.parse(path.read_text(encoding='utf-8')).body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted]
        self.assertEqual({node.name for node in nodes}, wanted)
        self.namespace = {
            'ET': ET, 'time': time, 'os': os, 'asyncio': asyncio,
            'NMAP_PATH': str(path), 'validate_nmap_target': lambda target: target,
            'NMAP_PROFILES': {name: {'profile': name} for name in PROFILES},
            'NMAP_QUICK_TIMEOUT': 1, 'NMAP_SERVICE_TIMEOUT': 1,
            'NMAP_DETAILED_TIMEOUT': 1, 'NMAP_COMPREHENSIVE_TIMEOUT': 1,
            'NMAP_PORT_SCAN_TIMEOUT': 1, 'NMAP_VULN_SCRIPTS': 'fixture-vuln',
            'NMAP_HTTP_SCRIPTS': 'fixture-http', '_nmap_rate_args': lambda: [],
        }
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     str(path), 'exec'), self.namespace)

    def run_fixture(self, profile='detailed', overrides=None, empty_full=False, subset_detail=False):
        self.calls, self.published = [], []
        overrides = overrides or {}
        async def fake_pass(command, *args, **kwargs):
            if '--top-ports' in command:
                stage = 'discovery'
            elif '-p-' in command:
                stage = 'full'
            elif '-sV' in command:
                stage = 'detail'
            else:
                script = command[command.index('--script') + 1]
                stage = 'vuln' if script == 'fixture-vuln' else 'http'
            self.calls.append(stage)
            data = overrides.get(stage, {})
            if isinstance(data, Exception):
                raise data
            if stage == 'full' and empty_full:
                xml = xml_fixture(ports=None)
            elif stage == 'detail':
                xml = xml_fixture(ports=(443,) if subset_detail else (22, 443), script='service-script')
            elif stage in ('vuln', 'http'):
                xml = xml_fixture(ports=(443,), script=stage + '-script', host_script=stage + '-host-script')
            else:
                xml = xml_fixture()
            return {'xml': xml, 'return_code': 0, 'timed_out': False, **data}
        async def capture(result):
            self.published.append(deepcopy(result))
        self.namespace['_run_nmap_pass'] = fake_pass
        return asyncio.run(self.namespace['_execute_nmap_command'](
            '192.0.2.10', profile, result_callback=capture))

    def stages(self, profile):
        return ('discovery', 'http') if profile == 'api' else ('discovery', 'full', 'detail', 'vuln', 'http')

    def scripts(self, result):
        return {script['id'] for host in result['results']['hosts']
                for port in host['ports'] for script in port['scripts']}

    def test_successful_profiles_complete(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                result = self.run_fixture(profile)
                self.assertEqual(result['status'], 'completed')
                self.assertEqual(result['return_code'], 0)
                self.assertEqual(set(result['open_ports']), {22, 443})

    def test_any_nonzero_stage_prevents_clean_completion(self):
        for profile in PROFILES:
            for stage in self.stages(profile):
                with self.subTest(profile=profile, stage=stage):
                    result = self.run_fixture(profile, {stage: {'return_code': 2}})
                    self.assertNotEqual(result['status'], 'completed')
                    self.assertNotEqual(result.get('return_code'), 0)

    def test_malformed_stage_output_prevents_clean_completion(self):
        for profile in PROFILES:
            for stage in self.stages(profile):
                with self.subTest(profile=profile, stage=stage):
                    result = self.run_fixture(profile, {stage: {'xml': '<nmaprun><host>'}})
                    self.assertNotEqual(result['status'], 'completed')

    def test_xml_reported_error_prevents_clean_completion(self):
        xml = '<nmaprun><runstats><finished exit="error" errormsg="Synthetic stage failure"/></runstats></nmaprun>'
        for profile in PROFILES:
            with self.subTest(profile=profile):
                result = self.run_fixture(profile, {'http': {'xml': xml}})
                self.assertNotEqual(result['status'], 'completed')

    def test_timeout_prevents_clean_completion(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                result = self.run_fixture(profile, {'http': {'return_code': -9, 'timed_out': True}})
                self.assertNotEqual(result['status'], 'completed')

    def test_failed_full_scan_never_claims_complete_tcp_coverage(self):
        for profile in ('detailed', 'comprehensive'):
            with self.subTest(profile=profile):
                result = self.run_fixture(profile, {'full': {'return_code': 2}})
                self.assertFalse(result['workflow']['all_tcp_ports_scanned'])

    def test_later_script_timeout_does_not_erase_completed_port_coverage(self):
        result = self.run_fixture(overrides={'http': {'return_code': -9, 'timed_out': True}})
        self.assertTrue(result['workflow']['all_tcp_ports_scanned'])
        self.assertNotEqual(result['status'], 'completed')

    def test_valid_empty_full_scan_is_authoritative(self):
        result = self.run_fixture(empty_full=True)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['open_ports'], [])
        self.assertEqual(self.calls, ['discovery', 'full'])

    def test_partial_service_pass_does_not_drop_discovered_ports(self):
        result = self.run_fixture(subset_detail=True)
        ports = {port['port'] for host in result['results']['hosts'] for port in host['ports']}
        self.assertEqual(ports, {22, 443})

    def test_successful_stage_evidence_is_preserved(self):
        result = self.run_fixture()
        self.assertTrue({'service-script', 'vuln-script', 'http-script'} <= self.scripts(result))

    def test_service_exception_keeps_other_stage_results(self):
        result = self.run_fixture(overrides={'detail': OSError('Synthetic service process failure')})
        self.assertNotEqual(result['status'], 'completed')
        self.assertTrue(result['results']['hosts'])
        self.assertIn('vuln-script', self.scripts(result))

    def test_intermediate_updates_do_not_claim_failed_full_scan_completed(self):
        self.run_fixture(overrides={'full': {'return_code': 2}})
        self.assertFalse(any(item.get('workflow', {}).get('all_tcp_ports_scanned')
                             for item in self.published))

    def test_final_callback_keeps_stage_error_details(self):
        result = self.run_fixture(overrides={'vuln': {'return_code': 2}})
        stage = next(item for item in result['workflow']['stage_results'] if item['name'] == 'vulnerability_nse')
        self.assertEqual(stage['return_code'], 2)
        self.assertNotEqual(stage['status'], 'completed')
        self.assertTrue(stage['errors'])
        self.assertEqual(self.published[-1]['status'], 'completed_with_errors')

    def test_cancellation_is_propagated(self):
        async def cancelled(*args, **kwargs):
            raise asyncio.CancelledError()
        self.namespace['_run_nmap_pass'] = cancelled
        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(self.namespace['_execute_nmap_command']('192.0.2.10', 'detailed'))


class NmapEvidenceMergeTests(unittest.TestCase):
    def setUp(self):
        from nmap_result_integrity import merge_nmap_results
        self.merge = merge_nmap_results

    def host(self, address='192.0.2.10', protocol='tcp', script='fixture-script'):
        return {'hosts': [{'addresses': [{'type': 'ipv4', 'address': address}],
                           'status': 'up', 'hostnames': [], 'scripts': [], 'os_matches': [],
                           'ports': [{'protocol': protocol, 'port': 443, 'state': 'open',
                                      'service': {'name': 'https'},
                                      'scripts': [{'id': script, 'output': 'Synthetic evidence'}]}]}]}

    def test_protocols_are_not_conflated(self):
        merged = self.merge(self.host(), self.host(protocol='udp'))
        self.assertEqual({port['protocol'] for port in merged['hosts'][0]['ports']}, {'tcp', 'udp'})

    def test_different_addresses_remain_separate_hosts(self):
        self.assertEqual(self.merge(self.host(), self.host(address='192.0.2.11'))['host_count'], 2)

    def test_identical_scripts_are_deduplicated_without_losing_distinct_scripts(self):
        merged = self.merge(self.host(), self.host(), self.host(script='other-script'))
        scripts = merged['hosts'][0]['ports'][0]['scripts']
        self.assertEqual({item['id'] for item in scripts}, {'fixture-script', 'other-script'})
        self.assertEqual(len(scripts), 2)

    def test_merging_does_not_mutate_original_evidence(self):
        first, second = self.host(), self.host(script='other-script')
        original = deepcopy(first)
        self.merge(first, second)
        self.assertEqual(first, original)

    def test_alias_order_does_not_prevent_matching_the_same_ip(self):
        first, second = self.host(), self.host(script='other-script')
        second['hosts'][0]['addresses'].insert(0, {'type': 'mac', 'address': '00:00:00:00:00:01'})
        merged = self.merge(first, second)
        self.assertEqual(merged['host_count'], 1)
        self.assertEqual(len(merged['hosts'][0]['ports'][0]['scripts']), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
