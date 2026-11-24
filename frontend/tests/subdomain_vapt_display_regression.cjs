const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

(async () => {
  const { subdomainVaptView: view, subdomainResultVisibility: visibility } = await import(pathToFileURL(path.join(__dirname, '../src/subdomainVaptView.mjs')));
  assert.deepEqual(visibility(null, true), {showCurrent: false});
  assert.deepEqual(visibility(null, false), {showCurrent: false}, 'Fresh page must not show historical results');
  assert.deepEqual(visibility({status: 'completed'}, false), {showCurrent: false}, 'A current job identifier is required');
  for (const status of ['queued', 'running', 'unknown']) {
    assert.deepEqual(visibility({jobId: 'fixture-job', status, result: {status: 'completed'}}, false),
      {showCurrent: false}, 'Pending job exposed stale results');
  }
  assert.deepEqual(visibility({jobId: 'fixture-job', status: 'completed', result: {status: 'running'}}, false),
    {showCurrent: false});
  for (const status of ['completed', 'completed_with_errors', 'failed', 'timeout', 'cancelled', 'not_available']) {
    assert.deepEqual(visibility({jobId: 'fixture-job', status}, false), {showCurrent: true});
    assert.deepEqual(visibility({jobId: 'fixture-job', status}, true), {showCurrent: false});
  }
  const discovery = {target_domain: 'example.test', discovered_subdomains: ['www.example.test', 'www.example.test'],
    discovered_hosts: ['www.example.test'], discovered_ips: ['192.0.2.10'],
    observations: [{name: 'www.example.test', type: 'A', address: '192.0.2.10'}]};
  const completed = view({jobId: 'fixture-job', status: 'completed', result: {
    status: 'completed', discovery, assessment_id: 7, discovery_run_id: 9, persistence: {status: 'saved'}}});
  assert.equal(completed.label, 'Completed');
  assert.deepEqual(completed.counts, {subdomains: 1, hosts: 1, ips: 1});
  assert.equal(completed.observations[0].address, '192.0.2.10');
  assert.equal(completed.assessmentId, 7);
  assert.equal(completed.runId, 9);
  const running = view({status: 'running'});
  assert.equal(running.counts, null, 'Pending execution must not claim zero results');
  assert.equal(running.terminal, false);
  const empty = view({status: 'completed', result: {status: 'completed', discovery: {
    discovered_subdomains: [], discovered_hosts: [], discovered_ips: [], observations: []}}});
  assert.deepEqual(empty.counts, {subdomains: 0, hosts: 0, ips: 0});
  const partial = view({status: 'completed', result: {status: 'completed_with_errors', discovery}});
  assert(partial.warning);
  assert.equal(partial.observations.length, 1);
  const failedSave = view({status: 'completed', result: {status: 'completed',
    persistence: {status: 'failed', error: 'Fixture save failure'}, json_output: [{name: 'www.example.test'}]}});
  assert.equal(failedSave.status, 'completed_with_errors');
  assert.equal(failedSave.counts, null);
  assert.match(failedSave.rawRecords, /www.example.test/);
  for (const status of ['failed', 'timeout', 'not_available', 'cancelled']) {
    const item = view({status, result: {status, error: 'Fixture error'}});
    assert(item.terminal);
    assert.notEqual(item.label, 'Completed');
    assert.equal(item.error, 'Fixture error');
  }
  assert.equal(view({status: 'completed', result: {status: 'failed'}}).status, 'failed');
  assert.equal(view({result: {discovery: 'invalid'}}).counts, null);
  const app = fs.readFileSync(path.join(__dirname, '../src/App.jsx'), 'utf8');
  const start = app.indexOf('function VAPTTesting({');
  const end = app.indexOf('\nfunction WiresharkResultsPage', start);
  const body = app.slice(start, end);
  assert.match(body, /<SubdomainVaptResults\s+job=\{genericToolJobs\["subdomain-discovery"\]\}/);
  assert.match(body, /<SubdomainVaptResults[^\n]+scanRunning=\{loading\}/);
  assert(body.indexOf('<SubdomainVaptResults') > body.indexOf('{/* GENERIC TOOLS LIVE PROGRESS */}'));
  const component = fs.readFileSync(path.join(__dirname, '../src/SubdomainVaptResults.jsx'), 'utf8');
  assert(!component.includes('SubdomainResults'), 'VAPT must not import or mount saved history');
  assert(!component.includes('Previous saved discovery runs'));
  assert.match(component, /if \(!visibility\.showCurrent\) return null/);
  assert.match(component, /return <CurrentSubdomainResult/);
  assert(!component.includes('dangerouslySetInnerHTML'));
  assert(!component.includes('fetch('), 'Inline current-job panel must not start a request or scan');
  console.log('PASS: no results before a scan or during execution; current terminal result displayed; no history mounted in VAPT; counts and errors preserved.');
})().catch(error => {console.error(error); process.exitCode = 1;});
