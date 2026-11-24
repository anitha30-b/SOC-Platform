const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const vm = require('node:vm');
(async () => {
  const app = fs.readFileSync(path.join(__dirname, '../src/App.jsx'), 'utf8');
  const body = app.slice(app.indexOf('function VAPTTesting({'), app.indexOf('\nfunction WiresharkResultsPage'));
  assert.match(body, /const \[subdomainProfile, setSubdomainProfile\] = useState\("full"\)/);
  assert.match(body, /<option value="quick">Quick — 250 names, limited coverage<\/option>/);
  assert.match(body, /toolId === "subdomain-discovery" \? \{ discovery_profile: subdomainProfile \} : \{\}/);
  assert.match(body, /<SubdomainScanProgress[^\n]+job=\{job\}/);
  assert.match(body, /disabled=\{loading\}/);
  assert.match(body, /vapt\/registry\/subdomain-profiles/);
  assert(body.indexOf('/vapt/registry/subdomain-profiles') < body.indexOf('/vapt/registry/tools/${encodeURIComponent(toolId)}/run-async'));
  assert.match(body, /\}, \[genericPollingKey\]\);/);
  const expression = body.match(/const genericPollingKey = ([\s\S]+?);\s*\/\/ Poll generic registry tool jobs\./)?.[1];
  assert(expression, 'Stable active-job polling key must exist');
  const key = jobs => vm.runInNewContext(expression, {genericToolJobs: jobs,
    isTerminalToolStatus: status => ['completed', 'failed', 'timeout', 'cancelled', 'not_available', 'completed_with_errors'].includes(status)});
  assert.equal(key({subdomain: {jobId: 'one', status: 'queued', progress: 0}}),
    key({subdomain: {jobId: 'one', status: 'running', progress: 35}}),
    'Progress-only changes must not immediately restart the poller');
  assert.notEqual(key({subdomain: {jobId: 'one', status: 'running'}}), key({subdomain: {jobId: 'two', status: 'running'}}));
  assert.equal(key({subdomain: {jobId: 'one', status: 'completed'}}), '');
  const {subdomainProgressView: progress, subdomainVaptView: result} = await import(pathToFileURL(path.join(__dirname, '../src/subdomainVaptView.mjs')));
  const running = progress({status: 'running', started_at: 100, discovery_profile: 'quick'}, 202000);
  assert.equal(running.elapsedLabel, '1m 42s');
  assert.equal(running.percent, null, 'Running job must not invent a completion percentage');
  assert.match(running.profileLabel, /250.*limited/);
  const completed = progress({status: 'completed', started_at: 100, finished_at: 110, discovery_profile: 'full'}, 999999);
  assert.equal(completed.elapsedLabel, '0m 10s');
  assert.equal(completed.percent, 100);
  assert.equal(progress({status: 'running'}, 0).elapsedLabel, 'Pending');
  const warning = progress({status: 'completed_with_errors', started_at: 1, finished_at: 2}, 0);
  assert.notEqual(warning.label, 'Completed');
  assert.equal(progress({status: 'running', result: {status: 'completed'}}, 0).terminal, false);
  const report = result({status: 'completed', result: {status: 'completed', discovery_profile: 'quick',
    candidate_count: 250, elapsed_seconds: 12.25, coverage: 'Limited coverage'}});
  assert.equal(report.discoveryProfile, 'quick');
  assert.equal(report.candidateCount, 250);
  assert.equal(report.executionSeconds, 12.25);
  const component = fs.readFileSync(path.join(__dirname, '../src/SubdomainScanProgress.jsx'), 'utf8');
  assert.match(component, /aria-valuenow=\{view\.terminal \? 100 : undefined\}/);
  assert.match(component, /clearInterval\(timer\)/);
  assert(!component.includes('fetch('));
  console.log('PASS: explicit Quick/Full selection, request profile, elapsed-time feedback, indeterminate execution and result coverage labels.');
})().catch(error => { console.error(error); process.exitCode = 1; });
