const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const helper = process.env.SOC_DEPLOY_API_HELPER || path.join(__dirname, '../src/deploymentApi.js');
  const source = fs.readFileSync(helper, 'utf8');
  const {resolveDeploymentEndpoints: resolve} = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
  assert.deepEqual(resolve({DEV:true}, 'http://localhost:5173'), {
    API_BASE_URL:'http://127.0.0.1:8000', WS_BASE_URL:'ws://127.0.0.1:8000'});
  assert.deepEqual(resolve({PROD:true}, 'https://soc.company.example'), {
    API_BASE_URL:'https://soc.company.example/api', WS_BASE_URL:'wss://soc.company.example/api'});
  assert.deepEqual(resolve({PROD:true}, 'http://10.0.0.10'), {
    API_BASE_URL:'http://10.0.0.10/api', WS_BASE_URL:'ws://10.0.0.10/api'});
  assert.deepEqual(resolve({VITE_API_BASE_URL:'https://api.company.example/v1/'}, 'https://soc.company.example'), {
    API_BASE_URL:'https://api.company.example/v1', WS_BASE_URL:'wss://api.company.example/v1'});
  assert.equal(resolve({VITE_API_BASE_URL:'/backend',VITE_WS_BASE_URL:'/stream/'}, 'https://soc.company.example').WS_BASE_URL,
    'wss://soc.company.example/stream');
  for (const value of ['ftp://host', 'https://user:secret@host', 'https://host/?token=secret', 'https://host/#hash']) {
    assert.throws(() => resolve({VITE_API_BASE_URL:value}, 'https://soc.company.example'));
  }
  assert.throws(() => resolve({VITE_API_BASE_URL:'http://internal:8000'}, 'https://soc.company.example'));
  assert.throws(() => resolve({VITE_WS_BASE_URL:'ws://internal:8000'}, 'https://soc.company.example'));
  assert.equal(resolve({VITE_API_URL:'https://legacy.company.example'}, 'https://soc.company.example').API_BASE_URL,
    'https://legacy.company.example');
  console.log('PASS: local development, company-origin /api routing, HTTPS/WSS, configured bases and invalid/mixed-content rejection.');
})().catch(error => { console.error(error); process.exitCode = 1; });
