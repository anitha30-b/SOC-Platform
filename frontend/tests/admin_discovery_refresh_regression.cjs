const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname, '../src/components/AdminDiscoveredServers.jsx'), 'utf8').replaceAll('\r\n', '\n');
const start = source.indexOf('  useEffect(() => {') + '  useEffect(() => {'.length;
const end = source.indexOf('  }, [apiUrl, query, offset, refresh]);', start);
assert(start > 20 && end > start, 'Actual discovery refresh effect must be present');
const params = ['axios','localStorage','apiUrl','query','offset','limit','setLoading','setData','setUpdatedAt','setError','setTimeout','setInterval','clearTimeout','clearInterval'];
const effect = new Function(...params, source.slice(start, end));

function fixture() {
  const state = { data: null, loading: null, error: null };
  const requests = [];
  let timeout, interval;
  const cleanup = effect({ get: (url, config) => new Promise((resolve, reject) => requests.push({ url, config, resolve, reject })) },
    { getItem: name => name === 'token' ? 'synthetic-token' : null }, '/assets/discovered-servers', ' customer ', 50, 50,
    value => state.loading = value, value => state.data = value, value => state.updatedAt = value, value => state.error = value,
    callback => { timeout = callback; return 1; }, callback => { interval = callback; return 2; }, () => {}, () => {});
  return { state, requests, cleanup, start: () => timeout(), tick: () => interval() };
}

(async () => {
  const f = fixture();
  assert.equal(f.requests.length, 0);
  f.start();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].url, '/assets/discovered-servers');
  assert.deepEqual(f.requests[0].config.params, { q: 'customer', limit: 50, offset: 50 });
  assert.equal(f.requests[0].config.headers.Authorization, 'Bearer synthetic-token');
  f.requests[0].resolve({ data: { total: 1, servers: [{ id: 1 }] } });
  await Promise.resolve();
  assert.equal(f.state.data.servers[0].id, 1);
  assert.equal(f.state.loading, false);
  f.tick();
  f.tick();
  assert.equal(f.requests[1].config.signal.aborted, true);
  f.requests[2].resolve({ data: { total: 1, servers: [{ id: 3 }] } });
  await Promise.resolve();
  f.requests[1].resolve({ data: { total: 1, servers: [{ id: 2 }] } });
  await Promise.resolve();
  assert.equal(f.state.data.servers[0].id, 3);
  f.tick();
  f.requests[3].reject({ response: { status: 403 } });
  await Promise.resolve();
  assert.match(f.state.error, /authorization/);
  assert.equal(f.state.data.servers[0].id, 3);
  f.tick();
  f.requests[4].resolve({ data: { total: 0, servers: null } });
  await Promise.resolve();
  assert.match(f.state.error, /Could not refresh/);
  assert.equal(f.state.data.servers[0].id, 3);
  f.tick();
  f.cleanup();
  assert.equal(f.requests[5].config.signal.aborted, true);
  f.requests[5].resolve({ data: { total: 1, servers: [{ id: 99 }] } });
  await Promise.resolve();
  assert.equal(f.state.data.servers[0].id, 3);
  console.log('PASS: authenticated discovery search/pagination, periodic refresh, stale-response protection, error visibility and cleanup.');
})().catch(error => { console.error(error); process.exitCode = 1; });
