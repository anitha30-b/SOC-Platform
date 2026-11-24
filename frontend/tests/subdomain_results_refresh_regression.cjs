const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../src/SubdomainResults.jsx'), 'utf8');
const start = source.indexOf('export default function SubdomainResults');
const end = source.indexOf('  return <section');
assert(start >= 0 && end > start);
const component = source.slice(start, end).replace('export default ', '') + '\n}';
const tick = () => new Promise(resolve => setImmediate(resolve));

function harness(admin = false) {
  const values = [null, 'example.test', 0, '', false, 0];
  const requests = [], timers = new Map(), intervals = new Map();
  let index = 0, callback, cleanup, timerId = 0;
  const ref = {current: 0};
  const context = {
    API_BASE_URL: 'https://soc.test/api', AbortController, encodeURIComponent,
    localStorage: {getItem: () => 'fixture-token'},
    useState(initial) {
      const i = index++;
      return [values[i], value => { values[i] = typeof value === 'function' ? value(values[i]) : value; }];
    },
    useRef: () => ref, useEffect: fn => {callback = fn;},
    setTimeout(fn) {timers.set(++timerId, fn); return timerId;},
    clearTimeout(id) {timers.delete(id);},
    setInterval(fn, ms) {assert.equal(ms, 15000); intervals.set(++timerId, fn); return timerId;},
    clearInterval(id) {intervals.delete(id);},
    fetch(url, options) {
      return new Promise((resolve, reject) => requests.push({url, options, resolve, reject}));
    },
  };
  vm.createContext(context);
  vm.runInContext(component + `\nSubdomainResults({admin: ${admin}});`, context);
  cleanup = callback();
  return {values, requests, timers, intervals, cleanup, fire() {
    const [id, fn] = timers.entries().next().value;
    timers.delete(id); fn();
  }, refresh() {intervals.values().next().value();}};
}
async function respond(request, data) {
  request.resolve({ok: true, json: async () => data});
  await tick();
}

(async () => {
  const customer = harness();
  assert.equal(customer.requests.length, 0);
  customer.fire();
  assert.match(customer.requests[0].url, /\/api\/client\/subdomain-discovery\?q=example.test&limit=50&offset=0$/);
  assert.equal(customer.requests[0].options.headers.Authorization, 'Bearer fixture-token');
  await respond(customer.requests[0], {runs: [{id: 1}], total: 1});
  assert.equal(customer.values[0].total, 1);
  customer.refresh();
  customer.refresh();
  await respond(customer.requests[2], {runs: [{id: 3}], total: 3});
  await respond(customer.requests[1], {runs: [{id: 2}], total: 2});
  assert.equal(customer.values[0].total, 3, 'Older response overwrote newer results');
  customer.refresh();
  customer.cleanup();
  assert(customer.requests[3].options.signal.aborted);
  await respond(customer.requests[3], {runs: [], total: 999});
  assert.equal(customer.values[0].total, 3, 'Response applied after cleanup');
  assert.equal(customer.intervals.size, 0);
  const admin = harness(true);
  admin.fire();
  assert.match(admin.requests[0].url, /\/api\/assets\/subdomain-discoveries\?/);
  admin.requests[0].resolve({ok: false, status: 403});
  await tick();
  assert.match(admin.values[3], /403/);
  admin.cleanup();
  console.log('PASS: user/admin discovery URLs, authentication, debounce, periodic refresh, response ordering, errors and cleanup.');
})().catch(error => {console.error(error); process.exitCode = 1;});
