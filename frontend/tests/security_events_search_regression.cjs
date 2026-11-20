// Exercise the actual component request/effect code without a browser or API.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../src/App.jsx'), 'utf8');
const start = source.indexOf('function SecurityEvents() {');
const end = source.indexOf('  const sources =', start);
assert(start >= 0 && end > start, 'Actual component request code must be found');
const component = source.slice(start, end) + 'return {loadEvents};\n}';

function mount(search = '') {
  const state = [[], search, 'INFO', 'telemetry:30', 'soc_threshold_verification', true, false, '', null];
  const writes = [], effects = [], timers = [], requests = [];
  let index = 0;
  const context = {
    URLSearchParams, AbortController, Date, console, API_URL: 'http://127.0.0.1:8000',
    localStorage: { getItem: () => 'synthetic-test-token', removeItem: () => {} },
    useState: initial => { const n = index++; return [state[n] ?? initial, value => {state[n] = value; writes.push([n, value]);}]; },
    useRef: value => ({current: value}),
    useEffect: (callback, deps) => effects.push({callback, deps}),
    setTimeout: callback => {timers.push(callback); return timers.length;},
    clearTimeout: () => {}, setInterval: () => 1, clearInterval: () => {},
    axios: {
      isCancel: () => false,
      get: (url, options) => new Promise((resolve, reject) => requests.push({url, options, resolve, reject})),
    },
  };
  const api = vm.runInNewContext(component + '\nSecurityEvents()', context);
  return {api, state, writes, effects, timers, requests};
}

async function main() {
  const first = mount('older-saved-marker');
  assert.deepEqual(Array.from(first.effects[0].deps),
    ['older-saved-marker', 'INFO', 'telemetry:30', 'soc_threshold_verification']);
  const cleanup = first.effects[0].callback();
  assert.equal(first.requests.length, 0, 'Typing waits for debounce');
  first.timers[0]();
  const pending = first.requests[0];
  const params = new URL(pending.url).searchParams;
  for (const [key, value] of Object.entries({search:'older-saved-marker', severity:'INFO', source:'telemetry:30', event_type:'soc_threshold_verification'})) {
    assert.equal(params.get(key), value);
  }
  pending.resolve({data:[{event_id:'old-event'}]});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(first.state[0][0].event_id, 'old-event');
  cleanup();
  console.log('PASS: search and every filter reach the API after debounce.');

  const second = mount();
  const older = second.api.loadEvents();
  const newer = second.api.loadEvents();
  assert.equal(second.requests[0].options.signal.aborted, true);
  second.requests[1].resolve({data:[{event_id:'new-result'}]});
  await newer;
  second.requests[0].resolve({data:[{event_id:'stale-result'}]});
  await older;
  assert.equal(second.state[0][0].event_id, 'new-result');
  assert.equal(second.writes.filter(([n]) => n === 0).length, 1);
  console.log('PASS: an older response cannot overwrite the latest result.');

  const third = mount();
  const release = third.effects[0].callback();
  third.timers[0]();
  release();
  assert.equal(third.requests[0].options.signal.aborted, true);
  third.requests[0].resolve({data:[{event_id:'after-unmount'}]});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(third.writes.filter(([n]) => n === 0).length, 0);
  console.log('PASS: cleanup cancels pending work and ignores late responses.');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
