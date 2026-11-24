// Execute actual frontend callback code with fake jobs; no browser/API required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const filename = process.argv[2] || path.join(__dirname, '../src/App.jsx');
const source = fs.readFileSync(filename, 'utf8').replace(/\r\n/g, '\n');
const helperPath = path.join(path.dirname(filename), 'toolOutcome.js');
const outcomeHelpers = fs.existsSync(helperPath) ? vm.runInNewContext(
  '(function(){'+fs.readFileSync(helperPath,'utf8').replace(/^export /gm,'')+
  '\nreturn {getToolOutcome,isTerminalToolStatus,normalizeToolStatus};})()'
) : {};
const pending = () => new Promise(resolve => setImmediate(resolve));

function section(startText, endText) {
  const start = source.indexOf(startText);
  assert(start >= 0, 'Missing actual frontend source anchor: ' + startText);
  const end = source.indexOf(endText, start + startText.length);
  assert(end > start, 'Missing frontend section boundary');
  return source.slice(start, end + endText.length);
}

async function pollNmap(status) {
  const code = section('  useEffect(() => {\n    if (!nmapJobId) return undefined;', '  }, [nmapJobId]);');
  const finished = [];
  let effect;
  vm.runInNewContext(code, {
    ...outcomeHelpers,
    nmapJobId:'fixture-job', API_URL:'http://synthetic.invalid', console,
    localStorage:{getItem:()=> 'synthetic-test-token',removeItem:()=>{}},
    axios:{get:async()=>({data:{status, progress:100, result:{status}}})},
    useEffect:callback=>{effect=callback;},
    setNmapProgress:()=>{}, setNmapStage:()=>{}, finishNmapJob:job=>finished.push(job),
    setLoading:()=>{},setNmapJobId:()=>{},setStatus:()=>{},setMessage:()=>{},
    window:{setInterval:()=>1, clearInterval:()=>{}},
  });
  const cleanup = effect();
  await pending();
  cleanup?.();
  return finished;
}

function finishNmap(status, multi=false) {
  const start = source.indexOf('  const finishNmapJob = (job) => {');
  const end = source.indexOf('  useEffect(() => {\n    if (!nmapJobId)', start);
  assert(start>=0 && end>start, 'Actual Nmap completion callback must be found');
  const state = {statuses:{}, results:{}, loading:true};
  const set = key=>value=>{state[key] = typeof value === 'function' ? value(state[key]) : value;};
  const context = {
    ...outcomeHelpers,
    vaptRunTools: multi ? ['nmap','dig'] : ['nmap'], nmapProfile:'detailed',
    targetUrl:'https://synthetic.invalid', Date, Math,
    normalizeNmapResult:result=>({nmap:result}), setScanResult:set('single'),
    setToolStatuses:set('statuses'),setStatus:set('status'),setMessage:set('message'),
    setVaptRunResults:set('results'),setLoading:set('loading'),setNmapJobId:set('jobId'),
    localStorage:{setItem:()=>{}},onViewNmapResults:result=>{state.opened=result;},
  };
  const callback = vm.runInNewContext('(function(){'+source.slice(start,end)+'\nreturn finishNmapJob;})()', context);
  callback({status,result:{status,results:{hosts:[],host_count:0},workflow:{stage_results:[{name:'fixture',status}]}}});
  return state;
}

async function pollGeneric(status) {
  const code = section('  useEffect(() => {\n    const runningJobs = Object.entries(genericToolJobs)', '  }, [genericPollingKey]);');
  let effect;
  const state={jobs:{dig:{jobId:'fixture-job',status:'running'}},statuses:{},results:{},loading:true};
  const set = key=>value=>{state[key] = typeof value==='function' ? value(state[key]) : value;};
  vm.runInNewContext(code, {
    ...outcomeHelpers,
    genericPollingKey:'fixture-job',genericToolJobs:state.jobs,vaptRunTools:['dig'],API_URL:'http://synthetic.invalid',console,
    localStorage:{getItem:()=> 'synthetic-test-token'},
    axios:{get:async()=>({data:{job_id:'fixture-job',status,result:{status}}})},
    useEffect:callback=>{effect=callback;},
    setGenericToolJobs:set('jobs'),setToolStatuses:set('statuses'),setVaptRunResults:set('results'),
    setLoading:set('loading'),setStatus:set('status'),setMessage:set('message'),
    window:{setInterval:()=>1,clearInterval:()=>{}},
  });
  const cleanup=effect();
  await pending();
  cleanup?.();
  return state;
}

function label(result, status) {
  const start=source.indexOf('function MultiToolResultsPage({ scanResult, onBack }) {');
  const end=source.indexOf('  // Accept both the normalized multi-tool payloads',start);
  assert(start>=0&&end>start,'Multi-tool result label code must be found');
  const fixture={results:{nmap:result},tool_statuses:status?{nmap:status}:{},tools:['nmap']};
  const helpers=vm.runInNewContext(source.slice(start,end)+'\nreturn {formatStatus,statusClass};\n}\nMultiToolResultsPage({scanResult:fixture})', {fixture,...outcomeHelpers});
  const text=helpers.formatStatus('nmap');
  return {text,css:helpers.statusClass(text)};
}

function coordinate(nmapResult, nmapStatus, digResult={status:'completed'}, digStatus='Completed') {
  const start=source.indexOf('  useEffect(() => {\n    // ZAP has its own dedicated progress/result lifecycle.');
  const end=source.indexOf('  const handlePrepareTools = async () => {', start);
  assert(start>=0&&end>start,'Actual multi-tool coordinator must be found');
  let effect,tick;
  const state={loading:true};
  const set=key=>value=>{state[key]=value;};
  vm.runInNewContext(source.slice(start,end),{
    ...outcomeHelpers,
    vaptRunId:'synthetic-run',vaptRunRedirected:false,vaptRunTools:['nmap','dig'],
    vaptRunResults:{nmap:nmapResult,dig:digResult},toolStatuses:{nmap:nmapStatus,dig:digStatus},
    genericToolJobs:{},targetUrl:'https://synthetic.invalid',Date,
    console:{log:()=>{}},
    useEffect:callback=>{effect=callback;},
    window:{setInterval:callback=>{tick=callback;return 1;},clearInterval:()=>{}},
    setVaptRunRedirected:set('redirected'),setLoading:set('loading'),setStatus:set('status'),
    setMessage:set('message'),setScanResult:set('scan'),onViewMultiToolResults:set('opened'),
  });
  const cleanup=effect();
  tick?.();cleanup?.();
  return state;
}

async function main() {
  let passed=0,failed=0;
  async function check(name, callback) {
    try {await callback(); passed++; console.log('PASS: '+name);}
    catch(error) {failed++; console.log('FAIL: '+name+' — '+error.message);}
  }
  for(const status of ['completed','completed_with_errors','failed','timeout','not_available']) {
    await check('Nmap polling finishes '+status,async()=>assert.equal((await pollNmap(status)).length,1));
  }
  await check('Running Nmap job remains pending',async()=>assert.equal((await pollNmap('running')).length,0));
  await check('Partial Nmap completion uses a warning label',()=>assert.match(finishNmap('completed_with_errors').statuses.nmap||'',/warning|error/i));
  await check('Partial Nmap evidence reaches the multi-tool coordinator',()=>assert.equal(finishNmap('completed_with_errors',true).results.nmap.nmap.status,'completed_with_errors'));
  await check('Generic timeout finishes loading',async()=>assert.equal((await pollGeneric('timeout')).loading,false));
  await check('Generic timeout retains its result',async()=>assert.equal((await pollGeneric('timeout')).results.dig.status,'timeout'));
  await check('A successful native result stays completed',()=>assert.match(label({status:'completed'}).text,/completed/i));
  await check('Native timeout is not labelled completed',()=>assert.doesNotMatch(label({status:'timeout'}).text,/completed/i));
  await check('Unavailable tool is not labelled completed',()=>assert.doesNotMatch(label({status:'not_available'}).text,/completed/i));
  await check('Wrapped Nmap warning is not clean success',()=>assert.match(label({nmap:{status:'completed_with_errors'}}).text,/warning|error/i));
  await check('Stale completed label cannot override a failed result',()=>assert.match(label({status:'failed'},'Completed').text,/fail/i));
  await check('Raw warning status never gets green success styling',()=>assert(!label({status:'completed_with_errors'},'completed_with_errors').css.includes('emerald')));
  await check('Multi-tool overall result retains warning status and stage evidence',()=>{
    const evidence={nmap:{status:'completed_with_errors',workflow:{stage_results:[{name:'fixture-stage',status:'completed_with_errors'}]}}};
    const state=coordinate(evidence,'Completed with warnings');
    assert.equal(state.scan.status,'completed_with_errors');
    assert.match(state.status,/warning/i);
    assert.equal(state.scan.results.nmap.nmap.workflow.stage_results[0].name,'fixture-stage');
  });
  await check('Unavailable specialized tool does not keep the coordinator waiting',()=>{
    const state=coordinate(null,'Not available');
    assert.equal(state.loading,false);
    assert.equal(state.scan.status,'completed_with_errors');
  });
  await check('A running native result prevents stale completed summary finalization',()=>{
    const state=coordinate({nmap:{status:'running'}},'Completed');
    assert.equal(state.loading,true);
    assert.equal(state.scan,undefined);
  });
  await check('All failed tools produce a failed combined result',()=>{
    const state=coordinate({status:'failed'},'Failed',{status:'timeout'},'Timed Out');
    assert.equal(state.scan.status,'failed');
  });
  await check('Result object with unknown status is not clean success',()=>assert.doesNotMatch(label({status:'unrecognized'},'Completed').text,/completed/i));
  await check('Missing result and status remain visibly absent',()=>assert.equal(label(null).text,'No result'));
  console.log(`Display callback checks: ${passed} passed; ${failed} need attention.`);
  if(failed) process.exitCode=1;
}
main().catch(error=>{console.error(error);process.exitCode=1;});
