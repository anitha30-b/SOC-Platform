// Exercise actual frontend metric and PDF callback code with synthetic evidence.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const filename=process.argv[2]||path.join(__dirname,'../src/App.jsx');
const source=fs.readFileSync(filename,'utf8').replace(/\r\n/g,'\n');
const helperPath=path.join(path.dirname(filename),'toolOutcome.js');
const helpers=fs.existsSync(helperPath)?vm.runInNewContext(
  '(function(){'+fs.readFileSync(helperPath,'utf8').replace(/^export /gm,'')+
  '\nreturn {getToolOutcome,isTerminalToolStatus,normalizeToolStatus};})()'
):{};
const metricsPath=path.join(path.dirname(filename),'toolMetrics.js');
if(fs.existsSync(metricsPath)) Object.assign(helpers,vm.runInNewContext(
  '(function(){'+fs.readFileSync(metricsPath,'utf8').replace(/^export /gm,'')+
  '\nreturn {reportedFindings,hostIdentity,getHostAddress,uniqueOpenPorts,nmapPortObservations,normalizeToolSeverity,masscanHostsFromResult};})()', {URL}
));
function nmap({macFirst=false,port=443,protocol='tcp',script=true,status='completed'}={}) {
  const addresses=[{type:'ipv4',address:'192.0.2.10'}];
  if(macFirst)addresses.unshift({type:'mac',address:'00:00:00:00:00:01'});
  return {status,scan_type:'detailed',results:{host_count:1,hosts:[{
    addresses,hostnames:[],scripts:[],os_matches:[],ports:[{
      port,protocol,state:'open',service:{name:'https'},
      scripts:script?[{id:'ssl-cert',output:'Synthetic certificate details, not a vulnerability.'}]:[],
    }],
  }]},workflow:{stage_results:[{name:'inventory',status}]},errors:status==='completed'?[]:['Synthetic stage failure']};
}
function masscan({host='192.0.2.10',port=443,protocol='tcp'}={}) {
  return {status:'completed',results:{hosts:[{host,ports:[{port,protocol,state:'open'}]}]}};
}
function normalized(result) {
  const start=source.indexOf('  const normalizeNmapResult = (result, cleanTarget, elapsedMs = null) => (');
  const end=source.indexOf('  const finishNmapJob = ',start);
  assert(start>=0&&end>start,'Actual Nmap normalizer must be found');
  const callback=vm.runInNewContext('(function(){'+source.slice(start,end)+'\nreturn normalizeNmapResult;})()',
    {...helpers,nmapProfile:'detailed'});
  return callback(result,'https://synthetic.invalid');
}
function metrics(results,toolStatuses={},overallStatus) {
  const start=source.indexOf('function MultiToolResultsPage({ scanResult, onBack }) {');
  const end=source.indexOf('  const severityColors = {',start);
  assert(start>=0&&end>start,'Actual multi-tool metrics must be found');
  const countStart=source.indexOf('  const completedCount = tools.filter(',end);
  const countEnd=source.indexOf('  const toolMeta = {',countStart);
  assert(countStart>=0&&countEnd>countStart,'Actual execution summary counts must be found');
  const headerStart=source.indexOf('              Assessment Status',end);
  const header=source.slice(headerStart,headerStart+1600);
  const expression=header.match(/<p[^>]*>\s*\{([\s\S]*?)\}\s*<\/p>/);
  assert(expression,'Actual assessment status label must be found');
  const fixture={tools:Object.keys(results),results,tool_statuses:toolStatuses,status:overallStatus};
  const code=source.slice(start,end)+source.slice(countStart,countEnd)+
    '\nreturn {totalFindings,totalOpenPorts,hostsDiscovered,severityCounts,toolFindings,completedCount,failedCount,'+
    'overallLabel:('+expression[1]+')};\n}\nMultiToolResultsPage({scanResult:fixture})';
  return vm.runInNewContext(code,{fixture,...helpers});
}
function pdfLines(result) {
  const start=source.indexOf('  const handleDownloadReport = () => {');
  const end=source.indexOf('  const headers = Array.isArray(scanResult?.security_headers)',start);
  assert(start>=0&&end>start,'Actual browser PDF callback must be found');
  const lines=[];
  class PdfFixture {
    constructor() {
      return new Proxy({}, {get:(object,key)=>{
        if(key==='text') return value=>lines.push(...(Array.isArray(value)?value:[value]).map(String));
        if(key==='splitTextToSize')return value=>[String(value)];
        return ()=>{};
      }});
    }
  }
  const callback=vm.runInNewContext('(function(){'+source.slice(start,end)+'\nreturn handleDownloadReport;})()',{
    ...helpers,jsPDF:PdfFixture,scanResult:normalized(result),targetUrl:'https://synthetic.invalid',
    scanType:'nmap',nmapProfile:'detailed',Date,setMessage:()=>{},
  });
  callback();
  return lines.join('\n');
}
function main() {
  let passed=0,failed=0;
  function check(name,callback) {
    try{callback();passed++;console.log('PASS: '+name);}
    catch(error){failed++;console.log('FAIL: '+name+' — '+error.message);}
  }
  check('Open ports do not populate the normalized vulnerability findings count',()=>{
    assert.equal(normalized(nmap()).assessment.findings_count,0);
  });
  check('Native Nmap port evidence is retained',()=>assert.equal(normalized(nmap()).nmap.results.hosts[0].ports[0].port,443));
  check('Port-only multi-tool results have zero vulnerability findings',()=>assert.equal(metrics({nmap:nmap(),masscan:masscan()}).totalFindings,0));
  check('Benign NSE output is not counted as a vulnerability finding',()=>assert.equal(metrics({nmap:nmap()}).toolFindings.nmap,0));
  check('Same host/protocol/port seen by two tools counts once in the summary',()=>assert.equal(metrics({nmap:nmap(),masscan:masscan()}).totalOpenPorts,1));
  check('Different protocols remain distinct port observations',()=>assert.equal(metrics({nmap:nmap(),masscan:masscan({protocol:'udp'})}).totalOpenPorts,2));
  check('Same port on different hosts remains distinct',()=>assert.equal(metrics({nmap:nmap(),masscan:masscan({host:'192.0.2.11'})}).totalOpenPorts,2));
  check('MAC address ordering does not inflate the IP host count',()=>assert.equal(metrics({nmap:nmap({macFirst:true}),masscan:masscan()}).hostsDiscovered,1));
  check('Reported vulnerability findings from separate tools are preserved',()=>{
    const result=metrics({nuclei:{findings:[{severity:'high',name:'Fixture A'}]},nikto:{findings:[{severity:'low',title:'Fixture B'}]}});
    assert.equal(result.totalFindings,2);
  });
  check('Informational ZAP risk is included in the INFO bucket',()=>assert.equal(metrics({'owasp-zap':{alerts:[{risk:'Informational',alert:'Fixture only'}]}}).severityCounts.INFO,1));
  check('Unknown severity findings are not silently lost from severity totals',()=>{
    const result=metrics({nuclei:{findings:[{severity:'unknown',name:'Unscored fixture'}]}});
    assert.equal(Object.values(result.severityCounts).reduce((total,count)=>total+count,0),result.totalFindings);
  });
  check('Partial combined assessment is not labelled clean Completed',()=>{
    const result=metrics({nmap:{nmap:nmap({status:'completed_with_errors'})},nuclei:{status:'completed',findings:[]}},
      {nmap:'Completed with warnings',nuclei:'Completed'},'completed_with_errors');
    assert.match(String(result.overallLabel),/warning|error|partial/i);
  });
  check('Nmap PDF preserves observed port evidence',()=>assert.match(pdfLines(nmap()),/443\/tcp/));
  check('Nmap PDF explicitly shows partial execution status',()=>{
    const text=pdfLines(nmap({status:'completed_with_errors'}));
    assert.match(text,/(?:scan|execution|assessment) status[^\n]*(?:warning|error|partial|completed_with_errors)/i);
  });
  check('Nmap PDF preserves stage failure details',()=>assert.match(pdfLines(nmap({status:'completed_with_errors'})),/Synthetic stage failure/));
  check('Explicitly reported Nmap findings are preserved separately from ports',()=>{
    const native=nmap();native.findings=[{title:'Structured reported fixture',severity:'medium'}];
    const result=normalized(native);
    assert.equal(result.assessment.findings_count,1);
    assert.equal(result.findings[0].title,'Structured reported fixture');
  });
  check('Per-tool reported finding totals agree with the overall finding total',()=>{
    const native=nmap();native.findings=[{title:'Fixture',severity:'medium'}];
    const result=metrics({nmap:native,nuclei:{findings:[{severity:'low',name:'Other fixture'}]}});
    assert.equal(Object.values(result.toolFindings).reduce((total,count)=>total+count,0),result.totalFindings);
    assert.equal(result.totalFindings,2);
  });
  check('Empty or malformed finding records do not inflate totals',()=>{
    const result=metrics({nuclei:{findings:[null,'',{}]},nikto:{findings:[null,{}]}});
    assert.equal(result.totalFindings,0);
  });
  check('Numeric informational ZAP risk is accounted for',()=>assert.equal(metrics({'owasp-zap':{alerts:[{riskcode:0,alert:'Fixture only'}]}}).severityCounts.INFO,1));
  check('Unrated finding remains visibly unscored',()=>assert.equal(metrics({nuclei:{findings:[{name:'Unscored fixture'}]}}).severityCounts.UNRATED,1));
  check('Structured flat Masscan open-port results are retained',()=>{
    const result=metrics({masscan:{results:{open_ports:[{host:'192.0.2.10',port:443,protocol:'tcp'}]}}});
    assert.equal(result.totalOpenPorts,1);assert.equal(result.hostsDiscovered,1);
  });
  check('Generic Masscan stdout observations are retained',()=>{
    const result=metrics({masscan:{stdout:'Discovered open port 443/tcp on 192.0.2.10\n'}});
    assert.equal(result.totalOpenPorts,1);assert.equal(result.hostsDiscovered,1);
  });
  check('Equivalent IPv6 forms do not inflate observation totals',()=>{
    const native=nmap();native.results.hosts[0].addresses=[{type:'ipv6',address:'2001:db8::1'}];
    const result=metrics({nmap:native,masscan:masscan({host:'2001:0db8:0:0:0:0:0:1'})});
    assert.equal(result.totalOpenPorts,1);assert.equal(result.hostsDiscovered,1);
  });
  check('Warning tool is not counted as cleanly completed',()=>{
    const result=metrics({nmap:{nmap:nmap({status:'completed_with_errors'})}}, {nmap:'Completed with warnings'}, 'completed_with_errors');
    assert.equal(result.completedCount,0);
  });
  check('Nmap PDF selects the IP instead of the MAC address',()=>{
    const text=pdfLines(nmap({macFirst:true}));
    assert.match(text,/192\.0\.2\.10\s+443\/tcp/);
    assert.doesNotMatch(text,/00:00:00:00:00:01\s+443\/tcp/);
  });
  check('PDF includes the recorded stage outcome',()=>assert.match(pdfLines(nmap({status:'completed_with_errors'})),/inventory[^\n]*warning/i));
  console.log(`Count/report callback checks: ${passed} passed; ${failed} need attention.`);
  if(failed)process.exitCode=1;
}
main();
