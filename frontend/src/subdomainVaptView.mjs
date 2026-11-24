import { getToolOutcome, isTerminalToolStatus } from './toolOutcome.js';

export function subdomainResultVisibility(job, scanRunning = false) {
  // The job status is authoritative while polling; stale evidence cannot
  // make a queued/running job look finished.
  const pending = Boolean(scanRunning) || Boolean(job &&
    (!isTerminalToolStatus(job.status) || !getToolOutcome(job.result, job.status).terminal));
  const id = job?.jobId || job?.job_id;
  const hasRun = typeof id === 'string' && id.trim().length > 0;
  return { showCurrent: hasRun && !pending };
}

const names = value => Array.isArray(value)
  ? [...new Set(value.filter(x => typeof x === 'string' && x.trim()).map(x => x.trim()))] : [];
const text = value => typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value, null, 2);

export function subdomainProgressView(job, now = Date.now()) {
  const terminal = isTerminalToolStatus(job?.status);
  const outcome = terminal ? getToolOutcome(job?.result, job?.status)
    : getToolOutcome(null, job?.status || 'queued');
  const profile = job?.result?.discovery_profile || job?.discovery_profile;
  const start = Number.isFinite(job?.started_at) ? job.started_at * 1000
    : Number.isFinite(job?.uiStartedAt) ? job.uiStartedAt : null;
  const finish = terminal && Number.isFinite(job?.finished_at) ? job.finished_at * 1000 : now;
  const elapsed = start == null ? null : Math.max(0, Math.floor((finish - start) / 1000));
  return { ...outcome, terminal, failed: ['failed', 'timeout', 'cancelled'].includes(outcome.status),
    profileLabel: profile === 'quick' ? 'Quick · up to 250 names · limited coverage'
      : profile === 'full' ? 'Full · installed 5,000-name wordlist' : 'Profile not recorded',
    elapsedLabel: elapsed == null ? 'Pending' : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`,
    percent: terminal ? 100 : null };
}

export function subdomainVaptView(job) {
  const result = job?.result && typeof job.result === 'object' ? job.result : null;
  const discovery = result?.discovery;
  const structured = !!discovery && typeof discovery === 'object'
    && ['discovered_subdomains', 'discovered_hosts', 'discovered_ips'].every(key => Array.isArray(discovery[key]));
  let outcome = getToolOutcome(result, job?.status);
  const storageFailed = result?.persistence?.status === 'failed';
  if (storageFailed && outcome.status === 'completed') {
    outcome = getToolOutcome({ ...result, status: 'completed_with_errors' }, job?.status);
  }
  const records = structured && Array.isArray(discovery.observations) ? discovery.observations : [];
  const observations = records.filter(item => item && typeof item === 'object'
    && ['name', 'type', 'address'].every(key => typeof item[key] === 'string'));
  const subdomains = structured ? names(discovery.discovered_subdomains) : [];
  const hosts = structured ? names(discovery.discovered_hosts) : [];
  const ips = structured ? names(discovery.discovered_ips) : [];
  return {
    ...outcome, structured, storageFailed,
    warning: ['completed_with_errors', 'not_available', 'unknown'].includes(outcome.status),
    failed: ['failed', 'timeout', 'cancelled'].includes(outcome.status),
    jobId: job?.jobId || job?.job_id || '',
    target: text(discovery?.target_domain || result?.target || job?.target || ''),
    subdomains, hosts, ips, observations,
    counts: structured ? { subdomains: subdomains.length, hosts: hosts.length, ips: ips.length } : null,
    assessmentId: result?.assessment_id,
    runId: result?.discovery_run_id || result?.persistence?.run_id,
    error: text(job?.error || result?.error || result?.persistence?.error || ''),
    stdout: text(result?.stdout), stderr: text(result?.stderr),
    rawRecords: result?.json_output == null ? '' : text(result.json_output),
    persistence: result?.persistence?.status || 'not_confirmed',
    discoveryProfile: result?.discovery_profile || null,
    candidateCount: Number.isFinite(result?.candidate_count) ? result.candidate_count : null,
    executionSeconds: Number.isFinite(result?.elapsed_seconds) ? result.elapsed_seconds : null,
    coverage: text(result?.coverage),
  };
}
