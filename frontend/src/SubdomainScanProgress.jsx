import { useEffect, useState } from 'react';
import { subdomainProgressView } from './subdomainVaptView.mjs';

export default function SubdomainScanProgress({ job }) {
  const [now, setNow] = useState(Date.now());
  const view = subdomainProgressView(job, now);
  useEffect(() => {
    if (view.terminal) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [view.terminal]);
  return <div className="border border-white/10 bg-[#080808] p-4">
    <div className="flex items-center justify-between gap-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-white">Subdomain Discovery</p>
      <span className={`text-xs font-semibold uppercase ${view.status === 'completed' ? 'text-green-400' : view.failed ? 'text-red-400' : 'text-yellow-400'}`}>{view.label}</span>
    </div>
    <p className="mt-2 text-xs text-gray-400">{view.profileLabel} · Elapsed: {view.elapsedLabel}</p>
    <div className="mt-3 h-2 overflow-hidden bg-white/5" role="progressbar"
      aria-label="Subdomain discovery execution" aria-valuemin={0} aria-valuemax={100}
      aria-valuenow={view.terminal ? 100 : undefined}>
      <div className={`h-full w-full ${view.terminal ? view.status === 'completed' ? 'bg-green-600' : 'bg-yellow-500' : 'animate-pulse bg-red-600'}`} />
    </div>
    <p className="mt-2 text-xs text-gray-500">{view.terminal ? 'Execution finished.' : 'DNS lookups are running; the tool does not report a measured completion percentage.'}</p>
    <p className="mt-3 break-all text-xs text-gray-500">Target: {job?.target || job?.result?.target || 'Pending'} · Job: {job?.jobId || job?.job_id || 'Pending'}</p>
  </div>;
}
