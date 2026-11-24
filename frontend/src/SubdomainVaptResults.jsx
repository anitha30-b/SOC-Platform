import { useState } from 'react';
import { subdomainVaptView, subdomainResultVisibility } from './subdomainVaptView.mjs';

function CurrentSubdomainResult({ job }) {
  const view = subdomainVaptView(job);
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(view.observations.length / 50));
  const selectedPage = Math.min(page, pages - 1);
  const rows = view.observations.slice(selectedPage * 50, (selectedPage + 1) * 50);
  const colour = view.failed ? 'text-red-400' : view.warning ? 'text-yellow-400'
    : view.status === 'completed' ? 'text-green-400' : 'text-yellow-400';
  return <section className="mt-5 border border-white/10 bg-[#0d0d0d] p-5 text-gray-300" aria-label="Current subdomain discovery result">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 className="text-lg font-semibold text-white">Subdomain Discovery Results</h2>
      <span className={`text-sm font-semibold ${colour}`}>{view.label}</span>
    </div>
    <p className="mt-2 break-all text-xs text-gray-400">Target: {view.target || 'Not returned'} · Job: {view.jobId || 'Not returned'}</p>
    {view.discoveryProfile && <p className="mt-2 text-xs text-gray-400">Profile: {view.discoveryProfile}
      {view.candidateCount != null && ` · Wordlist candidates: ${view.candidateCount}`}
      {view.executionSeconds != null && ` · Execution: ${view.executionSeconds.toFixed(1)} seconds`}
      {view.coverage && ` · ${view.coverage}`}</p>}
    {view.error && <p role="alert" className="mt-3 text-sm text-red-400">{view.error}</p>}
    {view.storageFailed && <p className="mt-3 text-sm text-yellow-400">Saving the discovery evidence failed. Any returned execution output is shown below.</p>}
    {view.structured ? <>
      <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
        {[
          ['Subdomains discovered', view.counts.subdomains],
          ['Observed DNS hosts', view.counts.hosts],
          ['Unique IP addresses', view.counts.ips],
        ].map(([label, count]) => <div key={label} className="border border-white/10 bg-black/20 p-4">
          <p className="text-xs text-gray-400">{label}</p><p className="mt-2 text-2xl font-semibold text-white">{count}</p>
        </div>)}
      </div>
      <p className="mt-3 text-xs text-gray-400">Recorded DNS observations · Saved history: {view.persistence === 'saved' ? 'Saved' : 'Not confirmed'}
        {view.assessmentId != null && ` · Assessment ${view.assessmentId}`}
        {view.runId != null && ` · Discovery ${view.runId}`}</p>
      <div className="mt-4 overflow-x-auto"><table className="w-full text-left text-sm">
        <thead><tr className="border-b border-white/10 text-gray-400"><th className="p-3">DNS name</th><th className="p-3">Type</th><th className="p-3">IP address / alias</th></tr></thead>
        <tbody>{rows.map((row, i) => <tr key={`${row.name}-${row.type}-${row.address}-${i}`} className="border-b border-white/5">
          <td className="break-all p-3">{row.name}</td><td className="p-3">{row.type}</td><td className="break-all p-3">{row.address}</td>
        </tr>)}</tbody>
      </table></div>
      {!view.observations.length && <p className="mt-3 text-sm text-gray-400">No DNS record rows were returned for this run.</p>}
      {pages > 1 && <div className="mt-3 flex items-center gap-3 text-xs">
        <button type="button" disabled={!selectedPage} onClick={() => setPage(selectedPage - 1)} className="border border-white/10 px-3 py-2 disabled:opacity-40">Previous</button>
        <span>Page {selectedPage + 1} of {pages}</span>
        <button type="button" disabled={selectedPage + 1 >= pages} onClick={() => setPage(selectedPage + 1)} className="border border-white/10 px-3 py-2 disabled:opacity-40">Next</button>
      </div>}
      <details className="mt-4 text-sm"><summary>All discovered subdomains ({view.subdomains.length})</summary>
        <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{view.subdomains.join('\n') || 'None reported'}</pre>
      </details>
      <details className="mt-3 text-sm"><summary>Unique IP addresses ({view.ips.length})</summary>
        <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{view.ips.join('\n') || 'None reported'}</pre>
      </details>
    </> : <p className="mt-4 text-sm text-gray-400" aria-live="polite">{view.terminal
      ? 'This response contains no structured discovery results. Check the status and returned output below.'
      : 'The discovery job is pending. Its results will appear here when returned by the backend.'}</p>}
    {(view.stdout || view.stderr || view.rawRecords) && <details className="mt-4 text-sm">
      <summary>Returned DNSRecon output</summary>
      {view.stdout && <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{view.stdout}</pre>}
      {view.stderr && <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs text-yellow-400">{view.stderr}</pre>}
      {view.rawRecords && <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{view.rawRecords}</pre>}
    </details>}
  </section>;
}

export default function SubdomainVaptResults({ job, scanRunning = false }) {
  const visibility = subdomainResultVisibility(job, scanRunning);
  if (!visibility.showCurrent) return null;
  return <CurrentSubdomainResult key={job.jobId || job.job_id} job={job} />;
}
