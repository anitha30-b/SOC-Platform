import { useEffect, useRef, useState } from 'react';
import { API_BASE_URL } from './deploymentApi.js';

export default function SubdomainResults({ admin = false }) {
  const [data, setData] = useState(null);
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const sequence = useRef(0);
  useEffect(() => {
    sequence.current++;
    const controller = new AbortController();
    const endpoint = admin ? '/assets/subdomain-discoveries' : '/client/subdomain-discovery';
    const load = async () => {
      const attempt = ++sequence.current;
      try {
        setBusy(true);
        const response = await fetch(`${API_BASE_URL}${endpoint}?q=${encodeURIComponent(q)}&limit=50&offset=${offset}`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }, signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Discovery history request failed (${response.status}).`);
        const result = await response.json();
        if (sequence.current === attempt) { setData(result); setError(''); }
      } catch (e) {
        if (sequence.current === attempt && e.name !== 'AbortError') setError(e.message);
      } finally {
        if (sequence.current === attempt) setBusy(false);
      }
    };
    const timer = setTimeout(load, 300);
    const interval = setInterval(load, 15000);
    return () => { clearTimeout(timer); clearInterval(interval); controller.abort(); sequence.current++; };
  }, [admin, q, offset, refresh]);
  return <section style={{ padding: 24, border: '1px solid #333', marginTop: 24 }}>
    <h2>Saved Subdomain Discovery Results</h2>
    <p>DNS observations from customer discovery runs. These are recorded observations; refreshing does not start a scan.</p>
    {admin && <p>Manage permission for “Subdomain Discovery” in User &amp; Access Management. Results retain the initiating account and customer scope.</p>}
    <label>Search domain or owner <input value={q} onChange={e => { setQ(e.target.value); setOffset(0); }} /></label>{' '}
    <button onClick={() => setRefresh(x => x + 1)}>Refresh results</button>
    <span aria-live="polite"> {busy ? 'Loading…' : `${data?.total ?? 0} saved runs`}</span>
    {error && <p role="alert" style={{ color: '#ff7777' }}>{error}</p>}
    <div style={{ overflowX: 'auto' }}><table style={{ width: '100%' }}>
      <thead><tr><th>Domain / owner</th><th>Status</th><th>Subdomains</th><th>Hosts / IPs</th><th>Recorded results</th></tr></thead>
      <tbody>{(data?.runs || []).map(run => <tr key={run.id}>
        <td>{run.target_domain}<br />{run.owner_username} · User {run.user_id}<br />Assessment {run.assessment_id}</td>
        <td>{run.status}<br />{run.completed_at || run.created_at}{run.error && <p>{run.error}</p>}</td>
        <td>{run.discovered_subdomain_count}</td><td>{run.discovered_host_count} / {run.discovered_ip_count}</td>
        <td><details><summary>Show DNS observations</summary>
          {(run.discovery?.observations || []).map((item, i) => <div key={i}>{item.name} · {item.type} · {item.address}</div>)}
          {!(run.discovery?.observations || []).length && <p>No structured DNS observations saved for this run.</p>}
        </details></td>
      </tr>)}</tbody>
    </table></div>
    {!busy && data && !data.runs?.length && <p>No discovery runs match this view.</p>}
    <button disabled={offset === 0} onClick={() => setOffset(x => Math.max(0, x - 50))}>Previous</button>{' '}
    <button disabled={!data || offset + 50 >= data.total} onClick={() => setOffset(x => x + 50)}>Next</button>
  </section>;
}
