import { useEffect, useState } from "react";
import axios from "axios";

function scanLabel(value) {
  const status = String(value || "unknown").toLowerCase();
  if (status === "completed_with_errors") return "Completed with warnings";
  if (status === "completed") return "Completed";
  return status.replaceAll("_", " ");
}

export default function AdminDiscoveredServers({ apiUrl }) {
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState({ servers: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState(null);
  const limit = 50;

  useEffect(() => {
    let active = true;
    let pending;
    async function load() {
      pending?.abort();
      const controller = new AbortController();
      pending = controller;
      setLoading(true);
      try {
        const token = localStorage.getItem("token");
        const response = await axios.get(apiUrl, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          params: { q: query.trim(), limit, offset }, signal: controller.signal,
        });
        if (!active || controller.signal.aborted) return;
        if (!Array.isArray(response.data?.servers) || !Number.isInteger(response.data?.total)) {
          throw new Error("Invalid discovery response");
        }
        setData(response.data);
        setUpdatedAt(new Date());
        setError("");
      } catch (err) {
        if (!active || controller.signal.aborted) return;
        setError(err.response?.status === 401 || err.response?.status === 403
          ? "Administrator authorization is required to view customer discoveries."
          : "Could not refresh customer discoveries. Any previously loaded observations may be out of date.");
      } finally {
        if (active && !controller.signal.aborted) setLoading(false);
      }
    }
    const debounce = setTimeout(load, 300);
    const timer = setInterval(load, 30000);
    return () => { active = false; clearTimeout(debounce); clearInterval(timer); pending?.abort(); };
  }, [apiUrl, query, offset, refresh]);

  return (
    <section aria-label="Customer server discoveries" className="rounded-lg border border-white/10 bg-[#0b0e11] text-white">
      <div className="flex flex-wrap justify-between gap-4 border-b border-white/10 p-5">
        <div>
          <h2 className="font-semibold">Customer server discoveries</h2>
          <p className="mt-1 text-xs text-gray-400">Latest scan observation for each owner and address. These records also appear in the customer inventory.</p>
          <p className="mt-2 text-xs text-gray-500">Scan observations are read-only. Host status reflects the last scan, not continuous health monitoring. Refreshes every 30 seconds.</p>
        </div>
        <button type="button" onClick={() => setRefresh(value => value + 1)} className="rounded border border-white/10 px-3 py-2 text-xs">Refresh discoveries</button>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 p-5">
        <input aria-label="Search customer discoveries" value={query} onChange={event => { setQuery(event.target.value); setOffset(0); }}
          placeholder="Search customer, owner, address or target" className="w-full rounded border border-white/10 bg-black px-3 py-2 text-sm sm:w-96" />
        <span className="text-xs text-gray-400">{loading ? "Refreshing..." : `${data.total} latest observations`}{updatedAt ? ` | Updated ${updatedAt.toLocaleTimeString()}` : ""}</span>
      </div>
      {error && <p role="alert" className="px-5 pb-4 text-sm text-red-300">{error}</p>}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[950px] text-left text-xs">
          <thead className="border-y border-white/10 text-gray-400"><tr>{["Customer / owner", "Address / hostname", "Target / assessment", "Scan outcome", "Open ports", "Last observed"].map(label => <th key={label} className="p-4">{label}</th>)}</tr></thead>
          <tbody className="divide-y divide-white/10">
            {!loading && !error && data.servers.length === 0 && <tr><td colSpan={6} className="p-8 text-center text-gray-400">No customer discoveries match this search.</td></tr>}
            {data.servers.map(server => <tr key={server.id}>
              <td className="p-4"><div>{server.client_name || "Personal account"}</div><div className="mt-1 text-gray-400">{server.owner_username} | User {server.owner_user_id}</div></td>
              <td className="p-4"><div className="font-mono">{server.ip_address || "Unavailable"}</div><div className="mt-1 text-gray-400">{server.hostname || "No hostname recorded"}</div></td>
              <td className="max-w-64 break-all p-4"><div>{server.target}</div><div className="mt-1 text-gray-400">Assessment {server.assessment_id} | Discovery {server.discovery_run_id}</div></td>
              <td className={`p-4 ${String(server.scan_status).toLowerCase() === "completed_with_errors" ? "text-amber-300" : "text-gray-300"}`}>{scanLabel(server.scan_status)}<div className="mt-1 text-gray-400">Host: {server.host_status || "unknown"}</div></td>
              <td className="p-4">{server.open_port_count ?? "Unavailable"}<details className="mt-2 text-gray-400"><summary className="cursor-pointer">Recorded services</summary><pre className="mt-2 max-h-48 max-w-72 overflow-auto whitespace-pre-wrap">{JSON.stringify(server.services, null, 2)}</pre></details></td>
              <td className="p-4 text-gray-400">{server.last_seen ? `${new Date(server.last_seen).toLocaleString()} (local time)` : "Not recorded"}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-end gap-3 border-t border-white/10 p-4 text-xs">
        <button disabled={offset === 0 || loading} onClick={() => setOffset(value => Math.max(0, value - limit))} className="rounded border border-white/10 px-3 py-2 disabled:opacity-40">Previous</button>
        <span>{data.total ? `${offset + 1}-${Math.min(offset + limit, data.total)} of ${data.total}` : "0 observations"}</span>
        <button disabled={offset + limit >= data.total || loading} onClick={() => setOffset(value => value + limit)} className="rounded border border-white/10 px-3 py-2 disabled:opacity-40">Next</button>
      </div>
    </section>
  );
}
