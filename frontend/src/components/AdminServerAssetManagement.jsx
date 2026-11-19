import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000/assets";
const REFRESH_MS = 20000;

function authConfig() {
  const token = localStorage.getItem("token");
  return { headers: token ? { Authorization: `Bearer ${token}` } : {} };
}

function discoveryInfo(notes = "") {
  const block = notes.match(
    /\[Nmap Discovery\]([\s\S]*?)\[\/Nmap Discovery\]/i
  )?.[1] || "";

  const line = (prefix) =>
    block.split("\n").find((item) =>
      item.trim().toLowerCase().startsWith(prefix.toLowerCase())
    )?.split(":").slice(1).join(":").trim() || "";

  return {
    hostStatus: line("Host status"),
    services: line("Open services"),
    target: line("Scan target"),
    discovered: Boolean(block),
  };
}

function Badge({ children, tone = "neutral" }) {
  const colors = {
    green: "border-emerald-500/25 bg-emerald-500/10 text-emerald-300",
    red: "border-red-500/25 bg-red-500/10 text-red-300",
    amber: "border-amber-500/25 bg-amber-500/10 text-amber-300",
    neutral: "border-white/10 bg-white/5 text-gray-300",
    blue: "border-blue-500/25 bg-blue-500/10 text-blue-300",
  };
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] ${colors[tone] || colors.neutral}`}>
      {children || "Unknown"}
    </span>
  );
}

export default function AdminServerAssetManagement({ onBack, onInventory }) {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [criticalityFilter, setCriticalityFilter] = useState("All");
  const [selected, setSelected] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadServers = useCallback(async (background = false) => {
    if (background) setRefreshing(true);
    else setLoading(true);
    setError("");

    try {
      const response = await axios.get(API, authConfig());
      const allAssets = Array.isArray(response.data)
        ? response.data
        : response.data?.assets || [];

      const servers = allAssets.filter(
        (asset) => String(asset.asset_type || "").toLowerCase() === "server"
      );

      setAssets(servers);
      setLastUpdated(new Date());
      setSelected((current) =>
        current ? servers.find((asset) => asset.id === current.id) || null : null
      );
    } catch (err) {
      setError(
        err.response?.status === 401 || err.response?.status === 403
          ? "Administrator authorization failed. Sign in with an authorized admin account."
          : err.response?.data?.detail ||
            "Unable to load server assets. Check the backend and database."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadServers();
    const timer = window.setInterval(() => loadServers(true), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [loadServers]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();

    return assets.filter((asset) => {
      const haystack = [
        asset.name, asset.hostname, asset.ip_address, asset.url,
        asset.environment, asset.status, asset.criticality, asset.owner,
        asset.notes,
      ].filter(Boolean).join(" ").toLowerCase();

      return haystack.includes(needle) &&
        (statusFilter === "All" || asset.status === statusFilter) &&
        (criticalityFilter === "All" || asset.criticality === criticalityFilter);
    });
  }, [assets, query, statusFilter, criticalityFilter]);

  const active = assets.filter((asset) => asset.status === "Active").length;
  const critical = assets.filter((asset) => asset.criticality === "Critical").length;
  const discovered = assets.filter((asset) => discoveryInfo(asset.notes).discovered).length;

  function exportCSV() {
    const columns = [
      "id", "name", "hostname", "ip_address", "url", "environment",
      "status", "criticality", "owner", "updated_at",
    ];
    const cell = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const content = "\uFEFF" + [
      columns.join(","),
      ...filtered.map((asset) => columns.map((key) => cell(asset[key])).join(",")),
    ].join("\r\n");

    const url = URL.createObjectURL(
      new Blob([content], { type: "text/csv;charset=utf-8;" })
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "soc-server-inventory.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const stats = [
    { label: "REGISTERED SERVERS", value: assets.length, symbol: "▣" },
    { label: "ACTIVE INVENTORY", value: active, symbol: "●" },
    { label: "CRITICAL SERVERS", value: critical, symbol: "!" },
    { label: "NMAP-DISCOVERED", value: discovered, symbol: "⌕" },
  ];

  return (
    <section className="space-y-6 text-white">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-[0.25em] text-red-400">
            <span className="h-px w-7 bg-red-500" />
            Asset Management / Infrastructure
          </div>
          <h1 className="text-3xl font-bold tracking-tight">Server Management</h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-500">
            Centralized administration of registered servers and their recorded discovery data.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-gray-500">
            <Badge tone="green">Auto-refresh enabled</Badge>
            <span>Refresh interval: 20 seconds</span>
            {lastUpdated && (
              <span>· Last successful sync: {lastUpdated.toLocaleTimeString()}</span>
            )}
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          {onBack && (
            <button onClick={onBack} className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/30">
              ← Overview
            </button>
          )}
          {onInventory && (
            <button onClick={onInventory} className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-red-500">
              Asset Inventory
            </button>
          )}
          <button onClick={() => loadServers(true)} disabled={refreshing} className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-red-500 disabled:opacity-50">
            {refreshing ? "Refreshing…" : "↻ Refresh"}
          </button>
          <button onClick={exportCSV} className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700">
            ↓ Export CSV
          </button>
        </div>
      </header>

      {error && (
        <div role="alert" className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
          <button onClick={() => loadServers(true)} className="ml-3 underline">Retry</button>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => (
          <div key={stat.label} className="rounded-lg border border-white/10 bg-[#0b0e11] p-5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold tracking-[0.15em] text-gray-500">{stat.label}</span>
              <span className="flex h-8 w-8 items-center justify-center rounded-md border border-red-500/20 bg-red-500/10 text-sm text-red-400">{stat.symbol}</span>
            </div>
            <div className="mt-4 text-3xl font-bold tabular-nums">
              {loading ? "—" : stat.value}
            </div>
            <p className="mt-2 text-[11px] text-gray-600">Database-backed inventory data</p>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-white/10 bg-[#0b0e11]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-4">
          <div>
            <h2 className="font-semibold">Registered Servers</h2>
            <p className="mt-1 text-xs text-gray-500">
              {filtered.length} displayed · {assets.length} total server records
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <input
              aria-label="Search servers"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search hostname, IP, owner…"
              className="min-w-48 rounded-md border border-white/10 bg-[#090c0f] px-3 py-2.5 text-sm text-white outline-none focus:border-red-500 sm:w-64"
            />
            <select aria-label="Filter inventory status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className="rounded-md border border-white/10 bg-[#090c0f] px-3 py-2.5 text-sm text-white">
              <option value="All">All statuses</option>
              <option>Active</option>
              <option>Inactive</option>
              <option>Under Maintenance</option>
              <option>Decommissioned</option>
            </select>
            <select aria-label="Filter criticality" value={criticalityFilter} onChange={(event) => setCriticalityFilter(event.target.value)} className="rounded-md border border-white/10 bg-[#090c0f] px-3 py-2.5 text-sm text-white">
              <option value="All">All criticality</option>
              <option>Critical</option>
              <option>High</option>
              <option>Medium</option>
              <option>Low</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1150px] text-left text-xs">
            <thead className="bg-white/[0.025] text-[10px] uppercase tracking-wider text-gray-500">
              <tr>
                {["Server", "IP Address", "Environment", "Discovery / Services", "Criticality", "Inventory Status", "Owner", "Actions"].map((heading) => (
                  <th key={heading} className="px-4 py-4 font-semibold">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {loading ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-gray-500">Loading server inventory…</td></tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-14 text-center">
                    <div className="text-2xl text-gray-600">▣</div>
                    <p className="mt-3 font-medium text-gray-300">{assets.length ? "No matching servers" : "No server assets registered"}</p>
                    <p className="mt-1 text-gray-600">{assets.length ? "Adjust your search or filters." : "Register a Server-type asset or run an authorized discovery scan."}</p>
                  </td>
                </tr>
              ) : filtered.map((asset) => {
                const discovery = discoveryInfo(asset.notes);
                return (
                  <tr key={asset.id} className="transition hover:bg-white/[0.025]">
                    <td className="px-4 py-4">
                      <div className="font-semibold text-gray-100">{asset.name || asset.hostname || "Unnamed server"}</div>
                      <div className="mt-1 text-[10px] text-gray-600">
                        {asset.hostname || `ASSET-${String(asset.id).padStart(4, "0")}`}
                      </div>
                    </td>
                    <td className="px-4 py-4 font-mono text-gray-300">{asset.ip_address || "—"}</td>
                    <td className="px-4 py-4">
                      <div className="text-gray-300">{asset.environment || "—"}</div>
                      <div className="mt-1 text-[10px] text-gray-600">{asset.asset_type || "Server"}</div>
                    </td>
                    <td className="max-w-[250px] px-4 py-4">
                      {discovery.discovered ? (
                        <>
                          <Badge tone="blue">Nmap data recorded</Badge>
                          <p className="mt-2 break-words text-gray-400">{discovery.services || "No open services recorded"}</p>
                          {discovery.hostStatus && <p className="mt-1 text-[10px] text-gray-600">Scan result: {discovery.hostStatus}</p>}
                        </>
                      ) : <span className="text-gray-600">No Nmap record</span>}
                    </td>
                    <td className="px-4 py-4">
                      <Badge tone={asset.criticality === "Critical" ? "red" : asset.criticality === "High" ? "amber" : "neutral"}>
                        {asset.criticality || "Unassigned"}
                      </Badge>
                    </td>
                    <td className="px-4 py-4">
                      <Badge tone={asset.status === "Active" ? "green" : asset.status === "Under Maintenance" ? "amber" : "neutral"}>
                        {asset.status || "Unknown"}
                      </Badge>
                      <p className="mt-1 text-[10px] text-gray-600">Inventory status, not live reachability</p>
                    </td>
                    <td className="px-4 py-4 text-gray-400">{asset.owner || "—"}</td>
                    <td className="px-4 py-4">
                      <button onClick={() => setSelected(asset)} className="rounded-md border border-white/10 px-3 py-2 text-[11px] text-gray-300 hover:border-red-500 hover:text-white">
                        View details
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="border-t border-white/10 px-4 py-3 text-[10px] text-gray-600">
          Records are fetched from the existing asset API. Refreshing inventory does not initiate a new Nmap scan.
        </div>
      </div>

      {selected && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center overflow-y-auto bg-black/80 p-4 backdrop-blur-sm" onClick={() => setSelected(null)}>
          <section role="dialog" aria-modal="true" aria-label="Server details" onClick={(event) => event.stopPropagation()} className="my-auto max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-xl border border-white/10 bg-[#0b0e11] shadow-2xl">
            <div className="flex items-start justify-between border-b border-white/10 p-5">
              <div>
                <p className="text-[10px] uppercase tracking-widest text-red-400">Server Asset Details</p>
                <h2 className="mt-1 text-xl font-bold">{selected.name || selected.hostname || "Server"}</h2>
                <p className="mt-1 font-mono text-xs text-gray-500">{selected.ip_address || "No IP recorded"}</p>
              </div>
              <button onClick={() => setSelected(null)} aria-label="Close details" className="text-xl text-gray-500 hover:text-white">×</button>
            </div>
            <div className="grid gap-3 p-5 sm:grid-cols-2">
              {[
                ["Hostname", selected.hostname],
                ["Website URL", selected.url],
                ["Environment", selected.environment],
                ["Inventory status", selected.status],
                ["Criticality", selected.criticality],
                ["Owner / team", selected.owner],
                ["Asset ID", selected.id],
                ["Record updated", selected.updated_at ? new Date(selected.updated_at).toLocaleString() : "Not provided"],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg border border-white/[0.08] p-3">
                  <p className="text-[10px] uppercase tracking-wider text-gray-500">{label}</p>
                  <p className="mt-1 break-all text-sm text-gray-200">{value || "—"}</p>
                </div>
              ))}
              <div className="sm:col-span-2">
                <p className="mb-2 text-[10px] uppercase tracking-wider text-gray-500">Recorded Discovery / Asset Notes</p>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-white/[0.08] bg-black/20 p-3 text-xs text-gray-300">{selected.notes || "No notes available."}</pre>
              </div>
            </div>
            <div className="flex justify-end border-t border-white/10 p-4">
              <button onClick={() => setSelected(null)} className="rounded-md border border-white/10 px-4 py-2 text-sm text-gray-300 hover:bg-white/5">Close</button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
