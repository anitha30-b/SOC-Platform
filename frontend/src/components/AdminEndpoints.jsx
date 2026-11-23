
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API = (SOC_DEPLOY_API_BASE + "/assets");

const emptyForm = {
  name: "",
  asset_type: "Endpoint",
  ip_address: "",
  hostname: "",
  url: "",
  environment: "Production",
  status: "Active",
  criticality: "Medium",
  owner: "",
  notes: "",
};

const inputClass =
  "w-full rounded-md border border-white/10 bg-[#090c0f] px-3 py-2.5 text-sm text-white outline-none focus:border-red-500";
const labelClass = "mb-1.5 block text-xs font-medium text-gray-400";

function authConfig() {
  const token = localStorage.getItem("token");
  return { headers: token ? { Authorization: `Bearer ${token}` } : {} };
}

export default function AdminEndpoints({ onBack }) {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [criticalityFilter, setCriticalityFilter] = useState("All");
  const [form, setForm] = useState(emptyForm);
  const [editing, setEditing] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [checkingId, setCheckingId] = useState(null);
  const [healthChecks, setHealthChecks] = useState({});

  const loadEndpoints = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await axios.get(API, authConfig());
      const allAssets = response.data.assets || [];
      setAssets(allAssets.filter(
        (asset) => ["endpoint", "workstation", "laptop", "desktop"].includes(
          (asset.asset_type || "").toLowerCase()
        )
      ));
    } catch (err) {
      setError(
        err.response?.status === 401 || err.response?.status === 403
          ? "Authorization failed. Sign in with an authorized account."
          : err.response?.data?.detail ||
            "Cannot load endpoints. Check that the backend and database are running."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadEndpoints();
  }, [loadEndpoints]);

  const filtered = useMemo(() => {
    const search = query.trim().toLowerCase();
    return assets.filter((asset) => {
      const text = [
        asset.name, asset.hostname, asset.ip_address, asset.owner,
        asset.environment, asset.status, asset.criticality, asset.notes,
      ].filter(Boolean).join(" ").toLowerCase();

      return text.includes(search) &&
        (statusFilter === "All" || asset.status === statusFilter) &&
        (criticalityFilter === "All" || asset.criticality === criticalityFilter);
    });
  }, [assets, query, statusFilter, criticalityFilter]);

  const activeCount = assets.filter((a) => a.status === "Active").length;
  const criticalCount = assets.filter((a) => a.criticality === "Critical").length;
  const inactiveCount = assets.filter((a) => a.status !== "Active").length;
  const healthValues = assets.map((asset) => healthChecks[asset.id]?.status);
  const reachableCount = healthValues.filter((status) => status === "reachable").length;
  const unreachableCount = healthValues.filter((status) => status === "unreachable").length;
  const uncheckedCount = assets.length - reachableCount - unreachableCount;


  function openCreate() {
    setEditing(null);
    setForm({ ...emptyForm });
    setError("");
    setMessage("");
    setShowForm(true);
  }

  function openEdit(asset) {
    setEditing(asset.id);
    setForm({ ...emptyForm, ...asset });
    setError("");
    setMessage("");
    setShowForm(true);
  }

  async function saveEndpoint(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setMessage("");

    try {
      const payload = Object.fromEntries(
        Object.entries(form).map(([key, value]) => [
          key, typeof value === "string" ? value.trim() : value,
        ])
      );

      if (!payload.name) {
        setError("Endpoint name is required.");
        return;
      }

      payload.asset_type = payload.asset_type || "Endpoint";

      if (editing !== null) {
        await axios.put(`${API}/${editing}`, payload, authConfig());
      } else {
        await axios.post(API, payload, authConfig());
      }

      setShowForm(false);
      setMessage(editing !== null ? "Endpoint updated successfully." : "Endpoint registered successfully.");
      await loadEndpoints();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not save the endpoint.");
    } finally {
      setSaving(false);
    }
  }

  async function deleteEndpoint(asset) {
    if (!window.confirm(`Delete endpoint "${asset.name}"? This cannot be undone.`)) {
      return;
    }

    setError("");
    setMessage("");

    try {
      await axios.delete(`${API}/${asset.id}`, authConfig());
      setMessage("Endpoint deleted successfully.");
      await loadEndpoints();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not delete the endpoint.");
    }
  }

  const [checkingAll, setCheckingAll] = useState(false);

  async function checkAllReachability() {
    if (checkingAll || checkingId !== null) return;
    setCheckingAll(true);
    setError("");
    setMessage("");

    try {
      for (const asset of assets) {
        if (asset.ip_address) {
          await checkReachability(asset);
        }
      }
      setMessage("Reachability checks completed for endpoints with IP addresses.");
    } finally {
      setCheckingAll(false);
    }
  }

  async function checkReachability(asset) {
    setCheckingId(asset.id);
    setError("");
    setMessage("");

    try {
      const response = await axios.get(
        `${API}/${asset.id}/reachability?port=443&timeout=2`,
        authConfig()
      );

      const result = response.data;
      const status = String(result.status || "").toLowerCase();
      const reachable =
        result.reachable ??
        result.is_reachable ??
        (status === "reachable" ? true :
         status === "unreachable" ? false : undefined);

      setHealthChecks((previous) => ({
        ...previous,
        [asset.id]: {
          status: reachable === true ? "reachable" :
                  reachable === false ? "unreachable" : "unknown",
          checkedAt: new Date().toISOString(),
          reason: result.reason || "",
        },
      }));

      if (reachable === true) {
        setMessage(`${asset.name}: TCP port 443 is reachable.`);
      } else if (reachable === false) {
        setError(
          `${asset.name}: TCP port 443 is unreachable. ${
            result.reason || "Connection failed or timed out."
          }`
        );
      } else {
        setError(
          `${asset.name}: Reachability could not be determined.`
        );
      }
    } catch (err) {
      setHealthChecks((previous) => ({
        ...previous,
        [asset.id]: {
          status: "unknown",
          checkedAt: new Date().toISOString(),
          reason: err.response?.data?.detail || "Check failed.",
        },
      }));
      setError(
        err.response?.data?.detail ||
        `Could not check reachability for ${asset.name}.`
      );
    } finally {
      setCheckingId(null);
    }
  }

  function exportCSV() {
    const columns = [
      "id", "name", "asset_type", "hostname", "ip_address",
      "environment", "status", "criticality", "owner",
    ];
    const cell = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const csv = "\uFEFF" + [
      columns.join(","),
      ...filtered.map((asset) => columns.map((key) => cell(asset[key])).join(",")),
    ].join("\r\n");

    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8;" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "soc-endpoints.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const stats = [
    { label: "TOTAL ENDPOINTS", value: assets.length, symbol: "▣" },
    { label: "ACTIVE", value: activeCount, symbol: "●" },
    { label: "CRITICAL", value: criticalCount, symbol: "!" },
    { label: "INACTIVE / OTHER", value: inactiveCount, symbol: "◷" },
  ];

  return (
    <section className="space-y-6 text-white">
      {(error || message) && (
        <div
          role={error ? "alert" : "status"}
          className={`flex items-start gap-3 rounded-xl border px-4 py-3 shadow-lg ${
            error
              ? "border-red-500/30 bg-red-500/10 text-red-200"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
          }`}
        >
          <span
            className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-sm font-bold ${
              error
                ? "bg-red-500/15 text-red-400"
                : "bg-emerald-500/15 text-emerald-400"
            }`}
            aria-hidden="true"
          >
            {error ? "!" : "✓"}
          </span>
          <p className="flex-1 text-sm leading-6">
            {error || message}
          </p>
          <button
            type="button"
            onClick={() => {
              setError("");
              setMessage("");
            }}
            aria-label="Dismiss notification"
            className="rounded-md px-2 py-1 text-lg leading-none text-gray-400 transition hover:bg-white/10 hover:text-white"
          >
            ×
          </button>
        </div>
      )}

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-[0.25em] text-red-400">
            <span className="h-px w-7 bg-red-500" />
            Asset Management / Endpoints
          </div>
          <h1 className="text-3xl font-bold tracking-tight">Endpoint Management</h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-500">
            Register and manage workstation, laptop, and desktop assets across your environment.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={onBack} className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/30">
            ← Overview
          </button>
          <button type="button" onClick={loadEndpoints} className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-red-500">
            ↻ Refresh
          </button>
          <button type="button" onClick={exportCSV} className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-red-500">
            ↓ Export CSV
          </button>
          <button type="button" onClick={openCreate} className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700">
            + Add Endpoint
          </button>
        </div>
      </div>


      <div className="space-y-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-200">Endpoint Health</h2>
          <p className="mt-1 text-xs text-gray-500">Latest TCP 443 checks for registered endpoints</p>
          <button
            type="button"
            onClick={checkAllReachability}
            disabled={checkingAll || checkingId !== null || assets.every((asset) => !asset.ip_address)}
            className="mt-3 rounded-md border border-cyan-500/25 px-3 py-2 text-xs text-cyan-300 transition hover:bg-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {checkingAll ? "Checking endpoints…" : "↻ Recheck All"}
          </button>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/[0.04] p-4 transition hover:border-emerald-500/40">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-gray-400">Reachable</span>
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
            </div>
            <div className="mt-3 text-2xl font-bold tabular-nums text-emerald-300">{reachableCount}</div>
            <p className="mt-1 text-[11px] text-gray-500">TCP 443 connection succeeded</p>
          </div>
          <div className="rounded-xl border border-red-500/20 bg-red-500/[0.04] p-4 transition hover:border-red-500/40">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-gray-400">Unreachable</span>
              <span className="h-2 w-2 rounded-full bg-red-400" />
            </div>
            <div className="mt-3 text-2xl font-bold tabular-nums text-red-300">{unreachableCount}</div>
            <p className="mt-1 text-[11px] text-gray-500">Connection failed or timed out</p>
          </div>
          <div className="rounded-xl border border-white/10 bg-[#0b0e11] p-4 transition hover:border-white/20">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-gray-400">Not checked</span>
              <span className="h-2 w-2 rounded-full bg-gray-500" />
            </div>
            <div className="mt-3 text-2xl font-bold tabular-nums text-gray-200">{uncheckedCount}</div>
            <p className="mt-1 text-[11px] text-gray-500">No result in this page session</p>
          </div>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => (
          <div key={stat.label} className="rounded-xl border border-white/10 bg-[#0b0e11] p-5 transition duration-200 hover:border-red-500/30 hover:bg-[#0d1014]">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold tracking-[0.15em] text-gray-500">{stat.label}</span>
              <span className="flex h-8 w-8 items-center justify-center rounded-md border border-red-500/20 bg-red-500/10 text-sm text-red-400">
                {stat.symbol}
              </span>
            </div>
            <div className="mt-4 text-3xl font-bold tabular-nums">
              {loading ? "—" : stat.value}
            </div>
            <div className="mt-2 text-[11px] text-gray-600">Registered in the SOC asset database</div>
          </div>
        ))}
      </div>

      <div className="overflow-hidden rounded-lg border border-white/10 bg-[#0b0e11]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-4">
          <div>
            <h2 className="font-semibold">Registered Endpoints</h2>
            <p className="mt-1 text-xs text-gray-500">{filtered.length} of {assets.length} endpoints</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <input
              aria-label="Search endpoints"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search name, hostname, IP..."
              className={`${inputClass} min-w-48 sm:w-64`}
            />
            <select aria-label="Filter endpoint status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className={inputClass}>
              <option value="All">All statuses</option>
              <option value="Active">Active</option>
              <option value="Inactive">Inactive</option>
              <option value="Under Maintenance">Under Maintenance</option>
              <option value="Decommissioned">Decommissioned</option>
            </select>
            <select aria-label="Filter endpoint criticality" value={criticalityFilter} onChange={(event) => setCriticalityFilter(event.target.value)} className={inputClass}>
              <option value="All">All criticality</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="p-10 text-center text-sm text-gray-500">Loading endpoints from the database...</div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center">
            <div className="text-3xl text-gray-700">▣</div>
            <h3 className="mt-3 text-sm font-semibold text-gray-300">No endpoints found</h3>
            <p className="mt-2 text-xs text-gray-500">
              Add an endpoint or adjust your search and filters. Only endpoint-type assets appear here.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1000px] text-left text-xs">
              <thead className="sticky top-0 border-b border-white/10 bg-[#101418] text-[10px] uppercase tracking-[0.12em] text-gray-400">
                <tr>
                  <th className="px-4 py-3">Endpoint</th>
                  <th className="px-4 py-3">IP / Hostname</th>
                  <th className="px-4 py-3">Environment</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Health Check</th>
                  <th className="px-4 py-3">Criticality</th>
                  <th className="px-4 py-3">Owner</th>
                  <th className="px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filtered.map((asset) => (
                  <tr key={asset.id} className="group transition-colors duration-150 hover:bg-white/[0.04]">
                    <td className="px-4 py-4">
                      <div className="font-semibold text-gray-100 transition-colors group-hover:text-white">{asset.name}</div>
                      <div className="mt-1 text-[10px] text-gray-500">ID {asset.id} · {asset.asset_type}</div>
                    </td>
                    <td className="px-4 py-4">
                      <div className="text-gray-300">{asset.ip_address || "—"}</div>
                      <div className="mt-1 text-[10px] text-gray-500">{asset.hostname || "No hostname"}</div>
                    </td>
                    <td className="px-4 py-4 text-gray-400">{asset.environment || "—"}</td>
                    <td className="px-4 py-4">
                      <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-semibold ${
                        asset.status === "Active"
                          ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                          : "border-amber-500/25 bg-amber-500/10 text-amber-300"
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${
                          asset.status === "Active" ? "bg-emerald-400" : "bg-amber-400"
                        }`} />
                        {asset.status || "Unknown"}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      {checkingId === asset.id ? (
                        <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/25 bg-cyan-500/10 px-2.5 py-1 text-[10px] text-cyan-300">
                          <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" />
                          Checking…
                        </div>
                      ) : (
                        <div>
                          <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-semibold ${
                            healthChecks[asset.id]?.status === "reachable"
                              ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                              : healthChecks[asset.id]?.status === "unreachable"
                              ? "border-red-500/25 bg-red-500/10 text-red-300"
                              : "border-white/10 bg-white/[0.03] text-gray-400"
                          }`}>
                            <span className={`h-1.5 w-1.5 rounded-full ${
                              healthChecks[asset.id]?.status === "reachable"
                                ? "bg-emerald-400"
                                : healthChecks[asset.id]?.status === "unreachable"
                                ? "bg-red-400"
                                : "bg-gray-500"
                            }`} />
                            {healthChecks[asset.id]?.status === "reachable"
                              ? "Reachable"
                              : healthChecks[asset.id]?.status === "unreachable"
                              ? "Unreachable"
                              : "Not checked"}
                          </span>
                          {healthChecks[asset.id]?.checkedAt && (
                            <div
                              className="mt-1.5 text-[10px] text-gray-500"
                              title={healthChecks[asset.id].reason || ""}
                            >
                              {new Date(healthChecks[asset.id].checkedAt).toLocaleTimeString([], {
                                hour: "2-digit",
                                minute: "2-digit",
                              })}
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-4">
                      <span className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-semibold ${
                        asset.criticality === "Critical" ? "border-red-500/30 bg-red-500/10 text-red-300" :
                        asset.criticality === "High" ? "border-orange-500/30 bg-orange-500/10 text-orange-300" :
                        asset.criticality === "Low" ? "border-sky-500/25 bg-sky-500/10 text-sky-300" :
                        "border-white/10 bg-white/[0.03] text-gray-300"
                      }`}>
                        {asset.criticality || "Medium"}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-gray-400">{asset.owner || "—"}</td>
                    <td className="px-4 py-4">
                      <div className="flex flex-wrap gap-2">
                        <button type="button" onClick={() => openEdit(asset)} className="rounded-md border border-white/10 px-3 py-1.5 text-gray-300 transition hover:border-red-500/50 hover:bg-red-500/5 hover:text-white">Edit</button>
                        <button type="button" disabled={checkingId === asset.id || !asset.ip_address} onClick={() => checkReachability(asset)} className="rounded-md border border-cyan-500/20 bg-cyan-500/[0.04] px-3 py-1.5 text-cyan-300 transition hover:border-cyan-400/50 hover:bg-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-40">
                          {checkingId === asset.id ? "Checking..." : "Check TCP 443"}
                        </button>
                        <button type="button" onClick={() => deleteEndpoint(asset)} className="rounded-md border border-red-500/25 px-3 py-1.5 text-red-300 transition hover:border-red-500/50 hover:bg-red-500/10">Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/75 p-4">
          <form onSubmit={saveEndpoint} className="my-6 w-full max-w-3xl rounded-xl border border-white/10 bg-[#0b1014] shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/10 p-5">
              <div>
                <h2 className="text-lg font-semibold">{editing !== null ? "Edit Endpoint" : "Register Endpoint"}</h2>
                <p className="mt-1 text-xs text-gray-500">Endpoint details are stored in the existing SOC asset inventory.</p>
              </div>
              <button type="button" onClick={() => setShowForm(false)} className="rounded border border-white/10 px-3 py-1.5 text-sm text-gray-400 hover:text-white">✕</button>
            </div>

            <div className="grid gap-4 p-5 sm:grid-cols-2">
              <label className={labelClass}>Endpoint name *
                <input required maxLength={200} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputClass} placeholder="e.g. Finance-Laptop-01" />
              </label>

              <label className={labelClass}>Device type
                <select value={form.asset_type} onChange={(e) => setForm({ ...form, asset_type: e.target.value })} className={inputClass}>
                  <option>Endpoint</option>
                  <option>Workstation</option>
                  <option>Laptop</option>
                  <option>Desktop</option>
                </select>
              </label>

              <label className={labelClass}>IP address
                <input value={form.ip_address || ""} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} className={inputClass} placeholder="e.g. 192.168.1.25" />
              </label>

              <label className={labelClass}>Hostname
                <input maxLength={255} value={form.hostname || ""} onChange={(e) => setForm({ ...form, hostname: e.target.value })} className={inputClass} placeholder="e.g. FIN-LT-01" />
              </label>

              <label className={labelClass}>Environment
                <select value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })} className={inputClass}>
                  <option>Production</option><option>Development</option><option>Testing</option><option>Staging</option><option>Corporate</option>
                </select>
              </label>

              <label className={labelClass}>Status
                <select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })} className={inputClass}>
                  <option>Active</option><option>Inactive</option><option>Under Maintenance</option><option>Decommissioned</option>
                </select>
              </label>

              <label className={labelClass}>Criticality
                <select value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })} className={inputClass}>
                  <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
                </select>
              </label>

              <label className={labelClass}>Owner / Department
                <input maxLength={200} value={form.owner || ""} onChange={(e) => setForm({ ...form, owner: e.target.value })} className={inputClass} placeholder="e.g. Finance" />
              </label>

              <label className={`${labelClass} sm:col-span-2`}>Asset URL (optional)
                <input type="url" value={form.url || ""} onChange={(e) => setForm({ ...form, url: e.target.value })} className={inputClass} placeholder="https://example.com" />
              </label>

              <label className={`${labelClass} sm:col-span-2`}>Notes
                <textarea rows={3} value={form.notes || ""} onChange={(e) => setForm({ ...form, notes: e.target.value })} className={inputClass} placeholder="Additional endpoint details..." />
              </label>

              {error && (
                <div role="alert" className="sm:col-span-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
                  {error}
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 border-t border-white/10 p-5">
              <button type="button" onClick={() => setShowForm(false)} className="rounded-md border border-white/10 px-4 py-2 text-xs text-gray-300 hover:border-white/30">Cancel</button>
              <button type="submit" disabled={saving} className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700 disabled:opacity-50">
                {saving ? "Saving..." : editing !== null ? "Save Changes" : "Register Endpoint"}
              </button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}
