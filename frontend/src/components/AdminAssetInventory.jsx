
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import AdminDiscoveredServers from "./AdminDiscoveredServers";

const API = (SOC_DEPLOY_API_BASE + "/assets");
const emptyForm = {
  name: "", asset_type: "Server", ip_address: "", url: "", hostname: "",
  environment: "Production", status: "Active", criticality: "Medium",
  owner: "", notes: "",
};

const fieldClass =
  "w-full rounded-md border border-white/10 bg-[#090c0f] px-3 py-2.5 text-sm text-white outline-none focus:border-red-500";
const labelClass = "mb-1.5 block text-xs font-medium text-gray-400";

function authConfig() {
  const token = localStorage.getItem("token");
  return { headers: token ? { Authorization: `Bearer ${token}` } : {} };
}

export default function AdminAssetInventory({ onBack }) {
  const [assets, setAssets] = useState([]);
  const [detailsAsset, setDetailsAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [typeFilter, setTypeFilter] = useState("All");
  const [form, setForm] = useState(emptyForm);
  const [editing, setEditing] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);

  const loadAssets = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await axios.get(API, authConfig());
      setAssets(response.data.assets || []);
    } catch (err) {
      setError(
        err.response?.status === 401 || err.response?.status === 403
          ? "Admin authorization failed. Sign in with an authorized administrator account."
          : err.response?.data?.detail || "Cannot load assets. Check that the backend and database are running."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAssets(); }, [loadAssets]);

  const filtered = useMemo(() => assets.filter((a) => {
    const haystack = [
      a.name, a.url, a.ip_address, a.hostname, a.owner,
      a.asset_type, a.environment, a.status, a.criticality, a.notes
    ].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(query.trim().toLowerCase()) &&
      (statusFilter === "All" || a.status === statusFilter) &&
      (typeFilter === "All" || a.asset_type === typeFilter);
  }), [assets, query, statusFilter, typeFilter]);

  const active = assets.filter((a) => a.status === "Active").length;
  const critical = assets.filter((a) => a.criticality === "Critical").length;
  const inactive = assets.filter((a) => a.status !== "Active").length;
  const types = [...new Set(assets.map((a) => a.asset_type).filter(Boolean))];

  function openCreate() {
    setEditing(null);
    setForm(emptyForm);
    setError("");
    setShowForm(true);
  }

  function openEdit(asset) {
    setEditing(asset.id);
    setForm({ ...emptyForm, ...asset });
    setError("");
    setShowForm(true);
  }

  async function saveAsset(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const payload = Object.fromEntries(
        Object.entries(form).map(([k, v]) => [k, typeof v === "string" ? v.trim() : v])
      );
      if (!payload.name) {
        setError("Asset name is required.");
        return;
      }
      if (editing) {
        await axios.put(`${API}/${editing}`, payload, authConfig());
      } else {
        await axios.post(API, payload, authConfig());
      }
      setShowForm(false);
      await loadAssets();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not save the asset.");
    } finally {
      setSaving(false);
    }
  }

  async function removeAsset(asset) {
    if (!window.confirm(`Delete asset "${asset.name}"? This cannot be undone.`)) return;
    setError("");
    try {
      await axios.delete(`${API}/${asset.id}`, authConfig());
      await loadAssets();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not delete the asset.");
    }
  }

  function downloadCSV() {
    const columns = [
      "id", "name", "asset_type", "url", "hostname", "ip_address",
      "environment", "status", "criticality", "owner",
    ];
    const cell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const csv = "\\uFEFF" + [
      columns.join(","),
      ...filtered.map((a) => columns.map((c) => cell(a[c])).join(",")),
    ].join("\r\n");
    const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8;" })
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "soc-asset-inventory.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const stats = [
    { label: "REGISTERED ASSETS", value: assets.length, mark: "▣" },
    { label: "ACTIVE ASSETS", value: active, mark: "●" },
    { label: "CRITICAL ASSETS", value: critical, mark: "!" },
    { label: "INACTIVE / OTHER", value: inactive, mark: "◷" },
  ];

  return (
    <section className="space-y-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-[0.25em] text-red-400">
            <span className="h-px w-7 bg-red-500" /> Asset Management / Inventory
          </div>
          <h1 className="text-3xl font-bold tracking-tight">Asset Inventory</h1>
          <p className="mt-2 max-w-xl text-sm text-gray-500">
            Centralized visibility of registered infrastructure, endpoints, and applications.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {onBack && <button onClick={onBack} className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/30">← Overview</button>}
          <button onClick={loadAssets} className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-red-500">↻ Refresh</button>
          <button onClick={downloadCSV} className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-red-500">↓ Export CSV</button>
          <button onClick={openCreate} className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700">+ Add Asset</button>
        </div>
      </div>

      {error && <div role="alert" className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((s) => (
          <div key={s.label} className="rounded-lg border border-white/10 bg-[#0b0e11] p-5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold tracking-[0.15em] text-gray-500">{s.label}</span>
              <span className="flex h-8 w-8 items-center justify-center rounded-md border border-red-500/20 bg-red-500/10 text-sm text-red-400">{s.mark}</span>
            </div>
            <div className="mt-4 text-3xl font-bold tabular-nums">{loading ? "—" : s.value}</div>
            <div className="mt-2 text-[11px] text-gray-600">Registered inventory count</div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-white/10 bg-[#0b0e11]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-4">
          <div>
            <h2 className="font-semibold">Registered Assets</h2>
            <p className="mt-1 text-xs text-gray-500">{filtered.length} of {assets.length} assets</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <input aria-label="Search assets" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search name, URL, hostname..." className={`${fieldClass} min-w-48 sm:w-64`} />
            <select aria-label="Filter by type" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className={fieldClass}>
              <option value="All">All types</option>
              {types.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <select aria-label="Filter by status" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={fieldClass}>
              <option>All</option><option>Active</option><option>Inactive</option><option>Under Maintenance</option><option>Decommissioned</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1250px] text-left text-xs">
            <thead className="bg-white/[0.025] text-[10px] uppercase tracking-wider text-gray-500">
              <tr>
                {["Asset", "IP Address", "Type / Environment", "Website URL", "Discovered Services", "Criticality", "Status", "Owner", "Actions"].map((h) => <th key={h} className="px-4 py-4 font-semibold">{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {loading ? <tr><td colSpan={9} className="px-4 py-12 text-center text-gray-500">Loading assets…</td></tr>
                : filtered.length === 0 ? <tr><td colSpan={9} className="px-4 py-14 text-center"><div className="text-2xl text-gray-600">▣</div><p className="mt-3 font-medium text-gray-300">{assets.length ? "No matching assets" : "No assets registered yet"}</p><p className="mt-1 text-gray-600">{assets.length ? "Change your search or filters." : "Select Add Asset to register your first asset."}</p></td></tr>
                : filtered.map((a) => {
                  const discoveryNotes = a.notes?.match(/\[Nmap Discovery\]([\s\S]*?)\[\/Nmap Discovery\]/)?.[1] || "";
                  const servicesLine = discoveryNotes.split("\n").find((line) => line.trim().startsWith("Open services:"));
                  const services = servicesLine ? servicesLine.replace("Open services:", "").trim() : "";

                  return (
                    <tr key={a.id} className="transition hover:bg-white/[0.025]">
                      <td className="px-4 py-4"><div className="font-semibold text-gray-100">{a.name}</div><div className="mt-1 text-[10px] text-gray-600">ASSET-{String(a.id).padStart(4, "0")}</div></td>
                      <td className="px-4 py-4 font-mono text-gray-300">{a.ip_address || "—"}</td>
                      <td className="px-4 py-4"><div className="text-gray-300">{a.asset_type || "—"}</div><div className="mt-1 text-[10px] text-gray-600">{a.environment || "—"}</div></td>
                      <td className="max-w-[220px] break-all px-4 py-4 font-mono text-gray-400">{a.url ? <a href={a.url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">{a.url}</a> : "—"}</td>
                      <td className="max-w-[260px] px-4 py-4 text-gray-300">{services || <span className="text-gray-600">Not discovered</span>}</td>
                      <td className="px-4 py-4"><span className={`rounded border px-2 py-1 text-[10px] ${a.criticality === "Critical" ? "border-red-500/30 bg-red-500/10 text-red-300" : a.criticality === "High" ? "border-orange-500/30 text-orange-300" : "border-white/10 text-gray-400"}`}>{a.criticality}</span></td>
                      <td className="px-4 py-4"><span className={`inline-flex items-center gap-1.5 ${a.status === "Active" ? "text-emerald-400" : "text-gray-500"}`}><span>●</span>{a.status}</span></td>
                      <td className="px-4 py-4 text-gray-400">{a.owner || "—"}</td>
                      <td className="px-4 py-4"><div className="flex flex-wrap gap-3">
                        <button type="button" onClick={() => setDetailsAsset(a)} className="text-blue-400 hover:text-blue-300">View Details</button>
                        <button type="button" onClick={() => openEdit(a)} className="text-gray-400 hover:text-white">Edit</button>
                        <button type="button" onClick={() => removeAsset(a)} className="text-red-400 hover:text-red-300">Delete</button>
                      </div></td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
        <div className="flex flex-wrap justify-between gap-2 border-t border-white/10 px-4 py-3 text-[10px] text-gray-600">
          <span>Source: SOC Platform database</span><span>Authorized administrator access</span>
        </div>
      </div>

      <AdminDiscoveredServers apiUrl={`${API}/discovered-servers`} />

      {detailsAsset && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm" onClick={() => setDetailsAsset(null)}>
          <div role="dialog" aria-modal="true" aria-labelledby="asset-details-title" className="w-full max-w-2xl rounded-xl border border-white/10 bg-[#0b0e11] shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-white/10 p-5">
              <div>
                <p className="text-[10px] uppercase tracking-widest text-blue-400">Asset Inventory</p>
                <h2 id="asset-details-title" className="mt-1 text-lg font-bold text-white">{detailsAsset.name}</h2>
              </div>
              <button type="button" onClick={() => setDetailsAsset(null)} className="px-2 text-xl text-gray-400 hover:text-white" aria-label="Close asset details">×</button>
            </div>
            <div className="grid gap-4 p-5 sm:grid-cols-2">
              {[
                ["IP Address", detailsAsset.ip_address],
                ["Hostname", detailsAsset.hostname],
                ["Asset Type", detailsAsset.asset_type],
                ["Environment", detailsAsset.environment],
                ["Website URL", detailsAsset.url],
                ["Criticality", detailsAsset.criticality],
                ["Status", detailsAsset.status],
                ["Owner", detailsAsset.owner],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg border border-white/[0.08] p-3">
                  <p className="text-[10px] uppercase tracking-wider text-gray-500">{label}</p>
                  <p className="mt-1 break-all text-sm text-gray-200">{value || "—"}</p>
                </div>
              ))}
              <div className="sm:col-span-2">
                <p className="mb-2 text-[10px] uppercase tracking-wider text-gray-500">Discovery Notes</p>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-white/[0.08] bg-black/20 p-3 text-xs text-gray-300">{detailsAsset.notes || "No discovery notes available."}</pre>
              </div>
            </div>
            <div className="flex justify-end border-t border-white/10 p-4">
              <button type="button" onClick={() => setDetailsAsset(null)} className="rounded-md border border-white/10 px-4 py-2 text-sm text-gray-300 hover:bg-white/5">Close</button>
            </div>
          </div>
        </div>
      )}

      {showForm && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center overflow-y-auto bg-black/80 p-4 backdrop-blur-sm">
          <form onSubmit={saveAsset} className="my-auto max-h-[92vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-white/10 bg-[#0b0e11] shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/10 p-5">
              <div><p className="text-[10px] uppercase tracking-widest text-red-400">Asset Management</p><h2 className="mt-1 text-lg font-bold">{editing ? "Edit Asset" : "Register New Asset"}</h2></div>
              <button type="button" onClick={() => setShowForm(false)} className="px-2 text-xl text-gray-500 hover:text-white" aria-label="Close">×</button>
            </div>
            <div className="grid gap-4 p-5 sm:grid-cols-2">
              {[
                ["name", "Asset Name", "e.g. Production Web Server", true],
                ["hostname", "Hostname", "e.g. web-prod-01"],
                ["url", "Website URL", "https://example.com"],
                ["owner", "Owner / Team", "e.g. Infrastructure"],
              ].map(([key, title, placeholder, required]) => (
                <label key={key}><span className={labelClass}>{title}{required ? " *" : ""}</span><input type={key === "url" ? "url" : "text"} required={!!required} maxLength={key === "name" ? 200 : key === "url" ? 2048 : 255} value={form[key] || ""} onChange={(e) => setForm({ ...form, [key]: e.target.value })} placeholder={placeholder} className={fieldClass} /></label>
              ))}
              {[
                ["asset_type", "Asset Type", ["Server", "Endpoint", "Network Device", "Application", "Database", "Cloud", "Domain", "Other"]],
                ["environment", "Environment", ["Production", "Staging", "Development", "Testing", "Cloud"]],
                ["criticality", "Criticality", ["Critical", "High", "Medium", "Low"]],
                ["status", "Status", ["Active", "Inactive", "Under Maintenance", "Decommissioned"]],
              ].map(([key, title, options]) => (
                <label key={key}><span className={labelClass}>{title}</span><select value={form[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} className={fieldClass}>{options.map((o) => <option key={o}>{o}</option>)}</select></label>
              ))}
              <label className="sm:col-span-2"><span className={labelClass}>Notes</span><textarea rows="3" value={form.notes || ""} onChange={(e) => setForm({ ...form, notes: e.target.value })} className={fieldClass} placeholder="Optional asset details…" /></label>
            </div>
            <div className="flex justify-end gap-2 border-t border-white/10 p-5">
              <button type="button" onClick={() => setShowForm(false)} className="rounded-md border border-white/10 px-4 py-2 text-xs text-gray-300">Cancel</button>
              <button disabled={saving} className="rounded-md bg-red-600 px-5 py-2 text-xs font-semibold disabled:opacity-50">{saving ? "Saving…" : editing ? "Save Changes" : "Register Asset"}</button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}
