import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000/assets";
const META_PREFIX = "CLOUD_ASSET_META:";

const EMPTY = {
  name: "",
  provider: "AWS",
  resource_type: "Virtual Machine",
  resource_id: "",
  region: "",
  ip_address: "",
  url: "",
  hostname: "",
  environment: "Production",
  status: "Active",
  criticality: "Medium",
  owner: "",
  notes: "",
};

const inputClass =
  "w-full rounded-md border border-white/10 bg-[#090c0f] px-3 py-2.5 text-sm text-white outline-none focus:border-red-500";

function authConfig() {
  const token = localStorage.getItem("token");
  return { headers: token ? { Authorization: `Bearer ${token}` } : {} };
}

function decodeAsset(asset) {
  const raw = asset.notes || "";
  if (!raw.startsWith(META_PREFIX)) {
    return { ...EMPTY, ...asset, provider: "Other", resource_type: "Other",
      resource_id: "", region: "", notes: raw };
  }

  try {
    const meta = JSON.parse(raw.slice(META_PREFIX.length));
    return { ...EMPTY, ...asset, ...meta, notes: meta.notes || "" };
  } catch {
    return { ...EMPTY, ...asset, notes: raw };
  }
}

function encodeAsset(form) {
  const metadata = {
    provider: form.provider,
    resource_type: form.resource_type,
    resource_id: form.resource_id.trim(),
    region: form.region.trim(),
    notes: form.notes.trim(),
  };

  return {
    name: form.name.trim(),
    asset_type: "Cloud Asset",
    ip_address: form.ip_address.trim() || null,
    url: form.url.trim() || null,
    hostname: form.hostname.trim() || null,
    environment: form.environment,
    status: form.status,
    criticality: form.criticality,
    owner: form.owner.trim() || null,
    notes: META_PREFIX + JSON.stringify(metadata),
  };
}

function badgeClass(value) {
  if (["Critical", "Inactive", "Retired"].includes(value)) {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }
  if (value === "High") {
    return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  }
  if (["Active", "Low"].includes(value)) {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }
  return "border-white/10 bg-white/5 text-gray-300";
}

function Field({ label, children }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs text-gray-400">{label}</span>
      {children}
    </label>
  );
}

export default function AdminCloudAssets({ onBack }) {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [providerFilter, setProviderFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [criticalityFilter, setCriticalityFilter] = useState("All");
  const [form, setForm] = useState(EMPTY);
  const [editing, setEditing] = useState(null);
  const [showForm, setShowForm] = useState(false);

  const loadAssets = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await axios.get(API, authConfig());
      setAssets(
        (response.data.assets || [])
          .filter((asset) => asset.asset_type === "Cloud Asset")
          .map(decodeAsset)
      );
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Could not load cloud assets. Check the backend and your administrator login."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return assets.filter((asset) => {
      const searchable = [
        asset.name, asset.provider, asset.resource_type, asset.resource_id,
        asset.region, asset.ip_address, asset.url, asset.environment,
        asset.owner, asset.status, asset.criticality,
      ].filter(Boolean).join(" ").toLowerCase();

      return searchable.includes(q) &&
        (providerFilter === "All" || asset.provider === providerFilter) &&
        (statusFilter === "All" || asset.status === statusFilter) &&
        (criticalityFilter === "All" || asset.criticality === criticalityFilter);
    });
  }, [assets, query, providerFilter, statusFilter, criticalityFilter]);

  const activeCount = assets.filter((a) => a.status === "Active").length;
  const criticalCount = assets.filter((a) => a.criticality === "Critical").length;

  function startCreate() {
    setForm({ ...EMPTY });
    setEditing(null);
    setShowForm(true);
    setError("");
    setNotice("");
  }

  function startEdit(asset) {
    setForm({ ...EMPTY, ...asset });
    setEditing(asset.id);
    setShowForm(true);
    setError("");
    setNotice("");
  }

  async function saveAsset(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");

    try {
      const payload = encodeAsset(form);
      if (editing !== null) {
        await axios.put(`${API}/${editing}`, payload, authConfig());
        setNotice("Cloud asset updated successfully.");
      } else {
        await axios.post(API, payload, authConfig());
        setNotice("Cloud asset registered successfully.");
      }
      setShowForm(false);
      setEditing(null);
      setForm({ ...EMPTY });
      await loadAssets();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not save the cloud asset.");
    } finally {
      setSaving(false);
    }
  }

  async function deleteAsset(asset) {
    if (!window.confirm(`Delete cloud asset "${asset.name}" from the inventory?`)) return;
    setError("");
    setNotice("");
    try {
      await axios.delete(`${API}/${asset.id}`, authConfig());
      setNotice("Cloud asset deleted.");
      await loadAssets();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not delete the cloud asset.");
    }
  }

  function exportCsv() {
    const columns = [
      "id", "name", "provider", "resource_type", "resource_id", "region",
      "ip_address", "url", "hostname", "environment", "status",
      "criticality", "owner", "notes", "created_at",
    ];
    const escape = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const rows = filtered.map((asset) =>
      columns.map((column) => escape(asset[column])).join(",")
    );
    const csv = [columns.join(","), ...rows].join("\r\n");
    const blobUrl = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8;" })
    );
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = "soc-cloud-assets.csv";
    link.click();
    URL.revokeObjectURL(blobUrl);
  }

  const selectClass = inputClass;

  return (
    <div className="space-y-6 text-gray-200">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Asset Management / Cloud Assets
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Cloud Asset Inventory</h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-500">
            Register and manage cloud resources in the SOC asset inventory.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={onBack}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/30">
            ← Overview
          </button>
          <button onClick={loadAssets}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/30">
            Refresh
          </button>
          <button onClick={exportCsv}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/30">
            Export CSV
          </button>
          <button onClick={startCreate}
            className="rounded-md bg-red-600 px-3 py-2 text-xs font-semibold text-white hover:bg-red-500">
            + Add Cloud Asset
          </button>
        </div>
      </div>

      {error && <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">{error}</div>}
      {notice && <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">{notice}</div>}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {[
          ["Total Cloud Assets", assets.length],
          ["Active Resources", activeCount],
          ["Critical Resources", criticalCount],
        ].map(([label, value]) => (
          <div key={label} className="rounded-lg border border-white/10 bg-[#111519] p-4">
            <p className="text-xs text-gray-500">{label}</p>
            <p className="mt-2 text-2xl font-bold text-white">{value}</p>
          </div>
        ))}
      </div>

      {showForm && (
        <form onSubmit={saveAsset} className="space-y-4 rounded-lg border border-white/10 bg-[#111519] p-5">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">
              {editing !== null ? "Edit Cloud Asset" : "Register Cloud Asset"}
            </h2>
            <button type="button" onClick={() => setShowForm(false)} className="text-sm text-gray-400 hover:text-white">Close</button>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            <Field label="Resource Name *">
              <input required maxLength={200} className={inputClass} value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Cloud Provider *">
              <select className={selectClass} value={form.provider}
                onChange={(e) => setForm({ ...form, provider: e.target.value })}>
                {["AWS", "Microsoft Azure", "Google Cloud", "Other"].map((v) => <option key={v}>{v}</option>)}
              </select>
            </Field>
            <Field label="Resource Type *">
              <select className={selectClass} value={form.resource_type}
                onChange={(e) => setForm({ ...form, resource_type: e.target.value })}>
                {["Virtual Machine", "Storage", "Database", "Network", "Kubernetes", "Serverless Function", "Other"].map((v) => <option key={v}>{v}</option>)}
              </select>
            </Field>
            <Field label="Resource ID">
              <input maxLength={255} className={inputClass} value={form.resource_id}
                onChange={(e) => setForm({ ...form, resource_id: e.target.value })} />
            </Field>
            <Field label="Region">
              <input maxLength={100} className={inputClass} placeholder="e.g. ap-south-1"
                value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} />
            </Field>
            <Field label="Environment">
              <select className={selectClass} value={form.environment}
                onChange={(e) => setForm({ ...form, environment: e.target.value })}>
                {["Production", "Staging", "Development", "Testing", "Other"].map((v) => <option key={v}>{v}</option>)}
              </select>
            </Field>
            <Field label="IP Address">
              <input maxLength={100} className={inputClass} value={form.ip_address}
                onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />
            </Field>
            <Field label="Resource URL">
              <input type="url" maxLength={2048} className={inputClass} placeholder="https://..."
                value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} />
            </Field>
            <Field label="Hostname">
              <input maxLength={255} className={inputClass} value={form.hostname}
                onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
            </Field>
            <Field label="Owner / Team">
              <input maxLength={200} className={inputClass} value={form.owner}
                onChange={(e) => setForm({ ...form, owner: e.target.value })} />
            </Field>
            <Field label="Status">
              <select className={selectClass} value={form.status}
                onChange={(e) => setForm({ ...form, status: e.target.value })}>
                {["Active", "Inactive", "Maintenance", "Retired"].map((v) => <option key={v}>{v}</option>)}
              </select>
            </Field>
            <Field label="Criticality">
              <select className={selectClass} value={form.criticality}
                onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
                {["Low", "Medium", "High", "Critical"].map((v) => <option key={v}>{v}</option>)}
              </select>
            </Field>
            <div className="md:col-span-2 lg:col-span-3">
              <Field label="Notes">
                <textarea rows={3} className={inputClass} value={form.notes}
                  onChange={(e) => setForm({ ...form, notes: e.target.value })} />
              </Field>
            </div>
          </div>
          <div className="flex gap-2">
            <button disabled={saving} className="rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">
              {saving ? "Saving..." : editing !== null ? "Save Changes" : "Register Cloud Asset"}
            </button>
            <button type="button" onClick={() => setShowForm(false)}
              className="rounded-md border border-white/10 px-4 py-2 text-sm text-gray-300">Cancel</button>
          </div>
        </form>
      )}

      <div className="flex flex-wrap gap-3 rounded-lg border border-white/10 bg-[#111519] p-4">
        <input className={`${inputClass} min-w-[220px] flex-1`} placeholder="Search name, provider, region, resource ID..."
          value={query} onChange={(e) => setQuery(e.target.value)} />
        <select className="rounded-md border border-white/10 bg-[#090c0f] px-3 py-2 text-sm text-white"
          value={providerFilter} onChange={(e) => setProviderFilter(e.target.value)}>
          {["All", "AWS", "Microsoft Azure", "Google Cloud", "Other"].map((v) => <option key={v}>{v}</option>)}
        </select>
        <select className="rounded-md border border-white/10 bg-[#090c0f] px-3 py-2 text-sm text-white"
          value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          {["All", "Active", "Inactive", "Maintenance", "Retired"].map((v) => <option key={v}>{v}</option>)}
        </select>
        <select className="rounded-md border border-white/10 bg-[#090c0f] px-3 py-2 text-sm text-white"
          value={criticalityFilter} onChange={(e) => setCriticalityFilter(e.target.value)}>
          {["All", "Low", "Medium", "High", "Critical"].map((v) => <option key={v}>{v}</option>)}
        </select>
      </div>

      <div className="overflow-hidden rounded-lg border border-white/10 bg-[#111519]">
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <h2 className="font-semibold text-white">Registered Cloud Assets</h2>
          <span className="text-xs text-gray-500">{filtered.length} records</span>
        </div>
        {loading ? <p className="p-6 text-sm text-gray-400">Loading cloud assets...</p> :
          filtered.length === 0 ? (
            <div className="p-10 text-center">
              <p className="font-medium text-white">No cloud assets found</p>
              <p className="mt-2 text-sm text-gray-500">Register an authorized cloud resource to populate this inventory.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1050px] text-left text-sm">
                <thead className="bg-white/[0.03] text-xs uppercase text-gray-500">
                  <tr>{["Resource", "Provider / Type", "Region / ID", "Environment", "Status", "Criticality", "Owner", "Actions"].map((h) => <th key={h} className="px-4 py-3 font-medium">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filtered.map((asset) => (
                    <tr key={asset.id} className="hover:bg-white/[0.02]">
                      <td className="px-4 py-4">
                        <p className="font-medium text-white">{asset.name}</p>
                        <p className="mt-1 text-xs text-gray-500">{asset.url || asset.ip_address || asset.hostname || "No endpoint provided"}</p>
                      </td>
                      <td className="px-4 py-4">
                        <p className="text-gray-200">{asset.provider}</p>
                        <p className="mt-1 text-xs text-gray-500">{asset.resource_type}</p>
                      </td>
                      <td className="px-4 py-4">
                        <p className="text-gray-300">{asset.region || "—"}</p>
                        <p className="mt-1 text-xs text-gray-500">{asset.resource_id || "No resource ID"}</p>
                      </td>
                      <td className="px-4 py-4 text-gray-300">{asset.environment}</td>
                      <td className="px-4 py-4"><span className={`rounded-full border px-2 py-1 text-xs ${badgeClass(asset.status)}`}>{asset.status}</span></td>
                      <td className="px-4 py-4"><span className={`rounded-full border px-2 py-1 text-xs ${badgeClass(asset.criticality)}`}>{asset.criticality}</span></td>
                      <td className="px-4 py-4 text-gray-300">{asset.owner || "—"}</td>
                      <td className="px-4 py-4">
                        <div className="flex gap-3">
                          <button onClick={() => startEdit(asset)} className="text-xs text-sky-300 hover:text-sky-200">Edit</button>
                          <button onClick={() => deleteAsset(asset)} className="text-xs text-red-300 hover:text-red-200">Delete</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </div>
      <p className="text-xs text-gray-600">
        Inventory only: this page does not connect to cloud provider accounts or perform cloud scans.
      </p>
    </div>
  );
}
