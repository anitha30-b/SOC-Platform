import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000/assets";

const EMPTY = {
  name: "",
  asset_type: "Application",
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

function authConfig() {
  const token = localStorage.getItem("token");
  return { headers: token ? { Authorization: `Bearer ${token}` } : {} };
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

export default function AdminApplications({ onBack }) {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [criticalityFilter, setCriticalityFilter] = useState("All");
  const [form, setForm] = useState(EMPTY);
  const [editing, setEditing] = useState(null);
  const [showForm, setShowForm] = useState(false);

  const loadApplications = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await axios.get(API, authConfig());
      setAssets(
        (response.data.assets || []).filter(
          (asset) =>
            String(asset.asset_type || "").toLowerCase() === "application"
        )
      );
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Could not load applications. Check your backend and administrator login."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadApplications();
  }, [loadApplications]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return assets.filter((asset) => {
      const searchable = [
        asset.name,
        asset.url,
        asset.hostname,
        asset.environment,
        asset.owner,
        asset.status,
        asset.criticality,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return (
        searchable.includes(q) &&
        (statusFilter === "All" || asset.status === statusFilter) &&
        (criticalityFilter === "All" ||
          asset.criticality === criticalityFilter)
      );
    });
  }, [assets, query, statusFilter, criticalityFilter]);

  const activeCount = assets.filter((a) => a.status === "Active").length;
  const criticalCount = assets.filter(
    (a) => a.criticality === "Critical"
  ).length;

  function startCreate() {
    setForm({ ...EMPTY });
    setEditing(null);
    setShowForm(true);
    setError("");
    setNotice("");
  }

  function startEdit(asset) {
    setForm({
      ...EMPTY,
      ...asset,
      ip_address: asset.ip_address || "",
      hostname: asset.hostname || "",
      url: asset.url || "",
      owner: asset.owner || "",
      notes: asset.notes || "",
    });
    setEditing(asset.id);
    setShowForm(true);
    setError("");
    setNotice("");
  }

  async function saveApplication(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");

    const payload = {
      ...form,
      asset_type: "Application",
      ip_address: form.ip_address.trim() || null,
      hostname: form.hostname.trim() || null,
      url: form.url.trim() || null,
      owner: form.owner.trim() || null,
      notes: form.notes.trim() || null,
    };

    try {
      if (editing !== null) {
        await axios.put(`${API}/${editing}`, payload, authConfig());
        setNotice("Application updated successfully.");
      } else {
        await axios.post(API, payload, authConfig());
        setNotice("Application registered successfully.");
      }
      setShowForm(false);
      setEditing(null);
      setForm({ ...EMPTY });
      await loadApplications();
    } catch (err) {
      setError(
        err.response?.data?.detail || "Could not save the application."
      );
    } finally {
      setSaving(false);
    }
  }

  async function deleteApplication(asset) {
    if (
      !window.confirm(
        `Delete application "${asset.name}" from the asset inventory?`
      )
    ) {
      return;
    }

    setError("");
    setNotice("");
    try {
      await axios.delete(`${API}/${asset.id}`, authConfig());
      setNotice("Application deleted.");
      await loadApplications();
    } catch (err) {
      setError(
        err.response?.data?.detail || "Could not delete the application."
      );
    }
  }

  function exportCsv() {
    const columns = [
      "id",
      "name",
      "url",
      "hostname",
      "environment",
      "status",
      "criticality",
      "owner",
      "notes",
      "created_at",
    ];
    const escape = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;
    const rows = filtered.map((asset) =>
      columns.map((column) => escape(asset[column])).join(",")
    );
    const csv = [columns.join(","), ...rows].join("\r\n");
    const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8;" })
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "soc-applications.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6 text-gray-200">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Asset Management / Applications
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">
            Application Inventory
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-500">
            Manage registered application assets using the SOC platform
            inventory.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={onBack}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/30"
          >
            ← Overview
          </button>
          <button
            onClick={loadApplications}
            className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-white/30"
          >
            Refresh
          </button>
          <button
            onClick={exportCsv}
            disabled={filtered.length === 0}
            className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-white/30 disabled:opacity-40"
          >
            Export CSV
          </button>
          <button
            onClick={startCreate}
            className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-500"
          >
            + Add Application
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {[
          ["Total Applications", assets.length],
          ["Active Applications", activeCount],
          ["Critical Applications", criticalCount],
        ].map(([label, value]) => (
          <div
            key={label}
            className="rounded-lg border border-white/10 bg-[#0b0e12] p-4"
          >
            <p className="text-xs text-gray-500">{label}</p>
            <p className="mt-2 text-2xl font-bold text-white">{value}</p>
          </div>
        ))}
      </div>

      {error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">
          {notice}
        </div>
      )}

      {showForm && (
        <form
          onSubmit={saveApplication}
          className="space-y-4 rounded-lg border border-white/10 bg-[#0b0e12] p-5"
        >
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-white">
              {editing !== null ? "Edit Application" : "Register Application"}
            </h2>
            <button
              type="button"
              onClick={() => setShowForm(false)}
              className="text-sm text-gray-400 hover:text-white"
            >
              Cancel
            </button>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <label className="space-y-1 text-xs text-gray-400">
              Application Name *
              <input
                required
                maxLength={200}
                className={inputClass}
                value={form.name}
                onChange={(e) =>
                  setForm({ ...form, name: e.target.value })
                }
                placeholder="Application name"
              />
            </label>

            <label className="space-y-1 text-xs text-gray-400">
              Application URL
              <input
                type="url"
                maxLength={2048}
                className={inputClass}
                value={form.url}
                onChange={(e) =>
                  setForm({ ...form, url: e.target.value })
                }
                placeholder="https://example.com"
              />
            </label>

            <label className="space-y-1 text-xs text-gray-400">
              Hostname
              <input
                maxLength={255}
                className={inputClass}
                value={form.hostname}
                onChange={(e) =>
                  setForm({ ...form, hostname: e.target.value })
                }
                placeholder="Optional hostname"
              />
            </label>

            <label className="space-y-1 text-xs text-gray-400">
              IP Address
              <input
                maxLength={100}
                className={inputClass}
                value={form.ip_address}
                onChange={(e) =>
                  setForm({ ...form, ip_address: e.target.value })
                }
                placeholder="Optional IP address"
              />
            </label>

            <label className="space-y-1 text-xs text-gray-400">
              Environment
              <select
                className={inputClass}
                value={form.environment}
                onChange={(e) =>
                  setForm({ ...form, environment: e.target.value })
                }
              >
                {["Production", "Staging", "Development", "Testing"].map(
                  (value) => (
                    <option key={value}>{value}</option>
                  )
                )}
              </select>
            </label>

            <label className="space-y-1 text-xs text-gray-400">
              Owner
              <input
                maxLength={200}
                className={inputClass}
                value={form.owner}
                onChange={(e) =>
                  setForm({ ...form, owner: e.target.value })
                }
                placeholder="Team or application owner"
              />
            </label>

            <label className="space-y-1 text-xs text-gray-400">
              Status
              <select
                className={inputClass}
                value={form.status}
                onChange={(e) =>
                  setForm({ ...form, status: e.target.value })
                }
              >
                {["Active", "Inactive", "Retired"].map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>

            <label className="space-y-1 text-xs text-gray-400">
              Criticality
              <select
                className={inputClass}
                value={form.criticality}
                onChange={(e) =>
                  setForm({ ...form, criticality: e.target.value })
                }
              >
                {["Low", "Medium", "High", "Critical"].map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>

            <label className="space-y-1 text-xs text-gray-400 md:col-span-2">
              Notes
              <textarea
                rows={3}
                className={inputClass}
                value={form.notes}
                onChange={(e) =>
                  setForm({ ...form, notes: e.target.value })
                }
                placeholder="Application purpose or additional notes"
              />
            </label>
          </div>

          <button
            type="submit"
            disabled={saving}
            className="rounded-md bg-red-600 px-5 py-2.5 text-sm font-semibold text-white disabled:opacity-50"
          >
            {saving ? "Saving..." : editing !== null ? "Save Changes" : "Register Application"}
          </button>
        </form>
      )}

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <input
          className={inputClass}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search name, URL, owner..."
        />
        <select
          className={inputClass}
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          {["All", "Active", "Inactive", "Retired"].map((value) => (
            <option key={value}>{value === "All" ? "All statuses" : value}</option>
          ))}
        </select>
        <select
          className={inputClass}
          value={criticalityFilter}
          onChange={(e) => setCriticalityFilter(e.target.value)}
        >
          {["All", "Low", "Medium", "High", "Critical"].map((value) => (
            <option key={value}>
              {value === "All" ? "All criticality levels" : value}
            </option>
          ))}
        </select>
      </div>

      <div className="overflow-x-auto rounded-lg border border-white/10 bg-[#0b0e12]">
        <div className="flex items-center justify-between border-b border-white/10 p-4">
          <h2 className="font-semibold text-white">Registered Applications</h2>
          <span className="text-xs text-gray-500">
            {filtered.length} record(s)
          </span>
        </div>

        {loading ? (
          <p className="p-8 text-center text-sm text-gray-500">
            Loading application inventory...
          </p>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm text-gray-300">No matching applications found.</p>
            <p className="mt-2 text-xs text-gray-500">
              Add an application or adjust your search and filters. No sample records are created automatically.
            </p>
          </div>
        ) : (
          <table className="w-full min-w-[900px] text-left text-xs">
            <thead className="border-b border-white/10 bg-white/[0.02] text-gray-500">
              <tr>
                {["Application", "URL / Host", "Environment", "Owner", "Criticality", "Status", "Actions"].map((heading) => (
                  <th key={heading} className="px-4 py-3 font-medium">
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((asset) => (
                <tr key={asset.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-4">
                    <p className="font-medium text-white">{asset.name}</p>
                    <p className="mt-1 text-[10px] text-gray-600">APP-{String(asset.id).padStart(4, "0")}</p>
                  </td>
                  <td className="max-w-[260px] px-4 py-4">
                    {asset.url ? (
                      <a
                        href={asset.url}
                        target="_blank"
                        rel="noreferrer"
                        className="break-all text-sky-400 hover:underline"
                      >
                        {asset.url}
                      </a>
                    ) : (
                      <span className="text-gray-600">No URL registered</span>
                    )}
                    {asset.hostname && (
                      <p className="mt-1 text-gray-500">{asset.hostname}</p>
                    )}
                    {asset.ip_address && (
                      <p className="mt-1 text-gray-500">{asset.ip_address}</p>
                    )}
                  </td>
                  <td className="px-4 py-4 text-gray-300">{asset.environment}</td>
                  <td className="px-4 py-4 text-gray-400">{asset.owner || "—"}</td>
                  <td className="px-4 py-4">
                    <span className={`rounded border px-2 py-1 ${badgeClass(asset.criticality)}`}>
                      {asset.criticality}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`rounded border px-2 py-1 ${badgeClass(asset.status)}`}>
                      {asset.status}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex gap-2">
                      <button onClick={() => startEdit(asset)} className="text-sky-400 hover:text-sky-300">
                        Edit
                      </button>
                      <button onClick={() => deleteApplication(asset)} className="text-red-400 hover:text-red-300">
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
