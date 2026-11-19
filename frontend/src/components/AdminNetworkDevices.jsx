import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000/assets";

const EMPTY = {
  name: "",
  asset_type: "Network Device",
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
  if (value === "Critical" || value === "Inactive" || value === "Retired") {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }
  if (value === "High") {
    return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  }
  if (value === "Active" || value === "Low") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }
  return "border-white/10 bg-white/5 text-gray-300";
}

export default function AdminNetworkDevices({ onBack }) {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [criticalityFilter, setCriticalityFilter] = useState("All");
  const [form, setForm] = useState(EMPTY);
  const [editing, setEditing] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [reachability, setReachability] = useState({});
  const [checkingReachability, setCheckingReachability] = useState({});
  const [reachabilityPort, setReachabilityPort] = useState("443");
  const [healthFilter, setHealthFilter] = useState("All");

  const loadDevices = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await axios.get(API, authConfig());
      const all = response.data.assets || [];
      setAssets(all.filter((a) =>
        String(a.asset_type || "").toLowerCase() === "network device"
      ));
    } catch (err) {
      setError(
        err.response?.status === 401 || err.response?.status === 403
          ? "Authorization failed. Sign in with an authorized administrator account."
          : err.response?.data?.detail ||
            "Cannot load network devices. Check the backend and database."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    const loadPageData = async () => {
      await loadDevices();
      try {
        const response = await axios.get(
          `${API}/reachability/latest`,
          authConfig()
        );

        if (cancelled) return;

        const savedResults = response.data.results || [];
        const restored = {};

        savedResults.forEach((result) => {
          restored[result.asset_id] = result;
        });

        setReachability((previous) => ({ ...restored, ...previous }));
      } catch (err) {
        if (!cancelled) {
          console.error("Could not load saved reachability results:", err);
        }
      }
    };

    loadPageData();

    return () => {
      cancelled = true;
    };
  }, [loadDevices]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return assets.filter((a) => {
      const text = [
        a.name, a.ip_address, a.hostname, a.environment,
        a.status, a.criticality, a.owner, a.notes
      ].filter(Boolean).join(" ").toLowerCase();

      const health = reachability[a.id]?.status;
      const healthMatches =
        healthFilter === "All" ||
        (healthFilter === "Reachable" && health === "reachable") ||
        (healthFilter === "Unreachable" && health === "unreachable") ||
        (healthFilter === "Not Checked" && !health);

      return text.includes(q) &&
        (statusFilter === "All" || a.status === statusFilter) &&
        (criticalityFilter === "All" || a.criticality === criticalityFilter) &&
        healthMatches;
    });
  }, [assets, query, statusFilter, criticalityFilter, healthFilter, reachability]);

  const active = assets.filter((a) => a.status === "Active").length;
  const critical = assets.filter((a) => a.criticality === "Critical").length;
  const inactive = assets.filter((a) => a.status !== "Active").length;
  const reachableCount = assets.filter(
    (a) => reachability[a.id]?.status === "reachable"
  ).length;
  const unreachableCount = assets.filter(
    (a) => reachability[a.id]?.status === "unreachable"
  ).length;
  const uncheckedCount = assets.filter(
    (a) => !reachability[a.id]?.status
  ).length;


  function openCreate() {
    setEditing(null);
    setForm({ ...EMPTY });
    setError("");
    setShowForm(true);
  }

  function openEdit(asset) {
    setEditing(asset.id);
    setForm({ ...EMPTY, ...asset });
    setError("");
    setShowForm(true);
  }

  async function saveDevice(event) {
    event.preventDefault();
    if (!form.name.trim()) {
      setError("Device name is required.");
      return;
    }

    setSaving(true);
    setError("");

    try {
      const payload = Object.fromEntries(
        Object.entries({ ...form, asset_type: "Network Device" })
          .map(([key, value]) => [
            key,
            typeof value === "string" ? value.trim() : value
          ])
      );

      if (editing) {
        await axios.put(`${API}/${editing}`, payload, authConfig());
      } else {
        await axios.post(API, payload, authConfig());
      }

      setShowForm(false);
      await loadDevices();
    } catch (err) {
      setError(err.response?.data?.detail || "Unable to save this device.");
    } finally {
      setSaving(false);
    }
  }

  async function deleteDevice(device) {
    if (!window.confirm(
      `Delete "${device.name}" from the asset inventory? This cannot be undone.`
    )) return;

    setError("");
    try {
      await axios.delete(`${API}/${device.id}`, authConfig());
      await loadDevices();
    } catch (err) {
      setError(err.response?.data?.detail || "Unable to delete this device.");
    }
  }

  async function checkReachability(device) {
    setCheckingReachability((previous) => ({
      ...previous,
      [device.id]: true,
    }));

    const selectedPort = Number(reachabilityPort);

    if (!Number.isInteger(selectedPort) || selectedPort < 1 || selectedPort > 65535) {
      setReachability((previous) => ({
        ...previous,
        [device.id]: {
          port: selectedPort,
          status: "error",
          port: selectedPort,
          reason: "Enter a valid TCP port between 1 and 65535.",
        },
      }));
      setCheckingReachability((previous) => ({
        ...previous,
        [device.id]: false,
      }));
      return;
    }

    setReachability((previous) => ({
      ...previous,
      [device.id]: { status: "checking", port: selectedPort },
    }));

    try {
      const response = await axios.get(
        `${API}/${device.id}/reachability`,
        {
          ...authConfig(),
          params: { port: selectedPort, timeout: 2 },
        }
      );

      setReachability((previous) => ({
        ...previous,
        [device.id]: { ...response.data, port: selectedPort },
      }));
    } catch (err) {
      setReachability((previous) => ({
        ...previous,
        [device.id]: {
          status: "error",
          reason:
            err.response?.data?.detail ||
            err.message ||
            "Reachability check failed",
        },
      }));
    } finally {
      setCheckingReachability((previous) => ({
        ...previous,
        [device.id]: false,
      }));
    }
  }

  function exportCSV() {
    const columns = [
      "id", "name", "asset_type", "ip_address", "hostname",
      "environment", "status", "criticality", "owner", "notes"
    ];
    const cell = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;
    const csv = "\uFEFF" + [
      columns.join(","),
      ...filtered.map((device) =>
        columns.map((column) => cell(device[column])).join(",")
      )
    ].join("\r\n");

    const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8;" })
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "soc-network-devices.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  const stats = [
    { label: "TOTAL DEVICES", value: assets.length, mark: "▦" },
    { label: "ACTIVE DEVICES", value: active, mark: "●" },
    { label: "CRITICAL DEVICES", value: critical, mark: "!" },
    { label: "INACTIVE / OTHER", value: inactive, mark: "◷" },
  ];

  const labelClass = "mb-1.5 block text-xs font-medium text-gray-400";

  return (
    <section className="space-y-6 text-white">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-[0.25em] text-red-400">
            <span className="h-px w-7 bg-red-500" />
            Asset Management / Network Devices
          </div>
          <h1 className="text-3xl font-bold tracking-tight">Network Devices</h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-500">
            Centralized inventory of registered routers, switches, firewalls,
            access points, and other network infrastructure.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {onBack && (
            <button onClick={onBack}
              className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/30">
              ← Overview
            </button>
          )}
          <button onClick={loadDevices}
            className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-red-500">
            ↻ Refresh
          </button>
          <button onClick={exportCSV}
            className="rounded-md border border-white/10 px-3 py-2 text-xs hover:border-red-500">
            ↓ Export CSV
          </button>
          <button onClick={openCreate}
            className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700">
            + Add Device
          </button>
        </div>
      </header>

      {error && (
        <div role="alert"
          className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => (
          <div key={stat.label}
            className="rounded-lg border border-white/10 bg-[#0b0e11] p-5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold tracking-[0.15em] text-gray-500">
                {stat.label}
              </span>
              <span className="flex h-8 w-8 items-center justify-center rounded-md border border-red-500/20 bg-red-500/10 text-sm text-red-400">
                {stat.mark}
              </span>
            </div>
            <div className="mt-4 text-3xl font-bold tabular-nums">
              {loading ? "—" : stat.value}
            </div>
            <div className="mt-2 text-[11px] text-gray-600">
              Registered database records
            </div>
          </div>
        ))}
      </div>

      {showForm && (
        <form onSubmit={saveDevice}
          className="space-y-4 rounded-lg border border-white/10 bg-[#0b0e11] p-5">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">
              {editing ? "Edit Network Device" : "Register Network Device"}
            </h2>
            <button type="button" onClick={() => setShowForm(false)}
              className="text-sm text-gray-400 hover:text-white">
              Cancel
            </button>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <label>
              <span className={labelClass}>Device name *</span>
              <input required maxLength={200} className={inputClass}
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Core Router 01" />
            </label>
            <label>
              <span className={labelClass}>IP address</span>
              <input className={inputClass} value={form.ip_address || ""}
                onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
                placeholder="192.168.1.1" />
            </label>
            <label>
              <span className={labelClass}>Hostname</span>
              <input className={inputClass} value={form.hostname || ""}
                onChange={(e) => setForm({ ...form, hostname: e.target.value })}
                placeholder="router01.local" />
            </label>
            <label>
              <span className={labelClass}>Environment</span>
              <select className={inputClass} value={form.environment}
                onChange={(e) => setForm({ ...form, environment: e.target.value })}>
                {["Production", "Staging", "Development", "Testing", "Lab"].map((v) =>
                  <option key={v}>{v}</option>
                )}
              </select>
            </label>
            <label>
              <span className={labelClass}>Status</span>
              <select className={inputClass} value={form.status}
                onChange={(e) => setForm({ ...form, status: e.target.value })}>
                {["Active", "Inactive", "Maintenance", "Retired"].map((v) =>
                  <option key={v}>{v}</option>
                )}
              </select>
            </label>
            <label>
              <span className={labelClass}>Criticality</span>
              <select className={inputClass} value={form.criticality}
                onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
                {["Critical", "High", "Medium", "Low"].map((v) =>
                  <option key={v}>{v}</option>
                )}
              </select>
            </label>
            <label>
              <span className={labelClass}>Owner / team</span>
              <input className={inputClass} value={form.owner || ""}
                onChange={(e) => setForm({ ...form, owner: e.target.value })}
                placeholder="Network Operations" />
            </label>
            <label className="sm:col-span-2">
              <span className={labelClass}>Notes</span>
              <input className={inputClass} value={form.notes || ""}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
                placeholder="Model, location, purpose, or authorized scope" />
            </label>
          </div>

          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setShowForm(false)}
              className="rounded-md border border-white/10 px-4 py-2 text-sm text-gray-300">
              Cancel
            </button>
            <button type="submit" disabled={saving}
              className="rounded-md bg-red-600 px-5 py-2 text-sm font-semibold disabled:opacity-50">
              {saving ? "Saving..." : editing ? "Save Changes" : "Register Device"}
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <button onClick={() => setHealthFilter("Reachable")}
          className="rounded-lg border border-emerald-500/20 bg-[#0b0e11] p-4 text-left hover:border-emerald-500/50">
          <p className="text-xs text-gray-400">Reachable</p>
          <p className="mt-2 text-2xl font-semibold text-emerald-400">{reachableCount}</p>
        </button>
        <button onClick={() => setHealthFilter("Unreachable")}
          className="rounded-lg border border-red-500/20 bg-[#0b0e11] p-4 text-left hover:border-red-500/50">
          <p className="text-xs text-gray-400">Unreachable</p>
          <p className="mt-2 text-2xl font-semibold text-red-400">{unreachableCount}</p>
        </button>
        <button onClick={() => setHealthFilter("Not Checked")}
          className="rounded-lg border border-white/10 bg-[#0b0e11] p-4 text-left hover:border-white/30">
          <p className="text-xs text-gray-400">Not Checked</p>
          <p className="mt-2 text-2xl font-semibold text-gray-200">{uncheckedCount}</p>
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-white/10 bg-[#0b0e11] p-4">
        <input className={`${inputClass} min-w-[200px] flex-1`}
          value={query} onChange={(e) => setQuery(e.target.value)}
          placeholder="Search name, IP, hostname, owner..." />
        <select className={`${inputClass} sm:w-44`} value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}>
          {["All", "Active", "Inactive", "Maintenance", "Retired"].map((v) =>
            <option key={v}>{v}</option>
          )}
        </select>
        <select className={`${inputClass} sm:w-44`} value={criticalityFilter}
          onChange={(e) => setCriticalityFilter(e.target.value)}>
          {["All", "Critical", "High", "Medium", "Low"].map((v) =>
            <option key={v}>{v}</option>
          )}
        </select>
        <select
          className={`${inputClass} sm:w-44`}
          value={healthFilter}
          onChange={(e) => setHealthFilter(e.target.value)}
          aria-label="Filter by reachability"
        >
          {["All", "Reachable", "Unreachable", "Not Checked"].map((v) =>
            <option key={v}>{v}</option>
          )}
        </select>
        <span className="text-xs text-gray-500">
          {filtered.length} of {assets.length} devices
        </span>
      </div>

      <div className="overflow-hidden rounded-lg border border-white/10 bg-[#0b0e11]">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 px-5 py-4">
          <h2 className="font-semibold">Registered Network Inventory</h2>
          <span className="text-[11px] text-gray-500">Asset database</span>
        </div>
        {loading ? (
          <div className="p-10 text-center text-sm text-gray-500">Loading network devices...</div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center">
            <div className="text-3xl text-gray-700">⌁</div>
            <p className="mt-3 text-sm text-gray-300">No network devices found</p>
            <p className="mt-1 text-xs text-gray-500">
              Add a device or change the search and filter settings.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="bg-white/[0.025] text-[10px] uppercase tracking-wider text-gray-500">
                <tr>
                  <th className="px-5 py-3">Device</th>
                  <th className="px-4 py-3">IP / Hostname</th>
                  <th className="px-4 py-3">Environment</th>
                  <th className="px-4 py-3">Criticality</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {filtered.map((device) => (
                  <tr key={device.id} className="transition hover:bg-white/[0.02]">
                    <td className="px-5 py-4">
                      <div className="font-medium text-gray-100">{device.name}</div>
                      <div className="mt-1 text-xs text-gray-500">
                        ID #{device.id} · {device.owner || "Unassigned"}
                      </div>
                    </td>
                    <td className="px-4 py-4">
                      <div className="font-mono text-xs text-gray-200">
                        {device.ip_address || "No IP recorded"}
                      </div>
                      <div className="mt-1 text-xs text-gray-500">
                        {device.hostname || "No hostname"}
                      </div>
                      {reachability[device.id] && (
                        <div className="mt-2 text-xs">
                          <span className={
                            reachability[device.id].status === "reachable"
                              ? "text-emerald-400"
                              : reachability[device.id].status === "checking"
                                ? "text-amber-300"
                                : "text-red-300"
                          }>
                            TCP/{reachability[device.id].port ?? reachabilityPort}: {reachability[device.id].status}
                          </span>
                          {reachability[device.id].duration_ms != null && (
                            <span className="ml-2 text-gray-500">
                              {reachability[device.id].duration_ms} ms
                            </span>
                          )}
                          {reachability[device.id].checked_at && (
                            <div className="mt-1 text-gray-500">
                              Checked: {new Date(
                                reachability[device.id].checked_at
                              ).toLocaleString()}
                            </div>
                          )}
                          {reachability[device.id].reason && (
                            <div className="mt-1 max-w-xs break-words text-gray-500">
                              {reachability[device.id].reason}
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-4 text-xs text-gray-400">
                      {device.environment || "—"}
                    </td>
                    <td className="px-4 py-4">
                      <span className={`rounded-full border px-2.5 py-1 text-[10px] font-medium ${badgeClass(device.criticality)}`}>
                        {device.criticality || "Medium"}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <span className={`rounded-full border px-2.5 py-1 text-[10px] font-medium ${badgeClass(device.status)}`}>
                        {device.status || "Unknown"}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex flex-wrap justify-end gap-2">
                        <select
                          value={reachabilityPort}
                          onChange={(e) => setReachabilityPort(e.target.value)}
                          aria-label="Select TCP port"
                          className="rounded border border-white/10 bg-slate-900 px-2 py-1.5 text-xs text-white"
                        >
                          <option value="22">22 — SSH</option>
                          <option value="80">80 — HTTP</option>
                          <option value="443">443 — HTTPS</option>
                        </select>
                        <input
                          type="number"
                          min="1"
                          max="65535"
                          value={reachabilityPort}
                          onChange={(e) => setReachabilityPort(e.target.value)}
                          aria-label="Custom TCP port"
                          title="Enter a TCP port from 1 to 65535"
                          className="w-20 rounded border border-white/10 bg-slate-900 px-2 py-1.5 text-xs text-white"
                        />
                        <button
                          onClick={() => checkReachability(device)}
                          disabled={Boolean(checkingReachability[device.id])}
                          className="rounded border border-emerald-500/30 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
                        >
                          {checkingReachability[device.id]
                            ? "Checking..."
                            : "Check Reachability"}
                        </button>
                        <button onClick={() => openEdit(device)}
                          className="rounded border border-white/10 px-3 py-1.5 text-xs hover:border-red-500">
                          Edit
                        </button>
                        <button onClick={() => deleteDevice(device)}
                          className="rounded border border-red-500/20 px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/10">
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <p className="text-[11px] text-gray-600">
        Inventory records show registered devices; they do not by themselves confirm live network reachability.
      </p>
    </section>
  );
}
