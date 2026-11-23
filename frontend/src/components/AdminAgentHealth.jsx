
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API_URL = SOC_DEPLOY_API_BASE;

const EMPTY_FORM = {
  name: "",
  hostname: "",
  operating_system: "Windows",
  agent_version: "",
  notes: "",
};

export default function AdminAgentHealth({ onBack }) {
  const [data, setData] = useState({
    agents: [],
    total: 0,
    online: 0,
    offline: 0,
    never_connected: 0,
  });
  const [form, setForm] = useState(EMPTY_FORM);
  const [search, setSearch] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [newCredential, setNewCredential] = useState(null);

  const getHeaders = () => {
    const token = localStorage.getItem("token");
    return token ? { Authorization: `Bearer ${token}` } : null;
  };

  const refresh = useCallback(async () => {
    const headers = getHeaders();

    if (!headers) {
      setError("Admin session token is missing. Please log in again.");
      return;
    }

    setLoading(true);
    try {
      const response = await axios.get(`${API_URL}/agent-health`, {
        headers,
        timeout: 15000,
      });
      setData(response.data);
      setError("");
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Unable to load agent inventory. Check the backend and permissions."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const registerAgent = async (event) => {
    event.preventDefault();
    const headers = getHeaders();

    if (!headers) {
      setError("Please log in again.");
      return;
    }

    setSaving(true);
    setError("");
    setSuccess("");

    try {
      const response = await axios.post(
        `${API_URL}/agent-health/register`,
        {
          ...form,
          agent_version: form.agent_version || null,
          notes: form.notes || null,
        },
        { headers, timeout: 15000 }
      );

      setNewCredential(response.data);
      setForm(EMPTY_FORM);
      setShowForm(false);
      setSuccess("Agent registered. Save its credential securely.");
      await refresh();
    } catch (err) {
      setError(
        err.response?.data?.detail || "Unable to register agent."
      );
    } finally {
      setSaving(false);
    }
  };

  const statusStyle = (status) => {
    if (status === "ONLINE") {
      return "border-green-500/30 bg-green-500/10 text-green-400";
    }
    if (status === "OFFLINE") {
      return "border-red-500/30 bg-red-500/10 text-red-400";
    }
    return "border-yellow-500/30 bg-yellow-500/10 text-yellow-400";
  };

  const filtered = (data.agents || []).filter((agent) =>
    [
      agent.name,
      agent.hostname,
      agent.operating_system,
      agent.status,
    ]
      .join(" ")
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  const downloadCSV = () => {
    const columns = [
      "id",
      "name",
      "hostname",
      "operating_system",
      "agent_version",
      "status",
      "last_seen",
      "registered_at",
    ];
    const quote = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;
    const rows = [
      columns.join(","),
      ...filtered.map((agent) =>
        columns.map((column) => quote(agent[column])).join(",")
      ),
    ];
    const blob = new Blob([rows.join("\r\n")], {
      type: "text/csv;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "soc-agent-health.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Administration
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Agent Health</h1>
          <p className="mt-2 text-xs text-gray-500">
            Registered endpoint agents and their actual heartbeat status.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => {
              setShowForm((value) => !value);
              setError("");
            }}
            className="rounded-md bg-red-600 px-4 py-2 text-xs text-white"
          >
            + Register Agent
          </button>
          <button
            onClick={refresh}
            disabled={loading}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 disabled:opacity-50"
          >
            {loading ? "Refreshing..." : "↻ Refresh"}
          </button>
          <button
            onClick={onBack}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-400 hover:text-white"
          >
            ← Overview
          </button>
        </div>
      </header>

      {error && (
        <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {String(error)}
        </div>
      )}

      {success && (
        <div className="rounded-lg border border-green-500/30 bg-green-500/10 p-4 text-sm text-green-300">
          {success}
        </div>
      )}

      {newCredential && (
        <section className="rounded-xl border border-yellow-500/30 bg-yellow-500/5 p-5">
          <h2 className="font-semibold text-yellow-300">
            Save this agent credential now
          </h2>
          <p className="mt-2 text-xs leading-5 text-gray-400">
            This credential is shown only at registration. Copy it to a secure
            secret store; do not share it or put it in source control.
          </p>
          <div className="mt-4 break-all rounded-md bg-black/30 p-3 font-mono text-xs text-gray-200">
            Agent ID: {newCredential.agent.id}
            {"\n"}Agent Key: {newCredential.agent_key}
          </div>
          <button
            onClick={() =>
              navigator.clipboard.writeText(
                JSON.stringify(
                  {
                    agent_id: newCredential.agent.id,
                    agent_key: newCredential.agent_key,
                  },
                  null,
                  2
                )
              )
            }
            className="mt-3 rounded-md border border-white/10 px-3 py-2 text-xs text-white"
          >
            Copy credentials
          </button>
          <button
            onClick={() => setNewCredential(null)}
            className="ml-2 mt-3 rounded-md border border-white/10 px-3 py-2 text-xs text-gray-400"
          >
            Close
          </button>
        </section>
      )}

      {showForm && (
        <form
          onSubmit={registerAgent}
          className="rounded-xl border border-white/10 bg-white/[0.03] p-5"
        >
          <h2 className="mb-4 text-sm font-semibold text-white">
            Register a real agent
          </h2>
          <div className="grid gap-4 md:grid-cols-2">
            {[
              ["name", "Agent name", "e.g. Security Workstation"],
              ["hostname", "Hostname", "Actual machine hostname"],
              ["operating_system", "Operating system", "e.g. Windows 11"],
              ["agent_version", "Agent version (optional)", "e.g. 1.0.0"],
            ].map(([key, label, placeholder]) => (
              <label key={key} className="text-xs text-gray-400">
                {label}
                <input
                  required={key !== "agent_version"}
                  maxLength={key === "name" ? 150 : key === "hostname" ? 255 : 100}
                  value={form[key]}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      [key]: event.target.value,
                    }))
                  }
                  placeholder={placeholder}
                  className="mt-2 w-full rounded-md border border-white/10 bg-black/30 px-3 py-2 text-sm text-white outline-none focus:border-red-500/50"
                />
              </label>
            ))}
          </div>
          <label className="mt-4 block text-xs text-gray-400">
            Notes (optional)
            <textarea
              value={form.notes}
              maxLength={2000}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  notes: event.target.value,
                }))
              }
              className="mt-2 w-full rounded-md border border-white/10 bg-black/30 px-3 py-2 text-sm text-white"
              rows={2}
            />
          </label>
          <div className="mt-4 flex gap-2">
            <button
              disabled={saving}
              className="rounded-md bg-red-600 px-4 py-2 text-xs text-white disabled:opacity-50"
            >
              {saving ? "Registering..." : "Register Agent"}
            </button>
            <button
              type="button"
              onClick={() => setShowForm(false)}
              className="rounded-md border border-white/10 px-4 py-2 text-xs text-gray-400"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          ["Registered Agents", data.total || 0],
          ["Online", data.online || 0],
          ["Offline", data.offline || 0],
          ["Never Connected", data.never_connected || 0],
        ].map(([label, value]) => (
          <div key={label} className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <p className="text-xs text-gray-500">{label}</p>
            <p className="mt-3 text-2xl font-semibold text-white">{value}</p>
          </div>
        ))}
      </section>

      <section className="overflow-hidden rounded-xl border border-white/10 bg-white/[0.03]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-4">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search name, hostname, OS or status..."
            className="min-w-[220px] flex-1 rounded-md border border-white/10 bg-black/30 px-3 py-2 text-xs text-white outline-none"
          />
          <button
            onClick={downloadCSV}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300"
          >
            Export CSV
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-black/20 text-gray-500">
              <tr>
                {["Agent", "Hostname", "Operating System", "Last Seen", "Status"].map((heading) => (
                  <th key={heading} className="px-4 py-3 font-medium">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filtered.map((agent) => (
                <tr key={agent.id} className="text-gray-300">
                  <td className="px-4 py-4">
                    <div className="font-medium text-white">{agent.name}</div>
                    <div className="mt-1 text-gray-500">ID: {agent.id}</div>
                  </td>
                  <td className="px-4 py-4">{agent.hostname}</td>
                  <td className="px-4 py-4">{agent.operating_system}</td>
                  <td className="px-4 py-4">
                    {agent.last_seen ? new Date(agent.last_seen + "Z").toLocaleString() : "Never"}
                  </td>
                  <td className="px-4 py-4">
                    <span className={`rounded-md border px-2 py-1 font-semibold ${statusStyle(agent.status)}`}>
                      {agent.status}
                    </span>
                  </td>
                </tr>
              ))}
              {!filtered.length && (
                <tr>
                  <td colSpan="5" className="px-4 py-10 text-center text-gray-500">
                    No registered agents found. Register an actual endpoint to begin monitoring.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="border-t border-white/10 px-4 py-3 text-xs text-gray-500">
          Showing {filtered.length} of {data.total || 0} registered agents. Refresh interval: 5 seconds.
        </div>
      </section>
    </div>
  );
}
