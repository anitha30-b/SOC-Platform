import { useCallback, useEffect, useState } from "react";

const API_URL = "http://127.0.0.1:8000";

export default function AdminSystemLogs({ onBack }) {
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [checkedAt, setCheckedAt] = useState("");

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const token = localStorage.getItem("token");

      if (!token) {
        throw new Error("Admin session not found. Please sign in again.");
      }

      const params = new URLSearchParams({
        search,
        status,
        limit: "1000",
      });

      const response = await fetch(
        `${API_URL}/system/logs?${params.toString()}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          throw new Error("Access denied. Sign in with an administrator account.");
        }
        throw new Error(`Unable to load logs (HTTP ${response.status}).`);
      }

      const data = await response.json();
      setLogs(Array.isArray(data.logs) ? data.logs : []);
      setCheckedAt(data.checked_at || "");
    } catch (err) {
      setError(err.message || "Unable to load system logs.");
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }, [search, status]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const formatTime = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  };

  const statusClass = (code) => {
    if (code >= 500) return "border-red-500/30 bg-red-500/10 text-red-400";
    if (code >= 400) return "border-amber-500/30 bg-amber-500/10 text-amber-300";
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
  };

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Administration
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">System Logs</h1>
          <p className="mt-2 text-xs text-gray-500">
            Review real SOC Platform API access records.
          </p>
        </div>

        <button
          type="button"
          onClick={onBack}
          className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-400 hover:text-white"
        >
          ← Overview
        </button>
      </div>

      <div className="rounded-xl border border-white/10 bg-[#0b0e12] p-4">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-semibold text-white">API Access Events</p>
            <p className="mt-1 text-xs text-gray-500">
              {logs.length} records shown
              {checkedAt ? ` · Refreshed ${formatTime(checkedAt)}` : ""}
            </p>
          </div>

          <button
            type="button"
            onClick={loadLogs}
            disabled={loading}
            className="rounded-md border border-red-500/30 px-3 py-2 text-xs text-red-400 hover:bg-red-500/10 disabled:opacity-50"
          >
            {loading ? "Refreshing…" : "↻ Refresh"}
          </button>
        </div>

        <div className="mb-4 flex flex-col gap-3 sm:flex-row">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search path, method, IP address, or status…"
            className="min-w-0 flex-1 rounded-md border border-white/10 bg-black/30 px-3 py-2 text-sm text-white outline-none focus:border-red-500/50"
          />

          <select
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            className="rounded-md border border-white/10 bg-[#101419] px-3 py-2 text-sm text-white outline-none"
          >
            <option value="all">All HTTP statuses</option>
            <option value="2xx">Success (2xx)</option>
            <option value="4xx">Client errors (4xx)</option>
            <option value="5xx">Server errors (5xx)</option>
          </select>
        </div>

        {error && (
          <div className="mb-4 rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full min-w-[850px] text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-[10px] uppercase tracking-wider text-gray-500">
                <th className="px-3 py-3">Timestamp</th>
                <th className="px-3 py-3">Request</th>
                <th className="px-3 py-3">Status</th>
                <th className="px-3 py-3">Duration</th>
                <th className="px-3 py-3">Client IP</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr
                  key={log.id}
                  className="border-b border-white/5 text-gray-300 hover:bg-white/[0.02]"
                >
                  <td className="whitespace-nowrap px-3 py-3 text-gray-400">
                    {formatTime(log.timestamp)}
                  </td>
                  <td className="px-3 py-3">
                    <span className="mr-2 text-red-400">{log.method}</span>
                    <span className="break-all">{log.path}</span>
                  </td>
                  <td className="px-3 py-3">
                    <span
                      className={`rounded border px-2 py-1 ${statusClass(log.status_code)}`}
                    >
                      {log.status_code}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-3">
                    {log.duration_ms} ms
                  </td>
                  <td className="px-3 py-3">{log.client_ip}</td>
                </tr>
              ))}

              {!loading && !error && logs.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-10 text-center text-gray-500">
                    No matching access logs found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
