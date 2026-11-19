import { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

function statusStyle(status) {
  switch (String(status || "").toUpperCase()) {
    case "HEALTHY":
      return "border-green-500/30 bg-green-500/10 text-green-400";
    case "WARNING":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-400";
    case "CRITICAL":
      return "border-red-500/30 bg-red-500/10 text-red-400";
    default:
      return "border-white/10 bg-white/5 text-gray-400";
  }
}

function StatusBadge({ status }) {
  return (
    <span
      className={`inline-flex rounded-md border px-2.5 py-1 text-xs font-semibold ${statusStyle(status)}`}
    >
      {status || "UNKNOWN"}
    </span>
  );
}

function MetricCard({ title, value, unit = "%", status }) {
  const number = Number(value);
  const valid = Number.isFinite(number);
  const width = valid ? Math.max(0, Math.min(100, number)) : 0;

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm text-gray-400">{title}</p>
        {status && <StatusBadge status={status} />}
      </div>
      <p className="mt-4 text-3xl font-semibold text-white">
        {valid ? number : "—"}
        {valid && <span className="ml-1 text-sm text-gray-500">{unit}</span>}
      </p>
      <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/10">
        <div
          className="h-full rounded-full bg-red-500 transition-all"
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  );
}

function formatUptime(seconds) {
  if (!Number.isFinite(Number(seconds))) return "—";
  const total = Math.max(0, Math.floor(Number(seconds)));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function AdminSystemHealth({ onBack }) {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadHealth = useCallback(async () => {
    const token = localStorage.getItem("token");

    if (!token) {
      setError("Your session token is missing. Please log in again.");
      setLoading(false);
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await axios.get(`${API_URL}/system/health`, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 15000,
      });
      setHealth(response.data);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Unable to load system health. Check the backend and administrator access."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHealth();
    const timer = setInterval(() => {
      loadHealth();
    }, 5000);
    return () => clearInterval(timer);
  }, [loadHealth]);

  const resources = health?.resources;
  const components = [
    { title: "API Service", data: health?.api },
    { title: "PostgreSQL Database", data: health?.database },
    {
      title: "PostgreSQL Event Listener",
      data: health?.postgres_event_listener,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Administration
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">System Health</h1>
          <p className="mt-2 text-xs leading-5 text-gray-500">
            Live health and resource metrics from the SOC Platform backend.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            type="button"
            onClick={loadHealth}
            disabled={loading}
            className="rounded-md bg-red-600 px-4 py-2 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
          >
            {loading ? "Checking..." : "↻ Refresh"}
          </button>
          <button
            type="button"
            onClick={onBack}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-400 hover:text-white"
          >
            ← Overview
          </button>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
        >
          {error}
        </div>
      )}

      {loading && !health && (
        <div className="rounded-xl border border-white/10 p-8 text-center text-sm text-gray-400">
          Checking system health...
        </div>
      )}

      {health && (
        <>
          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-xs text-gray-500">Overall system status</p>
                <h2 className="mt-2 text-xl font-semibold text-white">
                  {health.service || "SOC Platform"}
                </h2>
              </div>
              <StatusBadge status={health.status} />
            </div>
            <p className="mt-4 text-xs text-gray-500">
              Last checked: {formatDate(health.checked_at)}
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold text-white">
              Resource Usage
            </h2>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              <MetricCard
                title="CPU Usage"
                value={resources?.cpu_usage_percent}
                status={resources?.status}
              />
              <MetricCard
                title="Memory Usage"
                value={resources?.memory_usage_percent}
                status={resources?.status}
              />
              <MetricCard
                title="Disk Usage"
                value={resources?.disk_usage_percent}
                status={resources?.status}
              />
            </div>
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold text-white">
              Core Components
            </h2>
            <div className="grid gap-3 lg:grid-cols-3">
              {components.map(({ title, data }) => (
                <div
                  key={title}
                  className="rounded-xl border border-white/10 bg-white/[0.03] p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-medium text-white">{title}</h3>
                    <StatusBadge status={data?.status} />
                  </div>
                  <p className="mt-3 text-xs leading-5 text-gray-400">
                    {data?.message || "No status information returned."}
                  </p>
                  {data?.latency_ms !== undefined && (
                    <p className="mt-3 text-xs text-gray-500">
                      Database latency: {data.latency_ms} ms
                    </p>
                  )}
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <h2 className="mb-4 text-sm font-semibold text-white">
              Host Information
            </h2>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {[
                ["Hostname", health.host?.hostname],
                ["Operating System", health.host?.operating_system],
                ["OS Version", health.host?.os_version],
                ["Architecture", health.host?.architecture],
                ["Uptime", formatUptime(health.host?.uptime_seconds)],
                [
                  "Memory",
                  resources
                    ? `${resources.memory_used_gb} / ${resources.memory_total_gb} GB`
                    : "—",
                ],
                [
                  "Disk",
                  resources
                    ? `${resources.disk_free_gb} GB free of ${resources.disk_total_gb} GB`
                    : "—",
                ],
              ].map(([label, value]) => (
                <div key={label}>
                  <p className="text-xs text-gray-500">{label}</p>
                  <p className="mt-1 break-words text-sm text-gray-200">
                    {value ?? "—"}
                  </p>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
