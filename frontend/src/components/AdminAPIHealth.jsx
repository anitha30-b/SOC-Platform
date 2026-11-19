import { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

export default function AdminAPIHealth({ onBack }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token) {
      setError("Session token missing. Please log in again.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await axios.get(`${API_URL}/system/health`, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 15000,
      });
      setData(response.data);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Unable to retrieve API health. Check the backend and permissions."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(() => {
      refresh();
    }, 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const api = data?.api;
  const db = data?.database;
  const listener = data?.postgres_event_listener;

  const items = [
    {
      name: "API Service",
      status: api?.status,
      message: api?.message,
    },
    {
      name: "Database Connectivity",
      status: db?.status,
      message: db?.message,
      latency: db?.latency_ms,
    },
    {
      name: "PostgreSQL Event Listener",
      status: listener?.status,
      message: listener?.message,
    },
  ];

  const badge = (status) => {
    const value = String(status || "UNKNOWN").toUpperCase();
    const color =
      value === "HEALTHY"
        ? "border-green-500/30 bg-green-500/10 text-green-400"
        : value === "WARNING"
        ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
        : "border-red-500/30 bg-red-500/10 text-red-400";

    return (
      <span className={`rounded-md border px-3 py-1 text-xs font-semibold ${color}`}>
        {value}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Administration
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">API Health</h1>
          <p className="mt-2 text-xs text-gray-500">
            API availability and supporting service connectivity.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={refresh}
            disabled={loading}
            className="rounded-md bg-red-600 px-4 py-2 text-xs text-white disabled:opacity-50"
          >
            {loading ? "Checking..." : "↻ Refresh"}
          </button>
          <button
            onClick={onBack}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-400 hover:text-white"
          >
            ← Overview
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {loading && !data && (
        <p className="rounded-lg border border-white/10 p-6 text-sm text-gray-400">
          Checking API health...
        </p>
      )}

      {data && (
        <>
          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs text-gray-500">Overall platform status</p>
                <h2 className="mt-2 text-xl font-semibold text-white">
                  {data.service || "SOC Platform"}
                </h2>
              </div>
              {badge(data.status)}
            </div>
            <p className="mt-4 text-xs text-gray-500">
              Last checked: {data.checked_at ? new Date(data.checked_at).toLocaleString() : "—"}
            </p>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            {items.map((item) => (
              <div key={item.name} className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h3 className="text-sm font-semibold text-white">{item.name}</h3>
                  {badge(item.status)}
                </div>
                <p className="mt-4 text-sm leading-6 text-gray-400">
                  {item.message || "No status information available."}
                </p>
                {item.latency !== undefined && (
                  <p className="mt-3 text-xs text-gray-500">
                    Connection latency: {item.latency} ms
                  </p>
                )}
              </div>
            ))}
          </div>

          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <h2 className="text-sm font-semibold text-white">API Health Details</h2>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <div>
                <p className="text-xs text-gray-500">Health endpoint</p>
                <p className="mt-1 text-sm text-gray-200">GET /system/health</p>
              </div>
              <div>
                <p className="text-xs text-gray-500">Response received</p>
                <p className="mt-1 text-sm text-gray-200">
                  {data.checked_at ? "Yes" : "Unknown"}
                </p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
