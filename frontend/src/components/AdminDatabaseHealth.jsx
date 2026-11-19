import { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

export default function AdminDatabaseHealth({ onBack }) {
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
          "Unable to retrieve database health. Check backend availability and permissions."
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

  const db = data?.database;
  const status = String(db?.status || "UNKNOWN").toUpperCase();

  const statusClass =
    status === "HEALTHY"
      ? "border-green-500/30 bg-green-500/10 text-green-400"
      : status === "WARNING"
      ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
      : "border-red-500/30 bg-red-500/10 text-red-400";

  const formatDate = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Administration
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">
            Database Health
          </h1>
          <p className="mt-2 text-xs text-gray-500">
            PostgreSQL connectivity and connection response time.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            type="button"
            onClick={refresh}
            disabled={loading}
            className="rounded-md bg-red-600 px-4 py-2 text-xs text-white disabled:opacity-50"
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

      {!data && loading && (
        <div className="rounded-xl border border-white/10 p-6 text-sm text-gray-400">
          Checking database connectivity...
        </div>
      )}

      {data && (
        <>
          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-xs text-gray-500">Database service</p>
                <h2 className="mt-2 text-xl font-semibold text-white">
                  PostgreSQL
                </h2>
                <p className="mt-2 text-sm text-gray-400">
                  {db?.message || "No database status message available."}
                </p>
              </div>
              <span className={`rounded-md border px-3 py-1 text-xs font-semibold ${statusClass}`}>
                {status}
              </span>
            </div>
            <p className="mt-4 text-xs text-gray-500">
              Last checked: {formatDate(data.checked_at)}
            </p>
          </section>

          <section className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
              <p className="text-sm text-gray-400">Connection status</p>
              <p className="mt-3 text-2xl font-semibold text-white">
                {status === "HEALTHY" ? "Connected" : "Unavailable"}
              </p>
              <p className="mt-2 text-xs text-gray-500">
                Checked using a database query.
              </p>
            </div>

            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
              <p className="text-sm text-gray-400">Connection latency</p>
              <p className="mt-3 text-2xl font-semibold text-white">
                {db?.latency_ms !== undefined ? `${db.latency_ms} ms` : "—"}
              </p>
              <p className="mt-2 text-xs text-gray-500">
                Time taken for the health-check query.
              </p>
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <h2 className="text-sm font-semibold text-white">
              Database Check Details
            </h2>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <div>
                <p className="text-xs text-gray-500">Health endpoint</p>
                <p className="mt-1 text-sm text-gray-200">GET /system/health</p>
              </div>
              <div>
                <p className="text-xs text-gray-500">Check performed</p>
                <p className="mt-1 text-sm text-gray-200">SQL SELECT 1</p>
              </div>
            </div>
            <p className="mt-4 text-xs leading-5 text-gray-500">
              This check verifies database connectivity. It does not measure
              table-level integrity, replication lag, or database capacity.
            </p>
          </section>
        </>
      )}
    </div>
  );
}
