
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API_URL = SOC_DEPLOY_API_BASE;

export default function AdminLogPipelineHealth({ onBack }) {
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
      const response = await axios.get(`${API_URL}/system/log-pipeline`, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 10000,
      });
      setData(response.data);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Unable to retrieve log pipeline health."
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

  const statusClass = (status) => {
    if (status === "HEALTHY") {
      return "border-green-500/30 bg-green-500/10 text-green-400";
    }
    if (status === "WARNING") {
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-400";
    }
    return "border-red-500/30 bg-red-500/10 text-red-400";
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Administration
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">
            Log Pipeline Health
          </h1>
          <p className="mt-2 text-xs text-gray-500">
            Status of the platform's existing log sources and event listener.
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

      {!data && loading && (
        <p className="rounded-xl border border-white/10 p-6 text-sm text-gray-400">
          Checking log sources...
        </p>
      )}

      {data && (
        <>
          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-xs text-gray-500">Overall pipeline status</p>
                <h2 className="mt-2 text-xl font-semibold text-white">
                  SOC Platform Log Pipeline
                </h2>
              </div>
              <span className={`rounded-md border px-3 py-1 text-xs font-semibold ${statusClass(data.status)}`}>
                {data.status}
              </span>
            </div>
            <p className="mt-4 text-xs text-gray-500">
              Last checked: {data.checked_at ? new Date(data.checked_at).toLocaleString() : "—"}
            </p>
          </section>

          <section className="grid gap-4 lg:grid-cols-3">
            {Object.entries(data.components || {}).map(([key, component]) => (
              <article key={key} className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h3 className="text-sm font-semibold text-white">
                    {key.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                  </h3>
                  <span className={`rounded-md border px-3 py-1 text-xs font-semibold ${statusClass(component.status)}`}>
                    {component.status}
                  </span>
                </div>
                <p className="mt-4 text-sm leading-6 text-gray-400">
                  {component.message}
                </p>
                {component.exists !== undefined && (
                  <p className="mt-3 text-xs text-gray-500">
                    File exists: {component.exists ? "Yes" : "No"} · Readable: {component.readable ? "Yes" : "No"}
                  </p>
                )}
              </article>
            ))}
          </section>
        </>
      )}
    </div>
  );
}
