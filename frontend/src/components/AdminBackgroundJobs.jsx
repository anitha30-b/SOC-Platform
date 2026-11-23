
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useCallback, useEffect, useState } from "react";

const API_URL = SOC_DEPLOY_API_BASE;

export default function AdminBackgroundJobs({ onBack }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("ALL");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem("token");
      const response = await fetch(`${API_URL}/background-jobs`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        throw new Error(
          response.status === 401 || response.status === 403
            ? "Admin authentication failed. Sign in again."
            : `Request failed (${response.status})`
        );
      }
      setData(await response.json());
      setError("");
    } catch (e) {
      setError(e.message || "Unable to load background jobs.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const jobs = (data?.jobs || []).filter(
    (job) => filter === "ALL" || job.status === filter
  );

  const card = (label, value) => (
    <div key={label} className="rounded-xl border border-white/10 bg-[#0b0f12] p-5">
      <p className="text-sm text-gray-400">{label}</p>
      <p className="mt-3 text-3xl font-semibold text-white">{value ?? 0}</p>
    </div>
  );

  const statusClass = (status) => {
    if (status === "RUNNING") return "text-blue-400";
    if (status === "QUEUED") return "text-yellow-400";
    if (status === "FAILED") return "text-red-400";
    if (status.startsWith("COMPLETED")) return "text-green-400";
    return "text-gray-400";
  };

  const exportCsv = () => {
    const fields = [
      "job_id", "tool", "target", "scan_type", "status",
      "progress", "stage", "created_at", "updated_at",
      "duration_seconds", "error",
    ];
    const quote = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;
    const csv = [
      fields.join(","),
      ...(data?.jobs || []).map((job) =>
        fields.map((field) => quote(job[field])).join(",")
      ),
    ].join("\r\n");
    const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8;" })
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = "background-jobs.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-red-500">
            Administration
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Background Jobs</h1>
          <p className="mt-2 text-sm text-gray-400">
            Live status of jobs in the existing VAPT job stores.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={refresh} className="rounded-lg border border-white/15 px-4 py-2 text-sm text-gray-300">
            {loading ? "Refreshing…" : "↻ Refresh"}
          </button>
          <button onClick={exportCsv} className="rounded-lg border border-white/15 px-4 py-2 text-sm text-gray-300">
            Export CSV
          </button>
          <button onClick={onBack} className="rounded-lg border border-white/15 px-4 py-2 text-sm text-gray-300">
            ← Overview
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 xl:grid-cols-5">
        {card("Total Jobs", data?.total)}
        {card("Queued", data?.queued)}
        {card("Running", data?.running)}
        {card("Completed", data?.completed)}
        {card("Failed", data?.failed)}
      </div>

      <div className="overflow-hidden rounded-xl border border-white/10 bg-[#0b0f12]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-4">
          <h2 className="font-semibold text-white">Execution History</h2>
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="rounded-lg border border-white/15 bg-[#101519] px-3 py-2 text-sm text-white"
          >
            {["ALL", "QUEUED", "RUNNING", "COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"].map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1000px] text-left text-sm">
            <thead className="text-gray-400">
              <tr>
                {["Tool / Job ID", "Target", "Status", "Progress", "Stage", "Created", "Updated", "Duration", "Error"].map((heading) => (
                  <th key={heading} className="border-b border-white/10 px-4 py-3 font-medium">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={`${job.tool}-${job.job_id}`} className="border-b border-white/5 align-top">
                  <td className="px-4 py-4">
                    <div className="font-semibold text-white">{job.tool}</div>
                    <div className="mt-1 max-w-40 break-all text-xs text-gray-500">{job.job_id}</div>
                  </td>
                  <td className="max-w-48 break-all px-4 py-4 text-gray-300">{job.target || "—"}</td>
                  <td className={`px-4 py-4 font-semibold ${statusClass(job.status)}`}>{job.status}</td>
                  <td className="px-4 py-4 text-gray-300">{job.progress ?? 0}%</td>
                  <td className="px-4 py-4 text-gray-300">{job.stage || "—"}</td>
                  <td className="px-4 py-4 text-gray-400">{job.created_at ? new Date(job.created_at).toLocaleString() : "—"}</td>
                  <td className="px-4 py-4 text-gray-400">{job.updated_at ? new Date(job.updated_at).toLocaleString() : "—"}</td>
                  <td className="px-4 py-4 text-gray-300">{job.duration_seconds == null ? "—" : `${job.duration_seconds}s`}</td>
                  <td className="max-w-56 break-words px-4 py-4 text-red-300">{job.error || "—"}</td>
                </tr>
              ))}
              {!jobs.length && (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center text-gray-500">
                    {error ? "Job data unavailable." : "No jobs currently present in memory."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="border-t border-white/10 px-4 py-3 text-xs text-gray-500">
          Auto-refresh: 5 seconds · Source: {data?.source || "VAPT job stores"}
          {data?.checked_at && ` · Checked ${new Date(data.checked_at).toLocaleTimeString()}`}
        </div>
      </div>
      <p className="text-xs text-gray-500">
        This page reads existing job records only. Job history is in memory and may be lost when the backend restarts.
      </p>
    </div>
  );
}
