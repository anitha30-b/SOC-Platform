
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API = SOC_DEPLOY_API_BASE;

const colors = {
  CRITICAL: "bg-red-600",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
  LOW: "bg-green-600",
  NONE: "bg-gray-500",
  COMPLETED: "bg-green-600",
  FAILED: "bg-red-600",
  RUNNING: "bg-blue-600",
  QUEUED: "bg-yellow-500",
};

function StatCard({ title, value, subtitle }) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
      <p className="text-sm text-slate-400">{title}</p>
      <p className="mt-2 text-3xl font-bold text-white">{value ?? "—"}</p>
      {subtitle && <p className="mt-2 text-xs text-slate-500">{subtitle}</p>}
    </div>
  );
}

function Distribution({ title, data }) {
  const entries = Object.entries(data || {});
  const total = entries.reduce((sum, [, value]) => sum + Number(value || 0), 0);

  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
      <h3 className="mb-4 font-semibold text-white">{title}</h3>
      {entries.length === 0 || total === 0 ? (
        <p className="text-sm text-slate-500">No recorded data available.</p>
      ) : (
        <div className="space-y-4">
          {entries.map(([name, value]) => (
            <div key={name}>
              <div className="mb-1 flex justify-between text-sm">
                <span className="text-slate-300">
                  {name.replaceAll("_", " ")}
                </span>
                <span className="font-medium text-white">{value}</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-slate-700">
                <div
                  className={`h-full rounded-full ${
                    colors[name.toUpperCase()] || "bg-cyan-500"
                  }`}
                  style={{
                    width: `${Math.min((Number(value) / total) * 100, 100)}%`,
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function Badge({ value }) {
  const status = String(value || "UNKNOWN").toUpperCase();
  const style = {
    CRITICAL: "bg-red-500/20 text-red-400",
    HIGH: "bg-orange-500/20 text-orange-400",
    MEDIUM: "bg-yellow-500/20 text-yellow-400",
    LOW: "bg-green-500/20 text-green-400",
    COMPLETED: "bg-green-500/20 text-green-400",
    FAILED: "bg-red-500/20 text-red-400",
    RUNNING: "bg-blue-500/20 text-blue-400",
    QUEUED: "bg-yellow-500/20 text-yellow-400",
  };

  return (
    <span
      className={`rounded-full px-3 py-1 text-xs font-semibold ${
        style[status] || "bg-slate-700 text-slate-300"
      }`}
    >
      {status.replaceAll("_", " ")}
    </span>
  );
}

export default function AdminRiskOverview() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const loadData = useCallback(async (manual = false) => {
    const token = localStorage.getItem("token");

    if (!token) {
      setError("Administrator login token not found. Please log in again.");
      setLoading(false);
      return;
    }

    if (manual) setRefreshing(true);
    else setLoading(true);

    try {
      const response = await axios.get(
        `${API}/admin/risk-overview/summary`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setData(response.data);
      setError("");
    } catch (err) {
      if (err.response?.status === 401) {
        setError("Session expired. Please log in again.");
      } else if (err.response?.status === 403) {
        setError("Administrator access is required.");
      } else {
        setError(
          err.response?.data?.detail || "Unable to load risk overview data."
        );
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const timer = setInterval(() => loadData(true), 30000);
    return () => clearInterval(timer);
  }, [loadData]);

  if (loading) {
    return (
      <div className="p-8 text-center text-slate-300">
        Loading Risk Overview...
      </div>
    );
  }

  const cvss = data?.cvss || {};

  return (
    <div className="min-h-screen space-y-6 bg-slate-950 p-6 text-white">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Risk Overview</h1>
          <p className="mt-1 text-sm text-slate-400">
            Organisation-wide risk assessment and vulnerability indicators
          </p>
        </div>
        <button
          onClick={() => loadData(true)}
          disabled={refreshing}
          className="rounded-lg border border-slate-600 px-4 py-2 text-sm hover:bg-slate-800 disabled:opacity-50"
        >
          {refreshing ? "Refreshing..." : "Refresh Data"}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
          <button
            onClick={() => loadData(true)}
            className="ml-3 underline"
          >
            Retry
          </button>
        </div>
      )}

      {data && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              title="Total Risk Assessments"
              value={data.total_assessments}
              subtitle="Stored assessment runs"
            />
            <StatCard
              title="Total Security Findings"
              value={data.total_findings}
              subtitle="Recorded vulnerability findings"
            />
            <StatCard
              title="Average CVSS"
              value={cvss.average ?? "N/A"}
              subtitle={`${cvss.scored_findings || 0} findings with CVSS scores`}
            />
            <StatCard
              title="Highest CVSS"
              value={cvss.highest ?? "N/A"}
              subtitle="Highest recorded score"
            />
          </div>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
            <Distribution
              title="Risk Distribution"
              data={data.risk_distribution}
            />
            <Distribution
              title="Finding Severity Distribution"
              data={data.severity_distribution}
            />
            <Distribution
              title="Assessment Status"
              data={data.assessment_statuses}
            />
            <Distribution
              title="Finding Status"
              data={data.finding_statuses}
            />
          </div>

          <section className="rounded-xl border border-slate-700 bg-slate-900 p-5">
            <h2 className="mb-4 text-lg font-semibold">
              Validation Summary
            </h2>
            {Object.keys(data.validation_summary || {}).length === 0 ? (
              <p className="text-sm text-slate-500">
                No numeric validation summary data is recorded.
              </p>
            ) : (
              <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                {Object.entries(data.validation_summary).map(([key, value]) => (
                  <div key={key} className="rounded-lg bg-slate-800 p-4">
                    <p className="text-xs text-slate-400">
                      {key.replaceAll("_", " ")}
                    </p>
                    <p className="mt-2 text-xl font-bold">{value}</p>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900">
            <div className="border-b border-slate-700 p-5">
              <h2 className="text-lg font-semibold">
                Recent Risk Assessments
              </h2>
              <p className="mt-1 text-xs text-slate-400">
                Latest 10 stored assessment runs
              </p>
            </div>

            {data.recent_assessments?.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-800 text-slate-400">
                    <tr>
                      <th className="p-4">Assessment ID</th>
                      <th className="p-4">Status</th>
                      <th className="p-4">Overall Risk</th>
                      <th className="p-4">Findings</th>
                      <th className="p-4">Average CVSS</th>
                      <th className="p-4">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_assessments.map((run) => (
                      <tr key={run.id} className="border-t border-slate-800">
                        <td className="p-4">{run.assessment_id}</td>
                        <td className="p-4"><Badge value={run.status} /></td>
                        <td className="p-4">
                          <Badge value={run.overall_risk} />
                        </td>
                        <td className="p-4">{run.total_findings ?? 0}</td>
                        <td className="p-4">{run.average_cvss ?? "—"}</td>
                        <td className="p-4 text-slate-400">
                          {formatDate(run.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="p-6 text-sm text-slate-500">
                No risk assessment runs have been recorded yet.
              </p>
            )}
          </section>

          <p className="text-xs text-slate-500">
            Risk indicators are calculated from stored security findings and
            assessment records. Missing CVSS values are shown as unavailable,
            not as zero risk.
          </p>
        </>
      )}
    </div>
  );
}
