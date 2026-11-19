import { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";

function StatCard({ title, value, subtitle, color = "text-white" }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
      <p className="text-sm text-gray-400">{title}</p>
      <p className={`mt-3 text-3xl font-bold ${color}`}>{value ?? 0}</p>
      {subtitle && <p className="mt-2 text-xs text-gray-500">{subtitle}</p>}
    </div>
  );
}

function Badge({ value }) {
  const status = String(value || "UNKNOWN").toUpperCase();

  const styles = {
    CRITICAL: "bg-red-500/10 text-red-400 border-red-500/30",
    HIGH: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    MEDIUM: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    LOW: "bg-green-500/10 text-green-400 border-green-500/30",
    OPEN: "bg-red-500/10 text-red-400 border-red-500/30",
    IN_PROGRESS: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    FIXED: "bg-green-500/10 text-green-400 border-green-500/30",
    ACCEPTED: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    COMPLETED: "bg-green-500/10 text-green-400 border-green-500/30",
    RUNNING: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    FAILED: "bg-red-500/10 text-red-400 border-red-500/30",
  };

  return (
    <span className={`inline-block rounded-md border px-2.5 py-1 text-xs font-semibold ${
      styles[status] || "border-white/10 bg-white/5 text-gray-400"
    }`}>
      {status.replaceAll("_", " ")}
    </span>
  );
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function Distribution({ title, items, colors }) {
  const total = Object.values(items || {}).reduce(
    (sum, value) => sum + Number(value || 0), 0
  );

  return (
    <section className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
      <h2 className="mb-5 text-sm font-semibold">{title}</h2>
      <div className="space-y-4">
        {Object.entries(items || {}).map(([key, value]) => {
          const percentage = total ? (Number(value) / total) * 100 : 0;

          return (
            <div key={key}>
              <div className="mb-2 flex justify-between text-sm">
                <span className="capitalize text-gray-300">
                  {key.replaceAll("_", " ")}
                </span>
                <span className="text-gray-400">{value}</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-white/10">
                <div
                  className={`h-full rounded-full ${colors[key] || "bg-gray-400"}`}
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default function AdminSecurityPosture() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadData = useCallback(async (manual = false) => {
    const token = localStorage.getItem("token");

    if (!token) {
      setError("Session token missing. Please log in again.");
      setLoading(false);
      return;
    }

    if (manual) setRefreshing(true);
    else setLoading(true);

    setError("");

    try {
      const response = await axios.get(
        `${API}/admin/security-posture/summary`,
        {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 20000,
        }
      );

      setData(response.data);
      setLastUpdated(new Date());
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        setError("Administrator authentication failed. Please log in with an admin account.");
      } else {
        setError(err.response?.data?.detail || "Unable to load Security Posture data.");
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const timer = setInterval(() => loadData(), 30000);
    return () => clearInterval(timer);
  }, [loadData]);

  if (loading && !data) {
    return (
      <div className="p-8 text-center text-gray-400">
        Loading Security Posture...
      </div>
    );
  }

  const severity = data?.severity || {};
  const status = data?.status || {};
  const risks = data?.risk_levels || {};

  return (
    <div className="space-y-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Overview / Security
          </p>
          <h1 className="mt-2 text-2xl font-bold">Security Posture</h1>
          <p className="mt-2 text-sm text-gray-400">
            Organisation-wide vulnerability and security risk overview.
          </p>
          <p className="mt-2 text-xs text-gray-500">
            Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "Not available"}
            {" · "}Automatic refresh every 30 seconds
          </p>
        </div>

        <button
          type="button"
          onClick={() => loadData(true)}
          disabled={refreshing}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium hover:bg-red-700 disabled:opacity-50"
        >
          {refreshing ? "Refreshing..." : "↻ Refresh"}
        </button>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm text-yellow-300">
          {error}
        </div>
      )}

      {data && (
        <>
          <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard title="Total Findings" value={data.total_findings} subtitle="All recorded security findings" />
            <StatCard title="Critical Vulnerabilities" value={severity.critical} color="text-red-400" subtitle="Require immediate attention" />
            <StatCard title="High Vulnerabilities" value={severity.high} color="text-orange-400" subtitle="High-priority findings" />
            <StatCard title="Affected Assets" value={data.affected_assets} subtitle="Unique affected assets recorded" />
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold">Vulnerability Severity</h2>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
              <StatCard title="Critical" value={severity.critical} color="text-red-400" />
              <StatCard title="High" value={severity.high} color="text-orange-400" />
              <StatCard title="Medium" value={severity.medium} color="text-yellow-400" />
              <StatCard title="Low" value={severity.low} color="text-green-400" />
              <StatCard title="None" value={severity.none} color="text-gray-400" />
            </div>
          </section>

          <section className="grid gap-4 lg:grid-cols-2">
            <Distribution
              title="Risk Level Distribution"
              items={risks}
              colors={{
                level_1: "bg-red-500",
                level_2: "bg-yellow-500",
                level_3: "bg-green-500",
              }}
            />
            <Distribution
              title="Finding Status Distribution"
              items={status}
              colors={{
                open: "bg-red-500",
                in_progress: "bg-yellow-500",
                fixed: "bg-green-500",
                accepted: "bg-blue-500",
                false_positive: "bg-gray-500",
              }}
            />
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold">CVSS Risk Metrics</h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <StatCard title="Average CVSS Score" value={data.cvss?.average ?? 0} subtitle="Average of recorded CVSS scores" />
              <StatCard title="Highest CVSS Score" value={data.cvss?.highest ?? 0} color="text-red-400" subtitle="Highest recorded CVSS score" />
            </div>
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold">Recent Security Findings</h2>
            <div className="overflow-x-auto rounded-xl border border-white/10">
              <table className="w-full min-w-[850px] text-left text-sm">
                <thead className="bg-white/[0.04] text-xs text-gray-400">
                  <tr>
                    <th className="p-3">Finding ID</th>
                    <th className="p-3">Title</th>
                    <th className="p-3">Severity</th>
                    <th className="p-3">CVSS</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Tool</th>
                    <th className="p-3">Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_findings?.length ? data.recent_findings.map((finding) => (
                    <tr key={finding.finding_id} className="border-t border-white/10">
                      <td className="p-3 text-gray-400">{finding.finding_id}</td>
                      <td className="max-w-xs p-3">{finding.title}</td>
                      <td className="p-3"><Badge value={finding.severity} /></td>
                      <td className="p-3">{finding.cvss_score ?? "—"}</td>
                      <td className="p-3"><Badge value={finding.status} /></td>
                      <td className="p-3 text-gray-400">{finding.tool_name}</td>
                      <td className="p-3 text-gray-400">{formatDate(finding.created_at)}</td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan="7" className="p-6 text-center text-gray-500">
                        No security findings recorded yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold">Recent Risk Assessments</h2>
            <div className="overflow-x-auto rounded-xl border border-white/10">
              <table className="w-full min-w-[650px] text-left text-sm">
                <thead className="bg-white/[0.04] text-xs text-gray-400">
                  <tr>
                    <th className="p-3">Assessment ID</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Total Findings</th>
                    <th className="p-3">Average CVSS</th>
                    <th className="p-3">Highest CVSS</th>
                    <th className="p-3">Overall Risk</th>
                    <th className="p-3">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_assessments?.length ? data.recent_assessments.map((run, index) => (
                    <tr key={`${run.assessment_id}-${index}`} className="border-t border-white/10">
                      <td className="p-3">{run.assessment_id}</td>
                      <td className="p-3"><Badge value={run.status} /></td>
                      <td className="p-3">{run.total_findings}</td>
                      <td className="p-3">{run.average_cvss}</td>
                      <td className="p-3">{run.highest_cvss}</td>
                      <td className="p-3"><Badge value={run.overall_risk} /></td>
                      <td className="p-3 text-gray-400">{formatDate(run.created_at)}</td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan="7" className="p-6 text-center text-gray-500">
                        No risk assessment history available.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      <p className="text-xs text-gray-500">
        Statistics are calculated from stored security findings and risk assessment records.
        No synthetic security score is generated.
      </p>
    </div>
  );
}
