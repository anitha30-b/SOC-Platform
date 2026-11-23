
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useCallback, useEffect, useState } from "react";

const API = SOC_DEPLOY_API_BASE;

const frameworkMenus = [
  { name: "ISO 27001", menu: "admin-iso27001" },
  { name: "SOC 2", menu: "admin-soc2" },
  { name: "NIST CSF", menu: "admin-nist" },
  { name: "CIS Controls", menu: "admin-cis" },
  { name: "PCI DSS", menu: "admin-pcidss" },
];

const stats = [
  { key: "total_controls", label: "Total Controls" },
  { key: "compliant", label: "Compliant" },
  { key: "open_gaps", label: "Open Gaps" },
  { key: "not_assessed", label: "Not Assessed" },
];

export default function AdminComplianceDashboard({ onBack, onNavigate }) {
  const [data, setData] = useState(null);
  const [frameworks, setFrameworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError("");

    const token = localStorage.getItem("token");
    if (!token) {
      setError("Admin session missing. Please sign in again.");
      setLoading(false);
      return;
    }

    const headers = { Authorization: `Bearer ${token}` };

    try {
      const [dashboardResponse, frameworkResponse] = await Promise.all([
        fetch(`${API}/compliance/dashboard`, { headers }),
        fetch(`${API}/compliance/frameworks`, { headers }),
      ]);

      const dashboardData = await dashboardResponse.json().catch(() => ({}));
      const frameworkData = await frameworkResponse.json().catch(() => ({}));

      if (!dashboardResponse.ok) {
        throw new Error(
          dashboardData.detail || `Dashboard request failed (${dashboardResponse.status}).`
        );
      }
      if (!frameworkResponse.ok) {
        throw new Error(
          frameworkData.detail || `Framework request failed (${frameworkResponse.status}).`
        );
      }

      setData(dashboardData);
      setFrameworks(frameworkData.frameworks || []);
    } catch (err) {
      setError(err.message || "Unable to connect to the Compliance API.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  const frameworkStats = Object.fromEntries(
    frameworks.map((item) => [item.framework, item])
  );

  return (
    <div className="space-y-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Security Governance
          </p>
          <h1 className="mt-2 text-2xl font-bold">Compliance Dashboard</h1>
          <p className="mt-2 text-sm text-gray-400">
            Assess controls, monitor compliance gaps, and track security frameworks.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={loadDashboard}
            disabled={loading}
            className="rounded-md border border-white/15 px-4 py-2 text-xs hover:border-red-500 disabled:opacity-50"
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <button
            onClick={onBack}
            className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700"
          >
            ← Overview
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-950/40 p-4 text-sm text-red-300">
          {error}
          <p className="mt-1 text-xs text-gray-400">
            Check that the backend is running and your admin session is valid.
          </p>
        </div>
      )}

      {loading && !data ? (
        <div className="rounded-xl border border-white/10 bg-[#111111] p-8 text-sm text-gray-400">
          Loading compliance data...
        </div>
      ) : data ? (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {stats.map((item) => (
              <div
                key={item.key}
                className="rounded-xl border border-white/10 bg-[#111111] p-5"
              >
                <p className="text-xs text-gray-400">{item.label}</p>
                <p className="mt-3 text-3xl font-bold">
                  {data[item.key] ?? 0}
                </p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="rounded-xl border border-white/10 bg-[#111111] p-5 lg:col-span-2">
              <div className="flex items-center justify-between gap-3">
                <h2 className="font-semibold">Overall Compliance</h2>
                <span className="text-xl font-bold text-red-500">
                  {data.compliance_percentage ?? 0}%
                </span>
              </div>
              <div className="mt-4 h-3 overflow-hidden rounded-full bg-white/10">
                <div
                  className="h-full rounded-full bg-red-600 transition-all"
                  style={{
                    width: `${Math.min(100, Math.max(0, Number(data.compliance_percentage) || 0))}%`,
                  }}
                />
              </div>
              <p className="mt-3 text-xs text-gray-400">
                {data.assessed ?? 0} assessed controls out of{" "}
                {(data.total_controls ?? 0) - (data.not_applicable ?? 0)} applicable controls.
              </p>
              <p className="mt-2 text-xs text-gray-500">
                This is an internal assessment metric, not a certification result.
              </p>
            </div>

            <div className="rounded-xl border border-white/10 bg-[#111111] p-5">
              <h2 className="font-semibold">Assessment Status</h2>
              <div className="mt-4 space-y-4">
                {[
                  ["Partially Compliant", data.partially_compliant, "bg-amber-500"],
                  ["Non-Compliant", data.non_compliant, "bg-red-600"],
                  ["Not Applicable", data.not_applicable, "bg-gray-500"],
                ].map(([label, value, color]) => (
                  <div key={label}>
                    <div className="mb-1 flex justify-between gap-3 text-xs">
                      <span className="text-gray-400">{label}</span>
                      <span>{value ?? 0}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-white/10">
                      <div
                        className={`h-1.5 rounded-full ${color}`}
                        style={{
                          width: `${Math.min(
                            100,
                            (Number(value || 0) / Math.max(1, Number(data.total_controls || 0))) * 100
                          )}%`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-[#111111] p-5">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="font-semibold">Compliance Frameworks</h2>
                <p className="mt-1 text-xs text-gray-400">
                  Select a framework to assess its controls.
                </p>
              </div>
              <span className="text-xs text-gray-400">
                {frameworkMenus.length} frameworks
              </span>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {frameworkMenus.map((framework) => {
                const item = frameworkStats[framework.name] || {};
                const total = Number(item.total || 0);
                const compliant = Number(item.compliant || 0);
                const percent = total ? Math.round((compliant / total) * 100) : 0;

                return (
                  <button
                    key={framework.menu}
                    onClick={() => onNavigate?.(framework.menu)}
                    className="rounded-lg border border-white/10 bg-black/30 p-4 text-left transition hover:border-red-500/60"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold">{framework.name}</span>
                      <span className="text-xs text-red-400">Open →</span>
                    </div>
                    <div className="mt-4 flex justify-between text-xs text-gray-400">
                      <span>{total} controls</span>
                      <span>{percent}% compliant</span>
                    </div>
                    <div className="mt-2 h-1.5 rounded-full bg-white/10">
                      <div
                        className="h-1.5 rounded-full bg-red-600"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
