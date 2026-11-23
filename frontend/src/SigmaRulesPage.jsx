
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "./deploymentApi.js";
import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = SOC_DEPLOY_API_BASE;

export default function SigmaRulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [validation, setValidation] = useState("ALL");
  const [refreshKey, setRefreshKey] = useState(0);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [selected, setSelected] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadRules() {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Authentication token not found.");

        const response = await axios.get(`${API_URL}/sigma/rules`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (cancelled) return;
        if (!Array.isArray(response.data?.rules)) {
          throw new Error("Unexpected response from the Sigma rules API.");
        }

        setRules(response.data.rules);
        setLastUpdated(new Date());
        setError("");
      } catch (err) {
        if (!cancelled) {
          setError(
            err.response?.data?.detail ||
            err.message ||
            "Unable to load Sigma rules."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    }

    loadRules();
    const timer = window.setInterval(loadRules, 30000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [refreshKey]);

  const formatTime = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? "—"
      : `${date.toLocaleString("en-IN", {
          timeZone: "Asia/Kolkata",
          hour12: false,
        })} IST`;
  };

  async function openRule(ruleId) {
    setSelected(null);
    setDetailError("");
    setDetailLoading(true);

    try {
      const token = localStorage.getItem("token");
      if (!token) throw new Error("Authentication token not found.");

      const response = await axios.get(
        `${API_URL}/sigma/rules/${encodeURIComponent(ruleId)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      setSelected(response.data);
    } catch (err) {
      setDetailError(
        err.response?.data?.detail ||
        err.message ||
        "Unable to load rule details."
      );
    } finally {
      setDetailLoading(false);
    }
  }

  const visibleRules = rules.filter((rule) => {
    const text = [
      rule.rule_id,
      rule.title,
      rule.description,
      rule.filename,
      JSON.stringify(rule.logsource ?? {}),
      ...(Array.isArray(rule.tags) ? rule.tags : []),
    ].filter(Boolean).join(" ").toLowerCase();

    const matchesSearch = text.includes(search.trim().toLowerCase());
    const matchesSeverity =
      severity === "ALL" ||
      String(rule.level || "").toUpperCase() === severity;
    const matchesValidation =
      validation === "ALL" || rule.validation_status === validation;

    return matchesSearch && matchesSeverity && matchesValidation;
  });

  const validCount = rules.filter(
    (rule) => rule.validation_status === "VALID"
  ).length;
  const invalidCount = rules.filter(
    (rule) => rule.validation_status !== "VALID"
  ).length;

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Security Operations / Detection
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Sigma Rules</h1>
          <p className="mt-2 max-w-3xl text-xs leading-5 text-gray-500">
            Browse stored Sigma YAML rules, validation results, log-source
            metadata, tags, and rule source.
          </p>
          <p className="mt-2 text-[10px] text-gray-600">
            Last refresh: {formatTime(lastUpdated)} · Auto-refresh every 30 seconds
          </p>
        </div>
        <button
          type="button"
          disabled={refreshing}
          onClick={() => {
            setRefreshing(true);
            setRefreshKey((value) => value + 1);
          }}
          className="border border-white/10 px-4 py-2 text-xs text-gray-300 hover:border-red-500/40 hover:text-white disabled:opacity-50"
        >
          {refreshing ? "Refreshing..." : "Refresh rules"}
        </button>
      </header>

      <div className="border border-yellow-500/30 bg-yellow-500/5 p-4">
        <p className="text-xs font-semibold text-yellow-200">
          Library-only integration status
        </p>
        <p className="mt-2 text-xs leading-5 text-gray-400">
          These files are stored and structurally validated, but they are not
          currently executed by the live SIEM detection pipeline.
        </p>
        <div className="mt-3 flex flex-wrap gap-2 text-[10px]">
          <span className="border border-yellow-500/30 px-2 py-1 text-yellow-200">
            LIBRARY_ONLY
          </span>
          <span className="border border-white/10 px-2 py-1 text-gray-300">
            Live detection: Disabled
          </span>
        </div>
      </div>

      {error && (
        <div className="border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        {[
          ["Stored Sigma rules", rules.length],
          ["Structurally valid", validCount],
          ["Invalid / needs review", invalidCount],
        ].map(([label, value]) => (
          <div key={label} className="border border-white/10 bg-white/[0.02] p-4">
            <p className="text-[10px] uppercase tracking-wider text-gray-500">{label}</p>
            <p className="mt-3 text-2xl font-semibold tabular-nums text-white">{value}</p>
          </div>
        ))}
      </div>

      <section className="border border-white/10">
        <div className="flex flex-col gap-3 border-b border-white/10 p-4 lg:flex-row">
          <input
            type="search"
            aria-label="Search Sigma rules"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search title, ID, description, log source or tag..."
            className="min-w-0 flex-1 border border-white/10 bg-black/30 px-3 py-2 text-xs text-gray-200 outline-none focus:border-red-500/50"
          />
          <select
            aria-label="Filter Sigma rules by severity"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            className="border border-white/10 bg-[#111] px-3 py-2 text-xs text-gray-300"
          >
            {["ALL", "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((level) => (
              <option key={level} value={level}>
                {level === "ALL" ? "All severities" : level}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter by validation status"
            value={validation}
            onChange={(event) => setValidation(event.target.value)}
            className="border border-white/10 bg-[#111] px-3 py-2 text-xs text-gray-300"
          >
            {["ALL", "VALID", "INVALID"].map((status) => (
              <option key={status} value={status}>
                {status === "ALL" ? "All validation states" : status}
              </option>
            ))}
          </select>
        </div>

        {loading ? (
          <p className="p-8 text-sm text-gray-500">Loading Sigma rules...</p>
        ) : visibleRules.length === 0 ? (
          <p className="p-8 text-sm text-gray-500">
            {rules.length
              ? "No Sigma rules match the current filters."
              : "No Sigma rule files were returned by the backend."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[950px] text-left text-xs">
              <thead className="bg-black/30 text-[9px] uppercase tracking-wider text-gray-500">
                <tr>
                  {["Rule", "Level", "Log source", "Validation", "Integration", "Tags", "Source"].map((heading) => (
                    <th key={heading} className="px-4 py-3">{heading}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {visibleRules.map((rule) => (
                  <tr key={`${rule.rule_id}-${rule.filename}`} className="align-top hover:bg-white/[0.02]">
                    <td className="max-w-xs px-4 py-4">
                      <p className="font-medium text-gray-200">{rule.title}</p>
                      <p className="mt-1 break-all font-mono text-[10px] text-red-300">
                        {rule.rule_id}
                      </p>
                      <p className="mt-2 text-[10px] leading-4 text-gray-500">
                        {rule.description}
                      </p>
                    </td>
                    <td className="px-4 py-4 text-gray-300">
                      {String(rule.level || "unknown").toUpperCase()}
                    </td>
                    <td className="px-4 py-4 text-gray-400">
                      {[
                        rule.logsource?.product,
                        rule.logsource?.service,
                        rule.logsource?.category,
                      ].filter(Boolean).join(" / ") || "Unspecified"}
                    </td>
                    <td className="px-4 py-4">
                      <span className={`border px-2 py-1 text-[9px] ${
                        rule.validation_status === "VALID"
                          ? "border-emerald-500/30 text-emerald-300"
                          : "border-red-500/30 text-red-300"
                      }`}>
                        {rule.validation_status}
                      </span>
                      {rule.validation_errors?.length > 0 && (
                        <p className="mt-2 max-w-xs text-[10px] text-red-300">
                          {rule.validation_errors.join("; ")}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-4">
                      <p className="text-[10px] text-yellow-200">
                        {rule.integration_status || "UNKNOWN"}
                      </p>
                      <p className="mt-1 text-[10px] text-gray-500">
                        Live: {rule.live_detection_enabled ? "Enabled" : "Disabled"}
                      </p>
                    </td>
                    <td className="max-w-xs px-4 py-4 break-words text-gray-400">
                      {Array.isArray(rule.tags) && rule.tags.length
                        ? rule.tags.join(", ")
                        : "—"}
                    </td>
                    <td className="px-4 py-4">
                      <p className="mb-2 text-[10px] text-gray-400">{rule.filename}</p>
                      <button
                        type="button"
                        onClick={() => openRule(rule.rule_id)}
                        className="border border-white/10 px-3 py-2 text-[10px] text-gray-300 hover:border-red-500/40 hover:text-white"
                      >
                        View YAML
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="border-t border-white/10 px-4 py-3 text-[10px] text-gray-600">
          Showing {visibleRules.length} of {rules.length} rules.
        </div>
      </section>

      {(detailLoading || detailError || selected) && (
        <section className="border border-white/10">
          <div className="flex items-center justify-between gap-3 border-b border-white/10 px-5 py-4">
            <h2 className="text-sm font-semibold text-white">
              Sigma Rule Source
            </h2>
            <button
              type="button"
              onClick={() => {
                setSelected(null);
                setDetailError("");
              }}
              className="text-xs text-gray-400 hover:text-white"
            >
              Close
            </button>
          </div>
          {detailLoading && (
            <p className="p-5 text-xs text-gray-400">Loading rule source...</p>
          )}
          {detailError && (
            <p className="p-5 text-xs text-red-300">{detailError}</p>
          )}
          {selected && (
            <div className="space-y-3 p-4">
              <div>
                <p className="text-sm font-medium text-gray-200">
                  {selected.rule?.title || selected.filename}
                </p>
                <p className="mt-1 text-[10px] text-gray-500">
                  {selected.filename} · {selected.validation_status} · {selected.integration_status}
                </p>
              </div>
              {selected.validation_errors?.length > 0 && (
                <div className="border border-red-500/30 p-3 text-xs text-red-300">
                  {selected.validation_errors.join("; ")}
                </div>
              )}
              <pre className="max-h-[600px] overflow-auto border border-white/10 bg-black/30 p-4 text-[11px] leading-5 text-gray-300">
                {selected.yaml || "No YAML source returned."}
              </pre>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
