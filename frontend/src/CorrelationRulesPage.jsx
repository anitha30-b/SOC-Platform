
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "./deploymentApi.js";
import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = SOC_DEPLOY_API_BASE;

export default function CorrelationRulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [refreshKey, setRefreshKey] = useState(0);
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function loadRules() {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Authentication token not found.");

        const response = await axios.get(`${API_URL}/security-events/rules`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (cancelled) return;
        if (!Array.isArray(response.data?.rules)) {
          throw new Error("Unexpected response from the SIEM rules API.");
        }

        setRules(response.data.rules);
        setLastUpdated(new Date());
        setError("");
      } catch (err) {
        if (!cancelled) {
          setError(
            err.response?.data?.detail ||
            err.message ||
            "Unable to load correlation rules."
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

  const visibleRules = rules.filter((rule) => {
    const eventTypes = Array.isArray(rule.event_types)
      ? rule.event_types.join(" ")
      : "";
    const responseText = typeof rule.response === "string"
      ? rule.response
      : JSON.stringify(rule.response ?? "");

    const searchable = [
      rule.rule_id,
      rule.name,
      eventTypes,
      rule.group_by,
      rule.unique_field,
      responseText,
    ].filter(Boolean).join(" ").toLowerCase();

    return searchable.includes(search.trim().toLowerCase()) &&
      (severity === "ALL" ||
       String(rule.severity || "INFO").toUpperCase() === severity);
  });

  const uniqueRules = rules.filter(
    (rule) => rule.unique_field && rule.unique_threshold != null
  ).length;

  const automatedResponseRules = rules.filter(
    (rule) => Boolean(rule.response)
  ).length;

  const severityStyle = {
    CRITICAL: "border-red-500/30 text-red-400",
    HIGH: "border-orange-500/30 text-orange-300",
    MEDIUM: "border-yellow-500/30 text-yellow-300",
    LOW: "border-blue-500/30 text-blue-300",
    INFO: "border-white/10 text-gray-300",
  };

  function triggerDescription(rule) {
    const conditions = [
      `At least ${rule.threshold ?? "—"} matching event(s)`,
      `within ${rule.window_seconds ?? "—"} second(s)`,
    ];

    if (rule.unique_field && rule.unique_threshold != null) {
      conditions.push(
        `and at least ${rule.unique_threshold} distinct value(s) for ${rule.unique_field}`
      );
    }

    return `${conditions.join(" ")}.`;
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Security Operations / Detection
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Correlation Rules</h1>
          <p className="mt-2 max-w-3xl text-xs leading-5 text-gray-500">
            Effective rule definitions from the existing SIEM correlation engine.
            This page is read-only and does not change detection behavior.
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

      <div className="border border-white/10 bg-white/[0.02] p-4">
        <h2 className="text-xs font-semibold text-gray-200">How correlation triggers work</h2>
        <p className="mt-2 text-xs leading-5 text-gray-500">
          Matching events are grouped using each rule's grouping field and
          evaluated against its configured time window and event-count threshold.
          Rules with a unique-value requirement must also satisfy that requirement.
          The engine applies a 60-second alert cooldown for each rule/group key.
        </p>
      </div>

      {error && (
        <div className="border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Correlation rules", rules.length],
          ["High severity", rules.filter((r) => String(r.severity).toUpperCase() === "HIGH").length],
          ["With unique-value conditions", uniqueRules],
          ["With response actions", automatedResponseRules],
        ].map(([label, value]) => (
          <div key={label} className="border border-white/10 bg-white/[0.02] p-4">
            <p className="text-[10px] uppercase tracking-wider text-gray-500">{label}</p>
            <p className="mt-3 text-2xl font-semibold tabular-nums text-white">{value}</p>
          </div>
        ))}
      </div>

      <section className="border border-white/10">
        <div className="flex flex-col gap-3 border-b border-white/10 p-4 sm:flex-row">
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search rule ID, name, event type, grouping or response..."
            aria-label="Search correlation rules"
            className="min-w-0 flex-1 border border-white/10 bg-black/30 px-3 py-2 text-xs text-gray-200 outline-none focus:border-red-500/50"
          />
          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            aria-label="Filter correlation rules by severity"
            className="border border-white/10 bg-[#111] px-3 py-2 text-xs text-gray-300"
          >
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((level) => (
              <option key={level} value={level}>
                {level === "ALL" ? "All severities" : level}
              </option>
            ))}
          </select>
        </div>

        {loading ? (
          <p className="p-8 text-sm text-gray-500">Loading rules from the SIEM backend...</p>
        ) : visibleRules.length === 0 ? (
          <p className="p-8 text-sm text-gray-500">
            {rules.length
              ? "No rules match the current filters."
              : "No correlation rules were returned by the backend."}
          </p>
        ) : (
          <div className="divide-y divide-white/5">
            {visibleRules.map((rule) => {
              const level = String(rule.severity || "INFO").toUpperCase();

              return (
                <article key={rule.rule_id} className="p-4 sm:p-5">
                  <div className="flex flex-col justify-between gap-3 sm:flex-row">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-gray-200">
                        {rule.name || rule.rule_id}
                      </p>
                      <p className="mt-1 font-mono text-[10px] text-red-300">
                        {rule.rule_id}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-start gap-2">
                      <span className={`border px-2 py-1 text-[9px] ${severityStyle[level] || severityStyle.INFO}`}>
                        {level}
                      </span>
                      <span className={`border px-2 py-1 text-[9px] ${
                        rule.is_configured
                          ? "border-cyan-500/30 text-cyan-300"
                          : "border-white/10 text-gray-400"
                      }`}>
                        {rule.is_configured ? "CUSTOM" : "DEFAULT"}
                      </span>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                    <div>
                      <p className="text-[9px] uppercase tracking-wider text-gray-500">Event types</p>
                      <p className="mt-2 break-words text-xs text-gray-300">
                        {Array.isArray(rule.event_types) ? rule.event_types.join(", ") : "—"}
                      </p>
                    </div>
                    <div>
                      <p className="text-[9px] uppercase tracking-wider text-gray-500">Grouping</p>
                      <p className="mt-2 text-xs text-gray-300">
                        {rule.group_by || "Not specified"}
                      </p>
                    </div>
                    <div>
                      <p className="text-[9px] uppercase tracking-wider text-gray-500">Detection condition</p>
                      <p className="mt-2 text-xs leading-5 text-gray-300">
                        {triggerDescription(rule)}
                      </p>
                    </div>
                    <div>
                      <p className="text-[9px] uppercase tracking-wider text-gray-500">Response action</p>
                      <p className="mt-2 break-words text-xs text-gray-300">
                        {rule.response || "No automated response configured"}
                      </p>
                    </div>
                    <div>
                      <p className="text-[9px] uppercase tracking-wider text-gray-500">Effective configuration</p>
                      <p className="mt-2 text-xs text-gray-300">
                        {rule.threshold ?? "—"} event(s) / {rule.window_seconds ?? "—"} seconds
                      </p>
                      {(rule.threshold !== rule.default_threshold ||
                        rule.window_seconds !== rule.default_window_seconds) && (
                        <p className="mt-1 text-[10px] text-gray-500">
                          Original default: {rule.default_threshold} event(s) /
                          {" "}{rule.default_window_seconds} seconds
                        </p>
                      )}
                      {rule.updated_at && (
                        <p className="mt-1 text-[10px] text-gray-500">
                          Updated: {formatTime(rule.updated_at)}
                        </p>
                      )}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        )}
        <div className="border-t border-white/10 px-4 py-3 text-[10px] text-gray-600">
          Showing {visibleRules.length} of {rules.length} rules. Changes remain in the existing administrator tuning flow.
        </div>
      </section>
    </div>
  );
}
