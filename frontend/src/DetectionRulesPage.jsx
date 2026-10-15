import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

export default function DetectionRulesPage() {
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
          throw new Error("Unexpected response from the detection rules API.");
        }

        setRules(response.data.rules);
        setLastUpdated(new Date());
        setError("");
      } catch (err) {
        if (!cancelled) {
          setError(
            err.response?.data?.detail ||
            err.message ||
            "Unable to load detection rules."
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
    if (Number.isNaN(date.getTime())) return "—";
    return `${date.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour12: false,
    })} IST`;
  };

  const filteredRules = rules.filter((rule) => {
    const query = search.trim().toLowerCase();
    const eventTypes = Array.isArray(rule.event_types)
      ? rule.event_types.join(" ")
      : "";

    const responseText = typeof rule.response === "string"
      ? rule.response
      : JSON.stringify(rule.response ?? "");

    const text = [
      rule.rule_id,
      rule.name,
      eventTypes,
      rule.group_by,
      rule.unique_field,
      responseText,
    ].filter(Boolean).join(" ").toLowerCase();

    return (!query || text.includes(query)) &&
      (severity === "ALL" ||
       String(rule.severity || "INFO").toUpperCase() === severity);
  });

  const customCount = rules.filter((rule) => rule.is_configured).length;

  const severityStyle = {
    CRITICAL: "border-red-500/30 text-red-400",
    HIGH: "border-orange-500/30 text-orange-300",
    MEDIUM: "border-yellow-500/30 text-yellow-300",
    LOW: "border-blue-500/30 text-blue-300",
    INFO: "border-white/10 text-gray-300",
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Security Operations / Detection
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Detection Rules</h1>
          <p className="mt-2 text-xs text-gray-500">
            Read-only inventory of effective SIEM rules from the backend.
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

      {error && (
        <div className="border border-yellow-500/30 bg-yellow-500/5 p-3 text-xs text-yellow-200">
          {error}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        {[
          ["Total rules", rules.length],
          ["Custom configurations", customCount],
          ["Matching rules", filteredRules.length],
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
            placeholder="Search rule ID, name, event type, group or response..."
            aria-label="Search detection rules"
            className="min-w-0 flex-1 border border-white/10 bg-black/30 px-3 py-2 text-xs text-gray-200 outline-none focus:border-red-500/50"
          />
          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            aria-label="Filter by severity"
            className="border border-white/10 bg-[#111] px-3 py-2 text-xs text-gray-300 outline-none focus:border-red-500/50"
          >
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((level) => (
              <option key={level} value={level}>
                {level === "ALL" ? "All severities" : level}
              </option>
            ))}
          </select>
        </div>

        {loading ? (
          <p className="p-8 text-sm text-gray-500">Loading rules...</p>
        ) : filteredRules.length === 0 ? (
          <p className="p-8 text-sm text-gray-500">
            {rules.length
              ? "No rules match the selected filters."
              : "No rules were returned by the backend."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1050px] text-left text-xs">
              <thead className="bg-black/30 text-[9px] uppercase tracking-wider text-gray-500">
                <tr>
                  {["Rule", "Event types", "Threshold / window", "Severity", "Response", "Configuration"].map((heading) => (
                    <th key={heading} className="px-4 py-3">{heading}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredRules.map((rule) => {
                  const level = String(rule.severity || "INFO").toUpperCase();
                  const responseText = typeof rule.response === "string"
                    ? rule.response
                    : rule.response == null
                      ? "Not specified"
                      : JSON.stringify(rule.response);

                  return (
                    <tr key={rule.rule_id} className="align-top hover:bg-white/[0.02]">
                      <td className="max-w-xs px-4 py-4">
                        <p className="font-medium text-gray-200">
                          {rule.name || rule.rule_id}
                        </p>
                        <p className="mt-1 font-mono text-[10px] text-red-300">
                          {rule.rule_id}
                        </p>
                        <p className="mt-2 text-[10px] text-gray-500">
                          Group by: {rule.group_by || "Not specified"}
                        </p>
                        {rule.unique_field && (
                          <p className="mt-1 text-[10px] text-gray-500">
                            Unique field: {rule.unique_field}
                            {rule.unique_threshold != null
                              ? ` · Unique threshold: ${rule.unique_threshold}`
                              : ""}
                          </p>
                        )}
                      </td>
                      <td className="max-w-xs break-words px-4 py-4 text-gray-400">
                        {Array.isArray(rule.event_types)
                          ? rule.event_types.join(", ")
                          : "—"}
                      </td>
                      <td className="whitespace-nowrap px-4 py-4 text-gray-300">
                        <p>{rule.threshold ?? "—"} events</p>
                        <p className="mt-1 text-[10px] text-gray-500">
                          Window: {rule.window_seconds ?? "—"} sec
                        </p>
                        {(rule.threshold !== rule.default_threshold ||
                          rule.window_seconds !== rule.default_window_seconds) && (
                          <p className="mt-1 text-[10px] text-gray-500">
                            Default: {rule.default_threshold} events /
                            {" "}{rule.default_window_seconds} sec
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <span className={`border px-2 py-1 text-[9px] ${severityStyle[level] || severityStyle.INFO}`}>
                          {level}
                        </span>
                      </td>
                      <td className="max-w-xs break-words px-4 py-4 text-gray-400">
                        {responseText}
                      </td>
                      <td className="px-4 py-4">
                        <span className={`border px-2 py-1 text-[9px] ${
                          rule.is_configured
                            ? "border-cyan-500/30 text-cyan-300"
                            : "border-white/10 text-gray-400"
                        }`}>
                          {rule.is_configured ? "CUSTOM" : "DEFAULT"}
                        </span>
                        {rule.updated_at && (
                          <p className="mt-2 text-[10px] text-gray-500">
                            Updated: {formatTime(rule.updated_at)}
                          </p>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <div className="border-t border-white/10 px-4 py-3 text-[10px] text-gray-600">
          Showing {filteredRules.length} of {rules.length} backend rules. This page is read-only.
        </div>
      </section>
    </div>
  );
}
