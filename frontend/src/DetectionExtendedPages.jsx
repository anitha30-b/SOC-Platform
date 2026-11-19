import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

const PAGE_INFO = {
  "behavioral-detection": {
    title: "Behavioral Detection",
    description: "Persisted authentication and SIEM behavioral detection signals.",
  },
  "anomaly-detection": {
    title: "Anomaly Detection",
    description: "Historical event-volume baselines for analyst review, calculated from persisted security events.",
  },
  "ioc-detection": {
    title: "IOC Detection",
    description: "Manage persistent indicators and review candidate matches against stored SOC events.",
  },
  "detection-coverage": {
    title: "Detection Coverage",
    description: "Observed rule activity and stored MITRE ATT&CK mappings from the existing backend.",
  },
};

export default function DetectionExtendedPages({ view }) {
  const [data, setData] = useState({
    alerts: [],
    events: [],
    rules: [],
    techniques: [],
    tactics: [],
    mappedEvents: [],
    iocs: [],
    anomalyBaseline: null,
    mitreCoverage: null,
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const [iocType, setIocType] = useState("IP");
  const [iocValue, setIocValue] = useState("");
  const [iocDescription, setIocDescription] = useState("");
  const [iocSource, setIocSource] = useState("Manual");
  const [iocSeverity, setIocSeverity] = useState("MEDIUM");
  const [iocConfidence, setIocConfidence] = useState("50");
  const [iocBusy, setIocBusy] = useState(false);
  const [iocMessage, setIocMessage] = useState("");
  const [matchResults, setMatchResults] = useState({});

  const page = PAGE_INFO[view] || PAGE_INFO["behavioral-detection"];
  const token = () => localStorage.getItem("token");
  const auth = () => {
    const currentToken = token();
    if (!currentToken) throw new Error("Authentication token not found. Please log in again.");
    return { headers: { Authorization: `Bearer ${currentToken}` } };
  };

  useEffect(() => {
    let cancelled = false;

    async function loadAll() {
      if (refreshKey === 0) setLoading(true);
      else setRefreshing(true);

      const requests = [
        {
          key: "alerts",
          name: "persisted detections",
          run: () => axios.get(`${API_URL}/security-events/alerts?limit=500`, auth()),
          extract: (d) => Array.isArray(d?.alerts) ? d.alerts : [],
        },
        {
          key: "events",
          name: "security events",
          run: () => axios.get(`${API_URL}/security-events?limit=500`, auth()),
          extract: (d) => Array.isArray(d) ? d : [],
        },
        ...(view === "anomaly-detection" ? [{
          key: "anomalyBaseline",
          name: "historical anomaly baseline",
          run: () => axios.get(`${API_URL}/security-events/anomaly/baseline`, auth()),
          extract: (d) => d && typeof d === "object" ? d : null,
        }] : []),
        ...(view === "detection-coverage" ? [{
          key: "mitreCoverage",
          name: "MITRE ATT&CK coverage catalogue",
          run: () => axios.get(`${API_URL}/security-events/coverage/mitre`, auth()),
          extract: (d) => d && typeof d === "object" ? d : null,
        }] : []),
        {
          key: "rules",
          name: "SIEM rules",
          run: () => axios.get(`${API_URL}/security-events/rules`, auth()),
          extract: (d) => Array.isArray(d?.rules) ? d.rules : [],
        },
        {
          key: "techniques",
          name: "MITRE technique statistics",
          run: () => axios.get(`${API_URL}/security-events/stats/techniques?limit=50`, auth()),
          extract: (d) => Array.isArray(d?.techniques) ? d.techniques : [],
        },
        {
          key: "tactics",
          name: "MITRE tactic statistics",
          run: () => axios.get(`${API_URL}/security-events/stats/tactics?limit=50`, auth()),
          extract: (d) => Array.isArray(d?.tactics) ? d.tactics : [],
        },
        {
          key: "mappedEvents",
          name: "recent MITRE-mapped events",
          run: () => axios.get(`${API_URL}/security-events/stats/recent?limit=50`, auth()),
          extract: (d) => Array.isArray(d?.events) ? d.events : [],
        },
        {
          key: "iocs",
          name: "IOC registry",
          run: () => axios.get(`${API_URL}/ioc/indicators`, auth()),
          extract: (d) => Array.isArray(d?.indicators) ? d.indicators : [],
        },
      ];

      try {
        const results = await Promise.allSettled(
          requests.map((request) => request.run())
        );
        if (cancelled) return;

        const updates = {};
        const failed = [];

        results.forEach((result, index) => {
          const request = requests[index];
          if (result.status === "fulfilled") {
            updates[request.key] = request.extract(result.value.data);
          } else {
            failed.push(request.name);
          }
        });

        if (Object.keys(updates).length) {
          setData((previous) => ({ ...previous, ...updates }));
          setLastUpdated(new Date());
        }

        setError(
          failed.length
            ? `Some data could not be loaded: ${failed.join(", ")}. Other available data remains visible.`
            : ""
        );
      } catch (err) {
        if (!cancelled) {
          setError(err.response?.data?.detail || err.message || "Unable to load Detection data.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    }

    loadAll();
    const timer = window.setInterval(loadAll, 30000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [refreshKey, view]);

  const fmt = (value) => Number(value || 0).toLocaleString("en-IN");
  const fmtTime = (value) => {
    if (!value) return "—";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime())
      ? "—"
      : `${parsed.toLocaleString("en-IN", {
          timeZone: "Asia/Kolkata",
          hour12: false,
        })} IST`;
  };

  const refresh = () => {
    setRefreshing(true);
    setRefreshKey((value) => value + 1);
  };

  async function addIOC(event) {
    event.preventDefault();
    setIocBusy(true);
    setIocMessage("");

    try {
      const response = await axios.post(
        `${API_URL}/ioc/indicators`,
        {
          indicator_type: iocType,
          value: iocValue,
          description: iocDescription || null,
          source: iocSource || null,
          severity: iocSeverity,
          confidence: Number(iocConfidence),
        },
        auth()
      );

      setIocMessage(`Indicator added: ${response.data?.indicator?.value || iocValue}`);
      setIocValue("");
      setIocDescription("");
      refresh();
    } catch (err) {
      setIocMessage(
        err.response?.data?.detail || err.message || "Unable to add indicator."
      );
    } finally {
      setIocBusy(false);
    }
  }

  async function deleteIOC(item) {
    if (!window.confirm(`Delete indicator ${item.value}?`)) return;

    setIocBusy(true);
    setIocMessage("");
    try {
      await axios.delete(`${API_URL}/ioc/indicators/${item.id}`, auth());
      setIocMessage(`Deleted indicator ${item.value}.`);
      setMatchResults((previous) => {
        const next = { ...previous };
        delete next[item.id];
        return next;
      });
      refresh();
    } catch (err) {
      setIocMessage(err.response?.data?.detail || err.message || "Unable to delete indicator.");
    } finally {
      setIocBusy(false);
    }
  }

  async function checkIOC(item) {
    setMatchResults((previous) => ({
      ...previous,
      [item.id]: { loading: true },
    }));

    try {
      const response = await axios.get(
        `${API_URL}/ioc/indicators/${item.id}/matches`,
        auth()
      );
      setMatchResults((previous) => ({
        ...previous,
        [item.id]: { ...response.data, loading: false },
      }));
    } catch (err) {
      setMatchResults((previous) => ({
        ...previous,
        [item.id]: {
          loading: false,
          error: err.response?.data?.detail || err.message || "Match check failed.",
        },
      }));
    }
  }

  const behavioralAlerts = data.alerts.filter((item) => {
    const ruleId = String(item.detection?.rule_id || "");
    const eventType = String(item.event_type || "").toLowerCase();
    const ruleName = String(item.detection?.rule_name || "").toLowerCase();

    return ruleId.startsWith("AUTH-") ||
      eventType === "authentication_detection" ||
      ruleName.includes("credential") ||
      ruleName.includes("password spray") ||
      ruleName.includes("authentication");
  });

  const anomalyBaseline = data.anomalyBaseline;
  const volumeRows = Array.isArray(anomalyBaseline?.event_types)
    ? anomalyBaseline.event_types
    : [];

  const filteredIocs = data.iocs.filter((item) =>
    [
      item.value,
      item.indicator_type,
      item.description,
      item.source,
      item.severity,
    ].filter(Boolean).join(" ").toLowerCase().includes(search.trim().toLowerCase())
  );

  const coverageRuleRows = data.rules.map((rule) => ({
    ...rule,
    observed: data.alerts.filter(
      (alert) => alert.detection?.rule_id === rule.rule_id
    ).length,
  }));

  const mitreCoverage = data.mitreCoverage;
  const mappedCoverageTechniques = Array.isArray(mitreCoverage?.techniques)
    ? mitreCoverage.techniques.filter((technique) => technique.configured)
    : [];
  const unmappedSiemRules = Array.isArray(mitreCoverage?.siem_rules_without_explicit_mapping)
    ? mitreCoverage.siem_rules_without_explicit_mapping
    : [];

  const card = (label, value, note) => (
    <div key={label} className="border border-white/10 bg-white/[0.02] p-4">
      <p className="text-[10px] uppercase tracking-wider text-gray-500">{label}</p>
      <p className="mt-3 text-2xl font-semibold tabular-nums text-white">{fmt(value)}</p>
      {note && <p className="mt-2 text-[10px] leading-4 text-gray-600">{note}</p>}
    </div>
  );

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Security Operations / Detection
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">{page.title}</h1>
          <p className="mt-2 max-w-3xl text-xs leading-5 text-gray-500">{page.description}</p>
          <p className="mt-2 text-[10px] text-gray-600">
            Last refresh: {fmtTime(lastUpdated)} · Auto-refresh every 30 seconds
          </p>
        </div>
        <button
          type="button"
          disabled={refreshing}
          onClick={refresh}
          className="border border-white/10 px-4 py-2 text-xs text-gray-300 hover:border-red-500/40 hover:text-white disabled:opacity-50"
        >
          {refreshing ? "Refreshing..." : "Refresh data"}
        </button>
      </header>

      {error && (
        <div className="border border-yellow-500/30 bg-yellow-500/5 p-3 text-xs text-yellow-200">
          {error}
        </div>
      )}

      {loading ? (
        <div className="border border-white/10 p-8 text-sm text-gray-500">
          Loading Detection data...
        </div>
      ) : (
        <>
          {view === "behavioral-detection" && (
            <>
              <div className="border border-white/10 bg-white/[0.02] p-4">
                <p className="text-xs font-semibold text-gray-200">Evidence source</p>
                <p className="mt-2 text-xs leading-5 text-gray-500">
                  This view displays persisted authentication-related detection records
                  from the current SIEM. It does not recalculate detection decisions.
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-3">
                {[
                  ["Behavioral/auth detections", behavioralAlerts.length],
                  ["High / Critical", behavioralAlerts.filter((a) => ["HIGH", "CRITICAL"].includes(String(a.severity || "").toUpperCase())).length],
                  ["Distinct rule IDs", new Set(behavioralAlerts.map((a) => a.detection?.rule_id).filter(Boolean)).size],
                ].map(([label, value]) => card(label, value))}
              </div>
              <section className="border border-white/10">
                <div className="border-b border-white/10 p-4">
                  <h2 className="text-sm font-semibold text-white">Persisted Behavioral Signals</h2>
                </div>
                {behavioralAlerts.length === 0 ? (
                  <p className="p-5 text-xs text-gray-500">No authentication-related detections were returned in the latest detection sample.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[750px] text-left text-xs">
                      <thead className="bg-black/30 text-[9px] uppercase tracking-wider text-gray-500">
                        <tr>{["Time (IST)", "Rule", "Severity", "Status", "Source", "Technique"].map((h) => <th key={h} className="px-4 py-3">{h}</th>)}</tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {behavioralAlerts.slice(0, 50).map((a, index) => (
                          <tr key={a.event_id || a.id || index}>
                            <td className="whitespace-nowrap px-4 py-3 text-gray-500">{fmtTime(a.timestamp)}</td>
                            <td className="px-4 py-3 text-gray-200">
                              {a.detection?.rule_name || a.event_type}
                              <p className="mt-1 text-[10px] text-gray-500">{a.detection?.rule_id || "Rule ID unavailable"}</p>
                            </td>
                            <td className="px-4 py-3 text-gray-300">{a.severity || "—"}</td>
                            <td className="px-4 py-3 text-gray-400">{a.alert_status || "—"}</td>
                            <td className="px-4 py-3 text-gray-400">{a.source || "—"}</td>
                            <td className="px-4 py-3 text-gray-400">{a.mitre?.technique_id || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </>
          )}

          {view === "anomaly-detection" && (
            <>
              <div className="border border-sky-500/30 bg-sky-500/5 p-4">
                <p className="text-xs font-semibold text-sky-200">Historical baseline review</p>
                <p className="mt-2 text-xs leading-5 text-gray-400">
                  The latest completed 15-minute window is compared with seven days of historical
                  15-minute buckets from PostgreSQL. Volume outliers are review candidates, not
                  confirmed malicious activity. This is statistical thresholding, not a trained model.
                </p>
                {anomalyBaseline?.window_start && (
                  <p className="mt-2 text-[10px] text-gray-500">
                    Current window: {fmtTime(anomalyBaseline.window_start)} – {fmtTime(anomalyBaseline.window_end)}
                  </p>
                )}
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                {[
                  ["Events in latest 15 min", anomalyBaseline?.events_in_current_window ?? 0],
                  ["Event types evaluated", anomalyBaseline?.event_type_count ?? 0],
                  ["Volume review candidates", anomalyBaseline?.flagged_count ?? 0],
                ].map(([label, value]) => card(label, value, "Historical baseline API results"))}
              </div>

              <section className="border border-white/10">
                <div className="border-b border-white/10 p-4">
                  <h2 className="text-sm font-semibold text-white">Historical Event-Volume Review</h2>
                  <p className="mt-1 text-[10px] text-gray-500">
                    Threshold: median + 3 scaled MAD; minimum 5, or 1.5× median when MAD is zero.
                    Each event type uses 672 historical 15-minute buckets.
                  </p>
                </div>

                {!anomalyBaseline ? (
                  <p className="p-5 text-xs text-gray-500">
                    Historical baseline data is unavailable. Check the API error above and refresh.
                  </p>
                ) : volumeRows.length === 0 ? (
                  <p className="p-5 text-xs text-gray-500">
                    No stored event types were found in the comparison window.
                  </p>
                ) : (
                  <div className="divide-y divide-white/5">
                    {volumeRows.slice(0, 30).map((row) => (
                      <div key={row.event_type} className="flex flex-wrap items-center justify-between gap-3 p-4">
                        <div className="min-w-0">
                          <p className="text-xs text-gray-200">{row.event_type}</p>
                          <p className="mt-1 text-[10px] leading-4 text-gray-500">
                            Baseline median: {fmt(row.baseline_median)}
                            {" · "}MAD: {fmt(row.baseline_mad)}
                            {" · "}Threshold: {fmt(row.threshold)}
                            {" · "}Buckets: {fmt(row.historical_buckets)}
                          </p>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-sm tabular-nums text-white">{fmt(row.current_count)}</span>
                          <span className={`border px-2 py-1 text-[9px] ${
                            row.flagged
                              ? "border-yellow-500/30 text-yellow-200"
                              : "border-white/10 text-gray-500"
                          }`}>
                            {row.flagged ? "ANOMALY CANDIDATE" : "WITHIN THRESHOLD"}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                {anomalyBaseline?.interpretation && (
                  <p className="border-t border-white/10 p-4 text-[10px] leading-4 text-gray-500">
                    {anomalyBaseline.interpretation}
                  </p>
                )}
              </section>
            </>
          )}

          {view === "ioc-detection" && (
            <>
              <div className="border border-yellow-500/30 bg-yellow-500/5 p-4">
                <p className="text-xs font-semibold text-yellow-200">Indicator matching limitations</p>
                <p className="mt-2 text-xs leading-5 text-gray-400">
                  Match checks scan up to 500 persisted events linked to assessments owned by your
                  user/client. Events without an ownership-linked assessment are excluded to protect
                  tenant isolation. No external threat-intelligence feed is connected. Matches are
                  candidates, not proof of malicious activity.
                </p>
              </div>

              <section className="border border-white/10 p-4">
                <h2 className="text-sm font-semibold text-white">Add Indicator</h2>
                <form onSubmit={addIOC} className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                  <select value={iocType} onChange={(e) => setIocType(e.target.value)} className="border border-white/10 bg-[#111] px-3 py-2 text-xs text-gray-300" aria-label="Indicator type">
                    {["IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"].map((t) => <option key={t}>{t}</option>)}
                  </select>
                  <input value={iocValue} onChange={(e) => setIocValue(e.target.value)} required maxLength={2048} placeholder="IP, domain, URL or hash" className="border border-white/10 bg-black/30 px-3 py-2 text-xs text-gray-200" />
                  <select value={iocSeverity} onChange={(e) => setIocSeverity(e.target.value)} className="border border-white/10 bg-[#111] px-3 py-2 text-xs text-gray-300" aria-label="Indicator severity">
                    {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
                  </select>
                  <input value={iocDescription} onChange={(e) => setIocDescription(e.target.value)} maxLength={4000} placeholder="Description (optional)" className="border border-white/10 bg-black/30 px-3 py-2 text-xs text-gray-200" />
                  <input value={iocSource} onChange={(e) => setIocSource(e.target.value)} maxLength={255} placeholder="Source / reference (optional)" className="border border-white/10 bg-black/30 px-3 py-2 text-xs text-gray-200" />
                  <div className="flex gap-2">
                    <input type="number" min="0" max="100" value={iocConfidence} onChange={(e) => setIocConfidence(e.target.value)} required aria-label="Confidence 0 to 100" className="w-28 border border-white/10 bg-black/30 px-3 py-2 text-xs text-gray-200" />
                    <button disabled={iocBusy} type="submit" className="flex-1 border border-red-500/40 px-3 py-2 text-xs text-white hover:bg-red-500/10 disabled:opacity-50">
                      {iocBusy ? "Working..." : "Add indicator"}
                    </button>
                  </div>
                </form>
                {iocMessage && <p className="mt-3 break-words text-xs text-gray-300">{iocMessage}</p>}
              </section>

              <section className="border border-white/10">
                <div className="flex flex-col gap-3 border-b border-white/10 p-4 sm:flex-row">
                  <h2 className="flex-1 text-sm font-semibold text-white">Persistent Indicator Registry</h2>
                  <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search indicators..." aria-label="Search indicators" className="border border-white/10 bg-black/30 px-3 py-2 text-xs text-gray-200" />
                </div>
                {filteredIocs.length === 0 ? (
                  <p className="p-5 text-xs text-gray-500">
                    No indicators returned. Add a verified indicator above to begin the registry.
                  </p>
                ) : (
                  <div className="divide-y divide-white/5">
                    {filteredIocs.map((item) => {
                      const match = matchResults[item.id];
                      return (
                        <article key={item.id} className="space-y-3 p-4">
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="break-all font-mono text-xs text-gray-200">{item.value}</p>
                              <p className="mt-1 text-[10px] text-gray-500">
                                {item.indicator_type} · {item.severity} · Confidence {item.confidence}%
                              </p>
                              <p className="mt-1 break-words text-[10px] text-gray-500">
                                {item.description || "No description"} · Source: {item.source || "Not specified"}
                              </p>
                            </div>
                            <div className="flex flex-wrap gap-2">
                              <button type="button" disabled={iocBusy || match?.loading} onClick={() => checkIOC(item)} className="border border-white/10 px-3 py-2 text-[10px] text-gray-300 hover:text-white disabled:opacity-50">
                                {match?.loading ? "Checking..." : "Check matches"}
                              </button>
                              <button type="button" disabled={iocBusy} onClick={() => deleteIOC(item)} className="border border-red-500/30 px-3 py-2 text-[10px] text-red-300 hover:bg-red-500/10 disabled:opacity-50">
                                Delete
                              </button>
                            </div>
                          </div>
                          {match && !match.loading && (
                            <div className="border border-white/10 bg-black/20 p-3">
                              {match.error ? (
                                <p className="text-xs text-red-300">{match.error}</p>
                              ) : (
                                <>
                                  <p className="text-xs text-gray-200">
                                    Candidate matches: <strong>{fmt(match.candidate_match_count)}</strong>
                                    {" · "}Events scanned: {fmt(match.events_scanned)}
                                  </p>
                                  {match.scope_status === "NO_SCOPED_EVENTS" && (
                                    <p className="mt-2 border border-yellow-500/30 bg-yellow-500/5 p-3 text-[10px] leading-4 text-yellow-200">
                                      {match.scope_message}
                                    </p>
                                  )}
                                  <p className="mt-2 text-[10px] leading-4 text-gray-500">
                                    {match.tenant_scope_note || match.scope_message}
                                  </p>
                                </>
                              )}
                            </div>
                          )}
                        </article>
                      );
                    })}
                  </div>
                )}
              </section>
            </>
          )}

          {view === "detection-coverage" && (
            <>
              <div className="border border-white/10 bg-white/[0.02] p-4">
                <p className="text-xs font-semibold text-gray-200">Coverage scope</p>
                <p className="mt-2 text-xs leading-5 text-gray-500">
                  These are observed mappings and rule hits in data returned by the backend.
                  They are not a claim of complete MITRE ATT&CK coverage or that an untriggered
                  rule is ineffective.
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                {[
                  ["Configured SIEM rules", data.rules.length],
                  ["Observed techniques", data.techniques.length],
                  ["Observed tactics", data.tactics.length],
                  ["Recent mapped events returned", data.mappedEvents.length],
                ].map(([label, value]) => card(label, value))}
              </div>
              {mitreCoverage ? (
                <>
                  <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    {[
                      ["ATT&CK catalogue techniques", mitreCoverage.catalogue_technique_count],
                      ["Explicitly mapped techniques", mitreCoverage.configured_technique_count],
                      ["Observed techniques in scope", mitreCoverage.observed_catalogue_technique_count],
                      ["Without explicit mapping", mitreCoverage.catalogue_techniques_without_explicit_mapping],
                    ].map(([label, value]) => card(label, value, `Enterprise ATT&CK ${mitreCoverage.version}`))}
                  </div>

                  <section className="border border-white/10">
                    <div className="border-b border-white/10 p-4">
                      <h2 className="text-sm font-semibold text-white">Explicit ATT&CK Rule Mappings</h2>
                      <p className="mt-1 text-[10px] leading-4 text-gray-500">
                        Only explicit ATT&CK technique tags on valid Sigma rules count as configured
                        mappings. Observed counts use assessment-linked events in your user/client scope.
                      </p>
                    </div>
                    {mappedCoverageTechniques.length === 0 ? (
                      <p className="p-4 text-xs text-gray-500">No explicit Sigma technique mappings were found.</p>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full min-w-[700px] text-left text-xs">
                          <thead className="bg-black/30 text-[9px] uppercase tracking-wider text-gray-500">
                            <tr>
                              {["Technique", "Configured rule(s)", "Execution status", "Observed events", "Coverage status"].map((heading) => (
                                <th key={heading} className="px-4 py-3">{heading}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-white/5">
                            {mappedCoverageTechniques.map((technique) => (
                              <tr key={technique.technique_id}>
                                <td className="px-4 py-3">
                                  <p className="font-mono text-red-300">{technique.technique_id}</p>
                                  <p className="mt-1 text-gray-300">{technique.name}</p>
                                  <p className="mt-1 text-[10px] text-gray-500">
                                    {(technique.tactics || []).join(", ") || "Tactic unavailable"}
                                  </p>
                                </td>
                                <td className="px-4 py-3 text-gray-300">
                                  {(technique.configured_by || []).map((rule) => (
                                    <p key={`${rule.rule_type}-${rule.rule_id}`} className="mb-1">
                                      {rule.rule_name}
                                      <span className="mt-1 block font-mono text-[10px] text-gray-500">{rule.rule_id}</span>
                                    </p>
                                  ))}
                                </td>
                                <td className="px-4 py-3 text-gray-400">
                                  {(technique.configured_by || []).map((rule) => (
                                    <p key={`${rule.rule_type}-${rule.rule_id}-status`}>
                                      {rule.integration_status}
                                    </p>
                                  ))}
                                </td>
                                <td className="px-4 py-3 tabular-nums text-gray-300">
                                  {fmt(technique.observed_event_count)}
                                </td>
                                <td className="px-4 py-3 text-gray-300">
                                  {technique.coverage_status.replace(/_/g, " ")}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </section>

                  <section className="border border-white/10">
                    <div className="border-b border-white/10 p-4">
                      <h2 className="text-sm font-semibold text-white">SIEM Rules Without Explicit ATT&CK Mapping</h2>
                      <p className="mt-1 text-[10px] leading-4 text-gray-500">
                        These rules have no technique ID configured in their definitions. No mapping is inferred
                        from their names or event types.
                      </p>
                    </div>
                    {unmappedSiemRules.length === 0 ? (
                      <p className="p-4 text-xs text-gray-500">All current SIEM rules have explicit mapping metadata.</p>
                    ) : (
                      <div className="divide-y divide-white/5">
                        {unmappedSiemRules.map((rule) => (
                          <div key={rule.rule_id} className="flex flex-wrap items-start justify-between gap-3 p-4">
                            <div>
                              <p className="text-xs text-gray-200">{rule.rule_name}</p>
                              <p className="mt-1 font-mono text-[10px] text-gray-500">{rule.rule_id}</p>
                            </div>
                            <p className="max-w-xl text-[10px] leading-4 text-gray-500">{rule.reason}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>
                  <p className="text-[10px] leading-4 text-gray-500">
                    {mitreCoverage.interpretation}
                  </p>
                </>
              ) : (
                <section className="border border-white/10 p-4">
                  <p className="text-xs text-gray-400">
                    MITRE coverage data is unavailable. Check the API error above and refresh.
                  </p>
                </section>
              )}


              <section className="border border-white/10">
                <div className="border-b border-white/10 p-4">
                  <h2 className="text-sm font-semibold text-white">Observed Detection Rule Activity</h2>
                  <p className="mt-1 text-[10px] text-gray-500">
                    Counts are limited to the latest detection records returned by the API (maximum 500).
                  </p>
                </div>
                {coverageRuleRows.length === 0 ? (
                  <p className="p-5 text-xs text-gray-500">No SIEM rules returned.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[650px] text-left text-xs">
                      <thead className="bg-black/30 text-[9px] uppercase tracking-wider text-gray-500">
                        <tr>{["Rule", "Severity", "Event threshold", "Window", "Observed records", "Configuration"].map((h) => <th key={h} className="px-4 py-3">{h}</th>)}</tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {coverageRuleRows.map((rule) => (
                          <tr key={rule.rule_id}>
                            <td className="px-4 py-3 text-gray-200">
                              {rule.name}
                              <p className="mt-1 font-mono text-[10px] text-gray-500">{rule.rule_id}</p>
                            </td>
                            <td className="px-4 py-3 text-gray-300">{rule.severity}</td>
                            <td className="px-4 py-3 text-gray-300">{rule.threshold}</td>
                            <td className="px-4 py-3 text-gray-300">{rule.window_seconds}s</td>
                            <td className="px-4 py-3 text-gray-300">{fmt(rule.observed)}</td>
                            <td className="px-4 py-3 text-gray-400">{rule.is_configured ? "CUSTOM" : "DEFAULT"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <div className="grid gap-4 xl:grid-cols-2">
                <section className="border border-white/10">
                  <div className="border-b border-white/10 p-4">
                    <h2 className="text-sm font-semibold text-white">Observed MITRE Techniques</h2>
                  </div>
                  {data.techniques.length === 0 ? (
                    <p className="p-4 text-xs text-gray-500">No mapped techniques returned.</p>
                  ) : data.techniques.map((t) => (
                    <div key={`${t.technique_id}-${t.technique_name}`} className="flex justify-between gap-4 border-b border-white/5 p-4">
                      <div>
                        <p className="font-mono text-xs text-red-300">{t.technique_id}</p>
                        <p className="mt-1 text-xs text-gray-300">{t.technique_name || "Technique name unavailable"}</p>
                      </div>
                      <p className="text-sm tabular-nums text-white">{fmt(t.event_count)}</p>
                    </div>
                  ))}
                </section>
                <section className="border border-white/10">
                  <div className="border-b border-white/10 p-4">
                    <h2 className="text-sm font-semibold text-white">Observed MITRE Tactics</h2>
                  </div>
                  {data.tactics.length === 0 ? (
                    <p className="p-4 text-xs text-gray-500">No mapped tactics returned.</p>
                  ) : data.tactics.map((t) => (
                    <div key={t.tactic} className="flex justify-between gap-4 border-b border-white/5 p-4">
                      <p className="text-xs text-gray-300">{t.tactic}</p>
                      <p className="text-sm tabular-nums text-white">{fmt(t.event_count)}</p>
                    </div>
                  ))}
                </section>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
