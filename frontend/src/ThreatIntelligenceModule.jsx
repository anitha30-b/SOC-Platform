import { useEffect, useRef, useState } from "react";

export default function ThreatIntelligenceModule({ apiUrl, view }) {
  const dashboard = view === "threat-intelligence";
  const fixedKind = ({
    "threat-domains": "DOMAIN",
    "threat-urls": "URL",
    "threat-hashes": "HASH",
  })[view];
  const title = ({
    "threat-intelligence": "Threat Intelligence Dashboard",
    "threat-indicators": "Indicators",
    "threat-domains": "Domain Intelligence",
    "threat-urls": "URL Intelligence",
    "threat-hashes": "Hash Intelligence",
    "hunt-ioc": "IOC Hunting",
  })[view] || "Indicators";
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState(fixedKind || "ALL");
  const [severity, setSeverity] = useState("ALL");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [summary, setSummary] = useState(null);
  const [page, setPage] = useState({ indicators: [], total: 0, next_offset: null });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState("");
  const [createSuccess, setCreateSuccess] = useState("");
  const [draft, setDraft] = useState({
    indicator_type: fixedKind === "HASH" ? "SHA256" : fixedKind || "IP",
    value: "", description: "", source: "",
    severity: "MEDIUM", confidence: "50",
  });

  const createIndicator = async event => {
    event.preventDefault();
    if (createBusy) return;
    setCreateError("");
    setCreateSuccess("");

    const confidence = Number(draft.confidence);
    if (!draft.value.trim()) {
      setCreateError("Enter an indicator value.");
      return;
    }
    if (draft.confidence === "" || !Number.isInteger(confidence) ||
        confidence < 0 || confidence > 100) {
      setCreateError("Confidence must be a whole number from 0 to 100.");
      return;
    }

    setCreateBusy(true);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const token = localStorage.getItem("token");
      if (!token) throw new Error("Your session has expired. Please log in again.");
      const response = await fetch(`${apiUrl}/ioc/indicators`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        signal: controller.signal,
        body: JSON.stringify({
          indicator_type: draft.indicator_type,
          value: draft.value.trim(),
          description: draft.description.trim() || null,
          source: draft.source.trim() || "Manual",
          severity: draft.severity,
          confidence,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        const detail = typeof data.detail === "string"
          ? data.detail
          : Array.isArray(data.detail)
            ? data.detail.map(item => item.msg).join("; ")
            : `Unable to create indicator (${response.status}).`;
        throw new Error(detail);
      }
      if (!data.indicator?.id) throw new Error("Unexpected create response.");
      setCreateSuccess(`Saved ${data.indicator.indicator_type}: ${data.indicator.value}`);
      setDraft(previous => ({
        ...previous, value: "", description: "", source: "",
      }));
      setSearch("");
      setKind(fixedKind || "ALL");
      setSeverity("ALL");
      setOffset(0);
      setRefresh(value => value + 1);
    } catch (err) {
      setCreateError(err.name === "AbortError"
        ? "Request timed out. Refresh the registry before retrying; the save may have completed."
        : err.message);
    } finally {
      clearTimeout(timer);
      setCreateBusy(false);
    }
  };

  const [selected, setSelected] = useState(null);
  const [matchState, setMatchState] = useState({
    loading: false, data: null, error: "",
  });
  const matchController = useRef(null);
  const [toggleBusy, setToggleBusy] = useState(false);
  const [toggleError, setToggleError] = useState("");

  const toggleIndicator = async () => {
    if (!selected || toggleBusy) return;
    const item = selected;
    setToggleBusy(true);
    setToggleError("");
    matchController.current?.abort();
    matchController.current = null;
    setMatchState({ loading: false, data: null, error: "" });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const token = localStorage.getItem("token");
      if (!token) throw new Error("Your session has expired. Please log in again.");
      const response = await fetch(
        `${apiUrl}/ioc/indicators/${item.id}/enabled`,
        {
          method: "PATCH",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          signal: controller.signal,
          body: JSON.stringify({ enabled: !item.enabled }),
        }
      );
      const data = await response.json();
      if (!response.ok) throw new Error(
        typeof data.detail === "string" ? data.detail
          : `Status update failed (${response.status}).`
      );
      if (data.indicator?.id !== item.id ||
          typeof data.indicator.enabled !== "boolean") {
        throw new Error("Unexpected status update response.");
      }
      setSelected(previous =>
        previous?.id === item.id ? data.indicator : previous
      );
      setRefresh(value => value + 1);
    } catch (err) {
      setToggleError(err.name === "AbortError"
        ? "Request timed out. Reopen details after refreshing to verify status before retrying."
        : err.message);
    } finally {
      clearTimeout(timer);
      setToggleBusy(false);
    }
  };


  useEffect(() => () => matchController.current?.abort(), []);

  const openDetails = item => {
    matchController.current?.abort();
    matchController.current = null;
    setSelected(item);
    setToggleError("");
    setMatchState({ loading: false, data: null, error: "" });
  };

  const closeDetails = () => {
    matchController.current?.abort();
    matchController.current = null;
    setSelected(null);
    setMatchState({ loading: false, data: null, error: "" });
  };

  const checkMatches = async () => {
    if (!selected?.enabled || toggleBusy) return;
    matchController.current?.abort();
    const controller = new AbortController();
    matchController.current = controller;
    const timer = setTimeout(() => controller.abort(), 20000);
    setMatchState({ loading: true, data: null, error: "" });
    try {
      const token = localStorage.getItem("token");
      if (!token) throw new Error("Your session has expired. Please log in again.");
      const response = await fetch(
        `${apiUrl}/ioc/indicators/${selected.id}/matches`,
        {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        }
      );
      if (!response.ok) {
        throw new Error(`Candidate check failed (${response.status}).`);
      }
      const data = await response.json();
      if (!Number.isInteger(data.candidate_match_count) ||
          !Number.isInteger(data.events_scanned)) {
        throw new Error("Unexpected candidate-match response.");
      }
      if (matchController.current === controller && !controller.signal.aborted) {
        setMatchState({ loading: false, data, error: "" });
      }
    } catch (err) {
      if (matchController.current === controller) {
        setMatchState({
          loading: false, data: null,
          error: err.name === "AbortError"
            ? "Check timed out or was cancelled. Please retry."
            : err.message,
        });
      }
    } finally {
      clearTimeout(timer);
    }
  };
  const size = dashboard ? 10 : 25;

  useEffect(() => {
    let active = true;
    let timer;
    let controller;
    setLoading(true);
    setPage({ indicators: [], total: 0, next_offset: null });
    setError("");

    const load = async () => {
      controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Your session has expired. Please log in again.");
        const params = new URLSearchParams({
          search: search.trim(), indicator_type: kind, severity,
          offset: String(offset), page_size: String(size),
        });
        const get = async path => {
          const response = await fetch(`${apiUrl}${path}`, {
            headers: { Authorization: `Bearer ${token}` },
            signal: controller.signal,
          });
          if (!response.ok) throw new Error(`Registry request failed (${response.status}).`);
          return response.json();
        };
        const [totals, records] = await Promise.all([
          get("/ioc/registry-summary"), get(`/ioc/registry?${params}`),
        ]);
        if (!Number.isInteger(totals.total) ||
            !Number.isInteger(records.total) ||
            !Array.isArray(records.indicators)) {
          throw new Error("Unexpected registry response.");
        }
        if (active) {
          setSummary(totals);
          setPage(records);
          setError("");
          setUpdatedAt(new Date().toLocaleTimeString());
          if (offset > 0 && !records.indicators.length) setOffset(0);
        }
      } catch (err) {
        if (active) setError(err.name === "AbortError"
          ? "Registry request timed out." : err.message);
      } finally {
        clearTimeout(timeout);
        if (active) {
          setLoading(false);
          timer = setTimeout(load, 15000);
        }
      }
    };
    timer = setTimeout(load, 300);
    return () => {
      active = false;
      clearTimeout(timer);
      controller?.abort();
    };
  }, [apiUrl, search, kind, severity, offset, refresh, size]);

  const field = "mt-2 w-full rounded border border-white/10 bg-[#0b1014] px-3 py-2 text-xs text-gray-200";
  const button = "rounded border border-white/10 px-4 py-2 text-xs text-gray-300 disabled:opacity-40";
  const change = setter => event => { setter(event.target.value); setOffset(0); };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">Security Operations</p>
          <h1 className="mt-2 text-2xl font-bold text-white">
            {title}
          </h1>
          <p className="mt-2 text-xs text-gray-400">
            Your scoped indicator registry · {summary?.scope || "Loading scope"}
            {fixedKind && " · Registry records; external reputation enrichment is not connected"}
          </p>
        </div>
        <button className={button} disabled={loading}
          onClick={() => setRefresh(value => value + 1)}>Refresh</button>
      </div>

      {error && <p role="alert" className="mb-5 rounded border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-400">
        {error} {updatedAt && `Last successful update: ${updatedAt}.`}
      </p>}

      <div className="mb-5">
        <button className={button} disabled={createBusy}
          onClick={() => {
            setShowCreate(value => !value);
            setCreateError("");
          }}>
          {showCreate ? "Hide Add Indicator" : "Add Indicator"}
        </button>
        {createSuccess && (
          <p role="status" className="mt-3 break-all text-xs text-green-400">{createSuccess}</p>
        )}
      </div>

      {showCreate && (
        <form onSubmit={createIndicator}
          className="mb-5 rounded-lg border border-white/10 bg-[#0b1014] p-5">
          <h2 className="text-sm font-semibold text-white">Add Registry Indicator</h2>
          <p className="mt-2 text-xs leading-6 text-gray-400">
            Record the source and your assessment. Saving enables the indicator
            for candidate matching; it does not independently verify maliciousness.
          </p>
          <fieldset disabled={createBusy} className="mt-4 grid gap-4 md:grid-cols-2">
            <label className="text-xs text-gray-400">Type
              <select className={field} value={draft.indicator_type}
                onChange={event => setDraft({ ...draft, indicator_type: event.target.value })}>
                {(fixedKind === "HASH" ? ["MD5", "SHA1", "SHA256"]
                  : fixedKind ? [fixedKind]
                  : ["IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"]
                ).map(value => <option key={value}>{value}</option>)}
              </select>
            </label>
            <label className="text-xs text-gray-400">Value
              <input required maxLength={2048} className={field}
                value={draft.value}
                onChange={event => setDraft({ ...draft, value: event.target.value })}
                placeholder="IP, hostname, HTTP(S) URL, or hexadecimal hash" />
            </label>
            <label className="text-xs text-gray-400">Severity
              <select className={field} value={draft.severity}
                onChange={event => setDraft({ ...draft, severity: event.target.value })}>
                {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map(value =>
                  <option key={value}>{value}</option>)}
              </select>
            </label>
            <label className="text-xs text-gray-400">Confidence (0–100)
              <input required type="number" min={0} max={100} step={1}
                className={field} value={draft.confidence}
                onChange={event => setDraft({ ...draft, confidence: event.target.value })} />
            </label>
            <label className="text-xs text-gray-400">Source
              <input maxLength={255} className={field} value={draft.source}
                placeholder="Report, provider, or Manual"
                onChange={event => setDraft({ ...draft, source: event.target.value })} />
            </label>
            <label className="text-xs text-gray-400">Description
              <textarea maxLength={4000} rows={3} className={field}
                value={draft.description}
                onChange={event => setDraft({ ...draft, description: event.target.value })} />
            </label>
          </fieldset>
          {createError && (
            <p role="alert" className="mt-3 text-xs text-red-400">{createError}</p>
          )}
          <button type="submit" className={`${button} mt-4`} disabled={createBusy}>
            {createBusy ? "Saving..." : "Save Indicator"}
          </button>
        </form>
      )}

      <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[["Total Indicators", "total"], ["Enabled", "enabled"],
          ["Disabled", "disabled"], ["High / Critical", "high_critical"]].map(([label, key]) => (
          <div key={key} className="rounded-lg border border-white/10 bg-[#0b1014] p-4">
            <p className="text-xs text-gray-400">{label}</p>
            <p className="mt-2 text-2xl font-bold text-white">{summary?.[key] ?? "—"}</p>
          </div>
        ))}
      </div>

      {dashboard && summary && <section className="mb-5 rounded-lg border border-white/10 bg-[#0b1014] p-4">
        <h2 className="text-sm font-semibold text-white">Registry by Type</h2>
        <div className="mt-3 flex flex-wrap gap-4 text-xs text-gray-300">
          {Object.entries(summary.by_type || {}).map(([type, count]) =>
            <span key={type}>{type}: {count}</span>
          )}
        </div>
      </section>}

      <section className="mb-5 grid gap-3 rounded-lg border border-white/10 bg-[#0b1014] p-4 md:grid-cols-4">
        <label className="text-xs text-gray-400">Search
          <input type="search" maxLength={200} className={field}
            value={search} onChange={change(setSearch)} placeholder="Indicator, source, description" />
        </label>
        <label className="text-xs text-gray-400">Type
          <select className={field} value={kind} onChange={change(setKind)}
            disabled={Boolean(fixedKind) && fixedKind !== "HASH"}>
            {(fixedKind === "HASH"
              ? ["HASH", "MD5", "SHA1", "SHA256"]
              : fixedKind ? [fixedKind]
              : ["ALL", "IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"]
            ).map(value =>
              <option key={value}>{value}</option>)}
          </select>
        </label>
        <label className="text-xs text-gray-400">Severity
          <select className={field} value={severity} onChange={change(setSeverity)}>
            {["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map(value =>
              <option key={value}>{value}</option>)}
          </select>
        </label>
        <button className={`${button} self-end`} onClick={() => {
          setSearch(""); setKind(fixedKind || "ALL"); setSeverity("ALL"); setOffset(0);
        }}>Clear Filters</button>
      </section>

      <section className="overflow-hidden rounded-lg border border-white/10 bg-[#0b1014]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-4">
          <p className="text-xs text-gray-400" aria-live="polite">
            {loading ? "Loading indicators..." : page.total
              ? `${offset + 1}–${offset + page.indicators.length} of ${page.total} matching indicators`
              : "No matching indicators"}
          </p>
          <div className="flex gap-2">
            <button className={button} disabled={loading || offset === 0}
              onClick={() => setOffset(Math.max(0, offset - size))}>Previous</button>
            <button className={button} disabled={loading || page.next_offset === null}
              onClick={() => setOffset(page.next_offset)}>Next</button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-white/10 text-gray-400">
              <tr>{["Type", "Indicator", "Severity", "Confidence", "Source", "Status", "Actions"].map(label =>
                <th key={label} className="px-4 py-3">{label}</th>)}</tr>
            </thead>
            <tbody>
              {!loading && page.indicators.map(item => (
                <tr key={item.id} className="border-b border-white/5 text-gray-300">
                  <td className="px-4 py-4">{item.indicator_type}</td>
                  <td className="max-w-md break-all px-4 py-4 text-white">{item.value}</td>
                  <td className="px-4 py-4">{item.severity}</td>
                  <td className="px-4 py-4">{item.confidence}/100</td>
                  <td className="px-4 py-4">{item.source || "Not provided"}</td>
                  <td className="px-4 py-4">{item.enabled ? "Enabled" : "Disabled"}</td>
                  <td className="px-4 py-4">
                    <button className={button} disabled={toggleBusy} onClick={() => openDetails(item)}>
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      {selected && (
        <section aria-label="Indicator details"
          className="mt-5 rounded-lg border border-white/10 bg-[#0b1014] p-5">
          <div className="flex items-center justify-between gap-4">
            <h2 className="text-sm font-semibold text-white">Indicator Details</h2>
            <button className={button} disabled={toggleBusy} onClick={closeDetails}>Close Details</button>
          </div>
          <p className="mt-3 break-all text-sm text-white">{selected.value}</p>
          <dl className="mt-4 grid gap-4 text-xs sm:grid-cols-2">
            {[
              ["Type", selected.indicator_type],
              ["Severity", selected.severity],
              ["Recorded confidence", `${selected.confidence}/100`],
              ["Source", selected.source || "Not provided"],
              ["Description", selected.description || "Not provided"],
              ["Created", selected.created_at || "Unavailable"],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-gray-500">{label}</dt>
                <dd className="mt-1 break-words text-gray-200">{value}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-4 text-xs leading-6 text-gray-400">
            Details reflect the registry record when opened. Candidate matching checks
            up to the latest 500 authorized events. It does not query external reputation
            services, and a candidate match is not proof of malicious activity.
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <span className="text-xs text-gray-300">
              Status: {selected.enabled ? "Enabled" : "Disabled"}
            </span>
            <button className={button} disabled={toggleBusy}
              onClick={toggleIndicator}>
              {toggleBusy ? "Updating..." :
                selected.enabled ? "Disable Indicator" : "Enable Indicator"}
            </button>
          </div>
          {toggleError && (
            <p role="alert" className="mt-3 text-xs text-red-400">{toggleError}</p>
          )}
          <button className={`${button} mt-4`}
            disabled={!selected.enabled || matchState.loading || toggleBusy}
            onClick={checkMatches}>
            {matchState.loading ? "Checking..." : "Check Recent Events"}
          </button>
          {!selected.enabled && (
            <p className="mt-2 text-xs text-gray-500">Matching requires an enabled indicator.</p>
          )}
          {matchState.error && (
            <p role="alert" className="mt-3 text-xs text-red-400">{matchState.error}</p>
          )}
          {matchState.data && (
            <div role="status" className="mt-4 rounded border border-white/10 p-4 text-xs text-gray-300">
              <p>Candidate matches: {matchState.data.candidate_match_count}</p>
              <p className="mt-2">Events scanned: {matchState.data.events_scanned} / maximum 500</p>
              <p className="mt-2">{matchState.data.scope_message}</p>
              <p className="mt-2">{matchState.data.scan_scope}</p>
              <p className="mt-2 text-gray-500">
                Zero matches means none were found in this scanned subset.
              </p>
            </div>
          )}
        </section>
      )}

      <p className="mt-4 text-xs leading-6 text-gray-500">
        Registry severity and confidence are recorded assessments, not independently
        verified maliciousness. Totals cover your full registry; filters affect the table.
        Refreshes every 15 seconds.
      </p>
    </div>
  );
}
