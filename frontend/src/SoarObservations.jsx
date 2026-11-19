import { useEffect, useMemo, useRef, useState } from "react";

const titles = {
  "soar-triggers": "Triggers",
  "soar-actions": "Actions",
  "soar-approvals": "Approvals",
  "soar-responses": "Response Actions",
};
const panel = "rounded-xl border border-slate-800 bg-[#0b1217] p-6";
const button = "rounded border border-slate-700 px-5 py-3 text-white disabled:opacity-40";
const cell = "border-b border-slate-800 px-4 py-4 text-left align-top";
const scalar = (value) =>
  typeof value === "string" || typeof value === "number"
    ? String(value)
    : "—";

export default function SoarObservations({ apiUrl, view }) {
  const approvals = view === "soar-approvals";
  const responses = view === "soar-responses";
  const actions = view === "soar-actions";
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(!approvals);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [eventCount, setEventCount] = useState(0);
  const [malformedCount, setMalformedCount] = useState(0);
  const [selected, setSelected] = useState(null);
  const detailsRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
    if (approvals) return;
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError("");
    setSelected(null);
    setRecords([]);

    async function load() {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Authentication required. Please log in again.");
        const path = responses ? "/security-events?limit=500" : "/security-events/rules";
        const response = await fetch(`${apiUrl}${path}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(`SOAR data request returned ${response.status}.`);
        }
        const body = await response.json();
        let rows = [];
        let examined = 0;
        let malformed = 0;

        if (responses) {
          // Accept the existing event API's array or named event collection.
          const events = Array.isArray(body) ? body : body?.events;
          if (!Array.isArray(events)) {
            throw new Error("Unexpected event response. No action records were loaded.");
          }
          examined = events.length;
          for (const event of events) {
            const list = event?.response_actions;
            if (list == null) continue;
            if (!Array.isArray(list)) {
              malformed += 1;
              continue;
            }
            list.forEach((action, index) => {
              if (!action || typeof action !== "object" || Array.isArray(action)) {
                malformed += 1;
                return;
              }
              // Project known fields only; do not display the entire raw event.
              rows.push({
                key: `${event.id ?? event.event_id ?? "event"}-${rows.length}-${index}`,
                event_id: scalar(event.event_id ?? event.id),
                timestamp: scalar(event.timestamp),
                event_type: scalar(event.event_type),
                action: scalar(action.action),
                ip: scalar(action.ip),
                chain: scalar(action.chain),
                reason: scalar(action.reason),
                result: action.success === true
                  ? "Reported success"
                  : action.success === false
                    ? "Reported failure"
                    : "Result unspecified",
              });
            });
          }
        } else {
          if (!Array.isArray(body?.rules)) {
            throw new Error("Unexpected rule response. No rules were loaded.");
          }
          rows = body.rules.map((rule, index) => ({
            key: `${rule.rule_id ?? "rule"}-${index}`,
            rule_id: scalar(rule.rule_id),
            name: scalar(rule.name),
            severity: scalar(rule.severity),
            event_types: Array.isArray(rule.event_types)
              ? rule.event_types.filter((value) => typeof value === "string").join(", ")
              : "—",
            group_by: scalar(rule.group_by),
            threshold: scalar(rule.threshold),
            window_seconds: scalar(rule.window_seconds),
            unique_field: scalar(rule.unique_field),
            unique_threshold: scalar(rule.unique_threshold),
            response: typeof rule.response === "string" && rule.response.trim()
              ? rule.response
              : "No response label",
          }));
        }

        if (active) {
          setRecords(rows);
          setEventCount(examined);
          setMalformedCount(malformed);
          setPage(0);
        }
      } catch (err) {
        if (active && err.name !== "AbortError") {
          setError(err.message || "Unable to load SOAR records.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
      controller.abort();
    };
  }, [apiUrl, approvals, responses, refresh]);

  useEffect(() => {
    if (selected) {
      detailsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      detailsRef.current?.focus({ preventScroll: true });
    }
  }, [selected]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return records.filter((row) =>
      Object.entries(row).some(([key, value]) =>
        key !== "key" && String(value).toLowerCase().includes(query)
      )
    );
  }, [records, search]);
  const pages = Math.max(1, Math.ceil(filtered.length / 25));
  const currentPage = Math.min(page, pages - 1);
  const visible = filtered.slice(currentPage * 25, currentPage * 25 + 25);

  const columns = responses
    ? [["Event", "event_id"], ["Recorded time", "timestamp"], ["Action", "action"],
       ["IP", "ip"], ["Reported result", "result"]]
    : actions
      ? [["Rule", "rule_id"], ["Name", "name"], ["Response label", "response"]]
      : [["Rule", "rule_id"], ["Name", "name"], ["Event types", "event_types"],
         ["Threshold", "threshold"], ["Window (seconds)", "window_seconds"]];
  const detailFields = responses
    ? [["Event", "event_id"], ["Recorded time", "timestamp"], ["Event type", "event_type"],
       ["Action", "action"], ["IP", "ip"], ["Reported result", "result"],
       ["Chain", "chain"], ["Reason", "reason"]]
    : [["Rule", "rule_id"], ["Name", "name"], ["Severity", "severity"],
       ["Event types", "event_types"], ["Grouping", "group_by"],
       ["Threshold", "threshold"], ["Window (seconds)", "window_seconds"],
       ["Unique field", "unique_field"], ["Unique threshold", "unique_threshold"],
       ["Response label", "response"]];

  return (
    <div className="space-y-6 text-slate-200">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-widest text-red-500">SOAR / Automation</p>
          <h1 className="mt-3 text-3xl font-bold text-white">{titles[view]}</h1>
        </div>
        {!approvals && <button className={button} disabled={loading}
          onClick={() => setRefresh((value) => value + 1)}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>}
      </div>

      <section className={panel}>
        {approvals ? <>
          <h2 className="text-xl font-semibold text-white">Approval Queue Unavailable</h2>
          <p className="mt-4">
            The inspected interfaces do not provide an approval request, reviewer
            decision, or approval history API. Incident notes and assignment are
            not approval records.
          </p>
        </> : responses ? <>
          <p>
            Response-action entries embedded in up to the latest 500 authorized
            security events across all dates. This is a bounded event sample,
            not a complete response audit log.
          </p>
          <p className="mt-4">
            Results describe what the recorded handler reported at that time.
            They do not verify the current firewall state or identify a target endpoint.
          </p>
          {!loading && !error && <p className="mt-4">
            {eventCount} events returned · {records.length} action entries
            {eventCount === 500 ? " · Event limit reached; older records may be excluded." : ""}
          </p>}
          {malformedCount > 0 && <p className="mt-3 text-amber-300">
            {malformedCount} malformed response-action fields or entries were excluded.
          </p>}
        </> : <>
          <p>{actions
            ? "Response labels returned by the existing SIEM rule API. Rules without a response label are included for visibility."
            : "Detection conditions returned by the existing SIEM rule API, including thresholds, time windows, grouping, and uniqueness fields where supplied."}</p>
          <p className="mt-4">
            Rule configuration does not prove an action executed. The inspected
            telemetry ingestion path disables automatic responses; the correlation
            engine has a separate response-capable path.
          </p>
        </>}
      </section>

      {error && <div role="alert" className="rounded border border-red-800 p-5 text-red-300">{error}</div>}

      {!approvals && <section className={panel}>
        <label className="block">
          Search returned records
          <input value={search} onChange={(event) => {
            setSearch(event.target.value); setPage(0);
          }} className="mt-3 w-full rounded border border-slate-700 bg-transparent px-4 py-3 text-white" />
        </label>
        <div className="my-6 flex items-center justify-between gap-4">
          <p>{loading ? "Loading..." : `${filtered.length} matching returned records`}</p>
          <div className="flex gap-3">
            <button className={button} disabled={currentPage === 0}
              onClick={() => setPage(currentPage - 1)}>Previous</button>
            <button className={button} disabled={currentPage >= pages - 1}
              onClick={() => setPage(currentPage + 1)}>Next</button>
          </div>
        </div>
        {!loading && !error && <div className="overflow-x-auto">
          <table className="w-full min-w-[850px]">
            <thead><tr className="text-slate-400">
              {columns.map(([label, key]) => <th key={key} className={cell}>{label}</th>)}
              <th className={cell}>Details</th>
            </tr></thead>
            <tbody>
              {visible.map((row) => <tr key={row.key}>
                {columns.map(([, key]) => <td key={key} className={cell}>{row[key]}</td>)}
                <td className={cell}><button className={button} onClick={(event) => {
                  triggerRef.current = event.currentTarget;
                  setSelected(row);
                }}>Details</button></td>
              </tr>)}
              {!visible.length && <tr><td className={cell} colSpan={columns.length + 1}>
                No matching records returned.
                {responses ? " This does not establish that no response actions occurred." : ""}
              </td></tr>}
            </tbody>
          </table>
        </div>}
      </section>}

      {selected && <section ref={detailsRef} tabIndex={-1}
        style={{ scrollMarginTop: 110 }} className={panel}>
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-xl font-semibold">Recorded Details</h2>
          <button className={button} onClick={() => {
            setSelected(null); triggerRef.current?.focus();
          }}>Close</button>
        </div>
        <dl className="mt-5 grid gap-5 md:grid-cols-2">
          {detailFields.map(([label, key]) => <div key={key}>
            <dt className="text-sm text-slate-400">{label}</dt>
            <dd className="mt-2 whitespace-pre-wrap break-words">{selected[key]}</dd>
          </div>)}
        </dl>
      </section>}
    </div>
  );
}
