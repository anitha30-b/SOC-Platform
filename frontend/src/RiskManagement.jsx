import { useEffect, useRef, useState } from "react";

const definitions = {
  "risk-assets": {
    title: "Asset Risk", kind: "assets",
    note: "Findings grouped by their exact recorded asset label. These labels are not verified unique inventory assets. Counts include all recorded statuses; they do not measure asset criticality or business impact.",
    columns: [["Asset label", "label"], ["Findings", "findings"], ["High / critical", "high_critical"], ["Scored findings", "scored_findings"], ["Highest CVSS", "highest_cvss"]],
  },
  "risk-vulnerabilities": {
    title: "Vulnerability Risk", kind: "vulnerabilities",
    note: "Findings grouped by scanner and recorded vulnerability label, falling back to the finding title. Groups are not deduplicated vulnerabilities across scanners or assessments. Counts include all statuses.",
    columns: [["Recorded label", "label"], ["Tool", "tool_name"], ["Findings", "findings"], ["High / critical", "high_critical"], ["Highest CVSS", "highest_cvss"]],
  },
  "risk-register": {
    title: "Risk Register", kind: "register",
    note: "A read-only register of your persisted security findings. This is not a business risk register with risk owners, likelihood, treatment plans, or acceptance approvals. Severity, risk level, and status are stored labels.",
    columns: [["Finding", "finding_id"], ["Title", "title"], ["Asset label", "affected_asset"], ["Severity", "severity"], ["Status", "status"], ["CVSS", "cvss_score"]],
  },
  "risk-trends": {
    title: "Risk Trends", kind: "trends",
    note: "Persisted risk-assessment runs, newest created first. Compare runs only after considering their assessment, scope, and finding population. This history does not establish a continuous trend or improvement. Unfinished runs have no completed measurements.",
    columns: [["Run", "assessment_run_id"], ["Assessment", "assessment_id"], ["Status", "status"], ["Run classification", "overall_risk"], ["Findings", "total_findings"], ["Completed", "completed_at"]],
  },
};
const panel = "rounded-xl border border-slate-800 bg-[#0b1217] p-6";
const button = "rounded border border-slate-700 px-5 py-3 text-white disabled:opacity-40";
const cell = "border-b border-slate-800 px-4 py-4 text-left align-top";

function display(value) {
  if (value == null || value === "") return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

export default function RiskManagement({ apiUrl, view }) {
  const definition = definitions[view];
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [reload, setReload] = useState(0);
  const [selected, setSelected] = useState(null);
  const detailRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError("");
    setData(null);
    setSelected(null);

    const timer = window.setTimeout(async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Authentication required. Please log in again.");
        const params = new URLSearchParams({
          view: definition.kind, search, offset: String(offset), page_size: "25",
        });
        const response = await fetch(
          `${apiUrl}/vapt/risk-assessment/management?${params}`,
          {
            headers: { Authorization: `Bearer ${token}` },
            signal: controller.signal,
          }
        );
        if (!response.ok) throw new Error(`Risk API returned ${response.status}.`);
        const payload = await response.json();
        if (!Array.isArray(payload.rows)) throw new Error("Unexpected risk API response.");
        if (active) setData(payload);
      } catch (err) {
        if (active && err.name !== "AbortError") setError(err.message);
      } finally {
        if (active) setLoading(false);
      }
    }, 250);

    return () => {
      active = false;
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [apiUrl, definition.kind, search, offset, reload]);

  useEffect(() => {
    if (selected) {
      detailRef.current?.focus({ preventScroll: true });
      detailRef.current?.scrollIntoView({ block: "start", behavior: "smooth" });
    }
  }, [selected]);

  return (
    <div className="space-y-6 text-slate-200">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-widest text-red-500">Risk Management</p>
          <h1 className="mt-3 text-3xl font-bold text-white">{definition.title}</h1>
        </div>
        <button className={button} disabled={loading}
          onClick={() => setReload((value) => value + 1)}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      <div className={panel}>
        <p>{definition.note}</p>
        <p className="mt-4">
          Personal ownership, including when your account belongs to a client.
          Missing CVSS is shown as unavailable.
        </p>
        {data && <p className="mt-4 text-slate-400">
          {data.total} {definition.kind === "trends" ? "stored runs" : "records or groups"}
          {data.finding_count != null ? ` · ${data.finding_count} findings represented` : ""}
          {data.excluded_invalid_cvss > 0
            ? ` · ${data.excluded_invalid_cvss} invalid CVSS values excluded`
            : ""}
        </p>}
      </div>

      {error && <div role="alert" className="rounded border border-red-800 p-5 text-red-300">{error}</div>}

      <section className={panel}>
        <label className="block">
          Search metadata
          <input className="mt-3 w-full rounded border border-slate-700 bg-transparent px-4 py-3 text-white"
            maxLength={200} value={search} onChange={(event) => {
              setSearch(event.target.value); setOffset(0);
            }} />
        </label>
        <div className="my-6 flex items-center justify-between gap-4">
          <p>{loading ? "Loading..." : data ? `${data.matched_total} matching records` : "No data loaded"}</p>
          <div className="flex gap-3">
            <button className={button} disabled={loading || offset === 0}
              onClick={() => setOffset(Math.max(0, offset - 25))}>Previous</button>
            <button className={button} disabled={loading || data?.next_offset == null}
              onClick={() => setOffset(data.next_offset)}>Next</button>
          </div>
        </div>

        {data && <div className="overflow-x-auto">
          <table className="w-full min-w-[900px]">
            <thead><tr className="text-slate-400">
              {definition.columns.map(([label, key]) => <th className={cell} key={key}>{label}</th>)}
              <th className={cell}>Details</th>
            </tr></thead>
            <tbody>
              {data.rows.map((row, index) => <tr key={row.id ?? `${offset}-${index}`}>
                {definition.columns.map(([, key]) =>
                  <td className={`${cell} break-words`} key={key}>{display(row[key])}</td>
                )}
                <td className={cell}><button className={button} onClick={(event) => {
                  triggerRef.current = event.currentTarget; setSelected(row);
                }}>Details</button></td>
              </tr>)}
              {!data.rows.length && <tr><td className={cell} colSpan={definition.columns.length + 1}>
                No matching stored records. This does not establish that risk is absent.
              </td></tr>}
            </tbody>
          </table>
        </div>}
      </section>

      {selected && <section ref={detailRef} tabIndex={-1}
        style={{ scrollMarginTop: 110 }} className={panel}>
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold">Recorded Details</h2>
          <button className={button} onClick={() => {
            setSelected(null); triggerRef.current?.focus();
          }}>Close</button>
        </div>
        <dl className="mt-5 grid gap-5 md:grid-cols-2">
          {Object.entries(selected).filter(([key]) => key !== "id").map(([key, value]) =>
            <div key={key}>
              <dt className="text-sm text-slate-400">{key.replaceAll("_", " ")}</dt>
              <dd className="mt-2 whitespace-pre-wrap break-words">{display(value)}</dd>
            </div>
          )}
        </dl>
      </section>}
    </div>
  );
}
