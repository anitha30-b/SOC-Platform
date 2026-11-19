import { useEffect, useRef, useState } from "react";

const panel = "rounded-xl border border-slate-800 bg-[#0b1217] p-6";
const button = "rounded border border-slate-700 px-5 py-3 text-white disabled:opacity-40";
const cell = "border-b border-slate-800 px-4 py-4 text-left align-top";

function show(value) {
  return typeof value === "string" || typeof value === "number"
    ? String(value)
    : "—";
}

function date(value) {
  if (!value) return "—";
  const text = String(value);
  const parsed = new Date(
    /(?:Z|[+-]\d{2}:\d{2})$/i.test(text) ? text : `${text}Z`
  );
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

const fields = [
  ["Run ID", "id"], ["Job ID", "job_id"],
  ["Assessment", "assessment_id"], ["Target", "target"],
  ["Scan type", "scan_type"], ["Status", "status"],
  ["Reported hosts", "host_count"], ["Reported open ports", "open_port_count"],
  ["Started", "started_at"], ["Completed", "completed_at"],
  ["Created", "created_at"], ["Updated", "updated_at"],
];

export default function TestingScanHistory({ apiUrl }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(null);
  const detailsRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError("");
    setData(null);
    setSelected(null);

    async function load() {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Authentication required. Please log in again.");
        const response = await fetch(`${apiUrl}/client/asset-discovery`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Discovery history API returned ${response.status}.`);
        const payload = await response.json();
        if (!Array.isArray(payload.runs)) throw new Error("Unexpected discovery history response.");

        // Display metadata only, excluding raw scanner result objects.
        const runs = payload.runs.map((run) =>
          Object.fromEntries(fields.map(([, key]) => [key, run[key]]))
        );
        if (active) {
          setData({ scope: payload.scope, runs });
          setPage(0);
        }
      } catch (err) {
        if (active && err.name !== "AbortError") setError(err.message);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
      controller.abort();
    };
  }, [apiUrl, refresh]);

  useEffect(() => {
    if (selected) {
      detailsRef.current?.focus({ preventScroll: true });
      detailsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [selected]);

  const query = search.trim().toLowerCase();
  const filtered = (data?.runs || []).filter((row) =>
    !query || fields.some(([, key]) =>
      show(row[key]).toLowerCase().includes(query)
    )
  );
  const pages = Math.max(1, Math.ceil(filtered.length / 25));
  const currentPage = Math.min(page, pages - 1);
  const visible = filtered.slice(currentPage * 25, currentPage * 25 + 25);

  return (
    <div className="space-y-6 text-slate-200">
      <header className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-widest text-red-500">Security Testing</p>
          <h1 className="mt-3 text-3xl font-bold text-white">Scan History</h1>
        </div>
        <button className={button} disabled={loading}
          onClick={() => setRefresh((value) => value + 1)}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </header>

      <section className={panel}>
        <h2 className="text-xl font-semibold text-white">Persisted Network Discovery Runs</h2>
        <p className="mt-4">
          This view lists stored Nmap discovery runs from the existing discovery
          API. It is not a combined history of every VAPT tool or code scan.
          ZAP's browser-local history remains in its existing results page.
        </p>
        <p className="mt-4">
          Scope: {show(data?.scope)}. Counts describe each recorded run;
          repeated observations across runs are not unique hosts or ports.
        </p>
        <p className="mt-4 text-slate-400">
          Opening or refreshing this history does not start a scan.
        </p>
      </section>

      {error && <div role="alert" className="rounded border border-red-800 p-5 text-red-300">{error}</div>}

      <section className={panel}>
        <label className="block">
          Search discovery run metadata
          <input value={search} onChange={(event) => {
            setSearch(event.target.value); setPage(0);
          }} className="mt-3 w-full rounded border border-slate-700 bg-transparent px-4 py-3 text-white" />
        </label>
        <div className="my-6 flex items-center justify-between gap-4">
          <p>{loading ? "Loading..." : data ? `${filtered.length} matching runs` : "No data loaded"}</p>
          <div className="flex gap-3">
            <button className={button} disabled={loading || currentPage === 0}
              onClick={() => setPage(currentPage - 1)}>Previous</button>
            <button className={button} disabled={loading || currentPage >= pages - 1}
              onClick={() => setPage(currentPage + 1)}>Next</button>
          </div>
        </div>

        {data && <div className="overflow-x-auto">
          <table className="w-full min-w-[900px]">
            <thead><tr className="text-slate-400">
              {["Run", "Target", "Assessment", "Status", "Hosts", "Open ports", "Updated", "Details"].map(
                (label) => <th className={cell} key={label}>{label}</th>
              )}
            </tr></thead>
            <tbody>
              {visible.map((row) => <tr key={row.id}>
                <td className={cell}>{show(row.id)}</td>
                <td className={cell}>{show(row.target)}</td>
                <td className={cell}>{show(row.assessment_id)}</td>
                <td className={cell}>{show(row.status)}</td>
                <td className={cell}>{show(row.host_count)}</td>
                <td className={cell}>{show(row.open_port_count)}</td>
                <td className={cell}>{date(row.updated_at)}</td>
                <td className={cell}><button className={button} onClick={(event) => {
                  triggerRef.current = event.currentTarget; setSelected(row);
                }}>Details</button></td>
              </tr>)}
              {!visible.length && <tr><td className={cell} colSpan={8}>
                No matching persisted discovery runs.
              </td></tr>}
            </tbody>
          </table>
        </div>}
      </section>

      {selected && <section ref={detailsRef} tabIndex={-1}
        style={{ scrollMarginTop: 110 }} className={panel}>
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-xl font-semibold">Recorded Run Details</h2>
          <button className={button} onClick={() => {
            setSelected(null); triggerRef.current?.focus();
          }}>Close</button>
        </div>
        <dl className="mt-5 grid gap-5 md:grid-cols-2">
          {fields.map(([label, key]) => <div key={key}>
            <dt className="text-sm text-slate-400">{label}</dt>
            <dd className="mt-2 break-words">
              {key.endsWith("_at") ? date(selected[key]) : show(selected[key])}
            </dd>
          </div>)}
        </dl>
      </section>}
    </div>
  );
}
