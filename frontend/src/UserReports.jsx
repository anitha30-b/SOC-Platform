import { useEffect, useState } from "react";

const panel = "rounded-xl border border-slate-800 bg-[#0b1217] p-6";
const button = "rounded border border-slate-700 px-4 py-2 text-white disabled:opacity-40";
const cell = "border-b border-slate-800 px-4 py-4 text-left align-top";

const pages = {
  "reports-vulnerability": {
    title: "Vulnerability Reports",
    description: "Review current persisted findings and recorded vulnerability groupings. These views are live records, not separately generated vulnerability-report documents.",
    links: [["Review Security Findings", "findings"], ["Review Vulnerability Risk", "risk-vulnerabilities"], ["Open Generated Security Reports", "reports-security"]],
  },
  "reports-incidents": {
    title: "Incident Reports",
    description: "Review saved incident cases and their investigation history. A dedicated incident-report document generator is not available in the inspected interfaces.",
    links: [["Review Incident Cases", "incidents-cases"], ["Review Incident Timeline", "incidents-timeline"]],
  },
  "reports-risk": {
    title: "Risk Reports",
    description: "Review stored risk-assessment runs and the current risk overview. Generated complete VAPT reports include the risk data captured at generation time; current records may have changed since then.",
    links: [["Review Risk History", "risk-trends"], ["Open Risk Dashboard", "risk-dashboard"], ["Open Generated Security Reports", "reports-security"]],
  },
  "reports-scheduled": {
    title: "Scheduled Reports",
    description: "Report scheduling is unavailable. The inspected project has no report schedule API, scheduled-run history, or report delivery scheduler. Existing reports are generated manually.",
    links: [["Open Generated Security Reports", "reports-security"]],
  },
};

function date(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

export default function UserReports({ apiUrl, view, onNavigate }) {
  const library = view === "reports-security";
  const [data, setData] = useState(null);
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(library);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState("");

  useEffect(() => {
    if (!library) return;
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setData(null);
    setError("");

    const timer = window.setTimeout(async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Authentication required. Please log in again.");
        const params = new URLSearchParams({
          search, offset: String(offset), page_size: "25",
        });
        const response = await fetch(`${apiUrl}/vapt/reporting/history?${params}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Report history API returned ${response.status}.`);
        const body = await response.json();
        if (!Array.isArray(body.reports)) throw new Error("Unexpected report history response.");
        if (active) setData(body);
      } catch (err) {
        if (active && err.name !== "AbortError") setError(err.message);
      } finally {
        if (active) setLoading(false);
      }
    }, 250);

    return () => {
      active = false;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [apiUrl, library, search, offset, refresh]);

  async function download(report, format) {
    const key = `${report.report_run_id}-${format}`;
    setDownloading(key);
    setError("");
    try {
      const token = localStorage.getItem("token");
      if (!token) throw new Error("Authentication required. Please log in again.");
      const response = await fetch(
        `${apiUrl}/vapt/reporting/${encodeURIComponent(report.job_id)}/download/${format}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!response.ok) {
        let message = `Report download returned ${response.status}.`;
        try {
          const body = await response.json();
          if (typeof body.detail === "string") message = body.detail;
        } catch {}
        throw new Error(message);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const safeName = String(report.report_run_id).replace(/[^a-zA-Z0-9_-]/g, "_");
      link.href = url;
      link.download = `${safeName}.${format.toLowerCase()}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      setError(err.message || "Unable to download report.");
    } finally {
      setDownloading("");
    }
  }

  if (!library) {
    const page = pages[view];
    return (
      <div className="space-y-6 text-slate-200">
        <header>
          <p className="text-sm uppercase tracking-widest text-red-500">Reports</p>
          <h1 className="mt-3 text-3xl font-bold text-white">{page.title}</h1>
        </header>
        <section className={panel}>
          <p className="leading-7">{page.description}</p>
          <div className="mt-6 flex flex-wrap gap-3">
            {page.links.map(([label, route]) =>
              <button className={button} key={route} onClick={() => onNavigate(route)}>
                {label}
              </button>
            )}
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="space-y-6 text-slate-200">
      <header className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-widest text-red-500">Reports</p>
          <h1 className="mt-3 text-3xl font-bold text-white">Security Reports</h1>
        </div>
        <button className={button} disabled={loading}
          onClick={() => setRefresh((value) => value + 1)}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </header>

      <section className={panel}>
        <p>
          Persisted VAPT reports owned by your account, including when your account
          belongs to a client. Legacy PDFs stored in the separate Report table
          and browser-generated downloads are not included in this library.
        </p>
        <p className="mt-4">
          Downloads contain the report content captured at generation time.
          Available formats are listed for each completed report.
        </p>
        <p className="mt-4 text-slate-400">
          Generate complete reports through VAPT Stage 09 after completing its
          required risk assessment.
        </p>
        <button className={`${button} mt-5`} onClick={() => onNavigate("vapt")}>
          Open VAPT Reporting Workspace
        </button>
      </section>

      {error && <div role="alert" className="rounded border border-red-800 p-5 text-red-300">{error}</div>}

      <section className={panel}>
        <label className="block">
          Search report metadata
          <input maxLength={200} value={search} onChange={(event) => {
            setSearch(event.target.value); setOffset(0);
          }} className="mt-3 w-full rounded border border-slate-700 bg-transparent px-4 py-3 text-white" />
        </label>
        <div className="my-6 flex items-center justify-between gap-4">
          <p>{loading ? "Loading..." : data ? `${data.matched_total} matching reports · ${data.total} stored` : "No data loaded"}</p>
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
              {["Report", "Assessment", "Type", "Status", "Completed", "Download"].map(
                (label) => <th key={label} className={cell}>{label}</th>
              )}
            </tr></thead>
            <tbody>
              {data.reports.map((report) => <tr key={report.id}>
                <td className={cell}>{report.report_run_id}</td>
                <td className={cell}>{report.assessment_id}</td>
                <td className={cell}>{report.report_type}</td>
                <td className={cell}>{report.status}</td>
                <td className={cell}>{date(report.completed_at)}</td>
                <td className={cell}>
                  {report.status === "COMPLETED" && report.formats.length ? (
                    <div className="flex flex-wrap gap-2">
                      {report.formats.map((format) => <button
                        className={button}
                        disabled={Boolean(downloading)}
                        key={format}
                        onClick={() => download(report, format)}>
                        {downloading === `${report.report_run_id}-${format}` ? "Downloading..." : format}
                      </button>)}
                    </div>
                  ) : <span className="text-slate-500">No completed download</span>}
                </td>
              </tr>)}
              {!data.reports.length && <tr><td className={cell} colSpan={6}>
                No matching persisted VAPT reports.
              </td></tr>}
            </tbody>
          </table>
        </div>}
      </section>
    </div>
  );
}
