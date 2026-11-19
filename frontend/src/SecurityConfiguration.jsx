import { useEffect, useMemo, useRef, useState } from "react";

const TITLES = {
  baselines: "Security Baselines",
  hardening: "Hardening",
  cis: "CIS Benchmarks",
  linux: "Linux Configuration",
  windows: "Windows Configuration",
  web: "Web Server Configuration",
  drift: "Configuration Drift",
};

const UNAVAILABLE = {
  baselines: [
    "Security Baseline Assessment Unavailable",
    "Recorded hardening controls are available on the Hardening page. This view needs a versioned baseline with expected values and an explicit mapping from collected controls to that baseline.",
  ],
  cis: [
    "CIS Assessment Unavailable",
    "Collected hardening statuses do not establish CIS compliance. This view needs a named benchmark, its version and profile, and recorded results mapped to benchmark control identifiers.",
  ],
  web: [
    "Web Server Configuration Telemetry Unavailable",
    "The inspected server configuration API provides operating-system and hardware properties. It does not provide Apache, Nginx, or IIS configuration assessments.",
  ],
  drift: [
    "Configuration Drift Comparison Unavailable",
    "The inspected ingestion code updates the latest configuration and hardening records. Drift comparison needs retained historical snapshots and a defined reference snapshot or baseline.",
  ],
};

const panel = "rounded-xl border border-slate-800 bg-[#0b1217] p-6";
const button = "rounded border border-slate-700 px-5 py-3 text-white disabled:opacity-40";
const field = "w-full rounded border border-slate-700 bg-transparent px-4 py-3 text-white";
const cell = "border-b border-slate-800 px-4 py-4 text-left align-top";
const show = (value) => value == null || value === "" ? "—" : String(value);

function date(value) {
  if (!value) return "—";
  const text = String(value);
  const parsed = new Date(
    /(?:Z|[+-]\d{2}:\d{2})$/i.test(text) ? text : `${text}Z`
  );
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

function osFamily(value) {
  const name = String(value || "").trim().toLowerCase();
  if (/\bwindows\b/.test(name)) return "windows";
  if (/\b(linux|ubuntu|debian|kali|centos|fedora|rhel|red hat|rocky|alma|almalinux|arch|suse|opensuse|oracle linux|amazon linux)\b/.test(name)) {
    return "linux";
  }
  return "unknown";
}

export default function SecurityConfiguration({ apiUrl, view }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(null);
  const detailRef = useRef(null);
  const triggerRef = useRef(null);
  const unavailable = UNAVAILABLE[view];
  const hardening = view === "hardening";

  useEffect(() => {
    setSearch("");
    setStatus("all");
    setPage(0);
    setSelected(null);
    setData(null);
    setError("");
  }, [view]);

  useEffect(() => {
    if (unavailable) return;
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setData(null);
    setSelected(null);
    setError("");

    async function load() {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Authentication required. Please log in again.");
        const endpoint = hardening ? "system-hardening" : "server-configuration";
        const response = await fetch(`${apiUrl}/client/${endpoint}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(
            response.status === 401 || response.status === 403
              ? "Your session is not authorized. Please log in again."
              : `Configuration API returned ${response.status}.`
          );
        }
        const payload = await response.json();
        const key = hardening ? "controls" : "configurations";
        if (!Array.isArray(payload[key])) {
          throw new Error("The configuration API returned an unexpected response.");
        }
        if (active) setData(payload);
      } catch (err) {
        if (active && err.name !== "AbortError") {
          setError(err.message || "Unable to load configuration data.");
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
  }, [apiUrl, view, hardening, unavailable, reload]);

  useEffect(() => {
    if (selected) {
      detailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      detailRef.current?.focus({ preventScroll: true });
    }
  }, [selected]);

  const records = useMemo(() => {
    const all = hardening ? data?.controls : data?.configurations;
    if (!Array.isArray(all)) return [];
    return hardening ? all : all.filter((row) => osFamily(row.os_name) === view);
  }, [data, hardening, view]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return records.filter((row) => {
      const values = hardening
        ? [row.control_id, row.control_name, row.category, row.hostname, row.endpoint_id, row.status]
        : [row.hostname, row.endpoint_id, row.os_name, row.os_version, row.architecture];
      const matches = !query || values.some(
        (value) => String(value ?? "").toLowerCase().includes(query)
      );
      return matches && (
        !hardening || status === "all" || String(row.status || "").toUpperCase() === status
      );
    });
  }, [records, search, status, hardening]);

  const pages = Math.max(1, Math.ceil(filtered.length / 25));
  const currentPage = Math.min(page, pages - 1);
  const displayed = filtered.slice(currentPage * 25, currentPage * 25 + 25);
  const statuses = [...new Set(records.map(
    (row) => String(row.status || "UNKNOWN").toUpperCase()
  ))].sort();
  const endpoints = new Set(records.map((row) => row.endpoint_asset_id)).size;
  const unknownOS = Array.isArray(data?.configurations)
    ? data.configurations.filter((row) => osFamily(row.os_name) === "unknown").length
    : 0;

  const detailFields = hardening ? [
    ["Control ID", "control_id"], ["Control", "control_name"],
    ["Category", "category"], ["Status", "status"],
    ["Endpoint", "endpoint_id"], ["Hostname", "hostname"],
    ["Operating system", "os_name"], ["OS version", "os_version"],
    ["Observed value", "observed_value"], ["Details", "details"],
  ] : [
    ["Endpoint", "endpoint_id"], ["Hostname", "hostname"],
    ["Operating system", "os_name"], ["OS version", "os_version"],
    ["Architecture", "architecture"], ["Processor", "processor"],
    ["Memory (GB)", "memory_total_gb"], ["Disk total (GB)", "disk_total_gb"],
    ["Disk free (GB)", "disk_free_gb"], ["Disk usage (%)", "disk_usage_percent"],
    ["Uptime", "uptime"], ["Timezone", "timezone"],
    ["Domain or workgroup", "domain_or_workgroup"],
    ["Windows edition", "windows_edition"], ["Power plan", "power_plan"],
  ];

  return (
    <div className="space-y-6 text-slate-200">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-widest text-red-500">Security Configuration</p>
          <h1 className="mt-3 text-3xl font-bold text-white">{TITLES[view]}</h1>
        </div>
        {!unavailable && <button
          className={button}
          disabled={loading}
          onClick={() => { setPage(0); setReload((value) => value + 1); }}
        >{loading ? "Refreshing..." : "Refresh"}</button>}
      </div>

      {unavailable ? (
        <div className={panel}>
          <h2 className="text-xl font-semibold text-white">{unavailable[0]}</h2>
          <p className="mt-5 leading-7">{unavailable[1]}</p>
        </div>
      ) : (
        <>
          <div className={panel}>
            <p>{hardening
              ? "Latest persisted hardening observations reported by registered endpoints. PASS, WARN, and FAIL are recorded collector labels; they are not a CIS certification or a comparison with an approved baseline."
              : "Latest persisted configuration properties, filtered by the reported operating-system name. These properties are an inventory snapshot, not a security compliance assessment."}</p>
            <p className="mt-4">Scope: {data?.scope || "—"}. Last-seen timestamps indicate when telemetry was recorded.</p>
            {!hardening && <p className="mt-4 text-slate-400">
              OS classification uses reported names. {unknownOS} configuration records have an unrecognized or missing OS label and are excluded from this OS-specific view.
            </p>}
          </div>

          {error && <div role="alert" className="rounded border border-red-800 bg-red-950/20 p-5 text-red-300">{error}</div>}

          {data && <div className="grid gap-4 sm:grid-cols-2">
            <div className={panel}>
              <p className="text-slate-400">{hardening ? "Recorded controls" : "Configuration records"}</p>
              <p className="mt-3 text-3xl font-bold text-white">{records.length}</p>
            </div>
            <div className={panel}>
              <p className="text-slate-400">Endpoints represented</p>
              <p className="mt-3 text-3xl font-bold text-white">{endpoints}</p>
            </div>
          </div>}

          <div className={panel}>
            <label className="block">
              Search recorded metadata
              <input className={`${field} mt-3`} value={search} onChange={(event) => {
                setSearch(event.target.value); setPage(0);
              }} />
            </label>
            {hardening && <label className="mt-4 block">
              Recorded status
              <select className={`${field} mt-2`} value={status} onChange={(event) => {
                setStatus(event.target.value); setPage(0);
              }}>
                <option className="bg-slate-900" value="all">All statuses</option>
                {statuses.map((value) => <option className="bg-slate-900" key={value}>{value}</option>)}
              </select>
            </label>}

            <div className="my-6 flex items-center justify-between gap-4">
              <p>{data ? `${filtered.length} matching records` : "No data loaded"}</p>
              <div className="flex gap-3">
                <button className={button} disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
                <button className={button} disabled={currentPage >= pages - 1} onClick={() => setPage(currentPage + 1)}>Next</button>
              </div>
            </div>

            {loading ? <p>Loading recorded configuration data...</p> : data && (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[800px]">
                  <thead><tr className="text-slate-400">
                    <th className={cell}>{hardening ? "Control" : "Hostname"}</th>
                    <th className={cell}>Endpoint</th>
                    <th className={cell}>{hardening ? "Category" : "Operating system"}</th>
                    <th className={cell}>{hardening ? "Status" : "OS version"}</th>
                    <th className={cell}>Last seen</th>
                    <th className={cell}>Details</th>
                  </tr></thead>
                  <tbody>
                    {displayed.map((row) => <tr key={row.id}>
                      <td className={cell}>{show(hardening ? row.control_name : row.hostname)}</td>
                      <td className={cell}>{show(row.endpoint_id)}</td>
                      <td className={cell}>{show(hardening ? row.category : row.os_name)}</td>
                      <td className={cell}>{show(hardening ? row.status : row.os_version)}</td>
                      <td className={cell}>{date(row.last_seen)}</td>
                      <td className={cell}><button className={button} onClick={(event) => {
                        triggerRef.current = event.currentTarget; setSelected(row);
                      }}>Details</button></td>
                    </tr>)}
                    {!displayed.length && <tr><td className={cell} colSpan={6}>
                      No matching recorded telemetry. This does not establish that endpoints are securely configured.
                    </td></tr>}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {selected && <section
            ref={detailRef}
            tabIndex={-1}
            style={{ scrollMarginTop: 110 }}
            className={panel}
          >
            <div className="flex items-center justify-between gap-4">
              <h2 className="text-xl font-semibold">Recorded Details</h2>
              <button className={button} onClick={() => {
                setSelected(null); triggerRef.current?.focus();
              }}>Close</button>
            </div>
            <dl className="mt-5 grid gap-5 md:grid-cols-2">
              {detailFields.map(([label, key]) => <div key={key}>
                <dt className="text-sm text-slate-400">{label}</dt>
                <dd className="mt-2 whitespace-pre-wrap break-words">{show(selected[key])}</dd>
              </div>)}
              <div><dt className="text-sm text-slate-400">First seen</dt><dd className="mt-2">{date(selected.first_seen)}</dd></div>
              <div><dt className="text-sm text-slate-400">Last seen</dt><dd className="mt-2">{date(selected.last_seen)}</dd></div>
            </dl>
          </section>}
        </>
      )}
      <p className="text-sm text-slate-500">This page displays recorded information. It does not apply configuration changes.</p>
    </div>
  );
}
