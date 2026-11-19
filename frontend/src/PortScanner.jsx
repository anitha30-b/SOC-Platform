import { useEffect, useRef, useState } from "react";

const panel = "rounded-xl border border-slate-800 bg-[#0d1117] p-6";
const button = "rounded-lg border border-red-700 bg-red-700/20 px-5 py-3 text-white disabled:opacity-40";
const input = "w-full rounded-lg border border-slate-700 bg-[#080b10] px-4 py-3 text-white";
const cell = "border-b border-slate-800 px-4 py-4 text-left align-top";
const terminal = new Set(["completed", "failed", "timeout", "cancelled", "canceled"]);
const text = (value) =>
  typeof value === "string" || typeof value === "number" ? String(value) : "—";

async function request(url, options = {}) {
  const token = localStorage.getItem("token");
  if (!token) throw new Error("Authentication required. Please log in again.");

  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
  });

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Scanner API returned an unreadable response (${response.status}).`);
  }

  if (!response.ok) {
    const detail = payload?.detail;
    const message = typeof detail === "string"
      ? detail
      : Array.isArray(detail)
        ? detail.map((item) => item.msg || "Invalid request").join("; ")
        : `Scanner API returned ${response.status}.`;
    throw new Error(message);
  }
  return payload;
}

export default function PortScanner({
  apiUrl,
  title = "Port Scanner",
  initialProfile = "quick",
}) {
  const [target, setTarget] = useState("");
  const serviceMode = initialProfile === "service";
  const profile = serviceMode ? "service" : "quick";
  const [starting, setStarting] = useState(false);
  const [jobId, setJobId] = useState(null);
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  const [retry, setRetry] = useState(0);
  const [openOnly, setOpenOnly] = useState(true);
  const [page, setPage] = useState(0);
  const submitting = useRef(false);
  const mounted = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  const status = String(job?.status || "ready").toLowerCase();
  const running = Boolean(jobId) && !terminal.has(status);
  const busy = starting || running;

  async function startScan(event) {
    event.preventDefault();
    if (submitting.current || busy || !target.trim()) return;
    submitting.current = true;
    setStarting(true);
    setError("");
    setPollError("");
    setJob(null);
    setJobId(null);
    setPage(0);

    try {
      const payload = await request(`${apiUrl}/vapt/tools/run-async`, {
        method: "POST",
        body: JSON.stringify({ target: target.trim(), scan_type: profile }),
      });
      if (typeof payload?.job_id !== "string" || !payload.job_id) {
        throw new Error("The scanner did not return a job ID.");
      }
      if (mounted.current) {
        setJob({
          ...payload,
          status: payload.status || "queued",
          stage: "Scan queued",
          target: payload.target || target.trim(),
        });
        setJobId(payload.job_id);
      }
    } catch (err) {
      if (mounted.current) {
        setError(`${err.message} If submission was interrupted, the server may still have started a job.`);
      }
    } finally {
      submitting.current = false;
      if (mounted.current) setStarting(false);
    }
  }

  useEffect(() => {
    if (!jobId) return;
    const controller = new AbortController();
    let active = true;
    let timer;

    async function poll() {
      try {
        const payload = await request(
          `${apiUrl}/vapt/tools/progress/${encodeURIComponent(jobId)}`,
          { signal: controller.signal }
        );
        if (!active) return;
        if (!payload || typeof payload.status !== "string") {
          throw new Error("Unexpected scanner progress response.");
        }
        setJob(payload);
        setPollError("");
        if (!terminal.has(payload.status.toLowerCase())) {
          timer = window.setTimeout(poll, 1500);
        }
      } catch (err) {
        if (active && err.name !== "AbortError") {
          setPollError(err.message);
        }
      }
    }

    poll();
    return () => {
      active = false;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [apiUrl, jobId, retry]);

  const result = job?.result;
  const hosts = Array.isArray(result?.results?.hosts) ? result.results.hosts : [];
  const ports = hosts.flatMap((host, hostIndex) => {
    const addresses = Array.isArray(host.addresses) ? host.addresses : [];
    const hostLabel = addresses.map((item) => item?.address).filter(Boolean).join(", ")
      || job?.target || target;
    return (Array.isArray(host.ports) ? host.ports : []).map((port, index) => ({
      ...port, hostLabel, key: `${hostIndex}-${index}`,
    }));
  });
  const openPorts = ports.filter((port) =>
    String(port.state || "").toLowerCase() === "open"
  );
  const filtered = openOnly ? openPorts : ports;
  const pages = Math.max(1, Math.ceil(filtered.length / 25));
  const currentPage = Math.min(page, pages - 1);
  const visible = filtered.slice(currentPage * 25, currentPage * 25 + 25);
  const progressNumber = Number(job?.progress);
  const progress = Number.isFinite(progressNumber)
    ? Math.max(0, Math.min(100, progressNumber)) : 0;
  const warnings = Array.isArray(result?.errors) ? result.errors : [];
  const parseError = result?.results?.parse_error;

  return (
    <div className="space-y-6 text-slate-200">
      <header>
        <p className="text-sm uppercase tracking-widest text-red-500">Security Testing</p>
        <h1 className="mt-3 text-3xl font-bold text-white">{title}</h1>
        <p className="mt-3 text-slate-400">
          Scan an authorized hostname or IP address using your integrated Nmap scanner.
        </p>
      </header>

      <form onSubmit={startScan} className={`${panel} space-y-5`}>
        <label className="block">
          Target hostname or IP address
          <input className={`${input} mt-2`} value={target}
            onChange={(event) => setTarget(event.target.value)}
            disabled={busy} required maxLength={253}
            placeholder="127.0.0.1 or an authorized hostname" />
        </label>

        <div>
          <p className="text-sm text-slate-400">Scan mode</p>
          <p className="mt-2 font-semibold text-white">
            {serviceMode ? "Service and version detection" : "TCP port discovery"}
          </p>
        </div>
        <p className="text-sm text-slate-400">
          {profile === "quick"
            ? "Top 1,000 TCP ports. No service/version probes or NSE scripts."
            : "Top 1,000 TCP ports with service/version detection and default NSE scripts."}
        </p>

        <button type="submit" className={button} disabled={busy || !target.trim()}>
          {starting ? "Starting..." : running ? "Scanning..." : "Start Scan"}
        </button>
        <p className="text-sm text-slate-500">
          Leaving this page stops progress monitoring, not the server scan.
          The server enforces your existing tool permissions.
        </p>
      </form>

      {error && <div role="alert" className="rounded border border-red-800 p-5 text-red-300">{error}</div>}

      {jobId && <section className={`${panel} space-y-4`}>
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-xl font-semibold text-white">Scan Progress</h2>
          <span className="uppercase">{status}</span>
        </div>
        <p>{text(job?.stage)}</p>
        <progress className="h-3 w-full accent-red-600" value={progress} max="100" />
        <p>{progress}%</p>
        <p className="break-all text-sm text-slate-400">Job ID: {jobId}</p>
        {job?.error && <p className="text-red-300">{text(job.error)}</p>}

        {pollError && <div role="alert" className="space-y-3 text-amber-300">
          <p>{pollError}</p>
          <p>Monitoring stopped. The scan may still be running.</p>
          <button className={button} type="button"
            onClick={() => setRetry((value) => value + 1)}>
            Retry Status Check
          </button>
        </div>}
      </section>}

      {warnings.length > 0 && <section className={panel}>
        <h2 className="font-semibold text-amber-300">Scanner Warnings</h2>
        {warnings.map((value, index) =>
          <p className="mt-3 whitespace-pre-wrap break-words" key={index}>{text(value)}</p>
        )}
      </section>}

      {parseError && <div role="alert" className={panel}>
        Results could not be parsed: {text(parseError)}
      </div>}

      {result && <section className={`${panel} space-y-5`}>
        <h2 className="text-xl font-semibold text-white">{title} Results</h2>
        <p>
          {hosts.length} parsed hosts · {openPorts.length} open-port observations
          {status !== "completed" ? " · Partial or unsuccessful scan results" : ""}
        </p>
        <p className="text-sm text-slate-400">
          Results apply to the ports and profile tested during this run.
        </p>

        <div className="flex flex-wrap items-center justify-between gap-4">
          <label className="flex items-center gap-3">
            <input type="checkbox" checked={openOnly} onChange={(event) => {
              setOpenOnly(event.target.checked); setPage(0);
            }} />
            Show open ports only
          </label>
          <div className="flex gap-3">
            <button className={button} disabled={currentPage === 0}
              onClick={() => setPage(currentPage - 1)}>Previous</button>
            <button className={button} disabled={currentPage >= pages - 1}
              onClick={() => setPage(currentPage + 1)}>Next</button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[850px]">
            <thead><tr className="text-slate-400">
              {(serviceMode
                ? ["Host", "Port", "Protocol", "State", "Service", "Product / Version"]
                : ["Host", "Port", "Protocol", "State"]).map(
                (label) => <th className={cell} key={label}>{label}</th>
              )}
            </tr></thead>
            <tbody>
              {visible.map((port) => <tr key={port.key}>
                <td className={cell}>{text(port.hostLabel)}</td>
                <td className={cell}>{text(port.port)}</td>
                <td className={cell}>{text(port.protocol)}</td>
                <td className={cell}>{text(port.state)}</td>
                {serviceMode && <>
                  <td className={cell}>{text(port.service?.name)}</td>
                  <td className={cell}>
                    {[port.service?.product, port.service?.version]
                      .filter((value) => typeof value === "string" && value)
                      .join(" ") || "—"}
                  </td>
                </>}
              </tr>)}
              {!visible.length && <tr><td className={cell} colSpan={serviceMode ? 6 : 4}>
                No matching port observations were returned.
              </td></tr>}
            </tbody>
          </table>
        </div>

        <details>
          <summary className="cursor-pointer text-slate-300">Full Structured Results</summary>
          <pre className="mt-4 max-h-[500px] overflow-auto rounded bg-black p-4 text-xs">
            {JSON.stringify(result, null, 2)}
          </pre>
        </details>
      </section>}
    </div>
  );
}
