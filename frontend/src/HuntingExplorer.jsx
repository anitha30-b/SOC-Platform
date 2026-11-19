import { useEffect, useRef, useState } from "react";
import axios from "axios";

const titles = {
  users: "User Hunting",
  processes: "Process Hunting",
  network: "Network Hunting",
  timeline: "Timeline Analysis",
};
const columns = {
  users: ["timestamp", "username", "severity", "event_type", "source", "message"],
  processes: ["last_seen", "hostname", "pid", "name", "username", "status"],
  network: [
    "timestamp", "event_type", "source_ip", "destination_ip",
    "destination_port", "protocol", "dns_query",
  ],
  timeline: ["timestamp", "severity", "source", "event_type", "target", "message"],
};
const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const input = "rounded border border-gray-700 bg-[#0b1115] px-4 py-3 text-white";

export default function HuntingExplorer({ apiUrl, kind }) {
  const [hours, setHours] = useState("24");
  const [search, setSearch] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const detailsRef = useRef(null);
  const detailsTriggerRef = useRef(null);

  useEffect(() => {
    if (!selected) return;
    const frame = requestAnimationFrame(() => {
      detailsRef.current?.focus({ preventScroll: true });
      detailsRef.current?.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
          ? "auto" : "smooth",
        block: "start",
      });
    });
    return () => cancelAnimationFrame(frame);
  }, [selected]);

  const closeDetails = () => {
    setSelected(null);
    const trigger = detailsTriggerRef.current;
    requestAnimationFrame(() => {
      if (trigger?.isConnected) {
        trigger.focus({ preventScroll: true });
        trigger.scrollIntoView({ block: "center", behavior: "auto" });
      }
    });
  };
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setData(null);
    setSelected(null);
    setError("");
    setLoading(true);
    const timer = setTimeout(async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");
        const response = await axios.get(
          `${apiUrl}/hunting/explore/${kind}`,
          {
            headers: { Authorization: `Bearer ${token}` },
            params: { hours, search: search.trim() },
            signal: controller.signal,
            timeout: 20000,
          }
        );
        if (!Array.isArray(response.data?.rows)) {
          throw new Error("Unexpected hunting response.");
        }
        if (active) setData(response.data);
      } catch (err) {
        if (active && !controller.signal.aborted) {
          const detail = err.response?.data?.detail;
          setError(typeof detail === "string" ? detail : err.message);
        }
      } finally {
        if (active) setLoading(false);
      }
    }, 300);
    return () => {
      active = false;
      clearTimeout(timer);
      controller.abort();
    };
  }, [apiUrl, kind, hours, search, refresh]);

  return (
    <div className="space-y-6 text-gray-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-3 text-xs tracking-widest text-red-500">THREAT HUNTING</p>
          <h1 className="text-3xl font-bold text-white">{titles[kind]}</h1>
        </div>
        <button className={input} onClick={() => setRefresh(v => v + 1)}>
          Refresh
        </button>
      </div>

      <div className={`${box} flex flex-wrap gap-4`}>
        <label className="flex min-w-64 flex-1 flex-col gap-2">
          Search displayed record fields
          <input className={input} value={search} maxLength={200}
            placeholder={kind === "processes" ? "Process, username, or command" : "Username, IP, source, or message"}
            onChange={e => setSearch(e.target.value)} />
        </label>
        {kind !== "processes" && (
          <label className="flex flex-col gap-2">
            Event window
            <select className={input} value={hours}
              onChange={e => setHours(e.target.value)}>
              <option value="24">Last 24 hours</option>
              <option value="168">Last 7 days</option>
              <option value="720">Last 30 days</option>
            </select>
          </label>
        )}
      </div>

      {loading && <p role="status">Loading authorized records...</p>}
      {error && <p role="alert" className="text-red-400">{error}</p>}

      {data && (
        <>
          <div className={`${box} space-y-3 text-sm`}>
            <p>{data.scope} scope · Examined {data.scanned} records ·
              {" "}{data.matched_in_scanned} matches in examined records ·
              {" "}Showing {data.returned}</p>
            <p>{data.note}</p>
            <p>Search applies within up to the newest 5,000 eligible records;
              results show up to 500 matches. Counts are for that examined subset.</p>
            {data.results_truncated && (
              <p className="text-yellow-300">
                Display limit reached: showing the first 500 matching records
                in newest-first order. Narrow your search to see fewer matches.
              </p>
            )}
            {data.scan_truncated && (
              <p className="text-yellow-300">
                Examination limit reached: only the newest 5,000 eligible
                records were searched. Older records were not examined.
              </p>
            )}
            {data.window_start && <p>UTC: {data.window_start} to {data.window_end}</p>}
            <p>Recorded activity does not by itself establish malicious behavior.</p>
          </div>

          <div className={`${box} overflow-x-auto`}>
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {columns[kind].map(col => (
                    <th key={col} className="p-3 text-gray-400">
                      {col.replaceAll("_", " ")}
                    </th>
                  ))}
                  <th className="p-3">Details</th>
                </tr>
              </thead>
              <tbody>
                {data.rows.map(row => (
                  <tr key={row.id} className="border-t border-gray-800">
                    {columns[kind].map(col => (
                      <td key={col} className="max-w-md break-words p-3 align-top">
                        {row[col] ?? "Not recorded"}
                      </td>
                    ))}
                    <td className="p-3 align-top">
                      <button className={input} onClick={event => {
                        detailsTriggerRef.current = event.currentTarget;
                        setSelected(row);
                      }}>
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data.rows.length && (
              <p className="p-4">
                No matching records in the examined subset.
                {kind === "users" && " No supported structured or message-derived identity was found."}
              </p>
            )}
          </div>
        </>
      )}

      {selected && (
        <section
          ref={detailsRef}
          tabIndex={-1}
          aria-label="Recorded details"
          className={box}
          style={{ scrollMarginTop: "110px" }}
        >
          <div className="mb-4 flex justify-between gap-4">
            <h2 className="font-bold text-white">Recorded Details</h2>
            <button onClick={closeDetails}>Close Details</button>
          </div>
          <dl className="space-y-3">
            {Object.entries(selected).map(([key, value]) => (
              <div key={key}>
                <dt className="text-sm text-gray-400">{key.replaceAll("_", " ")}</dt>
                <dd className="whitespace-pre-wrap break-all">{value ?? "Not recorded"}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}
    </div>
  );
}
