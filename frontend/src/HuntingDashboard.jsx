import { useEffect, useState } from "react";

export default function HuntingDashboard({ apiUrl }) {
  const [hours, setHours] = useState("24");
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    let timer;
    let timeout;
    let controller;
    setLoading(true);
    setData(null);
    setError("");

    const load = async () => {
      controller = new AbortController();
      timeout = setTimeout(() => controller.abort(), 20000);
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");
        const response = await fetch(`${apiUrl}/hunting/dashboard?hours=${hours}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Dashboard request failed (${response.status}).`);
        const result = await response.json();
        if (!Number.isInteger(result.total_events) ||
            !Array.isArray(result.recent_events) ||
            !Array.isArray(result.top_event_types)) {
          throw new Error("Unexpected dashboard response.");
        }
        if (active) { setData(result); setError(""); }
      } catch (err) {
        if (active) setError(err.name === "AbortError" ? "Request timed out." : err.message);
      } finally {
        clearTimeout(timeout);
        if (active) {
          setLoading(false);
          timer = setTimeout(load, 30000);
        }
      }
    };
    void load();
    return () => {
      active = false;
      clearTimeout(timer);
      clearTimeout(timeout);
      controller?.abort();
    };
  }, [apiUrl, hours, refresh]);

  const panel = "rounded-lg border border-white/10 bg-[#0b1014] p-5";
  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">Threat Hunting</p>
          <h1 className="mt-2 text-2xl font-bold text-white">Hunting Dashboard</h1>
          <p className="mt-2 text-xs text-gray-400">Scoped telemetry · refreshes every 30 seconds</p>
        </div>
        <div className="flex gap-3">
          <select aria-label="Time window" value={hours}
            onChange={event => setHours(event.target.value)}
            className="rounded border border-white/10 bg-[#0b1014] px-3 py-2 text-xs text-gray-200">
            <option value="24">Last 24 hours</option>
            <option value="168">Last 7 days</option>
            <option value="720">Last 30 days</option>
          </select>
          <button disabled={loading} onClick={() => setRefresh(value => value + 1)}
            className="rounded border border-white/10 px-4 py-2 text-xs text-gray-300 disabled:opacity-40">
            {loading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>
      {error && <p role="alert" className="mb-4 text-xs text-red-400">
        {error} {data && "Displayed data is from the last successful request."}
      </p>}
      <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[["Events in window", "total_events"],
          ["High-severity events", "high_severity_events"],
          ["MITRE-mapped events", "mitre_mapped_events"],
          ["Saved queries · all dates", "saved_queries"]].map(([label, key]) => (
          <section key={key} className={panel}>
            <p className="text-xs text-gray-400">{label}</p>
            <p className="mt-3 text-2xl font-bold text-white">{data?.[key] ?? "—"}</p>
          </section>
        ))}
      </div>
      {data && <>
        <p className="mb-5 break-words text-xs leading-6 text-gray-500">
          {data.scope} scope · {data.window_start} to {data.window_end}.
          Counts cover the selected database window. High severity alone does not confirm a threat.
        </p>
        <section className={`${panel} mb-5`}>
          <h2 className="text-sm font-semibold text-white">Top 10 Event Types</h2>
          <div className="mt-4 space-y-3">
            {data.top_event_types.map(item => (
              <div key={item.event_type} className="flex justify-between gap-4 text-xs text-gray-300">
                <span>{item.event_type}</span><span>{item.count}</span>
              </div>
            ))}
            {!data.top_event_types.length && <p className="text-xs text-gray-500">No events in this window.</p>}
          </div>
        </section>
        <section className="overflow-x-auto rounded-lg border border-white/10 bg-[#0b1014]">
          <h2 className="p-5 text-sm font-semibold text-white">Latest 10 Events in Window</h2>
          <table className="w-full text-left text-xs">
            <thead className="border-y border-white/10 text-gray-400">
              <tr>{["Time (UTC)", "Severity", "Source", "Type", "Message"].map(label =>
                <th key={label} className="px-4 py-3">{label}</th>)}</tr>
            </thead>
            <tbody>{data.recent_events.map(item => (
              <tr key={item.id} className="border-b border-white/5 text-gray-300">
                <td className="px-4 py-4">{item.timestamp}</td>
                <td className="px-4 py-4">{item.severity}</td>
                <td className="px-4 py-4">{item.source}</td>
                <td className="px-4 py-4">{item.event_type}</td>
                <td className="max-w-lg break-words px-4 py-4">{item.message}</td>
              </tr>
            ))}</tbody>
          </table>
        </section>
      </>}
    </div>
  );
}
