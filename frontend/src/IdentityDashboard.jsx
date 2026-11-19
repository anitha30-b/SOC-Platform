import { useEffect, useState } from "react";
import axios from "axios";

const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const control =
  "rounded border border-gray-700 bg-[#0b1115] px-4 py-2 text-white disabled:opacity-40";

export default function IdentityDashboard({ apiUrl }) {
  const [hours, setHours] = useState("0");
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setData(null);
    setLoading(true);
    setError("");

    (async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");
        const response = await axios.get(
          `${apiUrl}/hunting/identity-summary`,
          {
            params: { hours },
            headers: { Authorization: `Bearer ${token}` },
            signal: controller.signal,
            timeout: 30000,
          }
        );
        if (!Array.isArray(response.data?.recent_events)) {
          throw new Error("Unexpected identity summary response.");
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
    })();

    return () => {
      active = false;
      controller.abort();
    };
  }, [apiUrl, hours, refresh]);

  return (
    <div className="space-y-6 text-gray-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-3 text-xs tracking-widest text-red-500">IDENTITY SECURITY</p>
          <h1 className="text-3xl font-bold text-white">Identity Dashboard</h1>
        </div>
        <div className="flex flex-wrap gap-3">
          <select aria-label="Identity event period" className={control}
            value={hours} onChange={event => setHours(event.target.value)}>
            <option value="0">All dates</option>
            <option value="24">Last 24 hours</option>
            <option value="168">Last 7 days</option>
            <option value="720">Last 30 days</option>
          </select>
          <button className={control} disabled={loading}
            onClick={() => setRefresh(value => value + 1)}>
            {loading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>

      <div className={`${box} space-y-3 text-sm`}>
        <p>
          Counts cover all authorized identity-related database events in the
          selected period. The latest-events table is limited separately.
        </p>
        <p>
          These are event counts, not unique accounts. Failure/invalid-user
          records are a subset of authentication records. Generic authentication
          and session labels do not by themselves establish successful logins.
        </p>
        {data && (
          <p>
            {data.scope} scope · {data.total_events} identity-related events
            {" · "}{data.all_dates ? "All recorded dates" : data.window_start}
            {" to "}{data.window_end}
          </p>
        )}
      </div>

      {loading && <p role="status">Loading full-period identity counts...</p>}
      {error && <p role="alert" className="text-red-400">{error}</p>}

      {data && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {[
              ["Authentication-related records", data.authentication_records],
              ["Failure / invalid-user records", data.failure_invalid_records],
              ["Privileged activity records", data.privileged_records],
              ["Account-change records", data.account_change_records],
            ].map(([label, value]) => (
              <div key={label} className={box}>
                <p className="text-sm text-gray-400">{label}</p>
                <p className="mt-3 text-3xl font-bold text-white">{value}</p>
              </div>
            ))}
          </div>

          <div className={box}>
            <h2 className="mb-4 font-bold text-white">Event Types · Full Selected Period</h2>
            {Object.entries(data.by_event_type).sort(([a], [b]) => a.localeCompare(b))
              .map(([kind, count]) => (
                <div key={kind} className="flex justify-between gap-4 border-t border-gray-800 py-3">
                  <span>{kind}</span><span>{count}</span>
                </div>
              ))}
            {!data.total_events && <p>No eligible events in this period.</p>}
          </div>

          <div className={`${box} overflow-x-auto`}>
            <h2 className="mb-4 font-bold text-white">Latest 10 Identity Events in Period</h2>
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {["Time (UTC)", "Type", "Severity", "Source", "Message"].map(label => (
                    <th key={label} className="p-3 text-gray-400">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.recent_events.map(row => (
                  <tr key={row.id} className="border-t border-gray-800">
                    {[row.timestamp, row.event_type, row.severity, row.source, row.message]
                      .map((value, index) => (
                        <td key={index} className="max-w-xl break-words p-3 align-top">
                          {value ?? "Not recorded"}
                        </td>
                      ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
