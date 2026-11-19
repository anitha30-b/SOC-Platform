import { useEffect, useState } from "react";
import axios from "axios";

const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const button =
  "rounded border border-gray-700 bg-[#0b1115] px-4 py-2 text-white disabled:opacity-40";

export default function NetworkSecurityDashboard({ apiUrl }) {
  const [events, setEvents] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState(null);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError("");
    setEvents(null);
    setUpdated(null);

    (async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");

        const params = new URLSearchParams({ limit: "500" });
        [
          "network_connection_attempt",
          "network_detection",
          "dns_query",
          "dns_detection",
        ].forEach(kind => params.append("event_type", kind));

        const response = await axios.get(
          `${apiUrl}/security-events?${params.toString()}`,
          {
            headers: { Authorization: `Bearer ${token}` },
            signal: controller.signal,
            timeout: 20000,
          }
        );

        if (!Array.isArray(response.data)) {
          throw new Error("Unexpected network event response.");
        }

        if (active) {
          setEvents(response.data);
          setUpdated(new Date().toLocaleString());
        }
      } catch (err) {
        if (active && !controller.signal.aborted) {
          const detail = err.response?.data?.detail;
          setError(
            typeof detail === "string"
              ? detail
              : err.message || "Unable to load network events."
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    })();

    return () => {
      active = false;
      controller.abort();
    };
  }, [apiUrl, refresh]);

  const rows = events || [];
  const count = kind => rows.filter(row => row.event_type === kind).length;
  const protocolCounts = new Map();

  for (const row of rows) {
    const protocol = String(
      row.network?.protocol || row.dns?.protocol || "Not recorded"
    ).toUpperCase();
    protocolCounts.set(protocol, (protocolCounts.get(protocol) || 0) + 1);
  }

  const protocols = [...protocolCounts.entries()].sort(
    (a, b) => b[1] - a[1] || a[0].localeCompare(b[0])
  );

  return (
    <div className="space-y-6 text-gray-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-3 text-xs tracking-widest text-red-500">
            NETWORK SECURITY
          </p>
          <h1 className="text-3xl font-bold text-white">Network Dashboard</h1>
        </div>
        <button className={button} disabled={loading}
          onClick={() => setRefresh(value => value + 1)}>
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      <div className={`${box} space-y-3 text-sm`}>
        <p>
          Summary of up to the latest 500 authorized network and DNS events
          across all dates. Counts describe this returned subset.
        </p>
        <p>
          Connection attempts do not establish successful connections.
          Detection records are signals for investigation.
          This summary does not measure traffic volume or bandwidth.
        </p>
        {updated && <p>Last successful check: {updated}</p>}
      </div>

      {error && <p role="alert" className="text-red-400">{error}</p>}
      {loading && <p role="status">Loading recorded network activity...</p>}

      {events && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {[
              ["Connection attempts in subset", count("network_connection_attempt")],
              ["Network detections in subset", count("network_detection")],
              ["DNS queries in subset", count("dns_query")],
              ["DNS detections in subset", count("dns_detection")],
            ].map(([label, value]) => (
              <div key={label} className={box}>
                <p className="text-sm text-gray-400">{label}</p>
                <p className="mt-3 text-3xl font-bold text-white">{value}</p>
              </div>
            ))}
          </div>

          {events.length === 500 && (
            <p className="text-sm text-yellow-300">
              The response reached the 500-event limit. Older eligible
              events may exist and are not included in these counts.
            </p>
          )}

          <div className={box}>
            <h2 className="mb-4 font-bold text-white">
              Recorded Protocol Labels · {events.length} Events
            </h2>
            {protocols.map(([protocol, total]) => (
              <div key={protocol}
                className="flex justify-between gap-4 border-t border-gray-800 py-3">
                <span>{protocol}</span><span>{total}</span>
              </div>
            ))}
            {!events.length && <p>No eligible network events returned.</p>}
          </div>

          <div className={`${box} overflow-x-auto`}>
            <h2 className="mb-4 font-bold text-white">Latest 10 Returned Events</h2>
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {["Recorded time", "Type", "Severity", "Source", "Message"].map(label => (
                    <th key={label} className="p-3 text-gray-400">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 10).map(row => (
                  <tr key={row.id} className="border-t border-gray-800">
                    <td className="p-3 align-top">{row.timestamp || "Not recorded"}</td>
                    <td className="p-3 align-top">{row.event_type}</td>
                    <td className="p-3 align-top">{row.severity}</td>
                    <td className="p-3 align-top">{row.source}</td>
                    <td className="max-w-xl break-words p-3 align-top">{row.message}</td>
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
