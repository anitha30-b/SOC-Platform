import { useEffect, useState } from "react";
import axios from "axios";

const titles = {
  "network-topology": "Network Topology",
  "network-traffic": "Traffic Analysis",
  "network-protocols": "Protocols",
};
const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const control =
  "rounded border border-gray-700 bg-[#0b1115] px-4 py-2 text-white disabled:opacity-40";

function groupRows(rows, keyFor, valuesFor) {
  const groups = new Map();
  for (const row of rows) {
    const key = JSON.stringify(keyFor(row));
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      groups.set(key, { ...valuesFor(row), count: 1 });
    }
  }
  return [...groups.values()].sort(
    (a, b) => b.count - a.count ||
      JSON.stringify(a).localeCompare(JSON.stringify(b))
  );
}

export default function NetworkObservations({ apiUrl, view }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setData(null);
    setError("");
    setLoading(true);
    setPage(0);

    (async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");

        const params = new URLSearchParams({ limit: "500" });
        [
          "network_connection_attempt", "network_detection",
          "dns_query", "dns_detection",
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
          throw new Error("Unexpected network response.");
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
  }, [apiUrl, refresh]);

  const events = data || [];
  const network = row => row.network || row.dns || {};
  const protocol = row =>
    String(network(row).protocol || "Not recorded").toUpperCase();

  let rows = [];
  let columns = [];
  let explanation = "";

  if (view === "network-topology") {
    const eligible = events.filter(row =>
      network(row).source_ip && network(row).destination_ip
    );
    rows = groupRows(
      eligible,
      row => [
        network(row).source_ip, network(row).destination_ip,
        protocol(row), row.event_type,
      ],
      row => ({
        source: network(row).source_ip,
        destination: network(row).destination_ip,
        protocol: protocol(row),
        event_type: row.event_type,
      })
    );
    columns = ["source", "destination", "protocol", "event_type", "count"];
    explanation =
      "Observed source–destination pairs from recorded event fields. " +
      "This is a logical observation view, not a physical network map. " +
      "Detection endpoints describe the triggering event; event counts are not packet counts. " +
      `${events.length - eligible.length} returned events lack a complete endpoint pair.`;
  } else if (view === "network-traffic") {
    const bucket = row => {
      if (!row.timestamp) return "Time not recorded";
      const date = new Date(row.timestamp);
      return Number.isNaN(date.getTime())
        ? "Time not recorded"
        : date.toISOString().slice(0, 13) + ":00 UTC";
    };
    rows = groupRows(
      events,
      row => [bucket(row), row.event_type],
      row => ({ hour: bucket(row), event_type: row.event_type })
    ).sort((a, b) =>
      b.hour.localeCompare(a.hour) || a.event_type.localeCompare(b.event_type)
    );
    columns = ["hour", "event_type", "count"];
    explanation =
      "Recorded event counts grouped into UTC hours. Queries, connection attempts, " +
      "and detections are separate event types. Counts do not represent bytes, " +
      "bandwidth, packets, or confirmed successful connections.";
  } else {
    rows = groupRows(
      events,
      row => [protocol(row), row.event_type],
      row => ({
        protocol: protocol(row),
        event_type: row.event_type,
      })
    );
    columns = ["protocol", "event_type", "count"];
    explanation =
      "Protocol labels supplied by recorded telemetry. DNS is an application " +
      "protocol label and does not identify its underlying TCP or UDP transport here. " +
      "Counts describe event records, not traffic volume.";
  }

  const needle = search.trim().toLowerCase();
  const filtered = rows.filter(row =>
    !needle || JSON.stringify(row).toLowerCase().includes(needle)
  );
  const shown = filtered.slice(page * 25, (page + 1) * 25);

  return (
    <div className="space-y-6 text-gray-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-3 text-xs tracking-widest text-red-500">
            NETWORK SECURITY
          </p>
          <h1 className="text-3xl font-bold text-white">{titles[view]}</h1>
        </div>
        <button className={control} disabled={loading}
          onClick={() => setRefresh(value => value + 1)}>
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      <div className={`${box} space-y-3 text-sm`}>
        <p>{explanation}</p>
        <p>
          Uses up to the latest 500 authorized network and DNS events across
          all dates. Grouped counts apply only to that returned subset.
        </p>
        {data?.length === 500 && (
          <p className="text-yellow-300">
            Response limit reached. Older eligible events may be excluded.
          </p>
        )}
        <label className="block">
          Search grouped records
          <input className={`${control} mt-2 w-full`} value={search}
            maxLength={200}
            onChange={event => {
              setSearch(event.target.value);
              setPage(0);
            }} />
        </label>
      </div>

      {error && <p role="alert" className="text-red-400">{error}</p>}
      {loading && <p role="status">Loading recorded observations...</p>}

      {data && (
        <div className={box}>
          <div className="mb-4 flex flex-wrap justify-between gap-3">
            <p>{data.length} events returned · {filtered.length} matching groups</p>
            <div className="flex gap-3">
              <button className={control} disabled={page === 0}
                onClick={() => setPage(value => value - 1)}>Previous</button>
              <button className={control} disabled={(page + 1) * 25 >= filtered.length}
                onClick={() => setPage(value => value + 1)}>Next</button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {columns.map(col => (
                    <th key={col} className="p-3 text-gray-400">
                      {col === "count" ? "Event records" : col.replaceAll("_", " ")}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.map(row => (
                  <tr key={JSON.stringify(columns.filter(col => col !== "count").map(col => row[col]))}
                    className="border-t border-gray-800">
                    {columns.map(col => (
                      <td key={col} className="break-words p-3">{row[col]}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {!shown.length && <p className="p-4">No matching recorded groups.</p>}
          </div>
        </div>
      )}
    </div>
  );
}
