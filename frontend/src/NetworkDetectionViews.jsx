import { useEffect, useRef, useState } from "react";
import axios from "axios";

const titles = {
  "network-vpn": "VPN",
  "network-ids": "IDS/IPS",
  "network-anomalies": "Network Anomalies",
};
const networkTypes = new Set([
  "network_connection_attempt", "network_detection",
  "dns_query", "dns_detection",
]);
const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const control =
  "rounded border border-gray-700 bg-[#0b1115] px-4 py-2 text-white disabled:opacity-40";

export default function NetworkDetectionViews({ apiUrl, view }) {
  const vpn = view === "network-vpn";
  const anomalies = view === "network-anomalies";
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(!vpn);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(null);
  const detailsRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
    if (vpn) return;
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError("");
    setData(null);
    setSelected(null);
    setPage(0);

    (async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");

        const params = new URLSearchParams({ limit: "500" });
        ["network_detection", "dns_detection"].forEach(
          kind => params.append("event_type", kind)
        );
        const endpoint = anomalies
          ? "/security-events/anomaly/baseline"
          : `/security-events?${params.toString()}`;

        const response = await axios.get(`${apiUrl}${endpoint}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
          timeout: 30000,
        });

        if (
          anomalies
            ? !Array.isArray(response.data?.event_types)
            : !Array.isArray(response.data)
        ) {
          throw new Error("Unexpected network detection response.");
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
  }, [apiUrl, vpn, anomalies, refresh]);

  useEffect(() => {
    if (!selected) return;
    const frame = requestAnimationFrame(() => {
      detailsRef.current?.focus({ preventScroll: true });
      detailsRef.current?.scrollIntoView({ block: "start", behavior: "auto" });
    });
    return () => cancelAnimationFrame(frame);
  }, [selected]);

  const closeDetails = () => {
    setSelected(null);
    requestAnimationFrame(() => {
      const trigger = triggerRef.current;
      if (trigger?.isConnected) {
        trigger.focus({ preventScroll: true });
        trigger.scrollIntoView({ block: "center", behavior: "auto" });
      }
    });
  };

  const rows = data
    ? anomalies
      ? data.event_types.filter(row => networkTypes.has(row.event_type))
      : data
    : [];
  const needle = search.trim().toLowerCase();
  const filtered = rows.filter(
    row => !needle || JSON.stringify(row).toLowerCase().includes(needle)
  );
  const shown = filtered.slice(page * 25, (page + 1) * 25);
  const flagged = rows.filter(row => row.flagged).length;

  return (
    <div className="space-y-6 text-gray-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-3 text-xs tracking-widest text-red-500">
            NETWORK SECURITY
          </p>
          <h1 className="text-3xl font-bold text-white">{titles[view]}</h1>
        </div>
        {!vpn && (
          <button className={control} disabled={loading}
            onClick={() => setRefresh(value => value + 1)}>
            {loading ? "Loading..." : "Refresh"}
          </button>
        )}
      </div>

      {vpn ? (
        <div className={`${box} space-y-4`}>
          <h2 className="text-lg font-bold text-white">
            VPN Telemetry Unavailable
          </h2>
          <p>
            No VPN-specific collector or session API was identified in the
            inspected project source. This page cannot report tunnel health,
            connected users, session history, or VPN traffic.
          </p>
          <p>
            A VPN provider integration is required before those values can
            be displayed. General network events do not establish VPN status.
          </p>
        </div>
      ) : (
        <>
          <div className={`${box} space-y-3 text-sm`}>
            {anomalies ? (
              <>
                <p>
                  Network and DNS event-volume comparisons for the latest
                  completed 15-minute UTC window against seven days of history.
                </p>
                <p>
                  Historical zero-event buckets are included. Sparse history
                  and collection changes can affect results. A flagged volume
                  is an investigation signal, not confirmed malicious activity.
                </p>
                {data && (
                  <>
                    <p>Window: {data.window_start} to {data.window_end}</p>
                    <p>
                      {rows.length} network/DNS event types · {flagged} flagged
                      {" · "}
                      {rows.reduce((sum, row) => sum + row.current_count, 0)}
                      {" "}events in this window
                    </p>
                  </>
                )}
              </>
            ) : (
              <>
                <p>
                  Up to the latest 500 authorized network_detection and
                  dns_detection records across all dates.
                </p>
                <p>
                  These are persisted detection signals. They do not establish
                  that Snort is running or that an IPS blocked traffic.
                  This page does not start an engine or change response policy.
                </p>
                {Array.isArray(data) && data.length === 500 && (
                  <p className="text-yellow-300">
                    Response limit reached. Older detections may be excluded.
                  </p>
                )}
              </>
            )}
            <label className="block">
              Search returned records
              <input className={`${control} mt-2 w-full`} value={search}
                maxLength={200} onChange={event => {
                  setSearch(event.target.value);
                  setPage(0);
                  setSelected(null);
                }} />
            </label>
          </div>

          {error && <p role="alert" className="text-red-400">{error}</p>}
          {loading && <p role="status">Loading network detection data...</p>}

          {data && (
            <div className={box}>
              <div className="mb-4 flex flex-wrap justify-between gap-3">
                <p>{filtered.length} matching returned records</p>
                <div className="flex gap-3">
                  <button className={control} disabled={page === 0}
                    onClick={() => { setPage(value => value - 1); setSelected(null); }}>
                    Previous
                  </button>
                  <button className={control}
                    disabled={(page + 1) * 25 >= filtered.length}
                    onClick={() => { setPage(value => value + 1); setSelected(null); }}>
                    Next
                  </button>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr>
                      {(anomalies
                        ? ["Event type", "Current", "Historical median", "Threshold", "Flagged", "Details"]
                        : ["Recorded time", "Type", "Severity", "Rule", "Message", "Details"]
                      ).map(label => (
                        <th key={label} className="p-3 text-gray-400">{label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map(row => (
                      <tr key={anomalies ? row.event_type : row.id}
                        className="border-t border-gray-800">
                        {(anomalies
                          ? [
                              row.event_type, row.current_count,
                              row.baseline_median, row.threshold,
                              row.flagged ? "Yes" : "No",
                            ]
                          : [
                              row.timestamp, row.event_type, row.severity,
                              row.detection?.rule_id || "Not recorded", row.message,
                            ]
                        ).map((value, index) => (
                          <td key={index} className="max-w-xl break-words p-3 align-top">
                            {value ?? "Not recorded"}
                          </td>
                        ))}
                        <td className="p-3 align-top">
                          <button className={control} onClick={event => {
                            triggerRef.current = event.currentTarget;
                            setSelected(row);
                          }}>Details</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!shown.length && (
                  <p className="p-4">
                    No matching records returned.
                    {anomalies && " This does not establish the absence of network anomalies."}
                  </p>
                )}
              </div>
            </div>
          )}

          {selected && (
            <section ref={detailsRef} tabIndex={-1}
              aria-label="Recorded detection details"
              className={box} style={{ scrollMarginTop: "110px" }}>
              <div className="mb-4 flex justify-between gap-4">
                <h2 className="font-bold text-white">Recorded Details</h2>
                <button className={control} onClick={closeDetails}>Close Details</button>
              </div>
              <pre className="max-h-[600px] overflow-auto whitespace-pre-wrap break-all text-sm">
                {JSON.stringify(selected, null, 2)}
              </pre>
            </section>
          )}
        </>
      )}
    </div>
  );
}
