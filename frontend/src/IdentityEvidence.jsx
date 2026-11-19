import { useEffect, useRef, useState } from "react";
import axios from "axios";

const titles = {
  "identity-users": "Users",
  "identity-groups": "Groups",
  "identity-mfa": "MFA",
  "identity-anomalies": "Login Anomalies",
  "identity-risk": "Identity Risk",
};
const authTypes = new Set([
  "authentication", "authentication_success", "authentication_session",
  "authentication_failure", "invalid_user",
]);
const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const control =
  "rounded border border-gray-700 bg-[#0b1115] px-4 py-2 text-white disabled:opacity-40";

export default function IdentityEvidence({ apiUrl, view }) {
  const users = view === "identity-users";
  const anomalies = view === "identity-anomalies";
  const risk = view === "identity-risk";
  const unavailable = view === "identity-groups" || view === "identity-mfa";

  const [hours, setHours] = useState(users ? "24" : "0");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(!unavailable);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(null);
  const detailsRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
    if (unavailable) return;
    const controller = new AbortController();
    let active = true;
    setData(null);
    setSelected(null);
    setLoading(true);
    setError("");
    setPage(0);

    (async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");

        const endpoint = users
          ? "/hunting/explore/users"
          : anomalies
            ? "/security-events/anomaly/baseline"
            : "/hunting/identity-summary";

        const response = await axios.get(`${apiUrl}${endpoint}`, {
          params: anomalies ? undefined : { hours },
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
          timeout: 30000,
        });

        const valid = users
          ? Array.isArray(response.data?.rows)
          : anomalies
            ? Array.isArray(response.data?.event_types)
            : Array.isArray(response.data?.recent_events);

        if (!valid) throw new Error("Unexpected identity response.");
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
  }, [apiUrl, users, anomalies, unavailable, hours, refresh]);

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

  let rows = [];
  let columns = [];

  if (data && users) {
    const grouped = new Map();
    for (const event of data.rows) {
      const key = JSON.stringify([
        event.username, event.source, event.target,
        event.identity_basis, event.identity_role,
      ]);
      if (grouped.has(key)) {
        grouped.get(key).observations += 1;
      } else {
        grouped.set(key, {
          username: event.username,
          source: event.source,
          target: event.target ?? "Not recorded",
          identity_role: event.identity_role,
          identity_basis: event.identity_basis,
          latest_returned_observation: event.timestamp,
          observations: 1,
        });
      }
    }
    rows = [...grouped.values()];
    columns = [
      "username", "source", "target", "identity_role", "observations",
    ];
  } else if (data && anomalies) {
    rows = data.event_types.filter(row => authTypes.has(row.event_type));
    columns = [
      "event_type", "current_count", "baseline_median", "threshold", "flagged",
    ];
  } else if (data && risk) {
    rows = data.recent_events;
    columns = ["timestamp", "event_type", "severity", "source", "message"];
  }

  const needle = search.trim().toLowerCase();
  const filtered = rows.filter(
    row => !needle || JSON.stringify(row).toLowerCase().includes(needle)
  );
  const shown = filtered.slice(page * 25, (page + 1) * 25);

  return (
    <div className="space-y-6 text-gray-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-3 text-xs tracking-widest text-red-500">
            IDENTITY SECURITY
          </p>
          <h1 className="text-3xl font-bold text-white">{titles[view]}</h1>
        </div>
        {!unavailable && (
          <div className="flex flex-wrap gap-3">
            {!anomalies && (
              <select className={control} aria-label="Identity period"
                value={hours} onChange={event => setHours(event.target.value)}>
                {risk && <option value="0">All dates</option>}
                <option value="24">Last 24 hours</option>
                <option value="168">Last 7 days</option>
                <option value="720">Last 30 days</option>
              </select>
            )}
            <button className={control} disabled={loading}
              onClick={() => setRefresh(value => value + 1)}>
              {loading ? "Loading..." : "Refresh"}
            </button>
          </div>
        )}
      </div>

      {unavailable ? (
        <div className={`${box} space-y-4`}>
          <h2 className="text-lg font-bold text-white">
            {view === "identity-groups"
              ? "Directory Group Inventory Unavailable"
              : "MFA Status Unavailable"}
          </h2>
          <p>
            {view === "identity-groups"
              ? "A directory group and membership integration is required to list identity groups. Asset groups and group-change attempts do not establish current directory membership."
              : "The inspected account API does not provide MFA enrollment or enforcement status. Missing telemetry does not mean MFA is disabled."}
          </p>
          <p>No identity policy or account settings are changed from this page.</p>
        </div>
      ) : (
        <>
          <div className={`${box} space-y-3 text-sm`}>
            {users && (
              <>
                <p>
                  Observed username labels grouped by source, target, identity
                  role, and extraction basis. These are not verified unique
                  people, platform accounts, or a complete endpoint directory.
                </p>
                <p>
                  A sudo target account can differ from the invoking user.
                  Open Details to see the identity role and extraction basis.
                </p>
                {data && (
                  <p>
                    {data.scope} scope · {data.scanned} events examined ·
                    {" "}{data.returned} identity observations returned ·
                    {" "}{rows.length} groups in returned observations
                  </p>
                )}
                <p>
                  Up to the newest 5,000 authorized events are examined;
                  up to 500 identity observations are returned.
                  Group counts apply only to returned observations.
                </p>
                {data?.scan_truncated && (
                  <p className="text-yellow-300">
                    Examination limit reached. Older events were not examined.
                  </p>
                )}
                {data?.results_truncated && (
                  <p className="text-yellow-300">
                    Display limit reached. Older matching identities are omitted.
                  </p>
                )}
              </>
            )}

            {anomalies && (
              <>
                <p>
                  Authentication event-volume outliers for the latest completed
                  15-minute window, compared with seven days of history.
                  Zero-event history buckets are included.
                </p>
                <p>
                  This does not assess impossible travel, unusual devices,
                  individual-user behavior, or account compromise.
                  Sparse collection history can affect the baseline.
                </p>
                {data && (
                  <p>
                    UTC window: {data.window_start} to {data.window_end}
                    {" · "}{rows.filter(row => row.flagged).length} flagged event types
                  </p>
                )}
              </>
            )}

            {risk && (
              <>
                <p>
                  Evidence review across all authorized identity events in the
                  selected period. No identity-risk score is calculated.
                </p>
                <p>
                  Privileged activity and authentication failures require context;
                  neither alone confirms compromise. Directory privilege,
                  MFA posture, and account-level risk are not available here.
                </p>
                {data && (
                  <p>
                    {data.scope} scope · {data.total_events} events ·
                    {" "}{data.all_dates ? "All recorded dates" : data.window_start}
                    {" to "}{data.window_end}
                  </p>
                )}
              </>
            )}
          </div>

          {loading && <p role="status">Loading identity evidence...</p>}
          {error && <p role="alert" className="text-red-400">{error}</p>}

          {data && risk && (
            <div className="grid gap-4 sm:grid-cols-2">
              {[
                ["Failure / invalid-user records", data.failure_invalid_records],
                ["Privileged activity records", data.privileged_records],
                ["Account-change records", data.account_change_records],
                ["Authentication-related records", data.authentication_records],
              ].map(([label, count]) => (
                <div key={label} className={box}>
                  <p className="text-sm text-gray-400">{label}</p>
                  <p className="mt-3 text-3xl font-bold text-white">{count}</p>
                </div>
              ))}
            </div>
          )}

          {data && (
            <div className={box}>
              {risk && (
                <h2 className="mb-4 font-bold text-white">
                  Latest 10 Identity Events in Period
                </h2>
              )}
              <label className="mb-5 block text-sm">
                Search returned records
                <input className={`${control} mt-2 w-full`} value={search}
                  maxLength={200} onChange={event => {
                    setSearch(event.target.value);
                    setPage(0);
                    setSelected(null);
                  }} />
              </label>

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
                      {columns.map(col => (
                        <th key={col} className="p-3 text-gray-400">
                          {col.replaceAll("_", " ")}
                        </th>
                      ))}
                      <th className="p-3 text-gray-400">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map(row => (
                      <tr key={users
                        ? JSON.stringify([row.username, row.source, row.target, row.identity_role, row.identity_basis])
                        : anomalies ? row.event_type : row.id}
                        className="border-t border-gray-800">
                        {columns.map(col => (
                          <td key={col} className="max-w-xl break-words p-3 align-top">
                            {typeof row[col] === "boolean"
                              ? row[col] ? "Yes" : "No"
                              : row[col] ?? "Not recorded"}
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
                    {anomalies && " This does not establish that logins are risk-free."}
                  </p>
                )}
              </div>
            </div>
          )}

          {selected && (
            <section ref={detailsRef} tabIndex={-1}
              aria-label="Identity evidence details"
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
