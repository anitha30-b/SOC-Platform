import { useEffect, useRef, useState } from "react";
import axios from "axios";

const titles = {
  "identity-dashboard": "Identity Dashboard",
  "identity-authentication": "Authentication",
  "identity-privileged": "Privileged Users",
};

const authTypes = [
  "authentication", "authentication_success",
  "authentication_session", "authentication_failure", "invalid_user",
];
const privilegedTypes = [
  "privileged_command", "privileged_session_opened",
  "privileged_session_closed", "privileged_group_change_attempt",
];
const changeTypes = [
  "account_creation", "account_modification", "password_change",
];

const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const control =
  "rounded border border-gray-700 bg-[#0b1115] px-4 py-2 text-white disabled:opacity-40";

export default function IdentityActivity({ apiUrl, view }) {
  const dashboard = view === "identity-dashboard";
  const privileged = view === "identity-privileged";

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(null);
  const detailsRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
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

        const types = dashboard
          ? [...authTypes, ...privilegedTypes, ...changeTypes]
          : privileged ? privilegedTypes : authTypes;

        const params = new URLSearchParams({ limit: "500" });
        types.forEach(type => params.append("event_type", type));

        const response = await axios.get(
          `${apiUrl}/security-events?${params.toString()}`,
          {
            headers: { Authorization: `Bearer ${token}` },
            signal: controller.signal,
            timeout: 20000,
          }
        );

        if (!Array.isArray(response.data)) {
          throw new Error("Unexpected identity event response.");
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
  }, [apiUrl, dashboard, privileged, refresh]);

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
      const button = triggerRef.current;
      if (button?.isConnected) {
        button.focus({ preventScroll: true });
        button.scrollIntoView({ block: "center", behavior: "auto" });
      }
    });
  };

  const rows = data || [];
  const count = types => rows.filter(row => types.includes(row.event_type)).length;
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
        <button className={control} disabled={loading}
          onClick={() => setRefresh(value => value + 1)}>
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      <div className={`${box} space-y-3 text-sm`}>
        <p>
          Up to the latest 500 authorized events for this view across all dates.
          Counts describe the returned subset.
        </p>
        {privileged ? (
          <p>
            Recorded privileged commands, sudo sessions, and privileged-group
            change attempts. These observations are not an inventory of all
            privileged users or proof of current administrative membership.
            A sudo session target can differ from the invoking user.
          </p>
        ) : (
          <p>
            Authentication labels describe recorded events. Generic authentication
            and session events are not automatically classified as successful
            logins. This is not a platform or endpoint account directory.
          </p>
        )}
        {data?.length === 500 && (
          <p className="text-yellow-300">
            Response limit reached. Older eligible events may be excluded.
            Each identity page applies its own event-type filter before this limit.
          </p>
        )}
      </div>

      {loading && <p role="status">Loading authorized identity activity...</p>}
      {error && <p role="alert" className="text-red-400">{error}</p>}

      {data && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {(dashboard
              ? [
                  ["Authentication-related records", count(authTypes)],
                  ["Failure / invalid-user records", count(["authentication_failure", "invalid_user"])],
                  ["Privileged activity records", count(privilegedTypes)],
                  ["Account-change records", count(changeTypes)],
                ]
              : privileged
                ? [
                    ["Privileged commands", count(["privileged_command"])],
                    ["Session-open records", count(["privileged_session_opened"])],
                    ["Session-close records", count(["privileged_session_closed"])],
                    ["Group-change attempts", count(["privileged_group_change_attempt"])],
                  ]
                : [
                    ["Explicit success-labelled records", count(["authentication_success"])],
                    ["Failure-labelled records", count(["authentication_failure"])],
                    ["Invalid-user records", count(["invalid_user"])],
                    ["Generic authentication / sessions", count(["authentication", "authentication_session"])],
                  ]
            ).map(([label, value]) => (
              <div key={label} className={box}>
                <p className="text-sm text-gray-400">{label}</p>
                <p className="mt-3 text-3xl font-bold text-white">{value}</p>
              </div>
            ))}
          </div>

          <div className={box}>
            <label className="block text-sm">
              Search returned records
              <input className={`${control} mt-2 w-full`} value={search}
                maxLength={200} onChange={event => {
                  setSearch(event.target.value);
                  setPage(0);
                  setSelected(null);
                }} />
            </label>
          </div>

          <div className={box}>
            <div className="mb-4 flex flex-wrap justify-between gap-3">
              <p>{rows.length} returned · {filtered.length} matching records</p>
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
                    {["Recorded time", "Type", "Severity", "Source", "Message", "Details"].map(label => (
                      <th key={label} className="p-3 text-gray-400">{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {shown.map(row => (
                    <tr key={row.id} className="border-t border-gray-800">
                      {[row.timestamp, row.event_type, row.severity, row.source, row.message].map((value, index) => (
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
              {!shown.length && <p className="p-4">No matching events returned.</p>}
            </div>
          </div>
        </>
      )}

      {selected && (
        <section ref={detailsRef} tabIndex={-1} aria-label="Identity event details"
          className={box} style={{ scrollMarginTop: "110px" }}>
          <div className="mb-4 flex justify-between gap-4">
            <h2 className="font-bold text-white">Recorded Event Details</h2>
            <button className={control} onClick={closeDetails}>Close Details</button>
          </div>
          <pre className="max-h-[600px] overflow-auto whitespace-pre-wrap break-all text-sm">
            {JSON.stringify(selected, null, 2)}
          </pre>
        </section>
      )}
    </div>
  );
}
