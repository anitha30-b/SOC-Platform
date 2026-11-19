import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000/monitoring/servers/latest";
const REFRESH_MS = 60000;

function authConfig() {
  const token = localStorage.getItem("token");
  return {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  };
}

function StatusBadge({ status }) {
  const rawStatus = String(status || "unknown").toLowerCase();

  const labels = {
    reachable: "UP",
    unreachable: "DOWN",
    unknown: "UNKNOWN",
  };

  const styles = {
    reachable: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    unreachable: "border-red-500/30 bg-red-500/10 text-red-300",
    unknown: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  };

  return (
    <span
      className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${
        styles[rawStatus] || styles.unknown
      }`}
    >
      {labels[rawStatus] || "UNKNOWN"}
    </span>
  );
}

export default function AdminServerMonitoring() {
  const [servers, setServers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadMonitoring = useCallback(async (background = false) => {
    if (background) setRefreshing(true);
    else setLoading(true);

    setError("");

    try {
      const response = await axios.get(API, authConfig());
      setServers(response.data?.servers || []);
      setLastUpdated(new Date());
    } catch (err) {
      setError(
        err.response?.status === 401 || err.response?.status === 403
          ? "Administrator authorization failed. Please sign in again with an authorized account."
          : err.response?.data?.detail ||
              "Unable to load monitoring results. Check that the backend is running."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadMonitoring();
    const timer = window.setInterval(
      () => loadMonitoring(true),
      REFRESH_MS
    );

    return () => window.clearInterval(timer);
  }, [loadMonitoring]);

  const filteredServers = useMemo(() => {
    const query = search.trim().toLowerCase();

    return servers.filter((server) =>
      [
        server.name,
        server.ip_address,
        server.status,
        server.reason,
        server.port,
      ]
        .filter((value) => value !== null && value !== undefined)
        .join(" ")
        .toLowerCase()
        .includes(query)
    );
  }, [servers, search]);

  const counts = useMemo(() => {
    const up = servers.filter(
      (server) => String(server.status).toLowerCase() === "reachable"
    ).length;

    const down = servers.filter(
      (server) => String(server.status).toLowerCase() === "unreachable"
    ).length;

    const unknown = servers.filter(
      (server) => String(server.status).toLowerCase() === "unknown"
    ).length;

    return {
      total: servers.length,
      up,
      down,
      unknown,
    };
  }, [servers]);

  function formatDate(value) {
    if (!value) return "Not available";

    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? "Not available"
      : date.toLocaleString();
  }

  const cards = [
    { label: "MONITORED SERVERS", value: counts.total, tone: "text-white" },
    { label: "SERVERS UP", value: counts.up, tone: "text-emerald-300" },
    { label: "SERVERS DOWN", value: counts.down, tone: "text-red-300" },
    { label: "UNKNOWN STATUS", value: counts.unknown, tone: "text-amber-300" },
  ];

  return (
    <section className="space-y-6 text-white">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-[0.25em] text-red-400">
            <span className="h-px w-7 bg-red-500" />
            Infrastructure / Live Monitoring
          </div>
          <h1 className="text-3xl font-bold tracking-tight">
            Server Monitoring
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-400">
            Monitor the latest TCP reachability checks for registered server
            assets.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-gray-500">
            <span className="rounded-full border border-emerald-500/25 bg-emerald-500/10 px-2.5 py-1 text-emerald-300">
              Auto-refresh enabled
            </span>
            <span>Refresh interval: 60 seconds</span>
            {lastUpdated && (
              <span>· Last API update: {lastUpdated.toLocaleTimeString()}</span>
            )}
          </div>
        </div>

        <button
          onClick={() => loadMonitoring(true)}
          disabled={refreshing}
          className="rounded-md border border-white/10 px-4 py-2 text-sm hover:border-red-500 disabled:opacity-50"
        >
          {refreshing ? "Refreshing..." : "↻ Refresh"}
        </button>
      </header>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
        >
          {error}
          <button
            onClick={() => loadMonitoring(true)}
            className="ml-3 underline"
          >
            Retry
          </button>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => (
          <div
            key={card.label}
            className="rounded-lg border border-white/10 bg-[#0b0e11] p-5"
          >
            <p className="text-[10px] font-semibold tracking-[0.15em] text-gray-500">
              {card.label}
            </p>
            <p className={`mt-4 text-3xl font-bold ${card.tone}`}>
              {loading ? "—" : card.value}
            </p>
            <p className="mt-2 text-[11px] text-gray-600">
              Latest database monitoring results
            </p>
          </div>
        ))}
      </div>

      <div className="overflow-hidden rounded-lg border border-white/10 bg-[#0b0e11]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-4">
          <div>
            <h2 className="font-semibold">Server Health Overview</h2>
            <p className="mt-1 text-xs text-gray-500">
              {filteredServers.length} displayed · {servers.length} monitored
            </p>
          </div>

          <input
            aria-label="Search monitored servers"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search server, IP, status..."
            className="w-full rounded-md border border-white/10 bg-[#090c0f] px-3 py-2.5 text-sm text-white outline-none focus:border-red-500 sm:w-72"
          />
        </div>

        {loading ? (
          <p className="p-8 text-center text-sm text-gray-400">
            Loading server monitoring results...
          </p>
        ) : filteredServers.length === 0 ? (
          <p className="p-8 text-center text-sm text-gray-400">
            No monitoring results found.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[850px] text-left text-sm">
              <thead className="bg-white/[0.03] text-[10px] uppercase tracking-wider text-gray-500">
                <tr>
                  <th className="px-4 py-3">Server</th>
                  <th className="px-4 py-3">IP Address</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Port</th>
                  <th className="px-4 py-3">Response Time</th>
                  <th className="px-4 py-3">Last Checked</th>
                  <th className="px-4 py-3">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredServers.map((server, index) => (
                  <tr
                    key={`${server.asset_id}-${index}`}
                    className="hover:bg-white/[0.025]"
                  >
                    <td className="px-4 py-4 font-medium">
                      {server.name || "Unnamed server"}
                    </td>
                    <td className="px-4 py-4 font-mono text-xs text-gray-300">
                      {server.ip_address || "—"}
                    </td>
                    <td className="px-4 py-4">
                      <StatusBadge status={server.status} />
                    </td>
                    <td className="px-4 py-4 text-gray-300">
                      {server.port ?? "—"}
                    </td>
                    <td className="px-4 py-4 text-gray-300">
                      {server.response_time_ms == null
                        ? "—"
                        : `${Number(server.response_time_ms).toFixed(2)} ms`}
                    </td>
                    <td className="px-4 py-4 text-xs text-gray-400">
                      {formatDate(server.checked_at)}
                    </td>
                    <td className="max-w-xs px-4 py-4 text-xs text-gray-400">
                      {server.reason || "No additional details"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className="text-xs leading-5 text-gray-500">
        Note: UP/DOWN reflects the configured TCP port check, not the complete
        health of the server. A server can be running while its checked port is
        closed. UNKNOWN means the monitoring result does not establish
        reachability.
      </p>
    </section>
  );
}
