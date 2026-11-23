
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API = SOC_DEPLOY_API_BASE;

function Badge({ status }) {
  const value = String(status || "UNKNOWN").toUpperCase();
  const styles = {
    HEALTHY: "bg-green-500/10 text-green-400 border-green-500/30",
    ONLINE: "bg-green-500/10 text-green-400 border-green-500/30",
    REACHABLE: "bg-green-500/10 text-green-400 border-green-500/30",
    WARNING: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    CRITICAL: "bg-red-500/10 text-red-400 border-red-500/30",
    OFFLINE: "bg-red-500/10 text-red-400 border-red-500/30",
    UNREACHABLE: "bg-red-500/10 text-red-400 border-red-500/30",
    NEVER_CONNECTED: "bg-gray-500/10 text-gray-400 border-gray-500/30",
  };
  return (
    <span className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${styles[value] || styles.NEVER_CONNECTED}`}>
      {value.replaceAll("_", " ")}
    </span>
  );
}

function Metric({ title, value, unit = "%", status }) {
  const number = Number(value);
  const valid = Number.isFinite(number);
  const width = valid ? Math.max(0, Math.min(100, number)) : 0;

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
      <div className="flex justify-between gap-2">
        <p className="text-sm text-gray-400">{title}</p>
        {status && <Badge status={status} />}
      </div>
      <p className="mt-4 text-3xl font-semibold text-white">
        {valid ? number : "—"}
        {valid && <span className="ml-1 text-sm text-gray-500">{unit}</span>}
      </p>
      <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/10">
        <div
          className={`h-full rounded-full transition-all ${
            number >= 90 ? "bg-red-500" : number >= 75 ? "bg-yellow-500" : "bg-green-500"
          }`}
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  );
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatUptime(seconds) {
  if (!Number.isFinite(Number(seconds))) return "—";
  const total = Math.max(0, Math.floor(Number(seconds)));
  return `${Math.floor(total / 86400)}d ${Math.floor((total % 86400) / 3600)}h ${Math.floor((total % 3600) / 60)}m`;
}

export default function AdminEnvironmentHealth() {
  const [system, setSystem] = useState(null);
  const [servers, setServers] = useState([]);
  const [agents, setAgents] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadEnvironment = useCallback(async (manual = false) => {
    const token = localStorage.getItem("token");

    if (!token) {
      setError("Session token missing. Please log in again.");
      setLoading(false);
      return;
    }

    if (manual) setRefreshing(true);
    else setLoading(true);

    setError("");
    const headers = { Authorization: `Bearer ${token}` };

    try {
      const results = await Promise.allSettled([
        axios.get(`${API}/system/health`, { headers, timeout: 15000 }),
        axios.get(`${API}/monitoring/servers/latest`, { headers, timeout: 15000 }),
        axios.get(`${API}/agent-health`, { headers, timeout: 15000 }),
      ]);

      const failures = [];

      if (results[0].status === "fulfilled") {
        setSystem(results[0].value.data);
      } else {
        failures.push("System health");
      }

      if (results[1].status === "fulfilled") {
        setServers(results[1].value.data.servers || []);
      } else {
        failures.push("Server monitoring");
      }

      if (results[2].status === "fulfilled") {
        setAgents(results[2].value.data);
      } else {
        failures.push("Agent health");
      }

      if (failures.length === 3) {
        setError("Unable to load environment health. Check backend connectivity and administrator access.");
      } else if (failures.length > 0) {
        setError(`Some monitoring data could not be loaded: ${failures.join(", ")}.`);
      }

      setLastUpdated(new Date());
    } catch {
      setError("Unable to load environment health.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadEnvironment();
    const timer = setInterval(() => loadEnvironment(), 10000);
    return () => clearInterval(timer);
  }, [loadEnvironment]);

  const onlineServers = servers.filter(
    (server) => ["REACHABLE", "ONLINE", "HEALTHY"].includes(
      String(server.status || "").toUpperCase()
    )
  ).length;

  const resources = system?.resources;
  const components = [
    ["API Service", system?.api],
    ["PostgreSQL Database", system?.database],
    ["PostgreSQL Event Listener", system?.postgres_event_listener],
  ];

  if (loading && !system && !agents && servers.length === 0) {
    return <div className="p-8 text-center text-gray-400">Loading environment health...</div>;
  }

  return (
    <div className="space-y-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">Overview / Monitoring</p>
          <h1 className="mt-2 text-2xl font-bold">Environment Health</h1>
          <p className="mt-2 text-sm text-gray-400">
            Monitor SOC Platform services, infrastructure resources, servers and security agents.
          </p>
          <p className="mt-2 text-xs text-gray-500">
            Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "Not available"}
            {" · "}Automatic refresh every 10 seconds
          </p>
        </div>
        <button
          type="button"
          onClick={() => loadEnvironment(true)}
          disabled={refreshing}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
        >
          {refreshing ? "Refreshing..." : "↻ Refresh"}
        </button>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm text-yellow-300">
          {error}
        </div>
      )}

      {system && (
        <>
          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-xs text-gray-500">Overall Environment Status</p>
                <h2 className="mt-2 text-xl font-semibold">{system.service || "SOC Platform"}</h2>
                <p className="mt-2 text-xs text-gray-500">Checked: {formatDate(system.checked_at)}</p>
              </div>
              <Badge status={system.status} />
            </div>
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold">Infrastructure Resource Usage</h2>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              <Metric title="CPU Usage" value={resources?.cpu_usage_percent} status={resources?.status} />
              <Metric title="Memory Usage" value={resources?.memory_usage_percent} status={resources?.status} />
              <Metric title="Disk Usage" value={resources?.disk_usage_percent} status={resources?.status} />
            </div>
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold">Core Service Health</h2>
            <div className="grid gap-3 lg:grid-cols-3">
              {components.map(([title, data]) => (
                <div key={title} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-medium">{title}</h3>
                    <Badge status={data?.status} />
                  </div>
                  <p className="mt-3 text-xs leading-5 text-gray-400">
                    {data?.message || "No status information available."}
                  </p>
                  {data?.latency_ms !== undefined && (
                    <p className="mt-3 text-xs text-gray-500">Latency: {data.latency_ms} ms</p>
                  )}
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <h2 className="mb-4 text-sm font-semibold">Host Information</h2>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {[
                ["Hostname", system.host?.hostname],
                ["Operating System", system.host?.operating_system],
                ["OS Version", system.host?.os_version],
                ["Architecture", system.host?.architecture],
                ["Uptime", formatUptime(system.host?.uptime_seconds)],
                ["Memory", resources ? `${resources.memory_used_gb} / ${resources.memory_total_gb} GB` : "—"],
                ["Disk Free", resources ? `${resources.disk_free_gb} GB` : "—"],
              ].map(([label, value]) => (
                <div key={label}>
                  <p className="text-xs text-gray-500">{label}</p>
                  <p className="mt-1 break-words text-sm text-gray-200">{value ?? "—"}</p>
                </div>
              ))}
            </div>
          </section>
        </>
      )}

      <section>
        <h2 className="mb-3 text-sm font-semibold">Server Health</h2>
        <div className="mb-3 grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
            <p className="text-xs text-gray-500">Monitored Servers</p>
            <p className="mt-2 text-2xl font-semibold">{servers.length}</p>
          </div>
          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
            <p className="text-xs text-gray-500">Healthy Servers</p>
            <p className="mt-2 text-2xl font-semibold text-green-400">{onlineServers}</p>
          </div>
        </div>
        <div className="overflow-x-auto rounded-xl border border-white/10">
          <table className="w-full min-w-[600px] text-left text-sm">
            <thead className="bg-white/[0.04] text-xs text-gray-400">
              <tr>
                <th className="p-3">Server</th>
                <th className="p-3">IP Address</th>
                <th className="p-3">Status</th>
                <th className="p-3">Response</th>
                <th className="p-3">Last Checked</th>
              </tr>
            </thead>
            <tbody>
              {servers.length ? servers.map((server) => (
                <tr key={server.asset_id} className="border-t border-white/10">
                  <td className="p-3">{server.name}</td>
                  <td className="p-3 text-gray-400">{server.ip_address || "—"}</td>
                  <td className="p-3"><Badge status={server.status} /></td>
                  <td className="p-3 text-gray-400">{server.response_time_ms ?? "—"} ms</td>
                  <td className="p-3 text-gray-400">{formatDate(server.checked_at)}</td>
                </tr>
              )) : (
                <tr><td colSpan="5" className="p-5 text-center text-gray-500">No server monitoring records available.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold">Security Agent Health</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            ["Total Agents", agents?.total ?? 0],
            ["Online", agents?.online ?? 0],
            ["Offline", agents?.offline ?? 0],
            ["Never Connected", agents?.never_connected ?? 0],
          ].map(([label, value]) => (
            <div key={label} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-xs text-gray-500">{label}</p>
              <p className="mt-2 text-2xl font-semibold">{value}</p>
            </div>
          ))}
        </div>

        <div className="mt-3 overflow-x-auto rounded-xl border border-white/10">
          <table className="w-full min-w-[600px] text-left text-sm">
            <thead className="bg-white/[0.04] text-xs text-gray-400">
              <tr>
                <th className="p-3">Agent</th>
                <th className="p-3">Hostname</th>
                <th className="p-3">Operating System</th>
                <th className="p-3">Status</th>
                <th className="p-3">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {agents?.agents?.length ? agents.agents.map((agent) => (
                <tr key={agent.id} className="border-t border-white/10">
                  <td className="p-3">{agent.name}</td>
                  <td className="p-3 text-gray-400">{agent.hostname}</td>
                  <td className="p-3 text-gray-400">{agent.operating_system}</td>
                  <td className="p-3"><Badge status={agent.status} /></td>
                  <td className="p-3 text-gray-400">{formatDate(agent.last_seen)}</td>
                </tr>
              )) : (
                <tr><td colSpan="5" className="p-5 text-center text-gray-500">No security agents registered.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {agents?.heartbeat_timeout_seconds && (
          <p className="mt-2 text-xs text-gray-500">
            Agent is considered offline after {agents.heartbeat_timeout_seconds} seconds without a heartbeat.
          </p>
        )}
      </section>
    </div>
  );
}
