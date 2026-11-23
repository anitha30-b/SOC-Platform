
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import React, { useEffect, useState } from "react";

const API = SOC_DEPLOY_API_BASE;

export default function AdminAssetDiscovery({ onBack }) {
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState("nmap");
  const [scanType, setScanType] = useState("quick");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [job, setJob] = useState(null);
  const [result, setResult] = useState(null);
  const [savingAssets, setSavingAssets] = useState(false);
  const [assetTypeToSave, setAssetTypeToSave] = useState("Network Device");

  const token = localStorage.getItem("token");

  async function startScan(e) {
    e.preventDefault();
    setError("");
    setMessage("");
    setResult(null);
    setJob(null);

    const value = target.trim();
    if (!value) {
      setError(scanMode === "nikto" ? "Enter an authorized HTTP/HTTPS website URL." : "Enter an authorized IP address, hostname, or network range.");
      return;
    }

    setLoading(true);
    try {
      const isNikto = scanMode === "nikto";
      if (isNikto) {
        let parsed;
        try {
          parsed = new URL(value);
        } catch {
          throw new Error("Enter a valid website URL starting with https:// or http://.");
        }
        if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
          throw new Error("Only HTTP/HTTPS URLs are supported.");
        }
      }

      const response = await fetch(
        isNikto ? `${API}/vapt/nikto/run-async` : `${API}/vapt/tools/run-async`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          body: JSON.stringify(
            isNikto
              ? { target_url: value, scan_type: scanType }
              : { target: value, scan_type: scanType }
          ),
        }
      );

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || data.message || "Unable to start scan.");
      }

      setJob({ ...data, scan_mode: scanMode });
      setMessage("Scan started. You can check its progress below.");
    } catch (err) {
      setError(err.message || "Request failed. Check the backend and login.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!job?.job_id || !["starting", "queued", "running"].includes(job.status)) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      checkProgress();
    }, 5000);

    return () => window.clearInterval(timer);
  }, [job?.job_id, job?.status]);

  async function checkProgress() {
    if (!job?.job_id) return;

    setError("");
    try {
      const progressUrl =
        job.scan_mode === "nikto"
          ? `${API}/vapt/nikto/progress/${encodeURIComponent(job.job_id)}`
          : `${API}/vapt/tools/progress/${encodeURIComponent(job.job_id)}`;

      const response = await fetch(progressUrl, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to retrieve scan progress.");
      }

      setJob({ ...data, scan_mode: job.scan_mode });
      if (["completed", "completed_with_errors"].includes(data.status)) {
        setResult(data.result);

        const sync = data.asset_sync || data.result?.asset_sync;
        const syncError = data.asset_sync_error || sync?.error;

        if (syncError) {
          setMessage(
            `Scan completed, but Asset Inventory synchronization failed: ${syncError}`
          );
        } else if (sync) {
          setMessage(
            `Scan ${data.status === "completed_with_errors" ? "completed with scan warnings" : "completed"}. ` +
            `Asset Inventory: ${sync.created ?? 0} created, ` +
            `${sync.updated ?? 0} updated, ${sync.skipped ?? 0} skipped.`
          );
        } else {
          setMessage(data.status === "completed_with_errors"
            ? "Scan finished with some errors."
            : "Scan completed.");
        }
      } else if (["failed", "timeout"].includes(data.status)) {
        setError(data.error || `The scan ${data.status}.`);
      } else {
        setMessage(`Scan status: ${data.status} — ${data.progress ?? 0}%`);
      }
    } catch (err) {
      setError(err.message || "Could not retrieve scan progress.");
    }
  }

  const hosts = (
    result?.hosts ||
    result?.result?.hosts ||
    result?.results?.hosts ||
    result?.result?.results?.hosts ||
    []
  ).map((host) => {
    const addressList = Array.isArray(host.addresses)
      ? host.addresses
      : [];
    const hostnameList = Array.isArray(host.hostnames)
      ? host.hostnames
      : [];

    const ip =
      host.ip ||
      host.address ||
      addressList.find((item) => item?.type === "ipv4")?.address ||
      addressList[0]?.address ||
      "";

    const hostname =
      host.hostname ||
      hostnameList.find((item) => item?.name)?.name ||
      "";

    const ports = (host.ports || []).map((port) => {
      const service = port?.service;
      const serviceName =
        typeof service === "string"
          ? service
          : service?.name || service?.product || port?.name || "unknown";

      return {
        ...port,
        port: port?.port ?? port?.portid ?? "?",
        service: serviceName,
      };
    });

    const status =
      typeof host.status === "string"
        ? host.status
        : host.status?.state || "Discovered";

    return { ...host, ip, hostname, ports, status };
  });

  function exportDiscoveryCSV() {
    if (!hosts.length) return;

    const columns = [
      { key: "ip", label: "IP Address" },
      { key: "hostname", label: "Hostname" },
      { key: "status", label: "Status" },
      { key: "ports", label: "Ports / Services" },
    ];
    const cell = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const rows = hosts.map((host) => ({
      ip: host.ip || host.address || "",
      hostname: host.hostname || host.hostnames?.[0]?.name || "",
      status: host.status || "Discovered",
      ports: (host.ports || []).map((port) =>
        typeof port === "object"
          ? `${port.port ?? port.portid ?? "?"}/${typeof port.service === "string" ? port.service : port.service?.name || port.service?.product || port.name || "unknown"}`
          : String(port)
      ).join("; ")
    }));

    const csv = "\uFEFF" + [
      columns.map(({ label }) => cell(label)).join(","),
      ...rows.map((row) =>
        columns.map(({ key }) => cell(row[key])).join(",")
      )
    ].join("\r\n");

    const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8;" })
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "network-discovery-results.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function saveDiscoveredHosts() {
    if (!hosts.length || savingAssets) return;

    setError("");
    setMessage("");
    setSavingAssets(true);

    try {
      const headers = {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      };

      const inventoryResponse = await fetch(`${API}/assets`, { headers });
      const inventoryData = await inventoryResponse.json();

      if (!inventoryResponse.ok) {
        throw new Error(
          inventoryData.detail || "Could not check the existing asset inventory."
        );
      }

      const existing = inventoryData.assets || [];
      const known = new Set(
        existing.flatMap((asset) =>
          [asset.ip_address, asset.hostname]
            .filter(Boolean)
            .map((value) => value.trim().toLowerCase())
        )
      );

      let saved = 0;
      let updated = 0;
      let skipped = 0;
      const failures = [];

      for (const host of hosts) {
        const ip = String(host.ip || host.address || "").trim();
        const hostname = String(
          host.hostname || host.hostnames?.[0]?.name || ""
        ).trim();
        const identifiers = [ip, hostname]
          .filter(Boolean)
          .map((value) => value.toLowerCase());

        if (!identifiers.length) {
          skipped++;
          continue;
        }

        const match = existing.find((asset) =>
          (ip && String(asset.ip_address || "").trim().toLowerCase() === ip.toLowerCase()) ||
          (hostname && String(asset.hostname || "").trim().toLowerCase() === hostname.toLowerCase())
        );

        if (!match && identifiers.some((value) => known.has(value))) {
          skipped++;
          continue;
        }

        const ports = (host.ports || []).map((port) =>
          typeof port === "object"
            ? `${port.port ?? port.portid ?? "?"}/${typeof port.service === "string" ? port.service : port.service?.name || port.service?.product || port.name || "unknown"}`
            : String(port)
        );
        const services = ports.join(", ") || "None reported";
        const name = hostname || ip;
        const discoveryNotes =
          `[Nmap Discovery]\n` +
          `Scan target: ${target.trim()}\n` +
          `Host status: ${host.status || "Discovered"}\n` +
          `Open services: ${services}\n` +
          `[/Nmap Discovery]`;

        try {
          if (match) {
            const oldNotes = match.notes || "";
            const begin = "[Nmap Discovery]";
            const close = "[/Nmap Discovery]";
            let notes;

            if (oldNotes.includes(begin) && oldNotes.includes(close) &&
                oldNotes.indexOf(close) > oldNotes.indexOf(begin)) {
              const left = oldNotes.slice(0, oldNotes.indexOf(begin)).trim();
              const right = oldNotes.slice(
                oldNotes.indexOf(close) + close.length
              ).trim();
              notes = [left, discoveryNotes, right]
                .filter(Boolean).join("\n\n");
            } else {
              notes = [oldNotes.trim(), discoveryNotes]
                .filter(Boolean).join("\n\n");
            }

            // PUT requires all AssetInput fields. Preserve existing values.
            const payload = {
              name: match.name,
              asset_type: match.asset_type || "Server",
              ip_address: match.ip_address || ip || null,
              url: match.url || null,
              hostname: match.hostname || hostname || null,
              environment: match.environment || "Production",
              status: match.status || "Active",
              criticality: match.criticality || "Medium",
              owner: match.owner ?? null,
              notes,
            };

            const response = await fetch(
              `${API}/assets/${encodeURIComponent(match.id)}`,
              {
                method: "PUT",
                headers,
                body: JSON.stringify(payload),
              }
            );
            const data = await response.json();
            if (!response.ok) {
              throw new Error(data.detail || `HTTP ${response.status}`);
            }
            Object.assign(match, data);
            updated++;
          } else {
            const payload = {
              name: name.slice(0, 200),
              asset_type: assetTypeToSave,
              ip_address: ip || null,
              hostname: hostname || null,
              url: null,
              environment: "Production",
              status: "Active",
              criticality: "Medium",
              owner: null,
              notes: discoveryNotes,
            };

            const response = await fetch(`${API}/assets`, {
              method: "POST",
              headers,
              body: JSON.stringify(payload),
            });
            const data = await response.json();
            if (!response.ok) {
              throw new Error(data.detail || `HTTP ${response.status}`);
            }
            existing.push(data);
            saved++;
          }

          identifiers.forEach((value) => known.add(value));
        } catch (err) {
          failures.push(`${name}: ${err.message}`);
        }
      }

      const summary =
        `Created ${saved} host(s), updated ${updated} existing host(s), skipped ${skipped} unidentified host(s).`;

      setMessage(
        failures.length
          ? `${summary} Failed: ${failures.join("; ")}`
          : summary
      );
    } catch (err) {
      setError(err.message || "Could not save discovered hosts.");
    } finally {
      setSavingAssets(false);
    }
  }

  return (
    <div className="min-h-full bg-[#07090c] p-6 text-white">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-2 text-xs uppercase tracking-[0.25em] text-red-400">
            Asset Management / Discovery
          </p>
          <h1 className="text-3xl font-bold">Asset Discovery</h1>
          <p className="mt-2 text-sm text-gray-400">
            Discover hosts and services on networks you are authorized to test.
          </p>
        </div>
        <button
          onClick={onBack}
          className="rounded-lg border border-gray-700 px-4 py-2 hover:border-red-500"
        >
          ← Asset Inventory
        </button>
      </div>

      <form
        onSubmit={startScan}
        className="mb-6 rounded-xl border border-gray-800 bg-[#0c0f12] p-5"
      >
        <h2 className="mb-4 text-lg font-semibold">New Discovery Scan</h2>

        <label className="mb-2 block text-sm text-gray-300">
          Discovery type
        </label>
        <select
          value={scanMode}
          onChange={(e) => {
            setScanMode(e.target.value);
            setScanType("quick");
            setError("");
            setMessage("");
            setJob(null);
            setResult(null);
          }}
          className="mb-4 w-full rounded-lg border border-gray-700 bg-[#080a0d] px-4 py-3 text-white"
        >
          <option value="nmap">IP / Network Scan (Nmap)</option>
          <option value="nikto">Website URL Scan (Nikto)</option>
        </select>

        <label className="mb-2 block text-sm text-gray-300">
          {scanMode === "nikto" ? "Authorized website URL" : "Authorized target"}
        </label>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={scanMode === "nikto" ? "Example: https://your-authorized-domain.example" : "Example: 192.168.56.10 or lab.example.test"}
          className="mb-4 w-full rounded-lg border border-gray-700 bg-[#080a0d] px-4 py-3 text-white outline-none focus:border-red-500"
          required
        />

        <label className="mb-2 block text-sm text-gray-300">
          {scanMode === "nikto" ? "Website scan profile" : "Scan profile"}
        </label>
        <select
          value={scanType}
          onChange={(e) => setScanType(e.target.value)}
          className="mb-5 w-full rounded-lg border border-gray-700 bg-[#080a0d] px-4 py-3 text-white"
        >
          <option value="quick">Quick scan</option>
          {scanMode === "nikto" ? (
            <option value="detailed">Detailed scan</option>
          ) : (
            <option value="service">Service detection</option>
          )}
        </select>

        <p className="mb-4 text-xs text-amber-300">
          Only scan systems and networks for which you have explicit permission.
          Follow your existing backend scan policies.
        </p>

        <button
          type="submit"
          disabled={loading}
          className="rounded-lg bg-red-600 px-5 py-3 font-semibold hover:bg-red-500 disabled:opacity-50"
        >
          {loading ? "Starting..." : scanMode === "nikto" ? "Start Website Scan" : "Start Discovery"}
        </button>
      </form>

      {error && (
        <div className="mb-4 rounded-lg border border-red-800 bg-red-950/40 p-4 text-red-300">
          {error}
        </div>
      )}

      {message && (
        <div className="mb-4 rounded-lg border border-gray-800 bg-[#0c0f12] p-4 text-gray-200">
          {message}
        </div>
      )}

      {job && (
        <section className="mb-6 rounded-xl border border-gray-800 bg-[#0c0f12] p-5">
          <h2 className="mb-3 text-lg font-semibold">Scan Progress</h2>
          <p className="mb-2 text-sm text-gray-400">Target: {job.target || target}</p>
          <p className="mb-3 text-sm">
            Status: <span className="text-red-300">{job.status}</span>
            {" · "}
            Progress: {job.progress ?? 0}%
          </p>
          <div className="mb-4 h-2 overflow-hidden rounded bg-gray-800">
            <div
              className="h-full bg-red-500 transition-all"
              style={{ width: `${Math.max(0, Math.min(100, Number(job.progress) || 0))}%` }}
            />
          </div>
          <button
            onClick={checkProgress}
            className="rounded-lg border border-gray-700 px-4 py-2 hover:border-red-500"
          >
            Check Progress
          </button>
        </section>
      )}

      {result && (
        <section className="rounded-xl border border-gray-800 bg-[#0c0f12] p-5">
          <h2 className="mb-4 text-lg font-semibold">
            {job?.scan_mode === "nikto" ? "Website Scan Results" : "Discovery Results"}
          </h2>
          {job?.scan_mode === "nikto" ? (
            <div>
              <p className="mb-3 text-sm text-gray-400">Target: {job.target || target}</p>
              <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-lg bg-black/40 p-4 text-xs text-gray-300">
                {typeof result === "string" ? result : JSON.stringify(result, null, 2)}
              </pre>
            </div>
          ) : (
          <>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-gray-400">
              Hosts returned: {hosts.length}
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-xs text-gray-400">
                Register as:
                <select
                  value={assetTypeToSave}
                  onChange={(e) => setAssetTypeToSave(e.target.value)}
                  className="ml-2 rounded-lg border border-gray-700 bg-[#080a0d] px-3 py-2 text-white"
                >
                  <option value="Network Device">Network Device</option>
                  <option value="Server">Server</option>
                  <option value="Endpoint">Endpoint</option>
                </select>
              </label>
              <button
                type="button"
                onClick={exportDiscoveryCSV}
                disabled={!hosts.length}
                className="rounded-lg border border-gray-700 px-4 py-2 text-sm hover:border-red-500 disabled:opacity-50"
              >
                Export CSV
              </button>
            </div>
            <button
              type="button"
              onClick={saveDiscoveredHosts}
              disabled={!hosts.length || savingAssets}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {savingAssets ? "Saving Hosts..." : "Save Discovered Hosts to Inventory"}
            </button>
          </div>

          {hosts.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-gray-700 text-gray-400">
                  <tr>
                    <th className="p-3">IP Address</th>
                    <th className="p-3">Hostname</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Ports / Services</th>
                  </tr>
                </thead>
                <tbody>
                  {hosts.map((host, index) => (
                    <tr
                      key={`${host.ip || host.address || "host"}-${index}`}
                      className="border-b border-gray-800"
                    >
                      <td className="p-3 font-mono">
                        {host.ip || host.address || "—"}
                      </td>
                      <td className="p-3">
                        {host.hostname || host.hostnames?.[0]?.name || "—"}
                      </td>
                      <td className="p-3">{host.status || "Discovered"}</td>
                      <td className="p-3">
                        {(host.ports || [])
                          .map((port) =>
                            typeof port === "object"
                              ? `${port.port ?? port.portid ?? "?"}/${typeof port.service === "string" ? port.service : port.service?.name || port.service?.product || port.name || "unknown"}`
                              : String(port)
                          )
                          .join(", ") || "No port details returned"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <pre className="overflow-x-auto whitespace-pre-wrap text-xs text-gray-300">
              {JSON.stringify(result, null, 2)}
            </pre>
          )}
          </>
          )}
        </section>
      )}
    </div>
  );
}
