// Observation counts and scanner-reported finding counts have different meanings.
export function reportedFindings(value) {
  return Array.isArray(value) ? value.filter(item => item && typeof item === "object" && !Array.isArray(item) && Object.keys(item).length) : [];
}

export function hostIdentity(value) {
  if (typeof value !== "string" && typeof value !== "number") return "";
  const host = String(value).trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || host === "-" || host === "—") return "";
  if (host.includes(":")) {
    try { return new URL(`http://[${host}]/`).hostname.replace(/^\[|\]$/g, ""); } catch { return host; }
  }
  return host.replace(/\.$/, "");
}

export function getHostAddress(host) {
  const addresses = Array.isArray(host?.addresses) ? host.addresses : [];
  const ip = addresses.find(item => ["ipv4", "ipv6"].includes(item?.type) && item?.address);
  return hostIdentity(ip?.address || host?.host || host?.ip);
}

export function uniqueOpenPorts(values) {
  const records = [], seen = new Set();
  for (const value of values || []) {
    if (!value || String(value.state ?? "open").toLowerCase() !== "open") continue;
    const port = Number(value.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    const host = hostIdentity(value.host || value.ip);
    const protocol = String(value.protocol || "tcp").toLowerCase();
    // Do not merge observations whose host was not recorded.
    const key = host ? JSON.stringify([host, protocol, port]) : `unattributed-${records.length}`;
    if (!seen.has(key)) {
      seen.add(key);
      records.push({ ...value, host: host || "-", protocol, port, state: "open" });
    }
  }
  return records;
}

export function nmapPortObservations(result) {
  const hosts = Array.isArray(result?.results?.hosts) ? result.results.hosts : [];
  return uniqueOpenPorts(hosts.flatMap(host => Array.isArray(host?.ports)
    ? host.ports.map(port => ({ ...port, host: getHostAddress(host) })) : []));
}

export function normalizeToolSeverity(value) {
  if (value === null || value === undefined || value === "") return "UNRATED";
  const severity = String(value).trim().toUpperCase().split(/\s*\(/)[0];
  const aliases = { INFORMATIONAL: "INFO", INFORMATION: "INFO", "0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH", "4": "CRITICAL" };
  const normalized = aliases[severity] || severity;
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(normalized) ? normalized : "UNRATED";
}

export function masscanHostsFromResult(payload) {
  const data = payload?.masscan || payload?.results || payload || {};
  const observations = [];
  for (const host of Array.isArray(data.hosts) ? data.hosts : []) {
    for (const port of Array.isArray(host?.ports) ? host.ports : []) {
      observations.push({ ...port, host: getHostAddress(host) });
    }
  }
  for (const port of Array.isArray(data.open_ports) ? data.open_ports : []) observations.push(port);
  const stdout = String(payload?.stdout || data.stdout || "");
  const pattern = /Discovered open port\s+(\d+)\/(tcp|udp)\s+on\s+([0-9a-fA-F:.]+)/gi;
  for (const match of stdout.matchAll(pattern)) observations.push({ host: match[3], port: match[1], protocol: match[2], state: "open" });
  const hosts = new Map();
  for (const observation of uniqueOpenPorts(observations)) {
    if (!hosts.has(observation.host)) hosts.set(observation.host, { host: observation.host, ports: [] });
    hosts.get(observation.host).ports.push(observation);
  }
  return [...hosts.values()];
}
