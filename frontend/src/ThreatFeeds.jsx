import { useEffect, useState } from "react";

export default function ThreatFeeds({ apiUrl }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timer = setTimeout(() => controller.abort(), 15000);
    setLoading(true);
    setError("");
    const load = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");
        const response = await fetch(`${apiUrl}/ioc/source-status`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Source-status request failed (${response.status}).`);
        const result = await response.json();
        if (!result.snapshot || !result.registry || !result.nvd) {
          throw new Error("Unexpected source-status response.");
        }
        if (active) setData(result);
      } catch (err) {
        if (active) setError(err.name === "AbortError" ? "Request timed out." : err.message);
      } finally {
        clearTimeout(timer);
        if (active) setLoading(false);
      }
    };
    void load();
    return () => { active = false; clearTimeout(timer); controller.abort(); };
  }, [apiUrl, refresh]);

  const panel = "rounded-lg border border-white/10 bg-[#0b1014] p-5";
  return (
    <div>
      <div className="mb-6 flex items-center justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">Threat Intelligence</p>
          <h1 className="mt-2 text-2xl font-bold text-white">Threat Feeds</h1>
          <p className="mt-2 text-xs text-gray-400">Intelligence sources and ingestion status</p>
        </div>
        <button disabled={loading} onClick={() => setRefresh(value => value + 1)}
          className="rounded border border-white/10 px-4 py-2 text-xs text-gray-300 disabled:opacity-40">
          {loading ? "Checking..." : "Refresh Status"}
        </button>
      </div>
      {error && <p role="alert" className="mb-4 text-xs text-red-400">{error}</p>}
      {data && <>
        <p className="mb-4 text-xs text-gray-500">
          Last successful status check: {data.checked_at}
        </p>
        <div className="grid gap-5 xl:grid-cols-2">
          <section className={panel}>
            <h2 className="text-sm font-semibold text-white">Enterprise ATT&CK</h2>
            <div className="mt-3 space-y-2 break-words text-xs leading-6 text-gray-300">
              <p>Mode: {data.snapshot.mode}</p>
              <p>Status: {data.snapshot.status}</p>
              <p>Dataset: {data.snapshot.dataset}</p>
              <p>Local file modified: {data.snapshot.file_modified_at || "Unavailable"}</p>
              <p>Latest record modified: {data.snapshot.latest_record_modified_at || "Unavailable"}</p>
              {Object.entries(data.snapshot.records).map(([kind, count]) =>
                <p key={kind}>{kind}: {count}</p>)}
              <p className="text-gray-500">
                File modification time is not an import time or proof that this is the latest published dataset.
              </p>
            </div>
          </section>
          <section className={panel}>
            <h2 className="text-sm font-semibold text-white">NVD</h2>
            <div className="mt-3 space-y-2 text-xs leading-6 text-gray-300">
              <p>Mode: {data.nvd.mode}</p>
              <p>Status: {data.nvd.status}</p>
              <p>API key configured: {data.nvd.api_key_configured ? "Yes" : "No"}</p>
              <p className="text-gray-500">
                Refresh Status does not contact NVD. Use CVE Intelligence to perform a lookup.
              </p>
            </div>
          </section>
          <section className={panel}>
            <h2 className="text-sm font-semibold text-white">Scoped IOC Registry</h2>
            <p className="mt-3 text-xs text-gray-300">
              {data.registry.total} indicators · {data.registry.scope} scope
            </p>
            <div className="mt-3 space-y-2 text-xs text-gray-300">
              {data.registry.sources.map(item =>
                <p key={item.label}>{item.label}: {item.count}</p>)}
            </div>
            <p className="mt-3 text-xs leading-6 text-gray-500">
              Source labels are registry metadata, not verified feed connections.
            </p>
          </section>
          <section className={panel}>
            <h2 className="text-sm font-semibold text-white">Automated Feed Ingestion</h2>
            <p className="mt-3 text-xs text-gray-300">{data.automated_ingestion}</p>
            <p className="mt-2 text-xs text-gray-300">Import history: {data.import_history}</p>
            <p className="mt-3 text-xs leading-6 text-gray-500">
              No scheduled sync or feed-import history is implemented by this page.
            </p>
          </section>
        </div>
      </>}
    </div>
  );
}
