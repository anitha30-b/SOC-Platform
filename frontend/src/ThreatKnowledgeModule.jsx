import { useEffect, useState } from "react";

export default function ThreatKnowledgeModule({ apiUrl, view }) {
  const [category, title] = ({
    "threat-actors": ["actors", "Threat Actors"],
    "threat-campaigns": ["campaigns", "Campaigns"],
    "threat-malware": ["malware", "Malware Intelligence"],
  })[view];
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [reload, setReload] = useState(0);
  const [page, setPage] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState("");
  const [detailLoading, setDetailLoading] = useState(false);
  const size = 25;
  const button = "rounded border border-white/10 px-4 py-2 text-xs text-gray-300 disabled:opacity-40";

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    let timeout;
    setLoading(true);
    setError("");
    setPage(null);
    const debounce = setTimeout(async () => {
      timeout = setTimeout(() => controller.abort(), 15000);
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");
        const params = new URLSearchParams({
          search: search.trim(), offset: String(offset), page_size: String(size),
        });
        const response = await fetch(
          `${apiUrl}/threat-knowledge/${category}?${params}`,
          { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal }
        );
        if (!response.ok) throw new Error(`Dataset request failed (${response.status}).`);
        const data = await response.json();
        if (!Array.isArray(data.records) || !Number.isInteger(data.total)) {
          throw new Error("Unexpected dataset response.");
        }
        if (active) {
          setPage(data);
          if (offset > 0 && !data.records.length) setOffset(0);
        }
      } catch (err) {
        if (active) setError(err.name === "AbortError" ? "Request timed out." : err.message);
      } finally {
        clearTimeout(timeout);
        if (active) setLoading(false);
      }
    }, 300);
    return () => {
      active = false;
      clearTimeout(debounce);
      clearTimeout(timeout);
      controller.abort();
    };
  }, [apiUrl, category, search, offset, reload]);

  useEffect(() => {
    setDetail(null);
    setDetailError("");
    if (!selectedId) {
      setDetailLoading(false);
      return;
    }
    const controller = new AbortController();
    let active = true;
    const timeout = setTimeout(() => controller.abort(), 15000);
    setDetailLoading(true);
    const load = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");
        const response = await fetch(
          `${apiUrl}/threat-knowledge/${category}/${encodeURIComponent(selectedId)}`,
          { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal }
        );
        if (!response.ok) throw new Error(`Detail request failed (${response.status}).`);
        const data = await response.json();
        if (!data.record || data.record.id !== selectedId) {
          throw new Error("Unexpected detail response.");
        }
        if (active) setDetail(data);
      } catch (err) {
        if (active) setDetailError(err.name === "AbortError" ? "Detail request timed out." : err.message);
      } finally {
        clearTimeout(timeout);
        if (active) setDetailLoading(false);
      }
    };
    void load();
    return () => {
      active = false;
      clearTimeout(timeout);
      controller.abort();
    };
  }, [apiUrl, category, selectedId, reload]);

  const safeLink = value => {
    try {
      const url = new URL(value);
      return ["https:", "http:"].includes(url.protocol) ? url.href : null;
    } catch { return null; }
  };

  const renderDescription = value => {
    const text = value || "No description provided.";
    return text.split(/\n\s*\n/).map((paragraph, paragraphIndex) => {
      const parts = [];
      const pattern = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g;
      let position = 0;

      for (const match of paragraph.matchAll(pattern)) {
        parts.push(paragraph.slice(position, match.index));
        const href = safeLink(match[2]);
        parts.push(href ? (
          <a key={`${paragraphIndex}-${match.index}`}
            href={href} target="_blank" rel="noopener noreferrer"
            className="break-words text-blue-400 underline underline-offset-2">
            {match[1]}
          </a>
        ) : match[0]);
        position = match.index + match[0].length;
      }
      parts.push(paragraph.slice(position));

      return (
        <p key={paragraphIndex}
          className="whitespace-pre-wrap break-words text-sm leading-7 text-gray-300">
          {parts}
        </p>
      );
    });
  };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">Threat Intelligence</p>
          <h1 className="mt-2 text-2xl font-bold text-white">{title}</h1>
          <p className="mt-2 text-xs text-gray-400">Local Enterprise ATT&CK reference intelligence</p>
        </div>
        <button className={button} disabled={loading}
          onClick={() => setReload(value => value + 1)}>Refresh</button>
      </div>

      <section className="mb-5 rounded-lg border border-white/10 bg-[#0b1014] p-4">
        <p className="text-xs leading-6 text-gray-400">
          {page?.dataset_file || "Loading dataset metadata"} · {page?.overall_total ?? "—"} active records
        </p>
        <p className="mt-2 text-xs text-gray-400">
          Reference records do not establish actor, campaign, or malware activity in your environment.
        </p>
        <label className="mt-4 block text-xs text-gray-400">Search name, ATT&CK ID, or alias
          <input type="search" maxLength={200} value={search}
            onChange={event => { setSearch(event.target.value); setOffset(0); }}
            className="mt-2 w-full rounded border border-white/10 bg-[#0b1014] px-3 py-2 text-gray-200" />
        </label>
      </section>

      {error && <p role="alert" className="mb-4 text-xs text-red-400">{error}</p>}

      <section className="overflow-hidden rounded-lg border border-white/10 bg-[#0b1014]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-4">
          <p className="text-xs text-gray-400" aria-live="polite">
            {loading ? "Loading..." : page?.total
              ? `${offset + 1}–${offset + page.records.length} of ${page.total} matching records`
              : "No matching records"}
          </p>
          <div className="flex gap-2">
            <button className={button} disabled={loading || offset === 0}
              onClick={() => setOffset(Math.max(0, offset - size))}>Previous</button>
            <button className={button} disabled={loading || page?.next_offset == null}
              onClick={() => setOffset(page.next_offset)}>Next</button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-white/10 text-gray-400">
              <tr>{["ID", "Name", "Aliases", "Modified", "Actions"].map(label =>
                <th key={label} className="px-4 py-3">{label}</th>)}</tr>
            </thead>
            <tbody>
              {page?.records.map(item => (
                <tr key={item.stix_id} className="border-b border-white/5 text-gray-300">
                  <td className="px-4 py-4">{item.id || "Unavailable"}</td>
                  <td className="px-4 py-4 text-white">{item.name}</td>
                  <td className="max-w-xs break-words px-4 py-4">{item.aliases.join(", ") || "—"}</td>
                  <td className="px-4 py-4">{item.modified || "—"}</td>
                  <td className="px-4 py-4">
                    <button className={button} disabled={!item.id}
                      onClick={() => setSelectedId(item.id)}>Details</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selectedId && <section className="mt-5 rounded-lg border border-white/10 bg-[#0b1014] p-5">
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-sm font-semibold text-white">{selectedId}</h2>
          <button className={button} onClick={() => setSelectedId(null)}>Close Details</button>
        </div>
        {detailLoading && <p role="status" className="mt-4 text-xs text-gray-400">Loading details...</p>}
        {detailError && <p role="alert" className="mt-4 text-xs text-red-400">{detailError}</p>}
        {detail && <>
          <h3 className="mt-4 text-lg font-semibold text-white">{detail.record.name}</h3>
          <p className="mt-2 text-xs text-gray-400">
            Record version: {detail.record.version || "Unavailable"} · Source: {detail.dataset_file}
          </p>
          <div className="mt-4 space-y-4">
            {renderDescription(detail.record.description)}
          </div>
          <h3 className="mt-5 text-sm font-semibold text-white">Source References</h3>
          <div className="mt-3 space-y-2">
            {detail.record.references.map((ref, index) => {
              const href = safeLink(ref.url);
              return href ? <a key={`${href}-${index}`} href={href}
                target="_blank" rel="noopener noreferrer"
                className="block break-all text-xs text-blue-400 underline">
                {ref.source || "Reference"} — {ref.url}
              </a> : null;
            })}
          </div>
        </>}
      </section>}
    </div>
  );
}
