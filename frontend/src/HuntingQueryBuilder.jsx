import { useState } from "react";

export default function HuntingQueryBuilder({ onRun }) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("");
  const [eventType, setEventType] = useState("");
  const field = "mt-2 w-full rounded border border-white/10 bg-[#0b1014] px-3 py-3 text-sm text-gray-200";
  const query = {
    search_text: search.trim(),
    severity,
    source: source.trim() || "all",
    event_type: eventType.trim().toLowerCase() || "all",
  };

  return (
    <div>
      <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">Threat Hunting</p>
      <h1 className="mt-2 text-2xl font-bold text-white">Query Builder</h1>
      <p className="mt-2 text-xs leading-6 text-gray-400">
        Combine filters to search authorized persisted events.
        All specified filters must match. Results contain up to the latest 500 matching events.
      </p>

      <form onSubmit={event => {
        event.preventDefault();
        onRun(query);
      }} className="mt-5 rounded-lg border border-white/10 bg-[#0b1014] p-5">
        <div className="grid gap-5 md:grid-cols-2">
          <label className="text-xs text-gray-400">
            Search text
            <input type="text" maxLength={200} className={field}
              value={search} onChange={event => setSearch(event.target.value)}
              placeholder="For example: 127.0.0.1 or sudo" />
            <span className="mt-2 block leading-5">
              Searches source, type, message, target, and MITRE fields.
              It does not search all raw evidence.
            </span>
          </label>

          <label className="text-xs text-gray-400">
            Severity
            <select className={field} value={severity}
              onChange={event => setSeverity(event.target.value)}>
              <option value="all">All levels</option>
              {["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "ERROR", "WARNING"].map(value =>
                <option key={value}>{value}</option>)}
            </select>
          </label>

          <label className="text-xs text-gray-400">
            Exact source
            <input type="text" maxLength={255} className={field}
              value={source} onChange={event => setSource(event.target.value)}
              placeholder="Leave blank for all; example: tshark-siem" />
          </label>

          <label className="text-xs text-gray-400">
            Exact event type
            <input type="text" maxLength={100} className={field}
              value={eventType} onChange={event => setEventType(event.target.value)}
              placeholder="Leave blank for all; example: network_detection" />
          </label>
        </div>

        <section className="mt-5 rounded border border-white/10 p-4">
          <h2 className="text-sm font-semibold text-white">Query Summary</h2>
          <dl className="mt-3 grid gap-3 text-xs md:grid-cols-2">
            {[
              ["Text", query.search_text || "Any"],
              ["Severity", query.severity],
              ["Source", query.source],
              ["Event type", query.event_type],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-gray-500">{label}</dt>
                <dd className="mt-1 break-all text-gray-200">{value}</dd>
              </div>
            ))}
          </dl>
        </section>

        <div className="mt-5 flex flex-wrap gap-3">
          <button type="submit"
            className="rounded border border-red-500/40 bg-red-500/10 px-5 py-3 text-xs text-red-300">
            Run Query
          </button>
          <button type="button" onClick={() => {
            setSearch(""); setSeverity("all"); setSource(""); setEventType("");
          }} className="rounded border border-white/10 px-5 py-3 text-xs text-gray-300">
            Clear Filters
          </button>
        </div>
        <p className="mt-3 text-xs leading-6 text-gray-500">
          Run Query opens Event Search. Use Save Current Search there to retain these filters.
          No scanning, blocking, or incident-status changes are performed.
        </p>
      </form>
    </div>
  );
}
