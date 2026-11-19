import { useEffect, useRef, useState } from "react";
import axios from "axios";

const titles = {
  "mitre-tactics": "Tactics",
  "mitre-techniques": "Techniques",
  "mitre-subtechniques": "Sub-Techniques",
  "mitre-groups": "Groups",
  "mitre-software": "Software",
  "mitre-coverage": "Detection Coverage",
};

const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const control =
  "rounded border border-gray-700 bg-[#0b1115] px-4 py-2 text-white disabled:cursor-not-allowed disabled:opacity-40";
const pageSize = 25;

function belongs(row, view) {
  if (view === "mitre-tactics") {
    return row.type === "x-mitre-tactic";
  }
  if (view === "mitre-groups") {
    return row.type === "intrusion-set";
  }
  if (view === "mitre-software") {
    return ["malware", "tool"].includes(row.type);
  }
  return (
    row.type === "attack-pattern" &&
    Boolean(row.is_subtechnique) ===
      (view === "mitre-subtechniques")
  );
}

function context(row, coverage) {
  if (coverage) {
    return `${row.coverage_status} · ${row.observed_event_count} observed events`;
  }
  if (row.type === "x-mitre-tactic") {
    return `${row.technique_count} techniques · ${row.subtechnique_count} sub-techniques`;
  }
  const values = row.tactics?.length
    ? row.tactics
    : row.aliases || [];
  return `${row.type}${values.length ? " · " + values.join(", ") : ""}`;
}

export default function MitreReference({ apiUrl, view }) {
  const coverage = view === "mitre-coverage";

  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
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

    (async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) {
          throw new Error("Please log in again.");
        }

        const endpoint = coverage
          ? "/security-events/coverage/mitre"
          : "/mitre/reference-catalogue";

        const response = await axios.get(
          `${apiUrl}${endpoint}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
            signal: controller.signal,
            timeout: 30000,
          }
        );

        const rows = coverage
          ? response.data?.techniques
          : response.data?.records;

        if (!Array.isArray(rows)) {
          throw new Error("Unexpected MITRE response.");
        }

        if (active) {
          setData(response.data);
          setPage(0);
        }
      } catch (err) {
        if (active && !controller.signal.aborted) {
          const detail = err.response?.data?.detail;
          setError(
            typeof detail === "string"
              ? detail
              : err.message || "Unable to load MITRE records."
          );
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    })();

    return () => {
      active = false;
      controller.abort();
    };
  }, [apiUrl, coverage, refresh]);

  useEffect(() => {
    if (!selected) return;

    const frame = requestAnimationFrame(() => {
      detailsRef.current?.focus({ preventScroll: true });
      detailsRef.current?.scrollIntoView({
        block: "start",
        behavior: "auto",
      });
    });

    return () => cancelAnimationFrame(frame);
  }, [selected]);

  const closeDetails = () => {
    setSelected(null);

    requestAnimationFrame(() => {
      const button = triggerRef.current;
      if (button?.isConnected) {
        button.focus({ preventScroll: true });
        button.scrollIntoView({
          block: "center",
          behavior: "auto",
        });
      }
    });
  };

  const catalogue = data
    ? coverage
      ? data.techniques
      : data.records.filter(row => belongs(row, view))
    : [];

  const needle = search.trim().toLowerCase();
  const filtered = catalogue.filter(
    row =>
      !needle ||
      JSON.stringify(row).toLowerCase().includes(needle)
  );

  const shown = filtered.slice(
    page * pageSize,
    (page + 1) * pageSize
  );

  return (
    <div className="space-y-6 text-gray-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-3 text-xs tracking-widest text-red-500">
            MITRE ATT&CK
          </p>
          <h1 className="text-3xl font-bold text-white">
            {titles[view]}
          </h1>
        </div>

        <button
          className={control}
          onClick={() => setRefresh(value => value + 1)}
        >
          Refresh
        </button>
      </div>

      <div className={`${box} space-y-3`}>
        <p>
          {coverage
            ? "Explicit rule mappings compared with authorized persisted observations across all dates."
            : "Active reference records from the local Enterprise ATT&CK snapshot. These records do not establish activity in your environment."}
        </p>

        {!coverage && data && (
          <p>
            Dataset: {data.dataset} · {catalogue.length} active records
          </p>
        )}

        {coverage && data && (
          <>
            <p>
              Catalogue: {data.catalogue_technique_count}
              {" · "}Explicitly mapped: {data.configured_technique_count}
              {" · "}Observed catalogue techniques:{" "}
              {data.observed_catalogue_technique_count}
            </p>
            <p>
              Rule tags describe configured mappings; they do not verify
              that a detection is enabled, effective, or tested.
            </p>
            <p>
              Unmapped techniques are not automatically coverage
              deficiencies for every deployment.
            </p>
            <p>
              Observations use the existing event ownership filter.
            </p>
          </>
        )}

        <label className="block">
          Search records
          <input
            className={`${control} mt-2 w-full`}
            value={search}
            maxLength={200}
            placeholder="ATT&CK ID, name, alias, tactic, or description"
            onChange={event => {
              setSearch(event.target.value);
              setPage(0);
              setSelected(null);
            }}
          />
        </label>
      </div>

      {loading && (
        <p role="status">Loading MITRE records...</p>
      )}

      {error && (
        <p role="alert" className="text-red-400">
          {error}
        </p>
      )}

      {data && (
        <div className={box}>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p>
              {filtered.length ? page * pageSize + 1 : 0}
              {"–"}
              {Math.min(
                (page + 1) * pageSize,
                filtered.length
              )}
              {" of "}
              {filtered.length} matching records
            </p>

            <div className="flex gap-3">
              <button
                className={control}
                disabled={page === 0}
                onClick={() => {
                  setPage(value => value - 1);
                  setSelected(null);
                }}
              >
                Previous
              </button>

              <button
                className={control}
                disabled={
                  (page + 1) * pageSize >= filtered.length
                }
                onClick={() => {
                  setPage(value => value + 1);
                  setSelected(null);
                }}
              >
                Next
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {[
                    "ID",
                    "Name",
                    coverage
                      ? "Mapping / observation"
                      : "Type / context",
                    "Details",
                  ].map(label => (
                    <th
                      key={label}
                      className="p-3 text-gray-400"
                    >
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {shown.map(row => (
                  <tr
                    key={row.stix_id || row.technique_id}
                    className="border-t border-gray-800"
                  >
                    <td className="p-3 align-top">
                      {row.id || row.technique_id}
                    </td>
                    <td className="p-3 align-top">
                      {row.name}
                    </td>
                    <td className="p-3 align-top">
                      {context(row, coverage)}
                    </td>
                    <td className="p-3 align-top">
                      <button
                        className={control}
                        onClick={event => {
                          triggerRef.current = event.currentTarget;
                          setSelected(row);
                        }}
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {!shown.length && (
              <p className="p-4">No matching records.</p>
            )}
          </div>
        </div>
      )}

      {selected && (
        <section
          ref={detailsRef}
          tabIndex={-1}
          aria-label="MITRE record details"
          className={box}
          style={{ scrollMarginTop: "110px" }}
        >
          <div className="mb-5 flex flex-wrap justify-between gap-4">
            <h2 className="text-xl font-bold text-white">
              {selected.id || selected.technique_id}
              {" · "}
              {selected.name}
            </h2>

            <button
              className={control}
              onClick={closeDetails}
            >
              Close Details
            </button>
          </div>

          {!coverage && (
            <>
              <p className="mb-4">
                Record version:{" "}
                {selected.version || "Not recorded"}
                {" · "}Modified:{" "}
                {selected.modified || "Not recorded"}
              </p>

              {selected.aliases?.length > 0 && (
                <p className="mb-4">
                  Aliases: {selected.aliases.join(", ")}
                </p>
              )}

              {selected.tactics?.length > 0 && (
                <p className="mb-4">
                  Tactics: {selected.tactics.join(", ")}
                </p>
              )}

              <p className="whitespace-pre-wrap leading-7">
                {selected.description ||
                  "No description recorded."}
              </p>

              <h3 className="mb-3 mt-6 font-bold text-white">
                Source References
              </h3>

              <ul className="space-y-3">
                {(selected.references || []).map(
                  (reference, index) => (
                    <li key={index}>
                      <a
                        className="break-all text-blue-400 underline"
                        href={reference.url}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {reference.name}
                        {" — "}
                        {reference.url}
                      </a>
                    </li>
                  )
                )}
              </ul>

              {!selected.references?.length && (
                <p>No source links recorded.</p>
              )}
            </>
          )}

          {coverage && (
            <div className="space-y-4">
              <p>Status: {selected.coverage_status}</p>
              <p>
                Authorized observed events:{" "}
                {selected.observed_event_count}
              </p>

              <h3 className="font-bold text-white">
                Explicit Rule Mappings
              </h3>

              {(selected.configured_by || []).map(
                (rule, index) => (
                  <p key={index}>
                    {rule.rule_type}
                    {" · "}
                    {rule.rule_id}
                    {" · "}
                    {rule.rule_name}
                    {" · "}
                    {rule.integration_status}
                  </p>
                )
              )}

              {!selected.configured_by?.length && (
                <p>No explicit rule mapping recorded.</p>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
