import { useEffect, useRef, useState } from "react";
import axios from "axios";

const titles = {
  "secrets-dashboard": "Secrets Dashboard",
  "secrets-exposed": "Exposed Secrets",
  "secrets-api-keys": "API Keys",
  "secrets-tokens": "Tokens",
  "secrets-credentials": "Credentials",
};
const categories = {
  "secrets-api-keys": "api_keys",
  "secrets-tokens": "tokens",
  "secrets-credentials": "credentials",
};
const box = "rounded-lg border border-gray-800 bg-[#0b1115] p-5";
const control =
  "rounded border border-gray-700 bg-[#0b1115] px-4 py-2 text-white disabled:opacity-40";

export default function SecretsSecurity({ apiUrl, view }) {
  const [data, setData] = useState(null);
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);
  const detailsRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError("");
    setData(null);
    setSelected(null);

    const timer = setTimeout(async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Please log in again.");
        const response = await axios.get(`${apiUrl}/code-security/secrets-registry`, {
          params: {
            category: categories[view] || "all",
            search: search.trim(),
            offset,
            page_size: 25,
          },
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
          timeout: 30000,
        });
        if (!Array.isArray(response.data?.findings)) {
          throw new Error("Unexpected secrets registry response.");
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
    }, 300);

    return () => {
      active = false;
      clearTimeout(timer);
      controller.abort();
    };
  }, [apiUrl, view, search, offset, refresh]);

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

  return (
    <div className="space-y-6 text-gray-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-3 text-xs tracking-widest text-red-500">SECRETS SECURITY</p>
          <h1 className="text-3xl font-bold text-white">{titles[view]}</h1>
        </div>
        <button className={control} disabled={loading}
          onClick={() => setRefresh(value => value + 1)}>
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      <div className={`${box} space-y-3 text-sm`}>
        <p>
          Persisted Gitleaks findings belonging to your platform account.
          This follows the existing personal finding scope, including when
          your account belongs to a client.
        </p>
        <p>
          Findings are potential exposures, not verified active credentials.
          Raw evidence, source snippets, secret values, and scanner Match
          fields are not returned by this registry.
        </p>
        <p>
          Categories use an explicit scanner rule-ID mapping.
          Unrecognized rules remain Unclassified and are visible in
          Secrets Dashboard or Exposed Secrets.
        </p>
        <p>
          Finding status is recorded workflow metadata, not verification
          that a credential was rotated or revoked.
        </p>
      </div>

      {loading && <p role="status">Loading finding metadata...</p>}
      {error && <p role="alert" className="text-red-400">{error}</p>}

      {data && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
          {[
            ["All Gitleaks findings", data.total],
            ["API key findings", data.by_category.api_keys],
            ["Token findings", data.by_category.tokens],
            ["Credential findings", data.by_category.credentials],
            ["Unclassified findings", data.by_category.unclassified],
          ].map(([label, count]) => (
            <div key={label} className={box}>
              <p className="text-sm text-gray-400">{label}</p>
              <p className="mt-3 text-3xl font-bold text-white">{count}</p>
            </div>
          ))}
        </div>
      )}

      <div className={box}>
        <label className="block text-sm">
          Search finding metadata
          <input className={`${control} mt-2 w-full`} value={search}
            maxLength={200} placeholder="File path, scanner rule, status, or assessment"
            onChange={event => {
              setSearch(event.target.value);
              setOffset(0);
              setSelected(null);
            }} />
        </label>
      </div>

      {data && (
        <div className={box}>
          <div className="mb-4 flex flex-wrap justify-between gap-3">
            <p>
              {data.matched_total ? offset + 1 : 0}–
              {Math.min(offset + 25, data.matched_total)}
              {" of "}{data.matched_total} matching findings
            </p>
            <div className="flex gap-3">
              <button className={control} disabled={offset === 0}
                onClick={() => setOffset(value => Math.max(0, value - 25))}>
                Previous
              </button>
              <button className={control} disabled={data.next_offset === null}
                onClick={() => setOffset(data.next_offset)}>
                Next
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {["Finding", "Category", "Rule", "File", "Line", "Status", "Details"].map(label => (
                    <th key={label} className="p-3 text-gray-400">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.findings.map(row => (
                  <tr key={row.id} className="border-t border-gray-800">
                    {[
                      `#${row.id}`, row.category, row.rule_id,
                      row.file_path, row.line_start, row.status,
                    ].map((value, index) => (
                      <td key={index} className="max-w-lg break-all p-3 align-top">
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
            {!data.findings.length && (
              <p className="p-4">
                No matching persisted Gitleaks findings.
                This does not establish that repositories contain no secrets.
              </p>
            )}
          </div>
        </div>
      )}

      {selected && (
        <section ref={detailsRef} tabIndex={-1} aria-label="Secret finding metadata"
          className={box} style={{ scrollMarginTop: "110px" }}>
          <div className="mb-4 flex justify-between gap-4">
            <h2 className="font-bold text-white">Finding Metadata</h2>
            <button className={control} onClick={closeDetails}>Close Details</button>
          </div>
          <dl className="space-y-3">
            {Object.entries(selected).map(([key, value]) => (
              <div key={key}>
                <dt className="text-sm text-gray-400">{key.replaceAll("_", " ")}</dt>
                <dd className="whitespace-pre-wrap break-all">
                  {typeof value === "boolean" ? String(value) : value ?? "Not recorded"}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      )}
    </div>
  );
}
