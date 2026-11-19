import { useCallback, useEffect, useState } from "react";

const API = "http://127.0.0.1:8000";

const FRAMEWORKS = {
  "admin-iso27001": "ISO 27001",
  "admin-soc2": "SOC 2",
  "admin-nist": "NIST CSF",
  "admin-cis": "CIS Controls",
  "admin-pcidss": "PCI DSS",
};

const STATUSES = [
  "Not Assessed",
  "Compliant",
  "Partially Compliant",
  "Non-Compliant",
  "Not Applicable",
];

export default function AdminComplianceFramework({ menu, onBack }) {
  const framework = FRAMEWORKS[menu];
  const [controls, setControls] = useState([]);
  const [filter, setFilter] = useState("All");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const loadControls = useCallback(async () => {
    setLoading(true);
    setError("");
    setMessage("");

    const token = localStorage.getItem("token");
    if (!token) {
      setError("Admin session missing. Please log in again.");
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(
        `${API}/compliance/controls?framework=${encodeURIComponent(framework)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.detail || `Request failed (${response.status})`);
      }

      setControls(result.controls || []);
    } catch (err) {
      setError(err.message || "Could not load controls.");
    } finally {
      setLoading(false);
    }
  }, [framework]);

  useEffect(() => {
    loadControls();
  }, [loadControls]);

  function updateControl(id, field, value) {
    setControls((previous) =>
      previous.map((item) =>
        item.control_id === id ? { ...item, [field]: value } : item
      )
    );
  }

  async function saveControl(control) {
    setSaving(control.control_id);
    setError("");
    setMessage("");

    try {
      const token = localStorage.getItem("token");
      const response = await fetch(
        `${API}/compliance/controls/${encodeURIComponent(control.control_id)}?framework=${encodeURIComponent(framework)}`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            status: control.status,
            notes: control.notes || "",
            owner: control.owner || "",
            evidence_reference: control.evidence_reference || "",
          }),
        }
      );

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.detail || `Save failed (${response.status})`);
      }

      setControls((previous) =>
        previous.map((item) =>
          item.control_id === control.control_id ? result.control : item
        )
      );
      setMessage(`Assessment saved for ${control.control_id}.`);
    } catch (err) {
      setError(err.message || "Could not save the assessment.");
    } finally {
      setSaving("");
    }
  }

  if (!framework) {
    return <p className="text-white">Unsupported framework.</p>;
  }

  const visibleControls =
    filter === "All"
      ? controls
      : controls.filter((item) => item.status === filter);

  const compliant = controls.filter((c) => c.status === "Compliant").length;
  const gaps = controls.filter((c) =>
    ["Partially Compliant", "Non-Compliant"].includes(c.status)
  ).length;

  const inputClass =
    "mt-2 w-full rounded-md border border-white/15 bg-[#080808] px-3 py-2 text-sm text-white";
  const labelClass = "block text-xs text-gray-400";

  return (
    <div className="space-y-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Security Governance
          </p>
          <h1 className="mt-2 text-2xl font-bold">{framework} Assessment</h1>
          <p className="mt-2 text-sm text-gray-400">
            Assess controls, record evidence, assign owners, and track remediation.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={loadControls}
            disabled={loading}
            className="rounded-md border border-white/15 px-4 py-2 text-xs hover:border-red-500"
          >
            {loading ? "Loading..." : "Refresh"}
          </button>
          <button
            onClick={onBack}
            className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700"
          >
            ← Overview
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-950/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}
      {message && (
        <div className="rounded-lg border border-green-500/30 bg-green-950/20 p-3 text-sm text-green-300">
          {message}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[
          ["Total Controls", controls.length],
          ["Compliant", compliant],
          ["Open Gaps", gaps],
        ].map(([label, value]) => (
          <div key={label} className="rounded-xl border border-white/10 bg-[#111111] p-5">
            <p className="text-xs text-gray-400">{label}</p>
            <p className="mt-3 text-3xl font-bold">{value}</p>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-white/10 bg-[#111111] p-4 sm:p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-semibold">Control Assessments</h2>
          <select
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            className="rounded-md border border-white/15 bg-black px-3 py-2 text-sm text-white"
          >
            <option value="All">All statuses</option>
            {STATUSES.map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>
        </div>

        {loading ? (
          <p className="p-6 text-sm text-gray-400">Loading controls...</p>
        ) : visibleControls.length === 0 ? (
          <p className="p-6 text-sm text-gray-400">
            No controls found for this filter.
          </p>
        ) : (
          <div className="space-y-4">
            {visibleControls.map((control) => (
              <div
                key={control.control_id}
                className="rounded-lg border border-white/10 bg-black/30 p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold text-red-400">
                      {control.control_id}
                    </p>
                    <h3 className="mt-1 font-semibold">{control.title}</h3>
                  </div>
                  <select
                    value={control.status}
                    onChange={(event) =>
                      updateControl(control.control_id, "status", event.target.value)
                    }
                    className="rounded-md border border-white/15 bg-[#111111] px-3 py-2 text-sm text-white"
                  >
                    {STATUSES.map((status) => (
                      <option key={status} value={status}>{status}</option>
                    ))}
                  </select>
                </div>

                <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
                  <label className={labelClass}>
                    Control Owner
                    <input
                      value={control.owner || ""}
                      maxLength={150}
                      onChange={(event) =>
                        updateControl(control.control_id, "owner", event.target.value)
                      }
                      placeholder="Responsible person or team"
                      className={inputClass}
                    />
                  </label>
                  <label className={labelClass}>
                    Evidence Reference
                    <input
                      value={control.evidence_reference || ""}
                      maxLength={500}
                      onChange={(event) =>
                        updateControl(control.control_id, "evidence_reference", event.target.value)
                      }
                      placeholder="Evidence filename, URL, or ticket ID"
                      className={inputClass}
                    />
                  </label>
                  <label className={`${labelClass} md:col-span-2`}>
                    Assessment Notes
                    <textarea
                      value={control.notes || ""}
                      maxLength={5000}
                      rows={3}
                      onChange={(event) =>
                        updateControl(control.control_id, "notes", event.target.value)
                      }
                      placeholder="Observations, justification, or remediation plan"
                      className={inputClass}
                    />
                  </label>
                </div>

                <div className="mt-3 flex justify-end">
                  <button
                    onClick={() => saveControl(control)}
                    disabled={saving === control.control_id}
                    className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700 disabled:opacity-50"
                  >
                    {saving === control.control_id ? "Saving..." : "Save Assessment"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="text-xs text-gray-500">
        Starter control examples for internal tracking. This is not a complete
        framework catalogue or an official certification determination.
      </p>
    </div>
  );
}
