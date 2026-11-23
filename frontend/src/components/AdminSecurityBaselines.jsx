
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = SOC_DEPLOY_API_BASE;
const EMPTY_FORM = {
  name: "",
  framework: "CIS",
  category: "Access Control",
  description: "",
  severity: "MEDIUM",
  enabled: true,
  baseline_content: "",
};

const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export default function AdminSecurityBaselines() {
  const [baselines, setBaselines] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [editingId, setEditingId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const getConfig = () => ({
    headers: {
      Authorization: `Bearer ${localStorage.getItem("token")}`,
    },
  });

  const loadBaselines = async () => {
    try {
      setLoading(true);
      setError("");
      const response = await axios.get(
        `${API_URL}/admin/security-baselines`,
        getConfig()
      );
      setBaselines(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Failed to load baselines.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadBaselines();
  }, []);

  const change = (field, value) =>
    setForm((current) => ({ ...current, [field]: value }));

  const resetForm = () => {
    setForm(EMPTY_FORM);
    setEditingId(null);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setSuccess("");

    try {
      setSaving(true);
      const payload = {
        ...form,
        name: form.name.trim(),
        description: form.description.trim(),
        baseline_content: form.baseline_content.trim() || null,
      };

      if (!payload.name || !payload.category || !payload.description) {
        setError("Name, category, and description are required.");
        return;
      }

      if (editingId !== null) {
        await axios.put(
          `${API_URL}/admin/security-baselines/${editingId}`,
          payload,
          getConfig()
        );
        setSuccess("Security baseline updated successfully.");
      } else {
        await axios.post(
          `${API_URL}/admin/security-baselines`,
          payload,
          getConfig()
        );
        setSuccess("Security baseline created successfully.");
      }

      resetForm();
      await loadBaselines();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not save baseline.");
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (item) => {
    setForm({
      name: item.name || "",
      framework: item.framework || "CIS",
      category: item.category || "Access Control",
      description: item.description || "",
      severity: item.severity || "MEDIUM",
      enabled: Boolean(item.enabled),
      baseline_content: item.baseline_content || "",
    });
    setEditingId(item.id);
    setError("");
    setSuccess("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleToggle = async (item) => {
    try {
      setError("");
      setSuccess("");
      await axios.patch(
        `${API_URL}/admin/security-baselines/${item.id}/status`,
        null,
        { ...getConfig(), params: { enabled: !item.enabled } }
      );
      setSuccess(`Baseline "${item.name}" status updated.`);
      await loadBaselines();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not update status.");
    }
  };

  const handleDelete = async (item) => {
    if (!window.confirm(`Delete security baseline "${item.name}"?`)) return;
    try {
      setError("");
      setSuccess("");
      await axios.delete(
        `${API_URL}/admin/security-baselines/${item.id}`,
        getConfig()
      );
      if (editingId === item.id) resetForm();
      setSuccess("Security baseline deleted successfully.");
      await loadBaselines();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not delete baseline.");
    }
  };

  const inputClass =
    "w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm text-white outline-none focus:border-red-500";
  const labelClass = "mb-1.5 block text-xs font-medium text-gray-400";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Security Configuration
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Security Baselines</h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-400">
            Define and manage security configuration standards across CIS, NIST,
            and ISO 27001 frameworks.
          </p>
        </div>
        <button onClick={loadBaselines} className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800">
          Refresh
        </button>
      </div>

      {error && <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">{error}</div>}
      {success && <div role="status" className="rounded-lg border border-emerald-800 bg-emerald-950/30 p-3 text-sm text-emerald-300">{success}</div>}

      <section className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h2 className="mb-4 text-base font-semibold text-white">
          {editingId !== null ? "Edit Security Baseline" : "Create Security Baseline"}
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className={labelClass}>Baseline name *</label>
              <input className={inputClass} value={form.name} onChange={(e) => change("name", e.target.value)} maxLength={150} required placeholder="e.g. Windows Server Hardening" />
            </div>
            <div>
              <label className={labelClass}>Framework *</label>
              <select className={inputClass} value={form.framework} onChange={(e) => change("framework", e.target.value)}>
                {["CIS", "NIST", "ISO 27001", "SOC 2", "PCI DSS", "Custom"].map((v) => <option key={v}>{v}</option>)}
              </select>
            </div>
            <div>
              <label className={labelClass}>Category *</label>
              <select className={inputClass} value={form.category} onChange={(e) => change("category", e.target.value)}>
                {["Access Control", "Password Security", "Network Security", "Endpoint Security", "Data Protection", "Logging and Monitoring", "System Hardening", "Other"].map((v) => <option key={v}>{v}</option>)}
              </select>
            </div>
            <div>
              <label className={labelClass}>Severity</label>
              <select className={inputClass} value={form.severity} onChange={(e) => change("severity", e.target.value)}>
                {SEVERITIES.map((v) => <option key={v}>{v}</option>)}
              </select>
            </div>
          </div>

          <div>
            <label className={labelClass}>Description *</label>
            <textarea className={inputClass} rows={3} value={form.description} onChange={(e) => change("description", e.target.value)} required placeholder="Describe the security baseline..." />
          </div>
          <div>
            <label className={labelClass}>Baseline requirements</label>
            <textarea className={inputClass} rows={4} value={form.baseline_content} onChange={(e) => change("baseline_content", e.target.value)} placeholder="Enter configuration requirements and recommended settings..." />
          </div>
          <label className="flex items-center gap-3 text-sm text-gray-300">
            <input type="checkbox" checked={form.enabled} onChange={(e) => change("enabled", e.target.checked)} />
            Enable this baseline
          </label>
          <div className="flex flex-wrap gap-3">
            <button disabled={saving} className="rounded-lg bg-red-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-red-500 disabled:opacity-50">
              {saving ? "Saving..." : editingId !== null ? "Update Baseline" : "Create Baseline"}
            </button>
            {editingId !== null && <button type="button" onClick={resetForm} className="rounded-lg border border-gray-700 px-5 py-2.5 text-sm text-gray-300 hover:bg-gray-800">Cancel</button>}
          </div>
        </form>
      </section>

      <section className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Baseline Inventory</h2>
          <span className="text-xs text-gray-400">{baselines.length} baseline(s)</span>
        </div>
        {loading ? <p className="text-sm text-gray-400">Loading baselines...</p> :
          baselines.length === 0 ? <p className="text-sm text-gray-400">No security baselines created yet.</p> :
          <div className="space-y-3">
            {baselines.map((item) => (
              <div key={item.id} className="rounded-lg border border-gray-800 bg-gray-950/70 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <h3 className="font-semibold text-white">{item.name}</h3>
                    <p className="mt-1 text-xs text-gray-400">{item.framework} · {item.category} · {item.severity}</p>
                    <p className="mt-2 text-sm text-gray-300">{item.description}</p>
                    <span className={`mt-3 inline-block rounded-full px-2.5 py-1 text-xs ${item.enabled ? "bg-emerald-950 text-emerald-300" : "bg-gray-800 text-gray-400"}`}>
                      {item.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button onClick={() => handleEdit(item)} className="rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800">Edit</button>
                    <button onClick={() => handleToggle(item)} className="rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800">{item.enabled ? "Disable" : "Enable"}</button>
                    <button onClick={() => handleDelete(item)} className="rounded-lg border border-red-900 px-3 py-2 text-xs text-red-300 hover:bg-red-950">Delete</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        }
      </section>
    </div>
  );
}
