import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

const EMPTY_FORM = {
  name: "",
  data_type: "System Logs",
  description: "",
  retention_days: 90,
  archive_enabled: false,
  archive_after_days: "",
  auto_delete: false,
  enabled: true,
};

const DATA_TYPES = [
  "System Logs",
  "Security Events",
  "Alerts",
  "Audit Logs",
  "Network Logs",
  "Application Logs",
  "Other",
];

export default function AdminRetentionPolicies() {
  const [policies, setPolicies] = useState([]);
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

  const loadPolicies = async () => {
    try {
      setLoading(true);
      setError("");
      const response = await axios.get(`${API_URL}/admin/retention`, getConfig());
      setPolicies(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Failed to load policies.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
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

    const payload = {
      ...form,
      name: form.name.trim(),
      data_type: form.data_type.trim(),
      description: form.description.trim(),
      retention_days: Number(form.retention_days),
      archive_after_days: form.archive_enabled
        ? Number(form.archive_after_days)
        : null,
    };

    if (!payload.name || !payload.description) {
      setError("Policy name and description are required.");
      return;
    }

    if (!Number.isInteger(payload.retention_days) || payload.retention_days < 1) {
      setError("Retention period must be at least 1 day.");
      return;
    }

    if (
      payload.archive_enabled &&
      (!Number.isInteger(payload.archive_after_days) ||
        payload.archive_after_days < 1 ||
        payload.archive_after_days > payload.retention_days)
    ) {
      setError("Archive days must be between 1 and the retention period.");
      return;
    }

    try {
      setSaving(true);

      if (editingId !== null) {
        await axios.put(`${API_URL}/admin/retention/${editingId}`, payload, getConfig());
        setSuccess("Retention policy updated successfully.");
      } else {
        await axios.post(`${API_URL}/admin/retention`, payload, getConfig());
        setSuccess("Retention policy created successfully.");
      }

      resetForm();
      await loadPolicies();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not save policy.");
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (item) => {
    setForm({
      name: item.name || "",
      data_type: item.data_type || "System Logs",
      description: item.description || "",
      retention_days: item.retention_days ?? 90,
      archive_enabled: Boolean(item.archive_enabled),
      archive_after_days: item.archive_after_days ?? "",
      auto_delete: Boolean(item.auto_delete),
      enabled: Boolean(item.enabled),
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
        `${API_URL}/admin/retention/${item.id}/status`,
        null,
        { ...getConfig(), params: { enabled: !item.enabled } }
      );
      setSuccess(`Policy "${item.name}" status updated.`);
      await loadPolicies();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not update status.");
    }
  };

  const handleDelete = async (item) => {
    if (!window.confirm(`Delete retention policy "${item.name}"?`)) return;

    try {
      setError("");
      setSuccess("");
      await axios.delete(`${API_URL}/admin/retention/${item.id}`, getConfig());
      if (editingId === item.id) resetForm();
      setSuccess("Retention policy deleted successfully.");
      await loadPolicies();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not delete policy.");
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
          <h1 className="mt-2 text-2xl font-bold text-white">Retention Policies</h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-400">
            Configure how long security data is retained, archived, and marked
            for automatic deletion.
          </p>
        </div>
        <button
          type="button"
          onClick={loadPolicies}
          className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">
          {error}
        </div>
      )}
      {success && (
        <div role="status" className="rounded-lg border border-emerald-800 bg-emerald-950/30 p-3 text-sm text-emerald-300">
          {success}
        </div>
      )}

      <section className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h2 className="mb-4 text-base font-semibold text-white">
          {editingId !== null ? "Edit Retention Policy" : "Create Retention Policy"}
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className={labelClass}>Policy name *</label>
              <input
                className={inputClass}
                value={form.name}
                onChange={(e) => change("name", e.target.value)}
                maxLength={150}
                required
                placeholder="e.g. Security Logs Retention"
              />
            </div>

            <div>
              <label className={labelClass}>Data type *</label>
              <select
                className={inputClass}
                value={form.data_type}
                onChange={(e) => change("data_type", e.target.value)}
              >
                {DATA_TYPES.map((v) => <option key={v}>{v}</option>)}
              </select>
            </div>

            <div>
              <label className={labelClass}>Retention period (days) *</label>
              <input
                type="number"
                min="1"
                className={inputClass}
                value={form.retention_days}
                onChange={(e) => change("retention_days", e.target.value)}
                required
              />
            </div>

            <div>
              <label className={labelClass}>Archive after (days)</label>
              <input
                type="number"
                min="1"
                max={form.retention_days}
                className={inputClass}
                value={form.archive_after_days}
                onChange={(e) => change("archive_after_days", e.target.value)}
                disabled={!form.archive_enabled}
                placeholder="e.g. 30"
              />
            </div>
          </div>

          <div>
            <label className={labelClass}>Description *</label>
            <textarea
              className={inputClass}
              rows={3}
              value={form.description}
              onChange={(e) => change("description", e.target.value)}
              required
              placeholder="Describe the purpose of this retention policy..."
            />
          </div>

          <div className="space-y-3">
            <label className="flex items-center gap-3 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={form.archive_enabled}
                onChange={(e) => change("archive_enabled", e.target.checked)}
              />
              Enable data archiving
            </label>

            <label className="flex items-center gap-3 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={form.auto_delete}
                onChange={(e) => change("auto_delete", e.target.checked)}
              />
              Enable automatic deletion setting
            </label>

            <label className="flex items-center gap-3 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => change("enabled", e.target.checked)}
              />
              Enable this retention policy
            </label>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              disabled={saving}
              className="rounded-lg bg-red-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-red-500 disabled:opacity-50"
            >
              {saving ? "Saving..." : editingId !== null ? "Update Policy" : "Create Policy"}
            </button>

            {editingId !== null && (
              <button
                type="button"
                onClick={resetForm}
                className="rounded-lg border border-gray-700 px-5 py-2.5 text-sm text-gray-300 hover:bg-gray-800"
              >
                Cancel
              </button>
            )}
          </div>
        </form>
      </section>

      <section className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Retention Policy Inventory</h2>
          <span className="text-xs text-gray-400">{policies.length} policy(s)</span>
        </div>

        {loading ? (
          <p className="text-sm text-gray-400">Loading retention policies...</p>
        ) : policies.length === 0 ? (
          <p className="text-sm text-gray-400">No retention policies created yet.</p>
        ) : (
          <div className="space-y-3">
            {policies.map((item) => (
              <div key={item.id} className="rounded-lg border border-gray-800 bg-gray-950/70 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <h3 className="font-semibold text-white">{item.name}</h3>
                    <p className="mt-1 text-xs text-gray-400">
                      {item.data_type} · Retention: {item.retention_days} days
                    </p>
                    <p className="mt-2 text-sm text-gray-300">{item.description}</p>
                    <div className="mt-2 space-y-1 text-xs text-gray-400">
                      <p>
                        Archiving: {item.archive_enabled
                          ? `Enabled · After ${item.archive_after_days} days`
                          : "Disabled"}
                      </p>
                      <p>
                        Automatic deletion setting: {item.auto_delete ? "Enabled" : "Disabled"}
                      </p>
                    </div>
                    <span className={`mt-3 inline-block rounded-full px-2.5 py-1 text-xs ${
                      item.enabled
                        ? "bg-emerald-950 text-emerald-300"
                        : "bg-gray-800 text-gray-400"
                    }`}>
                      {item.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => handleEdit(item)}
                      className="rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => handleToggle(item)}
                      className="rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800"
                    >
                      {item.enabled ? "Disable" : "Enable"}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDelete(item)}
                      className="rounded-lg border border-red-900 px-3 py-2 text-xs text-red-300 hover:bg-red-950"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
