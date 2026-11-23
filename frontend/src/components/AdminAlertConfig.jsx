
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = SOC_DEPLOY_API_BASE;

const EMPTY_FORM = {
  name: "",
  category: "Network Security",
  description: "",
  severity: "MEDIUM",
  priority: "MEDIUM",
  source: "",
  event_type: "",
  threshold: "",
  time_window_minutes: "",
  conditions: "",
  notification_policy_id: "",
  enabled: true,
};

const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const PRIORITIES = ["LOW", "MEDIUM", "HIGH", "URGENT"];
const CATEGORIES = [
  "Network Security",
  "Endpoint Security",
  "Authentication",
  "Malware Detection",
  "Web Security",
  "Data Protection",
  "System Monitoring",
  "Other",
];

export default function AdminAlertConfig() {
  const [alerts, setAlerts] = useState([]);
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

  const loadAlerts = async () => {
    try {
      setLoading(true);
      setError("");
      const response = await axios.get(
        `${API_URL}/admin/alert-config`,
        getConfig()
      );
      setAlerts(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Failed to load alerts.");
    } finally {
      setLoading(false);
    }
  };

  const loadPolicies = async () => {
    try {
      const response = await axios.get(
        `${API_URL}/admin/notification-policies`,
        getConfig()
      );
      setPolicies(Array.isArray(response.data) ? response.data : []);
    } catch {
      setPolicies([]);
    }
  };

  useEffect(() => {
    loadAlerts();
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
      description: form.description.trim(),
      source: form.source.trim() || null,
      event_type: form.event_type.trim() || null,
      threshold: form.threshold === "" ? null : Number(form.threshold),
      time_window_minutes:
        form.time_window_minutes === "" ? null : Number(form.time_window_minutes),
      conditions: form.conditions.trim() || null,
      notification_policy_id:
        form.notification_policy_id === ""
          ? null
          : Number(form.notification_policy_id),
    };

    if (!payload.name || !payload.category || !payload.description) {
      setError("Name, category, and description are required.");
      return;
    }

    if (
      (payload.threshold !== null && (!Number.isInteger(payload.threshold) || payload.threshold < 1)) ||
      (payload.time_window_minutes !== null &&
        (!Number.isInteger(payload.time_window_minutes) || payload.time_window_minutes < 1))
    ) {
      setError("Threshold and time window must be positive whole numbers.");
      return;
    }

    try {
      setSaving(true);

      if (editingId !== null) {
        await axios.put(
          `${API_URL}/admin/alert-config/${editingId}`,
          payload,
          getConfig()
        );
        setSuccess("Alert configuration updated successfully.");
      } else {
        await axios.post(
          `${API_URL}/admin/alert-config`,
          payload,
          getConfig()
        );
        setSuccess("Alert configuration created successfully.");
      }

      resetForm();
      await loadAlerts();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not save alert configuration.");
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (item) => {
    setForm({
      name: item.name || "",
      category: item.category || "Network Security",
      description: item.description || "",
      severity: item.severity || "MEDIUM",
      priority: item.priority || "MEDIUM",
      source: item.source || "",
      event_type: item.event_type || "",
      threshold: item.threshold ?? "",
      time_window_minutes: item.time_window_minutes ?? "",
      conditions: item.conditions || "",
      notification_policy_id: item.notification_policy_id ?? "",
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
        `${API_URL}/admin/alert-config/${item.id}/status`,
        null,
        { ...getConfig(), params: { enabled: !item.enabled } }
      );
      setSuccess(`Alert "${item.name}" status updated.`);
      await loadAlerts();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not update alert status.");
    }
  };

  const handleDelete = async (item) => {
    if (!window.confirm(`Delete alert configuration "${item.name}"?`)) return;

    try {
      setError("");
      setSuccess("");
      await axios.delete(
        `${API_URL}/admin/alert-config/${item.id}`,
        getConfig()
      );
      if (editingId === item.id) resetForm();
      setSuccess("Alert configuration deleted successfully.");
      await loadAlerts();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not delete alert.");
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
          <h1 className="mt-2 text-2xl font-bold text-white">
            Alert Configuration
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-400">
            Configure alert rules, severity, priorities, thresholds, and notification policies.
          </p>
        </div>
        <button
          onClick={() => {
            loadAlerts();
            loadPolicies();
          }}
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
          {editingId !== null ? "Edit Alert Configuration" : "Create Alert Configuration"}
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className={labelClass}>Alert name *</label>
              <input
                className={inputClass}
                value={form.name}
                onChange={(e) => change("name", e.target.value)}
                maxLength={150}
                required
                placeholder="e.g. Brute Force Attack Alert"
              />
            </div>

            <div>
              <label className={labelClass}>Category *</label>
              <select
                className={inputClass}
                value={form.category}
                onChange={(e) => change("category", e.target.value)}
              >
                {CATEGORIES.map((v) => <option key={v}>{v}</option>)}
              </select>
            </div>

            <div>
              <label className={labelClass}>Severity</label>
              <select
                className={inputClass}
                value={form.severity}
                onChange={(e) => change("severity", e.target.value)}
              >
                {SEVERITIES.map((v) => <option key={v}>{v}</option>)}
              </select>
            </div>

            <div>
              <label className={labelClass}>Priority</label>
              <select
                className={inputClass}
                value={form.priority}
                onChange={(e) => change("priority", e.target.value)}
              >
                {PRIORITIES.map((v) => <option key={v}>{v}</option>)}
              </select>
            </div>

            <div>
              <label className={labelClass}>Event source</label>
              <input
                className={inputClass}
                value={form.source}
                onChange={(e) => change("source", e.target.value)}
                placeholder="e.g. Firewall, IDS, Endpoint"
              />
            </div>

            <div>
              <label className={labelClass}>Event type</label>
              <input
                className={inputClass}
                value={form.event_type}
                onChange={(e) => change("event_type", e.target.value)}
                placeholder="e.g. Failed Login"
              />
            </div>

            <div>
              <label className={labelClass}>Alert threshold</label>
              <input
                type="number"
                min="1"
                className={inputClass}
                value={form.threshold}
                onChange={(e) => change("threshold", e.target.value)}
                placeholder="e.g. 5"
              />
            </div>

            <div>
              <label className={labelClass}>Time window (minutes)</label>
              <input
                type="number"
                min="1"
                className={inputClass}
                value={form.time_window_minutes}
                onChange={(e) => change("time_window_minutes", e.target.value)}
                placeholder="e.g. 5"
              />
            </div>

            <div>
              <label className={labelClass}>Notification policy</label>
              <select
                className={inputClass}
                value={form.notification_policy_id}
                onChange={(e) => change("notification_policy_id", e.target.value)}
              >
                <option value="">No policy linked</option>
                {policies.map((policy) => (
                  <option key={policy.id} value={policy.id}>
                    {policy.name}
                  </option>
                ))}
              </select>
              {policies.length === 0 && (
                <p className="mt-1 text-xs text-gray-500">
                  No notification policies loaded. You can create an alert without linking a policy.
                </p>
              )}
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
              placeholder="Describe when this alert should be raised..."
            />
          </div>

          <div>
            <label className={labelClass}>Alert conditions</label>
            <textarea
              className={inputClass}
              rows={4}
              value={form.conditions}
              onChange={(e) => change("conditions", e.target.value)}
              placeholder="Enter matching conditions and alert criteria..."
            />
          </div>

          <label className="flex items-center gap-3 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => change("enabled", e.target.checked)}
            />
            Enable this alert configuration
          </label>

          <div className="flex flex-wrap gap-3">
            <button
              disabled={saving}
              className="rounded-lg bg-red-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-red-500 disabled:opacity-50"
            >
              {saving ? "Saving..." : editingId !== null ? "Update Alert" : "Create Alert"}
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
          <h2 className="text-base font-semibold text-white">Alert Configuration Inventory</h2>
          <span className="text-xs text-gray-400">{alerts.length} alert(s)</span>
        </div>

        {loading ? (
          <p className="text-sm text-gray-400">Loading alert configurations...</p>
        ) : alerts.length === 0 ? (
          <p className="text-sm text-gray-400">No alert configurations created yet.</p>
        ) : (
          <div className="space-y-3">
            {alerts.map((item) => (
              <div key={item.id} className="rounded-lg border border-gray-800 bg-gray-950/70 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <h3 className="font-semibold text-white">{item.name}</h3>
                    <p className="mt-1 text-xs text-gray-400">
                      {item.category} · {item.severity} · Priority: {item.priority}
                    </p>
                    <p className="mt-2 text-sm text-gray-300">{item.description}</p>
                    {(item.source || item.event_type) && (
                      <p className="mt-2 text-xs text-gray-400">
                        Source: {item.source || "—"} · Event: {item.event_type || "—"}
                      </p>
                    )}
                    {(item.threshold || item.time_window_minutes) && (
                      <p className="mt-1 text-xs text-gray-400">
                        Threshold: {item.threshold ?? "—"} · Window: {item.time_window_minutes ? `${item.time_window_minutes} min` : "—"}
                      </p>
                    )}
                    {item.conditions && (
                      <p className="mt-2 whitespace-pre-wrap text-xs text-gray-400">
                        Conditions: {item.conditions}
                      </p>
                    )}
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
                      onClick={() => handleEdit(item)}
                      className="rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleToggle(item)}
                      className="rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800"
                    >
                      {item.enabled ? "Disable" : "Enable"}
                    </button>
                    <button
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
