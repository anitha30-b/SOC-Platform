
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = SOC_DEPLOY_API_BASE;

const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const EMPTY_FORM = {
  name: "",
  enabled: true,
  source: "",
  event_type: "",
  minimum_severity: "INFO",
  email_enabled: false,
  slack_enabled: false,
  teams_enabled: false,
  webhook_enabled: false,
};

export default function AdminNotificationPolicies() {
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

      const response = await axios.get(
        `${API_URL}/admin/notification-policies`,
        getConfig()
      );

      setPolicies(response.data?.policies || []);
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to load notification policies."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const handleChange = (field, value) => {
    setForm((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const resetForm = () => {
    setForm(EMPTY_FORM);
    setEditingId(null);
    setError("");
    setSuccess("");
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!form.name.trim()) {
      setError("Policy name is required.");
      return;
    }

    try {
      setSaving(true);
      setError("");
      setSuccess("");

      const payload = {
        ...form,
        name: form.name.trim(),
        source: form.source.trim() || null,
        event_type: form.event_type.trim() || null,
      };

      if (editingId) {
        await axios.put(
          `${API_URL}/admin/notification-policies/${editingId}`,
          payload,
          getConfig()
        );
        setSuccess("Notification policy updated successfully.");
      } else {
        await axios.post(
          `${API_URL}/admin/notification-policies`,
          payload,
          getConfig()
        );
        setSuccess("Notification policy created successfully.");
      }

      resetForm();
      await loadPolicies();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to save notification policy."
      );
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (policy) => {
    setEditingId(policy.id);
    setForm({
      name: policy.name || "",
      enabled: policy.enabled ?? true,
      source: policy.source || "",
      event_type: policy.event_type || "",
      minimum_severity: policy.minimum_severity || "INFO",
      email_enabled: policy.email_enabled ?? false,
      slack_enabled: policy.slack_enabled ?? false,
      teams_enabled: policy.teams_enabled ?? false,
      webhook_enabled: policy.webhook_enabled ?? false,
    });
    setError("");
    setSuccess("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleDelete = async (policy) => {
    if (!window.confirm(`Delete notification policy "${policy.name}"?`)) {
      return;
    }

    try {
      setError("");
      setSuccess("");

      await axios.delete(
        `${API_URL}/admin/notification-policies/${policy.id}`,
        getConfig()
      );

      setSuccess("Notification policy deleted successfully.");

      if (editingId === policy.id) {
        resetForm();
      }

      await loadPolicies();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to delete notification policy."
      );
    }
  };

  const handleToggle = async (policy) => {
    try {
      setError("");
      setSuccess("");

      await axios.put(
        `${API_URL}/admin/notification-policies/${policy.id}`,
        { enabled: !policy.enabled },
        getConfig()
      );

      setSuccess(
        `Policy "${policy.name}" ${
          policy.enabled ? "disabled" : "enabled"
        } successfully.`
      );

      await loadPolicies();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to update policy status."
      );
    }
  };

  const channelCount = (policy) =>
    [
      policy.email_enabled,
      policy.slack_enabled,
      policy.teams_enabled,
      policy.webhook_enabled,
    ].filter(Boolean).length;

  return (
    <div className="space-y-6">
      <div>
        <div className="text-xs uppercase tracking-[0.25em] text-red-400">
          Notifications
        </div>
        <h1 className="mt-2 text-2xl font-semibold text-white">
          Notification Policies
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Define which security events should trigger notification channels.
          Policies are stored centrally and can be enabled or disabled without
          changing the underlying detection pipeline.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {success && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
          {success}
        </div>
      )}

      <form
        onSubmit={handleSubmit}
        className="rounded-lg border border-white/10 bg-[#0b1014] p-6"
      >
        <div className="mb-5 flex items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white">
              {editingId ? "Edit Notification Policy" : "Create Notification Policy"}
            </h2>
            <p className="mt-1 text-xs text-gray-500">
              Configure event matching and delivery channels.
            </p>
          </div>

          {editingId && (
            <button
              type="button"
              onClick={resetForm}
              className="border border-white/10 px-4 py-2 text-xs text-gray-300 hover:border-white/20 hover:text-white"
            >
              Cancel Edit
            </button>
          )}
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <label className="block">
            <span className="text-xs uppercase tracking-wider text-gray-500">
              Policy Name
            </span>
            <input
              value={form.name}
              onChange={(e) => handleChange("name", e.target.value)}
              placeholder="Critical Security Events"
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </label>

          <label className="block">
            <span className="text-xs uppercase tracking-wider text-gray-500">
              Minimum Severity
            </span>
            <select
              value={form.minimum_severity}
              onChange={(e) =>
                handleChange("minimum_severity", e.target.value)
              }
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none focus:border-red-600"
            >
              {SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="text-xs uppercase tracking-wider text-gray-500">
              Source
            </span>
            <input
              value={form.source}
              onChange={(e) => handleChange("source", e.target.value)}
              placeholder="nmap, nuclei, zap, systemd..."
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </label>

          <label className="block">
            <span className="text-xs uppercase tracking-wider text-gray-500">
              Event Type
            </span>
            <input
              value={form.event_type}
              onChange={(e) => handleChange("event_type", e.target.value)}
              placeholder="vapt_scan, detection, incident..."
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </label>
        </div>

        <div className="mt-5">
          <div className="mb-3 text-xs uppercase tracking-wider text-gray-500">
            Delivery Channels
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              ["email_enabled", "Email"],
              ["slack_enabled", "Slack"],
              ["teams_enabled", "Microsoft Teams"],
              ["webhook_enabled", "Webhook"],
            ].map(([field, label]) => (
              <label
                key={field}
                className="flex cursor-pointer items-center gap-3 border border-white/10 bg-[#080808] px-4 py-3"
              >
                <input
                  type="checkbox"
                  checked={form[field]}
                  onChange={(e) => handleChange(field, e.target.checked)}
                  className="accent-red-600"
                />
                <span className="text-sm text-gray-300">{label}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="mt-5 flex items-center gap-3">
          <label className="flex cursor-pointer items-center gap-3 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => handleChange("enabled", e.target.checked)}
              className="accent-red-600"
            />
            Policy enabled
          </label>
        </div>

        <div className="mt-6 flex gap-3">
          <button
            type="submit"
            disabled={saving}
            className="bg-red-600 px-5 py-3 text-sm font-medium text-white hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving
              ? "Saving..."
              : editingId
              ? "Update Policy"
              : "Create Policy"}
          </button>

          {editingId && (
            <button
              type="button"
              onClick={resetForm}
              className="border border-white/10 px-5 py-3 text-sm text-gray-300 hover:border-white/20 hover:text-white"
            >
              Reset
            </button>
          )}
        </div>
      </form>

      <div className="rounded-lg border border-white/10 bg-[#0b1014]">
        <div className="flex items-center justify-between border-b border-white/10 px-6 py-4">
          <div>
            <h2 className="font-semibold text-white">Configured Policies</h2>
            <p className="mt-1 text-xs text-gray-500">
              {policies.length} policy{policies.length === 1 ? "" : "ies"}
            </p>
          </div>

          <button
            type="button"
            onClick={loadPolicies}
            className="border border-white/10 px-4 py-2 text-xs text-gray-300 hover:border-white/20 hover:text-white"
          >
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="px-6 py-10 text-center text-sm text-gray-500">
            Loading notification policies...
          </div>
        ) : policies.length === 0 ? (
          <div className="px-6 py-10 text-center text-sm text-gray-500">
            No notification policies configured.
          </div>
        ) : (
          <div className="divide-y divide-white/10">
            {policies.map((policy) => (
              <div
                key={policy.id}
                className="flex flex-col gap-5 px-6 py-5 lg:flex-row lg:items-center lg:justify-between"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-white">
                      {policy.name}
                    </span>

                    <span
                      className={`rounded-full border px-2 py-0.5 text-[10px] uppercase ${
                        policy.enabled
                          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                          : "border-gray-500/30 bg-gray-500/10 text-gray-400"
                      }`}
                    >
                      {policy.enabled ? "Enabled" : "Disabled"}
                    </span>

                    <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] text-gray-400">
                      {policy.minimum_severity}
                    </span>
                  </div>

                  <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-gray-500">
                    <span>
                      Source: {policy.source || "All sources"}
                    </span>
                    <span>
                      Event: {policy.event_type || "All events"}
                    </span>
                    <span>
                      Channels: {channelCount(policy)}
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => handleToggle(policy)}
                    className="border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/20 hover:text-white"
                  >
                    {policy.enabled ? "Disable" : "Enable"}
                  </button>

                  <button
                    type="button"
                    onClick={() => handleEdit(policy)}
                    className="border border-white/10 px-3 py-2 text-xs text-gray-300 hover:border-white/20 hover:text-white"
                  >
                    Edit
                  </button>

                  <button
                    type="button"
                    onClick={() => handleDelete(policy)}
                    className="border border-red-500/20 px-3 py-2 text-xs text-red-400 hover:border-red-500/40 hover:text-red-300"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
