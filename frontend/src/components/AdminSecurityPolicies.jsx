
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = SOC_DEPLOY_API_BASE;
const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

const EMPTY_FORM = {
  name: "",
  category: "Access Control",
  description: "",
  severity: "MEDIUM",
  enabled: true,
  policy_content: "",
};

export default function AdminSecurityPolicies() {
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
        `${API_URL}/admin/security-policies`,
        getConfig()
      );
      setPolicies(response.data?.policies || []);
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to load security policies."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const handleChange = (field, value) => {
    setForm((current) => ({ ...current, [field]: value }));
  };

  const resetForm = () => {
    setForm(EMPTY_FORM);
    setEditingId(null);
    setError("");
    setSuccess("");
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setSuccess("");

    if (!form.name.trim() || !form.category.trim() || !form.description.trim()) {
      setError("Name, category, and description are required.");
      return;
    }

    try {
      setSaving(true);
      const payload = {
        ...form,
        name: form.name.trim(),
        category: form.category.trim(),
        description: form.description.trim(),
        policy_content: form.policy_content.trim() || null,
      };

      if (editingId !== null) {
        await axios.put(
          `${API_URL}/admin/security-policies/${editingId}`,
          payload,
          getConfig()
        );
        setSuccess("Security policy updated successfully.");
      } else {
        await axios.post(
          `${API_URL}/admin/security-policies`,
          payload,
          getConfig()
        );
        setSuccess("Security policy created successfully.");
      }

      resetForm();
      setSuccess(
        editingId !== null
          ? "Security policy updated successfully."
          : "Security policy created successfully."
      );
      await loadPolicies();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Could not save security policy."
      );
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (policy) => {
    setForm({
      name: policy.name || "",
      category: policy.category || "Access Control",
      description: policy.description || "",
      severity: policy.severity || "MEDIUM",
      enabled: Boolean(policy.enabled),
      policy_content: policy.policy_content || "",
    });
    setEditingId(policy.id);
    setError("");
    setSuccess("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleToggle = async (policy) => {
    setError("");
    setSuccess("");
    try {
      await axios.patch(
        `${API_URL}/admin/security-policies/${policy.id}/status`,
        null,
        {
          ...getConfig(),
          params: { enabled: !policy.enabled },
        }
      );
      setSuccess(`Policy "${policy.name}" status updated.`);
      await loadPolicies();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Could not update policy status."
      );
    }
  };

  const handleDelete = async (policy) => {
    if (!window.confirm(`Delete security policy "${policy.name}"?`)) return;

    setError("");
    setSuccess("");
    try {
      await axios.delete(
        `${API_URL}/admin/security-policies/${policy.id}`,
        getConfig()
      );
      setSuccess("Security policy deleted successfully.");
      if (editingId === policy.id) resetForm();
      await loadPolicies();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Could not delete security policy."
      );
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
            Security Policies
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-400">
            Create, review, and manage security policies for your SOC platform.
            Policy changes are recorded in the audit log.
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
          {editingId !== null ? "Edit Security Policy" : "Create Security Policy"}
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className={labelClass}>Policy name *</label>
              <input
                className={inputClass}
                value={form.name}
                onChange={(e) => handleChange("name", e.target.value)}
                maxLength={150}
                required
                placeholder="e.g. Multi-Factor Authentication"
              />
            </div>

            <div>
              <label className={labelClass}>Category *</label>
              <select
                className={inputClass}
                value={form.category}
                onChange={(e) => handleChange("category", e.target.value)}
                required
              >
                {[
                  "Access Control",
                  "Password Security",
                  "Network Security",
                  "Endpoint Security",
                  "Data Protection",
                  "Incident Response",
                  "Compliance",
                  "Logging and Monitoring",
                  "Other",
                ].map((category) => (
                  <option key={category} value={category}>{category}</option>
                ))}
              </select>
            </div>

            <div>
              <label className={labelClass}>Severity</label>
              <select
                className={inputClass}
                value={form.severity}
                onChange={(e) => handleChange("severity", e.target.value)}
              >
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>{severity}</option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-3 pt-6">
              <input
                id="security-policy-enabled"
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => handleChange("enabled", e.target.checked)}
                className="h-4 w-4 accent-red-500"
              />
              <label htmlFor="security-policy-enabled" className="text-sm text-gray-300">
                Policy enabled
              </label>
            </div>
          </div>

          <div>
            <label className={labelClass}>Description *</label>
            <textarea
              className={inputClass}
              value={form.description}
              onChange={(e) => handleChange("description", e.target.value)}
              rows={3}
              required
              placeholder="Explain the purpose and scope of this policy."
            />
          </div>

          <div>
            <label className={labelClass}>Policy requirements or content</label>
            <textarea
              className={inputClass}
              value={form.policy_content}
              onChange={(e) => handleChange("policy_content", e.target.value)}
              rows={4}
              placeholder="Add detailed requirements, rules, or implementation guidance."
            />
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              type="submit"
              disabled={saving}
              className="rounded-lg bg-red-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-red-500 disabled:opacity-50"
            >
              {saving
                ? "Saving..."
                : editingId !== null
                  ? "Save Changes"
                  : "Create Policy"}
            </button>
            {editingId !== null && (
              <button
                type="button"
                onClick={resetForm}
                className="rounded-lg border border-gray-700 px-4 py-2.5 text-sm text-gray-300 hover:bg-gray-800"
              >
                Cancel
              </button>
            )}
          </div>
        </form>
      </section>

      <section className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900/60">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 p-5">
          <div>
            <h2 className="text-base font-semibold text-white">Policy Inventory</h2>
            <p className="mt-1 text-xs text-gray-500">
              {policies.length} {policies.length === 1 ? "policy" : "policies"} configured
            </p>
          </div>
        </div>

        {loading ? (
          <p className="p-6 text-sm text-gray-400">Loading security policies...</p>
        ) : policies.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-sm font-medium text-gray-300">No security policies yet</p>
            <p className="mt-1 text-xs text-gray-500">
              Create your first policy using the form above.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="bg-gray-950/70 text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-5 py-3">Policy</th>
                  <th className="px-5 py-3">Category</th>
                  <th className="px-5 py-3">Severity</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Updated</th>
                  <th className="px-5 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {policies.map((policy) => (
                  <tr key={policy.id} className="align-top hover:bg-gray-800/30">
                    <td className="px-5 py-4">
                      <p className="font-medium text-white">{policy.name}</p>
                      <p className="mt-1 max-w-sm whitespace-normal text-xs text-gray-500">
                        {policy.description}
                      </p>
                    </td>
                    <td className="px-5 py-4 text-gray-300">{policy.category}</td>
                    <td className="px-5 py-4">
                      <span className="rounded-md border border-gray-700 px-2 py-1 text-xs text-gray-300">
                        {policy.severity}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <span className={`rounded-md px-2 py-1 text-xs ${
                        policy.enabled
                          ? "bg-emerald-950 text-emerald-300"
                          : "bg-gray-800 text-gray-400"
                      }`}>
                        {policy.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                    <td className="px-5 py-4 text-xs text-gray-500">
                      {policy.updated_at
                        ? new Date(policy.updated_at).toLocaleString()
                        : "—"}
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => handleEdit(policy)}
                          className="rounded-md border border-gray-700 px-2.5 py-1.5 text-xs text-gray-300 hover:bg-gray-700"
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          onClick={() => handleToggle(policy)}
                          className="rounded-md border border-gray-700 px-2.5 py-1.5 text-xs text-gray-300 hover:bg-gray-700"
                        >
                          {policy.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDelete(policy)}
                          className="rounded-md border border-red-900 px-2.5 py-1.5 text-xs text-red-300 hover:bg-red-950"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
