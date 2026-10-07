import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

const CHANNEL_META = {
  email: {
    title: "Email Alerts",
    description: "Configure SMTP delivery for security notifications.",
    endpointLabel: "SMTP Host",
    endpointPlaceholder: "smtp.example.com",
    usernameLabel: "SMTP Username",
    secretLabel: "SMTP Password",
    configurationFields: [
      ["port", "SMTP Port", "587"],
      ["from_address", "From Address", "soc@example.com"],
      ["to_addresses", "Recipient Addresses", "security@example.com"],
      ["use_tls", "Use TLS", true],
    ],
  },
  slack: {
    title: "Slack Alerts",
    description: "Configure Slack webhook delivery for security notifications.",
    endpointLabel: "Slack Webhook URL",
    endpointPlaceholder: "https://hooks.slack.com/services/...",
    usernameLabel: "Username",
    secretLabel: "Webhook Secret",
    configurationFields: [
      ["channel", "Channel", "#security-alerts"],
    ],
  },
  teams: {
    title: "Microsoft Teams Alerts",
    description: "Configure Microsoft Teams webhook delivery.",
    endpointLabel: "Teams Webhook URL",
    endpointPlaceholder: "https://...",
    usernameLabel: "Username",
    secretLabel: "Webhook Secret",
    configurationFields: [
      ["display_name", "Display Name", "SecuzityShield"],
    ],
  },
  webhook: {
    title: "Webhook",
    description: "Configure a generic HTTP webhook for security notifications.",
    endpointLabel: "Webhook URL",
    endpointPlaceholder: "https://example.com/security/webhook",
    usernameLabel: "Username",
    secretLabel: "Webhook Secret",
    configurationFields: [
      ["method", "HTTP Method", "POST"],
      ["content_type", "Content Type", "application/json"],
    ],
  },
};

export default function AdminNotificationChannel({ channel }) {
  const meta = CHANNEL_META[channel] || CHANNEL_META.webhook;

  const [form, setForm] = useState({
    enabled: false,
    endpoint: "",
    username: "",
    secret: "",
    configuration: {},
  });

  const [hasSecret, setHasSecret] = useState(false);
  const [configured, setConfigured] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const getConfig = () => ({
    headers: {
      Authorization: `Bearer ${localStorage.getItem("token")}`,
    },
  });

  const loadChannel = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await axios.get(
        `${API_URL}/admin/notification-channels/${channel}`,
        getConfig()
      );

      const data = response.data || {};

      setConfigured(Boolean(data.configured));
      setHasSecret(Boolean(data.has_secret));

      setForm({
        enabled: Boolean(data.enabled),
        endpoint: data.endpoint || "",
        username: data.username || "",
        secret: "",
        configuration: data.configuration || {},
      });
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          `Failed to load ${meta.title}.`
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadChannel();
  }, [channel]);

  const updateField = (field, value) => {
    setForm((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const updateConfiguration = (field, value) => {
    setForm((current) => ({
      ...current,
      configuration: {
        ...current.configuration,
        [field]: value,
      },
    }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    try {
      setSaving(true);
      setError("");
      setSuccess("");

      const payload = {
        enabled: form.enabled,
        endpoint: form.endpoint.trim() || null,
        username: form.username.trim() || null,
        configuration: form.configuration,
      };

      if (form.secret.trim()) {
        payload.secret = form.secret;
      }

      await axios.put(
        `${API_URL}/admin/notification-channels/${channel}`,
        payload,
        getConfig()
      );

      setSuccess(`${meta.title} configuration saved successfully.`);
      setForm((current) => ({
        ...current,
        secret: "",
      }));

      await loadChannel();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          `Failed to save ${meta.title}.`
      );
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!configured) return;

    if (!window.confirm(`Delete ${meta.title} configuration?`)) {
      return;
    }

    try {
      setDeleting(true);
      setError("");
      setSuccess("");

      await axios.delete(
        `${API_URL}/admin/notification-channels/${channel}`,
        getConfig()
      );

      setSuccess(`${meta.title} configuration deleted.`);
      await loadChannel();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          `Failed to delete ${meta.title}.`
      );
    } finally {
      setDeleting(false);
    }
  };

  if (loading) {
    return (
      <div className="rounded-lg border border-white/10 bg-[#0b1014] px-6 py-10 text-center text-sm text-gray-500">
        Loading {meta.title}...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="text-xs uppercase tracking-[0.25em] text-red-400">
          Notifications
        </div>

        <h1 className="mt-2 text-2xl font-semibold text-white">
          {meta.title}
        </h1>

        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          {meta.description}
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
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Channel Configuration
            </h2>

            <p className="mt-1 text-xs text-gray-500">
              Credentials are never returned by the API.
            </p>
          </div>

          <label className="flex cursor-pointer items-center gap-3 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => updateField("enabled", e.target.checked)}
              className="accent-red-600"
            />
            Enabled
          </label>
        </div>

        <div className="grid gap-5 md:grid-cols-2">
          <label className="block">
            <span className="text-xs uppercase tracking-wider text-gray-500">
              {meta.endpointLabel}
            </span>

            <input
              value={form.endpoint}
              onChange={(e) => updateField("endpoint", e.target.value)}
              placeholder={meta.endpointPlaceholder}
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </label>

          <label className="block">
            <span className="text-xs uppercase tracking-wider text-gray-500">
              {meta.usernameLabel}
            </span>

            <input
              value={form.username}
              onChange={(e) => updateField("username", e.target.value)}
              placeholder="Optional"
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </label>

          <label className="block md:col-span-2">
            <span className="text-xs uppercase tracking-wider text-gray-500">
              {meta.secretLabel}
            </span>

            <input
              type="password"
              value={form.secret}
              onChange={(e) => updateField("secret", e.target.value)}
              placeholder={
                hasSecret ? "Secret already configured — enter only to replace" : "Enter secret"
              }
              autoComplete="new-password"
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />

            {hasSecret && (
              <span className="mt-2 block text-xs text-emerald-400">
                Secret configured
              </span>
            )}
          </label>
        </div>

        {meta.configurationFields.length > 0 && (
          <div className="mt-6">
            <div className="mb-3 text-xs uppercase tracking-wider text-gray-500">
              Additional Configuration
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              {meta.configurationFields.map(([field, label, defaultValue]) => (
                <label key={field} className="block">
                  <span className="text-xs uppercase tracking-wider text-gray-500">
                    {label}
                  </span>

                  {typeof defaultValue === "boolean" ? (
                    <div className="mt-3 flex items-center gap-3 text-sm text-gray-300">
                      <input
                        type="checkbox"
                        checked={
                          form.configuration[field] ??
                          defaultValue
                        }
                        onChange={(e) =>
                          updateConfiguration(field, e.target.checked)
                        }
                        className="accent-red-600"
                      />
                      Enabled
                    </div>
                  ) : (
                    <input
                      value={
                        form.configuration[field] ??
                        defaultValue ??
                        ""
                      }
                      onChange={(e) =>
                        updateConfiguration(field, e.target.value)
                      }
                      className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                    />
                  )}
                </label>
              ))}
            </div>
          </div>
        )}

        <div className="mt-6 flex flex-wrap gap-3">
          <button
            type="submit"
            disabled={saving}
            className="bg-red-600 px-5 py-3 text-sm font-medium text-white hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save Configuration"}
          </button>

          <button
            type="button"
            onClick={loadChannel}
            disabled={loading}
            className="border border-white/10 px-5 py-3 text-sm text-gray-300 hover:border-white/20 hover:text-white"
          >
            Refresh
          </button>

          {configured && (
            <button
              type="button"
              onClick={handleDelete}
              disabled={deleting}
              className="border border-red-500/20 px-5 py-3 text-sm text-red-400 hover:border-red-500/40 hover:text-red-300 disabled:opacity-50"
            >
              {deleting ? "Deleting..." : "Delete Configuration"}
            </button>
          )}
        </div>
      </form>
    </div>
  );
}
