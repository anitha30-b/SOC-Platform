
import { API_BASE_URL as SOC_DEPLOY_API_BASE } from "../deploymentApi.js";
import { useEffect, useState } from "react";
import axios from "axios";

const API = SOC_DEPLOY_API_BASE;

const initialConfig = {
  session_timeout_minutes: 30,
  password_min_length: 8,
  password_require_uppercase: true,
  password_require_lowercase: true,
  password_require_number: true,
  password_require_special: false,
  max_failed_login_attempts: 5,
  account_lockout_minutes: 15,
};

export default function AdminPlatformConfiguration() {
  const [config, setConfig] = useState(initialConfig);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const headers = {
    Authorization: `Bearer ${localStorage.getItem("token")}`,
  };

  const loadConfig = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await axios.get(`${API}/admin/platform-config`, {
        headers,
      });
      setConfig(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Could not load configuration.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadConfig();
  }, []);

  const updateField = (name, value) => {
    setConfig((previous) => ({ ...previous, [name]: value }));
    setMessage("");
  };

  const saveConfig = async (event) => {
    event.preventDefault();
    setSaving(true);
    setMessage("");
    setError("");

    try {
      const response = await axios.put(
        `${API}/admin/platform-config`,
        {
          session_timeout_minutes: Number(config.session_timeout_minutes),
          password_min_length: Number(config.password_min_length),
          password_require_uppercase: config.password_require_uppercase,
          password_require_lowercase: config.password_require_lowercase,
          password_require_number: config.password_require_number,
          password_require_special: config.password_require_special,
          max_failed_login_attempts: Number(config.max_failed_login_attempts),
          account_lockout_minutes: Number(config.account_lockout_minutes),
        },
        { headers }
      );

      setConfig(response.data.configuration);
      setMessage("Platform configuration saved successfully.");
    } catch (err) {
      setError(err.response?.data?.detail || "Could not save configuration.");
    } finally {
      setSaving(false);
    }
  };

  const inputStyle =
    "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-white outline-none focus:border-cyan-400";
  const cardStyle =
    "rounded-xl border border-slate-700 bg-slate-800/70 p-5 space-y-4";
  const labelStyle = "block text-sm font-medium text-slate-300 mb-2";

  const toggle = (name, label) => (
    <label className="flex items-center justify-between gap-4 text-sm text-slate-300">
      <span>{label}</span>
      <input
        type="checkbox"
        checked={Boolean(config[name])}
        onChange={(e) => updateField(name, e.target.checked)}
        className="h-4 w-4 accent-cyan-400"
      />
    </label>
  );

  if (loading) {
    return <div className="p-6 text-slate-300">Loading configuration...</div>;
  }

  return (
    <div className="space-y-6 p-6 text-white">
      <div>
        <h1 className="text-2xl font-bold">Platform Configuration</h1>
        <p className="mt-1 text-sm text-slate-400">
          Manage general platform security settings.
        </p>
      </div>

      {message && (
        <div className="rounded-lg border border-green-700 bg-green-900/30 p-3 text-green-300">
          {message}
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-700 bg-red-900/30 p-3 text-red-300">
          {error}
        </div>
      )}

      <form onSubmit={saveConfig} className="space-y-5">
        <section className={cardStyle}>
          <h2 className="text-lg font-semibold">Session Management</h2>
          <div>
            <label className={labelStyle}>Session timeout (minutes)</label>
            <input
              className={inputStyle}
              type="number"
              min="1"
              max="1440"
              value={config.session_timeout_minutes}
              onChange={(e) =>
                updateField("session_timeout_minutes", e.target.value)
              }
              required
            />
          </div>
        </section>

        <section className={cardStyle}>
          <h2 className="text-lg font-semibold">Password Policy</h2>
          <div>
            <label className={labelStyle}>Minimum password length</label>
            <input
              className={inputStyle}
              type="number"
              min="6"
              max="128"
              value={config.password_min_length}
              onChange={(e) =>
                updateField("password_min_length", e.target.value)
              }
              required
            />
          </div>
          {toggle("password_require_uppercase", "Require uppercase letters")}
          {toggle("password_require_lowercase", "Require lowercase letters")}
          {toggle("password_require_number", "Require numbers")}
          {toggle("password_require_special", "Require special characters")}
        </section>

        <section className={cardStyle}>
          <h2 className="text-lg font-semibold">Login Security</h2>
          <div>
            <label className={labelStyle}>Maximum failed login attempts</label>
            <input
              className={inputStyle}
              type="number"
              min="1"
              max="100"
              value={config.max_failed_login_attempts}
              onChange={(e) =>
                updateField("max_failed_login_attempts", e.target.value)
              }
              required
            />
          </div>
          <div>
            <label className={labelStyle}>
              Account lockout duration (minutes)
            </label>
            <input
              className={inputStyle}
              type="number"
              min="1"
              max="1440"
              value={config.account_lockout_minutes}
              onChange={(e) =>
                updateField("account_lockout_minutes", e.target.value)
              }
              required
            />
          </div>
        </section>

        <div className="flex flex-wrap gap-3">
          <button
            type="submit"
            disabled={saving}
            className="rounded-lg bg-cyan-600 px-5 py-2.5 font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save Settings"}
          </button>

          <button
            type="button"
            onClick={loadConfig}
            className="rounded-lg border border-slate-600 px-5 py-2.5 text-slate-200 hover:bg-slate-700"
          >
            Reload
          </button>
        </div>
      </form>

      <p className="text-xs text-slate-400">
        Note: These values are stored as platform configuration. Password and
        session enforcement requires integration with the authentication and
        session handlers.
      </p>
    </div>
  );
}
