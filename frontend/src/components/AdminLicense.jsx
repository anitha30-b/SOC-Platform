import { useEffect, useState } from "react";

const API = "http://127.0.0.1:8000";

export default function AdminLicense({ onBack }) {
  const [data, setData] = useState(null);
  const [organization, setOrganization] = useState("SOC Platform");
  const [edition, setEdition] = useState("Community");
  const [key, setKey] = useState("");
  const [expiry, setExpiry] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const headers = () => ({
    Authorization: `Bearer ${localStorage.getItem("token")}`,
    "Content-Type": "application/json",
  });

  async function load() {
    setBusy(true);
    try {
      const r = await fetch(`${API}/system/license`, { headers: headers() });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || "Could not load license.");
      setData(d);
      setOrganization(d.organization || "SOC Platform");
      setEdition(d.edition || "Community");
      setExpiry(d.expires_at ? d.expires_at.slice(0, 10) : "");
    } catch (e) {
      setMessage(e.message);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function save(e) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const r = await fetch(`${API}/system/license`, {
        method: "PUT",
        headers: headers(),
        body: JSON.stringify({
          organization,
          edition,
          license_key: key,
          expires_at: key.trim() ? expiry : null,
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || "Could not save license.");
      setMessage(d.message || "Configuration saved.");
      setKey("");
      await load();
    } catch (e) {
      setMessage(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function validate() {
    setBusy(true);
    setMessage("");
    try {
      const r = await fetch(`${API}/system/license/validate`, {
        method: "POST",
        headers: headers(),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || "Validation failed.");
      setMessage(d.message);
      await load();
    } catch (e) {
      setMessage(e.message);
    } finally {
      setBusy(false);
    }
  }

  const field = {
    display: "block",
    width: "100%",
    boxSizing: "border-box",
    padding: "11px",
    marginTop: "7px",
    border: "1px solid #d1d5db",
    borderRadius: "8px",
    background: "#ffffff",
    color: "#111827",
  };
  const card = {
    padding: "20px",
    border: "1px solid var(--border-color, #374151)",
    borderRadius: "12px",
    background: "#111827",
    minWidth: 0,
  };
  const button = {
    padding: "10px 15px",
    border: "0",
    borderRadius: "8px",
    cursor: busy ? "wait" : "pointer",
    marginRight: "8px",
    marginTop: "10px",
  };

  return (
    <main style={{ maxWidth: 1100, margin: "0 auto", padding: 24 }}>
      <button style={button} onClick={onBack}>← Back</button>
      <h1>License Management</h1>
      <p>Review and manage SOC Platform license configuration.</p>

      {message && (
        <p role="status" style={{ padding: 12, background: "#1f2937", color: "#f9fafb", borderRadius: 8 }}>
          {message}
        </p>
      )}

      <section style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
        gap: 16,
        margin: "20px 0",
      }}>
        <div style={card}>
          <p>License Status</p>
          <h2 style={{
            color: data?.status === "Active" ? "#16a34a" :
              data?.status === "Expired" ? "#dc2626" : "#d97706",
          }}>{data?.status || "Loading..."}</h2>
        </div>
        <div style={card}><p>Edition</p><h2>{data?.edition || "Community"}</h2></div>
        <div style={card}><p>Organization</p><h2>{data?.organization || "SOC Platform"}</h2></div>
        <div style={card}><p>Expiry Date</p><h2>{data?.expires_at || "Not set"}</h2></div>
      </section>

      <section style={{ ...card, marginBottom: 20 }}>
        <h2>Current License Details</h2>
        <p><strong>Product version:</strong> {data?.product_version || "—"}</p>
        <p><strong>Masked key:</strong> {data?.license_key || "Not activated"}</p>
        <p><strong>Activated at:</strong> {data?.activated_at || "Not activated"}</p>
        <p><strong>Last checked:</strong> {data?.checked_at ? new Date(data.checked_at).toLocaleString() : "—"}</p>
        <button style={{ ...button, background: "#dc0000", color: "#ffffff" }}
          disabled={busy} onClick={validate}>Validate License</button>
        <button style={{ ...button, border: "1px solid #d1d5db" }}
          disabled={busy} onClick={load}>Refresh</button>
      </section>

      <section style={card}>
        <h2>Configure License</h2>
        <p>Leave the key empty for an unactivated Community configuration.</p>
        <form onSubmit={save}>
          <label style={{ display: "block", marginTop: 14 }}>
            Organization
            <input style={field} value={organization}
              onChange={e => setOrganization(e.target.value)}
              maxLength={150} required />
          </label>

          <label style={{ display: "block", marginTop: 14 }}>
            Edition
            <select style={field} value={edition}
              onChange={e => setEdition(e.target.value)}>
              <option>Community</option>
              <option>Professional</option>
              <option>Enterprise</option>
            </select>
          </label>

          <label style={{ display: "block", marginTop: 14 }}>
            License Key
            <input style={field} type="password" value={key}
              onChange={e => setKey(e.target.value)}
              maxLength={250} autoComplete="new-password"
              placeholder="Enter a license key if issued to you" />
          </label>

          <label style={{ display: "block", marginTop: 14 }}>
            Expiry Date
            <input style={field} type="date" value={expiry}
              onChange={e => setExpiry(e.target.value)}
              required={Boolean(key.trim())} />
          </label>

          <button type="submit" style={{ ...button, background: "#dc0000", color: "#ffffff" }}
            disabled={busy}>Save Configuration</button>
        </form>
      </section>
    </main>
  );
}
