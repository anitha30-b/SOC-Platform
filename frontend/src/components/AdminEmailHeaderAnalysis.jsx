import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

export default function AdminEmailHeaderAnalysis() {
  const [headers, setHeaders] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const auth = () => ({
    Authorization: `Bearer ${localStorage.getItem("token")}`,
  });

  const loadHistory = async () => {
    try {
      const response = await axios.get(
        `${API_URL}/admin/email-header-analysis/history`,
        { headers: auth() }
      );
      setHistory(response.data.analyses || []);
    } catch (err) {
      console.error("Unable to load email analysis history:", err);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const analyzeHeaders = async () => {
    if (!headers.trim()) {
      setError("Paste email headers before starting the analysis.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await axios.post(
        `${API_URL}/admin/email-header-analysis/analyze`,
        { raw_headers: headers },
        { headers: auth() }
      );
      setResult(response.data);
      loadHistory();
    } catch (err) {
      setError(
        err.response?.data?.detail || "Unable to analyze the email headers."
      );
    } finally {
      setLoading(false);
    }
  };

  const analyzeFile = async () => {
    if (!file) {
      setError("Select an .eml file first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await axios.post(
        `${API_URL}/admin/email-header-analysis/analyze-eml`,
        formData,
        { headers: auth() }
      );
      setResult(response.data);
      loadHistory();
    } catch (err) {
      setError(
        err.response?.data?.detail || "Unable to analyze the uploaded file."
      );
    } finally {
      setLoading(false);
    }
  };

  const panelStyle = {
    background: "#111827",
    border: "1px solid #374151",
    borderRadius: "12px",
    padding: "20px",
    marginBottom: "18px",
  };

  const riskColor = (level) => ({
    LOW: "#16a34a",
    MEDIUM: "#ca8a04",
    HIGH: "#ea580c",
    CRITICAL: "#dc2626",
  }[level] || "#64748b");

  return (
    <div style={{ padding: "24px", maxWidth: "1200px", margin: "0 auto", color: "#f9fafb" }}>
      <div style={{ marginBottom: "22px" }}>
        <h2 style={{ marginBottom: "8px" }}>Email Header Analysis</h2>
        <p style={{ color: "#9ca3af" }}>
          Analyze email headers to identify suspicious sender information,
          authentication failures and possible phishing indicators.
        </p>
      </div>

      <div style={panelStyle}>
        <h3>Paste Email Headers</h3>
        <textarea
          value={headers}
          onChange={(e) => setHeaders(e.target.value)}
          placeholder={"From: sender@example.com\nReply-To: reply@example.com\nSubject: Important message\nAuthentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass"}
          rows={10}
          style={{
            width: "100%",
            boxSizing: "border-box",
            padding: "12px",
            borderRadius: "8px",
            border: "1px solid #374151",
            background: "#0b1220",
            color: "#f9fafb",
            fontFamily: "monospace",
            resize: "vertical",
          }}
        />
        <button
          onClick={analyzeHeaders}
          disabled={loading}
          style={{
            marginTop: "12px",
            padding: "10px 18px",
            border: 0,
            borderRadius: "7px",
            background: "#2563eb",
            color: "white",
            cursor: loading ? "wait" : "pointer",
          }}
        >
          {loading ? "Analyzing..." : "Analyze Headers"}
        </button>
      </div>

      <div style={panelStyle}>
        <h3>Upload Email File</h3>
        <p style={{ color: "#9ca3af" }}>
          Upload an .eml file. Maximum file size: 1 MB. Only its headers
          will be analyzed.
        </p>
        <input
          type="file"
          accept=".eml,message/rfc822"
          style={{ color: "#f9fafb", marginTop: "10px" }}
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />
        <button
          onClick={analyzeFile}
          disabled={loading || !file}
          style={{
            marginLeft: "12px",
            padding: "10px 18px",
            border: 0,
            borderRadius: "7px",
            background: "#2563eb",
            color: "white",
            cursor: loading || !file ? "not-allowed" : "pointer",
          }}
        >
          Analyze .eml File
        </button>
      </div>

      {error && (
        <div style={{
          ...panelStyle,
          color: "#dc2626",
          borderColor: "#dc2626",
        }}>
          {error}
        </div>
      )}

      {result && (
        <div style={panelStyle}>
          <h3>Analysis Results</h3>
          <div style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "24px",
            alignItems: "center",
            marginBottom: "18px",
          }}>
            <div>
              <div style={{ color: "#9ca3af" }}>
                Risk Score
              </div>
              <strong style={{ fontSize: "32px" }}>
                {result.risk_score}/100
              </strong>
            </div>
            <div>
              <div style={{ color: "#9ca3af" }}>
                Risk Level
              </div>
              <strong style={{
                color: riskColor(result.risk_level),
                fontSize: "22px",
              }}>
                {result.risk_level}
              </strong>
            </div>
          </div>

          <p><strong>Sender:</strong> {result.sender || "Not available"}</p>
          <p><strong>Reply-To:</strong> {result.reply_to || "Not available"}</p>
          <p><strong>Subject:</strong> {result.subject || "Not available"}</p>
          <p><strong>Sender Domain:</strong> {result.from_domain || "Not available"}</p>
          <p><strong>Received Hops:</strong> {result.received_hops}</p>
          <p><strong>Message-ID Present:</strong> {result.message_id_present ? "Yes" : "No"}</p>

          <h4>Authentication Results</h4>
          {Object.entries(result.authentication_results || {})
            .filter(([key]) => key !== "source")
            .map(([key, value]) => (
              <p key={key}>
                <strong>{key.toUpperCase()}:</strong> {value}
              </p>
            ))}
          <small>{result.authentication_results?.source}</small>

          <h4>Suspicious Indicators</h4>
          {result.indicators?.length ? (
            <ul>
              {result.indicators.map((item, index) => (
                <li key={index} style={{ marginBottom: "8px" }}>
                  <strong>{item.severity}:</strong> {item.message}
                </li>
              ))}
            </ul>
          ) : (
            <p>No suspicious indicators were identified by the current checks.</p>
          )}

          <p style={{
            marginTop: "16px",
            color: "#9ca3af",
            fontSize: "13px",
          }}>
            {result.analysis_note}
          </p>
        </div>
      )}

      <div style={panelStyle}>
        <h3>Analysis History</h3>
        {history.length === 0 ? (
          <p>No email analyses recorded yet.</p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  {["Date", "Sender", "Subject", "Score", "Risk"].map((heading) => (
                    <th key={heading} style={{
                      textAlign: "left",
                      padding: "10px",
                      borderBottom: "1px solid #374151",
                    }}>
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.id}>
                    <td style={{ padding: "10px" }}>
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: "10px" }}>
                      {item.sender || "Unknown"}
                    </td>
                    <td style={{ padding: "10px" }}>
                      {item.subject || "No subject"}
                    </td>
                    <td style={{ padding: "10px" }}>
                      {item.risk_score}/100
                    </td>
                    <td style={{
                      padding: "10px",
                      fontWeight: "bold",
                      color: riskColor(item.risk_level),
                    }}>
                      {item.risk_level}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <button
          onClick={loadHistory}
          style={{
            marginTop: "12px",
            padding: "8px 14px",
            borderRadius: "7px",
            border: "1px solid #374151",
            cursor: "pointer",
          }}
        >
          Refresh History
        </button>
      </div>
    </div>
  );
}
