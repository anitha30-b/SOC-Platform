import { useCallback, useEffect, useState } from "react";

const API = "http://127.0.0.1:8000";

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function AdminBackup({ onBack }) {
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [downloading, setDownloading] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const getToken = () => localStorage.getItem("token");

  const requestHeaders = () => ({
    Authorization: `Bearer ${getToken()}`,
  });

  const loadBackups = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API}/system/backups`, {
        headers: requestHeaders(),
      });

      if (!response.ok) {
        throw new Error(
          response.status === 401 || response.status === 403
            ? "Admin access is required. Please sign in again if your session expired."
            : `Could not load backups (HTTP ${response.status}).`
        );
      }

      const data = await response.json();
      setBackups(data.backups || []);
    } catch (err) {
      setError(err.message || "Unable to connect to the backend.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadBackups();
  }, [loadBackups]);

  async function createBackup() {
    if (
      !window.confirm(
        "Create a new PostgreSQL database backup now?"
      )
    ) {
      return;
    }

    setCreating(true);
    setError("");
    setMessage("");

    try {
      const response = await fetch(`${API}/system/backups`, {
        method: "POST",
        headers: requestHeaders(),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.detail || `Backup failed (HTTP ${response.status}).`);
      }

      setMessage(data.message || "Backup created successfully.");
      await loadBackups();
    } catch (err) {
      setError(err.message || "Unable to create the backup.");
    } finally {
      setCreating(false);
    }
  }

  async function downloadBackup(filename) {
    setDownloading(filename);
    setError("");
    setMessage("");

    try {
      const response = await fetch(
        `${API}/system/backups/${encodeURIComponent(filename)}/download`,
        { headers: requestHeaders() }
      );

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || `Download failed (HTTP ${response.status}).`);
      }

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setMessage(`Download started: ${filename}`);
    } catch (err) {
      setError(err.message || "Unable to download the backup.");
    } finally {
      setDownloading("");
    }
  }

  return (
    <div className="admin-backup-page">
      <div className="admin-backup-header">
        <div>
          <h2>Database Backup</h2>
          <p>Create and download PostgreSQL database backup archives.</p>
        </div>
        <div className="admin-backup-actions">
          <button type="button" onClick={loadBackups} disabled={loading || creating}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <button type="button" onClick={createBackup} disabled={creating || loading}>
            {creating ? "Creating backup..." : "+ Create Backup"}
          </button>
        </div>
      </div>

      <div className="admin-backup-notice">
        <strong>Database backup only</strong>
        <span>
          This creates a PostgreSQL database archive. It does not back up
          application files, environment variables, or uploaded files.
        </span>
      </div>

      {message && <div className="admin-backup-success" role="status">{message}</div>}
      {error && <div className="admin-backup-error" role="alert">{error}</div>}

      <div className="admin-backup-stats">
        <div className="admin-backup-stat">
          <span>Total backups</span>
          <strong>{backups.length}</strong>
        </div>
        <div className="admin-backup-stat">
          <span>Total stored size</span>
          <strong>
            {formatBytes(backups.reduce((sum, item) => sum + (item.size_bytes || 0), 0))}
          </strong>
        </div>
      </div>

      <div className="admin-backup-table-wrap">
        <table className="admin-backup-table">
          <thead>
            <tr>
              <th>Backup file</th>
              <th>Created</th>
              <th>Size</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan="5">Loading backups...</td></tr>
            ) : backups.length === 0 ? (
              <tr><td colSpan="5">No backups found. Create your first backup.</td></tr>
            ) : (
              backups.map((backup) => (
                <tr key={backup.filename}>
                  <td className="admin-backup-filename">{backup.filename}</td>
                  <td>{formatDate(backup.created_at)}</td>
                  <td>{formatBytes(backup.size_bytes || 0)}</td>
                  <td><span className="admin-backup-status">{backup.status}</span></td>
                  <td>
                    <button
                      type="button"
                      onClick={() => downloadBackup(backup.filename)}
                      disabled={Boolean(downloading) || creating}
                    >
                      {downloading === backup.filename ? "Downloading..." : "Download"}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {onBack && (
        <button className="admin-backup-back" type="button" onClick={onBack}>
          Back
        </button>
      )}
    </div>
  );
}
