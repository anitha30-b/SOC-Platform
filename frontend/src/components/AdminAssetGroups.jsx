import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";
const EMPTY_GROUP = { name: "", description: "" };

function authConfig() {
  const token = localStorage.getItem("token");
  return { headers: token ? { Authorization: `Bearer ${token}` } : {} };
}

const inputClass =
  "w-full rounded-md border border-white/10 bg-[#090c0f] px-3 py-2.5 text-sm text-white outline-none focus:border-red-500";

export default function AdminAssetGroups({ onBack }) {
  const [groups, setGroups] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [form, setForm] = useState(EMPTY_GROUP);
  const [editing, setEditing] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [selectedAssets, setSelectedAssets] = useState({});

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [groupResponse, assetResponse] = await Promise.all([
        axios.get(`${API}/asset-groups`, authConfig()),
        axios.get(`${API}/assets`, authConfig()),
      ]);
      setGroups(groupResponse.data.groups || []);
      setAssets(assetResponse.data.assets || []);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Could not load asset groups. Check the backend and administrator login."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return groups.filter((group) =>
      `${group.name} ${group.description || ""}`.toLowerCase().includes(q)
    );
  }, [groups, query]);

  const totalAssignments = groups.reduce(
    (sum, group) => sum + (group.asset_count || 0), 0
  );

  function startCreate() {
    setForm({ ...EMPTY_GROUP });
    setEditing(null);
    setShowForm(true);
    setError("");
    setNotice("");
  }

  function startEdit(group) {
    setForm({ name: group.name, description: group.description || "" });
    setEditing(group.id);
    setShowForm(true);
    setError("");
    setNotice("");
  }

  async function saveGroup(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");

    try {
      if (editing !== null) {
        await axios.put(`${API}/asset-groups/${editing}`, form, authConfig());
        setNotice("Asset group updated successfully.");
      } else {
        await axios.post(`${API}/asset-groups`, form, authConfig());
        setNotice("Asset group created successfully.");
      }
      setShowForm(false);
      setEditing(null);
      setForm({ ...EMPTY_GROUP });
      await loadData();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not save the asset group.");
    } finally {
      setSaving(false);
    }
  }

  async function deleteGroup(group) {
    if (!window.confirm(
      `Delete group "${group.name}"? Its memberships will be removed, but the assets themselves will remain.`
    )) return;

    setError("");
    setNotice("");
    try {
      await axios.delete(`${API}/asset-groups/${group.id}`, authConfig());
      setNotice("Asset group deleted.");
      await loadData();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not delete the group.");
    }
  }

  async function addAsset(group) {
    const assetId = Number(selectedAssets[group.id]);
    if (!assetId) {
      setError("Select an asset to assign to this group.");
      return;
    }

    setError("");
    setNotice("");
    try {
      await axios.post(
        `${API}/asset-groups/${group.id}/members`,
        { asset_id: assetId },
        authConfig()
      );
      setNotice("Asset assigned to group.");
      setSelectedAssets((prev) => ({ ...prev, [group.id]: "" }));
      await loadData();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not assign the asset.");
    }
  }

  async function removeAsset(group, asset) {
    if (!window.confirm(
      `Remove "${asset.name}" from "${group.name}"? The asset itself will not be deleted.`
    )) return;

    setError("");
    setNotice("");
    try {
      await axios.delete(
        `${API}/asset-groups/${group.id}/members/${asset.id}`,
        authConfig()
      );
      setNotice("Asset removed from group.");
      await loadData();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not remove the asset.");
    }
  }

  function exportCsv() {
    const columns = ["group_id", "group_name", "description", "asset_count",
      "asset_ids", "asset_names", "asset_types"];
    const escape = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const rows = filtered.map((group) => [
      group.id,
      group.name,
      group.description,
      group.asset_count,
      (group.assets || []).map((asset) => asset.id).join("; "),
      (group.assets || []).map((asset) => asset.name).join("; "),
      (group.assets || []).map((asset) => asset.asset_type).join("; "),
    ].map(escape).join(","));

    const blobUrl = URL.createObjectURL(
      new Blob([[columns.join(","), ...rows].join("\r\n")],
        { type: "text/csv;charset=utf-8;" })
    );
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = "soc-asset-groups.csv";
    link.click();
    URL.revokeObjectURL(blobUrl);
  }

  return (
    <div className="space-y-6 text-gray-200">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Asset Management / Asset Groups
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Asset Groups</h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-500">
            Organize existing SOC inventory assets into manageable groups.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={onBack}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300">
            ← Overview
          </button>
          <button onClick={loadData}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300">
            Refresh
          </button>
          <button onClick={exportCsv}
            className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300">
            Export CSV
          </button>
          <button onClick={startCreate}
            className="rounded-md bg-red-600 px-3 py-2 text-xs font-semibold text-white">
            + Create Group
          </button>
        </div>
      </div>

      {error && <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">{error}</div>}
      {notice && <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">{notice}</div>}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {[
          ["Total Groups", groups.length],
          ["Assigned Assets", totalAssignments],
          ["Available Inventory Assets", assets.length],
        ].map(([label, value]) => (
          <div key={label} className="rounded-lg border border-white/10 bg-[#111519] p-4">
            <p className="text-xs text-gray-500">{label}</p>
            <p className="mt-2 text-2xl font-bold text-white">{value}</p>
          </div>
        ))}
      </div>

      {showForm && (
        <form onSubmit={saveGroup}
          className="space-y-4 rounded-lg border border-white/10 bg-[#111519] p-5">
          <h2 className="text-lg font-semibold text-white">
            {editing !== null ? "Edit Asset Group" : "Create Asset Group"}
          </h2>
          <label className="block space-y-1.5">
            <span className="text-xs text-gray-400">Group Name *</span>
            <input required maxLength={150} className={inputClass}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </label>
          <label className="block space-y-1.5">
            <span className="text-xs text-gray-400">Description</span>
            <textarea rows={3} className={inputClass}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </label>
          <div className="flex gap-2">
            <button disabled={saving}
              className="rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">
              {saving ? "Saving..." : editing !== null ? "Save Changes" : "Create Group"}
            </button>
            <button type="button" onClick={() => setShowForm(false)}
              className="rounded-md border border-white/10 px-4 py-2 text-sm text-gray-300">
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="rounded-lg border border-white/10 bg-[#111519] p-4">
        <input className={inputClass} placeholder="Search groups by name or description..."
          value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>

      <div className="overflow-hidden rounded-lg border border-white/10 bg-[#111519]">
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <h2 className="font-semibold text-white">Registered Groups</h2>
          <span className="text-xs text-gray-500">{filtered.length} groups</span>
        </div>
        {loading ? <p className="p-6 text-sm text-gray-400">Loading asset groups...</p> :
          filtered.length === 0 ? (
            <div className="p-10 text-center">
              <p className="font-medium text-white">No asset groups found</p>
              <p className="mt-2 text-sm text-gray-500">Create a group to start organizing your inventory.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {filtered.map((group) => {
                const members = group.assets || [];
                const memberIds = new Set(members.map((asset) => asset.id));
                const available = assets.filter((asset) => !memberIds.has(asset.id));

                return (
                  <section key={group.id} className="space-y-4 p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <h3 className="font-semibold text-white">{group.name}</h3>
                        <p className="mt-1 text-sm text-gray-500">{group.description || "No description provided."}</p>
                        <p className="mt-2 text-xs text-gray-400">{members.length} assigned asset(s)</p>
                      </div>
                      <div className="flex gap-3">
                        <button onClick={() => startEdit(group)}
                          className="text-xs text-sky-300">Edit</button>
                        <button onClick={() => deleteGroup(group)}
                          className="text-xs text-red-300">Delete</button>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <select className={`${inputClass} min-w-[240px] flex-1`}
                        value={selectedAssets[group.id] || ""}
                        onChange={(e) => setSelectedAssets((prev) => ({
                          ...prev, [group.id]: e.target.value,
                        }))}>
                        <option value="">Select an inventory asset to assign</option>
                        {available.map((asset) => (
                          <option key={asset.id} value={asset.id}>
                            #{asset.id} · {asset.name} ({asset.asset_type})
                          </option>
                        ))}
                      </select>
                      <button onClick={() => addAsset(group)}
                        disabled={available.length === 0}
                        className="rounded-md border border-white/10 px-3 py-2 text-xs text-gray-200 disabled:opacity-40">
                        + Assign Asset
                      </button>
                    </div>

                    {members.length > 0 && (
                      <div className="overflow-x-auto">
                        <table className="w-full min-w-[600px] text-left text-sm">
                          <thead className="text-xs uppercase text-gray-500">
                            <tr>
                              {["Asset", "Type", "Environment", "Status", "Criticality", "Action"].map((h) =>
                                <th key={h} className="px-3 py-2 font-medium">{h}</th>
                              )}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-white/5">
                            {members.map((asset) => (
                              <tr key={asset.id}>
                                <td className="px-3 py-3 text-white">{asset.name}</td>
                                <td className="px-3 py-3">{asset.asset_type}</td>
                                <td className="px-3 py-3">{asset.environment}</td>
                                <td className="px-3 py-3">{asset.status}</td>
                                <td className="px-3 py-3">{asset.criticality}</td>
                                <td className="px-3 py-3">
                                  <button onClick={() => removeAsset(group, asset)}
                                    className="text-xs text-red-300">Remove</button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </section>
                );
              })}
            </div>
          )}
      </div>
    </div>
  );
}
