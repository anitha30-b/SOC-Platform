import { useEffect, useRef, useState } from "react";

export default function AccountNotificationCenter({ apiUrl: API_URL }) {
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [wsConnected, setWsConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const mounted = useRef(false);
  const sequence = useRef(0);
  const mutating = useRef(false);
  const fetchController = useRef(null);

  async function api(path, options = {}) {
    const token = localStorage.getItem("token");
    if (!token) throw new Error("User session expired. Please log in again.");
    const response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: { Authorization: `Bearer ${token}` },
    });
    let data;
    try { data = await response.json(); } catch {}
    if (!response.ok) {
      throw new Error(
        typeof data?.detail === "string"
          ? data.detail
          : `Notification request returned ${response.status}.`
      );
    }
    return data;
  }

  async function loadNotifications() {
    if (!mounted.current || mutating.current) return;
    const requestId = ++sequence.current;
    fetchController.current?.abort();
    const controller = new AbortController();
    fetchController.current = controller;

    try {
      const [list, count] = await Promise.all([
        api("/notifications?limit=100", { signal: controller.signal }),
        api("/notifications/unread-count", { signal: controller.signal }),
      ]);
      if (!Array.isArray(list?.notifications) ||
          !Number.isInteger(count?.unread_count) || count.unread_count < 0) {
        throw new Error("Unexpected notification response.");
      }
      if (mounted.current && requestId === sequence.current) {
        setNotifications(list.notifications);
        setUnreadCount(count.unread_count);
        setError("");
      }
    } catch (err) {
      if (mounted.current && requestId === sequence.current && err.name !== "AbortError") {
        setError(err.message || "Unable to load notifications.");
      }
    } finally {
      if (mounted.current && requestId === sequence.current) setLoading(false);
    }
  }

  async function mutate(path, method) {
    if (mutating.current) return;
    mutating.current = true;
    ++sequence.current;
    fetchController.current?.abort();
    setBusy(true);
    setError("");

    let failure = "";
    try {
      await api(path, { method });
    } catch (err) {
      failure = err.message || "Unable to update notification.";
    } finally {
      mutating.current = false;
      if (mounted.current) {
        await loadNotifications();
        if (failure) setError(failure);
        setBusy(false);
      }
    }
  }

  const markRead = (item) => mutate(
    `/notifications/${encodeURIComponent(item.notification_id)}/read`, "PATCH"
  );
  const markUnread = (item) => mutate(
    `/notifications/${encodeURIComponent(item.notification_id)}/unread`, "PATCH"
  );
  const markAllRead = () => mutate("/notifications/read-all", "PATCH");
  const deleteNotification = (item) => mutate(
    `/notifications/${encodeURIComponent(item.notification_id)}`, "DELETE"
  );

  useEffect(() => {
    mounted.current = true;
    let stopped = false;
    let socket;
    let reconnectTimer;
    let signalTimer;

    loadNotifications();

    function scheduleRefresh() {
      window.clearTimeout(signalTimer);
      signalTimer = window.setTimeout(loadNotifications, 250);
    }

    function connect() {
      if (stopped) return;
      const token = localStorage.getItem("token");
      if (!token) return;

      const url = new URL(API_URL, window.location.href);
      url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
      url.pathname = `${url.pathname.replace(/\/$/, "")}/ws/notifications`;
      url.search = "";
      url.searchParams.set("token", token);

      socket = new WebSocket(url.toString());
      socket.onopen = () => {
        if (!stopped) {
          setWsConnected(true);
          scheduleRefresh();
        }
      };
      socket.onmessage = (event) => {
        if (stopped) return;
        try {
          if (JSON.parse(event.data)?.type === "notification") scheduleRefresh();
        } catch {
          // Ignore malformed live signals; HTTP remains authoritative.
        }
      };
      socket.onerror = () => {
        if (!stopped) setWsConnected(false);
      };
      socket.onclose = () => {
        if (!stopped) {
          setWsConnected(false);
          reconnectTimer = window.setTimeout(connect, 3000);
        }
      };
    }

    connect();
    const pollTimer = window.setInterval(loadNotifications, 30000);

    return () => {
      stopped = true;
      mounted.current = false;
      ++sequence.current;
      fetchController.current?.abort();
      window.clearInterval(pollTimer);
      window.clearTimeout(reconnectTimer);
      window.clearTimeout(signalTimer);
      socket?.close();
    };
  }, [API_URL]);

  const severityClass = (severity) => {
    const value = String(severity || "INFO").toUpperCase();

    if (value === "CRITICAL") {
      return "border-red-500/40 bg-red-500/10 text-red-400";
    }

    if (value === "HIGH") {
      return "border-orange-500/40 bg-orange-500/10 text-orange-400";
    }

    if (value === "MEDIUM") {
      return "border-yellow-500/40 bg-yellow-500/10 text-yellow-400";
    }

    if (value === "LOW") {
      return "border-blue-500/40 bg-blue-500/10 text-blue-400";
    }

    return "border-gray-500/30 bg-gray-500/10 text-gray-400";
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            Security Workspace
          </p>
          <h1 className="mt-2 text-3xl font-bold text-white">
            Notification Center
          </h1>
          <p className="mt-2 text-sm text-gray-500">
            Latest 100 notifications for your account. The unread total covers all your stored notifications. Read status does not change the underlying security event.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button type="button" onClick={loadNotifications} disabled={busy}
            className="border border-white/10 px-3 py-2 text-xs text-gray-400 disabled:opacity-40">
            Refresh
          </button>
          <span className="border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-gray-400">
            {unreadCount == null ? "—" : unreadCount} unread
          </span>

          <span
            className={`border px-3 py-2 text-xs ${
              wsConnected
                ? "border-green-500/30 bg-green-500/10 text-green-400"
                : "border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
            }`}
          >
            {wsConnected ? "● REAL-TIME CONNECTED" : "● RECONNECTING"}
          </span>

          {unreadCount > 0 && (
            <button
              type="button"
              onClick={markAllRead}
              disabled={busy}
              className="border border-white/10 px-3 py-2 text-xs text-gray-400 hover:border-red-500/40 hover:text-white"
            >
              Mark all read
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="border border-red-600/30 bg-red-600/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {loading ? (
        <div className="border border-white/10 bg-white/[0.03] p-10 text-center text-sm text-gray-500">
          Loading notifications...
        </div>
      ) : error && notifications.length === 0 ? null : notifications.length === 0 ? (
        <div className="border border-white/10 bg-white/[0.03] p-10 text-center">
          <div className="text-3xl">🔔</div>
          <h2 className="mt-4 text-lg font-semibold text-white">
            No notifications
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            New security events will appear here in real time.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {notifications.map((notification) => (
            <div
              key={notification.notification_id}
              className={`border p-5 transition ${
                notification.is_read
                  ? "border-white/10 bg-white/[0.02]"
                  : "border-red-500/20 bg-red-500/[0.03]"
              }`}
            >
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`border px-2 py-1 text-[9px] font-semibold uppercase ${severityClass(
                        notification.severity
                      )}`}
                    >
                      {notification.severity || "INFO"}
                    </span>

                    {!notification.is_read && (
                      <span className="border border-red-500/30 bg-red-500/10 px-2 py-1 text-[9px] text-red-400">
                        UNREAD
                      </span>
                    )}
                  </div>

                  <h2 className="mt-3 text-base font-semibold text-white">
                    {notification.title || "Security Notification"}
                  </h2>

                  <p className="mt-2 text-sm leading-6 text-gray-400">
                    {notification.message || "Security event received."}
                  </p>

                  <div className="mt-4 grid grid-cols-1 gap-3 text-xs md:grid-cols-3">
                    <div>
                      <span className="text-gray-600">Source</span>
                      <div className="mt-1 text-gray-400">
                        {notification.source || "—"}
                      </div>
                    </div>

                    <div>
                      <span className="text-gray-600">Event</span>
                      <div className="mt-1 text-gray-400">
                        {notification.event_type || "—"}
                      </div>
                    </div>

                    <div>
                      <span className="text-gray-600">Target</span>
                      <div className="mt-1 break-all text-gray-400">
                        {notification.target || "—"}
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 text-[10px] text-gray-600">
                    {notification.created_at
                      ? new Date(notification.created_at).toLocaleString()
                      : "—"}
                    {" · "}
                    {notification.notification_id}
                  </div>
                </div>

                <div className="flex shrink-0 flex-wrap gap-2">
                  {notification.is_read ? (
                    <button
                      type="button"
                      onClick={() => markUnread(notification)}
                      disabled={busy}
                      className="border border-white/10 px-3 py-2 text-[10px] text-gray-400 hover:border-red-500/40 hover:text-white"
                    >
                      Mark unread
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => markRead(notification)}
                      disabled={busy}
                      className="border border-green-500/20 px-3 py-2 text-[10px] text-green-400 hover:bg-green-500/10"
                    >
                      Mark read
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => deleteNotification(notification)}
                      disabled={busy}
                    className="border border-red-500/20 px-3 py-2 text-[10px] text-red-400 hover:bg-red-500/10"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


// ==================================================
// LIVE SIEM ALERTS
// ==================================================

