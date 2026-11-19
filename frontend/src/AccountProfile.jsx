import { useEffect, useState } from "react";

export default function AccountProfile({ apiUrl, children }) {
  const [account, setAccount] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError("");
    setAccount(null);

    async function load() {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("Authentication required. Please log in again.");

        const response = await fetch(`${apiUrl}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(
            response.status === 401 || response.status === 403
              ? "Your session is not authorized. Please log in again."
              : `Account API returned ${response.status}.`
          );
        }

        const body = await response.json();
        if (!Number.isInteger(body?.id) ||
            typeof body.username !== "string" ||
            typeof body.email !== "string" ||
            !Number.isInteger(body.role_id)) {
          throw new Error("Unexpected account response.");
        }
        if (body.role_id !== 1) {
          throw new Error("This page requires user/client access.");
        }

        if (active) {
          setAccount({
            id: body.id,
            username: body.username,
            email: body.email,
            role_id: body.role_id,
          });
        }
      } catch (err) {
        if (active && err.name !== "AbortError") {
          setError(err.message || "Unable to load your account.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    load();
    return () => {
      active = false;
      controller.abort();
    };
  }, [apiUrl, refresh]);

  return (
    <div className="space-y-6 text-slate-200">
      <header className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-widest text-red-500">Account</p>
          <h1 className="mt-3 text-3xl font-bold text-white">Profile</h1>
        </div>
        <button disabled={loading}
          onClick={() => setRefresh((value) => value + 1)}
          className="rounded border border-slate-700 px-5 py-3 text-white disabled:opacity-40">
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </header>

      {error && <div role="alert"
        className="rounded border border-red-800 p-5 text-red-300">
        {error}
      </div>}

      <section className="rounded-xl border border-slate-800 bg-[#0b1217] p-6">
        <h2 className="text-xl font-semibold text-white">Account Details</h2>
        {loading ? <p className="mt-5">Loading your account...</p> : account && (
          <dl className="mt-6 grid gap-6 md:grid-cols-2">
            {[
              ["Account ID", account.id],
              ["Username", account.username],
              ["Email", account.email],
              ["Access role", "User / Client"],
            ].map(([label, value]) => <div key={label}>
              <dt className="text-sm text-slate-400">{label}</dt>
              <dd className="mt-2 break-words text-white">{value}</dd>
            </div>)}
          </dl>
        )}
        <p className="mt-6 text-sm text-slate-400">
          Account details are read-only in this view.
        </p>
      </section>

      {account && <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Telegram Connection</h2>
        {children}
      </section>}
    </div>
  );
}
