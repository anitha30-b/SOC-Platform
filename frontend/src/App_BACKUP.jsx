import { useEffect, useState } from "react";
import axios from "axios";
import { jsPDF } from "jspdf";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [page, setPage] = useState("home");

  // =========================
  // HOME PAGE
  // =========================
  if (page === "home") {
    return (
      <div className="min-h-screen bg-[#080808] text-white">

        {/* NAVBAR */}
        <nav className="border-b border-white/10">
          <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">

            <button
              onClick={() => setPage("home")}
              className="flex items-center gap-3"
            >
              <div className="flex h-9 w-9 items-center justify-center rounded-md bg-red-600 font-bold">
                S
              </div>

              <div className="text-left">
                <p className="text-lg font-semibold tracking-wide">
                  SOC PLATFORM
                </p>

                <p className="text-[10px] uppercase tracking-[0.25em] text-gray-500">
                  Security Operations Center
                </p>
              </div>
            </button>

            <div className="flex items-center gap-3">
              <button
                onClick={() => setPage("admin-login")}
                className="rounded-md border border-white/15 px-5 py-2 text-sm text-gray-300 transition hover:border-red-500 hover:text-white"
              >
                Admin Login
              </button>

              <button
                onClick={() => setPage("user-login")}
                className="rounded-md bg-red-600 px-5 py-2 text-sm font-medium transition hover:bg-red-700"
              >
                User Login
              </button>
            </div>

          </div>
        </nav>

        {/* MAIN */}
        <main className="mx-auto max-w-7xl px-6">

          <section className="grid min-h-[600px] items-center gap-16 py-16 lg:grid-cols-2">

            {/* LEFT */}
            <div>

              <div className="mb-6 flex items-center gap-3">
                <span className="h-px w-10 bg-red-600"></span>

                <span className="text-xs font-medium uppercase tracking-[0.3em] text-red-500">
                  Security Operations Center
                </span>
              </div>

              <h1 className="max-w-3xl text-5xl font-bold leading-[1.05] tracking-tight md:text-7xl">
                See Every Threat.
                <br />
                <span className="text-red-600">
                  Secure Every Layer.
                </span>
              </h1>

              <p className="mt-7 max-w-xl text-lg leading-8 text-gray-400">
                A unified security platform that helps organizations
                discover vulnerabilities, validate security, monitor
                critical activity, and turn security intelligence into
                actionable decisions.
              </p>

              <div className="mt-9 flex items-center gap-4">
                <button
                  onClick={() => setPage("user-login")}
                  className="rounded-md bg-red-600 px-7 py-3.5 text-sm font-semibold transition hover:bg-red-700"
                >
                  Get Started
                </button>

                <span className="text-sm text-gray-500">
                  Centralized Security Platform
                </span>
              </div>

              <div className="mt-12 flex flex-wrap gap-10 border-t border-white/10 pt-7">

                <Stat number="150+" label="Security Tools" />

                <Stat number="24/7" label="Monitoring" />

                <Stat number="PDF" label="Reporting" />

              </div>

            </div>

            {/* RIGHT */}
            <div className="relative">

              <div className="absolute inset-0 opacity-20">
                <div
                  className="h-full w-full"
                  style={{
                    backgroundImage:
                      "linear-gradient(rgba(255,255,255,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.08) 1px, transparent 1px)",
                    backgroundSize: "40px 40px",
                  }}
                />
              </div>

              <div className="relative border border-white/10 bg-[#0d0d0d] p-7">

                <div className="flex items-center justify-between border-b border-white/10 pb-5">

                  <div>
                    <p className="text-xs uppercase tracking-[0.25em] text-gray-500">
                      Security Intelligence
                    </p>

                    <p className="mt-1 text-xl font-semibold">
                      Platform Overview
                    </p>
                  </div>

                  <div className="flex items-center gap-2 text-xs text-gray-400">
                    <span className="h-2 w-2 rounded-full bg-green-500"></span>
                    Operational
                  </div>

                </div>

                <div className="py-8">

                  <p className="text-sm text-gray-500">
                    Security Coverage
                  </p>

                  <div className="mt-2 flex items-end gap-2">
                    <span className="text-6xl font-bold">
                      98
                    </span>

                    <span className="mb-2 text-2xl text-red-500">
                      %
                    </span>
                  </div>

                  <div className="mt-5 h-1.5 w-full bg-white/10">
                    <div className="h-full w-[98%] bg-red-600"></div>
                  </div>

                </div>

                <div className="space-y-3">

                  <SecurityItem
                    number="01"
                    title="Vulnerability Assessment"
                    description="VAPT & security testing"
                    status="ACTIVE"
                  />

                  <SecurityItem
                    number="02"
                    title="Threat Monitoring"
                    description="Logs & security events"
                    status="ONLINE"
                  />

                  <SecurityItem
                    number="03"
                    title="Security Reporting"
                    description="Findings & evidence"
                    status="READY"
                  />

                </div>

                <div className="mt-6 flex justify-between border-t border-white/10 pt-5 text-xs text-gray-600">
                  <span>SECURITY ENGINE</span>
                  <span>LIVE</span>
                </div>

              </div>
            </div>

          </section>

          {/* CAPABILITIES */}
          <section className="border-t border-white/10 py-12">

            <div className="mb-8">
              <p className="text-xs uppercase tracking-[0.3em] text-red-500">
                Core Capabilities
              </p>

              <h2 className="mt-2 text-2xl font-semibold">
                Complete security visibility.
              </h2>
            </div>

            <div className="grid gap-px overflow-hidden border border-white/10 bg-white/10 md:grid-cols-4">

              <Capability
                number="01"
                title="VAPT Testing"
                description="Identify vulnerabilities and security weaknesses."
              />

              <Capability
                number="02"
                title="QA Testing"
                description="Validate application behaviour and security."
              />

              <Capability
                number="03"
                title="Live Logs"
                description="Monitor security events and system activity."
              />

              <Capability
                number="04"
                title="Reporting"
                description="Generate professional security reports."
              />

            </div>

          </section>

        </main>

        {/* FOOTER */}
        <footer className="border-t border-white/10 px-6 py-6">

          <div className="mx-auto flex max-w-7xl flex-col justify-between gap-3 text-xs text-gray-500 md:flex-row">

            <p>© 2026 SOC Platform</p>

            <p>Security • Visibility • Response</p>

          </div>

        </footer>

      </div>
    );
  }


  // =========================
  // ADMIN LOGIN
  // =========================
  if (page === "admin-login") {
    return (
      <AdminLogin
        onBack={() => setPage("home")}
        onSuccess={() => setPage("admin-dashboard")}
      />
    );
  }


  // =========================
  // ADMIN DASHBOARD
  // =========================
  if (page === "admin-dashboard") {
    return (
      <AdminDashboard
        onLogout={() => {
          localStorage.removeItem("token");
          setPage("home");
        }}
      />
    );
  }


  // =========================
  // USER LOGIN
  // =========================
  if (page === "user-login") {
    return (
      <UserLogin
        onBack={() => setPage("home")}
        onSuccess={() => setPage("user-dashboard")}
      />
    );
  }

  // =========================
  // USER DASHBOARD
  // =========================
  if (page === "user-dashboard") {
    return (
      <UserDashboard
        onLogout={() => {
          localStorage.removeItem("token");
          localStorage.removeItem("active_vapt_target");
          localStorage.removeItem("active_vapt_target_meta");
          setPage("home");
        }}
      />
    );
  }

  return null;
}


// ==================================================
// ADMIN LOGIN
// ==================================================
function AdminLogin({ onBack, onSuccess }) {

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {

    e.preventDefault();

    setError("");

    if (!email || !password) {
      setError("Please enter your email and password.");
      return;
    }

    try {

      setLoading(true);

      const response = await axios.post(
        `${API_URL}/auth/login`,
        {
          email,
          password,
        }
      );

      const token = response.data.access_token;

      localStorage.setItem("token", token);

      // Check current user
      const meResponse = await axios.get(
        `${API_URL}/auth/me`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      // Admin role = 3
      if (meResponse.data.role_id !== 3) {

        localStorage.removeItem("token");

        setError("This account does not have Admin access.");

        return;
      }

      onSuccess();

    } catch (err) {

      console.error(err);

      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to connect to the SOC Platform API.");
      }

    } finally {
      setLoading(false);
    }
  };


  return (
    <div className="min-h-screen bg-[#080808] text-white">

      <div className="mx-auto flex min-h-screen max-w-6xl items-center px-6">

        <div className="grid w-full gap-16 lg:grid-cols-2">

          {/* LEFT */}
          <div className="hidden lg:flex lg:flex-col lg:justify-center">

            <div className="mb-6 flex items-center gap-3">
              <span className="h-px w-10 bg-red-600"></span>

              <span className="text-xs uppercase tracking-[0.3em] text-red-500">
                Administrator Access
              </span>
            </div>

            <h1 className="text-5xl font-bold leading-tight">
              Manage your
              <br />
              <span className="text-red-600">
                security operations.
              </span>
            </h1>

            <p className="mt-6 max-w-lg leading-7 text-gray-500">
              Access platform controls, users, security testing,
              reports, tools and audit information from one
              centralized administration console.
            </p>

          </div>


          {/* FORM */}
          <div className="flex items-center">

            <div className="w-full max-w-md">

              <button
                onClick={onBack}
                className="mb-8 text-sm text-gray-500 transition hover:text-white"
              >
                ← Back to Home
              </button>

              <div className="mb-8">

                <div className="mb-5 flex h-10 w-10 items-center justify-center rounded-md bg-red-600 font-bold">
                  S
                </div>

                <p className="text-xs uppercase tracking-[0.3em] text-red-500">
                  SOC PLATFORM
                </p>

                <h2 className="mt-3 text-3xl font-bold">
                  Admin Login
                </h2>

                <p className="mt-2 text-sm text-gray-500">
                  Sign in to access the administration console.
                </p>

              </div>

              <form
                onSubmit={handleSubmit}
                className="border border-white/10 bg-[#0d0d0d] p-7"
              >

                <label className="text-xs uppercase tracking-wider text-gray-500">
                  Email
                </label>

                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@example.com"
                  className="mt-2 mb-5 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                />

                <label className="text-xs uppercase tracking-wider text-gray-500">
                  Password
                </label>

                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                />

                {error && (
                  <div className="mt-5 border border-red-600/30 bg-red-600/10 px-4 py-3 text-sm text-red-400">
                    {error}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="mt-6 w-full bg-red-600 py-3.5 text-sm font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {loading ? "Signing In..." : "Sign In"}
                </button>

              </form>

              <p className="mt-5 text-center text-xs text-gray-600">
                Authorized administrator access only
              </p>

            </div>

          </div>

        </div>

      </div>

    </div>
  );
}


// ==================================================
// ADMIN DASHBOARD
// ==================================================
function AdminDashboard({ onLogout }) {

  const [dashboard, setDashboard] = useState(null);
  const [users, setUsers] = useState([]);

  const [assessments, setAssessments] = useState([]);
  const [assessmentLoading, setAssessmentLoading] = useState(false);
  const [assessmentError, setAssessmentError] = useState("");

  const [supportTickets, setSupportTickets] = useState([]);
  const [supportTicketLoading, setSupportTicketLoading] = useState(false);
  const [supportTicketError, setSupportTicketError] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [activeMenu, setActiveMenu] = useState("dashboard");


  useEffect(() => {

    const loadDashboard = async () => {

      try {

        const token = localStorage.getItem("token");

        if (!token) {
          throw new Error("No authentication token found.");
        }

        const config = {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        };

        const dashboardResponse = await axios.get(
          `${API_URL}/admin/dashboard`,
          config
        );

        setDashboard(dashboardResponse.data);


        const usersResponse = await axios.get(
          `${API_URL}/admin/users`,
          config
        );

        setUsers(usersResponse.data.users || []);

        setAssessmentLoading(true);
        setAssessmentError("");

        try {
          const assessmentsResponse = await axios.get(
            `${API_URL}/admin/assessments`,
            config
          );

          setAssessments(
            assessmentsResponse.data.assessments || []
          );
        } catch (assessmentErr) {
          console.error(
            "Unable to load assessments:",
            assessmentErr
          );

          if (assessmentErr.response?.data?.detail) {
            setAssessmentError(
              assessmentErr.response.data.detail
            );
          } else {
            setAssessmentError(
              "Unable to load assessment monitoring data."
            );
          }
        } finally {
          setAssessmentLoading(false);
        }

        setSupportTicketLoading(true);
        setSupportTicketError("");

        try {
          const ticketResponse = await axios.get(
            `${API_URL}/support/admin/tickets`,
            config
          );

          setSupportTickets(
            Array.isArray(ticketResponse.data)
              ? ticketResponse.data
              : []
          );
        } catch (ticketErr) {
          console.error(
            "Unable to load support tickets:",
            ticketErr
          );

          if (ticketErr.response?.data?.detail) {
            setSupportTicketError(
              ticketErr.response.data.detail
            );
          } else {
            setSupportTicketError(
              "Unable to load support ticket data."
            );
          }
        } finally {
          setSupportTicketLoading(false);
        }

      } catch (err) {

        console.error(err);

        if (err.response?.status === 401) {
          setError("Your session has expired. Please login again.");
        } else if (err.response?.status === 403) {
          setError("You do not have administrator permission.");
        } else {
          setError("Unable to load administrator data.");
        }

      } finally {

        setLoading(false);

      }
    };

    loadDashboard();

  }, []);


  const totalUsers =
    dashboard?.total_users ??
    users.length ??
    0;


  return (
    <div className="min-h-screen bg-[#080808] text-white">

      {/* TOP BAR */}
      <header className="fixed left-0 right-0 top-0 z-50 border-b border-white/10 bg-[#080808]">

        <div className="flex h-16 items-center justify-between px-6">

          <div className="flex items-center gap-3">

            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-red-600 font-bold">
              S
            </div>

            <div>
              <p className="text-sm font-semibold tracking-wide">
                SOC PLATFORM
              </p>

              <p className="text-[9px] uppercase tracking-[0.2em] text-gray-600">
                Administration Console
              </p>
            </div>

          </div>


          <div className="flex items-center gap-5">

            <div className="hidden text-right sm:block">
              <p className="text-sm font-medium">
                Administrator
              </p>

              <p className="text-[10px] text-green-500">
                ● Online
              </p>
            </div>

            <button
              onClick={onLogout}
              className="border border-white/10 px-4 py-2 text-xs text-gray-400 transition hover:border-red-600 hover:text-white"
            >
              Logout
            </button>

          </div>

        </div>

      </header>


      <div className="flex pt-16">

        {/* SIDEBAR */}
        <aside className="fixed bottom-0 left-0 top-16 hidden w-64 border-r border-white/10 bg-[#0a0a0a] lg:block">

          <div className="p-5">

            <p className="mb-4 px-3 text-[10px] uppercase tracking-[0.25em] text-gray-600">
              Administration
            </p>

            <SidebarItem
              label="Dashboard"
              active={activeMenu === "dashboard"}
              onClick={() => setActiveMenu("dashboard")}
            />

            <SidebarItem
              label="User Management"
              active={activeMenu === "users"}
              onClick={() => setActiveMenu("users")}
            />

            <SidebarItem
              label="Assessment Monitoring"
              active={activeMenu === "assessments"}
              onClick={() => setActiveMenu("assessments")}
            />

            <SidebarItem
              label="Support Tickets"
              active={activeMenu === "support-tickets"}
              onClick={() => setActiveMenu("support-tickets")}
            />

            <SidebarItem
              label="VAPT Testing"
              active={activeMenu === "vapt"}
              onClick={() => setActiveMenu("vapt")}
            />

            <SidebarItem
              label="QA Testing"
              active={activeMenu === "qa"}
              onClick={() => setActiveMenu("qa")}
            />

            <SidebarItem
              label="Reports"
              active={activeMenu === "reports"}
              onClick={() => setActiveMenu("reports")}
            />

            <SidebarItem
              label="Tool Permissions"
              active={activeMenu === "tools"}
              onClick={() => setActiveMenu("tools")}
            />

            <SidebarItem
              label="Audit Trail"
              active={activeMenu === "audit"}
              onClick={() => setActiveMenu("audit")}
            />

            <SidebarItem
              label="Settings"
              active={activeMenu === "settings"}
              onClick={() => setActiveMenu("settings")}
            />

          </div>


          {/* SIDEBAR FOOTER */}
          <div className="absolute bottom-0 left-0 right-0 border-t border-white/10 p-5">

            <p className="text-[10px] uppercase tracking-wider text-gray-600">
              Platform Status
            </p>

            <div className="mt-3 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-green-500"></span>

              <span className="text-xs text-gray-400">
                All systems operational
              </span>
            </div>

          </div>

        </aside>


        {/* CONTENT */}
        <main className="w-full p-6 lg:ml-64 lg:p-10">

          {/* ERROR */}
          {error && (
            <div className="mb-6 border border-red-600/30 bg-red-600/10 px-5 py-4 text-sm text-red-400">
              {error}
            </div>
          )}


          {/* DASHBOARD */}
          {activeMenu === "dashboard" && (
            <>

              <div className="mb-8">

                <p className="text-xs uppercase tracking-[0.3em] text-red-500">
                  Overview
                </p>

                <h1 className="mt-2 text-3xl font-bold">
                  Admin Dashboard
                </h1>

                <p className="mt-2 text-sm text-gray-500">
                  Monitor and manage your security operations platform.
                </p>

              </div>


              {/* STAT CARDS */}
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">

                <AdminStat
                  title="Total Users"
                  value={loading ? "—" : totalUsers}
                  subtitle="Registered platform users"
                />

                <AdminStat
                  title="Assessments"
                  value={
                    assessmentLoading
                      ? "—"
                      : assessments.length
                  }
                  subtitle="User/Client security assessments"
                />

                <AdminStat
                  title="Security Tools"
                  value="150+"
                  subtitle="Available integrations"
                />

                <AdminStat
                  title="Platform Status"
                  value="ONLINE"
                  subtitle="All core services"
                  status
                />

              </div>


              {/* TWO COLUMN AREA */}
              <div className="mt-8 grid gap-6 xl:grid-cols-3">

                {/* ACTIVITY */}
                <div className="border border-white/10 bg-[#0d0d0d] xl:col-span-2">

                  <div className="flex items-center justify-between border-b border-white/10 px-6 py-5">

                    <div>
                      <p className="text-sm font-semibold">
                        Recent Security Activity
                      </p>

                      <p className="mt-1 text-xs text-gray-600">
                        Latest platform events
                      </p>
                    </div>

                    <span className="text-[10px] uppercase tracking-wider text-gray-600">
                      Live
                    </span>

                  </div>


                  <div className="divide-y divide-white/5">

                    <Activity
                      user="Security Analyst"
                      action="Vulnerability assessment"
                      time="Recently"
                      status="Completed"
                    />

                    <Activity
                      user="Administrator"
                      action="User management"
                      time="Recently"
                      status="Completed"
                    />

                    <Activity
                      user="Security System"
                      action="Platform monitoring"
                      time="Live"
                      status="Active"
                    />

                  </div>

                </div>


                {/* PLATFORM HEALTH */}
                <div className="border border-white/10 bg-[#0d0d0d]">

                  <div className="border-b border-white/10 px-6 py-5">

                    <p className="text-sm font-semibold">
                      Platform Health
                    </p>

                    <p className="mt-1 text-xs text-gray-600">
                      Core service status
                    </p>

                  </div>

                  <div className="space-y-5 p-6">

                    <HealthItem
                      name="FastAPI Backend"
                      status="Operational"
                    />

                    <HealthItem
                      name="PostgreSQL"
                      status="Connected"
                    />

                    <HealthItem
                      name="Authentication"
                      status="Operational"
                    />

                    <HealthItem
                      name="Security Engine"
                      status="Ready"
                    />

                  </div>

                </div>

              </div>


              {/* MANAGEMENT */}
              <div className="mt-8">

                <div className="mb-5">

                  <p className="text-xs uppercase tracking-[0.25em] text-red-500">
                    Administration
                  </p>

                  <h2 className="mt-2 text-xl font-semibold">
                    Platform Management
                  </h2>

                </div>


                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">

                  <ManagementCard
                    number="01"
                    title="User Management"
                    description="Create and manage platform users."
                    onClick={() => setActiveMenu("users")}
                  />

                  <ManagementCard
                    number="02"
                    title="Assessment Monitoring"
                    description="Monitor User/Client VAPT, QA, monitoring and report status."
                    onClick={() => setActiveMenu("assessments")}
                  />

                  <ManagementCard
                    number="03"
                    title="Support Tickets"
                    description="Review, assign and resolve User support requests."
                    onClick={() => setActiveMenu("support-tickets")}
                  />

                  <ManagementCard
                    number="04"
                    title="Tool Permissions"
                    description="Control security tool access."
                    onClick={() => setActiveMenu("tools")}
                  />

                  <ManagementCard
                    number="03"
                    title="Testing Control"
                    description="Review VAPT and QA activity."
                    onClick={() => setActiveMenu("vapt")}
                  />

                  <ManagementCard
                    number="04"
                    title="Reports"
                    description="Review generated security reports."
                    onClick={() => setActiveMenu("reports")}
                  />

                </div>

              </div>

            </>
          )}


          {/* ==================================================
              ASSESSMENT MONITORING
          ================================================== */}
          {activeMenu === "assessments" && (
            <AdminAssessmentMonitoring
              assessments={assessments}
              loading={assessmentLoading}
              error={assessmentError}
              onRefresh={async () => {
                const token = localStorage.getItem("token");

                if (!token) {
                  setAssessmentError(
                    "Your admin session has expired. Please login again."
                  );
                  return;
                }

                try {
                  setAssessmentLoading(true);
                  setAssessmentError("");

                  const response = await axios.get(
                    `${API_URL}/admin/assessments`,
                    {
                      headers: {
                        Authorization: `Bearer ${token}`,
                      },
                    }
                  );

                  setAssessments(
                    response.data.assessments || []
                  );
                } catch (err) {
                  console.error(
                    "Unable to refresh assessments:",
                    err
                  );

                  if (err.response?.data?.detail) {
                    setAssessmentError(
                      err.response.data.detail
                    );
                  } else {
                    setAssessmentError(
                      "Unable to refresh assessment monitoring."
                    );
                  }
                } finally {
                  setAssessmentLoading(false);
                }
              }}
            />
          )}

          {/* SUPPORT TICKETS */}
          {activeMenu === "support-tickets" && (
            <AdminSupportTickets
              tickets={supportTickets}
              loading={supportTicketLoading}
              error={supportTicketError}
              onRefresh={async () => {
                const token = localStorage.getItem("token");

                if (!token) {
                  setSupportTicketError(
                    "Your admin session has expired. Please login again."
                  );
                  return;
                }

                try {
                  setSupportTicketLoading(true);
                  setSupportTicketError("");

                  const response = await axios.get(
                    `${API_URL}/support/admin/tickets`,
                    {
                      headers: {
                        Authorization: `Bearer ${token}`,
                      },
                    }
                  );

                  setSupportTickets(
                    Array.isArray(response.data)
                      ? response.data
                      : []
                  );
                } catch (err) {
                  console.error(
                    "Unable to refresh support tickets:",
                    err
                  );

                  if (err.response?.data?.detail) {
                    setSupportTicketError(
                      err.response.data.detail
                    );
                  } else {
                    setSupportTicketError(
                      "Unable to refresh support tickets."
                    );
                  }
                } finally {
                  setSupportTicketLoading(false);
                }
              }}
            />
          )}

          {/* USERS */}
          {activeMenu === "users" && (
            <UserManagement
              users={users}
              onUserCreated={async () => {
                try {
                  const token = localStorage.getItem("token");

                  const response = await axios.get(
                    `${API_URL}/admin/users`,
                    {
                      headers: {
                        Authorization: `Bearer ${token}`,
                      },
                    }
                  );

                  setUsers(response.data.users || []);
                } catch (err) {
                  console.error("Unable to refresh users:", err);
                }
              }}
            />
          )}


          {/* PLACEHOLDER MODULES */}
          {activeMenu !== "dashboard" &&
            activeMenu !== "users" &&
            activeMenu !== "assessments" &&
            activeMenu !== "support-tickets" && (
              <ModulePlaceholder
                menu={activeMenu}
              />
            )}

        </main>

      </div>

    </div>
  );
}


// ==================================================
// ADMIN SUPPORT TICKETS
// ==================================================
function AdminSupportTickets({
  tickets,
  loading,
  error,
  onRefresh,
}) {
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsError, setDetailsError] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [replyLoading, setReplyLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState("");

  const [assignedTo, setAssignedTo] = useState("");
  const [assignmentChannel, setAssignmentChannel] = useState("WHATSAPP");
  const [assignmentStatus, setAssignmentStatus] = useState("NOT_ASSIGNED");
  const [contactValue, setContactValue] = useState("");
  const [adminNotes, setAdminNotes] = useState("");
  const [resolution, setResolution] = useState("");
  const [finalAdminMessage, setFinalAdminMessage] = useState("");

  const statusClass = (status) => {
    const normalized = String(status || "").toUpperCase();

    if (normalized === "RESOLVED" || normalized === "CLOSED") {
      return "text-green-500";
    }

    if (normalized === "IN_PROGRESS") {
      return "text-yellow-500";
    }

    if (normalized === "WAITING_FOR_USER") {
      return "text-blue-400";
    }

    return "text-red-400";
  };

  const priorityClass = (priority) => {
    const normalized = String(priority || "").toUpperCase();

    if (normalized === "CRITICAL") return "text-red-500";
    if (normalized === "HIGH") return "text-orange-400";
    if (normalized === "MEDIUM") return "text-yellow-500";
    return "text-gray-400";
  };

  const loadTicketDetails = async (ticketId) => {
    const token = localStorage.getItem("token");

    if (!token) {
      setDetailsError("Your admin session has expired. Please login again.");
      return;
    }

    try {
      setDetailsLoading(true);
      setDetailsError("");
      setActionMessage("");

      const response = await axios.get(
        `${API_URL}/support/admin/tickets/${ticketId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const ticket = response.data;
      setSelectedTicket(ticket);
      setAssignedTo(ticket.assigned_to || "");
      setAssignmentChannel(ticket.assignment_channel || "WHATSAPP");
      setAssignmentStatus(ticket.assignment_status || "NOT_ASSIGNED");
      setAdminNotes(ticket.admin_notes || "");
      setResolution(ticket.resolution || "");
      setFinalAdminMessage(ticket.final_admin_message || "");
    } catch (err) {
      console.error("Ticket details error:", err);

      if (err.response?.data?.detail) {
        setDetailsError(err.response.data.detail);
      } else {
        setDetailsError("Unable to load ticket details.");
      }
    } finally {
      setDetailsLoading(false);
    }
  };

  const saveTicket = async (forceStatus = null) => {
    if (!selectedTicket) return;

    const token = localStorage.getItem("token");

    if (!token) {
      setDetailsError("Your admin session has expired. Please login again.");
      return;
    }

    const targetStatus = forceStatus || selectedTicket.status;

    if (targetStatus === "RESOLVED" && !resolution.trim()) {
      setActionMessage("Enter a resolution before marking the ticket resolved.");
      return;
    }

    try {
      setSaving(true);
      setActionMessage("");

      const response = await axios.put(
        `${API_URL}/support/admin/tickets/${selectedTicket.id}`,
        {
          status: targetStatus,
          assigned_to: assignedTo.trim() || null,
          assignment_channel: assignmentChannel || null,
          assignment_status: assignmentStatus || "NOT_ASSIGNED",
          admin_notes: adminNotes,
          resolution,
          final_admin_message: finalAdminMessage,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      setSelectedTicket((prev) => ({
        ...prev,
        ...response.data,
      }));

      setActionMessage(
        targetStatus === "RESOLVED"
          ? "Ticket marked as resolved successfully."
          : "Ticket updated successfully."
      );

      await onRefresh();
      await loadTicketDetails(selectedTicket.id);
    } catch (err) {
      console.error("Ticket update error:", err);

      if (err.response?.data?.detail) {
        setActionMessage(err.response.data.detail);
      } else {
        setActionMessage("Unable to update the ticket.");
      }
    } finally {
      setSaving(false);
    }
  };

  const sendAdminMessage = async () => {
    if (!selectedTicket || !message.trim()) return;

    const token = localStorage.getItem("token");

    if (!token) {
      setDetailsError("Your admin session has expired. Please login again.");
      return;
    }

    try {
      setReplyLoading(true);
      setActionMessage("");

      await axios.post(
        `${API_URL}/support/admin/tickets/${selectedTicket.id}/messages`,
        {
          message: message.trim(),
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      setMessage("");
      setActionMessage("Admin message sent to the ticket conversation.");
      await loadTicketDetails(selectedTicket.id);
    } catch (err) {
      console.error("Admin message error:", err);

      if (err.response?.data?.detail) {
        setActionMessage(err.response.data.detail);
      } else {
        setActionMessage("Unable to send the admin message.");
      }
    } finally {
      setReplyLoading(false);
    }
  };

  const buildAssignmentText = () => {
    if (!selectedTicket) return "";

    return [
      `SOC Platform Assignment`,
      `Ticket: ${selectedTicket.ticket_id}`,
      `Category: ${selectedTicket.category}`,
      `Priority: ${selectedTicket.priority}`,
      `Subject: ${selectedTicket.subject}`,
      `Description: ${selectedTicket.description}`,
      `Assigned To: ${assignedTo || "Not specified"}`,
      `Please investigate and send the solution back to the SOC Admin.`,
    ].join("\n");
  };

  const openWhatsApp = () => {
    const digits = contactValue.replace(/\D/g, "");
    const text = encodeURIComponent(buildAssignmentText());
    const url = digits
      ? `https://wa.me/${digits}?text=${text}`
      : `https://wa.me/?text=${text}`;

    window.open(url, "_blank", "noopener,noreferrer");
  };

  const openTelegram = () => {
    const text = encodeURIComponent(buildAssignmentText());
    const url = `https://t.me/share/url?url=${encodeURIComponent(
      window.location.origin
    )}&text=${text}`;

    window.open(url, "_blank", "noopener,noreferrer");
  };

  const total = tickets.length;
  const openCount = tickets.filter(
    (ticket) => String(ticket.status).toUpperCase() === "OPEN"
  ).length;
  const inProgressCount = tickets.filter(
    (ticket) => String(ticket.status).toUpperCase() === "IN_PROGRESS"
  ).length;
  const resolvedCount = tickets.filter((ticket) =>
    ["RESOLVED", "CLOSED"].includes(
      String(ticket.status).toUpperCase()
    )
  ).length;
  const criticalCount = tickets.filter(
    (ticket) => String(ticket.priority).toUpperCase() === "CRITICAL"
  ).length;

  return (
    <div>
      <div className="flex flex-col justify-between gap-5 md:flex-row md:items-end">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            Administration
          </p>

          <h1 className="mt-2 text-3xl font-bold">
            Support Tickets
          </h1>

          <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-500">
            Review User complaints, assign work, communicate with the assigned
            person, and close resolved support requests.
          </p>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          className="border border-white/10 px-5 py-3 text-xs text-gray-400 transition hover:border-red-600 hover:text-white disabled:opacity-50"
        >
          {loading ? "Refreshing..." : "Refresh Tickets"}
        </button>
      </div>

      {(error || detailsError) && (
        <div className="mt-6 border border-red-600/30 bg-red-600/10 px-5 py-4 text-sm text-red-400">
          {error || detailsError}
        </div>
      )}

      <div className="mt-6 grid gap-4 md:grid-cols-5">
        <AdminStat
          title="Total Tickets"
          value={loading ? "—" : total}
          subtitle="All User requests"
        />

        <AdminStat
          title="Open"
          value={loading ? "—" : openCount}
          subtitle="Awaiting action"
        />

        <AdminStat
          title="In Progress"
          value={loading ? "—" : inProgressCount}
          subtitle="Currently assigned"
        />

        <AdminStat
          title="Resolved"
          value={loading ? "—" : resolvedCount}
          subtitle="Completed requests"
        />

        <AdminStat
          title="Critical"
          value={loading ? "—" : criticalCount}
          subtitle="Needs priority handling"
        />
      </div>

      <div className="mt-8 overflow-hidden border border-white/10 bg-[#0d0d0d]">
        <div className="border-b border-white/10 px-6 py-5">
          <p className="text-sm font-semibold">
            User Support Queue
          </p>

          <p className="mt-1 text-xs text-gray-600">
            Every ticket is linked to the User who raised it.
          </p>
        </div>

        {loading ? (
          <div className="px-6 py-12 text-center text-sm text-gray-600">
            Loading support tickets...
          </div>
        ) : tickets.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-gray-600">
            No support tickets have been raised yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1050px]">
              <thead>
                <tr className="border-b border-white/10 text-left">
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Ticket ID
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    User
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Subject
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Category
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Priority
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Status
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Assignment
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Action
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/5">
                {tickets.map((ticket) => (
                  <tr
                    key={ticket.id}
                    className="align-top transition hover:bg-white/[0.02]"
                  >
                    <td className="px-5 py-5">
                      <p className="text-xs font-mono font-semibold text-red-400">
                        {ticket.ticket_id}
                      </p>
                      <p className="mt-1 text-[10px] text-gray-700">
                        #{ticket.id}
                      </p>
                    </td>

                    <td className="px-5 py-5 text-sm text-gray-400">
                      User #{ticket.user_id}
                    </td>

                    <td className="max-w-[220px] px-5 py-5">
                      <p className="text-sm font-semibold text-white">
                        {ticket.subject}
                      </p>
                    </td>

                    <td className="px-5 py-5 text-xs text-gray-400">
                      {ticket.category}
                    </td>

                    <td className="px-5 py-5">
                      <span className={`text-xs font-semibold ${priorityClass(ticket.priority)}`}>
                        {ticket.priority}
                      </span>
                    </td>

                    <td className="px-5 py-5">
                      <span className={`text-xs font-semibold ${statusClass(ticket.status)}`}>
                        {ticket.status}
                      </span>
                    </td>

                    <td className="px-5 py-5 text-xs text-gray-500">
                      {ticket.assigned_to || "Not assigned"}
                    </td>

                    <td className="px-5 py-5">
                      <button
                        onClick={() => loadTicketDetails(ticket.id)}
                        className="border border-white/10 px-3 py-2 text-xs text-gray-400 transition hover:border-red-600 hover:text-white"
                      >
                        View / Manage
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {(detailsLoading || selectedTicket) && (
        <div className="mt-6 border border-white/10 bg-[#0d0d0d]">
          <div className="flex items-center justify-between border-b border-white/10 px-6 py-5">
            <div>
              <p className="text-sm font-semibold">
                Ticket Management
              </p>
              <p className="mt-1 text-xs text-gray-600">
                Assign the ticket, coordinate through WhatsApp/Telegram, and
                record the solution.
              </p>
            </div>

            <button
              onClick={() => {
                setSelectedTicket(null);
                setDetailsError("");
                setActionMessage("");
              }}
              className="text-sm text-gray-600 hover:text-white"
            >
              ✕
            </button>
          </div>

          {detailsLoading ? (
            <div className="px-6 py-10 text-sm text-gray-600">
              Loading ticket details...
            </div>
          ) : selectedTicket ? (
            <div className="p-6">
              <div className="grid gap-4 md:grid-cols-4">
                <QAVKPI label="Ticket ID" value={selectedTicket.ticket_id} />
                <QAVKPI label="User ID" value={selectedTicket.user_id} />
                <QAVKPI label="Status" value={selectedTicket.status} />
                <QAVKPI label="Priority" value={selectedTicket.priority} />
              </div>

              <div className="mt-5 border border-white/10 bg-[#080808] p-5">
                <p className="text-[10px] uppercase tracking-wider text-gray-600">
                  User Request
                </p>

                <p className="mt-2 text-lg font-semibold text-white">
                  {selectedTicket.subject}
                </p>

                <p className="mt-2 text-xs text-red-400">
                  {selectedTicket.category}
                </p>

                <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-gray-400">
                  {selectedTicket.description}
                </p>
              </div>

              <div className="mt-5 border border-white/10 bg-[#080808] p-5">
                <p className="text-[10px] uppercase tracking-wider text-gray-600">
                  Assignment
                </p>

                <div className="mt-4 grid gap-5 md:grid-cols-2">
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-gray-600">
                      Assigned Person
                    </label>
                    <input
                      value={assignedTo}
                      onChange={(e) => setAssignedTo(e.target.value)}
                      placeholder="Name / team member"
                      className="mt-2 w-full border border-white/10 bg-[#0d0d0d] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-gray-600">
                      Assignment Status
                    </label>
                    <select
                      value={assignmentStatus}
                      onChange={(e) => setAssignmentStatus(e.target.value)}
                      className="mt-2 w-full border border-white/10 bg-[#0d0d0d] px-4 py-3 text-sm text-gray-300 outline-none focus:border-red-600"
                    >
                      <option value="NOT_ASSIGNED">Not Assigned</option>
                      <option value="ASSIGNED">Assigned</option>
                      <option value="WORKING">Working</option>
                      <option value="COMPLETED">Completed</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-gray-600">
                      Channel
                    </label>
                    <select
                      value={assignmentChannel}
                      onChange={(e) => setAssignmentChannel(e.target.value)}
                      className="mt-2 w-full border border-white/10 bg-[#0d0d0d] px-4 py-3 text-sm text-gray-300 outline-none focus:border-red-600"
                    >
                      <option value="WHATSAPP">WhatsApp</option>
                      <option value="TELEGRAM">Telegram</option>
                      <option value="OTHER">Other</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-gray-600">
                      Contact / Phone / Username
                    </label>
                    <input
                      value={contactValue}
                      onChange={(e) => setContactValue(e.target.value)}
                      placeholder="Optional contact value"
                      className="mt-2 w-full border border-white/10 bg-[#0d0d0d] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                    />
                  </div>
                </div>

                <div className="mt-5 flex flex-wrap gap-3">
                  <button
                    onClick={openWhatsApp}
                    type="button"
                    className="bg-green-600/80 px-4 py-3 text-xs font-semibold transition hover:bg-green-600"
                  >
                    Open WhatsApp Assignment
                  </button>

                  <button
                    onClick={openTelegram}
                    type="button"
                    className="bg-blue-600/80 px-4 py-3 text-xs font-semibold transition hover:bg-blue-600"
                  >
                    Open Telegram Assignment
                  </button>

                  <button
                    onClick={() => saveTicket()}
                    disabled={saving}
                    type="button"
                    className="bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:opacity-50"
                  >
                    {saving ? "Saving..." : "Save Assignment"}
                  </button>
                </div>
              </div>

              <div className="mt-5 grid gap-5 md:grid-cols-3">
                <div>
                  <label className="text-[10px] uppercase tracking-wider text-gray-600">
                    Admin Notes
                  </label>
                  <textarea
                    value={adminNotes}
                    onChange={(e) => setAdminNotes(e.target.value)}
                    placeholder="Internal admin notes..."
                    className="mt-2 min-h-[140px] w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                  />
                </div>

                <div>
                  <label className="text-[10px] uppercase tracking-wider text-gray-600">
                    Resolution
                  </label>
                  <textarea
                    value={resolution}
                    onChange={(e) => setResolution(e.target.value)}
                    placeholder="Solution returned by the assigned person..."
                    className="mt-2 min-h-[140px] w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                  />
                </div>

                <div>
                  <label className="text-[10px] uppercase tracking-wider text-gray-600">
                    Final Message to User
                  </label>
                  <textarea
                    value={finalAdminMessage}
                    onChange={(e) => setFinalAdminMessage(e.target.value)}
                    placeholder="Message the User will see after resolution..."
                    className="mt-2 min-h-[140px] w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                  />
                </div>
              </div>

              <div className="mt-5 flex flex-wrap gap-3">
                <button
                  onClick={() => saveTicket("IN_PROGRESS")}
                  disabled={saving}
                  type="button"
                  className="border border-yellow-500/30 px-5 py-3 text-xs text-yellow-500 transition hover:border-yellow-500 hover:text-white disabled:opacity-50"
                >
                  Mark In Progress
                </button>

                <button
                  onClick={() => saveTicket("WAITING_FOR_USER")}
                  disabled={saving}
                  type="button"
                  className="border border-blue-500/30 px-5 py-3 text-xs text-blue-400 transition hover:border-blue-500 hover:text-white disabled:opacity-50"
                >
                  Waiting for User
                </button>

                <button
                  onClick={() => saveTicket("RESOLVED")}
                  disabled={saving}
                  type="button"
                  className="bg-green-600 px-5 py-3 text-xs font-semibold transition hover:bg-green-500 disabled:opacity-50"
                >
                  Mark Resolved
                </button>
              </div>

              {actionMessage && (
                <div className="mt-5 border border-white/10 bg-[#080808] px-4 py-3 text-sm text-gray-400">
                  {actionMessage}
                </div>
              )}

              <div className="mt-6 border border-white/10 bg-[#080808] p-5">
                <p className="text-[10px] uppercase tracking-wider text-gray-600">
                  Conversation
                </p>

                <div className="mt-4 space-y-3">
                  {Array.isArray(selectedTicket.messages) &&
                  selectedTicket.messages.length > 0 ? (
                    selectedTicket.messages.map((item) => (
                      <div
                        key={item.id}
                        className={`border p-4 ${
                          item.sender_type === "ADMIN"
                            ? "border-red-600/20 bg-red-600/5"
                            : "border-white/10 bg-[#0d0d0d]"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-xs font-semibold text-white">
                            {item.sender_name} · {item.sender_type}
                          </p>
                          <p className="text-[10px] text-gray-700">
                            {item.created_at
                              ? new Date(item.created_at).toLocaleString()
                              : "—"}
                          </p>
                        </div>
                        <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-400">
                          {item.message}
                        </p>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-gray-600">
                      No messages yet.
                    </p>
                  )}
                </div>

                <div className="mt-5">
                  <label className="text-[10px] uppercase tracking-wider text-gray-600">
                    Admin Message
                  </label>
                  <textarea
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder="Send an update to the User..."
                    className="mt-2 min-h-[120px] w-full border border-white/10 bg-[#0d0d0d] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                  />

                  <button
                    onClick={sendAdminMessage}
                    disabled={replyLoading || !message.trim()}
                    type="button"
                    className="mt-3 bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {replyLoading ? "Sending..." : "Send Admin Message"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}


// ==================================================
// ADMIN ASSESSMENT MONITORING
// ==================================================

function AdminAssessmentMonitoring({
  assessments,
  loading,
  error,
  onRefresh,
}) {
  const [selectedAssessment, setSelectedAssessment] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsError, setDetailsError] = useState("");

  const viewDetails = async (assessmentId) => {
    const token = localStorage.getItem("token");

    if (!token) {
      setDetailsError(
        "Your admin session has expired. Please login again."
      );
      return;
    }

    try {
      setDetailsLoading(true);
      setDetailsError("");
      setSelectedAssessment(null);

      const response = await axios.get(
        `${API_URL}/admin/assessments/${assessmentId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setSelectedAssessment(response.data);
    } catch (err) {
      console.error("Assessment details error:", err);

      if (err.response?.data?.detail) {
        setDetailsError(err.response.data.detail);
      } else {
        setDetailsError(
          "Unable to load assessment details."
        );
      }
    } finally {
      setDetailsLoading(false);
    }
  };

  const statusClass = (status) => {
    const normalized = String(
      status || ""
    ).toLowerCase();

    if (
      normalized === "completed" ||
      normalized === "active" ||
      normalized === "generated" ||
      normalized === "pass"
    ) {
      return "text-green-500";
    }

    if (
      normalized === "failed" ||
      normalized === "error" ||
      normalized === "regression_detected"
    ) {
      return "text-red-400";
    }

    return "text-yellow-500";
  };

  return (
    <div>
      <div className="flex flex-col justify-between gap-5 md:flex-row md:items-end">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            Administration
          </p>

          <h1 className="mt-2 text-3xl font-bold">
            Assessment Monitoring
          </h1>

          <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-500">
            Monitor security assessments created by Users. User and Client
            are treated as the same application actor.
          </p>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          className="border border-white/10 px-5 py-3 text-xs text-gray-400 transition hover:border-red-600 hover:text-white disabled:opacity-50"
        >
          {loading ? "Refreshing..." : "Refresh Assessments"}
        </button>
      </div>

      {error && (
        <div className="mt-6 border border-red-600/30 bg-red-600/10 px-5 py-4">
          <p className="text-sm text-red-400">
            {error}
          </p>
        </div>
      )}

      <div className="mt-6 grid gap-4 md:grid-cols-4">
        <AdminStat
          title="Total Assessments"
          value={loading ? "—" : assessments.length}
          subtitle="User-owned assessments"
        />

        <AdminStat
          title="VAPT Completed"
          value={
            loading
              ? "—"
              : assessments.filter(
                  (item) =>
                    item.vapt_status === "completed"
                ).length
          }
          subtitle="Completed VAPT scans"
        />

        <AdminStat
          title="QA Completed"
          value={
            loading
              ? "—"
              : assessments.filter(
                  (item) =>
                    item.qa_status === "completed"
                ).length
          }
          subtitle="Completed QA workflows"
        />

        <AdminStat
          title="Monitoring Active"
          value={
            loading
              ? "—"
              : assessments.filter(
                  (item) =>
                    item.monitoring_status === "active"
                ).length
          }
          subtitle="Active monitoring"
        />
      </div>

      <div className="mt-8 overflow-hidden border border-white/10 bg-[#0d0d0d]">
        <div className="border-b border-white/10 px-6 py-5">
          <p className="text-sm font-semibold">
            User Assessments
          </p>

          <p className="mt-1 text-xs text-gray-600">
            Admin monitoring only — VAPT is performed from the User workspace.
          </p>
        </div>

        {loading ? (
          <div className="px-6 py-12 text-center text-sm text-gray-600">
            Loading assessments...
          </div>
        ) : assessments.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-gray-600">
            No assessments have been created yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1100px]">
              <thead>
                <tr className="border-b border-white/10 text-left">
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    User
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Target
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    VAPT
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Findings
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    QA
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Monitoring
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Report
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Overall
                  </th>
                  <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                    Action
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/5">
                {assessments.map((assessment) => (
                  <tr
                    key={assessment.id}
                    className="align-top transition hover:bg-white/[0.02]"
                  >
                    <td className="px-5 py-5">
                      <p className="text-sm font-medium text-white">
                        {assessment.user?.username || "Unknown"}
                      </p>

                      <p className="mt-1 text-xs text-gray-600">
                        {assessment.user?.email || "—"}
                      </p>
                    </td>

                    <td className="max-w-[260px] px-5 py-5">
                      <p className="break-all text-xs font-mono text-gray-400">
                        {assessment.target}
                      </p>
                    </td>

                    <td className="px-5 py-5">
                      <span
                        className={`text-xs font-semibold ${statusClass(
                          assessment.vapt_status
                        )}`}
                      >
                        {assessment.vapt_status}
                      </span>
                    </td>

                    <td className="px-5 py-5 text-sm text-gray-300">
                      {assessment.vapt_findings_count ?? 0}
                    </td>

                    <td className="px-5 py-5">
                      <span
                        className={`text-xs font-semibold ${statusClass(
                          assessment.qa_status
                        )}`}
                      >
                        {assessment.qa_status}
                      </span>

                      {assessment.qa_score != null && (
                        <p className="mt-1 text-xs text-gray-600">
                          Score: {assessment.qa_score}%
                        </p>
                      )}
                    </td>

                    <td className="px-5 py-5">
                      <span
                        className={`text-xs font-semibold ${statusClass(
                          assessment.monitoring_status
                        )}`}
                      >
                        {assessment.monitoring_status}
                      </span>
                    </td>

                    <td className="px-5 py-5">
                      <span
                        className={`text-xs font-semibold ${statusClass(
                          assessment.report_status
                        )}`}
                      >
                        {assessment.report_status}
                      </span>
                    </td>

                    <td className="px-5 py-5">
                      <span
                        className={`text-xs font-semibold ${statusClass(
                          assessment.overall_status
                        )}`}
                      >
                        {assessment.overall_status}
                      </span>
                    </td>

                    <td className="px-5 py-5">
                      <button
                        onClick={() =>
                          viewDetails(assessment.id)
                        }
                        className="border border-white/10 px-3 py-2 text-xs text-gray-400 transition hover:border-red-600 hover:text-white"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {(detailsLoading || detailsError || selectedAssessment) && (
        <div className="mt-6 border border-white/10 bg-[#0d0d0d]">
          <div className="flex items-center justify-between border-b border-white/10 px-6 py-5">
            <div>
              <p className="text-sm font-semibold">
                Assessment Details
              </p>

              <p className="mt-1 text-xs text-gray-600">
                Detailed view of the selected User assessment.
              </p>
            </div>

            <button
              onClick={() => {
                setSelectedAssessment(null);
                setDetailsError("");
              }}
              className="text-sm text-gray-600 hover:text-white"
            >
              ✕
            </button>
          </div>

          {detailsLoading && (
            <div className="px-6 py-10 text-sm text-gray-600">
              Loading assessment details...
            </div>
          )}

          {detailsError && (
            <div className="px-6 py-5 text-sm text-red-400">
              {detailsError}
            </div>
          )}

          {selectedAssessment && !detailsLoading && (
            <div className="p-6">
              <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
                <QAVKPI
                  label="User"
                  value={
                    selectedAssessment.user?.username ||
                    "Unknown"
                  }
                />

                <QAVKPI
                  label="Target"
                  value={selectedAssessment.target}
                />

                <QAVKPI
                  label="Overall"
                  value={
                    selectedAssessment.overall_status
                  }
                />

                <QAVKPI
                  label="Report"
                  value={
                    selectedAssessment.report?.status ||
                    "—"
                  }
                />
              </div>

              <div className="mt-6 grid gap-4 md:grid-cols-3">
                <div className="border border-white/10 bg-[#080808] p-5">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    VAPT
                  </p>

                  <p
                    className={`mt-2 text-sm font-semibold ${statusClass(
                      selectedAssessment.vapt?.status
                    )}`}
                  >
                    {selectedAssessment.vapt?.status || "—"}
                  </p>

                  <p className="mt-2 text-xs text-gray-600">
                    Findings:{" "}
                    {selectedAssessment.vapt?.findings_count ?? 0}
                  </p>
                </div>

                <div className="border border-white/10 bg-[#080808] p-5">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    QA
                  </p>

                  <p
                    className={`mt-2 text-sm font-semibold ${statusClass(
                      selectedAssessment.qa?.status
                    )}`}
                  >
                    {selectedAssessment.qa?.status || "—"}
                  </p>

                  <p className="mt-2 text-xs text-gray-600">
                    Score:{" "}
                    {selectedAssessment.qa?.score ?? "—"}
                  </p>
                </div>

                <div className="border border-white/10 bg-[#080808] p-5">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    Live Monitoring
                  </p>

                  <p
                    className={`mt-2 text-sm font-semibold ${statusClass(
                      selectedAssessment.monitoring?.status
                    )}`}
                  >
                    {selectedAssessment.monitoring?.status || "—"}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}


// ==================================================
// USER MANAGEMENT
// ==================================================
function UserManagement({ users, onUserCreated }) {
  const [showCreateUser, setShowCreateUser] = useState(false);

  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const filteredUsers = users.filter((user) => {
    const query = search.toLowerCase().trim();

    const matchesSearch =
      !query ||
      String(user.username || "").toLowerCase().includes(query) ||
      String(user.email || "").toLowerCase().includes(query);

    const matchesRole =
      roleFilter === "all" ||
      String(user.role_id) === roleFilter;

    return matchesSearch && matchesRole;
  });

  const getRoleLabel = (roleId) => {
    const roles = {
      1: "Client",
      2: "Analyst",
      3: "Admin",
    };

    return roles[roleId] || `Role ${roleId}`;
  };

  const getUserStatus = (user) => {
    if (
      user.is_active === false ||
      user.status === "inactive" ||
      user.status === "disabled"
    ) {
      return "Inactive";
    }

    return "Active";
  };

  const resetCreateForm = () => {
    setUsername("");
    setEmail("");
    setPassword("");
    setError("");
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();

    setError("");
    setSuccess("");

    if (!username.trim()) {
      setError("Username is required.");
      return;
    }

    if (!email.trim()) {
      setError("Email is required.");
      return;
    }

    if (!password) {
      setError("Password is required.");
      return;
    }

    if (password.length < 6) {
      setError("Password should contain at least 6 characters.");
      return;
    }

    const token = localStorage.getItem("token");

    if (!token) {
      setError("Your admin session has expired. Please login again.");
      return;
    }

    try {
      setLoading(true);

      await axios.post(
        `${API_URL}/admin/users`,
        {
          username: username.trim(),
          email: email.trim(),
          password,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      setSuccess("User created successfully.");
      setShowCreateUser(false);
      resetCreateForm();

      if (onUserCreated) {
        await onUserCreated();
      }
    } catch (err) {
      console.error("Create user error:", err);

      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to create the user.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {/* HEADER */}
      <div className="flex flex-col justify-between gap-5 md:flex-row md:items-end">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            Administration
          </p>

          <h1 className="mt-2 text-3xl font-bold">
            User Management
          </h1>

          <p className="mt-2 max-w-2xl text-sm text-gray-500">
            Create, search and monitor users who have access to the SOC Platform.
          </p>
        </div>

        <button
          onClick={() => {
            setShowCreateUser(true);
            setError("");
            setSuccess("");
          }}
          className="flex items-center justify-center gap-2 bg-red-600 px-5 py-3 text-sm font-semibold transition hover:bg-red-700"
        >
          <span className="text-lg leading-none">+</span>
          Create User
        </button>
      </div>

      {/* SUCCESS */}
      {success && (
        <div className="mt-6 border border-green-600/20 bg-green-600/5 px-5 py-4">
          <p className="text-sm text-green-400">
            {success}
          </p>
        </div>
      )}

      {/* CREATE USER PANEL */}
      {showCreateUser && (
        <div className="mt-6 border border-white/10 bg-[#0d0d0d]">
          <div className="flex items-center justify-between border-b border-white/10 px-6 py-5">
            <div>
              <p className="text-sm font-semibold">
                Create New User
              </p>

              <p className="mt-1 text-xs text-gray-600">
                Create a real User/Client account through the authenticated backend.
              </p>
            </div>

            <button
              onClick={() => {
                setShowCreateUser(false);
                resetCreateForm();
              }}
              className="text-sm text-gray-500 transition hover:text-white"
              aria-label="Close create user form"
            >
              ✕
            </button>
          </div>

          <form
            onSubmit={handleCreateUser}
            className="grid gap-5 p-6 md:grid-cols-2"
          >
            <div>
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Username
              </label>

              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                disabled={loading}
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600 disabled:opacity-50"
              />
            </div>

            <div>
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Email
              </label>

              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@example.com"
                disabled={loading}
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600 disabled:opacity-50"
              />
            </div>

            <div>
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Temporary Password
              </label>

              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter temporary password"
                disabled={loading}
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600 disabled:opacity-50"
              />
            </div>

            <div>
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Account Type
              </label>

              <div className="mt-2 border border-white/10 bg-[#080808] px-4 py-3 text-sm text-gray-400">
                Client / User
              </div>

              <p className="mt-2 text-[11px] text-gray-700">
                Clients and users are treated as the same platform account.
              </p>
            </div>

            {error && (
              <div className="border border-red-600/20 bg-red-600/5 px-4 py-3 md:col-span-2">
                <p className="text-sm text-red-400">
                  {error}
                </p>
              </div>
            )}

            <div className="flex gap-3 md:col-span-2">
              <button
                type="submit"
                disabled={loading}
                className="bg-red-600 px-6 py-3 text-sm font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? "Creating User..." : "Create User"}
              </button>

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  setShowCreateUser(false);
                  resetCreateForm();
                }}
                className="border border-white/10 px-6 py-3 text-sm text-gray-400 transition hover:border-white/30 hover:text-white"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* SEARCH + FILTER */}
      <div className="mt-8 flex flex-col gap-4 md:flex-row">
        <div className="flex-1">
          <label className="text-[10px] uppercase tracking-wider text-gray-600">
            Search Users
          </label>

          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by username or email..."
            className="mt-2 w-full border border-white/10 bg-[#0d0d0d] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
          />
        </div>

        <div className="md:w-56">
          <label className="text-[10px] uppercase tracking-wider text-gray-600">
            Role
          </label>

          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="mt-2 w-full border border-white/10 bg-[#0d0d0d] px-4 py-3 text-sm text-gray-400 outline-none focus:border-red-600"
          >
            <option value="all">All Roles</option>
            <option value="1">Client</option>
            <option value="2">Analyst</option>
            <option value="3">Admin</option>
          </select>
        </div>
      </div>

      {/* USER TABLE */}
      <div className="mt-6 overflow-hidden border border-white/10 bg-[#0d0d0d]">
        <div className="flex items-center justify-between border-b border-white/10 px-6 py-5">
          <div>
            <p className="text-sm font-semibold">
              Registered Users
            </p>

            <p className="mt-1 text-xs text-gray-600">
              Showing {filteredUsers.length} of {users.length} users
            </p>
          </div>

          <div className="border border-white/10 px-3 py-2 text-xs text-gray-500">
            {users.length} Total
          </div>
        </div>

        {filteredUsers.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <p className="text-sm text-gray-500">
              No users match your search.
            </p>

            <button
              onClick={() => {
                setSearch("");
                setRoleFilter("all");
              }}
              className="mt-3 text-xs text-red-500 hover:text-red-400"
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="border-b border-white/10 bg-[#0a0a0a] text-[10px] uppercase tracking-wider text-gray-600">
                <tr>
                  <th className="px-6 py-4">ID</th>
                  <th className="px-6 py-4">User</th>
                  <th className="px-6 py-4">Email</th>
                  <th className="px-6 py-4">Role</th>
                  <th className="px-6 py-4">Client ID</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Access</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/5">
                {filteredUsers.map((user) => {
                  const status = getUserStatus(user);

                  return (
                    <tr
                      key={user.id}
                      className="transition hover:bg-white/[0.02]"
                    >
                      <td className="px-6 py-5 text-gray-600">
                        #{user.id}
                      </td>

                      <td className="px-6 py-5">
                        <p className="font-medium text-white">
                          {user.username || "—"}
                        </p>
                      </td>

                      <td className="px-6 py-5 text-gray-400">
                        {user.email || "—"}
                      </td>

                      <td className="px-6 py-5">
                        <span
                          className={`px-2 py-1 text-xs ${
                            user.role_id === 3
                              ? "bg-red-600/10 text-red-400"
                              : user.role_id === 2
                              ? "bg-yellow-600/10 text-yellow-400"
                              : "bg-white/5 text-gray-400"
                          }`}
                        >
                          {getRoleLabel(user.role_id)}
                        </span>
                      </td>

                      <td className="px-6 py-5 text-gray-500">
                        {user.client_id ?? "—"}
                      </td>

                      <td className="px-6 py-5">
                        <span className="flex items-center gap-2 text-xs">
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              status === "Active"
                                ? "bg-green-500"
                                : "bg-red-500"
                            }`}
                          />

                          <span
                            className={
                              status === "Active"
                                ? "text-green-500"
                                : "text-red-400"
                            }
                          >
                            {status}
                          </span>
                        </span>
                      </td>

                      <td className="px-6 py-5">
                        {user.role_id === 1 && (
                          <span className="text-xs text-green-500">
                            User Portal
                          </span>
                        )}

                        {user.role_id === 2 && (
                          <span className="text-xs text-yellow-500">
                            Analyst
                          </span>
                        )}

                        {user.role_id === 3 && (
                          <span className="text-xs text-red-400">
                            Admin
                          </span>
                        )}

                        {!user.role_id && (
                          <span className="text-xs text-gray-600">
                            Unknown
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mt-5 border border-white/10 bg-[#0a0a0a] px-5 py-4">
        <p className="text-xs leading-6 text-gray-600">
          User accounts are managed through the authenticated SOC Platform
          backend. Server-side authorization remains the source of truth for
          account access and permissions.
        </p>
      </div>
    </div>
  );
}


// ==================================================
// SIDEBAR ITEM
// ==================================================
function SidebarItem({
  label,
  active,
  onClick,
}) {

  return (
    <button
      onClick={onClick}
      className={`mb-1 flex w-full items-center border-l-2 px-3 py-3 text-left text-sm transition ${
        active
          ? "border-red-600 bg-red-600/10 text-white"
          : "border-transparent text-gray-500 hover:bg-white/[0.03] hover:text-white"
      }`}
    >
      {label}
    </button>
  );
}


// ==================================================
// ADMIN STAT
// ==================================================
function AdminStat({
  title,
  value,
  subtitle,
  status,
}) {

  return (
    <div className="border border-white/10 bg-[#0d0d0d] p-5">

      <div className="flex items-center justify-between">

        <p className="text-xs uppercase tracking-wider text-gray-600">
          {title}
        </p>

        {status && (
          <span className="h-2 w-2 rounded-full bg-green-500"></span>
        )}

      </div>

      <p className="mt-5 text-3xl font-bold">
        {value}
      </p>

      <p className="mt-2 text-xs text-gray-600">
        {subtitle}
      </p>

    </div>
  );
}


// ==================================================
// ACTIVITY
// ==================================================
function Activity({
  user,
  action,
  time,
  status,
}) {

  return (
    <div className="flex items-center justify-between px-6 py-4">

      <div className="flex items-center gap-4">

        <div className="flex h-9 w-9 items-center justify-center bg-red-600/10 text-xs text-red-500">
          S
        </div>

        <div>

          <p className="text-sm font-medium">
            {action}
          </p>

          <p className="mt-1 text-xs text-gray-600">
            {user} • {time}
          </p>

        </div>

      </div>

      <span className="text-[10px] uppercase tracking-wider text-green-500">
        {status}
      </span>

    </div>
  );
}


// ==================================================
// HEALTH ITEM
// ==================================================
function HealthItem({
  name,
  status,
}) {

  return (
    <div className="flex items-center justify-between">

      <span className="text-sm text-gray-400">
        {name}
      </span>

      <span className="flex items-center gap-2 text-xs text-green-500">

        <span className="h-1.5 w-1.5 rounded-full bg-green-500"></span>

        {status}

      </span>

    </div>
  );
}


// ==================================================
// MANAGEMENT CARD
// ==================================================
function ManagementCard({
  number,
  title,
  description,
  onClick,
}) {

  return (
    <button
      onClick={onClick}
      className="group border border-white/10 bg-[#0d0d0d] p-6 text-left transition hover:border-red-600/50 hover:bg-[#111111]"
    >

      <div className="flex items-center justify-between">

        <span className="text-xs text-red-500">
          {number}
        </span>

        <span className="text-gray-700 transition group-hover:text-red-500">
          ↗
        </span>

      </div>

      <h3 className="mt-8 text-base font-semibold">
        {title}
      </h3>

      <p className="mt-2 text-sm leading-6 text-gray-600">
        {description}
      </p>

    </button>
  );
}


// ==================================================
// MODULE PLACEHOLDER
// ==================================================
function ModulePlaceholder({ menu }) {

  const titles = {
    vapt: "VAPT Testing",
    qa: "QA Testing",
    reports: "Reports",
    tools: "Tool Permissions",
    audit: "Audit Trail",
    settings: "Settings",
  };

  return (
    <div>

      <p className="text-xs uppercase tracking-[0.3em] text-red-500">
        Administration
      </p>

      <h1 className="mt-2 text-3xl font-bold">
        {titles[menu] || "Module"}
      </h1>

      <div className="mt-8 border border-white/10 bg-[#0d0d0d] p-10 text-center">

        <div className="mx-auto flex h-14 w-14 items-center justify-center bg-red-600/10 text-xl text-red-500">
          {menu === "vapt"
            ? "V"
            : menu === "qa"
            ? "Q"
            : menu === "reports"
            ? "R"
            : menu === "tools"
            ? "T"
            : menu === "audit"
            ? "A"
            : "S"}
        </div>

        <h2 className="mt-5 text-xl font-semibold">
          {titles[menu]}
        </h2>

        <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-gray-600">
          This module will be implemented in the next development step.
        </p>

      </div>

    </div>
  );
}


// ==================================================
// STAT
// ==================================================
function Stat({
  number,
  label,
}) {

  return (
    <div>

      <p className="text-2xl font-semibold">
        {number}
      </p>

      <p className="mt-1 text-xs uppercase tracking-wider text-gray-500">
        {label}
      </p>

    </div>
  );
}


// ==================================================
// SECURITY ITEM
// ==================================================
function SecurityItem({
  number,
  title,
  description,
  status,
}) {

  return (
    <div className="flex items-center justify-between border border-white/10 p-4 transition hover:border-red-600/40">

      <div className="flex items-center gap-4">

        <div className="flex h-9 w-9 items-center justify-center border border-red-600/40 bg-red-600/10 text-xs text-red-500">
          {number}
        </div>

        <div>

          <p className="text-sm font-medium">
            {title}
          </p>

          <p className="mt-1 text-xs text-gray-500">
            {description}
          </p>

        </div>

      </div>

      <span className="text-[10px] tracking-wider text-green-500">
        {status}
      </span>

    </div>
  );
}


// ==================================================
// CAPABILITY
// ==================================================
function Capability({
  number,
  title,
  description,
}) {

  return (
    <div className="bg-[#0d0d0d] p-6 transition hover:bg-[#121212]">

      <div className="flex items-center justify-between">

        <span className="text-xs text-red-500">
          {number}
        </span>

        <span className="text-gray-600">
          ↗
        </span>

      </div>

      <h3 className="mt-8 text-base font-semibold">
        {title}
      </h3>

      <p className="mt-2 text-sm leading-6 text-gray-500">
        {description}
      </p>

    </div>
  );
}


// ==================================================
// USER LOGIN
// ==================================================
function UserLogin({ onBack, onSuccess }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (!email || !password) {
      setError("Please enter your email and password.");
      return;
    }

    try {
      setLoading(true);

      const response = await axios.post(`${API_URL}/auth/login`, {
        email,
        password,
      });

      const token = response.data.access_token;

      localStorage.setItem("token", token);

      const meResponse = await axios.get(`${API_URL}/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      // Client role = 1
      if (meResponse.data.role_id !== 1) {
        localStorage.removeItem("token");
        setError("This account does not have User/Client access.");
        return;
      }

      // Start each authenticated user session without inheriting a previous
      // user's VAPT target. A target is created only after a successful scan.
      localStorage.removeItem("active_vapt_target");
      localStorage.removeItem("active_vapt_target_meta");

      onSuccess();
    } catch (err) {
      console.error(err);

      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to connect to the SOC Platform API.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#080808] text-white">
      <div className="mx-auto flex min-h-screen max-w-6xl items-center px-6">
        <div className="grid w-full gap-16 lg:grid-cols-2">

          {/* LEFT */}
          <div className="hidden lg:flex lg:flex-col lg:justify-center">
            <div className="mb-6 flex items-center gap-3">
              <span className="h-px w-10 bg-red-600"></span>
              <span className="text-xs uppercase tracking-[0.3em] text-red-500">
                Secure User Access
              </span>
            </div>

            <h1 className="text-5xl font-bold leading-tight">
              Access your
              <br />
              <span className="text-red-600">security workspace.</span>
            </h1>

            <p className="mt-6 max-w-lg leading-7 text-gray-500">
              Sign in to monitor security activity, review findings,
              access reports and communicate with your security team.
            </p>
          </div>

          {/* FORM */}
          <div className="flex items-center">
            <div className="w-full max-w-md">

              <button
                onClick={onBack}
                className="mb-8 text-sm text-gray-500 transition hover:text-white"
              >
                ← Back to Home
              </button>

              <div className="mb-8">
                <div className="mb-5 flex h-10 w-10 items-center justify-center rounded-md bg-red-600 font-bold">
                  S
                </div>

                <p className="text-xs uppercase tracking-[0.3em] text-red-500">
                  SOC PLATFORM
                </p>

                <h2 className="mt-3 text-3xl font-bold">
                  User Login
                </h2>

                <p className="mt-2 text-sm text-gray-500">
                  Sign in to access your security dashboard.
                </p>
              </div>

              <form
                onSubmit={handleSubmit}
                className="border border-white/10 bg-[#0d0d0d] p-7"
              >
                <label className="text-xs uppercase tracking-wider text-gray-500">
                  Email
                </label>

                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="user@example.com"
                  className="mt-2 mb-5 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                />

                <label className="text-xs uppercase tracking-wider text-gray-500">
                  Password
                </label>

                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                />

                {error && (
                  <div className="mt-5 border border-red-600/30 bg-red-600/10 px-4 py-3 text-sm text-red-400">
                    {error}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="mt-6 w-full bg-red-600 py-3.5 text-sm font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {loading ? "Signing In..." : "Sign In"}
                </button>
              </form>

              <p className="mt-5 text-center text-xs text-gray-600">
                Authorized user access only
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


// ==================================================
// USER DASHBOARD
// ==================================================
function UserDashboard({ onLogout }) {
  const [user, setUser] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeMenu, setActiveMenu] = useState("dashboard");

  useEffect(() => {
    const loadUserDashboard = async () => {
      try {
        const token = localStorage.getItem("token");

        if (!token) {
          throw new Error("No authentication token found.");
        }

        const config = {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        };

        const meResponse = await axios.get(`${API_URL}/auth/me`, config);

        if (meResponse.data.role_id !== 1) {
          localStorage.removeItem("token");
          setError("You do not have user/client access.");
          return;
        }

        setUser(meResponse.data);

        const dashboardResponse = await axios.get(
          `${API_URL}/client/dashboard`,
          config
        );

        setDashboard(dashboardResponse.data);
      } catch (err) {
        console.error(err);

        if (err.response?.status === 401) {
          setError("Your session has expired. Please login again.");
        } else if (err.response?.status === 403) {
          setError("You do not have permission to access this dashboard.");
        } else {
          setError("Unable to load user dashboard.");
        }
      } finally {
        setLoading(false);
      }
    };

    loadUserDashboard();
  }, []);

  const displayUsername = user?.username || dashboard?.username || "User";
  const displayEmail = user?.email || dashboard?.email || "—";
  const organization = dashboard?.organization || dashboard?.client?.organization || "Not assigned";
  const clientName = dashboard?.client_name || dashboard?.client?.name || "Client Account";

  return (
    <div className="min-h-screen bg-[#080808] text-white">

      {/* TOP BAR */}
      <header className="fixed left-0 right-0 top-0 z-50 border-b border-white/10 bg-[#080808]">
        <div className="flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-red-600 font-bold">
              S
            </div>

            <div>
              <p className="text-sm font-semibold tracking-wide">
                SOC PLATFORM
              </p>
              <p className="text-[9px] uppercase tracking-[0.2em] text-gray-600">
                Security Workspace
              </p>
            </div>
          </div>

          <div className="flex items-center gap-5">
            <div className="hidden text-right sm:block">
              <p className="text-sm font-medium">
                {displayUsername}
              </p>
              <p className="text-[10px] text-green-500">
                ● Online
              </p>
            </div>

            <button
              onClick={onLogout}
              className="border border-white/10 px-4 py-2 text-xs text-gray-400 transition hover:border-red-600 hover:text-white"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      <div className="flex pt-16">

        {/* SIDEBAR */}
        <aside className="fixed bottom-0 left-0 top-16 hidden w-64 border-r border-white/10 bg-[#0a0a0a] lg:block">
          <div className="p-5">
            <p className="mb-4 px-3 text-[10px] uppercase tracking-[0.25em] text-gray-600">
              Security Workspace
            </p>

            <SidebarItem
              label="Dashboard"
              active={activeMenu === "dashboard"}
              onClick={() => setActiveMenu("dashboard")}
            />

            <SidebarItem
              label="VAPT Testing"
              active={activeMenu === "vapt"}
              onClick={() => setActiveMenu("vapt")}
            />

            <SidebarItem
              label="QA Testing"
              active={activeMenu === "qa"}
              onClick={() => setActiveMenu("qa")}
            />

            <SidebarItem
              label="Live Log Monitoring"
              active={activeMenu === "logs"}
              onClick={() => setActiveMenu("logs")}
            />

            <SidebarItem
              label="Uptime Monitoring"
              active={activeMenu === "uptime"}
              onClick={() => setActiveMenu("uptime")}
            />

            <SidebarItem
              label="Security Findings"
              active={activeMenu === "findings"}
              onClick={() => setActiveMenu("findings")}
            />

            <SidebarItem
              label="Reports"
              active={activeMenu === "reports"}
              onClick={() => setActiveMenu("reports")}
            />

            <SidebarItem
              label="Complaints / Support"
              active={activeMenu === "support"}
              onClick={() => setActiveMenu("support")}
            />

            <SidebarItem
              label="Profile"
              active={activeMenu === "profile"}
              onClick={() => setActiveMenu("profile")}
            />
          </div>

          <div className="absolute bottom-0 left-0 right-0 border-t border-white/10 p-5">
            <p className="text-[10px] uppercase tracking-wider text-gray-600">
              Platform Status
            </p>

            <div className="mt-3 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-green-500"></span>
              <span className="text-xs text-gray-400">
                All systems operational
              </span>
            </div>
          </div>
        </aside>

        {/* CONTENT */}
        <main className="w-full p-6 lg:ml-64 lg:p-10">
          {error && (
            <div className="mb-6 border border-red-600/30 bg-red-600/10 px-5 py-4 text-sm text-red-400">
              {error}
            </div>
          )}

          {/* DASHBOARD */}
          {activeMenu === "dashboard" && (
            <>
              <div className="mb-8">
                <p className="text-xs uppercase tracking-[0.3em] text-red-500">
                  Security Workspace
                </p>

                <h1 className="mt-2 text-3xl font-bold">
                  Welcome, {displayUsername}
                </h1>

                <p className="mt-2 text-sm text-gray-500">
                  Monitor your organization's security posture from one place.
                </p>
              </div>

              {/* STATS */}
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <AdminStat
                  title="Account"
                  value={loading ? "—" : "ACTIVE"}
                  subtitle="User account status"
                  status
                />

                <AdminStat
                  title="Security Scans"
                  value={dashboard?.total_scans ?? "—"}
                  subtitle="VAPT scans"
                />

                <AdminStat
                  title="Findings"
                  value={dashboard?.total_vulnerabilities ?? dashboard?.total_findings ?? "—"}
                  subtitle="Security findings"
                />

                <AdminStat
                  title="Reports"
                  value={dashboard?.total_reports ?? "—"}
                  subtitle="Available reports"
                />
              </div>

              {/* ACCOUNT + SECURITY */}
              <div className="mt-8 grid gap-6 xl:grid-cols-3">
                <div className="border border-white/10 bg-[#0d0d0d] xl:col-span-2">
                  <div className="border-b border-white/10 px-6 py-5">
                    <p className="text-sm font-semibold">
                      Account Overview
                    </p>
                    <p className="mt-1 text-xs text-gray-600">
                      Your registered SOC Platform account
                    </p>
                  </div>

                  <div className="grid gap-6 p-6 md:grid-cols-2">
                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-gray-600">
                        Username
                      </p>
                      <p className="mt-2 text-sm font-medium">
                        {displayUsername}
                      </p>
                    </div>

                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-gray-600">
                        Email
                      </p>
                      <p className="mt-2 text-sm text-gray-400">
                        {displayEmail}
                      </p>
                    </div>

                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-gray-600">
                        Client
                      </p>
                      <p className="mt-2 text-sm text-gray-400">
                        {clientName}
                      </p>
                    </div>

                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-gray-600">
                        Organization
                      </p>
                      <p className="mt-2 text-sm text-gray-400">
                        {organization}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="border border-white/10 bg-[#0d0d0d]">
                  <div className="border-b border-white/10 px-6 py-5">
                    <p className="text-sm font-semibold">
                      Security Status
                    </p>
                    <p className="mt-1 text-xs text-gray-600">
                      Current platform status
                    </p>
                  </div>

                  <div className="space-y-5 p-6">
                    <HealthItem
                      name="SOC Platform"
                      status="Operational"
                    />
                    <HealthItem
                      name="Authentication"
                      status="Protected"
                    />
                    <HealthItem
                      name="Security Monitoring"
                      status="Ready"
                    />
                    <HealthItem
                      name="Reporting"
                      status="Available"
                    />
                  </div>
                </div>
              </div>

              {/* QUICK ACTIONS */}
              <div className="mt-8">
                <div className="mb-5">
                  <p className="text-xs uppercase tracking-[0.25em] text-red-500">
                    Quick Access
                  </p>
                  <h2 className="mt-2 text-xl font-semibold">
                    Security Operations
                  </h2>
                </div>

                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <ManagementCard
                    number="01"
                    title="VAPT Testing"
                    description="View and initiate authorized security testing."
                    onClick={() => setActiveMenu("vapt")}
                  />

                  <ManagementCard
                    number="02"
                    title="Uptime Monitoring"
                    description="Monitor website availability, latency and live traffic."
                    onClick={() => setActiveMenu("uptime")}
                  />

                  <ManagementCard
                    number="03"
                    title="Security Findings"
                    description="Review identified vulnerabilities and risks."
                    onClick={() => setActiveMenu("findings")}
                  />

                  <ManagementCard
                    number="03"
                    title="Reports"
                    description="Access your security assessment reports."
                    onClick={() => setActiveMenu("reports")}
                  />

                  <ManagementCard
                    number="04"
                    title="Support"
                    description="Contact the security team about an issue."
                    onClick={() => setActiveMenu("support")}
                  />
                </div>
              </div>
            </>
          )}

          {/* VAPT TESTING */}
          {activeMenu === "vapt" && (
            <VAPTTesting />
          )}

          {/* QA TESTING */}
          {activeMenu === "qa" && (
            <QATesting />
          )}

          {/* LIVE LOG MONITORING */}
          {activeMenu === "logs" && (
            <LiveLogMonitoring />
          )}

          {/* UPTIME MONITORING */}
          {activeMenu === "uptime" && (
            <UptimeMonitoring />
          )}

          {/* COMPLAINTS / SUPPORT */}
          {activeMenu === "support" && (
            <SupportDashboard />
          )}

          {/* SECURITY FINDINGS */}
          {activeMenu === "findings" && (
            <SecurityFindings />
          )}

          {/* OTHER MODULES */}
          {activeMenu === "profile" && (
            <TelegramConnection />
          )}

          {activeMenu !== "dashboard" &&
            activeMenu !== "vapt" &&
            activeMenu !== "qa" &&
            activeMenu !== "logs" &&
            activeMenu !== "uptime" &&
            activeMenu !== "findings" &&
            activeMenu !== "support" &&
            activeMenu !== "profile" && (
              <UserModulePlaceholder menu={activeMenu} />
            )}
        </main>
      </div>
    </div>
  );
}


// ==================================================
// UPTIME MONITORING
// ==================================================
function UptimeMonitoring() {
  const [websiteName, setWebsiteName] = useState("");
  const [targetUrl, setTargetUrl] = useState(
    localStorage.getItem("active_vapt_target") || "http://127.0.0.1:3000"
  );

  const [monitoring, setMonitoring] = useState(false);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");

  const formatDuration = (startedAt) => {
    if (!startedAt) return "—";

    const started = new Date(startedAt).getTime();
    if (Number.isNaN(started)) return "—";

    const diffSeconds = Math.max(
      0,
      Math.floor((Date.now() - started) / 1000)
    );

    const days = Math.floor(diffSeconds / 86400);
    const hours = Math.floor((diffSeconds % 86400) / 3600);
    const minutes = Math.floor((diffSeconds % 3600) / 60);
    const seconds = diffSeconds % 60;

    const parts = [];

    if (days) parts.push(`${days}d`);
    if (hours || days) parts.push(`${hours}h`);
    if (minutes || hours || days) parts.push(`${minutes}m`);
    parts.push(`${seconds}s`);

    return parts.join(" ");
  };

  const formatTime = (value) => {
    if (!value) return "—";

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";

    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const loadStatus = async (url = targetUrl) => {
    if (!url) return;

    try {
      const response = await axios.get(`${API_URL}/uptime/status`, {
        params: {
          target_url: url,
        },
      });

      const data = response.data;

      if (data?.monitoring) {
        setMonitoring(true);
        setStatus(data);
      } else {
        setMonitoring(false);
        setStatus(null);
      }
    } catch (err) {
      console.error("Uptime status error:", err);
      setError(
        err.response?.data?.detail ||
          "Unable to load uptime monitoring status."
      );
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  useEffect(() => {
    if (!monitoring || !targetUrl) return undefined;

    const checkInterval = setInterval(async () => {
      try {
        setChecking(true);

        await axios.post(`${API_URL}/uptime/check`, null, {
          params: {
            target_url: targetUrl,
          },
        });

        await loadStatus(targetUrl);
      } catch (err) {
        console.error("Automatic uptime check error:", err);

        setError(
          err.response?.data?.detail ||
            "Unable to perform the uptime check."
        );
      } finally {
        setChecking(false);
      }
    }, 5000);

    return () => clearInterval(checkInterval);
  }, [monitoring, targetUrl]);

  useEffect(() => {
    if (!monitoring || !status?.started_at) return undefined;

    const durationInterval = setInterval(() => {
      setStatus((prev) =>
        prev
          ? {
              ...prev,
              _durationRefresh: Date.now(),
            }
          : prev
      );
    }, 1000);

    return () => clearInterval(durationInterval);
  }, [monitoring, status?.started_at]);

  const startMonitoring = async () => {
    const cleanUrl = targetUrl.trim();
    const cleanName = websiteName.trim();

    setError("");

    if (!cleanUrl) {
      setError("Please enter a website URL.");
      return;
    }

    if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
      setError("Website URL must start with http:// or https://.");
      return;
    }

    if (!cleanName) {
      setError("Please enter the website name.");
      return;
    }

    try {
      setLoading(true);

      const response = await axios.post(
        `${API_URL}/uptime/start`,
        null,
        {
          params: {
            website_name: cleanName,
            target_url: cleanUrl,
          },
        }
      );

      setWebsiteName(response.data.website_name || cleanName);
      setTargetUrl(response.data.target_url || cleanUrl);
      setMonitoring(true);
      setStatus(response.data);
      setError("");
    } catch (err) {
      console.error("Start uptime error:", err);

      setError(
        err.response?.data?.detail ||
          "Unable to start uptime monitoring."
      );
    } finally {
      setLoading(false);
    }
  };

  const checkNow = async () => {
    if (!targetUrl || !monitoring) return;

    try {
      setChecking(true);
      setError("");

      await axios.post(`${API_URL}/uptime/check`, null, {
        params: {
          target_url: targetUrl,
        },
      });

      await loadStatus(targetUrl);
    } catch (err) {
      console.error("Manual uptime check error:", err);

      setError(
        err.response?.data?.detail ||
          "Unable to perform the website check."
      );
    } finally {
      setChecking(false);
    }
  };

  const stopMonitoring = async () => {
    if (!targetUrl) return;

    try {
      setLoading(true);
      setError("");

      await axios.post(`${API_URL}/uptime/stop`, null, {
        params: {
          target_url: targetUrl,
        },
      });

      setMonitoring(false);
      setStatus(null);
    } catch (err) {
      console.error("Stop uptime error:", err);

      setError(
        err.response?.data?.detail ||
          "Unable to stop uptime monitoring."
      );
    } finally {
      setLoading(false);
    }
  };

  const current = status?.current || {};
  const totalRequests = status?.total_requests ?? 0;
  const successfulRequests = status?.successful_requests ?? 0;
  const failedRequests = status?.failed_requests ?? 0;
  const recentChecks = Array.isArray(status?.recent_checks)
    ? status.recent_checks
    : [];

  const recentWindow = recentChecks.slice(-12);
  const trafficPerMinute =
    recentChecks.length > 1
      ? Math.round(
          (recentChecks.length /
            Math.max(
              1,
              (Date.now() -
                new Date(recentChecks[0].checked_at).getTime()) /
                60000
            ))
        )
      : totalRequests > 0
      ? 1
      : 0;

  const averageLatency =
    recentChecks.length > 0
      ? Math.round(
          recentChecks.reduce(
            (sum, item) => sum + Number(item.latency_ms || 0),
            0
          ) / recentChecks.length
        )
      : 0;

  const minLatency =
    recentChecks.length > 0
      ? Math.min(
          ...recentChecks.map((item) => Number(item.latency_ms || 0))
        )
      : 0;

  const maxLatency =
    recentChecks.length > 0
      ? Math.max(
          ...recentChecks.map((item) => Number(item.latency_ms || 0))
        )
      : 0;

  return (
    <div>
      <div className="flex flex-col justify-between gap-5 md:flex-row md:items-end">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            Performance Monitoring
          </p>

          <h1 className="mt-2 text-3xl font-bold">
            Uptime Monitoring
          </h1>

          <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-500">
            Monitor website availability, response time, request activity and
            live traffic from your security workspace.
          </p>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={checkNow}
            disabled={!monitoring || checking}
            className="border border-white/10 px-5 py-3 text-xs text-gray-400 transition hover:border-red-600 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            {checking ? "Checking..." : "Check Now"}
          </button>

          {monitoring ? (
            <button
              type="button"
              onClick={stopMonitoring}
              disabled={loading}
              className="border border-red-600/40 px-5 py-3 text-xs text-red-400 transition hover:bg-red-600/10 disabled:opacity-50"
            >
              {loading ? "Stopping..." : "Stop Monitoring"}
            </button>
          ) : (
            <button
              type="button"
              onClick={startMonitoring}
              disabled={loading}
              className="bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:opacity-50"
            >
              {loading ? "Starting..." : "Start Monitoring"}
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="mt-6 border border-red-600/30 bg-red-600/10 px-5 py-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {!monitoring && (
        <div className="mt-6 border border-white/10 bg-[#0d0d0d] p-6">
          <div className="mb-5">
            <p className="text-sm font-semibold">Add Website</p>
            <p className="mt-1 text-xs text-gray-600">
              Start a live uptime monitor for an authorized website or
              application.
            </p>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <div>
              <label className="text-[10px] uppercase tracking-wider text-gray-600">
                Website Name
              </label>

              <input
                value={websiteName}
                onChange={(e) => setWebsiteName(e.target.value)}
                placeholder="Juice Shop"
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
              />
            </div>

            <div>
              <label className="text-[10px] uppercase tracking-wider text-gray-600">
                Website URL
              </label>

              <input
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://127.0.0.1:3000"
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
              />
            </div>
          </div>

          <div className="mt-5 flex items-center justify-between gap-4 border-t border-white/10 pt-5">
            <p className="text-xs text-gray-600">
              Monitoring checks the target every 5 seconds while this page is
              open.
            </p>

            <button
              type="button"
              onClick={startMonitoring}
              disabled={loading}
              className="bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:opacity-50"
            >
              {loading ? "Starting..." : "Start Uptime"}
            </button>
          </div>
        </div>
      )}

      {monitoring && status && (
        <>
          <div className="mt-8 border border-white/10 bg-[#0d0d0d]">
            <div className="flex flex-col justify-between gap-4 border-b border-white/10 px-6 py-5 md:flex-row md:items-center">
              <div>
                <p className="text-[10px] uppercase tracking-[0.25em] text-gray-600">
                  Website
                </p>

                <h2 className="mt-1 text-xl font-semibold">
                  {status.website_name}
                </h2>

                <p className="mt-1 break-all text-xs text-gray-500">
                  {status.target_url}
                </p>
              </div>

              <div
                className={`flex items-center gap-2 text-xs font-semibold ${
                  current.status === "UP"
                    ? "text-green-500"
                    : "text-red-500"
                }`}
              >
                <span
                  className={`h-2.5 w-2.5 rounded-full ${
                    current.status === "UP"
                      ? "bg-green-500"
                      : "bg-red-500"
                  }`}
                ></span>
                {current.status || "UNKNOWN"}
              </div>
            </div>

            <div className="grid gap-px bg-white/10 sm:grid-cols-2 xl:grid-cols-5">
              <UptimeMetric
                label="Uptime"
                value={`${status.uptime_percentage ?? 0}%`}
                subtitle="Availability"
              />

              <UptimeMetric
                label="Latency"
                value={`${current.latency_ms ?? 0} ms`}
                subtitle="Latest response"
              />

              <UptimeMetric
                label="Requests"
                value={totalRequests}
                subtitle={`${successfulRequests} successful`}
              />

              <UptimeMetric
                label="Live Traffic"
                value={`${trafficPerMinute}/min`}
                subtitle={`${failedRequests} failed`}
              />

              <UptimeMetric
                label="Monitoring Since"
                value={formatDuration(status.started_at)}
                subtitle={formatTime(status.started_at)}
              />
            </div>
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-3">
            <div className="border border-white/10 bg-[#0d0d0d] xl:col-span-2">
              <div className="border-b border-white/10 px-6 py-5">
                <p className="text-sm font-semibold">
                  Latency & Traffic
                </p>

                <p className="mt-1 text-xs text-gray-600">
                  Recent uptime checks from the monitoring engine.
                </p>
              </div>

              <div className="grid gap-4 p-6 md:grid-cols-3">
                <UptimeMetric
                  label="Average Latency"
                  value={`${averageLatency} ms`}
                  subtitle="Recent checks"
                />

                <UptimeMetric
                  label="Minimum Latency"
                  value={`${minLatency} ms`}
                  subtitle="Best response"
                />

                <UptimeMetric
                  label="Maximum Latency"
                  value={`${maxLatency} ms`}
                  subtitle="Slowest response"
                />
              </div>

              <div className="px-6 pb-6">
                <div className="flex h-40 items-end gap-2 overflow-hidden border border-white/10 bg-[#080808] px-4 py-4">
                  {recentWindow.length === 0 ? (
                    <div className="flex h-full w-full items-center justify-center text-xs text-gray-700">
                      Waiting for monitoring data...
                    </div>
                  ) : (
                    recentWindow.map((item, index) => {
                      const value = Number(item.latency_ms || 0);
                      const maxValue = Math.max(
                        ...recentWindow.map((entry) =>
                          Number(entry.latency_ms || 0)
                        ),
                        1
                      );

                      const height = Math.max(
                        8,
                        Math.round((value / maxValue) * 100)
                      );

                      return (
                        <div
                          key={`${item.checked_at}-${index}`}
                          className="flex h-full flex-1 items-end"
                          title={`${formatTime(item.checked_at)} • ${value} ms`}
                        >
                          <div
                            className={`w-full ${
                              item.status === "UP"
                                ? "bg-red-600"
                                : "bg-gray-600"
                            }`}
                            style={{ height: `${height}%` }}
                          ></div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>

            <div className="border border-white/10 bg-[#0d0d0d]">
              <div className="border-b border-white/10 px-6 py-5">
                <p className="text-sm font-semibold">
                  Monitoring Details
                </p>
              </div>

              <div className="space-y-5 p-6">
                <UptimeDetail
                  label="HTTP Status"
                  value={current.http_status ?? "—"}
                />

                <UptimeDetail
                  label="Last Checked"
                  value={formatTime(current.checked_at)}
                />

                <UptimeDetail
                  label="Monitoring Started"
                  value={
                    status.started_at
                      ? new Date(status.started_at).toLocaleString()
                      : "—"
                  }
                />

                <UptimeDetail
                  label="Successful Requests"
                  value={successfulRequests}
                />

                <UptimeDetail
                  label="Failed Requests"
                  value={failedRequests}
                />
              </div>
            </div>
          </div>

          <div className="mt-6 overflow-hidden border border-white/10 bg-[#0d0d0d]">
            <div className="border-b border-white/10 px-6 py-5">
              <p className="text-sm font-semibold">
                Live Traffic
              </p>

              <p className="mt-1 text-xs text-gray-600">
                Latest website availability checks and response performance.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[700px]">
                <thead>
                  <tr className="border-b border-white/10 text-left">
                    <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                      Time
                    </th>
                    <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                      Requests
                    </th>
                    <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                      Latency
                    </th>
                    <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                      HTTP
                    </th>
                    <th className="px-5 py-4 text-[10px] uppercase tracking-wider text-gray-600">
                      Status
                    </th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-white/5">
                  {recentChecks
                    .slice()
                    .reverse()
                    .map((item, index) => (
                      <tr
                        key={`${item.checked_at}-${index}`}
                        className="transition hover:bg-white/[0.02]"
                      >
                        <td className="px-5 py-4 text-xs text-gray-400">
                          {formatTime(item.checked_at)}
                        </td>

                        <td className="px-5 py-4 text-xs text-gray-500">
                          {totalRequests - index}
                        </td>

                        <td className="px-5 py-4 text-xs font-semibold text-white">
                          {item.latency_ms ?? 0} ms
                        </td>

                        <td className="px-5 py-4 text-xs text-gray-500">
                          {item.http_status ?? "—"}
                        </td>

                        <td className="px-5 py-4">
                          <span
                            className={`text-xs font-semibold ${
                              item.status === "UP"
                                ? "text-green-500"
                                : "text-red-500"
                            }`}
                          >
                            {item.status}
                          </span>
                        </td>
                      </tr>
                    ))}

                  {recentChecks.length === 0 && (
                    <tr>
                      <td
                        colSpan="5"
                        className="px-5 py-10 text-center text-sm text-gray-700"
                      >
                        No traffic/check data yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function UptimeMetric({ label, value, subtitle }) {
  return (
    <div className="bg-[#0d0d0d] px-6 py-5">
      <p className="text-[10px] uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <p className="mt-2 text-2xl font-bold text-white">
        {value}
      </p>

      <p className="mt-1 text-xs text-gray-600">
        {subtitle}
      </p>
    </div>
  );
}

function UptimeDetail({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-white/5 pb-4">
      <span className="text-xs uppercase tracking-wider text-gray-600">
        {label}
      </span>

      <span className="text-right text-sm text-gray-300">
        {value}
      </span>
    </div>
  );
}


// ==================================================
// USER COMPLAINTS / SUPPORT DASHBOARD
// ==================================================
function SupportDashboard() {
  const [tickets, setTickets] = useState([]);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [messageSubmitting, setMessageSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [reply, setReply] = useState("");

  const [form, setForm] = useState({
    category: "Tool Not Working",
    subject: "",
    description: "",
    priority: "MEDIUM",
    assessment_id: "",
  });

  const categories = [
    "Tool Not Working",
    "Login / Credential Reset",
    "Website / Application Issue",
    "VAPT Scan Issue",
    "QA Testing Issue",
    "Live Monitoring Issue",
    "Security Finding Dispute",
    "Report Issue",
    "Account / Profile Issue",
    "Performance Issue",
    "Access / Permission Issue",
    "Other",
  ];

  const priorities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

  const getConfig = () => {
    const token = localStorage.getItem("token");

    if (!token) {
      throw new Error("Your session has expired. Please log in again.");
    }

    return {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    };
  };

  const loadTickets = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await axios.get(
        `${API_URL}/support/tickets`,
        getConfig()
      );

      setTickets(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      console.error("Support ticket load error:", err);

      if (err.response?.status === 401) {
        setError("Your session has expired. Please log in again.");
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to load your support tickets.");
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTickets();
  }, []);

  const loadTicketDetails = async (ticketId) => {
    try {
      setDetailsLoading(true);
      setError("");

      const response = await axios.get(
        `${API_URL}/support/tickets/${ticketId}`,
        getConfig()
      );

      setSelectedTicket(response.data);
    } catch (err) {
      console.error("Support ticket details error:", err);

      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to load ticket details.");
      }
    } finally {
      setDetailsLoading(false);
    }
  };

  const resetForm = () => {
    setForm({
      category: "Tool Not Working",
      subject: "",
      description: "",
      priority: "MEDIUM",
      assessment_id: "",
    });
  };

  const handleCreateTicket = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const subject = form.subject.trim();
    const description = form.description.trim();

    if (!subject) {
      setError("Please enter a ticket subject.");
      return;
    }

    if (!description) {
      setError("Please describe the problem clearly.");
      return;
    }

    let assessmentId = null;

    if (form.assessment_id.trim()) {
      assessmentId = Number(form.assessment_id.trim());

      if (!Number.isInteger(assessmentId) || assessmentId <= 0) {
        setError("Assessment ID must be a valid positive number.");
        return;
      }
    }

    try {
      setSubmitting(true);

      const response = await axios.post(
        `${API_URL}/support/tickets`,
        {
          category: form.category,
          subject,
          description,
          priority: form.priority,
          assessment_id: assessmentId,
        },
        {
          ...getConfig(),
          headers: {
            ...getConfig().headers,
            "Content-Type": "application/json",
          },
        }
      );

      setSuccess(
        `Ticket ${response.data.ticket_id} was created successfully.`
      );
      setShowCreate(false);
      resetForm();
      await loadTickets();
      await loadTicketDetails(response.data.id);
    } catch (err) {
      console.error("Create ticket error:", err);

      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to create the support ticket.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleReply = async (e) => {
    e.preventDefault();

    if (!selectedTicket || !reply.trim()) {
      return;
    }

    try {
      setMessageSubmitting(true);
      setError("");
      setSuccess("");

      await axios.post(
        `${API_URL}/support/tickets/${selectedTicket.id}/messages`,
        {
          message: reply.trim(),
        },
        {
          ...getConfig(),
          headers: {
            ...getConfig().headers,
            "Content-Type": "application/json",
          },
        }
      );

      setReply("");
      setSuccess(`Reply added to ${selectedTicket.ticket_id}.`);
      await loadTickets();
      await loadTicketDetails(selectedTicket.id);
    } catch (err) {
      console.error("Ticket reply error:", err);

      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to send your message.");
      }
    } finally {
      setMessageSubmitting(false);
    }
  };

  const countStatus = (status) =>
    tickets.filter((ticket) => ticket.status === status).length;

  const statusClass = (status) => {
    switch (String(status || "").toUpperCase()) {
      case "OPEN":
        return "bg-blue-500/10 text-blue-400";
      case "IN_PROGRESS":
        return "bg-yellow-500/10 text-yellow-400";
      case "WAITING_FOR_USER":
        return "bg-purple-500/10 text-purple-400";
      case "RESOLVED":
        return "bg-green-500/10 text-green-400";
      case "CLOSED":
        return "bg-gray-500/10 text-gray-400";
      default:
        return "bg-white/5 text-gray-400";
    }
  };

  const priorityClass = (priority) => {
    switch (String(priority || "").toUpperCase()) {
      case "CRITICAL":
        return "text-red-400";
      case "HIGH":
        return "text-orange-400";
      case "MEDIUM":
        return "text-yellow-400";
      default:
        return "text-gray-400";
    }
  };

  return (
    <div>
      <div className="flex flex-col justify-between gap-5 md:flex-row md:items-end">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            Security Workspace
          </p>
          <h1 className="mt-2 text-3xl font-bold">
            Complaints &amp; Support
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-500">
            Raise technical issues, account problems, testing issues, or other
            security support requests. Every request receives a unique ticket ID
            and can be tracked from this workspace.
          </p>
        </div>

        <div className="flex gap-3">
          <button
            onClick={() => {
              setError("");
              setSuccess("");
              loadTickets();
            }}
            disabled={loading}
            className="border border-white/10 px-5 py-3 text-xs text-gray-400 transition hover:border-red-600 hover:text-white disabled:opacity-50"
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>

          <button
            onClick={() => {
              setShowCreate(true);
              setError("");
              setSuccess("");
            }}
            className="bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700"
          >
            + Raise New Ticket
          </button>
        </div>
      </div>

      {success && (
        <div className="mt-6 border border-green-600/20 bg-green-600/5 px-5 py-4">
          <p className="text-sm text-green-400">{success}</p>
        </div>
      )}

      {error && (
        <div className="mt-6 border border-red-600/30 bg-red-600/10 px-5 py-4">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <AdminStat
          title="Total Tickets"
          value={loading ? "—" : tickets.length}
          subtitle="All your support requests"
        />
        <AdminStat
          title="Open"
          value={loading ? "—" : countStatus("OPEN")}
          subtitle="Waiting for action"
        />
        <AdminStat
          title="In Progress"
          value={loading ? "—" : countStatus("IN_PROGRESS")}
          subtitle="Being worked on"
        />
        <AdminStat
          title="Resolved"
          value={loading ? "—" : countStatus("RESOLVED")}
          subtitle="Completed requests"
          status
        />
      </div>

      {showCreate && (
        <div className="mt-8 border border-white/10 bg-[#0d0d0d]">
          <div className="flex items-center justify-between border-b border-white/10 px-6 py-5">
            <div>
              <p className="text-sm font-semibold">Raise a New Ticket</p>
              <p className="mt-1 text-xs text-gray-600">
                Provide enough detail for the security team to investigate the issue.
              </p>
            </div>
            <button
              onClick={() => {
                setShowCreate(false);
                resetForm();
              }}
              className="text-sm text-gray-500 transition hover:text-white"
            >
              ✕
            </button>
          </div>

          <form onSubmit={handleCreateTicket} className="grid gap-5 p-6 md:grid-cols-2">
            <div>
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Category
              </label>
              <select
                value={form.category}
                onChange={(e) =>
                  setForm((current) => ({
                    ...current,
                    category: e.target.value,
                  }))
                }
                disabled={submitting}
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-gray-300 outline-none focus:border-red-600 disabled:opacity-50"
              >
                {categories.map((category) => (
                  <option key={category} value={category}>
                    {category}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Priority
              </label>
              <select
                value={form.priority}
                onChange={(e) =>
                  setForm((current) => ({
                    ...current,
                    priority: e.target.value,
                  }))
                }
                disabled={submitting}
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-gray-300 outline-none focus:border-red-600 disabled:opacity-50"
              >
                {priorities.map((priority) => (
                  <option key={priority} value={priority}>
                    {priority}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2">
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Subject
              </label>
              <input
                type="text"
                value={form.subject}
                onChange={(e) =>
                  setForm((current) => ({
                    ...current,
                    subject: e.target.value,
                  }))
                }
                placeholder="Example: Nmap scan is not working"
                maxLength={200}
                disabled={submitting}
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600 disabled:opacity-50"
              />
            </div>

            <div className="md:col-span-2">
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Description
              </label>
              <textarea
                value={form.description}
                onChange={(e) =>
                  setForm((current) => ({
                    ...current,
                    description: e.target.value,
                  }))
                }
                rows={6}
                maxLength={5000}
                placeholder="Explain what happened, what you expected, and any error message you received."
                disabled={submitting}
                className="mt-2 w-full resize-y border border-white/10 bg-[#080808] px-4 py-3 text-sm leading-6 text-white outline-none placeholder:text-gray-700 focus:border-red-600 disabled:opacity-50"
              />
            </div>

            <div className="md:col-span-2">
              <label className="text-xs uppercase tracking-wider text-gray-500">
                Related Assessment ID (Optional)
              </label>
              <input
                type="number"
                min="1"
                value={form.assessment_id}
                onChange={(e) =>
                  setForm((current) => ({
                    ...current,
                    assessment_id: e.target.value,
                  }))
                }
                placeholder="Example: 1"
                disabled={submitting}
                className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600 disabled:opacity-50"
              />
              <p className="mt-2 text-[11px] leading-5 text-gray-700">
                Add an assessment ID when the ticket is related to a specific VAPT / QA assessment.
              </p>
            </div>

            <div className="flex gap-3 md:col-span-2">
              <button
                type="submit"
                disabled={submitting}
                className="bg-red-600 px-6 py-3 text-sm font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? "Creating Ticket..." : "Create Ticket"}
              </button>

              <button
                type="button"
                onClick={() => {
                  setShowCreate(false);
                  resetForm();
                }}
                disabled={submitting}
                className="border border-white/10 px-6 py-3 text-sm text-gray-400 transition hover:border-white/30 hover:text-white disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="mt-8 overflow-hidden border border-white/10 bg-[#0d0d0d]">
        <div className="border-b border-white/10 px-6 py-5">
          <p className="text-sm font-semibold">My Tickets</p>
          <p className="mt-1 text-xs text-gray-600">
            Track the current status of every support request.
          </p>
        </div>

        {loading ? (
          <div className="px-6 py-12 text-center text-sm text-gray-600">
            Loading tickets...
          </div>
        ) : tickets.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center bg-red-600/10 text-xl text-red-500">
              S
            </div>
            <p className="mt-5 text-sm font-medium text-gray-300">
              No support tickets yet
            </p>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-gray-600">
              Create a ticket when you experience a security tool issue,
              login problem, website issue, testing problem, or another support concern.
            </p>
            <button
              onClick={() => setShowCreate(true)}
              className="mt-5 bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700"
            >
              Raise Your First Ticket
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1000px] text-left text-sm">
              <thead className="border-b border-white/10 bg-[#0a0a0a] text-[10px] uppercase tracking-wider text-gray-600">
                <tr>
                  <th className="px-6 py-4">Ticket ID</th>
                  <th className="px-6 py-4">Subject</th>
                  <th className="px-6 py-4">Category</th>
                  <th className="px-6 py-4">Priority</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Created</th>
                  <th className="px-6 py-4">Action</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/5">
                {tickets.map((ticket) => (
                  <tr key={ticket.id} className="transition hover:bg-white/[0.02]">
                    <td className="px-6 py-5">
                      <p className="font-mono text-xs font-semibold text-red-400">
                        {ticket.ticket_id}
                      </p>
                    </td>

                    <td className="max-w-[260px] px-6 py-5">
                      <p className="truncate font-medium text-white">
                        {ticket.subject}
                      </p>
                    </td>

                    <td className="px-6 py-5 text-gray-400">
                      {ticket.category}
                    </td>

                    <td className="px-6 py-5">
                      <span className={`text-xs font-semibold ${priorityClass(ticket.priority)}`}>
                        {ticket.priority}
                      </span>
                    </td>

                    <td className="px-6 py-5">
                      <span className={`inline-flex px-2 py-1 text-[10px] font-semibold tracking-wider ${statusClass(ticket.status)}`}>
                        {ticket.status}
                      </span>
                    </td>

                    <td className="px-6 py-5 text-xs text-gray-500">
                      {ticket.created_at
                        ? new Date(ticket.created_at).toLocaleString()
                        : "—"}
                    </td>

                    <td className="px-6 py-5">
                      <button
                        onClick={() => loadTicketDetails(ticket.id)}
                        className="border border-white/10 px-3 py-2 text-xs text-gray-400 transition hover:border-red-600 hover:text-white"
                      >
                        View Ticket
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {(detailsLoading || selectedTicket) && (
        <div className="mt-8 border border-white/10 bg-[#0d0d0d]">
          <div className="flex items-center justify-between border-b border-white/10 px-6 py-5">
            <div>
              <p className="text-sm font-semibold">Ticket Details</p>
              <p className="mt-1 text-xs text-gray-600">
                Conversation and resolution information for the selected request.
              </p>
            </div>
            <button
              onClick={() => {
                setSelectedTicket(null);
                setReply("");
              }}
              className="text-sm text-gray-500 transition hover:text-white"
            >
              ✕
            </button>
          </div>

          {detailsLoading ? (
            <div className="px-6 py-12 text-sm text-gray-600">
              Loading ticket details...
            </div>
          ) : selectedTicket ? (
            <div className="p-6">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <SupportDetail label="Ticket ID" value={selectedTicket.ticket_id} mono />
                <SupportDetail label="Status" value={selectedTicket.status} />
                <SupportDetail label="Priority" value={selectedTicket.priority} />
                <SupportDetail label="Category" value={selectedTicket.category} />
              </div>

              <div className="mt-6 grid gap-6 lg:grid-cols-2">
                <div className="border border-white/10 bg-[#080808] p-5">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    Subject
                  </p>
                  <p className="mt-2 text-sm font-semibold text-white">
                    {selectedTicket.subject}
                  </p>

                  <p className="mt-5 text-[10px] uppercase tracking-wider text-gray-600">
                    Original Description
                  </p>
                  <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-400">
                    {selectedTicket.description}
                  </p>
                </div>

                <div className="border border-white/10 bg-[#080808] p-5">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    Assignment
                  </p>
                  <p className="mt-2 text-sm text-gray-300">
                    {selectedTicket.assigned_to || "Not assigned yet"}
                  </p>
                  <p className="mt-1 text-xs text-gray-600">
                    Channel: {selectedTicket.assignment_channel || "—"}
                  </p>
                  <p className="mt-1 text-xs text-gray-600">
                    Assignment status: {selectedTicket.assignment_status || "—"}
                  </p>

                  <div className="mt-5 border-t border-white/10 pt-5">
                    <p className="text-[10px] uppercase tracking-wider text-gray-600">
                      Resolution
                    </p>
                    <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-400">
                      {selectedTicket.resolution || "No resolution has been posted yet."}
                    </p>
                  </div>

                  {selectedTicket.final_admin_message && (
                    <div className="mt-5 border-t border-white/10 pt-5">
                      <p className="text-[10px] uppercase tracking-wider text-gray-600">
                        Final Admin Message
                      </p>
                      <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-400">
                        {selectedTicket.final_admin_message}
                      </p>
                    </div>
                  )}
                </div>
              </div>

              <div className="mt-6 border border-white/10 bg-[#080808]">
                <div className="border-b border-white/10 px-5 py-4">
                  <p className="text-sm font-semibold">Conversation</p>
                </div>

                <div className="max-h-[420px] space-y-4 overflow-y-auto p-5">
                  {Array.isArray(selectedTicket.messages) && selectedTicket.messages.length > 0 ? (
                    selectedTicket.messages.map((message) => (
                      <div
                        key={message.id}
                        className="border border-white/10 bg-[#0d0d0d] p-4"
                      >
                        <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
                          <p className="text-xs font-semibold text-gray-300">
                            {message.sender_name} · {message.sender_type}
                          </p>
                          <p className="text-[10px] text-gray-600">
                            {message.created_at
                              ? new Date(message.created_at).toLocaleString()
                              : "—"}
                          </p>
                        </div>
                        <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-gray-400">
                          {message.message}
                        </p>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-gray-600">No messages yet.</p>
                  )}
                </div>

                {!['RESOLVED', 'CLOSED'].includes(
                  String(selectedTicket.status || "").toUpperCase()
                ) && (
                  <form
                    onSubmit={handleReply}
                    className="border-t border-white/10 p-5"
                  >
                    <label className="text-xs uppercase tracking-wider text-gray-500">
                      Add Message
                    </label>
                    <textarea
                      value={reply}
                      onChange={(e) => setReply(e.target.value)}
                      rows={4}
                      maxLength={5000}
                      placeholder="Send additional information to the security team..."
                      disabled={messageSubmitting}
                      className="mt-2 w-full resize-y border border-white/10 bg-[#0d0d0d] px-4 py-3 text-sm leading-6 text-white outline-none placeholder:text-gray-700 focus:border-red-600 disabled:opacity-50"
                    />
                    <button
                      type="submit"
                      disabled={messageSubmitting || !reply.trim()}
                      className="mt-3 bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {messageSubmitting ? "Sending..." : "Send Message"}
                    </button>
                  </form>
                )}
              </div>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}

// ==================================================
// SUPPORT DETAIL
// ==================================================
function SupportDetail({ label, value, mono = false }) {
  return (
    <div className="border border-white/10 bg-[#080808] p-4">
      <p className="text-[10px] uppercase tracking-wider text-gray-600">
        {label}
      </p>
      <p className={`mt-2 break-all text-sm font-semibold ${mono ? "font-mono text-red-400" : "text-white"}`}>
        {value || "—"}
      </p>
    </div>
  );
}


// ==================================================
// LIVE LOG MONITORING
// ==================================================
function LiveLogMonitoring() {
  const [activeLog, setActiveLog] = useState("syslog");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const [activeTarget, setActiveTarget] = useState(
    localStorage.getItem("active_vapt_target") || ""
  );

  const [activeTargetMeta, setActiveTargetMeta] = useState(() => {
    try {
      const saved = localStorage.getItem("active_vapt_target_meta");
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [monitoringStatus, setMonitoringStatus] = useState("not_started");
  const [monitoringLoading, setMonitoringLoading] = useState(false);

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");

  const [logs, setLogs] = useState([]);
  const [summaryLogs, setSummaryLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [dataSource, setDataSource] = useState("—");

  const logTabs = [
    { id: "syslog", label: "Sys Logs" },
    { id: "auth", label: "Auth Logs" },
    { id: "access", label: "Access Logs" },
  ];

  const getAuthConfig = () => {
    const token = localStorage.getItem("token");

    if (!token) {
      throw new Error("Your session has expired. Please log in again.");
    }

    return {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    };
  };

  const syncActiveTarget = () => {
    const target = localStorage.getItem("active_vapt_target") || "";
    setActiveTarget(target);

    try {
      const saved = localStorage.getItem("active_vapt_target_meta");
      setActiveTargetMeta(saved ? JSON.parse(saved) : null);
    } catch {
      setActiveTargetMeta(null);
    }

    setMonitoringStatus("not_started");
  };

  useEffect(() => {
    window.addEventListener("storage", syncActiveTarget);

    return () => {
      window.removeEventListener("storage", syncActiveTarget);
    };
  }, []);

  const getMonitoringStatus = async (target = activeTarget) => {
    if (!target) {
      setMonitoringStatus("not_started");
      return null;
    }

    const token = localStorage.getItem("token");

    if (!token) {
      setError("Your session has expired. Please log in again.");
      return null;
    }

    try {
      const response = await axios.get(
        `${API_URL}/logs/monitoring/status`,
        {
          ...getAuthConfig(),
          params: { target },
        }
      );

      setMonitoringStatus(
        response.data?.monitoring_status || "not_started"
      );

      return response.data;
    } catch (err) {
      console.error("Monitoring status error:", err);

      if (err.response?.status === 401) {
        localStorage.removeItem("token");
        setError("Your session has expired. Please log in again.");
      } else if (err.response?.status === 404) {
        setMonitoringStatus("not_started");
      }

      return null;
    }
  };

  const startMonitoring = async (target = activeTarget) => {
    if (!target) {
      setMonitoringStatus("not_started");
      return false;
    }

    const token = localStorage.getItem("token");

    if (!token) {
      setError("Your session has expired. Please log in again.");
      return false;
    }

    try {
      setMonitoringLoading(true);
      setError("");

      const response = await axios.post(
        `${API_URL}/logs/monitoring/start`,
        { target },
        {
          ...getAuthConfig(),
          headers: {
            ...getAuthConfig().headers,
            "Content-Type": "application/json",
          },
        }
      );

      setMonitoringStatus(
        response.data?.monitoring_status || "active"
      );

      return true;
    } catch (err) {
      console.error("Start monitoring error:", err);

      if (err.response?.status === 401) {
        localStorage.removeItem("token");
        setError("Your session has expired. Please log in again.");
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to start live monitoring for this target.");
      }

      return false;
    } finally {
      setMonitoringLoading(false);
    }
  };

  const fetchLogs = async ({
    includeFilters = true,
    silent = false,
  } = {}) => {
    const token = localStorage.getItem("token");

    if (!token) {
      setError("Your session has expired. Please log in again.");
      setLoading(false);
      return;
    }

    if (!activeTarget) {
      setLogs([]);
      setSummaryLogs([]);
      setDataSource("—");
      setLoading(false);
      return;
    }

    try {
      if (!silent) {
        setLoading(true);
      }

      setError("");

      const params = new URLSearchParams();
      params.set("limit", "200");
      params.set("target", activeTarget);

      if (includeFilters) {
        if (search.trim()) {
          params.set("search", search.trim());
        }

        params.set("severity", severity);
      } else {
        params.set("severity", "all");
      }

      const response = await axios.get(
        `${API_URL}/logs/${activeLog}?${params.toString()}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const returnedLogs = response.data.logs || [];

      if (includeFilters) {
        setLogs(returnedLogs);
      } else {
        setSummaryLogs(returnedLogs);
      }

      setDataSource(
        response.data.source ||
          (activeLog === "access"
            ? "SOC Platform API"
            : "systemd-journald")
      );

      if (response.data.monitoring_status) {
        setMonitoringStatus(response.data.monitoring_status);
      }

      setLastUpdated(new Date());
    } catch (err) {
      console.error("Live log fetch error:", err);

      if (err.response?.status === 401) {
        setError("Your session has expired. Please log in again.");
        localStorage.removeItem("token");
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError(
          "Unable to retrieve live logs from the SOC Platform backend."
        );
      }

      if (!silent) {
        setLogs([]);
        setSummaryLogs([]);
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  // Automatically connect monitoring to the active VAPT target.
  useEffect(() => {
    const initializeMonitoring = async () => {
      if (!activeTarget) {
        setMonitoringStatus("not_started");
        setLogs([]);
        setSummaryLogs([]);
        setLoading(false);
        return;
      }

      const status = await getMonitoringStatus(activeTarget);

      if (
        !status ||
        status.monitoring_status !== "active"
      ) {
        await startMonitoring(activeTarget);
      }

      await fetchLogs({ includeFilters: true });
      await fetchLogs({
        includeFilters: false,
        silent: true,
      });
    };

    initializeMonitoring();
  }, [activeTarget]);

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchLogs({ includeFilters: true });
      fetchLogs({ includeFilters: false, silent: true });
    }, 300);

    return () => clearTimeout(timer);
  }, [search, severity]);

  useEffect(() => {
    if (!autoRefresh || !activeTarget) {
      return undefined;
    }

    const interval = setInterval(async () => {
      await getMonitoringStatus(activeTarget);
      await fetchLogs({
        includeFilters: true,
        silent: true,
      });
      await fetchLogs({
        includeFilters: false,
        silent: true,
      });
    }, 5000);

    return () => clearInterval(interval);
  }, [autoRefresh, activeTarget, activeLog, search, severity]);

  const totalEvents = summaryLogs.length;

  const errorCount = summaryLogs.filter(
    (log) => String(log.level || "").toUpperCase() === "ERROR"
  ).length;

  const warningCount = summaryLogs.filter(
    (log) => String(log.level || "").toUpperCase() === "WARN"
  ).length;

  const authFailures = summaryLogs.filter((log) => {
    const event = String(log.event || "").toLowerCase();
    const message = String(log.message || "").toLowerCase();

    return (
      event.includes("failed") ||
      event.includes("failure") ||
      message.includes("authentication failure") ||
      message.includes("failed password") ||
      message.includes("invalid user")
    );
  }).length;

  const handleTabChange = (tabId) => {
    setActiveLog(tabId);
    setSearch("");
    setSeverity("all");
  };

  const handleManualStart = async () => {
    if (!activeTarget) {
      setError(
        "Complete an authorized VAPT scan first. The successful target becomes the monitoring context."
      );
      return;
    }

    const started = await startMonitoring(activeTarget);

    if (started) {
      await fetchLogs({ includeFilters: true });
      await fetchLogs({
        includeFilters: false,
        silent: true,
      });
    }
  };

  const handleStop = async () => {
    if (!activeTarget) {
      return;
    }

    try {
      setMonitoringLoading(true);
      setError("");

      await axios.post(
        `${API_URL}/logs/monitoring/stop`,
        { target: activeTarget },
        {
          ...getAuthConfig(),
          headers: {
            ...getAuthConfig().headers,
            "Content-Type": "application/json",
          },
        }
      );

      setMonitoringStatus("not_started");
      setAutoRefresh(false);
    } catch (err) {
      console.error("Stop monitoring error:", err);

      if (err.response?.status === 401) {
        localStorage.removeItem("token");
        setError("Your session has expired. Please log in again.");
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to stop monitoring for this target.");
      }
    } finally {
      setMonitoringLoading(false);
    }
  };

  const sourceForDisplay =
    dataSource === "soc-api"
      ? "SOC Platform API"
      : dataSource;

  const monitoringIsActive =
    monitoringStatus === "active";

  return (
    <div>
      {/* HEADER */}
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            Security Monitoring
          </p>

          <h1 className="mt-2 text-3xl font-bold">
            Live Log Monitoring
          </h1>

          <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-500">
            Monitor system, authentication and application access events for
            the active VAPT assessment. The monitoring context is selected
            automatically from the successful VAPT target.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="border border-white/10 bg-[#0d0d0d] px-4 py-3 text-xs">
            <p className="text-[10px] uppercase tracking-wider text-gray-600">
              Monitoring Status
            </p>

            <p
              className={`mt-1 font-semibold ${
                monitoringIsActive
                  ? "text-green-500"
                  : "text-yellow-500"
              }`}
            >
              {monitoringLoading
                ? "CONNECTING..."
                : monitoringIsActive
                ? "ACTIVE"
                : "NOT STARTED"}
            </p>
          </div>

          <div className="border border-white/10 bg-[#0d0d0d] px-4 py-3 text-xs">
            <p className="text-[10px] uppercase tracking-wider text-gray-600">
              Data Source
            </p>

            <p className="mt-1 max-w-[190px] truncate text-green-500">
              {sourceForDisplay || "Loading..."}
            </p>
          </div>

          <span className="flex items-center gap-2 border border-white/10 bg-[#0d0d0d] px-4 py-3 text-xs">
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                autoRefresh && monitoringIsActive
                  ? "bg-green-500"
                  : "bg-gray-600"
              }`}
            />

            <span
              className={
                autoRefresh && monitoringIsActive
                  ? "text-green-500"
                  : "text-gray-600"
              }
            >
              {autoRefresh && monitoringIsActive
                ? "LIVE"
                : "PAUSED"}
            </span>
          </span>

          <button
            onClick={() => setAutoRefresh((value) => !value)}
            className="border border-white/10 px-4 py-3 text-xs text-gray-400 transition hover:border-red-600 hover:text-white"
          >
            {autoRefresh ? "Pause" : "Resume"}
          </button>
        </div>
      </div>

      {/* ERROR */}
      {error && (
        <div className="mb-6 border border-red-600/20 bg-red-600/5 px-5 py-4">
          <p className="text-sm text-red-400">
            {error}
          </p>
        </div>
      )}

      {/* ACTIVE VAPT TARGET */}
      <div className="mb-6 border border-red-600/20 bg-red-600/5 p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <p className="text-[10px] uppercase tracking-[0.2em] text-red-500">
              Active Security Target
            </p>

            {activeTarget ? (
              <>
                <p className="mt-2 break-all text-base font-semibold text-white">
                  {activeTarget}
                </p>

                <div className="mt-2 flex flex-wrap gap-x-5 gap-y-2 text-xs text-gray-600">
                  <span>
                    VAPT Status:{" "}
                    <span className="text-green-500">
                      {activeTargetMeta?.status || "Completed"}
                    </span>
                  </span>

                  {activeTargetMeta?.scenario && (
                    <span>
                      Scenario:{" "}
                      <span className="text-gray-400">
                        {activeTargetMeta.scenario}
                      </span>
                    </span>
                  )}

                  {activeTargetMeta?.profile && (
                    <span>
                      Profile:{" "}
                      <span className="text-gray-400">
                        {activeTargetMeta.profile}
                      </span>
                    </span>
                  )}

                  {activeTargetMeta?.scannedAt && (
                    <span>
                      Last Scan:{" "}
                      <span className="text-gray-400">
                        {new Date(
                          activeTargetMeta.scannedAt
                        ).toLocaleString()}
                      </span>
                    </span>
                  )}

                  <span>
                    Monitoring:{" "}
                    <span
                      className={
                        monitoringIsActive
                          ? "text-green-500"
                          : "text-yellow-500"
                      }
                    >
                      {monitoringIsActive
                        ? "Active"
                        : "Not started"}
                    </span>
                  </span>
                </div>
              </>
            ) : (
              <>
                <p className="mt-2 text-base font-semibold text-white">
                  No active VAPT target selected
                </p>

                <p className="mt-2 text-xs leading-5 text-gray-600">
                  Complete an authorized VAPT scan first. The successful scan
                  target becomes the monitoring context for this workspace.
                </p>
              </>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {activeTarget && !monitoringIsActive && (
              <button
                onClick={handleManualStart}
                disabled={monitoringLoading}
                className="bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {monitoringLoading
                  ? "Starting..."
                  : "Start Monitoring"}
              </button>
            )}

            {activeTarget && monitoringIsActive && (
              <button
                onClick={handleStop}
                disabled={monitoringLoading}
                className="border border-white/10 px-5 py-3 text-xs text-gray-400 transition hover:border-red-600 hover:text-white disabled:opacity-50"
              >
                Stop Monitoring
              </button>
            )}

            <div className="border border-white/10 bg-[#080808] px-4 py-3 text-xs">
              <p className="text-[10px] uppercase tracking-wider text-gray-600">
                Log Source
              </p>

              <p className="mt-1 text-green-500">
                {dataSource || "Loading..."}
              </p>
            </div>
          </div>
        </div>
      </div>

      {!activeTarget && (
        <div className="mb-6 border border-yellow-600/20 bg-yellow-600/5 px-5 py-4">
          <p className="text-sm text-yellow-500">
            No VAPT target is linked yet. Complete an authorized VAPT scan to
            establish the active security target.
          </p>
        </div>
      )}

      {/* EVENT SUMMARY */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <LogStat label="Total Events" value={totalEvents} />
        <LogStat label="Errors" value={errorCount} critical />
        <LogStat label="Warnings" value={warningCount} />

        <LogStat
          label="Auth Failures"
          value={authFailures}
          critical={authFailures > 0}
        />
      </div>

      {/* LOG TABS */}
      <div className="mt-8 border border-white/10 bg-[#0d0d0d]">
        <div className="border-b border-white/10 px-6 pt-5">
          <div className="flex flex-wrap gap-1">
            {logTabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => handleTabChange(tab.id)}
                className={`border-b-2 px-5 py-3 text-sm transition ${
                  activeLog === tab.id
                    ? "border-red-600 text-white"
                    : "border-transparent text-gray-600 hover:text-gray-300"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* FILTERS */}
        <div className="grid gap-4 border-b border-white/10 p-6 md:grid-cols-[1fr_180px_auto]">
          <div>
            <label className="text-[10px] uppercase tracking-wider text-gray-600">
              Search Logs
            </label>

            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search source, event or message..."
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </div>

          <div>
            <label className="text-[10px] uppercase tracking-wider text-gray-600">
              Severity
            </label>

            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-gray-300 outline-none focus:border-red-600"
            >
              <option value="all">All Levels</option>
              <option value="INFO">INFO</option>
              <option value="WARN">WARN</option>
              <option value="ERROR">ERROR</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={() => {
                fetchLogs({ includeFilters: true });
                fetchLogs({ includeFilters: false, silent: true });
              }}
              disabled={loading || !activeTarget}
              className="border border-white/10 px-4 py-3 text-xs text-gray-400 transition hover:border-red-600 hover:text-white disabled:opacity-50"
            >
              {loading ? "Loading..." : "Refresh Now"}
            </button>
          </div>
        </div>

        {/* TABLE */}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[950px] text-left text-sm">
            <thead className="border-b border-white/10 bg-[#0a0a0a] text-[10px] uppercase tracking-wider text-gray-600">
              <tr>
                <th className="px-6 py-4">Time</th>
                <th className="px-6 py-4">Source</th>
                <th className="px-6 py-4">Level</th>
                <th className="px-6 py-4">Event</th>
                <th className="px-6 py-4">Message</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-white/5">
              {logs.map((log) => (
                <tr
                  key={log.id}
                  className="transition hover:bg-white/[0.02]"
                >
                  <td className="whitespace-nowrap px-6 py-5 font-mono text-xs text-gray-600">
                    {log.timestamp || "—"}
                  </td>

                  <td className="px-6 py-5 text-gray-400">
                    {log.source || "—"}
                  </td>

                  <td className="px-6 py-5">
                    <LogLevel level={log.level} />
                  </td>

                  <td className="max-w-xs px-6 py-5 font-medium text-gray-300">
                    {log.event || "—"}
                  </td>

                  <td className="max-w-2xl px-6 py-5 text-gray-600">
                    {log.message || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!loading && logs.length === 0 && (
            <div className="px-6 py-12 text-center">
              <p className="text-sm text-gray-500">
                No real log events match the current filters.
              </p>

              <p className="mt-2 text-xs text-gray-700">
                Try clearing the search or selecting All Levels.
              </p>
            </div>
          )}

          {loading && (
            <div className="px-6 py-12 text-center text-sm text-gray-600">
              Loading real log events...
            </div>
          )}
        </div>
      </div>

      {/* MONITORING STATUS */}
      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <div className="border border-white/10 bg-[#0d0d0d] p-6 xl:col-span-2">
          <div className="flex items-center justify-between border-b border-white/10 pb-5">
            <div>
              <p className="text-sm font-semibold">
                Monitoring Status
              </p>

              <p className="mt-1 text-xs text-gray-600">
                Current backend log-source status for the active assessment.
              </p>
            </div>

            <span
              className={`flex items-center gap-2 text-xs ${
                monitoringIsActive && autoRefresh
                  ? "text-green-500"
                  : "text-yellow-500"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  monitoringIsActive && autoRefresh
                    ? "bg-green-500"
                    : "bg-yellow-500"
                }`}
              />
              {monitoringIsActive
                ? autoRefresh
                  ? "Monitoring Active"
                  : "Monitoring Active / Paused"
                : "Monitoring Not Started"}
            </span>
          </div>

          <div className="mt-6 grid gap-4 md:grid-cols-3">
            <LogSource
              title="Sys Logs"
              description="Operating-system and service events from systemd-journald."
              active={monitoringIsActive}
            />

            <LogSource
              title="Auth Logs"
              description="Authentication and account events from systemd-journald."
              active={monitoringIsActive}
            />

            <LogSource
              title="Access Logs"
              description="Real HTTP/API requests generated by the SOC Platform."
              active={monitoringIsActive}
            />
          </div>
        </div>

        <div className="border border-white/10 bg-[#0d0d0d] p-6">
          <p className="text-sm font-semibold">
            Monitoring Controls
          </p>

          <div className="mt-6 space-y-5">
            <LogControl
              label="Active Target"
              value={activeTarget || "No target"}
            />

            <LogControl
              label="Monitoring"
              value={monitoringIsActive ? "Active" : "Not started"}
            />

            <LogControl
              label="Current Source"
              value={sourceForDisplay || "Loading..."}
            />

            <LogControl
              label="Current Stream"
              value={activeLog}
            />

            <LogControl
              label="Auto Refresh"
              value={autoRefresh ? "5 sec" : "Paused"}
            />

            <LogControl
              label="Last Updated"
              value={
                lastUpdated
                  ? lastUpdated.toLocaleTimeString()
                  : "—"
              }
            />
          </div>

          <p className="mt-6 border-t border-white/10 pt-5 text-xs leading-6 text-gray-600">
            Monitoring is linked to the selected VAPT assessment. Sys Logs and
            Auth Logs come from the local system collector, while Access Logs
            come from the SOC Platform API. Remote target logs require an
            authorized collector on the target environment.
          </p>
        </div>
      </div>
    </div>
  );
}

// ==================================================
// LOG STAT
// ==================================================
function LogStat({
  label,
  value,
  critical,
}) {
  return (
    <div className="border border-white/10 bg-[#0d0d0d] p-5">
      <p className="text-[10px] uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <p
        className={`mt-4 text-3xl font-bold ${
          critical ? "text-red-500" : "text-white"
        }`}
      >
        {value}
      </p>
    </div>
  );
}


// ==================================================
// LOG LEVEL
// ==================================================
function LogLevel({ level }) {
  const normalized = String(level || "INFO").toUpperCase();

  const classes =
    normalized === "ERROR"
      ? "bg-red-600/10 text-red-400"
      : normalized === "WARN"
      ? "bg-yellow-600/10 text-yellow-400"
      : "bg-white/5 text-gray-400";

  return (
    <span className={`px-2 py-1 text-[10px] ${classes}`}>
      {normalized}
    </span>
  );
}


// ==================================================
// LOG SOURCE
// ==================================================
function LogSource({
  title,
  description,
  active,
}) {
  return (
    <div className="border border-white/10 bg-[#080808] p-5">
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold">
          {title}
        </span>

        <span
          className={`h-1.5 w-1.5 rounded-full ${
            active ? "bg-green-500" : "bg-gray-600"
          }`}
        />
      </div>

      <p className="mt-2 text-xs leading-5 text-gray-600">
        {description}
      </p>

      <p className="mt-5 text-[10px] uppercase tracking-wider text-green-500">
        {active ? "Connected" : "No events"}
      </p>
    </div>
  );
}


// ==================================================
// LOG CONTROL
// ==================================================
function LogControl({
  label,
  value,
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-sm text-gray-400">
        {label}
      </span>

      <span className="max-w-[180px] truncate text-right text-xs text-green-500">
        {value}
      </span>
    </div>
  );
}


// ==================================================
// ==================================================
// VAPT TESTING
// ==================================================
function VAPTTesting() {
  const [targetUrl, setTargetUrl] = useState(
    localStorage.getItem("active_vapt_target") || ""
  );
  const [scanType, setScanType] = useState("quick");
  const [status, setStatus] = useState("Ready");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  const handleStartScan = async (type = scanType) => {
    setMessage("");
    setScanResult(null);
    setScanType(type);

    const cleanUrl = targetUrl.trim();

    if (!cleanUrl) {
      setMessage("Enter an authorized target URL before starting a scan.");
      return;
    }

    try {
      const parsed = new URL(cleanUrl);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        setMessage("Only HTTP and HTTPS URLs are supported.");
        return;
      }
    } catch {
      setMessage("Enter a valid URL, for example https://example.com");
      return;
    }

    const token = localStorage.getItem("token");
    if (!token) {
      setMessage("Your session has expired. Please log in again.");
      return;
    }

    try {
      setLoading(true);
      setStatus("Scanning");

      const response = await axios.post(
        `${API_URL}/vapt/scan`,
        {
          target_url: cleanUrl,
          scan_type: type,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      setScanResult(response.data);
      setStatus("Completed");

      const activeTargetMeta = {
        target: cleanUrl,
        scanType: type,
        scannedAt: new Date().toISOString(),
        status: "Completed",
      };

      localStorage.setItem("active_vapt_target", cleanUrl);
      localStorage.setItem(
        "active_vapt_target_meta",
        JSON.stringify(activeTargetMeta)
      );

      setMessage(
        `${type === "quick" ? "Quick" : "Detailed"} VAPT scan completed successfully. This URL is now the active security target.`
      );
    } catch (err) {
      console.error("VAPT scan error:", err);
      setStatus("Failed");

      if (err.response?.data?.detail) {
        setMessage(err.response.data.detail);
      } else {
        setMessage(
          "Unable to complete the VAPT scan. Check that the backend is running."
        );
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = () => {
    if (!scanResult) {
      setMessage("Run a VAPT scan before downloading the report.");
      return;
    }

    const doc = new jsPDF();
    const target = scanResult.target || targetUrl || "—";
    const type = scanResult.scan_type || scanType;
    const httpStatus = scanResult.scan?.http_status ?? "—";
    const responseTime = scanResult.scan?.response_time_ms != null
      ? `${scanResult.scan.response_time_ms} ms`
      : "—";
    const totalFindings = scanResult.assessment?.findings_count ?? 0;
    const headers = scanResult.security_headers || [];
    const findings = scanResult.findings || [];

    doc.setFontSize(20);
    doc.text("SOC Platform", 20, 20);
    doc.setFontSize(14);
    doc.text("VAPT Security Assessment Report", 20, 31);
    doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 40);
    doc.line(20, 44, 190, 44);

    let y = 56;
    const addField = (label, value) => {
      doc.setFont("helvetica", "bold");
      doc.text(`${label}:`, 20, y);
      doc.setFont("helvetica", "normal");
      const lines = doc.splitTextToSize(String(value), 125);
      doc.text(lines, 65, y);
      y += Math.max(8, lines.length * 5 + 3);
    };

    addField("Target URL", target);
    addField("Scan Type", type === "quick" ? "Quick Scan" : "Detailed Scan");
    addField("Status", "Completed");
    addField("HTTP Status", httpStatus);
    addField("Response Time", responseTime);
    addField("Total Findings", totalFindings);

    y += 4;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text("Security Headers", 20, y);
    y += 8;
    doc.setFontSize(9);

    headers.forEach((item) => {
      if (y > 275) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "normal");
      doc.text(
        `${item.header}: ${item.present ? "Present" : "Missing"}`,
        25,
        y
      );
      y += 6;
    });

    y += 5;
    if (y > 255) {
      doc.addPage();
      y = 20;
    }

    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text("Findings", 20, y);
    y += 8;
    doc.setFontSize(9);

    if (findings.length === 0) {
      doc.setFont("helvetica", "normal");
      doc.text("No findings returned by the current assessment.", 25, y);
    } else {
      findings.forEach((finding, index) => {
        if (y > 255) {
          doc.addPage();
          y = 20;
        }
        doc.setFont("helvetica", "bold");
        const titleLines = doc.splitTextToSize(
          `${index + 1}. ${finding.severity || "UNKNOWN"} - ${finding.title || "Finding"}`,
          155
        );
        doc.text(titleLines, 25, y);
        y += titleLines.length * 5 + 2;
        doc.setFont("helvetica", "normal");

        const detail = [
          finding.tool_name ? `Tool: ${finding.tool_name}` : null,
          finding.cvss_score != null ? `CVSS: ${finding.cvss_score}` : null,
          finding.cve_id ? `CVE: ${finding.cve_id}` : null,
          finding.cwe_id ? `CWE: ${finding.cwe_id}` : null,
          finding.risk_level ? `Risk: ${finding.risk_level}` : null,
          finding.description ? `Description: ${finding.description}` : null,
          finding.remediation ? `Remediation: ${finding.remediation}` : null,
        ].filter(Boolean).join("\n");

        const lines = doc.splitTextToSize(detail || "No additional details.", 155);
        doc.text(lines, 30, y);
        y += lines.length * 5 + 5;
      });
    }

    if (y > 275) {
      doc.addPage();
      y = 20;
    }
    doc.setFontSize(8);
    doc.text("SOC Platform • Authorized security assessment report", 20, 285);

    const safeHost = target
      .replace(/^https?:\/\//i, "")
      .replace(/[^a-z0-9.-]+/gi, "-")
      .replace(/-+/g, "-")
      .slice(0, 50) || "target";

    doc.save(`SOC-${type === "quick" ? "Quick" : "Detailed"}-VAPT-Report-${safeHost}.pdf`);
  };

  const headers = scanResult?.security_headers || [];
  const findings = scanResult?.findings || [];
  const isDetailed = scanResult?.scan_type === "detailed" || scanType === "detailed";

  return (
    <div>
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">Security Workspace</p>
          <h1 className="mt-2 text-3xl font-bold">VAPT Testing</h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-500">
            Choose a fast security check or a detailed assessment for authorized targets.
          </p>
        </div>

        <div className="border border-white/10 bg-[#0d0d0d] px-4 py-3">
          <p className="text-[10px] uppercase tracking-wider text-gray-600">Scan Status</p>
          <p className={`mt-1 text-sm font-semibold ${
            status === "Scanning" ? "text-yellow-500" :
            status === "Completed" ? "text-green-500" :
            status === "Failed" ? "text-red-500" : "text-gray-400"
          }`}>
            {status}
          </p>
        </div>
      </div>

      <div className="mb-6 border border-red-600/20 bg-red-600/5 px-5 py-4">
        <p className="text-xs uppercase tracking-wider text-red-500">Authorized Testing Only</p>
        <p className="mt-1 text-sm leading-6 text-gray-500">
          Only scan systems and URLs that you own or have explicit permission to test.
        </p>
      </div>

      <div className="border border-white/10 bg-[#0d0d0d] p-6">
        <div className="border-b border-white/10 pb-5">
          <p className="text-sm font-semibold">New Security Assessment</p>
          <p className="mt-1 text-xs text-gray-600">
            Quick Scan is faster and shows essential results. Detailed Scan takes longer and shows richer findings.
          </p>
        </div>

        <div className="mt-6">
          <label className="text-xs uppercase tracking-wider text-gray-500">Target URL</label>
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://authorized-target.example.com"
            disabled={loading}
            className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600 disabled:opacity-50"
          />
        </div>

        <div className="mt-7 grid gap-4 md:grid-cols-2">
          <button
            onClick={() => handleStartScan("quick")}
            disabled={loading}
            className={`border px-6 py-5 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${
              scanType === "quick"
                ? "border-red-600 bg-red-600/10"
                : "border-white/10 bg-[#080808] hover:border-red-600/60"
            }`}
          >
            <p className="text-sm font-semibold text-white">Quick Scan</p>
            <p className="mt-2 text-xs leading-5 text-gray-500">
              Fast check with essential HTTP, security-header and high-priority vulnerability information.
            </p>
            <span className="mt-4 inline-block text-[10px] uppercase tracking-wider text-red-500">
              Faster
            </span>
          </button>

          <button
            onClick={() => handleStartScan("detailed")}
            disabled={loading}
            className={`border px-6 py-5 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${
              scanType === "detailed"
                ? "border-red-600 bg-red-600/10"
                : "border-white/10 bg-[#080808] hover:border-red-600/60"
            }`}
          >
            <p className="text-sm font-semibold text-white">Detailed Scan</p>
            <p className="mt-2 text-xs leading-5 text-gray-500">
              Extended scanner coverage with richer finding, CVE/CWE, CVSS, evidence and remediation information.
            </p>
            <span className="mt-4 inline-block text-[10px] uppercase tracking-wider text-red-500">
              In Detail
            </span>
          </button>
        </div>

        <div className="mt-7 flex flex-col gap-3 sm:flex-row sm:items-center">
          <button
            onClick={() => handleStartScan(scanType)}
            disabled={loading}
            className="bg-red-600 px-6 py-3 text-sm font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? "Scanning..." : `Run ${scanType === "quick" ? "Quick" : "Detailed"} Scan`}
          </button>

          <button
            onClick={handleDownloadReport}
            disabled={!scanResult || loading}
            className="border border-red-600 px-6 py-3 text-sm font-semibold text-red-500 transition hover:bg-red-600 hover:text-white disabled:cursor-not-allowed disabled:border-white/10 disabled:text-gray-700 disabled:hover:bg-transparent disabled:hover:text-gray-700"
          >
            Download Report
          </button>
        </div>

        {message && (
          <div className="mt-5 border border-white/10 bg-[#080808] px-4 py-3">
            <p className={`text-sm ${status === "Completed" ? "text-green-400" : status === "Failed" ? "text-red-400" : "text-gray-400"}`}>
              {message}
            </p>
          </div>
        )}
      </div>

      {scanResult && (
        <>
          <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <VAPTResultCard title="Scan Type" value={scanResult.scan_type === "detailed" ? "Detailed" : "Quick"} />
            <VAPTResultCard title="Total Findings" value={scanResult.assessment?.findings_count ?? 0} />
            <VAPTResultCard title="HTTP Status" value={scanResult.scan?.http_status ?? "—"} />
            <VAPTResultCard title="Response Time" value={scanResult.scan?.response_time_ms != null ? `${scanResult.scan.response_time_ms} ms` : "—"} />
          </div>

          {!isDetailed ? (
            <div className="mt-6 grid gap-6 md:grid-cols-2">
              <div className="border border-white/10 bg-[#0d0d0d] p-6">
                <p className="text-xs uppercase tracking-wider text-gray-500">Quick Summary</p>
                <div className="mt-5 space-y-4">
                  <VAPTInfo label="Target" value={scanResult.target || "—"} />
                  <VAPTInfo label="HTTPS" value={scanResult.scan?.https_enabled ? "Enabled" : "Not enabled"} />
                  <VAPTInfo label="Findings" value={scanResult.assessment?.findings_count ?? 0} />
                  <VAPTInfo label="Missing Headers" value={scanResult.summary?.missing_security_headers ?? 0} />
                </div>
              </div>
              <div className="border border-white/10 bg-[#0d0d0d] p-6">
                <p className="text-xs uppercase tracking-wider text-gray-500">Scanner Summary</p>
                <div className="mt-5 space-y-4">
                  <VAPTInfo label="Nuclei Status" value={scanResult.nuclei_scan?.status || "—"} />
                  <VAPTInfo label="Matched Results" value={scanResult.nuclei_scan?.matched_results ?? 0} />
                  <VAPTInfo label="Imported Findings" value={scanResult.nuclei_scan?.imported_findings?.length ?? 0} />
                  <VAPTInfo label="Executed Tools" value={(scanResult.security_scanners?.executed_tools || []).join(", ") || "—"} />
                </div>
              </div>
            </div>
          ) : (
            <>
              <div className="mt-6 border border-white/10 bg-[#0d0d0d]">
                <div className="border-b border-white/10 px-6 py-5">
                  <p className="text-sm font-semibold">Detailed Security Headers</p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-white/10 bg-[#0a0a0a] text-xs uppercase tracking-wider text-gray-600">
                      <tr><th className="px-6 py-4">Header</th><th className="px-6 py-4">Result</th><th className="px-6 py-4">Value</th></tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {headers.map((item) => (
                        <tr key={item.header}>
                          <td className="px-6 py-4 text-gray-300">{item.header}</td>
                          <td className={`px-6 py-4 ${item.present ? "text-green-500" : "text-red-400"}`}>{item.present ? "Present" : "Missing"}</td>
                          <td className="px-6 py-4 text-gray-500 break-all">{item.value || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="mt-6 border border-white/10 bg-[#0d0d0d] p-6">
                <div className="flex items-center justify-between gap-4 border-b border-white/10 pb-5">
                  <div>
                    <p className="text-sm font-semibold">Detailed Findings</p>
                    <p className="mt-1 text-xs text-gray-600">Full findings returned by the current assessment.</p>
                  </div>
                  <span className="text-xs text-gray-500">{findings.length} findings</span>
                </div>

                <div className="mt-5 space-y-4">
                  {findings.length === 0 ? (
                    <p className="py-8 text-center text-sm text-gray-600">No findings returned.</p>
                  ) : findings.map((finding, index) => (
                    <div key={`${finding.finding_id || finding.title}-${index}`} className="border border-white/10 bg-[#080808] p-5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-mono text-red-500">{finding.finding_id || `FIND-${index + 1}`}</span>
                        <span className="border border-red-600/30 bg-red-600/10 px-2 py-1 text-[10px] text-red-400">{finding.severity || "UNKNOWN"}</span>
                        <span className="border border-white/10 px-2 py-1 text-[10px] text-gray-500">{finding.risk_level || "—"}</span>
                      </div>
                      <h3 className="mt-3 text-lg font-semibold text-white">{finding.title || "Security Finding"}</h3>
                      <p className="mt-2 text-sm text-gray-500">{finding.description || finding.vulnerability || "No description available."}</p>
                      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4 text-xs">
                        <VAPTInfo label="Tool" value={finding.tool_name || "—"} />
                        <VAPTInfo label="CVSS" value={finding.cvss_score ?? "N/A"} />
                        <VAPTInfo label="CVE" value={finding.cve_id || "N/A"} />
                        <VAPTInfo label="CWE" value={finding.cwe_id || "N/A"} />
                      </div>
                      <div className="mt-4 grid gap-4 md:grid-cols-2">
                        <div><p className="text-[10px] uppercase tracking-wider text-gray-600">Evidence</p><p className="mt-2 whitespace-pre-wrap break-words text-xs leading-5 text-gray-500">{finding.evidence || "No evidence recorded."}</p></div>
                        <div><p className="text-[10px] uppercase tracking-wider text-gray-600">Remediation</p><p className="mt-2 whitespace-pre-wrap break-words text-xs leading-5 text-gray-500">{finding.remediation || "No remediation information recorded."}</p></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

function QATesting() {
  const [activeTab, setActiveTab] = useState("uiux");

  const [activeTarget, setActiveTarget] = useState(
    localStorage.getItem("active_vapt_target") || ""
  );

  const [activeTargetMeta, setActiveTargetMeta] = useState(() => {
    try {
      const saved = localStorage.getItem("active_vapt_target_meta");
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [uiuxChecks, setUiuxChecks] = useState({
    responsive: true,
    navigation: true,
    accessibility: false,
    performance: false,
    visual_consistency: true,
  });

  const [reviewNotes, setReviewNotes] = useState("");
  const [uiuxTargetReview, setUiuxTargetReview] = useState(null);
  const [uiuxTargetReviewLoading, setUiuxTargetReviewLoading] = useState(false);

  const [market, setMarket] = useState({
    product: "",
    industry: "",
    competitor: "",
    analysis_focus: "Customer Experience",
    notes: "",
  });

  const [saveLoading, setSaveLoading] = useState(false);
  const [saveMessage, setSaveMessage] = useState("");

  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");

  // Automatic API discovery
  const [apiDiscovery, setApiDiscovery] = useState(null);
  const [apiDiscoveryLoading, setApiDiscoveryLoading] = useState(false);
  const [apiDiscoveryError, setApiDiscoveryError] = useState("");

  // Automatic API CRUD suite
  const [apiSuite, setApiSuite] = useState(null);
  const [apiSuiteLoading, setApiSuiteLoading] = useState(false);
  const [apiSuiteError, setApiSuiteError] = useState("");

  // Regression testing
  const [regressionResult, setRegressionResult] = useState(null);
  const [regressionLoading, setRegressionLoading] = useState(false);
  const [regressionError, setRegressionError] = useState("");

  useEffect(() => {
    const syncTarget = () => {
      const target = localStorage.getItem("active_vapt_target") || "";
      setActiveTarget(target);

      try {
        const saved = localStorage.getItem("active_vapt_target_meta");
        setActiveTargetMeta(saved ? JSON.parse(saved) : null);
      } catch {
        setActiveTargetMeta(null);
      }

      // A new target invalidates target-specific API/Regression state.
      setApiDiscovery(null);
      setApiSuite(null);
      setRegressionResult(null);
    };

    window.addEventListener("storage", syncTarget);

    return () => {
      window.removeEventListener("storage", syncTarget);
    };
  }, []);

  const tabs = [
    { id: "uiux", label: "UI / UX" },
    { id: "api", label: "API Testing" },
    { id: "regression", label: "Regression Testing" },
    { id: "market", label: "Market Analysis" },
    { id: "history", label: "QA History" },
  ];

  const loadHistory = async () => {
    const token = localStorage.getItem("token");

    if (!token) {
      setHistoryError("Your session has expired. Please log in again.");
      return;
    }

    try {
      setHistoryLoading(true);
      setHistoryError("");

      const response = await axios.get(
        `${API_URL}/qa/history`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setHistory(response.data || []);
    } catch (err) {
      console.error("QA history error:", err);

      if (err.response?.data?.detail) {
        setHistoryError(err.response.data.detail);
      } else {
        setHistoryError("Unable to load QA history.");
      }
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const calculateUIUXScore = () => {
    const values = Object.values(uiuxChecks);

    if (!values.length) {
      return 0;
    }

    return Math.round(
      (values.filter(Boolean).length / values.length) * 100
    );
  };

  const getTokenConfig = () => {
    const token = localStorage.getItem("token");

    if (!token) {
      throw new Error("Your session has expired. Please log in again.");
    }

    return {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    };
  };

  const runUIUXTargetReview = async () => {
    setSaveMessage("");
    setUiuxTargetReview(null);

    if (!activeTarget) {
      setSaveMessage(
        "Complete a successful VAPT scan first. UI / UX review is linked to the active VAPT target."
      );
      return;
    }

    try {
      setUiuxTargetReviewLoading(true);

      const response = await axios.post(
        `${API_URL}/qa/uiux-test`,
        { target: activeTarget },
        getTokenConfig()
      );

      setUiuxTargetReview(response.data);

      setUiuxChecks({
        responsive: Boolean(response.data.checks?.responsive?.pass),
        navigation: Boolean(response.data.checks?.navigation?.pass),
        accessibility: Boolean(response.data.checks?.accessibility?.pass),
        performance: Boolean(response.data.checks?.performance?.pass),
        visual_consistency: Boolean(
          response.data.checks?.visual_consistency?.pass
        ),
      });

      setSaveMessage("Automated UI / UX target review completed.");
      await loadHistory();
    } catch (err) {
      console.error("UI/UX target review error:", err);

      if (err.response?.data?.detail) {
        setSaveMessage(err.response.data.detail);
      } else {
        setSaveMessage("Unable to review the active VAPT target.");
      }
    } finally {
      setUiuxTargetReviewLoading(false);
    }
  };

  const saveUIUXReview = async () => {
    setSaveMessage("");

    if (!activeTarget) {
      setSaveMessage(
        "Complete a successful VAPT scan before saving QA results."
      );
      return;
    }

    try {
      setSaveLoading(true);

      await axios.post(
        `${API_URL}/qa/uiux`,
        {
          responsive: uiuxChecks.responsive,
          navigation: uiuxChecks.navigation,
          accessibility: uiuxChecks.accessibility,
          performance: uiuxChecks.performance,
          visual_consistency: uiuxChecks.visual_consistency,
          uiux_score:
            uiuxTargetReview?.uiux_score ?? calculateUIUXScore(),
          review_notes: reviewNotes.trim() || null,
          target: activeTarget,
        },
        getTokenConfig()
      );

      setSaveMessage("UI / UX review saved successfully.");
      await loadHistory();
    } catch (err) {
      console.error("Save UI/UX error:", err);

      if (err.response?.data?.detail) {
        setSaveMessage(err.response.data.detail);
      } else {
        setSaveMessage("Unable to save the UI / UX review.");
      }
    } finally {
      setSaveLoading(false);
    }
  };

  const discoverAPIs = async () => {
    setApiDiscovery(null);
    setApiDiscoveryError("");

    if (!activeTarget) {
      setApiDiscoveryError(
        "Complete a successful VAPT scan first."
      );
      return;
    }

    try {
      setApiDiscoveryLoading(true);

      const response = await axios.post(
        `${API_URL}/qa/discover`,
        { target: activeTarget },
        getTokenConfig()
      );

      setApiDiscovery(response.data);
    } catch (err) {
      console.error("API discovery error:", err);

      if (err.response?.data?.detail) {
        setApiDiscoveryError(err.response.data.detail);
      } else {
        setApiDiscoveryError(
          "No API definition could be discovered from the active target."
        );
      }
    } finally {
      setApiDiscoveryLoading(false);
    }
  };

  const runFullAPISuite = async () => {
    setApiSuite(null);
    setApiSuiteError("");

    if (!activeTarget) {
      setApiSuiteError(
        "Complete a successful VAPT scan first."
      );
      return;
    }

    try {
      setApiSuiteLoading(true);

      const response = await axios.post(
        `${API_URL}/qa/run-api-suite`,
        { target: activeTarget },
        getTokenConfig()
      );

      setApiSuite(response.data);

      await loadHistory();
    } catch (err) {
      console.error("API suite error:", err);

      if (err.response?.data?.detail) {
        setApiSuiteError(err.response.data.detail);
      } else {
        setApiSuiteError("Automated API QA could not be completed.");
      }
    } finally {
      setApiSuiteLoading(false);
    }
  };

  const runRegression = async () => {
    setRegressionResult(null);
    setRegressionError("");

    if (!activeTarget) {
      setRegressionError(
        "Complete a successful VAPT scan first."
      );
      return;
    }

    const previousHistory = [...history];

    try {
      setRegressionLoading(true);

      const [uiuxResponse, apiResponse] = await Promise.all([
        axios.post(
          `${API_URL}/qa/uiux-test`,
          { target: activeTarget },
          getTokenConfig()
        ),
        axios.post(
          `${API_URL}/qa/run-api-suite`,
          { target: activeTarget },
          getTokenConfig()
        ),
      ]);

      const currentUIUXScore = uiuxResponse.data?.uiux_score ?? null;
      const currentApiPassed = apiResponse.data?.passed_tests ?? 0;
      const currentApiTotal = apiResponse.data?.total_tests ?? 0;

      const targetHistory = previousHistory.filter(
        (record) =>
          record.target === activeTarget
      );

      const previousUIUX = targetHistory.find(
        (record) =>
          record.test_type === "uiux"
          && typeof record.uiux_score === "number"
      );

      const previousAPI = targetHistory.find(
        (record) =>
          record.test_type === "api"
          && record.status_code != null
      );

      let previousApiPassed = null;
      let previousApiTotal = null;

      if (previousAPI?.response_body) {
        try {
          const parsed = JSON.parse(previousAPI.response_body);

          const steps = Array.isArray(parsed.steps)
            ? parsed.steps
            : [];

          previousApiPassed = steps.filter(
            (step) => step.passed
          ).length;

          previousApiTotal = steps.length;
        } catch {
          previousApiPassed = null;
          previousApiTotal = null;
        }
      }

      const uiuxChanged =
        previousUIUX
          ? currentUIUXScore !== previousUIUX.uiux_score
          : null;

      const apiChanged =
        previousApiPassed !== null
          && previousApiTotal !== null
          ? (
              currentApiPassed !== previousApiPassed
              || currentApiTotal !== previousApiTotal
            )
          : null;

      const hasRegression =
        uiuxChanged === true
        && currentUIUXScore < previousUIUX.uiux_score;

      const apiRegression =
        apiChanged === true
        && currentApiPassed <
          (previousApiPassed ?? currentApiPassed);

      const overall =
        hasRegression || apiRegression
          ? "REGRESSION DETECTED"
          : "NO REGRESSION DETECTED";

      setRegressionResult({
        target: activeTarget,
        overall,
        previous_uiux_score:
          previousUIUX?.uiux_score ?? null,
        current_uiux_score: currentUIUXScore,
        previous_api_passed: previousApiPassed,
        previous_api_total: previousApiTotal,
        current_api_passed: currentApiPassed,
        current_api_total: currentApiTotal,
        uiux_changed: uiuxChanged,
        api_changed: apiChanged,
        uiux_regression: hasRegression,
        api_regression: apiRegression,
      });

      await loadHistory();
    } catch (err) {
      console.error("Regression test error:", err);

      if (err.response?.data?.detail) {
        setRegressionError(err.response.data.detail);
      } else {
        setRegressionError("Regression testing could not be completed.");
      }
    } finally {
      setRegressionLoading(false);
    }
  };

  const saveMarketAnalysis = async () => {
    setSaveMessage("");

    if (!activeTarget) {
      setSaveMessage(
        "Complete a successful VAPT scan before saving market analysis."
      );
      return;
    }

    try {
      setSaveLoading(true);

      await axios.post(
        `${API_URL}/qa/market`,
        {
          product: market.product.trim() || null,
          industry: market.industry.trim() || null,
          competitor: market.competitor.trim() || null,
          analysis_focus: market.analysis_focus,
          market_notes: market.notes.trim() || null,
          target: activeTarget,
        },
        getTokenConfig()
      );

      setSaveMessage("Market analysis saved successfully.");
      await loadHistory();
    } catch (err) {
      console.error("Save market analysis error:", err);

      if (err.response?.data?.detail) {
        setSaveMessage(err.response.data.detail);
      } else {
        setSaveMessage("Unable to save the market analysis.");
      }
    } finally {
      setSaveLoading(false);
    }
  };

  const automatedScore =
    uiuxTargetReview?.uiux_score ?? null;

  return (
    <div>
      {/* HEADER */}
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            Quality Assurance
          </p>

          <h1 className="mt-2 text-3xl font-bold">
            QA Testing
          </h1>

          <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-500">
            Automatically validate the active VAPT target across UI/UX,
            API behaviour and regression changes, while keeping market
            analysis and reviewer notes available.
          </p>
        </div>

        <div className="border border-white/10 bg-[#0d0d0d] px-4 py-3">
          <p className="text-[10px] uppercase tracking-wider text-gray-600">
            QA Workspace
          </p>

          <p className="mt-1 text-sm font-semibold text-green-500">
            Ready
          </p>
        </div>
      </div>

      {/* ACTIVE TARGET */}
      <div className="mb-6 border border-red-600/20 bg-red-600/5 p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <p className="text-[10px] uppercase tracking-[0.2em] text-red-500">
              Active VAPT Target
            </p>

            <p className="mt-2 break-all text-base font-semibold text-white">
              {activeTarget || "No successful VAPT target"}
            </p>

            {activeTargetMeta && (
              <p className="mt-2 text-xs text-gray-600">
                VAPT Status:
                <span className="ml-1 text-green-500">
                  {activeTargetMeta.status || "Completed"}
                </span>
                {activeTargetMeta.scenario && (
                  <>
                    <span className="mx-2 text-gray-800">•</span>
                    Scenario: {activeTargetMeta.scenario}
                  </>
                )}
                {activeTargetMeta.lastScan && (
                  <>
                    <span className="mx-2 text-gray-800">•</span>
                    Last Scan: {activeTargetMeta.lastScan}
                  </>
                )}
              </p>
            )}

            {!activeTarget && (
              <p className="mt-2 text-xs leading-5 text-gray-600">
                Complete a successful VAPT scan before running automated QA.
              </p>
            )}
          </div>

          <div className="border border-white/10 bg-[#080808] px-4 py-3 text-xs">
            <p className="text-[10px] uppercase tracking-wider text-gray-600">
              QA Context
            </p>

            <p className="mt-1 text-green-500">
              {activeTarget ? "VAPT target linked" : "Awaiting target"}
            </p>
          </div>
        </div>
      </div>

      {/* TABS */}
      <div className="border-b border-white/10">
        <div className="flex flex-wrap gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id);
                setSaveMessage("");
              }}
              className={`border-b-2 px-5 py-3 text-sm transition ${
                activeTab === tab.id
                  ? "border-red-600 text-white"
                  : "border-transparent text-gray-600 hover:text-gray-300"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* SAVE MESSAGE */}
      {saveMessage && (
        <div className="mt-5 border border-white/10 bg-[#0d0d0d] px-5 py-4">
          <p className="text-sm text-gray-300">
            {saveMessage}
          </p>
        </div>
      )}

      {/* ==================================================
          UI / UX
      ================================================== */}
      {activeTab === "uiux" && (
        <div className="mt-6">
          <div className="grid gap-6 xl:grid-cols-3">
            <div className="border border-white/10 bg-[#0d0d0d] p-6 xl:col-span-2">
              <div className="border-b border-white/10 pb-5">
                <p className="text-sm font-semibold">
                  UI / UX Target Review
                </p>

                <p className="mt-1 text-xs leading-5 text-gray-600">
                  The active VAPT target is reviewed automatically. Manual
                  checklist controls remain available only for human
                  validation and reviewer notes.
                </p>
              </div>

              <div className="mt-6 border border-red-600/20 bg-red-600/5 p-5">
                <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                  <div className="min-w-0">
                    <p className="text-[10px] uppercase tracking-[0.2em] text-red-500">
                      Automated Target Review
                    </p>

                    <p className="mt-2 break-all text-sm font-semibold text-white">
                      {activeTarget || "No active VAPT target"}
                    </p>

                    <p className="mt-2 text-xs leading-5 text-gray-600">
                      The backend evaluates responsive metadata,
                      navigation, accessibility indicators, initial
                      response performance and document structure.
                    </p>
                  </div>

                  <button
                    onClick={runUIUXTargetReview}
                    disabled={!activeTarget || uiuxTargetReviewLoading}
                    className="shrink-0 bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {uiuxTargetReviewLoading
                      ? "Reviewing..."
                      : "Review Target URL"}
                  </button>
                </div>

                {uiuxTargetReview && (
                  <div className="mt-5 grid gap-3 md:grid-cols-2">
                    {Object.entries(
                      uiuxTargetReview.checks || {}
                    ).map(([key, item]) => (
                      <div
                        key={key}
                        className="border border-white/10 bg-[#080808] p-4"
                      >
                        <div className="flex items-center justify-between gap-4">
                          <p className="text-sm text-gray-300">
                            {item.label || key}
                          </p>

                          <span
                            className={`text-xs font-semibold ${
                              item.pass
                                ? "text-green-500"
                                : "text-red-400"
                            }`}
                          >
                            {item.pass ? "PASS" : "REVIEW"}
                          </span>
                        </div>

                        <p className="mt-2 text-xs leading-5 text-gray-600">
                          {item.details || "No additional details."}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="mt-6 flex items-center justify-between border-b border-white/10 pb-3">
                <p className="text-[10px] uppercase tracking-wider text-gray-600">
                  Reviewer Checklist
                </p>

                <p className="text-[10px] text-gray-700">
                  Optional human validation
                </p>
              </div>

              <div className="mt-4 space-y-3">
                <QACheckRow
                  label="Responsive layout"
                  description="Verify layout across desktop, tablet and mobile sizes."
                  checked={uiuxChecks.responsive}
                  onChange={(value) =>
                    setUiuxChecks((prev) => ({
                      ...prev,
                      responsive: value,
                    }))
                  }
                />

                <QACheckRow
                  label="Navigation consistency"
                  description="Confirm navigation, labels and user flows behave consistently."
                  checked={uiuxChecks.navigation}
                  onChange={(value) =>
                    setUiuxChecks((prev) => ({
                      ...prev,
                      navigation: value,
                    }))
                  }
                />

                <QACheckRow
                  label="Accessibility"
                  description="Review keyboard access, labels, contrast and semantic structure."
                  checked={uiuxChecks.accessibility}
                  onChange={(value) =>
                    setUiuxChecks((prev) => ({
                      ...prev,
                      accessibility: value,
                    }))
                  }
                />

                <QACheckRow
                  label="Performance"
                  description="Review perceived loading time and major UI delays."
                  checked={uiuxChecks.performance}
                  onChange={(value) =>
                    setUiuxChecks((prev) => ({
                      ...prev,
                      performance: value,
                    }))
                  }
                />

                <QACheckRow
                  label="Visual consistency"
                  description="Check spacing, typography, components and feedback states."
                  checked={uiuxChecks.visual_consistency}
                  onChange={(value) =>
                    setUiuxChecks((prev) => ({
                      ...prev,
                      visual_consistency: value,
                    }))
                  }
                />
              </div>
            </div>

            <div className="border border-white/10 bg-[#0d0d0d] p-6">
              <p className="text-sm font-semibold">
                UI / UX Score
              </p>

              <p className="mt-6 text-6xl font-bold">
                {automatedScore ?? "—"}
                {automatedScore !== null && (
                  <span className="text-2xl text-red-500">%</span>
                )}
              </p>

              <div className="mt-5 h-1.5 bg-white/10">
                <div
                  className="h-full bg-red-600 transition-all"
                  style={{
                    width: `${automatedScore ?? 0}%`,
                  }}
                />
              </div>

              <p className="mt-5 text-xs leading-6 text-gray-600">
                The displayed score is generated from the active VAPT target.
              </p>
            </div>
          </div>

          <div className="mt-6 border border-white/10 bg-[#0d0d0d] p-6">
            <p className="text-sm font-semibold">
              Review Notes
            </p>

            <p className="mt-1 text-xs text-gray-600">
              Notes are stored in PostgreSQL with the QA record and remain
              associated with this VAPT target.
            </p>

            <textarea
              value={reviewNotes}
              onChange={(e) => setReviewNotes(e.target.value)}
              placeholder="Enter UI defects, usability observations, accessibility issues or recommendations..."
              className="mt-4 min-h-[160px] w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />

            <button
              onClick={saveUIUXReview}
              disabled={saveLoading || !activeTarget}
              className="mt-5 bg-red-600 px-6 py-3 text-sm font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saveLoading ? "Saving..." : "Save UI / UX Review"}
            </button>
          </div>
        </div>
      )}

      {/* ==================================================
          API TESTING
      ================================================== */}
      {activeTab === "api" && (
        <div className="mt-6 space-y-6">
          <div className="border border-white/10 bg-[#0d0d0d] p-6">
            <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-sm font-semibold">
                  Automatic API Discovery
                </p>

                <p className="mt-1 text-xs leading-5 text-gray-600">
                  The active VAPT target is used automatically to locate its
                  OpenAPI/Swagger definition. No request URL or JSON body is
                  required here.
                </p>
              </div>

              <button
                onClick={discoverAPIs}
                disabled={!activeTarget || apiDiscoveryLoading}
                className="bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {apiDiscoveryLoading
                  ? "Discovering..."
                  : "Discover APIs"}
              </button>
            </div>

            <div className="mt-5 border border-white/10 bg-[#080808] p-4">
              <p className="text-[10px] uppercase tracking-wider text-gray-600">
                Active Target
              </p>

              <p className="mt-2 break-all text-sm text-white">
                {activeTarget || "No active target"}
              </p>

              {apiDiscovery && (
                <div className="mt-4 grid gap-4 sm:grid-cols-3">
                  <QAVKPI
                    label="OpenAPI Source"
                    value={apiDiscovery.openapi_url || "—"}
                  />

                  <QAVKPI
                    label="API Version"
                    value={apiDiscovery.openapi_version || "—"}
                  />

                  <QAVKPI
                    label="Discovered Endpoints"
                    value={apiDiscovery.endpoint_count}
                  />
                </div>
              )}
            </div>

            {apiDiscoveryError && (
              <div className="mt-4 border border-red-600/20 bg-red-600/5 px-4 py-3">
                <p className="text-sm text-red-400">
                  {apiDiscoveryError}
                </p>
              </div>
            )}

            {apiDiscovery && (
              <div className="mt-5 overflow-hidden border border-white/10">
                <div className="grid grid-cols-[1fr_140px_1.4fr] border-b border-white/10 bg-[#080808] px-4 py-3 text-[10px] uppercase tracking-wider text-gray-600">
                  <span>Endpoint</span>
                  <span>Methods</span>
                  <span>Summary</span>
                </div>

                <div className="divide-y divide-white/5">
                  {(apiDiscovery.endpoints || []).map((endpoint) => (
                    <div
                      key={endpoint.path}
                      className="grid grid-cols-[1fr_140px_1.4fr] gap-4 px-4 py-4 text-xs"
                    >
                      <span className="break-all font-mono text-gray-300">
                        {endpoint.path}
                      </span>

                      <span className="text-green-500">
                        {(endpoint.methods || []).join(", ")}
                      </span>

                      <span className="text-gray-600">
                        {endpoint.summary || "—"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="grid gap-6 xl:grid-cols-3">
            <div className="border border-white/10 bg-[#0d0d0d] p-6 xl:col-span-2">
              <p className="text-sm font-semibold">
                Automatic GET / POST / PUT / DELETE QA
              </p>

              <p className="mt-1 text-xs leading-5 text-gray-600">
                The platform creates temporary QA test data and executes a
                safe CRUD sequence. This avoids manually entering request
                bodies or modifying real user records.
              </p>

              <div className="mt-6 grid gap-3 sm:grid-cols-4">
                {["POST", "PUT", "GET", "DELETE"].map((verb) => (
                  <div
                    key={verb}
                    className="border border-white/10 bg-[#080808] p-4"
                  >
                    <p className="text-xs font-semibold text-white">
                      {verb}
                    </p>

                    <p className="mt-2 text-[10px] uppercase tracking-wider text-gray-600">
                      Automated
                    </p>
                  </div>
                ))}
              </div>

              <button
                onClick={runFullAPISuite}
                disabled={!activeTarget || apiSuiteLoading}
                className="mt-6 bg-red-600 px-6 py-3 text-sm font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {apiSuiteLoading
                  ? "Running API QA..."
                  : "Run Full API QA"}
              </button>

              {apiSuiteError && (
                <div className="mt-4 border border-red-600/20 bg-red-600/5 px-4 py-3">
                  <p className="text-sm text-red-400">
                    {apiSuiteError}
                  </p>
                </div>
              )}

              {apiSuite && (
                <div className="mt-6">
                  <div className="grid gap-4 sm:grid-cols-3">
                    <QAVKPI
                      label="Overall Status"
                      value={apiSuite.overall_status}
                    />

                    <QAVKPI
                      label="Passed"
                      value={`${apiSuite.passed_tests}/${apiSuite.total_tests}`}
                    />

                    <QAVKPI
                      label="Failed"
                      value={apiSuite.failed_tests}
                    />
                  </div>

                  <div className="mt-5 divide-y divide-white/5 border border-white/10">
                    {(apiSuite.steps || []).map((step, index) => (
                      <div
                        key={`${step.method}-${step.endpoint}-${index}`}
                        className="grid gap-3 p-4 md:grid-cols-[100px_1fr_90px_100px]"
                      >
                        <span className="text-xs font-semibold text-white">
                          {step.method}
                        </span>

                        <span className="break-all font-mono text-xs text-gray-500">
                          {step.endpoint}
                        </span>

                        <span className="text-xs text-gray-500">
                          {step.status_code ?? "—"}
                        </span>

                        <span
                          className={`text-xs font-semibold ${
                            step.passed
                              ? "text-green-500"
                              : "text-red-400"
                          }`}
                        >
                          {step.passed ? "PASS" : "FAIL"}
                        </span>

                        <p className="text-xs leading-5 text-gray-600 md:col-span-4">
                          {step.message}
                          {step.response_time_ms != null
                            ? ` • ${step.response_time_ms} ms`
                            : ""}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="border border-white/10 bg-[#0d0d0d] p-6">
              <p className="text-sm font-semibold">
                API QA Target
              </p>

              <div className="mt-6 space-y-5">
                <QAVKPI
                  label="Target"
                  value={activeTarget || "—"}
                />

                <QAVKPI
                  label="API Discovery"
                  value={
                    apiDiscovery
                      ? `${apiDiscovery.endpoint_count} endpoints`
                      : "Not run"
                  }
                />

                <QAVKPI
                  label="CRUD QA"
                  value={
                    apiSuite
                      ? apiSuite.overall_status
                      : "Not run"
                  }
                />

                <QAVKPI
                  label="Request Input"
                  value="Automatic"
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================
          REGRESSION
      ================================================== */}
      {activeTab === "regression" && (
        <div className="mt-6">
          <div className="border border-white/10 bg-[#0d0d0d] p-6">
            <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-sm font-semibold">
                  Regression Testing
                </p>

                <p className="mt-1 text-xs leading-5 text-gray-600">
                  Re-run the active target's UI/UX and automated API suite,
                  then compare the result with the previous QA baseline for
                  the same target.
                </p>
              </div>

              <button
                onClick={runRegression}
                disabled={!activeTarget || regressionLoading}
                className="bg-red-600 px-5 py-3 text-xs font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {regressionLoading
                  ? "Running Regression..."
                  : "Run Regression Test"}
              </button>
            </div>

            <div className="mt-6 border border-red-600/20 bg-red-600/5 p-5">
              <p className="text-[10px] uppercase tracking-[0.2em] text-red-500">
                Regression Target
              </p>

              <p className="mt-2 break-all text-sm font-semibold text-white">
                {activeTarget || "No active target"}
              </p>
            </div>

            {regressionError && (
              <div className="mt-5 border border-red-600/20 bg-red-600/5 px-4 py-3">
                <p className="text-sm text-red-400">
                  {regressionError}
                </p>
              </div>
            )}

            {regressionResult && (
              <div className="mt-6">
                <div className="border border-white/10 bg-[#080808] p-5">
                  <p
                    className={`text-lg font-semibold ${
                      regressionResult.overall ===
                      "NO REGRESSION DETECTED"
                        ? "text-green-500"
                        : "text-red-400"
                    }`}
                  >
                    {regressionResult.overall}
                  </p>
                </div>

                <div className="mt-5 grid gap-4 md:grid-cols-2">
                  <div className="border border-white/10 bg-[#080808] p-5">
                    <p className="text-[10px] uppercase tracking-wider text-gray-600">
                      UI / UX Baseline
                    </p>

                    <p className="mt-2 text-2xl font-bold text-white">
                      {regressionResult.previous_uiux_score ?? "—"}
                      {regressionResult.previous_uiux_score != null && "%"}
                    </p>

                    <p className="mt-2 text-xs text-gray-600">
                      Current:{" "}
                      {regressionResult.current_uiux_score ?? "—"}
                      {regressionResult.current_uiux_score != null && "%"}
                    </p>

                    <p
                      className={`mt-3 text-xs font-semibold ${
                        regressionResult.uiux_regression
                          ? "text-red-400"
                          : "text-green-500"
                      }`}
                    >
                      {regressionResult.uiux_regression
                        ? "UI/UX regression detected"
                        : regressionResult.uiux_changed === null
                        ? "No previous UI/UX baseline"
                        : "No UI/UX regression detected"}
                    </p>
                  </div>

                  <div className="border border-white/10 bg-[#080808] p-5">
                    <p className="text-[10px] uppercase tracking-wider text-gray-600">
                      API Baseline
                    </p>

                    <p className="mt-2 text-2xl font-bold text-white">
                      {regressionResult.previous_api_passed != null
                        ? `${regressionResult.previous_api_passed}/${regressionResult.previous_api_total}`
                        : "—"}
                    </p>

                    <p className="mt-2 text-xs text-gray-600">
                      Current:{" "}
                      {regressionResult.current_api_passed}/
                      {regressionResult.current_api_total}
                    </p>

                    <p
                      className={`mt-3 text-xs font-semibold ${
                        regressionResult.api_regression
                          ? "text-red-400"
                          : "text-green-500"
                      }`}
                    >
                      {regressionResult.api_regression
                        ? "API regression detected"
                        : regressionResult.api_changed === null
                        ? "No previous API baseline"
                        : "No API regression detected"}
                    </p>
                  </div>
                </div>

                <div className="mt-5 border border-white/10 bg-[#080808] p-5">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    Regression Checks
                  </p>

                  <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                    <QAVKPI
                      label="Target"
                      value={regressionResult.target}
                    />

                    <QAVKPI
                      label="UI / UX Changed"
                      value={
                        regressionResult.uiux_changed === null
                          ? "Baseline unavailable"
                          : regressionResult.uiux_changed
                          ? "Yes"
                          : "No"
                      }
                    />

                    <QAVKPI
                      label="API Changed"
                      value={
                        regressionResult.api_changed === null
                          ? "Baseline unavailable"
                          : regressionResult.api_changed
                          ? "Yes"
                          : "No"
                      }
                    />

                    <QAVKPI
                      label="Overall"
                      value={regressionResult.overall}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================
          MARKET ANALYSIS
      ================================================== */}
      {activeTab === "market" && (
        <div className="mt-6">
          <div className="grid gap-6 xl:grid-cols-3">
            <div className="border border-white/10 bg-[#0d0d0d] p-6 xl:col-span-2">
              <p className="text-sm font-semibold">
                Market Analysis
              </p>

              <p className="mt-1 text-xs leading-5 text-gray-600">
                Record product and market observations for the active VAPT
                target. These notes are stored in PostgreSQL.
              </p>

              <div className="mt-6 grid gap-5 md:grid-cols-2">
                <QATextField
                  label="Product"
                  value={market.product}
                  onChange={(value) =>
                    setMarket((prev) => ({
                      ...prev,
                      product: value,
                    }))
                  }
                  placeholder="Enter product or service"
                />

                <QATextField
                  label="Industry"
                  value={market.industry}
                  onChange={(value) =>
                    setMarket((prev) => ({
                      ...prev,
                      industry: value,
                    }))
                  }
                  placeholder="Enter industry"
                />

                <QATextField
                  label="Competitor"
                  value={market.competitor}
                  onChange={(value) =>
                    setMarket((prev) => ({
                      ...prev,
                      competitor: value,
                    }))
                  }
                  placeholder="Enter competitor"
                />

                <div>
                  <label className="text-[10px] uppercase tracking-wider text-gray-600">
                    Analysis Focus
                  </label>

                  <select
                    value={market.analysis_focus}
                    onChange={(e) =>
                      setMarket((prev) => ({
                        ...prev,
                        analysis_focus: e.target.value,
                      }))
                    }
                    className="mt-3 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none focus:border-red-600"
                  >
                    <option value="Customer Experience">
                      Customer Experience
                    </option>
                    <option value="Competitive Position">
                      Competitive Position
                    </option>
                    <option value="Product Quality">
                      Product Quality
                    </option>
                    <option value="Market Opportunity">
                      Market Opportunity
                    </option>
                  </select>
                </div>

                <div className="md:col-span-2">
                  <label className="text-[10px] uppercase tracking-wider text-gray-600">
                    Market Notes
                  </label>

                  <textarea
                    value={market.notes}
                    onChange={(e) =>
                      setMarket((prev) => ({
                        ...prev,
                        notes: e.target.value,
                      }))
                    }
                    placeholder="Enter customer feedback, competitor observations, product gaps, market opportunities or recommendations..."
                    className="mt-3 min-h-[170px] w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
                  />
                </div>
              </div>

              <button
                onClick={saveMarketAnalysis}
                disabled={saveLoading || !activeTarget}
                className="mt-5 bg-red-600 px-6 py-3 text-sm font-semibold transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {saveLoading ? "Saving..." : "Save Market Analysis"}
              </button>
            </div>

            <div className="border border-white/10 bg-[#0d0d0d] p-6">
              <p className="text-sm font-semibold">
                Analysis Snapshot
              </p>

              <div className="mt-6 space-y-5">
                <QAVKPI
                  label="Target"
                  value={activeTarget || "—"}
                />

                <QAVKPI
                  label="Product"
                  value={market.product || "Not specified"}
                />

                <QAVKPI
                  label="Industry"
                  value={market.industry || "Not specified"}
                />

                <QAVKPI
                  label="Competitor"
                  value={market.competitor || "Not specified"}
                />

                <QAVKPI
                  label="Focus"
                  value={market.analysis_focus}
                />

                <QAVKPI
                  label="Notes"
                  value={
                    market.notes
                      ? `${market.notes.length} characters`
                      : "No notes yet"
                  }
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================
          HISTORY
      ================================================== */}
      {activeTab === "history" && (
        <div className="mt-6 border border-white/10 bg-[#0d0d0d]">
          <div className="flex flex-col gap-3 border-b border-white/10 px-6 py-5 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-sm font-semibold">
                QA History
              </p>

              <p className="mt-1 text-xs text-gray-600">
                Saved QA records belonging to the logged-in User/Client.
              </p>
            </div>

            <button
              onClick={loadHistory}
              disabled={historyLoading}
              className="border border-white/10 px-4 py-2 text-xs text-gray-400 hover:border-white/30 hover:text-white disabled:opacity-50"
            >
              {historyLoading ? "Refreshing..." : "Refresh"}
            </button>
          </div>

          {historyError && (
            <div className="border-b border-red-600/20 bg-red-600/5 px-6 py-4">
              <p className="text-sm text-red-400">
                {historyError}
              </p>
            </div>
          )}

          {historyLoading ? (
            <div className="px-6 py-12 text-center text-sm text-gray-600">
              Loading QA history...
            </div>
          ) : history.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm text-gray-600">
              No saved QA records yet.
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {history.map((record) => (
                <div
                  key={record.id}
                  className="p-6 transition hover:bg-white/[0.02]"
                >
                  <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div>
                      <p className="text-sm font-semibold text-white">
                        {record.test_type === "uiux"
                          ? "UI / UX Review"
                          : record.test_type === "api"
                          ? "Automated API QA"
                          : "Market Analysis"}
                      </p>

                      <p className="mt-1 text-xs text-gray-600">
                        Saved on{" "}
                        {record.created_at
                          ? new Date(
                              record.created_at
                            ).toLocaleString()
                          : "—"}
                      </p>
                    </div>

                    <div className="text-right">
                      {record.test_type === "uiux" && (
                        <span className="bg-red-600/10 px-3 py-1 text-xs text-red-400">
                          Score: {record.uiux_score ?? 0}%
                        </span>
                      )}

                      {record.test_type === "api" && (
                        <span className="bg-green-600/10 px-3 py-1 text-xs text-green-400">
                          API: {record.status_code ?? "—"}
                        </span>
                      )}
                    </div>
                  </div>

                  {record.test_type === "uiux" ? (
                    <div className="mt-5 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
                      <QAVKPI
                        label="Responsive"
                        value={
                          record.responsive ? "Pass" : "Review"
                        }
                      />

                      <QAVKPI
                        label="Navigation"
                        value={
                          record.navigation ? "Pass" : "Review"
                        }
                      />

                      <QAVKPI
                        label="Accessibility"
                        value={
                          record.accessibility ? "Pass" : "Review"
                        }
                      />

                      <QAVKPI
                        label="Performance"
                        value={
                          record.performance ? "Pass" : "Review"
                        }
                      />

                      <div className="sm:col-span-2 xl:col-span-4">
                        <p className="text-[10px] uppercase tracking-wider text-gray-600">
                          Target
                        </p>

                        <p className="mt-2 break-all text-sm text-gray-400">
                          {record.target || "No target recorded"}
                        </p>
                      </div>

                      <div className="sm:col-span-2 xl:col-span-4">
                        <p className="text-[10px] uppercase tracking-wider text-gray-600">
                          Review Notes
                        </p>

                        <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-400">
                          {record.review_notes || "No review notes."}
                        </p>
                      </div>
                    </div>
                  ) : record.test_type === "api" ? (
                    <div className="mt-5 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
                      <QAVKPI
                        label="Target"
                        value={record.target || "—"}
                      />

                      <QAVKPI
                        label="Method"
                        value={record.method || "—"}
                      />

                      <QAVKPI
                        label="Status"
                        value={record.status_code ?? "—"}
                      />

                      <QAVKPI
                        label="Duration"
                        value={
                          record.response_time_ms != null
                            ? `${record.response_time_ms} ms`
                            : "—"
                        }
                      />

                      <div className="sm:col-span-2 xl:col-span-4">
                        <p className="text-[10px] uppercase tracking-wider text-gray-600">
                          API Result
                        </p>

                        <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words border border-white/10 bg-[#080808] p-4 font-mono text-xs leading-5 text-gray-500">
                          {record.response_body || "No API result stored."}
                        </pre>
                      </div>
                    </div>
                  ) : (
                    <div className="mt-5 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
                      <QAVKPI
                        label="Product"
                        value={record.product || "—"}
                      />

                      <QAVKPI
                        label="Industry"
                        value={record.industry || "—"}
                      />

                      <QAVKPI
                        label="Competitor"
                        value={record.competitor || "—"}
                      />

                      <QAVKPI
                        label="Focus"
                        value={record.analysis_focus || "—"}
                      />

                      <div className="sm:col-span-2 xl:col-span-4">
                        <p className="text-[10px] uppercase tracking-wider text-gray-600">
                          Target
                        </p>

                        <p className="mt-2 break-all text-sm text-gray-400">
                          {record.target || "No target recorded"}
                        </p>
                      </div>

                      <div className="sm:col-span-2 xl:col-span-4">
                        <p className="text-[10px] uppercase tracking-wider text-gray-600">
                          Market Notes
                        </p>

                        <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-400">
                          {record.market_notes || "No market notes."}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* COVERAGE */}
      <div className="mt-8">
        <div className="mb-5">
          <p className="text-xs uppercase tracking-[0.25em] text-red-500">
            QA Coverage
          </p>

          <h2 className="mt-2 text-xl font-semibold">
            Quality checks in this workspace
          </h2>
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <QACapability
            number="01"
            title="UI / UX"
            description="Automatically review the active target and keep reviewer notes for human validation."
          />

          <QACapability
            number="02"
            title="API QA"
            description="Discover APIs and run the safe POST, PUT, GET and DELETE QA workflow."
          />

          <QACapability
            number="03"
            title="Regression"
            description="Compare current UI/UX and API results against the previous target baseline."
          />

          <QACapability
            number="04"
            title="Market Analysis"
            description="Capture product, industry and competitive context for quality and product review."
          />
        </div>
      </div>
    </div>
  );
}


// QA CHECK ROW
// ==================================================
function QACheckRow({
  label,
  description,
  checked,
  onChange,
}) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-5 border border-white/10 bg-[#080808] p-5 transition hover:border-red-600/30">
      <div>
        <p className="text-sm font-medium">
          {label}
        </p>

        <p className="mt-1 max-w-2xl text-xs leading-5 text-gray-600">
          {description}
        </p>
      </div>

      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 h-4 w-4 accent-red-600"
      />
    </label>
  );
}


// ==================================================
// QA KPI
// ==================================================
function QAVKPI({
  label,
  value,
}) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <p className="mt-1 break-words text-sm text-gray-300">
        {value}
      </p>
    </div>
  );
}


// ==================================================
// QA TEXT FIELD
// ==================================================
function QATextField({
  label,
  value,
  onChange,
  placeholder,
}) {
  return (
    <div>
      <label className="text-[10px] uppercase tracking-wider text-gray-600">
        {label}
      </label>

      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
      />
    </div>
  );
}


// ==================================================
// QA CAPABILITY
// ==================================================
function QACapability({
  number,
  title,
  description,
}) {
  return (
    <div className="border border-white/10 bg-[#0d0d0d] p-6 transition hover:border-red-600/30">
      <span className="text-xs text-red-500">
        {number}
      </span>

      <h3 className="mt-7 text-base font-semibold">
        {title}
      </h3>

      <p className="mt-2 text-sm leading-6 text-gray-600">
        {description}
      </p>
    </div>
  );
}


// ==================================================
// VAPT RESULT CARD
// ==================================================
function VAPTResultCard({ title, value, critical }) {
  return (
    <div
      className={`border bg-[#0d0d0d] p-5 ${
        critical ? "border-red-600/30" : "border-white/10"
      }`}
    >
      <p className="text-xs uppercase tracking-wider text-gray-600">
        {title}
      </p>

      <p
        className={`mt-4 text-3xl font-bold ${
          critical ? "text-red-500" : "text-white"
        }`}
      >
        {value}
      </p>
    </div>
  );
}


// ==================================================
// VAPT INFO
// ==================================================
function VAPTInfo({ label, value }) {
  return (
    <div>

      <p className="text-[10px] uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <p className="mt-1 break-words text-sm text-gray-300">
        {value}
      </p>

    </div>
  );
}


// ==================================================
// VAPT STAGE
// ==================================================
function VAPTStage({
  number,
  title,
  description,
  active,
}) {
  return (
    <div className="border-b border-white/10 p-6 last:border-b-0 md:border-b-0 md:border-r md:last:border-r-0">

      <div className="flex items-center justify-between">

        <span
          className={`text-xs ${
            active ? "text-red-500" : "text-gray-600"
          }`}
        >
          {number}
        </span>

        {active && (
          <span className="h-1.5 w-1.5 rounded-full bg-red-500"></span>
        )}

      </div>

      <p className="mt-6 text-sm font-semibold">
        {title}
      </p>

      <p className="mt-1 text-xs text-gray-600">
        {description}
      </p>

    </div>
  );
}


// ==================================================
// TELEGRAM CONNECTION
// ==================================================
function TelegramConnection() {
  const [connected, setConnected] = useState(false);
  const [telegramUsername, setTelegramUsername] = useState("");
  const [connectedAt, setConnectedAt] = useState(null);

  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(false);

  const [telegramLink, setTelegramLink] = useState("");
  const [telegramCommand, setTelegramCommand] = useState("");

  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const getConfig = () => {
    const token = localStorage.getItem("token");

    if (!token) {
      throw new Error("Your session has expired. Please login again.");
    }

    return {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    };
  };

  const loadStatus = async ({ silent = false } = {}) => {
    try {
      if (!silent) {
        setLoading(true);
      }

      setError("");

      const response = await axios.get(
        `${API_URL}/telegram/status`,
        getConfig()
      );

      const isConnected = Boolean(response.data.connected);

      setConnected(isConnected);
      setTelegramUsername(response.data.telegram_username || "");
      setConnectedAt(response.data.connected_at || null);

      if (isConnected) {
        setTelegramCommand("");
        setTelegramLink("");
        setMessage("✅ Telegram account connected successfully.");
      }

      return response.data;
    } catch (err) {
      console.error("Telegram status error:", err);

      if (!silent) {
        if (err.response?.status === 401) {
          setError("Your session has expired. Please login again.");
        } else if (err.response?.data?.detail) {
          setError(err.response.data.detail);
        } else {
          setError("Unable to load Telegram connection status.");
        }
      }

      return null;
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  // Poll the backend after generating a connection command so the page
  // automatically changes to "Telegram Connected" after Telegram succeeds.
  useEffect(() => {
    if (connected || !telegramCommand) {
      return undefined;
    }

    const intervalId = window.setInterval(async () => {
      const result = await loadStatus({ silent: true });

      if (result?.connected) {
        window.clearInterval(intervalId);
      }
    }, 3000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [connected, telegramCommand]);

  const connectTelegram = async () => {
    try {
      setConnecting(true);
      setMessage("");
      setError("");
      setTelegramLink("");
      setTelegramCommand("");

      const response = await axios.post(
        `${API_URL}/telegram/connect`,
        {},
        getConfig()
      );

      if (response.data.connected) {
        setConnected(true);
        setTelegramUsername(response.data.telegram_username || "");
        setConnectedAt(response.data.connected_at || null);
        setMessage("✅ Your Telegram account is already connected.");
        return;
      }

      const link = response.data.telegram_link || "";

      if (!link) {
        setError("The SOC Platform did not return a Telegram connection link.");
        return;
      }

      setTelegramLink(link);

      // Extract only the start parameter from the temporary Telegram URL.
      // The token is never sent to the browser except as part of this command,
      // and the UI never logs it to the console.
      const url = new URL(link);
      const startToken = url.searchParams.get("start");

      if (!startToken) {
        setError("The Telegram connection link does not contain a start token.");
        return;
      }

      const command = `/start ${startToken}`;
      setTelegramCommand(command);

      setMessage(
        `Secure connection command created. It expires in ${
          response.data.expires_in_minutes || 10
        } minutes. Copy the command and send it to the SOC Telegram Bot.`
      );
    } catch (err) {
      console.error("Telegram connect error:", err);

      if (err.response?.status === 401) {
        setError("Your session has expired. Please login again.");
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to create the Telegram connection command.");
      }
    } finally {
      setConnecting(false);
    }
  };

  const copyTelegramCommand = async () => {
    if (!telegramCommand) return;

    try {
      await navigator.clipboard.writeText(telegramCommand);

      setError("");
      setMessage(
        "✅ Connection command copied. Open the SOC Security Platform Bot and paste it into the message box."
      );
    } catch (err) {
      console.error("Clipboard error:", err);

      setError(
        "Automatic copy is unavailable. Select the command manually and press Ctrl+C."
      );
    }
  };

  const openTelegram = () => {
    window.open(
      "https://t.me/SOC_Security_Platform_Bot",
      "_blank",
      "noopener,noreferrer"
    );
  };

  const checkTelegramStatus = async () => {
    setMessage("");
    setError("");

    const result = await loadStatus();

    if (!result?.connected) {
      setMessage(
        "Telegram is not connected yet. Send the copied /start command to the bot and wait a few seconds."
      );
    }
  };

  const disconnectTelegram = () => {
    setError("");
    setMessage(
      "Telegram disconnect is not enabled yet. The current integration is designed for one-time secure account linking."
    );
  };

  const formatDate = (value) => {
    if (!value) return "—";

    try {
      return new Date(value).toLocaleString();
    } catch {
      return value;
    }
  };

  return (
    <div>
      <div className="mb-8">
        <p className="text-xs uppercase tracking-[0.3em] text-red-500">
          Profile & Integrations
        </p>

        <h1 className="mt-2 text-3xl font-bold">
          Telegram Integration
        </h1>

        <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-500">
          Securely connect your Telegram account to access authorized SOC
          Platform services through the Telegram bot.
        </p>
      </div>

      {error && (
        <div className="mb-6 border border-red-600/30 bg-red-600/10 px-5 py-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {message && (
        <div className="mb-6 border border-green-600/20 bg-green-600/5 px-5 py-4 text-sm text-green-400">
          {message}
        </div>
      )}

      <div className="max-w-3xl border border-white/10 bg-[#0d0d0d]">
        <div className="border-b border-white/10 px-6 py-5">
          <p className="text-sm font-semibold">
            Telegram Account
          </p>

          <p className="mt-1 text-xs text-gray-600">
            Connect your SOC Platform account without sharing your SOC password
            with Telegram.
          </p>
        </div>

        <div className="p-6">
          {loading ? (
            <p className="text-sm text-gray-500">
              Checking Telegram connection...
            </p>
          ) : connected ? (
            <>
              <div className="flex items-center gap-3">
                <span className="h-3 w-3 rounded-full bg-green-500"></span>

                <div>
                  <p className="text-sm font-semibold text-green-500">
                    Telegram Connected
                  </p>

                  <p className="mt-1 text-xs text-gray-500">
                    @{telegramUsername || "Telegram User"}
                  </p>
                </div>
              </div>

              <div className="mt-6 grid gap-5 md:grid-cols-2">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    Bot
                  </p>

                  <p className="mt-2 text-sm text-gray-300">
                    @SOC_Security_Platform_Bot
                  </p>
                </div>

                <div>
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    Connected At
                  </p>

                  <p className="mt-2 text-sm text-gray-300">
                    {formatDate(connectedAt)}
                  </p>
                </div>
              </div>

              <div className="mt-6 border border-green-600/20 bg-green-600/5 p-4">
                <p className="text-sm text-gray-300">
                  Your Telegram account is ready for authorized SOC Platform
                  bot features.
                </p>
              </div>

              <button
                onClick={disconnectTelegram}
                className="mt-5 border border-white/10 px-5 py-3 text-xs font-semibold text-gray-400 transition hover:bg-white/5 hover:text-white"
              >
                Manage Connection
              </button>
            </>
          ) : (
            <>
              <div className="flex items-center gap-3">
                <span className="h-3 w-3 rounded-full bg-yellow-500"></span>

                <div>
                  <p className="text-sm font-semibold text-yellow-500">
                    Telegram Not Connected
                  </p>

                  <p className="mt-1 text-xs text-gray-500">
                    Generate a temporary connection command and send it to the
                    SOC Security Platform Bot.
                  </p>
                </div>
              </div>

              <div className="mt-6">
                <button
                  onClick={connectTelegram}
                  disabled={connecting}
                  className="bg-blue-600 px-6 py-3 text-sm font-semibold transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {connecting
                    ? "Creating Secure Command..."
                    : "Connect Telegram"}
                </button>
              </div>

              {telegramCommand && (
                <div className="mt-6 border border-white/10 bg-[#080808] p-5">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    Telegram Connection Command
                  </p>

                  <p className="mt-2 text-sm leading-6 text-gray-400">
                    Copy the command below, open the SOC Security Platform Bot,
                    paste it into the Telegram message box, and press Send.
                  </p>

                  <div className="mt-4 border border-white/10 bg-black p-4">
                    <code className="block break-all select-all text-sm text-green-400">
                      {telegramCommand}
                    </code>
                  </div>

                  <div className="mt-4 flex flex-wrap gap-3">
                    <button
                      onClick={copyTelegramCommand}
                      className="bg-blue-600 px-5 py-3 text-xs font-semibold transition hover:bg-blue-700"
                    >
                      Copy Connection Command
                    </button>

                    <button
                      onClick={openTelegram}
                      className="bg-gray-700 px-5 py-3 text-xs font-semibold transition hover:bg-gray-600"
                    >
                      Open Telegram Bot
                    </button>
                  </div>

                  <div className="mt-5 border border-yellow-600/20 bg-yellow-600/5 p-4">
                    <p className="text-xs leading-5 text-yellow-400">
                      The command contains a temporary connection token. Use it
                      once and do not share it with anyone.
                    </p>
                  </div>

                  <button
                    onClick={checkTelegramStatus}
                    className="mt-4 border border-white/10 px-5 py-3 text-xs font-semibold text-gray-300 transition hover:bg-white/5"
                  >
                    Check Connection Status
                  </button>

                  <p className="mt-4 text-xs leading-5 text-gray-600">
                    The page checks the backend automatically every few seconds
                    after the command is generated. Once Telegram accepts the
                    command successfully, this page will change to
                    “Telegram Connected”.
                  </p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ==================================================
// SECURITY FINDINGS
// ==================================================
function SecurityFindings() {
  const [findings, setFindings] = useState([]);
  const [stats, setStats] = useState(null);

  const [loading, setLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);

  const [error, setError] = useState("");
  const [selectedFinding, setSelectedFinding] = useState(null);

  const [filters, setFilters] = useState({
    severity: "",
    riskLevel: "",
    status: "",
    cve: "",
    owasp: "",
    owaspApi: "",
  });

  // ========================================================
  // AUTH CONFIG
  // ========================================================

  const getConfig = () => {
    const token = localStorage.getItem("token");

    if (!token) {
      throw new Error(
        "Your session has expired. Please login again."
      );
    }

    return {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    };
  };

  // ========================================================
  // LOAD FINDINGS
  // ========================================================

  const loadFindings = async () => {
    try {
      setLoading(true);
      setError("");

      const params = new URLSearchParams();

      if (filters.severity) {
        params.set(
          "severity",
          filters.severity
        );
      }

      if (filters.riskLevel) {
        params.set(
          "risk_level",
          filters.riskLevel
        );
      }

      if (filters.status) {
        params.set(
          "status",
          filters.status
        );
      }


      if (filters.cve.trim()) {
        params.set(
          "cve",
          filters.cve.trim()
        );
      }

      if (filters.owasp.trim()) {
        params.set(
          "owasp",
          filters.owasp.trim()
        );
      }

      if (filters.owaspApi.trim()) {
        params.set(
          "owasp_api",
          filters.owaspApi.trim()
        );
      }

      const queryString = params.toString();

      const url = queryString
        ? `${API_URL}/security-findings?${queryString}`
        : `${API_URL}/security-findings`;

      const response = await axios.get(
        url,
        getConfig()
      );

      setFindings(
        Array.isArray(response.data)
          ? response.data
          : []
      );
    } catch (err) {
      console.error(
        "Security findings load error:",
        err
      );

      if (err.response?.status === 401) {
        setError(
          "Your session has expired. Please login again."
        );
      } else if (
        err.response?.data?.detail
      ) {
        setError(
          err.response.data.detail
        );
      } else {
        setError(
          "Unable to load security findings."
        );
      }
    } finally {
      setLoading(false);
    }
  };

  // ========================================================
  // LOAD STATISTICS
  // ========================================================

  const loadStats = async () => {
    try {
      setStatsLoading(true);

      const response = await axios.get(
        `${API_URL}/security-findings/stats/summary`,
        getConfig()
      );

      setStats(response.data);
    } catch (err) {
      console.error(
        "Security findings statistics error:",
        err
      );
    } finally {
      setStatsLoading(false);
    }
  };

  // ========================================================
  // INITIAL LOAD
  // ========================================================

  useEffect(() => {
    const initialize = async () => {
      await Promise.all([
        loadFindings(),
        loadStats(),
      ]);
    };

    initialize();
  }, []);

  // ========================================================
  // FILTER CHANGE
  // ========================================================

  useEffect(() => {
    if (!loading) {
      loadFindings();
    }
  }, [
    filters.severity,
    filters.riskLevel,
    filters.status,
    filters.cve,
    filters.owasp,
    filters.owaspApi,
  ]);

  // ========================================================
  // HELPERS
  // ========================================================

  const severityClass = (severity) => {
    switch (severity) {
      case "CRITICAL":
        return "border-red-600/40 bg-red-600/10 text-red-400";

      case "HIGH":
        return "border-orange-500/40 bg-orange-500/10 text-orange-400";

      case "MEDIUM":
        return "border-yellow-500/40 bg-yellow-500/10 text-yellow-400";

      case "LOW":
        return "border-green-500/40 bg-green-500/10 text-green-400";

      default:
        return "border-white/10 bg-white/5 text-gray-400";
    }
  };

  const levelClass = (level) => {
    switch (level) {
      case "LEVEL_1":
        return "border-red-600/40 bg-red-600/10 text-red-400";

      case "LEVEL_2":
        return "border-yellow-500/40 bg-yellow-500/10 text-yellow-400";

      case "LEVEL_3":
        return "border-green-500/40 bg-green-500/10 text-green-400";

      default:
        return "border-white/10 bg-white/5 text-gray-400";
    }
  };

  const statusClass = (status) => {
    switch (status) {
      case "OPEN":
        return "text-red-400";

      case "IN_PROGRESS":
        return "text-yellow-400";

      case "FIXED":
        return "text-green-400";

      case "ACCEPTED":
        return "text-blue-400";

      case "FALSE_POSITIVE":
        return "text-gray-400";

      default:
        return "text-gray-500";
    }
  };

  const formatLevel = (level) => {
    if (!level) {
      return "—";
    }

    return level.replace(
      "LEVEL_",
      "LEVEL "
    );
  };

  // ========================================================
  // CLEAR FILTERS
  // ========================================================

  const clearFilters = () => {
    setFilters({
      severity: "",
      riskLevel: "",
      status: "",
        cve: "",
      owasp: "",
      owaspApi: "",
    });
  };

  // ========================================================
  // REFRESH
  // ========================================================

  const refreshAll = async () => {
    await Promise.all([
      loadFindings(),
      loadStats(),
    ]);
  };

  // ========================================================
  // DOWNLOAD FINDINGS REPORT
  // ========================================================

  const handleDownloadFindingsReport = () => {
    if (!findings.length) {
      setError("There are no security findings to include in the report.");
      return;
    }

    setError("");

    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const left = 18;
    const right = pageWidth - 18;
    const contentWidth = pageWidth - 36;
    let y = 20;

    const ensureSpace = (needed = 10) => {
      if (y + needed > pageHeight - 18) {
        doc.addPage();
        y = 20;
      }
    };

    const addLabelValue = (label, value) => {
      const textValue = value == null || value === "" ? "N/A" : String(value);
      const valueLines = doc.splitTextToSize(textValue, contentWidth - 38);
      ensureSpace(Math.max(6, valueLines.length * 5 + 2));

      doc.setFont("helvetica", "bold");
      doc.text(`${label}:`, left, y);
      doc.setFont("helvetica", "normal");
      doc.text(valueLines, left + 34, y);
      y += Math.max(6, valueLines.length * 5 + 2);
    };

    doc.setFont("helvetica", "bold");
    doc.setFontSize(20);
    doc.text("SOC Platform", left, y);
    y += 9;

    doc.setFontSize(14);
    doc.text("Security Findings Report", left, y);
    y += 7;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.text(`Generated: ${new Date().toLocaleString()}`, left, y);
    y += 4;

    doc.setDrawColor(220, 0, 0);
    doc.line(left, y, right, y);
    y += 10;

    addLabelValue("Total findings", stats?.total_findings ?? findings.length);
    addLabelValue("Critical", stats?.severity?.critical ?? 0);
    addLabelValue("High", stats?.severity?.high ?? 0);
    addLabelValue("Medium", stats?.severity?.medium ?? 0);
    addLabelValue("Low", stats?.severity?.low ?? 0);
    addLabelValue("Average CVSS", stats?.cvss?.average ?? 0);

    y += 3;

    findings.forEach((finding, index) => {
      ensureSpace(50);

      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      const titleLines = doc.splitTextToSize(
        `${index + 1}. ${finding.finding_id || "Finding"} — ${finding.title || "Security Finding"}`,
        contentWidth
      );
      doc.text(titleLines, left, y);
      y += titleLines.length * 6 + 2;

      doc.setFontSize(9);
      addLabelValue("Tool", finding.tool_name);
      addLabelValue("Severity", finding.severity);
      addLabelValue("Risk Level", formatLevel(finding.risk_level));
      addLabelValue("Status", finding.status);
      addLabelValue("CVSS", finding.cvss_score);
      addLabelValue("CVE", finding.cve_id);
      addLabelValue("CWE", finding.cwe_id);
      addLabelValue("OWASP", finding.owasp_category || finding.owasp_api_category);
      addLabelValue("Affected URL", finding.affected_url);
      addLabelValue("Endpoint", finding.endpoint);

      if (finding.description) {
        addLabelValue("Description", finding.description);
      }
      if (finding.impact) {
        addLabelValue("Impact", finding.impact);
      }
      if (finding.remediation) {
        addLabelValue("Remediation", finding.remediation);
      }
      if (finding.references) {
        addLabelValue("References", finding.references);
      }

      ensureSpace(6);
      doc.setDrawColor(60);
      doc.line(left, y, right, y);
      y += 7;
    });

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(100);
    doc.text(
      "SOC Platform • Authorized security assessment report",
      left,
      pageHeight - 10
    );

    doc.save(
      `SOC-Security-Findings-Report-${new Date().toISOString().slice(0, 10)}.pdf`
    );
  };

  // ========================================================
  // RENDER
  // ========================================================

  return (
    <div>
      {/* ==================================================
          PAGE HEADER
      ================================================== */}

      <div className="mb-8">
        <p className="text-xs uppercase tracking-[0.3em] text-red-500">
          Vulnerability Management
        </p>

        <div className="mt-2 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <h1 className="text-3xl font-bold">
              Security Findings
            </h1>

            <p className="mt-2 text-sm text-gray-500">
              Review vulnerabilities discovered
              during your security assessments.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleDownloadFindingsReport}
              disabled={loading || findings.length === 0}
              className="border border-red-600 px-4 py-2 text-xs font-semibold text-red-500 transition hover:bg-red-600 hover:text-white disabled:cursor-not-allowed disabled:border-white/10 disabled:text-gray-700 disabled:hover:bg-transparent disabled:hover:text-gray-700"
            >
              Download Report
            </button>

            <button
              onClick={refreshAll}
              className="border border-white/10 px-4 py-2 text-xs text-gray-400 transition hover:border-red-600 hover:text-white"
            >
              Refresh Findings
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="mb-6 border border-red-600/30 bg-red-600/10 px-5 py-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* ==================================================
          SUMMARY CARDS
      ================================================== */}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <FindingStatCard
          title="Total Findings"
          value={
            statsLoading
              ? "—"
              : stats?.total_findings ?? 0
          }
        />

        <FindingStatCard
          title="Critical"
          value={
            statsLoading
              ? "—"
              : stats?.severity?.critical ?? 0
          }
          danger
        />

        <FindingStatCard
          title="High"
          value={
            statsLoading
              ? "—"
              : stats?.severity?.high ?? 0
          }
        />

        <FindingStatCard
          title="Medium"
          value={
            statsLoading
              ? "—"
              : stats?.severity?.medium ?? 0
          }
        />

        <FindingStatCard
          title="Low"
          value={
            statsLoading
              ? "—"
              : stats?.severity?.low ?? 0
          }
        />
      </div>

      {/* ==================================================
          RISK / CVSS SUMMARY
      ================================================== */}

      <div className="mt-6 grid gap-4 md:grid-cols-4">
        <FindingSecondaryCard
          title="Level 1"
          value={
            statsLoading
              ? "—"
              : stats?.risk_levels?.level_1 ?? 0
          }
          subtitle="Critical / High"
        />

        <FindingSecondaryCard
          title="Level 2"
          value={
            statsLoading
              ? "—"
              : stats?.risk_levels?.level_2 ?? 0
          }
          subtitle="Medium"
        />

        <FindingSecondaryCard
          title="Level 3"
          value={
            statsLoading
              ? "—"
              : stats?.risk_levels?.level_3 ?? 0
          }
          subtitle="Low / None"
        />

        <FindingSecondaryCard
          title="Average CVSS"
          value={
            statsLoading
              ? "—"
              : stats?.cvss?.average ?? "0.0"
          }
          subtitle="CVSS score"
        />
      </div>

      {/* ==================================================
          FILTERS
      ================================================== */}

      <div className="mt-8 border border-white/10 bg-[#0d0d0d] p-5">
        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-gray-500">
              Filters
            </p>

            <p className="mt-1 text-sm text-gray-600">
              All tool findings are consolidated here. Narrow results by severity, risk level or status.
            </p>
          </div>

          <button
            onClick={clearFilters}
            className="text-xs text-gray-500 hover:text-white"
          >
            Clear Filters
          </button>
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-3">
          <div>
            <label className="text-[10px] uppercase tracking-wider text-gray-600">
              Severity
            </label>

            <select
              value={filters.severity}
              onChange={(e) =>
                setFilters((current) => ({
                  ...current,
                  severity: e.target.value,
                }))
              }
              className="mt-2 w-full border border-white/10 bg-[#080808] px-3 py-3 text-sm text-white outline-none focus:border-red-600"
            >
              <option value="">
                All Severities
              </option>
              <option value="CRITICAL">
                Critical
              </option>
              <option value="HIGH">
                High
              </option>
              <option value="MEDIUM">
                Medium
              </option>
              <option value="LOW">
                Low
              </option>
            </select>
          </div>

          <div>
            <label className="text-[10px] uppercase tracking-wider text-gray-600">
              Risk Level
            </label>

            <select
              value={filters.riskLevel}
              onChange={(e) =>
                setFilters((current) => ({
                  ...current,
                  riskLevel: e.target.value,
                }))
              }
              className="mt-2 w-full border border-white/10 bg-[#080808] px-3 py-3 text-sm text-white outline-none focus:border-red-600"
            >
              <option value="">
                All Levels
              </option>
              <option value="LEVEL_1">
                Level 1
              </option>
              <option value="LEVEL_2">
                Level 2
              </option>
              <option value="LEVEL_3">
                Level 3
              </option>
            </select>
          </div>

          <div>
            <label className="text-[10px] uppercase tracking-wider text-gray-600">
              Status
            </label>

            <select
              value={filters.status}
              onChange={(e) =>
                setFilters((current) => ({
                  ...current,
                  status: e.target.value,
                }))
              }
              className="mt-2 w-full border border-white/10 bg-[#080808] px-3 py-3 text-sm text-white outline-none focus:border-red-600"
            >
              <option value="">
                All Status
              </option>
              <option value="OPEN">
                Open
              </option>
              <option value="IN_PROGRESS">
                In Progress
              </option>
              <option value="FIXED">
                Fixed
              </option>
              <option value="ACCEPTED">
                Accepted
              </option>
              <option value="FALSE_POSITIVE">
                False Positive
              </option>
            </select>
          </div>

        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <div>
            <label className="text-[10px] uppercase tracking-wider text-gray-600">
              CVE
            </label>

            <input
              value={filters.cve}
              onChange={(e) =>
                setFilters((current) => ({
                  ...current,
                  cve: e.target.value,
                }))
              }
              placeholder="CVE-2025-..."
              className="mt-2 w-full border border-white/10 bg-[#080808] px-3 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </div>

          <div>
            <label className="text-[10px] uppercase tracking-wider text-gray-600">
              OWASP
            </label>

            <input
              value={filters.owasp}
              onChange={(e) =>
                setFilters((current) => ({
                  ...current,
                  owasp: e.target.value,
                }))
              }
              placeholder="A03 / Injection"
              className="mt-2 w-full border border-white/10 bg-[#080808] px-3 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </div>

          <div>
            <label className="text-[10px] uppercase tracking-wider text-gray-600">
              OWASP API
            </label>

            <input
              value={filters.owaspApi}
              onChange={(e) =>
                setFilters((current) => ({
                  ...current,
                  owaspApi: e.target.value,
                }))
              }
              placeholder="API1 / BOLA"
              className="mt-2 w-full border border-white/10 bg-[#080808] px-3 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
            />
          </div>
        </div>
      </div>

      {/* ==================================================
          FINDINGS LIST
      ================================================== */}

      <div className="mt-8">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-gray-500">
              Findings
            </p>

            <p className="mt-1 text-sm text-gray-600">
              {findings.length} finding
              {findings.length === 1
                ? ""
                : "s"} displayed
            </p>
          </div>
        </div>

        {loading ? (
          <div className="border border-white/10 bg-[#0d0d0d] p-10 text-center text-sm text-gray-500">
            Loading security findings...
          </div>
        ) : findings.length === 0 ? (
          <div className="border border-white/10 bg-[#0d0d0d] p-10 text-center">
            <p className="text-lg font-semibold text-gray-300">
              No Security Findings
            </p>

            <p className="mt-2 text-sm text-gray-600">
              No findings match the current
              filters.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <div
                key={finding.id}
                className="border border-white/10 bg-[#0d0d0d] p-5 transition hover:border-white/20"
              >
                <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-mono text-red-500">
                        {finding.finding_id}
                      </span>

                      <span
                        className={`border px-2 py-1 text-[10px] uppercase ${severityClass(
                          finding.severity
                        )}`}
                      >
                        {finding.severity}
                      </span>

                      <span
                        className={`border px-2 py-1 text-[10px] uppercase ${levelClass(
                          finding.risk_level
                        )}`}
                      >
                        {formatLevel(
                          finding.risk_level
                        )}
                      </span>

                      <span
                        className={`text-[10px] uppercase ${statusClass(
                          finding.status
                        )}`}
                      >
                        {finding.status.replace(
                          "_",
                          " "
                        )}
                      </span>
                    </div>

                    <h2 className="mt-3 text-lg font-semibold text-white">
                      {finding.title}
                    </h2>

                    <p className="mt-2 text-sm text-gray-500">
                      {finding.description ||
                        finding.vulnerability ||
                        "No description available."}
                    </p>

                    <div className="mt-4 grid gap-3 text-xs text-gray-500 md:grid-cols-2 xl:grid-cols-4">
                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-gray-700">
                          Tool
                        </span>

                        <span className="mt-1 block text-gray-300">
                          {finding.tool_name}
                        </span>
                      </div>

                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-gray-700">
                          CVSS
                        </span>

                        <span className="mt-1 block text-gray-300">
                          {finding.cvss_score ??
                            "N/A"}
                        </span>
                      </div>

                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-gray-700">
                          CVE
                        </span>

                        <span className="mt-1 block text-gray-300">
                          {finding.cve_id ||
                            "N/A"}
                        </span>
                      </div>

                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-gray-700">
                          OWASP
                        </span>

                        <span className="mt-1 block text-gray-300">
                          {finding.owasp_category ||
                            finding.owasp_api_category ||
                            "N/A"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex shrink-0 flex-col gap-2 xl:w-36">
                    <button
                      onClick={() =>
                        setSelectedFinding(
                          finding
                        )
                      }
                      className="border border-white/10 px-4 py-2 text-xs text-gray-400 transition hover:border-red-600 hover:text-white"
                    >
                      View Details
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ==================================================
          FINDING DETAIL MODAL
      ================================================== */}

      {selectedFinding && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 px-4 py-8">
          <div className="max-h-[90vh] w-full max-w-4xl overflow-y-auto border border-white/10 bg-[#0d0d0d]">
            <div className="sticky top-0 flex items-center justify-between border-b border-white/10 bg-[#0d0d0d] px-6 py-4">
              <div>
                <p className="text-[10px] uppercase tracking-[0.2em] text-red-500">
                  Security Finding
                </p>

                <h2 className="mt-1 text-xl font-bold">
                  {selectedFinding.finding_id}
                </h2>
              </div>

              <button
                onClick={() =>
                  setSelectedFinding(null)
                }
                className="text-xl text-gray-500 hover:text-white"
              >
                ×
              </button>
            </div>

            <div className="p-6">
              <div className="flex flex-wrap gap-2">
                <span
                  className={`border px-3 py-1 text-xs uppercase ${severityClass(
                    selectedFinding.severity
                  )}`}
                >
                  {selectedFinding.severity}
                </span>

                <span
                  className={`border px-3 py-1 text-xs uppercase ${levelClass(
                    selectedFinding.risk_level
                  )}`}
                >
                  {formatLevel(
                    selectedFinding.risk_level
                  )}
                </span>

                <span
                  className={`text-xs uppercase ${statusClass(
                    selectedFinding.status
                  )}`}
                >
                  {selectedFinding.status.replace(
                    "_",
                    " "
                  )}
                </span>
              </div>

              <h3 className="mt-5 text-2xl font-bold">
                {selectedFinding.title}
              </h3>

              <div className="mt-6 grid gap-4 md:grid-cols-2">
                <FindingDetailItem
                  label="Security Tool"
                  value={
                    selectedFinding.tool_name
                  }
                />

                <FindingDetailItem
                  label="Tool Category"
                  value={
                    selectedFinding.tool_category ||
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="CVSS Score"
                  value={
                    selectedFinding.cvss_score ??
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="CVE"
                  value={
                    selectedFinding.cve_id ||
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="CWE"
                  value={
                    selectedFinding.cwe_id ||
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="OWASP"
                  value={
                    selectedFinding.owasp_category ||
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="OWASP API"
                  value={
                    selectedFinding.owasp_api_category ||
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="Risk Level"
                  value={formatLevel(
                    selectedFinding.risk_level
                  )}
                />

                <FindingDetailItem
                  label="Affected URL"
                  value={
                    selectedFinding.affected_url ||
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="Endpoint"
                  value={
                    selectedFinding.endpoint ||
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="Parameter"
                  value={
                    selectedFinding.parameter ||
                    "N/A"
                  }
                />

                <FindingDetailItem
                  label="Affected Asset"
                  value={
                    selectedFinding.affected_asset ||
                    "N/A"
                  }
                />
              </div>

              <FindingDetailSection
                title="Description"
                value={
                  selectedFinding.description ||
                  "No description available."
                }
              />

              <FindingDetailSection
                title="Evidence"
                value={
                  selectedFinding.evidence ||
                  "No evidence recorded."
                }
              />

              <FindingDetailSection
                title="Impact"
                value={
                  selectedFinding.impact ||
                  "No impact information recorded."
                }
              />

              <FindingDetailSection
                title="Remediation"
                value={
                  selectedFinding.remediation ||
                  "No remediation information recorded."
                }
              />

              <FindingDetailSection
                title="Request Data"
                value={
                  selectedFinding.request_data ||
                  "N/A"
                }
              />

              <FindingDetailSection
                title="Response Data"
                value={
                  selectedFinding.response_data ||
                  "N/A"
                }
              />

              <FindingDetailSection
                title="References"
                value={
                  selectedFinding.references ||
                  "N/A"
                }
              />

              <div className="mt-6 flex justify-end">
                <button
                  onClick={() =>
                    setSelectedFinding(null)
                  }
                  className="border border-white/10 px-5 py-2 text-xs text-gray-400 hover:border-red-600 hover:text-white"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


// ==================================================
// FINDING STAT CARD
// ==================================================

function FindingStatCard({
  title,
  value,
  danger = false,
}) {
  return (
    <div className="border border-white/10 bg-[#0d0d0d] p-5">
      <p className="text-[10px] uppercase tracking-[0.2em] text-gray-600">
        {title}
      </p>

      <p
        className={`mt-3 text-3xl font-bold ${
          danger
            ? "text-red-500"
            : "text-white"
        }`}
      >
        {value}
      </p>
    </div>
  );
}


// ==================================================
// FINDING SECONDARY CARD
// ==================================================

function FindingSecondaryCard({
  title,
  value,
  subtitle,
}) {
  return (
    <div className="border border-white/10 bg-[#0d0d0d] p-5">
      <p className="text-xs font-semibold text-gray-300">
        {title}
      </p>

      <p className="mt-3 text-2xl font-bold text-white">
        {value}
      </p>

      <p className="mt-1 text-[10px] uppercase tracking-wider text-gray-600">
        {subtitle}
      </p>
    </div>
  );
}


// ==================================================
// FINDING DETAIL ITEM
// ==================================================

function FindingDetailItem({
  label,
  value,
}) {
  return (
    <div className="border border-white/10 bg-[#080808] p-4">
      <p className="text-[9px] uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <p className="mt-2 break-words text-sm text-gray-300">
        {value}
      </p>
    </div>
  );
}


// ==================================================
// FINDING DETAIL SECTION
// ==================================================

function FindingDetailSection({
  title,
  value,
}) {
  return (
    <div className="mt-6">
      <p className="text-[10px] uppercase tracking-[0.2em] text-red-500">
        {title}
      </p>

      <div className="mt-2 whitespace-pre-wrap border border-white/10 bg-[#080808] p-4 text-sm leading-6 text-gray-400">
        {value}
      </div>
    </div>
  );
}


// ==================================================
// USER MODULE PLACEHOLDER
// ==================================================
function UserModulePlaceholder({ menu }) {
  const titles = {
    findings: "Security Findings",
    reports: "Reports",
    support: "Complaints / Support",
    profile: "Profile",
  };

  const descriptions = {
    findings:
      "Security vulnerabilities and risk findings will be displayed here.",
    reports:
      "Security assessment and compliance reports will be available here.",
    support:
      "Raise and track security complaints or support requests here.",
    profile:
      "View and manage your account information here.",
  };

  return (
    <div>

      <p className="text-xs uppercase tracking-[0.3em] text-red-500">
        Security Workspace
      </p>

      <h1 className="mt-2 text-3xl font-bold">
        {titles[menu] || "Module"}
      </h1>

      <p className="mt-2 text-sm text-gray-500">
        {descriptions[menu] ||
          "This module will be implemented in the next development step."}
      </p>

      <div className="mt-8 border border-white/10 bg-[#0d0d0d] p-10 text-center">

        <div className="mx-auto flex h-14 w-14 items-center justify-center bg-red-600/10 text-xl text-red-500">

          {menu === "findings"
            ? "F"
            : menu === "reports"
            ? "R"
            : menu === "support"
            ? "S"
            : "P"}

        </div>

        <h2 className="mt-5 text-xl font-semibold">
          {titles[menu]}
        </h2>

        <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-gray-600">
          This section is ready for the next development stage.
        </p>

      </div>

    </div>
  );
}


// ==================================================
// GENERIC LOGIN PAGE
// ==================================================
function LoginPage({
  title,
  subtitle,
  onBack,
  onLogin,
}) {

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e) => {

    e.preventDefault();

    if (!email || !password) {
      alert("Please enter email and password.");
      return;
    }

    onLogin();
  };


  return (
    <div className="flex min-h-screen items-center justify-center bg-[#080808] px-6 text-white">

      <div className="w-full max-w-md">

        <button
          onClick={onBack}
          className="mb-10 text-sm text-gray-500 transition hover:text-white"
        >
          ← Back to Home
        </button>

        <div className="mb-10">

          <div className="mb-5 flex h-10 w-10 items-center justify-center rounded-md bg-red-600 font-bold">
            S
          </div>

          <p className="text-xs uppercase tracking-[0.3em] text-red-500">
            SOC PLATFORM
          </p>

          <h1 className="mt-3 text-3xl font-bold">
            {title}
          </h1>

          <p className="mt-2 text-sm text-gray-500">
            {subtitle}
          </p>

        </div>


        <form
          onSubmit={handleSubmit}
          className="border border-white/10 bg-[#0d0d0d] p-7"
        >

          <label className="text-xs uppercase tracking-wider text-gray-500">
            Email
          </label>

          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
            className="mt-2 mb-6 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
          />

          <label className="text-xs uppercase tracking-wider text-gray-500">
            Password
          </label>

          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            className="mt-2 w-full border border-white/10 bg-[#080808] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-700 focus:border-red-600"
          />

          <button
            type="submit"
            className="mt-7 w-full bg-red-600 py-3.5 text-sm font-semibold transition hover:bg-red-700"
          >
            Sign In
          </button>

        </form>

        <p className="mt-6 text-center text-xs text-gray-600">
          Authorized access only
        </p>

      </div>

    </div>
  );
}


export default App;