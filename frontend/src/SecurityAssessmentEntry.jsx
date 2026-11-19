const pages = {
  "assessment-web": {
    title: "Web Application Testing",
    description: "Use the existing VAPT workspace to select a web target and the intended scanner. Review target authorization, tool options, and results in that workspace.",
    steps: [
      "Open VAPT and enter the authorized web target.",
      "Select the intended web testing tool and review its available options.",
      "Start testing explicitly and inspect progress and returned findings.",
      "Review persisted findings and record remediation separately.",
    ],
  },
  "assessment-api": {
    title: "API Testing",
    description: "Use the existing VAPT workspace for available API security tools, or QA Testing for its API testing workflow. These are separate testing capabilities; a QA score does not establish that an API is secure.",
    steps: [
      "Choose the security-testing or QA workflow for the intended objective.",
      "Review the authorized API target and any supplied authentication.",
      "Inspect the selected tool and request methods before starting.",
      "Review results in the original workflow and correlate persisted findings.",
    ],
  },
};

const button = "rounded-lg border border-slate-700 px-5 py-3 text-white hover:border-red-500";
const panel = "rounded-xl border border-slate-800 bg-[#0b1217] p-6";

export default function SecurityAssessmentEntry({ view, onNavigate }) {
  if (view === "assessment-audit") {
    return (
      <div className="space-y-6 text-slate-200">
        <header>
          <p className="text-sm uppercase tracking-widest text-red-500">Security Assessment</p>
          <h1 className="mt-3 text-3xl font-bold text-white">Security Audit</h1>
        </header>
        <section className={panel}>
          <h2 className="text-xl font-semibold text-white">Security Audit Assessment Unavailable</h2>
          <p className="mt-4 leading-7">
            The inspected interfaces provide testing results, remediation issues,
            and platform activity logs. They do not provide a security audit
            engagement with defined criteria, scope, evidence review, auditor
            conclusions, and approval.
          </p>
          <p className="mt-4 leading-7">
            Existing findings and remediation records can support an audit.
            Their presence does not establish that an audit was completed.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <button className={button} onClick={() => onNavigate("findings")}>Review Findings</button>
            <button className={button} onClick={() => onNavigate("assessment-remediation")}>Review Remediation</button>
          </div>
        </section>
      </div>
    );
  }

  const page = pages[view];
  return (
    <div className="space-y-6 text-slate-200">
      <header>
        <p className="text-sm uppercase tracking-widest text-red-500">Security Assessment</p>
        <h1 className="mt-3 text-3xl font-bold text-white">{page.title}</h1>
      </header>
      <section className={panel}>
        <p className="leading-7">{page.description}</p>
        <ol className="mt-6 list-decimal space-y-4 pl-6">
          {page.steps.map((step) => <li key={step}>{step}</li>)}
        </ol>
        <div className="mt-7 flex flex-wrap gap-3">
          <button className={button} onClick={() => onNavigate("vapt")}>Open VAPT Workspace</button>
          {view === "assessment-api" && (
            <button className={button} onClick={() => onNavigate("qa")}>Open QA Testing</button>
          )}
          <button className={button} onClick={() => onNavigate("findings")}>Review Findings</button>
        </div>
        <p className="mt-5 text-sm text-slate-400">
          Opening a workspace does not start a scan. Configure and start testing
          within the existing workflow.
        </p>
      </section>
    </div>
  );
}
