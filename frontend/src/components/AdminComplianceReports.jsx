import { useCallback, useEffect, useState } from "react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

const API = "http://127.0.0.1:8000";

const FRAMEWORKS = [
  "All frameworks",
  "ISO 27001",
  "SOC 2",
  "NIST CSF",
  "CIS Controls",
  "PCI DSS",
];

const STATUSES = [
  "Compliant",
  "Partially Compliant",
  "Non-Compliant",
  "Not Assessed",
  "Not Applicable",
];

export default function AdminComplianceReports({ onBack }) {
  const [framework, setFramework] = useState("All frameworks");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadReport = useCallback(async () => {
    setLoading(true);
    setError("");

    const token = localStorage.getItem("token");
    if (!token) {
      setError("Admin session missing. Please sign in again.");
      setLoading(false);
      return;
    }

    try {
      const query =
        framework === "All frameworks"
          ? ""
          : `?framework=${encodeURIComponent(framework)}`;

      const response = await fetch(`${API}/compliance/reports${query}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          result.detail || `Report request failed (${response.status}).`
        );
      }

      setReport(result);
    } catch (err) {
      setError(err.message || "Unable to load the compliance report.");
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [framework]);

  useEffect(() => {
    loadReport();
  }, [loadReport]);

  function downloadCSV() {
    if (!report?.controls?.length) {
      setError("There are no controls to export.");
      return;
    }

    const columns = [
      ["Framework", "framework"],
      ["Control ID", "control_id"],
      ["Control Title", "title"],
      ["Status", "status"],
      ["Owner", "owner"],
      ["Evidence Reference", "evidence_reference"],
      ["Assessment Notes", "notes"],
      ["Updated At", "updated_at"],
      ["Updated By", "updated_by"],
    ];

    const escapeCSV = (value) => {
      let text = String(value ?? "");
      if (/^[=+\-@]/.test(text)) text = "'" + text;
      return `"${text.replace(/"/g, '""')}"`;
    };

    const rows = [
      columns.map(([heading]) => escapeCSV(heading)).join(","),
      ...report.controls.map((control) =>
        columns.map(([, key]) => escapeCSV(control[key])).join(",")
      ),
    ];

    const blob = new Blob(
      ["\uFEFF" + rows.join("\r\n")],
      { type: "text/csv;charset=utf-8;" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `compliance-report-${framework
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")}-${new Date()
      .toISOString()
      .slice(0, 10)}.csv`;

    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }


  function downloadPDF() {
    const rows = report?.controls || [];

    if (!report || rows.length === 0) {
      setError("There are no controls to export.");
      return;
    }

    try {
      const doc = new jsPDF({ orientation: "landscape" });
      const generated = report.generated_at
        ? new Date(report.generated_at).toLocaleString()
        : new Date().toLocaleString();

      const total = rows.length;
      const countStatus = (status) =>
        rows.filter((item) => item.status === status).length;
      const compliant = countStatus("Compliant");
      const percentage = Math.round((compliant / total) * 100);

      doc.setFillColor(18, 18, 18);
      doc.rect(0, 0, 297, 32, "F");
      doc.setTextColor(255, 255, 255);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(19);
      doc.text("SOC PLATFORM", 14, 13);
      doc.setFontSize(14);
      doc.text("Compliance Assessment Report", 14, 23);

      doc.setTextColor(35, 35, 35);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.text(`Framework: ${report.framework || framework}`, 14, 42);
      doc.text(`Generated: ${generated}`, 14, 49);

      autoTable(doc, {
        startY: 56,
        head: [["Metric", "Result"]],
        body: [
          ["Total Controls", String(total)],
          ["Compliant", String(compliant)],
          ["Compliance Percentage", `${percentage}%`],
          ["Partially Compliant", String(countStatus("Partially Compliant"))],
          ["Non-Compliant", String(countStatus("Non-Compliant"))],
          ["Not Assessed", String(countStatus("Not Assessed"))],
          ["Not Applicable", String(countStatus("Not Applicable"))],
        ],
        theme: "grid",
        headStyles: { fillColor: [190, 0, 20] },
        styles: { fontSize: 9, cellPadding: 3 },
        tableWidth: 120,
      });

      const summaryEnd = doc.lastAutoTable.finalY;

      autoTable(doc, {
        startY: summaryEnd + 8,
        head: [[
          "Framework",
          "Control ID",
          "Control Title",
          "Status",
          "Owner",
          "Evidence Reference",
          "Assessment Notes",
          "Updated At",
        ]],
        body: rows.map((item) => [
          item.framework ?? report.framework ?? framework,
          item.control_id ?? "",
          item.title ?? "",
          item.status ?? "Not Assessed",
          item.owner ?? "",
          item.evidence_reference ?? "",
          item.notes ?? "",
          item.updated_at
            ? new Date(item.updated_at).toLocaleString()
            : "",
        ]),
        theme: "grid",
        headStyles: { fillColor: [190, 0, 20], fontSize: 8 },
        styles: {
          fontSize: 7,
          cellPadding: 2,
          overflow: "linebreak",
        },
        columnStyles: {
          0: { cellWidth: 25 },
          1: { cellWidth: 22 },
          2: { cellWidth: 42 },
          3: { cellWidth: 25 },
          4: { cellWidth: 24 },
          5: { cellWidth: 35 },
          6: { cellWidth: 65 },
          7: { cellWidth: 30 },
        },
        margin: { left: 10, right: 10, bottom: 18 },
        didDrawPage: () => {
          const pageCount = doc.internal.getNumberOfPages();
          doc.setFontSize(8);
          doc.setTextColor(100, 100, 100);
          doc.text(
            "Internal assessment report — not a certification.",
            10,
            doc.internal.pageSize.getHeight() - 8
          );
          doc.text(
            `Page ${pageCount}`,
            doc.internal.pageSize.getWidth() - 20,
            doc.internal.pageSize.getHeight() - 8
          );
        },
      });

      const filename = `compliance-report-${framework
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")}-${new Date()
        .toISOString()
        .slice(0, 10)}.pdf`;

      doc.save(filename);
      setError("");
    } catch (err) {
      console.error("PDF export failed:", err);
      setError("PDF export failed. Check the browser console for details.");
    }
  }

  const controls = report?.controls || [];
  const count = (status) =>
    controls.filter((control) => control.status === status).length;

  const percentage = controls.length
    ? Math.round((count("Compliant") / controls.length) * 100)
    : 0;

  const cardClass =
    "rounded-xl border border-white/10 bg-[#111111] p-5";
  const mutedClass = "text-xs text-gray-400";

  return (
    <div className="space-y-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-red-500">
            Security Governance
          </p>
          <h1 className="mt-2 text-2xl font-bold">Compliance Reports</h1>
          <p className="mt-2 text-sm text-gray-400">
            Review assessment results and export detailed compliance reports to CSV or PDF.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={loadReport}
            disabled={loading}
            className="rounded-md border border-white/15 px-4 py-2 text-xs hover:border-red-500 disabled:opacity-50"
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <button
            type="button"
            onClick={downloadCSV}
            disabled={loading || !controls.length}
            className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold hover:bg-red-700 disabled:opacity-50"
          >
            Download CSV
          </button>
          <button
            type="button"
            onClick={downloadPDF}
            disabled={loading || !controls.length}
            className="rounded-md border border-red-500/60 px-4 py-2 text-xs font-semibold hover:bg-red-950 disabled:opacity-50"
          >
            Download PDF
          </button>
          <button
            type="button"
            onClick={onBack}
            className="rounded-md border border-white/15 px-4 py-2 text-xs hover:border-red-500"
          >
            ← Overview
          </button>
        </div>
      </div>

      <div className={cardClass}>
        <label className="block text-xs text-gray-400">
          Select framework
          <select
            value={framework}
            onChange={(event) => setFramework(event.target.value)}
            className="mt-2 w-full rounded-md border border-white/15 bg-black px-3 py-3 text-sm text-white sm:max-w-md"
          >
            {FRAMEWORKS.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
        </label>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-950/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {loading && !report ? (
        <div className={cardClass}>Loading compliance report...</div>
      ) : report ? (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {[
              ["Total Controls", controls.length],
              ["Compliant", count("Compliant")],
              ["Open Gaps", count("Partially Compliant") + count("Non-Compliant")],
              ["Not Assessed", count("Not Assessed")],
            ].map(([label, value]) => (
              <div className={cardClass} key={label}>
                <p className={mutedClass}>{label}</p>
                <p className="mt-3 text-3xl font-bold">{value}</p>
              </div>
            ))}
          </div>

          <div className={cardClass}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="font-semibold">Compliance Summary</h2>
                <p className={`mt-1 ${mutedClass}`}>
                  {report.framework} · {percentage}% of listed controls marked compliant
                </p>
              </div>
              <span className="text-xl font-bold text-red-400">{percentage}%</span>
            </div>

            <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/10">
              <div
                className="h-full rounded-full bg-red-600"
                style={{ width: `${percentage}%` }}
              />
            </div>

            <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {STATUSES.map((status) => (
                <div
                  key={status}
                  className="flex items-center justify-between rounded-md border border-white/10 bg-black/20 p-3"
                >
                  <span className="text-xs text-gray-400">{status}</span>
                  <span className="font-semibold">{count(status)}</span>
                </div>
              ))}
            </div>

            <p className="mt-4 text-xs text-gray-500">
              Generated: {report.generated_at
                ? new Date(report.generated_at).toLocaleString()
                : "Not available"}
            </p>
          </div>

          <div className={`${cardClass} overflow-hidden`}>
            <div className="mb-4">
              <h2 className="font-semibold">Control Details</h2>
              <p className={`mt-1 ${mutedClass}`}>
                Export control details using Download CSV or Download PDF.
              </p>
            </div>

            {controls.length === 0 ? (
              <p className="py-6 text-sm text-gray-400">
                No controls are available for this report.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[850px] text-left text-xs">
                  <thead>
                    <tr className="border-b border-white/10 text-gray-400">
                      <th className="px-3 py-3">Framework</th>
                      <th className="px-3 py-3">Control</th>
                      <th className="px-3 py-3">Title</th>
                      <th className="px-3 py-3">Status</th>
                      <th className="px-3 py-3">Owner</th>
                      <th className="px-3 py-3">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {controls.map((control) => (
                      <tr
                        key={`${control.framework}-${control.control_id}`}
                        className="border-b border-white/5 align-top hover:bg-white/[0.02]"
                      >
                        <td className="px-3 py-3">{control.framework}</td>
                        <td className="px-3 py-3 font-semibold text-red-400">
                          {control.control_id}
                        </td>
                        <td className="px-3 py-3">{control.title}</td>
                        <td className="px-3 py-3">{control.status}</td>
                        <td className="px-3 py-3">{control.owner || "—"}</td>
                        <td className="px-3 py-3">{control.evidence_reference || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <p className="text-xs text-gray-500">
            This report reflects internal control assessments. It does not establish
            independent certification or audit compliance.
          </p>
        </>
      ) : null}
    </div>
  );
}
