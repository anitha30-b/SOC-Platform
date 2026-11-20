// Shared outcome vocabulary for tool callbacks and result summaries.
export function normalizeToolStatus(value) {
  const status = String(value ?? "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  const aliases = {
    completed_with_warnings: "completed_with_errors", completed_with_warning: "completed_with_errors",
    timed_out: "timeout", timedout: "timeout", unavailable: "not_available",
    canceled: "cancelled", error: "failed", failure: "failed", in_progress: "running",
  };
  return aliases[status] || status;
}

export function isTerminalToolStatus(value) {
  return ["completed", "completed_with_errors", "failed", "timeout", "not_available", "cancelled"]
    .includes(normalizeToolStatus(value));
}

export function getToolOutcome(result, fallbackStatus) {
  const payloads = [result, result?.result, ...[
    "nmap", "nikto", "nuclei", "masscan", "hping3", "tshark", "snort", "hydra", "john",
  ].map(key => result?.[key])].filter(value => value && typeof value === "object");
  const native = payloads.flatMap(value => [
    value.status,
    ...(Array.isArray(value.workflow?.stage_results)
      ? value.workflow.stage_results.map(stage => stage.status) : []),
  ]).map(normalizeToolStatus).filter(Boolean);
  const fallback = normalizeToolStatus(fallbackStatus);
  const candidates = [...native, fallback].filter(Boolean);
  const problems = ["failed", "timeout", "not_available", "cancelled", "completed_with_errors"];
  let status = problems.find(value => candidates.includes(value));
  if (!status) {
    const preferred = native.length ? native : (fallback ? [fallback] : []);
    status = ["running", "queued", "not_started", "selected", "input_required"]
      .find(value => preferred.includes(value));
    if (!status) status = preferred.length && preferred.every(value => value === "completed")
      ? "completed" : "unknown";
  }
  const labels = {
    completed: "Completed", completed_with_errors: "Completed with warnings",
    failed: "Failed", timeout: "Timed Out", not_available: "Not available", cancelled: "Cancelled",
    running: "Running", queued: "Queued", not_started: "Not started", selected: "Selected",
    input_required: "Input Required", unknown: result || fallback ? "Status unavailable" : "No result",
  };
  return { status, label: labels[status], terminal: isTerminalToolStatus(status) };
}
