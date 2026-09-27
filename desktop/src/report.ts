export type ReportScan = {
  id: number;
  status: string;
  findingsCount: number;
  statusCode?: number;
  finalUrl?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
};

export type ReportFinding = {
  id?: number;
  scanId: number;
  check: string;
  title?: string;
  severity: string;
  status: string;
  description?: string;
  evidence?: string;
  recommendation?: string;
  reference?: string;
  value?: string;
};

export type ReportProject = {
  name: string;
  client?: string;
  description?: string;
};

const escapeText = (value: unknown) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const formatDate = (value?: string) => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
};

export function buildAssessmentReport(
  targetUrl: string,
  scan: ReportScan,
  findings: ReportFinding[],
  project?: ReportProject,
) {
  const counts = findings.reduce<Record<string, number>>((out, finding) => {
    const key = finding.severity || "Unknown";
    out[key] = (out[key] ?? 0) + 1;
    return out;
  }, {});

  const metrics = Object.entries(counts)
    .map(
      ([key, value]) =>
        '<div class="metric"><span>' +
        escapeText(key) +
        "</span><strong>" +
        value +
        "</strong></div>",
    )
    .join("");

  const rows = findings.length
    ? findings
        .map(
          (finding) =>
            "<tr><td><strong>" +
            escapeText(finding.title || finding.check) +
            '</strong><div class="sub">' +
            escapeText(finding.check) +
            "</div></td><td>" +
            escapeText(finding.severity) +
            "</td><td>" +
            escapeText(finding.status) +
            "</td><td>" +
            escapeText(finding.description || "No description recorded.") +
            "</td><td>" +
            escapeText(finding.evidence || finding.value || "No evidence recorded.") +
            "</td><td>" +
            escapeText(
              finding.recommendation ||
                "Review this observation against the authorized scope.",
            ) +
            "</td></tr>",
        )
        .join("")
    : '<tr><td colspan="6" class="empty">No observations were recorded.</td></tr>';

  return (
    '<!doctype html><html><head><meta charset="utf-8"><title>DadaDevourer Assessment</title><style>' +
    "body{font-family:Segoe UI,Arial,sans-serif;background:#f5f7fb;color:#182235;margin:0;padding:40px}" +
    ".report{max-width:1180px;margin:auto;background:#fff;border:1px solid #dce2ec}" +
    "header{padding:32px;border-bottom:1px solid #e3e7ef}" +
    ".brand{font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#53627c;font-size:12px}" +
    ".title{font-size:29px;margin:12px 0}.muted{color:#68758b;font-size:13px}" +
    ".actions{margin-top:16px}button{padding:10px 14px;border:0;border-radius:7px;background:#182b4d;color:#fff;font-weight:700}" +
    "main{padding:30px 32px}.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}" +
    ".meta div{border:1px solid #e1e6ef;border-radius:8px;padding:13px}.meta span{display:block;color:#718099;font-size:10px;margin-bottom:5px}" +
    ".meta strong{font-size:13px;word-break:break-word}.metrics{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}" +
    ".metric{border:1px solid #e1e6ef;border-radius:8px;padding:12px;min-width:90px}.metric span{display:block;color:#718099;font-size:10px;text-transform:uppercase}" +
    ".metric strong{display:block;font-size:21px;margin-top:4px}h2{font-size:17px;margin-top:28px}" +
    "table{width:100%;border-collapse:collapse;font-size:11px;table-layout:fixed}th,td{padding:11px;text-align:left;border-top:1px solid #e4e8ef;vertical-align:top;overflow-wrap:anywhere}" +
    "th{background:#f7f9fc;color:#64718a;font-size:10px;text-transform:uppercase}th:nth-child(1){width:16%}th:nth-child(2){width:8%}th:nth-child(3){width:10%}th:nth-child(4){width:20%}th:nth-child(5){width:23%}th:nth-child(6){width:23%}" +
    ".sub{color:#718099;font-size:9px;margin-top:4px}.empty{text-align:center;color:#718099;padding:25px}" +
    "footer{padding:16px 32px;border-top:1px solid #e3e7ef;color:#7a869a;font-size:10px}" +
    "@media print{body{padding:0;background:#fff}.report{border:0}.actions{display:none}}"+
    "</style></head><body><article class="report"><header><div class="brand">DadaDevourer • Authorized Testing</div>" +
    '<h1 class="title">Security Assessment Report</h1><div class="muted">Generated locally from a completed authorized assessment.</div>' +
    '<div class="actions"><button onclick="window.print()">Print / Save as PDF</button></div></header><main>' +
    '<div class="meta"><div><span>Project</span><strong>' +
    escapeText(project?.name || "Assessment") +
    '</strong></div><div><span>Client</span><strong>' +
    escapeText(project?.client || "—") +
    '</strong></div><div><span>Target</span><strong>' +
    escapeText(targetUrl) +
    '</strong></div><div><span>Scan ID</span><strong>#' +
    scan.id +
    '</strong></div><div><span>Status</span><strong>' +
    escapeText(scan.status) +
    '</strong></div><div><span>HTTP status</span><strong>' +
    (scan.statusCode ?? "—") +
    '</strong></div><div><span>Final URL</span><strong>' +
    escapeText(scan.finalUrl || "—") +
    '</strong></div><div><span>Started</span><strong>' +
    escapeText(formatDate(scan.startedAt)) +
    '</strong></div><div><span>Finished</span><strong>' +
    escapeText(formatDate(scan.finishedAt)) +
    '</strong></div></div>' +
    '<div class="metrics"><div class="metric"><span>Total</span><strong>' +
    findings.length +
    "</strong></div>" +
    metrics +
    '</div><h2>Observations</h2><table><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Description</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>' +
    rows +
    '</tbody></table><h2>Review note</h2><p class="muted">Observations are generated from the selected scanner run. Confirm findings against the authorized scope and application context before remediation.</p>' +
    '</main><footer>DadaDevourer Desktop • ' +
    escapeText(new Date().toLocaleString()) +
    "</footer></article></body></html>"
  );
}

export function openAssessmentReport(html: string) {
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const tab = window.open(url, "_blank", "noopener,noreferrer");
  if (!tab) {
    const link = document.createElement("a");
    link.href = url;
    link.download = "dadadevourer-assessment.html";
    link.click();
  }
  window.setTimeout(() => URL.revokeObjectURL(url), 60000);
}
