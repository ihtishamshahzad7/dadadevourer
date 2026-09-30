export type AssessmentExport = {
  exportedAt: string;
  application: string;
  projects: unknown[];
  targets: unknown[];
  scans: unknown[];
  findings: unknown[];
  reports: unknown[];
  audit: unknown[];
};

export async function exportAssessmentData(data: Omit<AssessmentExport, "exportedAt"|"application">) {
  const payload: AssessmentExport = {
    exportedAt: new Date().toISOString(),
    application: "DadaDevourer",
    ...data,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `dadadevourer-assessment-${new Date().toISOString().slice(0,10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 60000);
}
