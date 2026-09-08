import { useEffect, useMemo, useState } from "react";
import { runHeadersScan, type ScannerFinding } from "./scanner";

type ScanStatus = "queued" | "running" | "completed" | "failed";
type Target = { url: string; authorized: boolean; createdAt: string };
type Finding = ScannerFinding & { scanId: string; target: string };
type Scan = {
  id: string;
  target: string;
  status: ScanStatus;
  findings: Finding[];
  statusCode?: number;
  finalUrl?: string;
  error?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
};

const sections = ["Dashboard", "Targets", "Scans", "Findings", "Reports", "Settings"];
const STORAGE_KEY = "dadadevourer.desktop.v1";

type PersistedState = { targets: Target[]; scans: Scan[] };

function isAllowedTarget(value: string) {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) return false;
    if (url.username || url.password) return false;
    if (url.port && !["80", "443"].includes(url.port)) return false;
    return Boolean(url.hostname);
  } catch {
    return false;
  }
}

function loadState(): PersistedState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { targets: [], scans: [] };
    const parsed = JSON.parse(raw) as Partial<PersistedState>;
    return {
      targets: Array.isArray(parsed.targets) ? parsed.targets : [],
      scans: Array.isArray(parsed.scans) ? parsed.scans : [],
    };
  } catch {
    return { targets: [], scans: [] };
  }
}

export default function App() {
  const initial = useMemo(loadState, []);
  const [active, setActive] = useState("Dashboard");
  const [target, setTarget] = useState("");
  const [targets, setTargets] = useState<Target[]>(initial.targets);
  const [scans, setScans] = useState<Scan[]>(initial.scans);
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [error, setError] = useState("");

  const findings = useMemo(() => scans.flatMap((scan) => scan.findings), [scans]);

  useEffect(() => {
    const state: PersistedState = { targets, scans };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }, [targets, scans]);

  function addTarget() {
    setError("");
    const value = target.trim();
    if (!scopeConfirmed) return setError("Confirm that you own or are authorized to test this target.");
    if (!isAllowedTarget(value)) return setError("Use a valid HTTP(S) target on port 80 or 443.");
    if (!targets.some((item) => item.url === value)) {
      setTargets((items) => [...items, { url: value, authorized: true, createdAt: new Date().toISOString() }]);
    }
    setTarget("");
    setActive("Targets");
  }

  async function startScan(value: string) {
    setError("");
    if (!scopeConfirmed) {
      setError("Authorization confirmation is required before scanning.");
      return;
    }

    const scanId = crypto.randomUUID();
    const startedAt = new Date().toISOString();
    const scan: Scan = {
      id: scanId,
      target: value,
      status: "running",
      findings: [],
      createdAt: startedAt,
      startedAt,
    };
    setScans((items) => [scan, ...items]);
    setActive("Scans");

    try {
      const result = await runHeadersScan(value);
      const completedAt = new Date().toISOString();
      const normalized = result.findings.map((finding) => ({
        ...finding,
        scanId,
        target: value,
      }));
      setScans((items) => items.map((item) => item.id === scanId ? {
        ...item,
        status: "completed",
        findings: normalized,
        statusCode: result.status_code,
        finalUrl: result.url,
        finishedAt: completedAt,
      } : item));
    } catch (scanError) {
      const message = scanError instanceof Error ? scanError.message : String(scanError);
      setScans((items) => items.map((item) => item.id === scanId ? {
        ...item,
        status: "failed",
        error: message,
        finishedAt: new Date().toISOString(),
      } : item));
      setError(message);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark">DD</div><div><strong>DadaDevourer</strong><span>Security testing</span></div></div>
        <nav>{sections.map((section) => <button key={section} className={active === section ? "nav-item active" : "nav-item"} onClick={() => { setError(""); setActive(section); }}>{section}</button>)}</nav>
        <div className="scope-card"><span className="status-dot" /><div><b>Local scanner</b><small>Bundled Windows engine</small></div></div>
      </aside>

      <main className="content">
        <header className="topbar"><div><span className="eyebrow">WORKSPACE</span><h1>{active}</h1></div><div className="connection"><span className="status-dot" /> Engine ready</div></header>
        {error && <div className="error-banner">{error}</div>}

        {active === "Dashboard" && <>
          <section className="hero"><div><span className="eyebrow">AUTHORIZED SECURITY TESTING</span><h2>Find security weaknesses before attackers do.</h2><p>Run authorized scans locally on Windows and keep your testing data under your control.</p></div><div className="hero-badge">Windows x64<br /><b>Desktop Edition</b></div></section>
          <section className="stats"><article><span>Targets</span><b>{targets.length}</b><small>Configured targets</small></article><article><span>Active scans</span><b>{scans.filter(s => s.status === "running").length}</b><small>Local scanner activity</small></article><article><span>Findings</span><b>{findings.length}</b><small>From completed scans</small></article><article><span>Reports</span><b>0</b><small>Report engine next</small></article></section>
          <section className="panel"><div className="panel-heading"><div><h3>Start an authorized test</h3><p>Add a system you own or have explicit permission to assess.</p></div><span className="safe-pill">SCOPE REQUIRED</span></div><div className="target-row"><input value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") addTarget(); }} placeholder="https://example.com" /><button onClick={addTarget}>Add target</button></div><label className="scope-check"><input type="checkbox" checked={scopeConfirmed} onChange={(e) => setScopeConfirmed(e.target.checked)} /> I confirm I own this target or have explicit authorization to test it.</label></section>
        </>}

        {active === "Targets" && <section className="panel"><div className="panel-heading"><div><h3>Authorized targets</h3><p>Only add systems you are permitted to assess.</p></div></div>{targets.length === 0 ? <div className="empty-state compact"><h2>No targets yet</h2><p>Add your first authorized HTTP(S) target from the dashboard.</p></div> : targets.map((item) => <div className="target-card" key={item.url}><div><b>{item.url}</b><small>HTTP(S) target • authorization recorded</small></div><button onClick={() => startScan(item.url)} disabled={scans.some((scan) => scan.target === item.url && scan.status === "running")}>{scans.some((scan) => scan.target === item.url && scan.status === "running") ? "Scanning…" : "Start headers scan"}</button></div>)}</section>}

        {active === "Scans" && <section className="panel"><div className="panel-heading"><div><h3>Scan history</h3><p>Real local scanner lifecycle and results.</p></div></div>{scans.length === 0 ? <div className="empty-state compact"><h2>No scans yet</h2><p>Start a headers scan from Targets.</p></div> : scans.map((scan) => <div className="scan-card" key={scan.id}><div><b>{scan.target}</b><small>{new Date(scan.createdAt).toLocaleString()} • Headers scanner{scan.statusCode ? ` • HTTP ${scan.statusCode}` : ""}{scan.finalUrl && scan.finalUrl !== scan.target ? ` • ${scan.finalUrl}` : ""}</small>{scan.error && <small className="scan-error">{scan.error}</small>}</div><span className={`scan-status ${scan.status}`}>{scan.status}</span><strong>{scan.findings.length} findings</strong></div>)}</section>}

        {active === "Findings" && <section className="panel"><div className="panel-heading"><div><h3>Findings</h3><p>Security header observations from the local engine.</p></div></div>{findings.length === 0 ? <div className="empty-state compact"><h2>No findings</h2><p>Completed scans will appear here.</p></div> : findings.map((finding, i) => <div className="finding-card" key={`${finding.scanId}-${finding.check}-${i}`}><div><b>{finding.check}</b><small>{finding.status}{finding.value ? ` • ${finding.value}` : ""}</small><small>{finding.target}</small></div><span>{finding.severity}</span></div>)}</section>}

        {active === "Reports" && <section className="panel empty-state"><div className="empty-icon">R</div><h2>Reports</h2><p>Report generation will use persisted scan and finding data.</p></section>}
        {active === "Settings" && <section className="panel"><div className="panel-heading"><div><h3>Application settings</h3><p>Desktop-first configuration.</p></div></div><div className="settings-row"><b>Scanner mode</b><span>Bundled local Windows engine</span></div><div className="settings-row"><b>Target policy</b><span>HTTP(S), ports 80/443, explicit authorization</span></div><div className="settings-row"><b>Data storage</b><span>Local application storage • SQLite migration planned</span></div><div className="settings-row"><b>Cloud sync</b><span>Optional — not required for local testing</span></div></section>}
      </main>
    </div>
  );
}
