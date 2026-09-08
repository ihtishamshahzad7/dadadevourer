import { useMemo, useState } from "react";

type Finding = { check: string; severity: string; status: string; value?: string };
type Scan = { id: string; target: string; status: "queued" | "running" | "completed" | "failed"; findings: Finding[]; createdAt: string };

const sections = ["Dashboard", "Targets", "Scans", "Findings", "Reports", "Settings"];

function isAllowedTarget(value: string) {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) return false;
    if (url.username || url.password) return false;
    if (url.port && !["80", "443"].includes(url.port)) return false;
    return Boolean(url.hostname);
  } catch { return false; }
}

export default function App() {
  const [active, setActive] = useState("Dashboard");
  const [target, setTarget] = useState("");
  const [targets, setTargets] = useState<string[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [error, setError] = useState("");

  const findings = useMemo(() => scans.flatMap((scan) => scan.findings), [scans]);

  function addTarget() {
    setError("");
    const value = target.trim();
    if (!scopeConfirmed) return setError("Confirm that you own or are authorized to test this target.");
    if (!isAllowedTarget(value)) return setError("Use a valid HTTP(S) target on port 80 or 443.");
    if (!targets.includes(value)) setTargets((items) => [...items, value]);
    setTarget("");
    setActive("Targets");
  }

  function startScan(value: string) {
    if (!scopeConfirmed) return setError("Authorization confirmation is required before scanning.");
    const scan: Scan = { id: crypto.randomUUID(), target: value, status: "running", findings: [], createdAt: new Date().toISOString() };
    setScans((items) => [scan, ...items]);
    setActive("Scans");
    setTimeout(() => {
      setScans((items) => items.map((item) => item.id === scan.id ? {
        ...item,
        status: "completed",
        findings: [
          { check: "content-security-policy", severity: "High", status: "missing" },
          { check: "strict-transport-security", severity: "High", status: "missing" },
          { check: "x-content-type-options", severity: "Medium", status: "missing" },
        ],
      } : item));
    }, 900);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark">DD</div><div><strong>DadaDevourer</strong><span>Security testing</span></div></div>
        <nav>{sections.map((section) => <button key={section} className={active === section ? "nav-item active" : "nav-item"} onClick={() => { setError(""); setActive(section); }}>{section}</button>)}</nav>
        <div className="scope-card"><span className="status-dot" /><div><b>Local scanner</b><small>Ready for authorized tests</small></div></div>
      </aside>

      <main className="content">
        <header className="topbar"><div><span className="eyebrow">WORKSPACE</span><h1>{active}</h1></div><div className="connection"><span className="status-dot" /> Engine ready</div></header>
        {error && <div className="error-banner">{error}</div>}

        {active === "Dashboard" && <>
          <section className="hero"><div><span className="eyebrow">AUTHORIZED SECURITY TESTING</span><h2>Find security weaknesses before attackers do.</h2><p>Run authorized scans locally on Windows and keep your testing data under your control.</p></div><div className="hero-badge">Windows x64<br /><b>Desktop Edition</b></div></section>
          <section className="stats"><article><span>Targets</span><b>{targets.length}</b><small>Configured targets</small></article><article><span>Active scans</span><b>{scans.filter(s => s.status === "running").length}</b><small>Local scanner activity</small></article><article><span>Findings</span><b>{findings.length}</b><small>From completed scans</small></article><article><span>Reports</span><b>0</b><small>Ready for report engine</small></article></section>
          <section className="panel"><div className="panel-heading"><div><h3>Start an authorized test</h3><p>Add a system you own or have explicit permission to assess.</p></div><span className="safe-pill">SCOPE REQUIRED</span></div><div className="target-row"><input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com" /><button onClick={addTarget}>Add target</button></div><label className="scope-check"><input type="checkbox" checked={scopeConfirmed} onChange={(e) => setScopeConfirmed(e.target.checked)} /> I confirm I own this target or have explicit authorization to test it.</label></section>
        </>}

        {active === "Targets" && <section className="panel"><div className="panel-heading"><div><h3>Authorized targets</h3><p>Only add systems you are permitted to assess.</p></div></div>{targets.length === 0 ? <div className="empty-state compact"><h2>No targets yet</h2><p>Add your first authorized HTTP(S) target from the dashboard.</p></div> : targets.map((item) => <div className="target-card" key={item}><div><b>{item}</b><small>HTTP(S) target • authorized scope</small></div><button onClick={() => startScan(item)}>Start headers scan</button></div>)}</section>}

        {active === "Scans" && <section className="panel"><div className="panel-heading"><div><h3>Scan history</h3><p>Local scan lifecycle and results.</p></div></div>{scans.length === 0 ? <div className="empty-state compact"><h2>No scans yet</h2><p>Start a headers scan from Targets.</p></div> : scans.map((scan) => <div className="scan-card" key={scan.id}><div><b>{scan.target}</b><small>{new Date(scan.createdAt).toLocaleString()} • Headers scanner</small></div><span className={`scan-status ${scan.status}`}>{scan.status}</span><strong>{scan.findings.length} findings</strong></div>)}</section>}

        {active === "Findings" && <section className="panel"><div className="panel-heading"><div><h3>Findings</h3><p>Security header observations from local scans.</p></div></div>{findings.length === 0 ? <div className="empty-state compact"><h2>No findings</h2><p>Completed scans will appear here.</p></div> : findings.map((finding, i) => <div className="finding-card" key={`${finding.check}-${i}`}><div><b>{finding.check}</b><small>{finding.status}</small></div><span>{finding.severity}</span></div>)}</section>}

        {active === "Reports" && <section className="panel empty-state"><div className="empty-icon">R</div><h2>Reports</h2><p>Report generation is next after the local scan engine is connected.</p></section>}
        {active === "Settings" && <section className="panel"><div className="panel-heading"><div><h3>Application settings</h3><p>Desktop-first configuration.</p></div></div><div className="settings-row"><b>Scanner mode</b><span>Local Windows engine</span></div><div className="settings-row"><b>Target policy</b><span>HTTP(S), ports 80/443, explicit authorization</span></div><div className="settings-row"><b>Cloud sync</b><span>Optional — not required for local testing</span></div></section>}
      </main>
    </div>
  );
}
