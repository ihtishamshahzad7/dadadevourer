import { useEffect, useMemo, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { runHeadersScan, type ScannerFinding } from "./scanner";
import { addFinding, addScan, addTarget, deleteTarget, initDatabase, listFindings, listScans, listTargets, updateScan, type TargetRecord, type ScanRecord, type FindingRecord } from "./db";
import { checkForUpdate, openLatestRelease } from "./update";

type Target = TargetRecord & { id: number };
type Scan = ScanRecord & { id: number };
type Finding = FindingRecord & { id?: number };
const sections = ["Dashboard", "Targets", "Scans", "Findings", "Reports", "Settings"];

function isAllowedTarget(value: string) {
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password && (!url.port || ["80", "443"].includes(url.port)) && Boolean(url.hostname); } catch { return false; }
}

export default function App() {
  const [active, setActive] = useState("Dashboard");
  const [target, setTarget] = useState("");
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [error, setError] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [version, setVersion] = useState("0.1.0");
  const [updateText, setUpdateText] = useState("");
  const [checkingUpdate, setCheckingUpdate] = useState(false);

  const reload = async () => {
    const [targetRows, scanRows] = await Promise.all([listTargets(), listScans()]);
    setTargets(targetRows as Target[]); setScans(scanRows as Scan[]);
    const rows = await Promise.all(scanRows.map((scan) => listFindings(scan.id!)));
    setFindings(rows.flat() as Finding[]);
  };

  useEffect(() => { Promise.all([initDatabase(), getVersion()]).then(async ([, v]) => { setVersion(v); await reload(); setLoaded(true); }).catch((e) => setError(e instanceof Error ? e.message : String(e))); }, []);

  async function addNewTarget() {
    setError(""); const value = target.trim();
    if (!scopeConfirmed) return setError("Confirm that you own or are authorized to test this target.");
    if (!isAllowedTarget(value)) return setError("Use a valid HTTP(S) target on port 80 or 443.");
    try { await addTarget({ url: value, authorized: true, createdAt: new Date().toISOString() }); await reload(); setTarget(""); setActive("Targets"); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  }

  async function startScan(value: string, targetId: number) {
    setError(""); if (!scopeConfirmed) return setError("Authorization confirmation is required before scanning.");
    const createdAt = new Date().toISOString(); let scanId: number;
    try { scanId = await addScan({ targetId, status: "running", findingsCount: 0, createdAt, startedAt: createdAt }); await reload(); setActive("Scans");
      const result = await runHeadersScan(value);
      await updateScan(scanId, { status: "completed", findingsCount: result.findings.length, statusCode: result.status_code, finalUrl: result.url, finishedAt: new Date().toISOString() });
      for (const finding of result.findings) await addFinding({ scanId, check: finding.check, severity: finding.severity, status: finding.status, value: finding.value });
      await reload();
    } catch (e) { const message = e instanceof Error ? e.message : String(e); if (scanId!) await updateScan(scanId, { status: "failed", error: message, finishedAt: new Date().toISOString() }); await reload(); setError(message); }
  }

  async function removeTarget(id: number) { try { await deleteTarget(id); await reload(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } }

  async function checkUpdates() {
    setCheckingUpdate(true); setUpdateText("");
    try { const result = await checkForUpdate(version); setUpdateText(result.available ? `Update ${result.version} is available.` : `You are up to date (${version}).`); if (result.available) await openLatestRelease(); }
    catch (e) { setUpdateText(`Update check failed: ${e instanceof Error ? e.message : String(e)}`); }
    finally { setCheckingUpdate(false); }
  }

  const activeScans = useMemo(() => scans.filter(s => s.status === "running").length, [scans]);
  if (!loaded) return <div className="loading-screen">Starting DadaDevourer…</div>;

  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark">DD</div><div><strong>DadaDevourer</strong><span>Security testing</span></div></div><nav>{sections.map(s => <button key={s} className={active === s ? "nav-item active" : "nav-item"} onClick={() => { setError(""); setActive(s); }}>{s}</button>)}</nav><div className="scope-card"><span className="status-dot" /><div><b>Local scanner</b><small>Bundled Windows engine</small></div></div></aside>
    <main className="content"><header className="topbar"><div><span className="eyebrow">WORKSPACE</span><h1>{active}</h1></div><div className="connection"><span className="status-dot" /> Engine ready <button className="update-button" onClick={checkUpdates} disabled={checkingUpdate}>{checkingUpdate ? "Checking…" : "Check for updates"}</button></div></header>
      {error && <div className="error-banner">{error}</div>}
      {updateText && <div className="info-banner">{updateText}</div>}
      {active === "Dashboard" && <><section className="hero"><div><span className="eyebrow">AUTHORIZED SECURITY TESTING</span><h2>Find security weaknesses before attackers do.</h2><p>Run authorized scans locally on Windows and keep your testing data under your control.</p></div><div className="hero-badge">Windows x64<br /><b>Desktop Edition</b><small>v{version}</small></div></section><section className="stats"><article><span>Targets</span><b>{targets.length}</b><small>SQLite targets</small></article><article><span>Active scans</span><b>{activeScans}</b><small>Local scanner activity</small></article><article><span>Findings</span><b>{findings.length}</b><small>SQLite findings</small></article><article><span>Reports</span><b>0</b><small>Report engine next</small></article></section><section className="panel"><div className="panel-heading"><div><h3>Start an authorized test</h3><p>Add a system you own or have explicit permission to assess.</p></div><span className="safe-pill">SCOPE REQUIRED</span></div><div className="target-row"><input value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => { if (e.key === "Enter") void addNewTarget(); }} placeholder="https://example.com" /><button onClick={() => void addNewTarget()}>Add target</button></div><label className="scope-check"><input type="checkbox" checked={scopeConfirmed} onChange={e => setScopeConfirmed(e.target.checked)} /> I confirm I own this target or have explicit authorization to test it.</label></section></>}
      {active === "Targets" && <section className="panel"><div className="panel-heading"><div><h3>Authorized targets</h3><p>Stored in the local SQLite database.</p></div></div>{targets.length === 0 ? <div className="empty-state compact"><h2>No targets yet</h2><p>Add your first authorized HTTP(S) target from the dashboard.</p></div> : targets.map(t => <div className="target-card" key={t.id}><div><b>{t.url}</b><small>Authorization recorded • SQLite</small></div><div><button onClick={() => void startScan(t.url, t.id)} disabled={scans.some(s => s.targetId === t.id && s.status === "running")}>Start headers scan</button><button className="danger-button" onClick={() => void removeTarget(t.id)}>Delete</button></div></div>)}</section>}
      {active === "Scans" && <section className="panel"><div className="panel-heading"><div><h3>Scan history</h3><p>Persistent local scanner lifecycle and results.</p></div></div>{scans.length === 0 ? <div className="empty-state compact"><h2>No scans yet</h2><p>Start a headers scan from Targets.</p></div> : scans.map(s => <div className="scan-card" key={s.id}><div><b>{targets.find(t => t.id === s.targetId)?.url || `Target #${s.targetId}`}</b><small>{new Date(s.createdAt).toLocaleString()} • Headers scanner{s.statusCode ? ` • HTTP ${s.statusCode}` : ""}{s.finalUrl ? ` • ${s.finalUrl}` : ""}</small>{s.error && <small className="scan-error">{s.error}</small>}</div><span className={`scan-status ${s.status}`}>{s.status}</span><strong>{s.findingsCount} findings</strong></div>)}</section>}
      {active === "Findings" && <section className="panel"><div className="panel-heading"><div><h3>Findings</h3><p>Security header observations stored in SQLite.</p></div></div>{findings.length === 0 ? <div className="empty-state compact"><h2>No findings</h2><p>Completed scans will appear here.</p></div> : findings.map((f, i) => <div className="finding-card" key={`${f.id ?? f.scanId}-${i}`}><div><b>{f.check}</b><small>{f.status}{f.value ? ` • ${f.value}` : ""}</small><small>{targets.find(t => t.id === scans.find(s => s.id === f.scanId)?.targetId)?.url || ""}</small></div><span>{f.severity}</span></div>)}</section>}
      {active === "Reports" && <section className="panel empty-state"><div className="empty-icon">R</div><h2>Reports</h2><p>Report generation will use persisted scan and finding data.</p></section>}
      {active === "Settings" && <section className="panel"><div className="panel-heading"><div><h3>Application settings</h3><p>DadaDevourer Desktop v{version}</p></div></div><div className="settings-row"><b>Scanner mode</b><span>Bundled local Windows x64 engine</span></div><div className="settings-row"><b>Data storage</b><span>Native SQLite database</span></div><div className="settings-row"><b>Updates</b><span>Check the GitHub release channel from the button in the top bar.</span></div><div className="settings-row"><b>Cloud sync</b><span>Optional — not required for local testing</span></div></section>}
    </main></div>;
}
