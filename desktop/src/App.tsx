import { useState } from "react";

const sections = ["Dashboard", "Targets", "Scans", "Findings", "Reports", "Settings"];

export default function App() {
  const [active, setActive] = useState("Dashboard");
  const [target, setTarget] = useState("");

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">DD</div>
          <div><strong>DadaDevourer</strong><span>Security testing</span></div>
        </div>
        <nav>
          {sections.map((section) => (
            <button key={section} className={active === section ? "nav-item active" : "nav-item"} onClick={() => setActive(section)}>
              {section}
            </button>
          ))}
        </nav>
        <div className="scope-card">
          <span className="status-dot" />
          <div><b>Local scanner</b><small>Ready for authorized tests</small></div>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div><span className="eyebrow">WORKSPACE</span><h1>{active}</h1></div>
          <div className="connection"><span className="status-dot" /> Engine ready</div>
        </header>

        {active === "Dashboard" && (
          <>
            <section className="hero">
              <div><span className="eyebrow">AUTHORIZED SECURITY TESTING</span><h2>Find security weaknesses before attackers do.</h2><p>Run scans locally on Windows and keep your authorized testing data under your control.</p></div>
              <div className="hero-badge">Windows x64<br /><b>Desktop Edition</b></div>
            </section>
            <section className="stats">
              <article><span>Targets</span><b>0</b><small>No targets configured</small></article>
              <article><span>Active scans</span><b>0</b><small>Scanner is idle</small></article>
              <article><span>Findings</span><b>0</b><small>No findings yet</small></article>
              <article><span>Reports</span><b>0</b><small>Nothing generated</small></article>
            </section>
            <section className="panel">
              <div className="panel-heading"><div><h3>Start an authorized test</h3><p>Add a system you own or have explicit permission to assess.</p></div><span className="safe-pill">SCOPE REQUIRED</span></div>
              <div className="target-row"><input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com" /><button onClick={() => target.trim() && setActive("Targets")}>Add target</button></div>
            </section>
          </>
        )}

        {active !== "Dashboard" && (
          <section className="panel empty-state"><div className="empty-icon">{active.slice(0, 1)}</div><h2>{active}</h2><p>This module is now part of the native Windows application. The scanner engine and persistence layer will be connected in the next build stages.</p></section>
        )}
      </main>
    </div>
  );
}
