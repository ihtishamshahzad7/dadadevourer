"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./lib/api";

type Target = { id: number; name: string | null; url: string };
type Scan = { id: number; target_id: number; scanner: string; status: string; created_at: string; finished_at: string | null };
type Finding = { check: string; severity: string; status: string; value: string | null };
type ScanDetail = Scan & { error: string | null; findings: Finding[] };

export default function Home() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<ScanDetail | null>(null);
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [editingId, setEditingId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const loadDashboard = useCallback(async () => {
    const [targetsResponse, scansResponse] = await Promise.all([api("/targets"), api("/scans")]);
    if (targetsResponse.ok) setTargets(await targetsResponse.json());
    if (scansResponse.ok) setScans(await scansResponse.json());
  }, []);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) { router.replace("/login"); return; }
    loadDashboard();
  }, [loadDashboard, router]);

  useEffect(() => {
    const active = scans.some((s) => ["queued", "running"].includes(s.status));
    if (!active) return;
    const timer = setInterval(loadDashboard, 3000);
    return () => clearInterval(timer);
  }, [scans, loadDashboard]);

  function startEdit(target: Target) {
    setEditingId(target.id);
    setName(target.name || "");
    setUrl(target.url);
    setMessage("");
  }

  function cancelEdit() {
    setEditingId(null);
    setName("");
    setUrl("");
    setMessage("");
  }

  async function saveTarget(event: FormEvent) {
    event.preventDefault();
    if (!url.trim()) return;
    setBusy(true); setMessage("");
    try {
      const response = await api(editingId ? `/targets/${editingId}` : "/targets", {
        method: editingId ? "PATCH" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), name: name.trim() || null }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Unable to save target");
      setMessage(editingId ? "Target updated successfully." : "Target added successfully.");
      cancelEdit();
      await loadDashboard();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to save target");
    } finally { setBusy(false); }
  }

  async function deleteTarget(target: Target) {
    if (!window.confirm(`Delete ${target.name || target.url}? Existing scans and findings for this target will also be removed.`)) return;
    setBusy(true); setMessage("");
    try {
      const response = await api(`/targets/${target.id}`, { method: "DELETE" });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || "Unable to delete target");
      }
      setMessage("Target deleted.");
      if (editingId === target.id) cancelEdit();
      if (selected?.target_id === target.id) setSelected(null);
      await loadDashboard();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to delete target");
    } finally { setBusy(false); }
  }

  async function runHeaderScan(targetId: number) {
    setBusy(true); setMessage("");
    try {
      const response = await api("/scans/headers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target_id: targetId }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Unable to start scan");
      setMessage(`Header scan #${data.id} queued.`); await loadDashboard();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to start scan"); }
    finally { setBusy(false); }
  }

  async function viewScan(scanId: number) {
    const response = await api(`/scans/${scanId}`);
    if (response.ok) setSelected(await response.json());
  }

  function signOut() { localStorage.removeItem("access_token"); router.replace("/login"); }

  const activeCount = scans.filter((s) => ["queued", "running"].includes(s.status)).length;
  const completedCount = scans.filter((s) => s.status === "completed").length;

  return (
    <main style={{ maxWidth: 1180, margin: "0 auto", padding: "32px 20px", fontFamily: "system-ui, sans-serif" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 20, marginBottom: 28 }}>
        <div><h1 style={{ margin: 0 }}>DadaDevourer</h1><p style={{ margin: "6px 0 0", color: "#666" }}>Authorized security testing dashboard</p></div>
        <button onClick={signOut} style={{ padding: "9px 14px", borderRadius: 8, border: "1px solid #ccc", background: "white", cursor: "pointer" }}>Sign out</button>
      </header>

      <section style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 28 }}>
        {[['Targets', targets.length], ['Active scans', activeCount], ['Completed scans', completedCount]].map(([label, value]) => <div key={String(label)} style={{ border: "1px solid #e5e5e5", borderRadius: 12, padding: 18, background: "#fafafa" }}><div style={{ color: "#666", fontSize: 13 }}>{label}</div><div style={{ fontSize: 28, fontWeight: 700, marginTop: 5 }}>{value}</div></div>)}
      </section>

      <section style={{ border: "1px solid #e5e5e5", borderRadius: 12, padding: 20, marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>{editingId ? "Edit target" : "Add authorized target"}</h2>
        <form onSubmit={saveTarget} style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 10 }}>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={200} placeholder="Target name (optional)" style={{ padding: 11, border: "1px solid #ccc", borderRadius: 8 }} />
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" type="url" required style={{ padding: 11, border: "1px solid #ccc", borderRadius: 8 }} />
          <button disabled={busy} type="submit" style={{ padding: "11px 18px", border: 0, borderRadius: 8, cursor: "pointer" }}>{editingId ? "Save changes" : "Add target"}</button>
        </form>
        {editingId && <button disabled={busy} onClick={cancelEdit} style={{ marginTop: 10, padding: "8px 12px", borderRadius: 7, border: "1px solid #bbb", background: "white", cursor: "pointer" }}>Cancel edit</button>}
        {message && <p style={{ marginBottom: 0, color: "#555" }}>{message}</p>}
      </section>

      <section style={{ border: "1px solid #e5e5e5", borderRadius: 12, padding: 20, marginBottom: 24, overflowX: "auto" }}>
        <h2 style={{ marginTop: 0 }}>Targets</h2>
        {targets.length === 0 ? <p style={{ color: "#777" }}>No targets yet. Add an authorized target above.</p> : <table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr><th align="left">Name</th><th align="left">URL</th><th align="right">Actions</th></tr></thead><tbody>{targets.map((target) => <tr key={target.id} style={{ borderTop: "1px solid #eee" }}><td style={{ padding: "12px 4px" }}>{target.name || "Unnamed target"}</td><td style={{ padding: "12px 4px", wordBreak: "break-all" }}>{target.url}</td><td align="right" style={{ whiteSpace: "nowrap" }}><button disabled={busy} onClick={() => runHeaderScan(target.id)} style={{ padding: "8px 12px", borderRadius: 7, border: "1px solid #bbb", background: "white", cursor: "pointer", marginLeft: 6 }}>Header scan</button><button disabled={busy} onClick={() => startEdit(target)} style={{ padding: "8px 12px", borderRadius: 7, border: "1px solid #bbb", background: "white", cursor: "pointer", marginLeft: 6 }}>Edit</button><button disabled={busy} onClick={() => deleteTarget(target)} style={{ padding: "8px 12px", borderRadius: 7, border: "1px solid #bbb", background: "white", cursor: "pointer", marginLeft: 6 }}>Delete</button></td></tr>)}</tbody></table>}
      </section>

      <section style={{ border: "1px solid #e5e5e5", borderRadius: 12, padding: 20, overflowX: "auto" }}>
        <h2 style={{ marginTop: 0 }}>Recent scans</h2>
        {scans.length === 0 ? <p style={{ color: "#777" }}>No scans have been run.</p> : <table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr><th align="left">Scan</th><th align="left">Scanner</th><th align="left">Status</th><th align="left">Created</th><th align="right">Details</th></tr></thead><tbody>{scans.map((scan) => <tr key={scan.id} style={{ borderTop: "1px solid #eee" }}><td style={{ padding: "12px 4px" }}>#{scan.id}</td><td>{scan.scanner}</td><td><b>{scan.status}</b></td><td>{new Date(scan.created_at).toLocaleString()}</td><td align="right"><button onClick={() => viewScan(scan.id)} style={{ padding: "7px 11px", borderRadius: 7, border: "1px solid #bbb", background: "white", cursor: "pointer" }}>View</button></td></tr>)}</tbody></table>}
      </section>

      {selected && <section style={{ border: "1px solid #e5e5e5", borderRadius: 12, padding: 20, marginTop: 24 }}><div style={{ display: "flex", justifyContent: "space-between" }}><h2 style={{ marginTop: 0 }}>Scan #{selected.id}</h2><button onClick={() => setSelected(null)} style={{ border: 0, background: "none", cursor: "pointer" }}>Close</button></div><p>Status: <b>{selected.status}</b></p>{selected.error && <p>{selected.error}</p>}<table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr><th align="left">Check</th><th align="left">Severity</th><th align="left">Status</th><th align="left">Value</th></tr></thead><tbody>{selected.findings.map((finding, index) => <tr key={`${finding.check}-${index}`} style={{ borderTop: "1px solid #eee" }}><td style={{ padding: "10px 4px" }}>{finding.check}</td><td>{finding.severity}</td><td>{finding.status}</td><td style={{ wordBreak: "break-all" }}>{finding.value || "—"}</td></tr>)}</tbody></table></section>}
    </main>
  );
}
