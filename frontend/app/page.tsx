"use client";

import { useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export default function Home() {
  const [token, setToken] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [targetId, setTargetId] = useState<number | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [result, setResult] = useState<any>(null);
  const [message, setMessage] = useState("");

  async function createTargetAndScan() {
    if (!token || !targetUrl) { setMessage("Login first and enter a target URL."); return; }
    setMessage("Saving target…");
    const t = await fetch(`${API}/targets`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ url: targetUrl }) });
    if (!t.ok) { setMessage((await t.json()).detail || "Target creation failed"); return; }
    const target = await t.json(); setTargetId(target.id);
    const s = await fetch(`${API}/scans/headers`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ target_id: target.id }) });
    const scan = await s.json();
    if (!s.ok) { setMessage(scan.detail || "Scan creation failed"); return; }
    setScanId(scan.id); setMessage(`Scan #${scan.id} queued.`);
  }

  useEffect(() => {
    if (!scanId || !token) return;
    const timer = setInterval(async () => {
      const r = await fetch(`${API}/scans/${scanId}`, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) return;
      const data = await r.json(); setResult(data); setMessage(`Scan #${scanId}: ${data.status}`);
      if (["completed", "failed"].includes(data.status)) clearInterval(timer);
    }, 1500);
    return () => clearInterval(timer);
  }, [scanId, token]);

  return <main style={{maxWidth:1000,margin:"50px auto",padding:24,fontFamily:"system-ui"}}>
    <h1>DadaDevourer</h1><p>Security testing platform · Async scan engine</p>
    <section style={{marginTop:25}}><input value={token} onChange={e=>setToken(e.target.value)} placeholder="Paste JWT access token" style={{width:"100%",padding:12,marginBottom:10}}/><input value={targetUrl} onChange={e=>setTargetUrl(e.target.value)} placeholder="https://example.com" style={{width:"100%",padding:12}}/><button onClick={createTargetAndScan} style={{marginTop:10,padding:"10px 20px"}}>Run Header Scan</button></section>
    <p>{message}</p>
    {result && <section><h2>Scan #{result.id}</h2><p>Status: <b>{result.status}</b></p>{result.error && <p>{result.error}</p>}<table style={{width:"100%",borderCollapse:"collapse"}}><thead><tr><th align="left">Check</th><th align="left">Severity</th><th align="left">Status</th><th align="left">Value</th></tr></thead><tbody>{result.findings.map((f:any)=><tr key={f.check}><td style={{padding:"10px 4px"}}>{f.check}</td><td>{f.severity}</td><td>{f.status}</td><td style={{wordBreak:"break-all"}}>{f.value || "—"}</td></tr>)}</tbody></table></section>}
  </main>;
}
