"use client";

import { useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function scan() {
    setLoading(true); setError(""); setResult(null);
    try {
      const res = await fetch(`${API}/scans/headers`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Scan failed");
      setResult(data);
    } catch (e: any) { setError(e.message); } finally { setLoading(false); }
  }

  return <main style={{maxWidth: 1000, margin: "60px auto", padding: 24, fontFamily: "system-ui"}}>
    <h1>DadaDevourer</h1><p>Security testing platform · Phase 1</p>
    <section style={{display:"flex", gap:12, marginTop:30}}>
      <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://example.com" style={{flex:1,padding:14,border:"1px solid #ccc",borderRadius:8}} />
      <button onClick={scan} disabled={loading || !url} style={{padding:"0 24px",borderRadius:8}}>{loading ? "Scanning…" : "Scan Headers"}</button>
    </section>
    {error && <p style={{color:"crimson"}}>{error}</p>}
    {result && <section style={{marginTop:30}}><h2>Security Headers</h2><p>HTTP {result.status_code} · {result.url}</p><table style={{width:"100%",borderCollapse:"collapse"}}><thead><tr><th align="left">Header</th><th align="left">Severity</th><th align="left">Status</th><th align="left">Value</th></tr></thead><tbody>{result.findings.map((f:any)=><tr key={f.header}><td style={{padding:"12px 4px"}}>{f.header}</td><td>{f.severity}</td><td>{f.status}</td><td style={{wordBreak:"break-all"}}>{f.value || "—"}</td></tr>)}</tbody></table></section>}
  </main>;
}
