"use client";
import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
export default function Login() {
  const router = useRouter(); const [email,setEmail]=useState(""); const [password,setPassword]=useState(""); const [error,setError]=useState(""); const [loading,setLoading]=useState(false);
  async function submit(e:FormEvent){e.preventDefault();setLoading(true);setError("");try{const r=await fetch(`${API}/auth/login`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password})});const d=await r.json();if(!r.ok)throw new Error(d.detail||"Login failed");localStorage.setItem("access_token",d.access_token);router.push("/");}catch(e:any){setError(e.message)}finally{setLoading(false)}}
  return <main style={{maxWidth:420,margin:"100px auto",padding:24,fontFamily:"system-ui"}}><h1>Sign in</h1><p>Access your DadaDevourer workspace.</p><form onSubmit={submit} style={{display:"grid",gap:14,marginTop:28}}><input type="email" required placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} style={{padding:14}}/><input type="password" required placeholder="Password" value={password} onChange={e=>setPassword(e.target.value)} style={{padding:14}}/>{error&&<div style={{color:"crimson"}}>{error}</div>}<button disabled={loading} style={{padding:14}}>{loading?"Signing in…":"Sign in"}</button></form></main>
}