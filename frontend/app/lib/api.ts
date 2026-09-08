export const API=process.env.NEXT_PUBLIC_API_URL||"http://localhost:8000/api/v1";

function csrfToken(){
  if(typeof document==="undefined") return "";
  const match=document.cookie.split("; ").find(row=>row.startsWith("dd_csrf="));
  return match?decodeURIComponent(match.split("=").slice(1).join("=")):"";
}

export async function api(path:string,init:RequestInit={}){
  const method=(init.method||"GET").toUpperCase();
  const headers=new Headers(init.headers);
  if(["POST","PUT","PATCH","DELETE"].includes(method)){
    const csrf=csrfToken();
    if(csrf) headers.set("X-CSRF-Token",csrf);
  }
  const r=await fetch(`${API}${path}`,{...init,credentials:"include",headers});
  if(r.status===401&&typeof window!=="undefined") window.location.href="/login";
  return r;
}
