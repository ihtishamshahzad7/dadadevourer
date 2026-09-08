export const API=process.env.NEXT_PUBLIC_API_URL||"http://localhost:8000/api/v1";
export function authHeaders(){const token=typeof window!=="undefined"?localStorage.getItem("access_token"):null;return token?{Authorization:`Bearer ${token}`}:{}}
export async function api(path:string,init:RequestInit={}){const r=await fetch(`${API}${path}`,{...init,headers:{...authHeaders(),...(init.headers||{})}});if(r.status===401&&typeof window!=="undefined")window.location.href="/login";return r}
