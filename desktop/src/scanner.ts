import { Command } from "@tauri-apps/plugin-shell";

export type ScannerFinding = {
  check: string; title?: string; severity: string; status: string; description?: string;
  evidence?: string; recommendation?: string; reference?: string; value?: string;
};
export type ScanModule = "headers" | "tls" | "technology" | "assessment";
export type ScanResult = { url: string; status_code?: number; redirect_chain?: Array<{url:string;status_code:number}>; findings: ScannerFinding[]; modules?: string[] };

type ScannerMessage={id?:string;event?:string;data?:ScanResult;error?:string};
const SIDE_CAR="binaries/dadadevourer-scanner";

function parseMessage(line:string):ScannerMessage{
  const value:unknown=JSON.parse(line);
  if(!value || typeof value!=="object") throw new Error("Scanner returned an invalid message");
  return value as ScannerMessage;
}

export async function runScan(target:string,module:ScanModule="assessment",timeoutMs=60000):Promise<ScanResult>{
  const id=crypto.randomUUID(); const command=Command.sidecar(SIDE_CAR); let settled=false; let buffer="";
  const commandName=module==="headers"?"headers_scan":module==="tls"?"tls_scan":module==="technology"?"tech_scan":"assessment_scan";
  return new Promise<ScanResult>(async(resolve,reject)=>{
    let child:{kill:()=>Promise<void>}|undefined;
    const timer=window.setTimeout(()=>{void child?.kill().catch(()=>undefined);finishError(new Error("Scanner timed out. The scan was stopped by the desktop safety timeout."));},timeoutMs);
    const finishError=(error:Error)=>{if(settled)return;settled=true;window.clearTimeout(timer);reject(error)};
    const finishSuccess=(result:ScanResult)=>{if(settled)return;settled=true;window.clearTimeout(timer);resolve(result)};
    command.stdout.on("data",(chunk)=>{buffer+=String(chunk);const lines=buffer.split(/\r?\n/);buffer=lines.pop()??"";for(const line of lines.map(x=>x.trim()).filter(Boolean)){try{const m=parseMessage(line);if(m.id!==id)continue;if(m.event==="error")finishError(new Error(m.error||"Scanner failed"));else if(m.event==="result"&&m.data)finishSuccess(m.data)}catch(e){finishError(e instanceof Error?e:new Error(String(e)))}}});
    command.stderr.on("data",(chunk)=>console.warn("DadaDevourer scanner:",String(chunk)));
    command.on("error",(error)=>finishError(new Error(String(error))));
    command.on("close",({code,signal})=>{if(!settled)finishError(new Error(`Scanner exited before returning a result (code=${code??"unknown"}, signal=${signal??"none"})`))});
    try{child=await command.spawn();await child.write(JSON.stringify({id,command:commandName,target})+"\n")}catch(e){finishError(e instanceof Error?e:new Error(String(e)))}
  });
}
export const runHeadersScan=(target:string)=>runScan(target,"headers");
