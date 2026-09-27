import Database from "@tauri-apps/plugin-sql";

let dbPromise: Promise<Database> | undefined;

export type ProjectRecord = {
  id?: number; name: string; client: string; description?: string; status: string;
  startDate?: string; endDate?: string; authorizationNotes?: string; createdAt: string;
};
export type TargetRecord = {
  id?: number; projectId: number; url: string; name?: string; environment?: string;
  tags?: string; authorized: boolean; authorizationExpiresAt?: string; createdAt: string;
};
export type ScanRecord = {
  id?: number; targetId: number; projectId: number; scanner: string; status: string;
  findingsCount: number; statusCode?: number; finalUrl?: string; error?: string;
  createdAt: string; startedAt?: string; finishedAt?: string;
};
export type FindingRecord = {
  id?: number; scanId: number; targetId: number; check: string; title?: string;
  severity: string; status: string; description?: string; evidence?: string;
  recommendation?: string; reference?: string; value?: string; createdAt?: string; updatedAt?: string;
};
export type AuditRecord = { id?: number; action: string; objectType: string; objectId?: number; details?: string; createdAt: string };
export type ReportRecord = { id?: number; projectId: number; scanId: number; name: string; createdAt: string };

type Row = Record<string, unknown>;
async function db() { return (dbPromise ??= Database.load("sqlite:dadadevourer.db")); }
async function hasColumn(database: Database, table: string, column: string) {
  const rows = await database.select<Row[]>(`PRAGMA table_info(${table})`);
  return rows.some(row => row.name === column);
}
async function addColumn(database: Database, table: string, column: string, definition: string) {
  if (!(await hasColumn(database, table, column))) await database.execute(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

export async function initDatabase() {
  const database = await db();
  await database.execute("PRAGMA foreign_keys = ON");
  await database.execute("CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, client TEXT NOT NULL DEFAULT '', description TEXT, status TEXT NOT NULL DEFAULT 'active', start_date TEXT, end_date TEXT, authorization_notes TEXT, created_at TEXT NOT NULL)");
  await database.execute("CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, authorized INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)");
  await database.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, status TEXT NOT NULL, findings_count INTEGER NOT NULL DEFAULT 0, status_code INTEGER, final_url TEXT, error TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT)");
  await database.execute("CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, check_name TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, value TEXT)");
  await addColumn(database, "targets", "project_id", "INTEGER");
  await addColumn(database, "targets", "name", "TEXT");
  await addColumn(database, "targets", "environment", "TEXT");
  await addColumn(database, "targets", "tags", "TEXT");
  await addColumn(database, "targets", "authorization_expires_at", "TEXT");
  await addColumn(database, "scans", "project_id", "INTEGER");
  await addColumn(database, "scans", "scanner", "TEXT NOT NULL DEFAULT 'headers'");
  await addColumn(database, "findings", "target_id", "INTEGER");
  await addColumn(database, "findings", "title", "TEXT");
  await addColumn(database, "findings", "description", "TEXT");
  await addColumn(database, "findings", "evidence", "TEXT");
  await addColumn(database, "findings", "recommendation", "TEXT");
  await addColumn(database, "findings", "reference", "TEXT");
  await addColumn(database, "findings", "created_at", "TEXT");
  await addColumn(database, "findings", "updated_at", "TEXT");
  await database.execute("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, object_type TEXT NOT NULL, object_id INTEGER, details TEXT, created_at TEXT NOT NULL)");
  await database.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL, scan_id INTEGER NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL)");
  const projects = await database.select<Row[]>("SELECT id FROM projects ORDER BY id LIMIT 1");
  if (!projects.length) await database.execute("INSERT INTO projects (name,client,status,created_at) VALUES ('Default Assessment','Local','active',?)", [new Date().toISOString()]);
  const projectId = Number((await database.select<Row[]>("SELECT id FROM projects ORDER BY id LIMIT 1"))[0].id);
  await database.execute("UPDATE targets SET project_id = ? WHERE project_id IS NULL", [projectId]);
  await database.execute("UPDATE scans SET project_id = COALESCE(project_id, (SELECT project_id FROM targets WHERE targets.id=scans.target_id), ?)", [projectId]);
  await database.execute("UPDATE findings SET target_id = COALESCE(target_id, (SELECT target_id FROM scans WHERE scans.id=findings.scan_id))");
  await database.execute("UPDATE findings SET created_at = COALESCE(created_at, ?), updated_at = COALESCE(updated_at, ?)", [new Date().toISOString(), new Date().toISOString()]);
  await database.execute("CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id)");
  await database.execute("CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id)");
  await database.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id)");
}

const mapProject=(r:Row):ProjectRecord=>({id:Number(r.id),name:String(r.name),client:String(r.client??""),description:r.description as string|undefined,status:String(r.status),startDate:r.start_date as string|undefined,endDate:r.end_date as string|undefined,authorizationNotes:r.authorization_notes as string|undefined,createdAt:String(r.created_at)});
const mapTarget=(r:Row):TargetRecord=>({id:Number(r.id),projectId:Number(r.project_id),url:String(r.url),name:r.name as string|undefined,environment:r.environment as string|undefined,tags:r.tags as string|undefined,authorized:Boolean(r.authorized),authorizationExpiresAt:r.authorization_expires_at as string|undefined,createdAt:String(r.created_at)});
const mapScan=(r:Row):ScanRecord=>({id:Number(r.id),targetId:Number(r.target_id),projectId:Number(r.project_id),scanner:String(r.scanner??"headers"),status:String(r.status),findingsCount:Number(r.findings_count??0),statusCode:r.status_code as number|undefined,finalUrl:r.final_url as string|undefined,error:r.error as string|undefined,createdAt:String(r.created_at),startedAt:r.started_at as string|undefined,finishedAt:r.finished_at as string|undefined});
const mapFinding=(r:Row):FindingRecord=>({id:Number(r.id),scanId:Number(r.scan_id),targetId:Number(r.target_id),check:String(r.check_name),title:r.title as string|undefined,severity:String(r.severity),status:String(r.status),description:r.description as string|undefined,evidence:r.evidence as string|undefined,recommendation:r.recommendation as string|undefined,reference:r.reference as string|undefined,value:r.value as string|undefined,createdAt:r.created_at as string|undefined,updatedAt:r.updated_at as string|undefined});

export async function listProjects(){return (await (await db()).select<Row[]>("SELECT * FROM projects ORDER BY id DESC")).map(mapProject)}
export async function addProject(p:ProjectRecord){const r=await (await db()).execute("INSERT INTO projects (name,client,description,status,start_date,end_date,authorization_notes,created_at) VALUES (?,?,?,?,?,?,?,?)",[p.name,p.client,p.description??null,p.status,p.startDate??null,p.endDate??null,p.authorizationNotes??null,p.createdAt]);await audit("project.created","project",Number(r.lastInsertId),p.name);return Number(r.lastInsertId)}
export async function updateProject(id:number,p:Partial<ProjectRecord>){const fields:string[]=[];const values:unknown[]=[];const map:Record<string,string>={name:"name",client:"client",description:"description",status:"status",startDate:"start_date",endDate:"end_date",authorizationNotes:"authorization_notes"};for(const [k,c] of Object.entries(map))if(k in p){fields.push(`${c}=?`);values.push((p as Row)[k]??null)}if(fields.length){values.push(id);await (await db()).execute(`UPDATE projects SET ${fields.join(",")} WHERE id=?`,values);await audit("project.updated","project",id,"Project updated")}}
export async function deleteProject(id:number){const count=Number((await (await db()).select<Row[]>("SELECT COUNT(*) c FROM targets WHERE project_id=?",[id]))[0].c);if(count)throw new Error("Remove or reassign project targets before deleting the project.");await (await db()).execute("DELETE FROM projects WHERE id=?",[id]);await audit("project.deleted","project",id,"Project deleted")}

export async function listTargets(){return (await (await db()).select<Row[]>("SELECT * FROM targets ORDER BY id DESC")).map(mapTarget)}
export async function addTarget(t:TargetRecord){const r=await (await db()).execute("INSERT INTO targets (project_id,url,name,environment,tags,authorized,authorization_expires_at,created_at) VALUES (?,?,?,?,?,?,?,?)",[t.projectId,t.url,t.name??null,t.environment??"production",t.tags??null,t.authorized?1:0,t.authorizationExpiresAt??null,t.createdAt]);await audit("target.created","target",Number(r.lastInsertId),t.url);return Number(r.lastInsertId)}
export async function updateTarget(id:number,p:Partial<TargetRecord>){const fields:string[]=[];const values:unknown[]=[];const map:Record<string,string>={projectId:"project_id",url:"url",name:"name",environment:"environment",tags:"tags",authorized:"authorized",authorizationExpiresAt:"authorization_expires_at"};for(const [k,c] of Object.entries(map))if(k in p){fields.push(`${c}=?`);const v=(p as Row)[k];values.push(k==="authorized"?(v?1:0):v??null)}if(fields.length){values.push(id);await (await db()).execute(`UPDATE targets SET ${fields.join(",")} WHERE id=?`,values);await audit("target.updated","target",id,"Target updated")}}
export async function deleteTarget(id:number){await (await db()).execute("DELETE FROM targets WHERE id=?",[id]);await audit("target.deleted","target",id,"Target deleted")}

export async function addScan(s:ScanRecord){const r=await (await db()).execute("INSERT INTO scans (target_id,project_id,scanner,status,findings_count,status_code,final_url,error,created_at,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",[s.targetId,s.projectId,s.scanner,s.status,s.findingsCount,s.statusCode??null,s.finalUrl??null,s.error??null,s.createdAt,s.startedAt??null,s.finishedAt??null]);await audit("scan.created","scan",Number(r.lastInsertId),s.scanner);return Number(r.lastInsertId)}
export async function updateScan(id:number,p:Partial<ScanRecord>){const fields:string[]=[];const values:unknown[]=[];const map:Record<string,string>={status:"status",scanner:"scanner",findingsCount:"findings_count",statusCode:"status_code",finalUrl:"final_url",error:"error",startedAt:"started_at",finishedAt:"finished_at"};for(const [k,c] of Object.entries(map))if(k in p){fields.push(`${c}=?`);values.push((p as Row)[k]??null)}if(fields.length){values.push(id);await (await db()).execute(`UPDATE scans SET ${fields.join(",")} WHERE id=?`,values)}}
export async function listScans(){return (await (await db()).select<Row[]>("SELECT * FROM scans ORDER BY id DESC")).map(mapScan)}
export async function addFinding(f:FindingRecord){await (await db()).execute("INSERT INTO findings (scan_id,target_id,check_name,title,severity,status,description,evidence,recommendation,reference,value,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",[f.scanId,f.targetId,f.check,f.title??f.check,f.severity,f.status,f.description??null,f.evidence??null,f.recommendation??null,f.reference??null,f.value??null,f.createdAt??new Date().toISOString(),f.updatedAt??new Date().toISOString()])}
export async function listFindings(scanId?:number){const rows=scanId!==undefined?await (await db()).select<Row[]>("SELECT * FROM findings WHERE scan_id=? ORDER BY id",[scanId]):await (await db()).select<Row[]>("SELECT * FROM findings ORDER BY id");return rows.map(mapFinding)}
export async function updateFinding(id:number,p:Partial<FindingRecord>){const fields:string[]=[];const values:unknown[]=[];const map:Record<string,string>={title:"title",severity:"severity",status:"status",description:"description",evidence:"evidence",recommendation:"recommendation",reference:"reference",value:"value"};for(const [k,c] of Object.entries(map))if(k in p){fields.push(`${c}=?`);values.push((p as Row)[k]??null)}if(fields.length){fields.push("updated_at=?");values.push(new Date().toISOString(),id);await (await db()).execute(`UPDATE findings SET ${fields.join(",")} WHERE id=?`,values);await audit("finding.updated","finding",id,JSON.stringify(p))}}
export async function audit(action:string,objectType:string,objectId?:number,details?:string){await (await db()).execute("INSERT INTO audit_logs (action,object_type,object_id,details,created_at) VALUES (?,?,?,?,?)",[action,objectType,objectId??null,details??null,new Date().toISOString()])}
export async function listAudit(){return await (await db()).select<AuditRecord[]>("SELECT id,action,object_type as objectType,object_id as objectId,details,created_at as createdAt FROM audit_logs ORDER BY id DESC LIMIT 100")}
export async function addReport(r:ReportRecord){const id=await (async()=>{const x=await (await db()).execute("INSERT INTO reports (project_id,scan_id,name,created_at) VALUES (?,?,?,?)",[r.projectId,r.scanId,r.name,r.createdAt]);return Number(x.lastInsertId)})();await audit("report.generated","report",id,r.name);return id}
export async function listReports(){return await (await db()).select<ReportRecord[]>("SELECT id,project_id as projectId,scan_id as scanId,name,created_at as createdAt FROM reports ORDER BY id DESC")}
