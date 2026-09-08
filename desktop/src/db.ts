import Database from "@tauri-apps/plugin-sql";

let dbPromise: Promise<Database> | undefined;

export type TargetRecord = { id?: number; url: string; authorized: boolean; createdAt: string };
export type ScanRecord = { id?: number; targetId: number; status: string; findingsCount: number; statusCode?: number; finalUrl?: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type FindingRecord = { id?: number; scanId: number; check: string; severity: string; status: string; value?: string };

async function db() {
  return (dbPromise ??= Database.load("sqlite:dadadevourer.db"));
}

export async function initDatabase() {
  const database = await db();
  await database.execute(`CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, authorized INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)`);
  await database.execute(`CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, status TEXT NOT NULL, findings_count INTEGER NOT NULL DEFAULT 0, status_code INTEGER, final_url TEXT, error TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT)`);
  await database.execute(`CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, check_name TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, value TEXT)`);
  await database.execute(`CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id)`);
  await database.execute(`CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)`);
}

export async function listTargets() { return (await db()).select<TargetRecord[]>("SELECT id, url, authorized, created_at as createdAt FROM targets ORDER BY id DESC"); }
export async function addTarget(target: TargetRecord) { const result = await (await db()).execute("INSERT INTO targets (url, authorized, created_at) VALUES (?, ?, ?)", [target.url, target.authorized ? 1 : 0, target.createdAt]); return Number(result.lastInsertId); }
export async function deleteTarget(id: number) { await (await db()).execute("DELETE FROM targets WHERE id = ?", [id]); }
export async function addScan(scan: ScanRecord) { const result = await (await db()).execute("INSERT INTO scans (target_id,status,findings_count,status_code,final_url,error,created_at,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?)", [scan.targetId,scan.status,scan.findingsCount,scan.statusCode ?? null,scan.finalUrl ?? null,scan.error ?? null,scan.createdAt,scan.startedAt ?? null,scan.finishedAt ?? null]); return Number(result.lastInsertId); }
export async function updateScan(id: number, patch: Partial<ScanRecord>) { const fields: string[] = []; const values: unknown[] = []; const map: Record<string,string> = { status:"status", findingsCount:"findings_count", statusCode:"status_code", finalUrl:"final_url", error:"error", startedAt:"started_at", finishedAt:"finished_at" }; for (const [key,column] of Object.entries(map)) if (key in patch) { fields.push(`${column} = ?`); values.push((patch as Record<string,unknown>)[key] ?? null); } if (!fields.length) return; values.push(id); await (await db()).execute(`UPDATE scans SET ${fields.join(", ")} WHERE id = ?`, values); }
export async function addFinding(finding: FindingRecord) { await (await db()).execute("INSERT INTO findings (scan_id,check_name,severity,status,value) VALUES (?,?,?,?,?)", [finding.scanId,finding.check,finding.severity,finding.status,finding.value ?? null]); }
export async function listScans() { return (await db()).select<ScanRecord[]>("SELECT id,target_id as targetId,status,findings_count as findingsCount,status_code as statusCode,final_url as finalUrl,error,created_at as createdAt,started_at as startedAt,finished_at as finishedAt FROM scans ORDER BY id DESC"); }
export async function listFindings(scanId: number) { return (await db()).select<FindingRecord[]>("SELECT id,scan_id as scanId,check_name as check,severity,status,value FROM findings WHERE scan_id = ? ORDER BY id", [scanId]); }
