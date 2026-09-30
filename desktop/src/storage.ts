import { load, Store } from "@tauri-apps/plugin-store";

export type TargetRecord = { url: string; authorized: boolean; createdAt: string };
export type FindingRecord = {
  check: string;
  severity: string;
  status: string;
  value?: string;
  scanId: string;
  target: string;
};
export type ScanRecord = {
  id: string;
  target: string;
  status: "queued" | "running" | "completed" | "failed";
  findings: FindingRecord[];
  statusCode?: number;
  finalUrl?: string;
  error?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
};

export type DesktopState = { targets: TargetRecord[]; scans: ScanRecord[] };

const STORE_FILE = "dadadevourer.json";
const STATE_KEY = "state";
let storePromise: Promise<Store> | undefined;

function getStore() {
  return (storePromise ??= load(STORE_FILE, { autoSave: true, defaults: {} }));
}

export async function loadState(): Promise<DesktopState> {
  try {
    const store = await getStore();
    const value = await store.get<DesktopState>(STATE_KEY);
    if (!value) return { targets: [], scans: [] };
    return {
      targets: Array.isArray(value.targets) ? value.targets : [],
      scans: Array.isArray(value.scans) ? value.scans : [],
    };
  } catch {
    return { targets: [], scans: [] };
  }
}

export async function saveState(state: DesktopState): Promise<void> {
  const store = await getStore();
  await store.set(STATE_KEY, state);
  await store.save();
}
