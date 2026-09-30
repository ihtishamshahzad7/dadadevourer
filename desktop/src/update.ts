import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export type UpdateProgress =
  | { event: "Started"; contentLength: number | null }
  | { event: "Progress"; downloaded: number; contentLength: number | null }
  | { event: "Finished" };

export type AvailableUpdate = {
  version: string;
  notes: string;
  date: string | null;
};

let pendingUpdate: Update | null = null;

async function closePendingUpdate() {
  if (!pendingUpdate) return;
  try {
    await pendingUpdate.close();
  } catch {
    // The native updater resource may already be released after install.
  }
  pendingUpdate = null;
}

export async function checkForUpdate(): Promise<AvailableUpdate | null> {
  await closePendingUpdate();

  const update = await check({ timeout: 15000 });
  if (!update) return null;

  pendingUpdate = update;
  return {
    version: update.version,
    notes: update.body ?? "",
    date: update.date ?? null,
  };
}

export async function downloadUpdate(
  onProgress?: (progress: UpdateProgress) => void,
) {
  if (!pendingUpdate) {
    throw new Error("No update is available. Check for updates first.");
  }

  let downloaded = 0;
  let contentLength: number | null = null;

  await pendingUpdate.download((event) => {
    if (event.event === "Started") {
      contentLength = event.data.contentLength ?? null;
      onProgress?.({ event: "Started", contentLength });
    } else if (event.event === "Progress") {
      downloaded += event.data.chunkLength;
      onProgress?.({ event: "Progress", downloaded, contentLength });
    } else {
      onProgress?.({ event: "Finished" });
    }
  });
}

export async function installUpdate() {
  if (!pendingUpdate) {
    throw new Error("No downloaded update is available.");
  }

  await pendingUpdate.install({ restartAfterInstall: true });
  pendingUpdate = null;

  // Windows exits when the installer is launched. On platforms that do not,
  // explicitly relaunch so the newly installed version becomes active.
  await relaunch();
}
