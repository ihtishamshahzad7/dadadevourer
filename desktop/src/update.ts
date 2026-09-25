import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export type UpdateProgress =
  | { event: "Started"; contentLength: number | null }
  | { event: "Progress"; downloaded: number; contentLength: number | null }
  | { event: "Finished" };

export async function checkForUpdate(
  onProgress?: (progress: UpdateProgress) => void,
) {
  const update = await check();
  if (!update) return null;

  let downloaded = 0;
  let contentLength: number | null = null;

  await update.downloadAndInstall((event) => {
    if (event.event === "Started") {
      contentLength = event.data.contentLength ?? null;
      onProgress?.({
        event: "Started",
        contentLength,
      });
    } else if (event.event === "Progress") {
      downloaded += event.data.chunkLength;
      onProgress?.({
        event: "Progress",
        downloaded,
        contentLength,
      });
    } else if (event.event === "Finished") {
      onProgress?.({ event: "Finished" });
    }
  });

  return {
    version: update.version,
    notes: update.body ?? "",
    date: update.date ?? null,
  };
}

export async function restartAfterUpdate() {
  await relaunch();
}
