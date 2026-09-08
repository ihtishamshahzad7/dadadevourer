import { open } from "@tauri-apps/plugin-shell";

const RELEASES_API = "https://api.github.com/repos/ihtishamshahzad7/dadadevourer/releases/latest";
const RELEASES_PAGE = "https://github.com/ihtishamshahzad7/dadadevourer/releases/latest";

function versionParts(value: string) {
  return value.replace(/^v/, "").split(".").map((part) => Number.parseInt(part, 10) || 0);
}

export function isNewerVersion(current: string, latest: string) {
  const a = versionParts(current);
  const b = versionParts(latest);
  for (let i = 0; i < 3; i += 1) if ((b[i] ?? 0) !== (a[i] ?? 0)) return (b[i] ?? 0) > (a[i] ?? 0);
  return false;
}

export async function checkForUpdate(currentVersion: string) {
  const response = await fetch(RELEASES_API, { headers: { Accept: "application/vnd.github+json" } });
  if (!response.ok) throw new Error(`Update service returned HTTP ${response.status}`);
  const release = await response.json() as { tag_name?: string; html_url?: string; draft?: boolean; prerelease?: boolean };
  const latest = release.tag_name ?? "";
  return { available: Boolean(latest && !release.draft && !release.prerelease && isNewerVersion(currentVersion, latest)), version: latest.replace(/^v/, ""), url: release.html_url || RELEASES_PAGE };
}

export async function openLatestRelease() {
  await open(RELEASES_PAGE);
}
