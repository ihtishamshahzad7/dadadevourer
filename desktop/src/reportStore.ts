import Database from "@tauri-apps/plugin-sql";

/** Deletes only report metadata; generated HTML is intentionally not persisted by the current schema. */
export async function deleteReport(id: number): Promise<void> {
  const database = await Database.load("sqlite:dadadevourer.db");
  await database.execute("DELETE FROM reports WHERE id = ?", [id]);
}
