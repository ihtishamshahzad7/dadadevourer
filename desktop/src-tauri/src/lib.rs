#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(tauri::plugin::Builder::new("dev").build())?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running DadaDevourer");
}
