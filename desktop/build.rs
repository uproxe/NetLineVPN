fn main() {
    // Windows: программа сразу запускается с правами администратора — без них нельзя
    // создать VPN-подключение (TUN). При автозапуске окно UAC не появляется (задание планировщика).
    let windows = tauri_build::WindowsAttributes::new().app_manifest(include_str!("windows/app.manifest"));
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("tauri-build");
}
