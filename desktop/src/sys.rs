//! Зависящее от системы: системный прокси Windows, автозапуск, открытие ссылок.

use std::path::PathBuf;
use std::sync::OnceLock;

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn init(data_dir: PathBuf) {
    let _ = DATA_DIR.set(data_dir);
    // если программа в прошлый раз упала с включённым прокси — вернуть настройки
    clear_system_proxy();
}

fn data_dir() -> PathBuf {
    DATA_DIR.get().cloned().unwrap_or_else(std::env::temp_dir)
}

pub fn exe_path() -> String {
    // в AppImage текущий файл лежит во временной папке — для автозапуска нужен сам .AppImage
    if let Some(p) = std::env::var_os("APPIMAGE") {
        return p.to_string_lossy().into_owned();
    }
    std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

// ───────── системный прокси (Windows) ─────────
// На macOS и Linux прокси включает и выключает само ядро sing-box (set_system_proxy).

#[cfg(windows)]
const INET: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(windows)]
fn refresh_wininet() {
    use windows_sys::Win32::Networking::WinInet::InternetSetOptionW;
    unsafe {
        // INTERNET_OPTION_SETTINGS_CHANGED = 39, INTERNET_OPTION_REFRESH = 37
        InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
    }
}

#[cfg(windows)]
pub fn set_system_proxy(port: u16) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(INET).map_err(|e| e.to_string())?;
    let marker = data_dir().join("sysproxy.json");
    if !marker.exists() {
        // запомнить прежние настройки пользователя, чтобы вернуть их после отключения
        let enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        let server: String = key.get_value("ProxyServer").unwrap_or_default();
        let over: String = key.get_value("ProxyOverride").unwrap_or_default();
        let saved = serde_json::json!({ "enable": enable, "server": server, "override": over });
        let _ = std::fs::write(&marker, saved.to_string());
    }
    key.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
    key.set_value("ProxyServer", &format!("127.0.0.1:{port}")).map_err(|e| e.to_string())?;
    key.set_value(
        "ProxyOverride",
        &"localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>".to_string(),
    )
    .map_err(|e| e.to_string())?;
    refresh_wininet();
    Ok(())
}

#[cfg(windows)]
pub fn clear_system_proxy() {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let marker = data_dir().join("sysproxy.json");
    let Ok(text) = std::fs::read_to_string(&marker) else { return };
    let saved: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    if let Ok((key, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(INET) {
        let enable = saved.get("enable").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let server = saved.get("server").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let over = saved.get("override").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let _ = key.set_value("ProxyEnable", &enable);
        let _ = key.set_value("ProxyServer", &server);
        let _ = key.set_value("ProxyOverride", &over);
        refresh_wininet();
    }
    let _ = std::fs::remove_file(marker);
}

#[cfg(not(windows))]
pub fn set_system_proxy(_port: u16) -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
pub fn clear_system_proxy() {}

// ───────── автозапуск ─────────

#[cfg(windows)]
const TASK: &str = "NetLine VPN";

#[cfg(windows)]
fn hidden(cmd: &mut std::process::Command) -> &mut std::process::Command {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x0800_0000)
}

#[cfg(windows)]
pub fn autostart_get() -> bool {
    hidden(std::process::Command::new("schtasks").args(["/Query", "/TN", TASK]))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
pub fn autostart_set(on: bool) -> Result<(), String> {
    use std::process::Command;
    if !on {
        let _ = hidden(Command::new("schtasks").args(["/Delete", "/TN", TASK, "/F"])).output();
        return Ok(());
    }
    // Задание планировщика с наивысшими правами: при входе в систему окно UAC не появляется,
    // и оно работает от батареи (обычное schtasks /create этого не умеет — поэтому XML)
    let user = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").unwrap_or_default(),
        std::env::var("USERNAME").unwrap_or_default()
    );
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>NetLine VPN</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>"{exe}"</Command><Arguments>--hidden</Arguments></Exec></Actions>
</Task>
"#,
        user = esc(&user),
        exe = esc(&exe_path())
    );
    let file = data_dir().join("autostart.xml");
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&file, bytes).map_err(|e| e.to_string())?;
    let out = hidden(Command::new("schtasks").arg("/Create").arg("/TN").arg(TASK).arg("/XML").arg(&file).arg("/F"))
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&file);
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("Не удалось включить автозапуск: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

#[cfg(target_os = "macos")]
fn agent_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/LaunchAgents/io.github.uproxe.netline.plist")
}

#[cfg(target_os = "macos")]
pub fn autostart_get() -> bool {
    agent_path().exists()
}

#[cfg(target_os = "macos")]
pub fn autostart_set(on: bool) -> Result<(), String> {
    let p = agent_path();
    if !on {
        let _ = std::fs::remove_file(&p);
        return Ok(());
    }
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.github.uproxe.netline</string>
  <key>ProgramArguments</key><array><string>{}</string><string>--hidden</string></array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
"#,
        esc(&exe_path())
    );
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    std::fs::write(&p, plist).map_err(|e| format!("Не удалось включить автозапуск: {e}"))
}

#[cfg(target_os = "linux")]
fn desktop_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config"));
    base.join("autostart/netline-vpn.desktop")
}

#[cfg(target_os = "linux")]
pub fn autostart_get() -> bool {
    desktop_path().exists()
}

#[cfg(target_os = "linux")]
pub fn autostart_set(on: bool) -> Result<(), String> {
    let p = desktop_path();
    if !on {
        let _ = std::fs::remove_file(&p);
        return Ok(());
    }
    let exe = exe_path().replace('"', "\\\"");
    let text = format!(
        "[Desktop Entry]\nType=Application\nName=NetLine VPN\nExec=\"{exe}\" --hidden\nIcon=netline-vpn\nX-GNOME-Autostart-enabled=true\nX-GNOME-Autostart-Delay=3\nNoDisplay=true\n"
    );
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    std::fs::write(&p, text).map_err(|e| format!("Не удалось включить автозапуск: {e}"))
}

// ───────── ссылки ─────────

pub fn open_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("Можно открыть только адрес https".into());
    }
    #[cfg(windows)]
    let r = hidden(&mut std::process::Command::new("rundll32")).args(["url.dll,FileProtocolHandler", url]).spawn();
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let r = std::process::Command::new("xdg-open").arg(url).spawn();
    r.map(|_| ()).map_err(|e| e.to_string())
}
