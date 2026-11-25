// NetLine VPN для Windows, macOS и Linux.
// Интерфейс — общая страница ui/ (та же, что на Android), здесь — окно, трей и запуск ядер.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod net;
mod sys;
mod vpn;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, State, WebviewUrl, WebviewWindowBuilder, Wry};

struct AppState {
    core: Arc<vpn::Core>,
    config_dir: PathBuf,
    rules_dir: PathBuf,
    ready: Mutex<Option<Value>>,
    toggle: Mutex<Option<MenuItem<Wry>>>,
}

type Res<T> = Result<T, String>;

fn arg_str(a: &Value, k: &str) -> String {
    a.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

// ───────── команды для интерфейса ─────────

#[tauri::command]
fn platform(state: State<'_, AppState>, args: Value) -> Value {
    let _ = args;
    let os = if cfg!(windows) { "windows" } else if cfg!(target_os = "macos") { "macos" } else { "linux" };
    json!({
        "os": os,
        "version": env!("CARGO_PKG_VERSION"),
        "cores": {
            "singbox": option_env!("NETLINE_SINGBOX_VERSION").unwrap_or("—"),
            "xray": option_env!("NETLINE_XRAY_VERSION").unwrap_or("—"),
        },
        "rulesDir": state.rules_dir.to_string_lossy(),
        "autostart": sys::autostart_get(),
        "appimage": std::env::var_os("APPIMAGE").is_some(),
    })
}

#[tauri::command]
fn load_state(state: State<'_, AppState>, args: Value) -> Option<String> {
    let _ = args;
    std::fs::read_to_string(state.config_dir.join("state.json")).ok()
}

#[tauri::command]
fn save_state(state: State<'_, AppState>, args: Value) -> Res<()> {
    let data = arg_str(&args, "data");
    let _ = std::fs::create_dir_all(&state.config_dir);
    vpn::write_private(&state.config_dir.join("state.json"), data.as_bytes()).map_err(|e| e.to_string())
}

#[tauri::command]
fn free_ports(args: Value) -> Vec<u16> {
    let n = args.get("count").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
    vpn::free_ports(n)
}

#[tauri::command]
async fn connect(state: State<'_, AppState>, args: Value) -> Res<()> {
    let req = vpn::Request::from_json(&args)?;
    let core = Arc::clone(&state.core);
    tauri::async_runtime::spawn_blocking(move || core.start(req))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>, args: Value) -> Res<()> {
    let _ = args;
    let core = Arc::clone(&state.core);
    tauri::async_runtime::spawn_blocking(move || core.stop()).await.map_err(|e| e.to_string())
}

#[tauri::command]
fn status(state: State<'_, AppState>, args: Value) -> Value {
    let _ = args;
    state.core.status()
}

#[tauri::command]
async fn fetch_url(args: Value) -> Res<Value> {
    let url = arg_str(&args, "url");
    let timeout = args.get("timeout").and_then(|v| v.as_u64()).unwrap_or(20000);
    let headers = args.get("headers").and_then(|v| v.as_object()).cloned().unwrap_or_else(Map::new);
    tauri::async_runtime::spawn_blocking(move || net::fetch(&url, &headers, timeout))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn test_start(state: State<'_, AppState>, args: Value) -> Res<()> {
    let core = Arc::clone(&state.core);
    let singbox = arg_str(&args, "singbox");
    let xray = args.get("xray").and_then(|v| v.as_str()).map(|s| s.to_string());
    let port = args.get("clashPort").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    tauri::async_runtime::spawn_blocking(move || core.test_start(&singbox, xray.as_deref(), port))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn test_stop(state: State<'_, AppState>, args: Value) -> Res<()> {
    let _ = args;
    let core = Arc::clone(&state.core);
    tauri::async_runtime::spawn_blocking(move || core.test_stop()).await.map_err(|e| e.to_string())
}

#[tauri::command]
fn set_ready(state: State<'_, AppState>, args: Value) -> Res<()> {
    let ready = args.get("ready").cloned().filter(|v| !v.is_null());
    let path = state.config_dir.join("ready.json");
    match &ready {
        Some(v) => vpn::write_private(&path, v.to_string().as_bytes()).map_err(|e| e.to_string())?,
        None => {
            let _ = std::fs::remove_file(&path);
        }
    }
    *state.ready.lock().unwrap() = ready;
    Ok(())
}

#[tauri::command]
fn set_autostart(args: Value) -> Res<()> {
    sys::autostart_set(args.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
}

#[tauri::command]
fn log_tail(state: State<'_, AppState>, args: Value) -> String {
    let _ = args;
    vpn::log_tail(&state.core.log, 200)
}

#[tauri::command]
fn open_url(args: Value) -> Res<()> {
    sys::open_url(&arg_str(&args, "url"))
}

#[tauri::command]
fn quit(app: AppHandle, args: Value) {
    let _ = args;
    app.exit(0);
}

// ───────── окно и трей ─────────

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let _ = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("NetLine VPN")
        .inner_size(400.0, 700.0)
        .min_inner_size(360.0, 560.0)
        .center()
        .build();
}

fn tray_image(active: bool) -> Option<Image<'static>> {
    #[cfg(target_os = "macos")]
    let bytes: &'static [u8] = if active {
        include_bytes!("../icons/tray-on-template.png")
    } else {
        include_bytes!("../icons/tray-off-template.png")
    };
    #[cfg(not(target_os = "macos"))]
    let bytes: &'static [u8] = if active { include_bytes!("../icons/tray-on.png") } else { include_bytes!("../icons/tray-off.png") };
    Image::from_bytes(bytes).ok()
}

fn update_tray(app: &AppHandle, active: bool) {
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_icon(tray_image(active));
        #[cfg(target_os = "macos")]
        let _ = tray.set_icon_as_template(true);
        let _ = tray.set_tooltip(Some(if active { "NetLine VPN — подключено" } else { "NetLine VPN — отключено" }));
    }
    if let Some(state) = app.try_state::<AppState>() {
        if let Some(item) = state.toggle.lock().unwrap().as_ref() {
            let _ = item.set_text(if active { "Отключить" } else { "Подключить" });
        }
    }
}

/// Подключить без окна — по последним настройкам из интерфейса
fn connect_ready(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else { return };
    let ready = state.ready.lock().unwrap().clone();
    let Some(ready) = ready else {
        show_window(app);
        return;
    };
    let core = Arc::clone(&state.core);
    let app = app.clone();
    std::thread::spawn(move || {
        if let Ok(req) = vpn::Request::from_json(&ready) {
            if core.start(req).is_err() {
                // окно покажет ошибку
                show_window(&app);
            }
        }
    });
}

fn tray_toggle(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else { return };
    if state.core.is_active() {
        let core = Arc::clone(&state.core);
        std::thread::spawn(move || core.stop());
    } else {
        connect_ready(app);
    }
}

fn build_tray(app: &tauri::App) -> tauri::Result<MenuItem<Wry>> {
    let open = MenuItem::with_id(app, "open", "Открыть NetLine VPN", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Подключить", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &toggle, &sep, &quit])?;
    let mut tb = TrayIconBuilder::with_id("main")
        .tooltip("NetLine VPN")
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_window(app),
            "toggle" => tray_toggle(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_window(tray.app_handle());
            }
        });
    if let Some(img) = tray_image(false) {
        tb = tb.icon(img);
    }
    #[cfg(target_os = "macos")]
    {
        tb = tb.icon_as_template(true);
    }
    tb.build(app)?;
    Ok(toggle)
}

fn main() {
    let hidden = std::env::args().any(|a| a == "--hidden");
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_window(app)))
        .invoke_handler(tauri::generate_handler![
            platform, load_state, save_state, free_ports, connect, disconnect, status, fetch_url, test_start,
            test_stop, set_ready, set_autostart, log_tail, open_url, quit
        ])
        .setup(move |app| {
            let paths = app.path();
            let config_dir = paths.app_config_dir()?;
            let data_dir = paths.app_local_data_dir()?;
            let rules_dir = paths.resource_dir().map(|d| d.join("rules")).unwrap_or_default();
            std::fs::create_dir_all(&config_dir)?;
            std::fs::create_dir_all(&data_dir)?;
            sys::init(data_dir.clone());

            let toggle = build_tray(app).ok();
            let handle = app.handle().clone();
            let core = Arc::new(vpn::Core::new(data_dir.join("run"), Box::new(move |active| update_tray(&handle, active))));
            let ready = std::fs::read_to_string(config_dir.join("ready.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok());
            let auto = ready.as_ref().and_then(|r| r.get("autoConnect")).and_then(|v| v.as_bool()).unwrap_or(false);
            app.manage(AppState { core, config_dir, rules_dir, ready: Mutex::new(ready), toggle: Mutex::new(toggle) });

            if !hidden {
                show_window(app.handle());
            }
            if auto {
                connect_ready(app.handle());
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("не удалось запустить NetLine VPN");

    app.run(|app, event| match event {
        // окно закрыли: если VPN включён — остаёмся в трее (без окна почти не тратим память)
        RunEvent::ExitRequested { code, api, .. } => {
            if code.is_none() {
                if let Some(state) = app.try_state::<AppState>() {
                    if state.core.is_active() {
                        api.prevent_exit();
                    }
                }
            }
        }
        RunEvent::Exit => {
            if let Some(state) = app.try_state::<AppState>() {
                state.core.shutdown();
            }
        }
        _ => {}
    });
}
