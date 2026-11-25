//! Запуск и остановка ядер VPN (sing-box и, если нужно, Xray).
//!
//! Windows: программа запущена от администратора, ядра — обычные дочерние процессы в «задании»
//! (Job Object): если программа упадёт, Windows закроет и их.
//! macOS и Linux: ядро запускается через маленький сценарий sh, который следит за программой.
//! Если программа закрылась или появился файл-стоп, сценарий мягко (SIGTERM) останавливает ядро —
//! sing-box успевает вернуть маршруты и системный прокси на место. Для режима VPN ядру нужны права:
//! в пакетах .deb/.rpm/.pacman их выдаёт setcap, иначе — pkexec (Linux) или окно пароля (macOS).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) { format!("{base}.exe") } else { base.to_string() }
}

/// Папка программы: там же лежат ядра (externalBin в Tauri)
pub fn core_path(base: &str) -> PathBuf {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join(exe_name(base))
}

pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Последние строки журнала ядер
pub fn log_tail(path: &Path, max: usize) -> String {
    let Ok(mut f) = File::open(path) else { return String::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(64 * 1024);
    let _ = f.seek(SeekFrom::Start(start));
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let from = lines.len().saturating_sub(max);
    lines[from..].join("\n")
}

/// Понятная причина ошибки из журнала
fn explain(log: &str) -> String {
    let low = log.to_lowercase();
    let last = log
        .lines()
        .rev()
        .find(|l| {
            let l = l.to_lowercase();
            l.contains("fatal") || l.contains("error") || l.contains("failed")
        })
        .unwrap_or_else(|| log.lines().last().unwrap_or(""))
        .trim()
        .to_string();
    if low.contains("address already in use") || low.contains("only one usage of each socket") {
        return "Порт занят другой программой (возможно, запущен другой VPN-клиент)".into();
    }
    if low.contains("operation not permitted") || low.contains("permission denied") || low.contains("access is denied") {
        return "Нет прав на создание VPN-подключения. Переустановите программу или выберите режим «Прокси»".into();
    }
    if last.is_empty() {
        return "Ядро VPN неожиданно завершилось".into();
    }
    // в строках sing-box время и уровень в начале — оставим суть
    let short = last.splitn(2, "] ").nth(1).unwrap_or(&last).to_string();
    format!("Ошибка ядра: {}", short.chars().take(300).collect::<String>())
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Priv {
    None,
    #[allow(dead_code)]
    Pkexec,
    #[allow(dead_code)]
    Osascript,
}

pub struct Proc {
    pub name: &'static str,
    child: Child,
    stop_file: Option<PathBuf>,
}

#[cfg(unix)]
const WRAPPER: &str = r#"A="$1"; S="$2"; L="$3"; shift 3
"$@" >>"$L" 2>&1 </dev/null &
P=$!
while kill -0 "$P" 2>/dev/null && kill -0 "$A" 2>/dev/null && [ ! -e "$S" ]; do sleep 1; done
kill -TERM "$P" 2>/dev/null
wait "$P"
"#;

#[cfg(unix)]
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(windows)]
mod job {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::JobObjects::*;

    struct Job(HANDLE);
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}
    static JOB: OnceLock<Option<Job>> = OnceLock::new();

    /// Все ядра — в одном задании: если программа завершится, Windows закроет и их
    pub fn adopt(child: &Child) {
        let job = JOB.get_or_init(|| unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            Some(Job(h))
        });
        if let Some(j) = job {
            unsafe {
                AssignProcessToJobObject(j.0, child.as_raw_handle() as HANDLE);
            }
        }
    }
}

impl Proc {
    /// Запустить ядро. exe — путь к ядру, args — его аргументы.
    pub fn spawn(name: &'static str, exe: &Path, args: &[String], log: &Path, run_dir: &Path, how: Priv) -> Result<Proc, String> {
        if !exe.exists() {
            return Err(format!("Не найдено ядро {}: переустановите программу", exe.display()));
        }
        spawn_impl(name, exe, args, log, run_dir, how)
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Мягкая остановка (до 5 секунд), потом принудительная
    pub fn stop(mut self) {
        if let Some(f) = self.stop_file.clone() {
            let _ = File::create(&f);
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(5) {
                if !self.alive() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let _ = fs::remove_file(&f);
        }
        if self.alive() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[cfg(windows)]
fn spawn_impl(name: &'static str, exe: &Path, args: &[String], log: &Path, run_dir: &Path, _how: Priv) -> Result<Proc, String> {
    use std::os::windows::process::CommandExt;
    let out = OpenOptions::new().create(true).append(true).open(log).map_err(|e| e.to_string())?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let child = Command::new(exe)
        .args(args)
        .current_dir(run_dir)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|e| format!("Не удалось запустить {name}: {e}"))?;
    job::adopt(&child);
    Ok(Proc { name, child, stop_file: None })
}

#[cfg(unix)]
fn spawn_impl(name: &'static str, exe: &Path, args: &[String], log: &Path, run_dir: &Path, how: Priv) -> Result<Proc, String> {
    let stop = run_dir.join(format!("stop-{name}-{}", now_ms()));
    let _ = fs::remove_file(&stop);
    let mut tail: Vec<String> = vec![
        std::process::id().to_string(),
        stop.to_string_lossy().into_owned(),
        log.to_string_lossy().into_owned(),
        exe.to_string_lossy().into_owned(),
    ];
    tail.extend(args.iter().cloned());
    let mut cmd = match how {
        Priv::None => {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(WRAPPER).arg("sh").args(&tail);
            c
        }
        Priv::Pkexec => {
            let mut c = Command::new("pkexec");
            c.arg("/bin/sh").arg("-c").arg(WRAPPER).arg("sh").args(&tail);
            c
        }
        Priv::Osascript => {
            let shell = format!(
                "/bin/sh -c {} sh {}",
                sh_quote(WRAPPER),
                tail.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" ")
            );
            let apple = shell.replace('\\', "\\\\").replace('"', "\\\"");
            let script = format!(
                "do shell script \"{apple}\" with administrator privileges with prompt \"NetLine VPN включает VPN для всего компьютера.\""
            );
            let mut c = Command::new("/usr/bin/osascript");
            c.arg("-e").arg(script);
            c
        }
    };
    let errlog = OpenOptions::new().create(true).append(true).open(log).map_err(|e| e.to_string())?;
    let child = cmd
        .current_dir(run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(errlog)
        .spawn()
        .map_err(|e| format!("Не удалось запустить {name}: {e}"))?;
    Ok(Proc { name, child, stop_file: Some(stop) })
}

fn port_open(port: u16) -> bool {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

/// Свободные локальные порты
pub fn free_ports(n: usize) -> Vec<u16> {
    let mut keep = Vec::new();
    for _ in 0..n.min(200) {
        if let Ok(l) = std::net::TcpListener::bind("127.0.0.1:0") {
            keep.push(l);
        }
    }
    keep.iter().filter_map(|l| l.local_addr().ok().map(|a| a.port())).collect()
}

#[derive(Clone, Copy, PartialEq)]
pub enum Phase {
    Off,
    Connecting,
    On,
    Error,
}

impl Phase {
    fn as_str(&self) -> &'static str {
        match self {
            Phase::Off => "off",
            Phase::Connecting => "connecting",
            Phase::On => "on",
            Phase::Error => "error",
        }
    }
}

struct Inner {
    phase: Phase,
    since: u64,
    error: String,
    procs: Vec<Proc>,
    gen: u64,
    clash: (u16, String),
    names: Value,
    mode: String,
    proxy_set: bool,
}

pub struct Core {
    inner: Mutex<Inner>,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    pub run_dir: PathBuf,
    pub log: PathBuf,
    on_change: Box<dyn Fn(bool) + Send + Sync>,
    test: Mutex<Vec<Proc>>,
}

/// Параметры подключения от интерфейса
pub struct Request {
    pub mode: String,
    pub singbox: String,
    pub xray: Option<String>,
    pub clash_port: u16,
    pub clash_secret: String,
    pub proxy_port: u16,
    pub names: Value,
}

impl Request {
    pub fn from_json(v: &Value) -> Result<Request, String> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string());
        let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0) as u16;
        Ok(Request {
            mode: s("mode").unwrap_or_else(|| "tun".into()),
            singbox: s("singbox").ok_or("Нет конфигурации")?,
            xray: s("xray").filter(|x| !x.is_empty()),
            clash_port: n("clashPort"),
            clash_secret: s("clashSecret").unwrap_or_default(),
            proxy_port: n("proxyPort"),
            names: v.get("names").cloned().unwrap_or(Value::Null),
        })
    }
}

fn xray_ports(cfg: &str) -> Vec<u16> {
    serde_json::from_str::<Value>(cfg)
        .ok()
        .and_then(|v| v.get("inbounds").and_then(|i| i.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|i| i.get("port").and_then(|p| p.as_u64()).map(|p| p as u16))
        .collect()
}

/// Как запускать sing-box в режиме VPN на этой системе
#[cfg(target_os = "macos")]
fn tun_privilege(_singbox: &Path) -> Priv {
    Priv::Osascript
}

#[cfg(target_os = "linux")]
fn tun_privilege(singbox: &Path) -> Priv {
    if unsafe { libc::geteuid() } == 0 {
        return Priv::None;
    }
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    if let Ok(p) = CString::new(singbox.as_os_str().as_bytes()) {
        let name = CString::new("security.capability").unwrap();
        let n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if n > 0 {
            return Priv::None;
        }
    }
    Priv::Pkexec
}

#[cfg(windows)]
fn tun_privilege(_singbox: &Path) -> Priv {
    Priv::None
}

/// AppImage смонтирован только для пользователя: root (pkexec) его не видит, поэтому ядро копируем
#[cfg(target_os = "linux")]
fn rootable_copy(exe: &Path, run_dir: &Path) -> PathBuf {
    if std::env::var_os("APPIMAGE").is_none() {
        return exe.to_path_buf();
    }
    let dst = run_dir.join("netline-singbox");
    let same = fs::metadata(&dst).map(|m| m.len()).ok() == fs::metadata(exe).map(|m| m.len()).ok();
    if !same && fs::copy(exe, &dst).is_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(0o755));
    }
    if dst.exists() { dst } else { exe.to_path_buf() }
}

impl Core {
    pub fn new(run_dir: PathBuf, on_change: Box<dyn Fn(bool) + Send + Sync>) -> Core {
        let _ = fs::create_dir_all(&run_dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700));
        }
        // остатки прошлого запуска: конфигурации с ключами и файлы-стопы
        if let Ok(rd) = fs::read_dir(&run_dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.ends_with(".json") || n.starts_with("stop-") || n.ends_with(".tmp") {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        let log = run_dir.join("core.log");
        Core {
            inner: Mutex::new(Inner {
                phase: Phase::Off,
                since: 0,
                error: String::new(),
                procs: Vec::new(),
                gen: 0,
                clash: (0, String::new()),
                names: Value::Null,
                mode: String::new(),
                proxy_set: false,
            }),
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
            run_dir,
            log,
            on_change,
            test: Mutex::new(Vec::new()),
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.inner.lock().unwrap().phase, Phase::On | Phase::Connecting)
    }

    pub fn status(&self) -> Value {
        let i = self.inner.lock().unwrap();
        json!({
            "state": i.phase.as_str(),
            "since": i.since,
            "error": i.error,
            "rx": self.rx.load(Ordering::Relaxed),
            "tx": self.tx.load(Ordering::Relaxed),
            "clashPort": if i.phase == Phase::On { i.clash.0 } else { 0 },
            "clashSecret": if i.phase == Phase::On { i.clash.1.clone() } else { String::new() },
            "names": i.names,
            "mode": i.mode,
        })
    }

    fn notify(&self) {
        (self.on_change)(self.is_active());
    }

    fn fail(&self, gen: u64, msg: String) {
        let procs = {
            let mut i = self.inner.lock().unwrap();
            if i.gen != gen {
                return;
            }
            i.gen += 1;
            i.phase = Phase::Error;
            i.error = msg;
            std::mem::take(&mut i.procs)
        };
        for p in procs {
            p.stop();
        }
        self.clear_proxy();
        self.notify();
    }

    fn clear_proxy(&self) {
        let mut i = self.inner.lock().unwrap();
        if i.proxy_set {
            i.proxy_set = false;
            crate::sys::clear_system_proxy();
        }
    }

    /// Подключиться. Блокирует до готовности ядра или ошибки.
    pub fn start(self: &Arc<Self>, req: Request) -> Result<(), String> {
        self.stop();
        let gen = {
            let mut i = self.inner.lock().unwrap();
            i.gen += 1;
            i.phase = Phase::Connecting;
            i.error.clear();
            i.since = 0;
            i.clash = (req.clash_port, req.clash_secret.clone());
            i.names = req.names.clone();
            i.mode = req.mode.clone();
            i.gen
        };
        self.rx.store(0, Ordering::Relaxed);
        self.tx.store(0, Ordering::Relaxed);
        self.notify();
        match self.launch(gen, &req) {
            Ok(()) => {
                let ok = {
                    let mut i = self.inner.lock().unwrap();
                    if i.gen == gen {
                        i.phase = Phase::On;
                        i.since = now_ms();
                        true
                    } else {
                        false
                    }
                };
                if !ok {
                    return Err("Подключение отменено".into());
                }
                self.notify();
                self.watch(gen);
                crate::net::traffic(gen, req.clash_port, req.clash_secret.clone(), Arc::clone(self));
                Ok(())
            }
            Err(e) => {
                let cancelled = self.inner.lock().unwrap().gen != gen;
                self.fail(gen, e.clone());
                if cancelled { Err("Подключение отменено".into()) } else { Err(e) }
            }
        }
    }

    fn launch(&self, gen: u64, req: &Request) -> Result<(), String> {
        let _ = fs::create_dir_all(&self.run_dir);
        if let Ok(meta) = fs::metadata(&self.log) {
            if meta.len() > 2 * 1024 * 1024 {
                let _ = fs::remove_file(&self.log);
            }
        }
        let mut lf = OpenOptions::new().create(true).append(true).open(&self.log).map_err(|e| e.to_string())?;
        let _ = writeln!(lf, "\n===== {} подключение, режим {} =====", now_ms() / 1000, req.mode);
        drop(lf);

        let sb_cfg = self.run_dir.join(format!("singbox-{gen}.json"));
        let x_cfg = self.run_dir.join(format!("xray-{gen}.json"));
        let cleanup = || {
            let _ = fs::remove_file(&sb_cfg);
            let _ = fs::remove_file(&x_cfg);
        };
        write_private(&sb_cfg, req.singbox.as_bytes()).map_err(|e| format!("Не удалось записать настройки: {e}"))?;

        let result = (|| -> Result<(), String> {
            // 1. Xray (если сервер требует его возможностей)
            if let Some(x) = &req.xray {
                write_private(&x_cfg, x.as_bytes()).map_err(|e| e.to_string())?;
                let exe = core_path("netline-xray");
                let args = vec!["run".into(), "-c".into(), x_cfg.to_string_lossy().into_owned()];
                let p = Proc::spawn("xray", &exe, &args, &self.log, &self.run_dir, Priv::None)?;
                self.add(gen, p)?;
                let ports = xray_ports(x);
                let t = Instant::now();
                while t.elapsed() < Duration::from_secs(8) {
                    if ports.iter().all(|&p| port_open(p)) {
                        break;
                    }
                    if !self.all_alive(gen) {
                        return Err(explain(&log_tail(&self.log, 30)));
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
            // 2. sing-box
            let exe = core_path("netline-singbox");
            let how = if req.mode == "tun" { tun_privilege(&exe) } else { Priv::None };
            #[cfg(target_os = "linux")]
            let exe = if how == Priv::Pkexec { rootable_copy(&exe, &self.run_dir) } else { exe };
            let args = vec![
                "run".into(),
                "-c".into(),
                sb_cfg.to_string_lossy().into_owned(),
                "-D".into(),
                self.run_dir.to_string_lossy().into_owned(),
            ];
            let p = Proc::spawn("sing-box", &exe, &args, &self.log, &self.run_dir, how)?;
            self.add(gen, p)?;
            // ждём, пока ядро начнёт отвечать (с окном пароля — дольше)
            let limit = if how == Priv::None { 30 } else { 180 };
            let t = Instant::now();
            loop {
                if self.inner.lock().unwrap().gen != gen {
                    return Err("Подключение отменено".into());
                }
                if port_open(req.clash_port) {
                    break;
                }
                if !self.all_alive(gen) {
                    let tail = log_tail(&self.log, 30);
                    if how == Priv::Osascript && (tail.contains("-128") || tail.to_lowercase().contains("cancel")) {
                        return Err("Подключение отменено: пароль администратора не введён".into());
                    }
                    if how == Priv::Pkexec && (tail.contains("126") || tail.contains("Not authorized") || tail.contains("dismissed")) {
                        return Err("Подключение отменено: пароль не введён".into());
                    }
                    return Err(explain(&tail));
                }
                if t.elapsed() > Duration::from_secs(limit) {
                    return Err("Ядро VPN не ответило вовремя".into());
                }
                thread::sleep(Duration::from_millis(150));
            }
            // 3. Windows: системный прокси ставим сами (sing-box снимает его только при мягкой остановке)
            if req.mode == "proxy" && cfg!(windows) {
                crate::sys::set_system_proxy(req.proxy_port)?;
                self.inner.lock().unwrap().proxy_set = true;
            }
            Ok(())
        })();
        // ядра прочитали настройки при запуске — файлы с ключами больше не нужны
        thread::sleep(Duration::from_millis(300));
        cleanup();
        result
    }

    fn add(&self, gen: u64, p: Proc) -> Result<(), String> {
        let mut i = self.inner.lock().unwrap();
        if i.gen != gen {
            drop(i);
            p.stop();
            return Err("Подключение отменено".into());
        }
        i.procs.push(p);
        Ok(())
    }

    fn all_alive(&self, gen: u64) -> bool {
        let mut i = self.inner.lock().unwrap();
        if i.gen != gen {
            return false;
        }
        i.procs.iter_mut().all(|p| p.alive())
    }

    /// Следить за ядрами: если одно упало — показать ошибку
    fn watch(self: &Arc<Self>, gen: u64) {
        let me = Arc::clone(self);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            let dead = {
                let mut i = me.inner.lock().unwrap();
                if i.gen != gen {
                    return;
                }
                i.procs.iter_mut().find_map(|p| if p.alive() { None } else { Some(p.name) })
            };
            if let Some(name) = dead {
                let tail = log_tail(&me.log, 30);
                let mut msg = explain(&tail);
                if msg == "Ядро VPN неожиданно завершилось" {
                    msg = format!("Ядро {name} неожиданно завершилось");
                }
                me.fail(gen, msg);
                return;
            }
        });
    }

    pub fn add_traffic(&self, gen: u64, up: u64, down: u64) -> bool {
        if self.inner.lock().unwrap().gen != gen {
            return false;
        }
        self.tx.fetch_add(up, Ordering::Relaxed);
        self.rx.fetch_add(down, Ordering::Relaxed);
        true
    }

    pub fn current(&self, gen: u64) -> bool {
        let i = self.inner.lock().unwrap();
        i.gen == gen && i.phase == Phase::On
    }

    /// Отключиться
    pub fn stop(&self) {
        let procs = {
            let mut i = self.inner.lock().unwrap();
            i.gen += 1;
            i.phase = Phase::Off;
            i.error.clear();
            i.since = 0;
            std::mem::take(&mut i.procs)
        };
        self.clear_proxy();
        for p in procs.into_iter().rev() {
            p.stop();
        }
        self.notify();
    }

    // ───────── проверка задержки: отдельный экземпляр без VPN ─────────

    pub fn test_start(&self, singbox: &str, xray: Option<&str>, clash_port: u16) -> Result<(), String> {
        self.test_stop();
        let dir = self.run_dir.join("test");
        let _ = fs::create_dir_all(&dir);
        let log = dir.join("test.log");
        let _ = fs::remove_file(&log);
        let sb_cfg = dir.join("singbox.json");
        let x_cfg = dir.join("xray.json");
        write_private(&sb_cfg, singbox.as_bytes()).map_err(|e| e.to_string())?;
        let mut procs = Vec::new();
        let res = (|| -> Result<(), String> {
            if let Some(x) = xray {
                write_private(&x_cfg, x.as_bytes()).map_err(|e| e.to_string())?;
                let args = vec!["run".into(), "-c".into(), x_cfg.to_string_lossy().into_owned()];
                procs.push(Proc::spawn("xray", &core_path("netline-xray"), &args, &log, &dir, Priv::None)?);
            }
            let args = vec![
                "run".into(),
                "-c".into(),
                sb_cfg.to_string_lossy().into_owned(),
                "-D".into(),
                dir.to_string_lossy().into_owned(),
            ];
            procs.push(Proc::spawn("sing-box", &core_path("netline-singbox"), &args, &log, &dir, Priv::None)?);
            let t = Instant::now();
            while !port_open(clash_port) {
                if procs.iter_mut().any(|p| !p.alive()) {
                    return Err(explain(&log_tail(&log, 20)));
                }
                if t.elapsed() > Duration::from_secs(20) {
                    return Err("Проверка не запустилась вовремя".into());
                }
                thread::sleep(Duration::from_millis(100));
            }
            Ok(())
        })();
        thread::sleep(Duration::from_millis(200));
        let _ = fs::remove_file(&sb_cfg);
        let _ = fs::remove_file(&x_cfg);
        if res.is_err() {
            for p in procs {
                p.stop();
            }
        } else {
            *self.test.lock().unwrap() = procs;
        }
        res
    }

    pub fn test_stop(&self) {
        let procs = std::mem::take(&mut *self.test.lock().unwrap());
        for p in procs {
            p.stop();
        }
    }

    pub fn shutdown(&self) {
        self.test_stop();
        self.stop();
    }
}
