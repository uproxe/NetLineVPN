//! Сеть: загрузка подписок и запросы к ядру (Clash API), счётчик трафика.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::vpn::Core;

const MAX_BODY: u64 = 32 * 1024 * 1024;

/// GET-запрос. Возвращает { status, headers, body } и для ответов с ошибкой (4xx/5xx).
pub fn fetch(url: &str, headers: &Map<String, Value>, timeout_ms: u64) -> Result<Value, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Поддерживаются только адреса http и https".into());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(timeout_ms.clamp(1000, 120_000)))
        .redirects(8)
        .build();
    let mut req = agent.get(url);
    for (k, v) in headers {
        if let Some(v) = v.as_str() {
            req = req.set(k, v);
        }
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(ureq::Error::Transport(t)) => {
            let msg = t.to_string();
            let low = msg.to_lowercase();
            if low.contains("timed out") || low.contains("timeout") {
                return Err("Сервер не ответил вовремя".into());
            }
            if low.contains("dns") || low.contains("resolve") || low.contains("lookup") {
                return Err("Не удалось найти сервер по адресу — проверьте ссылку и интернет".into());
            }
            if low.contains("certificate") || low.contains("tls") {
                return Err(format!("Ошибка защищённого соединения: {msg}"));
            }
            return Err(format!("Не удалось соединиться: {msg}"));
        }
    };
    let status = resp.status();
    let mut hs = Map::new();
    for name in resp.headers_names() {
        if let Some(v) = resp.header(&name) {
            hs.insert(name.to_lowercase(), Value::String(v.to_string()));
        }
    }
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_BODY)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Ответ прочитан не полностью: {e}"))?;
    Ok(json!({ "status": status, "headers": hs, "body": String::from_utf8_lossy(&buf) }))
}

/// Счётчик трафика: sing-box раз в секунду сообщает объём в /traffic
pub fn traffic(gen: u64, port: u16, secret: String, core: Arc<Core>) {
    thread::spawn(move || {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        while core.current(gen) {
            if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(4)));
                let req = format!(
                    "GET /traffic HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {secret}\r\nAccept: application/json\r\n\r\n"
                );
                if s.write_all(req.as_bytes()).is_ok() {
                    let rd = BufReader::new(s);
                    for line in rd.lines() {
                        let Ok(line) = line else { break };
                        let Some(pos) = line.find('{') else { continue };
                        if let Ok(v) = serde_json::from_str::<Value>(&line[pos..]) {
                            let up = v.get("up").and_then(|x| x.as_u64()).unwrap_or(0);
                            let down = v.get("down").and_then(|x| x.as_u64()).unwrap_or(0);
                            if !core.add_traffic(gen, up, down) {
                                return;
                            }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    });
}

// ───────── проверка подключения ─────────

/// GET через SOCKS5 с паролем (проверочный вход ядра). Возвращает (код ответа, текст)
fn socks_get(port: u16, user: &str, pass: &str, host: &str, hport: u16, path: &str) -> Result<(u16, String), String> {
    let e = |x: std::io::Error| x.to_string();
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(e)?;
    s.set_read_timeout(Some(Duration::from_secs(8))).map_err(e)?;
    s.set_write_timeout(Some(Duration::from_secs(5))).map_err(e)?;
    s.write_all(&[5, 1, 2]).map_err(e)?;
    let mut b = [0u8; 2];
    s.read_exact(&mut b).map_err(e)?;
    if b != [5, 2] {
        return Err("локальный вход ядра не принял вход по паролю".into());
    }
    let mut a = vec![1u8, user.len() as u8];
    a.extend_from_slice(user.as_bytes());
    a.push(pass.len() as u8);
    a.extend_from_slice(pass.as_bytes());
    s.write_all(&a).map_err(e)?;
    s.read_exact(&mut b).map_err(e)?;
    if b[1] != 0 {
        return Err("локальный вход ядра отклонил пароль".into());
    }
    let mut c = vec![5u8, 1, 0];
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            c.push(1);
            c.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            c.push(3);
            c.push(host.len() as u8);
            c.extend_from_slice(host.as_bytes());
        }
    }
    c.extend_from_slice(&hport.to_be_bytes());
    s.write_all(&c).map_err(e)?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).map_err(e)?;
    if h[1] != 0 {
        return Err(format!("сервер не открыл соединение (код SOCKS {})", h[1]));
    }
    let rest = match h[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).map_err(e)?;
            l[0] as usize
        }
        _ => 0,
    } + 2;
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).map_err(e)?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(e)?;
    let mut buf = Vec::new();
    let _ = (&mut s).take(256 * 1024).read_to_end(&mut buf);
    if buf.is_empty() {
        return Err(format!("{host}: нет ответа через сервер"));
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let code = text.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|x| x.1.to_string()).unwrap_or_default();
    Ok((code, body))
}

/// Проверка, что через сервер работает интернет. Возвращает (внешний IP, код страны) —
/// они могут быть пустыми, если сервис определения адреса недоступен, но связь есть.
pub fn check(port: u16, user: &str, pass: &str) -> Result<(String, String), String> {
    let mut errors = Vec::new();
    // 1. Cloudflare: ip=… и loc=…
    match socks_get(port, user, pass, "1.1.1.1", 80, "/cdn-cgi/trace") {
        Ok((200, body)) => {
            let get = |k: &str| body.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").trim().to_string();
            let ip = get("ip=");
            let mut cc = get("loc=");
            if cc == "XX" || cc == "T1" {
                cc.clear();
            }
            if !ip.is_empty() {
                return Ok((ip, cc));
            }
            errors.push("1.1.1.1: неожиданный ответ".to_string());
        }
        Ok((code, _)) => errors.push(format!("1.1.1.1: ответ {code}")),
        Err(x) => errors.push(x),
    }
    // 2. ip-api.com: success / код страны / IP
    match socks_get(port, user, pass, "ip-api.com", 80, "/line/?fields=status,countryCode,query") {
        Ok((200, body)) => {
            let l: Vec<&str> = body.lines().map(|x| x.trim()).filter(|x| !x.is_empty()).collect();
            if l.first() == Some(&"success") && l.len() >= 3 {
                return Ok((l[2].to_string(), l[1].to_string()));
            }
            return Ok((String::new(), String::new()));
        }
        Ok((code, _)) if code > 0 => return Ok((String::new(), String::new())),
        Ok(_) => errors.push("ip-api.com: пустой ответ".into()),
        Err(x) => errors.push(x),
    }
    // 3. просто связь
    match socks_get(port, user, pass, "cp.cloudflare.com", 80, "/generate_204") {
        Ok((code, _)) if code > 0 => Ok((String::new(), String::new())),
        Ok(_) => Err(errors.join("; ")),
        Err(x) => {
            errors.push(x);
            Err(errors.join("; "))
        }
    }
}
