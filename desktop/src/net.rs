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
