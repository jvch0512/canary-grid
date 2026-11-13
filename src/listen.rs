//! A tiny HTTP listener. Any request whose path carries a valid token is a hit.
//! It never proxies, never reflects request content into responses, and bounds everything it reads.

use crate::json::{self, Value};
use crate::store::Store;
use crate::timefmt::now_rfc3339;
use crate::token;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_HEADER: usize = 16 * 1024;
const MAX_CONNS: usize = 64;
const PER_SOURCE_PER_MINUTE: u32 = 60;
const GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

#[derive(Clone)]
pub struct Config {
    pub trust_proxy: bool,
    pub quiet: bool,
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub fn parse_request(buf: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(buf).ok()?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    let mut it = first.split(' ');
    let (method, path, ver) = (it.next()?, it.next()?, it.next()?);
    if !ver.starts_with("HTTP/")
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !path.starts_with('/')
    {
        return None;
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':')?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    Some(Request {
        method: method.to_string(),
        path: path.to_string(),
        headers,
    })
}

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

/// Extracts a token from `/t/<TOKEN>/...`. Returns (token text, is it genuine).
pub fn token_in_path(key: &[u8], path: &str) -> Option<(String, bool)> {
    let rest = path.strip_prefix("/t/")?;
    let cand: String = rest.chars().take(token::TOKEN_LEN).collect();
    if cand.len() != token::TOKEN_LEN {
        return None;
    }
    let boundary_ok = rest[token::TOKEN_LEN..]
        .chars()
        .next()
        .is_none_or(|c| matches!(c, '/' | '?' | '#'));
    Some((cand.clone(), boundary_ok && token::verify(key, &cand)))
}

struct Limiter(Mutex<HashMap<IpAddr, (Instant, u32)>>);

impl Limiter {
    fn allow(&self, ip: IpAddr) -> bool {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let e = m.entry(ip).or_insert((Instant::now(), 0));
        if e.0.elapsed() > Duration::from_secs(60) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        e.1 <= PER_SOURCE_PER_MINUTE
    }
}

fn respond(s: &mut TcpStream, status: &str, ctype: &str, body: &[u8], head_only: bool) {
    let head = format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len());
    let _ = s.write_all(head.as_bytes());
    if !head_only {
        let _ = s.write_all(body);
    }
}

fn handle(mut s: TcpStream, store: &Store, cfg: &Config, lim: &Limiter, write_lock: &Mutex<()>) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let peer = match s.peer_addr() {
        Ok(p) => p.ip(),
        Err(_) => return,
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() > MAX_HEADER {
            respond(
                &mut s,
                "431 Request Header Fields Too Large",
                "text/plain",
                b"too large",
                false,
            );
            return;
        }
    }
    let Some(req) = parse_request(&buf) else {
        respond(
            &mut s,
            "400 Bad Request",
            "text/plain",
            b"bad request",
            false,
        );
        return;
    };
    let head_only = req.method == "HEAD";
    let path_only = req.path.split(['?', '#']).next().unwrap_or("");
    let Some((tok, genuine)) = token_in_path(&store.key, path_only) else {
        respond(
            &mut s,
            "404 Not Found",
            "text/plain",
            b"not found",
            head_only,
        );
        return;
    };
    if lim.allow(peer) {
        let rec = if genuine { store.lookup(&tok) } else { None };
        let mut src = peer.to_string();
        if cfg.trust_proxy {
            if let Some(x) = req.header("x-forwarded-for") {
                src = clip(x.split(',').next().unwrap_or(""), 64);
            }
        }
        let status = if !genuine {
            "forged"
        } else if rec.is_some() {
            "hit"
        } else {
            "hit-unregistered"
        };
        let hit = json::obj(vec![
            ("time", json::s(now_rfc3339())),
            ("status", json::s(status)),
            ("token", json::s(clip(&tok, 16))),
            (
                "kind",
                json::s(rec.as_ref().map_or("", |r| r.kind.as_str())),
            ),
            (
                "label",
                json::s(rec.as_ref().map_or("", |r| r.label.as_str())),
            ),
            ("source", json::s(src)),
            ("method", json::s(clip(&req.method, 16))),
            ("path", json::s(clip(&req.path, 200))),
            (
                "user_agent",
                json::s(clip(req.header("user-agent").unwrap_or(""), 200)),
            ),
            ("host", json::s(clip(req.header("host").unwrap_or(""), 100))),
        ]);
        let _g = write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = store.log_hit(&hit);
        if !cfg.quiet {
            let g = |k: &str| hit.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            println!(
                "ALERT {} {} token={} label={:?} from {} {} {}",
                g("time"),
                g("status"),
                g("token"),
                g("label"),
                g("source"),
                g("method"),
                g("path")
            );
        }
    }
    if path_only.ends_with(".gif") {
        respond(&mut s, "200 OK", "image/gif", GIF, head_only);
    } else {
        respond(
            &mut s,
            "200 OK",
            "application/json",
            b"{\"status\":\"ok\"}",
            head_only,
        );
    }
}

/// Accept loop. Stops when `stop` is set. Handles each connection on its own thread, bounded by MAX_CONNS.
pub fn serve(
    listener: TcpListener,
    store: Store,
    cfg: Config,
    stop: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    let lim = Arc::new(Limiter(Mutex::new(HashMap::new())));
    let write_lock = Arc::new(Mutex::new(()));
    let store = Arc::new(store);
    let cfg = Arc::new(cfg);
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((s, _)) => {
                let _ = s.set_nonblocking(false);
                if active.load(Ordering::Relaxed) >= MAX_CONNS {
                    continue; // shed load: drop the connection
                }
                active.fetch_add(1, Ordering::Relaxed);
                let (a, st, c, l, w) = (
                    active.clone(),
                    store.clone(),
                    cfg.clone(),
                    lim.clone(),
                    write_lock.clone(),
                );
                std::thread::spawn(move || {
                    handle(s, &st, &c, &l, &w);
                    a.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests() {
        let r =
            parse_request(b"GET /t/X/a.gif?x=1 HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8\r\n\r\n")
                .unwrap();
        assert_eq!(
            (r.method.as_str(), r.path.as_str()),
            ("GET", "/t/X/a.gif?x=1")
        );
        assert_eq!(r.header("user-agent"), Some("curl/8"));
    }

    #[test]
    fn rejects_malformed_requests() {
        for bad in [
            &b"GARBAGE\r\n\r\n"[..],
            b"get / HTTP/1.1\r\n\r\n",
            b"GET nopath HTTP/1.1\r\n\r\n",
            b"GET / FTP/1\r\n\r\n",
            b"GET / HTTP/1.1\r\nbadheader\r\n\r\n",
            &[0xff, 0xfe][..],
        ] {
            assert!(
                parse_request(bad).is_none(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn token_extraction_requires_a_clean_boundary() {
        let key = b"k";
        let t = token::mint_with(key, [1, 2, 3, 4, 5]);
        assert_eq!(
            token_in_path(key, &format!("/t/{t}/x")),
            Some((t.clone(), true))
        );
        assert_eq!(
            token_in_path(key, &format!("/t/{t}")),
            Some((t.clone(), true))
        );
        assert_eq!(
            token_in_path(key, &format!("/t/{t}X/x")).map(|x| x.1),
            Some(false)
        );
        assert_eq!(
            token_in_path(key, "/t/AAAAAAAAAAAAAAAA/x"),
            Some(("AAAAAAAAAAAAAAAA".to_string(), false))
        );
        assert_eq!(token_in_path(key, "/t/short"), None);
        assert_eq!(token_in_path(key, "/other"), None);
    }

    #[test]
    fn clip_removes_control_characters() {
        assert_eq!(clip("a\r\nb\x1b[31mc", 100), "ab[31mc");
        assert_eq!(clip("abcdef", 3), "abc");
    }
}
