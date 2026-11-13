use canary_grid::json::Value;
use canary_grid::store::{Record, Store};
use canary_grid::{listen, token};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cg-it-{n}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

struct Server {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start(store: Store) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let handle = std::thread::spawn(move || {
            listen::serve(
                l,
                store,
                listen::Config {
                    trust_proxy: false,
                    quiet: true,
                },
                s2,
            )
            .unwrap();
        });
        Server {
            addr,
            stop,
            handle: Some(handle),
        }
    }
    fn send(&self, raw: &[u8]) -> Vec<u8> {
        let mut s = TcpStream::connect(&self.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(raw).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }
    fn get(&self, path: &str, ua: &str) -> String {
        String::from_utf8_lossy(
            &self.send(
                format!("GET {path} HTTP/1.1\r\nHost: canary.test\r\nUser-Agent: {ua}\r\n\r\n")
                    .as_bytes(),
            ),
        )
        .into_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn setup(name: &str) -> (PathBuf, Store, String) {
    let d = tmp(name);
    let st = Store::init(&d).unwrap();
    let t = token::mint(&st.key).unwrap();
    st.register(&Record {
        token: t.clone(),
        kind: "html".into(),
        label: "finance/salaries".into(),
        created: "2026-11-13T00:00:00Z".into(),
        path: String::new(),
    })
    .unwrap();
    (d, st, t)
}

fn wait_hits(st: &Store, n: usize) -> Vec<Value> {
    for _ in 0..100 {
        let h = st.hits();
        if h.len() >= n {
            return h;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    st.hits()
}

#[test]
fn a_valid_token_is_logged_with_its_label_and_gets_a_gif() {
    let (d, st, t) = setup("valid");
    let srv = Server::start(st.clone());
    let resp = srv.get(&format!("/t/{t}/pixel.gif"), "Mozilla/5.0 test");
    assert!(
        resp.starts_with("HTTP/1.1 200 OK") && resp.contains("image/gif"),
        "{resp}"
    );
    let hits = wait_hits(&st, 1);
    assert_eq!(hits.len(), 1);
    let h = &hits[0];
    assert_eq!(h.get("status").and_then(Value::as_str), Some("hit"));
    assert_eq!(
        h.get("label").and_then(Value::as_str),
        Some("finance/salaries")
    );
    assert_eq!(h.get("kind").and_then(Value::as_str), Some("html"));
    assert_eq!(h.get("source").and_then(Value::as_str), Some("127.0.0.1"));
    assert_eq!(
        h.get("user_agent").and_then(Value::as_str),
        Some("Mozilla/5.0 test")
    );
    drop(srv);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn forged_tokens_are_flagged_and_unrelated_paths_are_ignored() {
    let (d, st, t) = setup("forged");
    let srv = Server::start(st.clone());
    assert!(srv
        .get("/t/AAAAAAAAAAAAAAAA/x", "ua")
        .starts_with("HTTP/1.1 200"));
    assert!(srv.get("/robots.txt", "ua").starts_with("HTTP/1.1 404"));
    assert!(srv.get("/", "ua").starts_with("HTTP/1.1 404"));
    srv.get(&format!("/t/{t}EXTRA/x"), "ua");
    let hits = wait_hits(&st, 2);
    let statuses: Vec<&str> = hits
        .iter()
        .filter_map(|h| h.get("status").and_then(Value::as_str))
        .collect();
    assert_eq!(
        statuses,
        vec!["forged", "forged"],
        "robots.txt and / must not be logged"
    );
    drop(srv);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_valid_but_unregistered_token_is_still_a_hit() {
    let (d, st, _) = setup("unreg");
    let other = token::mint(&st.key).unwrap(); // genuine signature, never registered
    let srv = Server::start(st.clone());
    srv.get(&format!("/t/{other}/x"), "ua");
    let hits = wait_hits(&st, 1);
    assert_eq!(
        hits[0].get("status").and_then(Value::as_str),
        Some("hit-unregistered")
    );
    drop(srv);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn hostile_input_cannot_break_the_log() {
    let (d, st, t) = setup("inject");
    let srv = Server::start(st.clone());
    srv.get(
        &format!("/t/{t}/x%0d%0aFAKE"),
        "evil\x1b[2J agent \"quoted\" \\ backslash",
    );
    srv.send(
        format!(
            "GET /t/{t}/y HTTP/1.1\r\nUser-Agent: {}\r\nHost: h\r\n\r\n",
            "A".repeat(5000)
        )
        .as_bytes(),
    );
    let hits = wait_hits(&st, 2);
    assert_eq!(hits.len(), 2);
    let raw = std::fs::read_to_string(d.join("hits.jsonl")).unwrap();
    assert_eq!(raw.lines().count(), 2, "one line per hit");
    for h in &hits {
        assert!(h.get("user_agent").and_then(Value::as_str).unwrap().len() <= 200);
        assert!(!h
            .get("user_agent")
            .and_then(Value::as_str)
            .unwrap()
            .contains('\x1b'));
    }
    drop(srv);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn protocol_errors_get_proper_statuses() {
    let (d, st, _) = setup("proto");
    let srv = Server::start(st);
    assert!(String::from_utf8_lossy(&srv.send(b"NOT HTTP\r\n\r\n")).starts_with("HTTP/1.1 400"));
    let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(40_000));
    assert!(String::from_utf8_lossy(&srv.send(big.as_bytes())).starts_with("HTTP/1.1 431"));
    drop(srv);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn head_requests_get_no_body() {
    let (d, st, t) = setup("head");
    let srv = Server::start(st);
    let r = String::from_utf8_lossy(
        &srv.send(format!("HEAD /t/{t}/a HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes()),
    )
    .into_owned();
    assert!(
        r.starts_with("HTTP/1.1 200") && r.ends_with("\r\n\r\n"),
        "{r:?}"
    );
    drop(srv);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_flood_from_one_source_is_rate_limited() {
    let (d, st, t) = setup("flood");
    let srv = Server::start(st.clone());
    for _ in 0..80 {
        srv.get(&format!("/t/{t}/x"), "ua");
    }
    std::thread::sleep(Duration::from_millis(300));
    let n = st.hits().len();
    assert!((55..=60).contains(&n), "logged {n}");
    drop(srv);
    let _ = std::fs::remove_dir_all(&d);
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_canary-grid"))
}

#[test]
fn cli_mint_list_scan_workflow() {
    let d = tmp("cli");
    let ds = d.to_str().unwrap();
    assert_eq!(bin().args(["init", ds]).status().unwrap().code(), Some(0));
    assert_eq!(
        bin().args(["init", ds]).status().unwrap().code(),
        Some(2),
        "must not overwrite the key"
    );
    let out = d.join("credentials");
    assert_eq!(
        bin()
            .args([
                "mint",
                ds,
                "--kind",
                "aws",
                "--label",
                "ci-runner home",
                "--out",
                out.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .code(),
        Some(0)
    );
    let body = std::fs::read_to_string(&out).unwrap();
    let key_id = body
        .lines()
        .find(|l| l.starts_with("aws_access_key_id"))
        .unwrap()
        .split(" = ")
        .nth(1)
        .unwrap()
        .to_string();
    assert!(key_id.starts_with("AKIA") && key_id.len() == 20);

    let listed = bin().args(["list", ds]).output().unwrap();
    assert!(String::from_utf8_lossy(&listed.stdout).contains("ci-runner home"));

    let trail = d.join("trail.json");
    std::fs::write(
        &trail,
        format!(
            "{{\"userIdentity\":{{\"accessKeyId\":\"{key_id}\"}},\"eventName\":\"ListBuckets\"}}\n"
        ),
    )
    .unwrap();
    let hit = bin()
        .args(["scan", ds, trail.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(hit.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&hit.stdout).contains("ci-runner home"));

    let clean = d.join("clean.log");
    std::fs::write(&clean, "AKIAIOSFODNN7EXAMPLE normal line\n").unwrap();
    assert_eq!(
        bin()
            .args(["scan", ds, clean.to_str().unwrap()])
            .status()
            .unwrap()
            .code(),
        Some(0)
    );

    assert_eq!(
        bin()
            .args(["mint", ds, "--kind", "pdf", "--label", "x"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
    assert_eq!(
        bin()
            .args(["mint", ds, "--kind", "aws"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
    assert_eq!(
        bin()
            .args(["list", "/nonexistent-state"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
    let _ = std::fs::remove_dir_all(&d);
}
