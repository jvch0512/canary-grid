use canary_grid::json::Value;
use canary_grid::store::{Record, Store};
use canary_grid::{decoy, listen, scan, timefmt, token};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const USAGE: &str = "canary-grid 1.0.0: self-hosted honeytokens

USAGE:
  canary-grid init   <state-dir>
  canary-grid mint   <state-dir> --kind aws|env|kube|html|url --label <where it is planted> [--host host:port] [--out file]
  canary-grid list   <state-dir>
  canary-grid listen <state-dir> [--bind 127.0.0.1:8088] [--trust-proxy] [--quiet]
  canary-grid hits   <state-dir>
  canary-grid scan   <state-dir> <file>...      exit 1 if any token is found

Plant decoys only on systems you own or are authorised to defend.
";

fn die(m: &str) -> ExitCode {
    eprintln!("error: {m}");
    ExitCode::from(2)
}

fn flag(a: &[String], name: &str) -> Option<String> {
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1))
        .cloned()
}

fn main() -> ExitCode {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(cmd), Some(dir)) = (a.first(), a.get(1)) else {
        print!("{USAGE}");
        return ExitCode::from(u8::from(!a.is_empty()) * 2);
    };
    let dir = PathBuf::from(dir);
    let rest = &a[2..];
    match cmd.as_str() {
        "init" => match Store::init(&dir) {
            Ok(_) => {
                println!("initialised {}", dir.display());
                ExitCode::SUCCESS
            }
            Err(e) => die(&e),
        },
        "mint" => {
            let (Some(kind), Some(label)) = (flag(rest, "--kind"), flag(rest, "--label")) else {
                return die("mint needs --kind and --label");
            };
            let host = flag(rest, "--host").unwrap_or_else(|| "127.0.0.1:8088".into());
            let st = match Store::open(&dir) {
                Ok(s) => s,
                Err(e) => return die(&e),
            };
            let tok = match token::mint(&st.key) {
                Ok(t) => t,
                Err(e) => return die(&e),
            };
            let (name, body) = match decoy::render(&kind, &tok, &st.key, &host, &label) {
                Ok(x) => x,
                Err(e) => return die(&e),
            };
            let out = flag(rest, "--out");
            if let Some(p) = &out {
                if let Err(e) = std::fs::write(p, &body) {
                    return die(&format!("{p}: {e}"));
                }
            }
            let rec = Record {
                token: tok.clone(),
                kind,
                label,
                created: timefmt::now_rfc3339(),
                path: out.clone().unwrap_or_default(),
            };
            if let Err(e) = st.register(&rec) {
                return die(&e);
            }
            match out {
                Some(p) => println!("token {tok} written to {p} (suggested name: {name})"),
                None => print!("{body}"),
            }
            ExitCode::SUCCESS
        }
        "list" => match Store::open(&dir) {
            Ok(s) => {
                for r in s.records() {
                    println!("{}  {:<5} {}  {}", r.token, r.kind, r.created, r.label);
                }
                ExitCode::SUCCESS
            }
            Err(e) => die(&e),
        },
        "hits" => match Store::open(&dir) {
            Ok(s) => {
                for h in s.hits() {
                    let g = |k: &str| h.get(k).and_then(Value::as_str).unwrap_or("");
                    println!(
                        "{} {:<16} {} {:?} from {} {} {}",
                        g("time"),
                        g("status"),
                        g("token"),
                        g("label"),
                        g("source"),
                        g("method"),
                        g("path")
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => die(&e),
        },
        "listen" => {
            let st = match Store::open(&dir) {
                Ok(s) => s,
                Err(e) => return die(&e),
            };
            let bind = flag(rest, "--bind").unwrap_or_else(|| "127.0.0.1:8088".into());
            let l = match TcpListener::bind(&bind) {
                Ok(l) => l,
                Err(e) => return die(&format!("{bind}: {e}")),
            };
            eprintln!(
                "listening on {bind}, hits go to {}",
                dir.join("hits.jsonl").display()
            );
            let cfg = listen::Config {
                trust_proxy: rest.iter().any(|x| x == "--trust-proxy"),
                quiet: rest.iter().any(|x| x == "--quiet"),
            };
            match listen::serve(l, st, cfg, Arc::new(AtomicBool::new(false))) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => die(&e.to_string()),
            }
        }
        "scan" => {
            let st = match Store::open(&dir) {
                Ok(s) => s,
                Err(e) => return die(&e),
            };
            if rest.is_empty() {
                return die("scan needs at least one file");
            }
            let mut any = false;
            for f in rest {
                match scan::scan_file(&st.key, std::path::Path::new(f)) {
                    Ok(found) => {
                        for x in found {
                            any = true;
                            let label = st
                                .lookup(&x.token)
                                .map_or("(unregistered)".to_string(), |r| r.label);
                            println!(
                                "{}:{}: token {} [{}]\n    {}",
                                x.file,
                                x.line,
                                x.token,
                                label,
                                x.context.trim()
                            );
                        }
                    }
                    Err(e) => eprintln!("warning: {e}"),
                }
            }
            ExitCode::from(u8::from(any))
        }
        _ => {
            print!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
