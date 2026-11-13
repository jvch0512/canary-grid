//! State directory: the signing key, the registry of minted tokens and the hit log.

use crate::hash::{hex, unhex};
use crate::json::{self, Value};
use crate::token;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub token: String,
    pub kind: String,
    pub label: String,
    pub created: String,
    pub path: String,
}

#[derive(Clone)]
pub struct Store {
    pub dir: PathBuf,
    pub key: Vec<u8>,
}

impl std::fmt::Debug for Store {
    // the signing key must never end up in a log or a panic message
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Store {{ dir: {:?}, key: <redacted> }}", self.dir)
    }
}

impl Store {
    pub fn init(dir: &Path) -> Result<Store, String> {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let kp = dir.join("key");
        let key = token::random_bytes::<32>()?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&kp)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "{} already exists: refusing to overwrite the signing key",
                        kp.display()
                    )
                } else {
                    format!("{}: {e}", kp.display())
                }
            })?;
        f.write_all(hex(&key).as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(Store {
            dir: dir.to_path_buf(),
            key: key.to_vec(),
        })
    }

    pub fn open(dir: &Path) -> Result<Store, String> {
        let text = fs::read_to_string(dir.join("key")).map_err(|e| {
            format!(
                "{}: {e} (run `canary-grid init` first)",
                dir.join("key").display()
            )
        })?;
        let key = unhex(text.trim())
            .filter(|k| k.len() == 32)
            .ok_or("signing key is corrupt")?;
        Ok(Store {
            dir: dir.to_path_buf(),
            key,
        })
    }

    fn append(&self, file: &str, v: &Value) -> Result<(), String> {
        let line = json::pretty(v).replace("\n  ", "").replace('\n', "");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(file))
            .map_err(|e| e.to_string())?;
        f.write_all(format!("{line}\n").as_bytes())
            .map_err(|e| e.to_string())
    }

    pub fn register(&self, r: &Record) -> Result<(), String> {
        self.append(
            "tokens.jsonl",
            &json::obj(vec![
                ("token", json::s(&r.token)),
                ("kind", json::s(&r.kind)),
                ("label", json::s(&r.label)),
                ("created", json::s(&r.created)),
                ("path", json::s(&r.path)),
            ]),
        )
    }

    pub fn records(&self) -> Vec<Record> {
        read_lines(&self.dir.join("tokens.jsonl"))
            .iter()
            .filter_map(|v| {
                let g = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
                Some(Record {
                    token: g("token")?,
                    kind: g("kind")?,
                    label: g("label")?,
                    created: g("created")?,
                    path: g("path").unwrap_or_default(),
                })
            })
            .collect()
    }

    pub fn lookup(&self, token: &str) -> Option<Record> {
        self.records().into_iter().find(|r| r.token == token)
    }

    pub fn log_hit(&self, v: &Value) -> Result<(), String> {
        self.append("hits.jsonl", v)
    }

    pub fn hits(&self) -> Vec<Value> {
        read_lines(&self.dir.join("hits.jsonl"))
    }
}

fn read_lines(p: &Path) -> Vec<Value> {
    fs::read_to_string(p)
        .map(|t| t.lines().filter_map(|l| json::parse(l).ok()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cg-{n}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn init_open_and_refuse_overwrite() {
        let d = tmp("init");
        let s = Store::init(&d).unwrap();
        assert_eq!(Store::open(&d).unwrap().key, s.key);
        assert!(Store::init(&d).unwrap_err().contains("refusing"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(d.join("key")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn open_fails_without_init_or_with_bad_key() {
        let d = tmp("open");
        assert!(Store::open(&d).is_err());
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("key"), "nothex").unwrap();
        assert!(Store::open(&d).unwrap_err().contains("corrupt"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn registry_round_trip_with_awkward_labels() {
        let d = tmp("reg");
        let s = Store::init(&d).unwrap();
        let r = Record {
            token: "T".into(),
            kind: "aws".into(),
            label: "finance \"share\"\nline2".into(),
            created: "now".into(),
            path: "/x".into(),
        };
        s.register(&r).unwrap();
        assert_eq!(s.records(), vec![r.clone()]);
        assert_eq!(s.lookup("T"), Some(r));
        assert_eq!(s.lookup("U"), None);
        let _ = fs::remove_dir_all(&d);
    }
}
