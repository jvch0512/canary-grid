//! Search files for tokens we minted. Use it on CloudTrail exports, proxy and web logs, shell history,
//! or a checked-out repository: a decoy key that shows up there has been copied or used.

use crate::token;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub file: String,
    pub line: usize,
    pub token: String,
    pub context: String,
}

const MAX_LINE: usize = 64 * 1024;

pub fn scan_file(key: &[u8], path: &Path) -> Result<Vec<Found>, String> {
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut rd = BufReader::new(f);
    let mut out = Vec::new();
    let mut buf = Vec::new();
    let mut n = 0;
    loop {
        buf.clear();
        let got = rd
            .by_ref()
            .take(MAX_LINE as u64)
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if got == 0 {
            break;
        }
        n += 1;
        let line = String::from_utf8_lossy(&buf);
        for (pos, t) in token::find_in_text(key, &line) {
            let start = pos.saturating_sub(30);
            let ctx: String = line
                .chars()
                .skip(start)
                .take(90)
                .filter(|c| !c.is_control())
                .collect();
            out.push(Found {
                file: path.display().to_string(),
                line: n,
                token: t.to_string(),
                context: ctx,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_tokens_across_lines_and_skips_noise() {
        let key = b"scan-key";
        let t = token::mint_with(key, [5, 4, 3, 2, 1]);
        let d = std::env::temp_dir().join(format!("cg-scan-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        let p = d.join("trail.json");
        let mut data = format!("{{\"eventName\":\"GetCallerIdentity\"}}\n{{\"userIdentity\":{{\"accessKeyId\":\"AKIA{t}\"}}}}\nnothing here\n").into_bytes();
        data.extend_from_slice(&[0xff, 0xfe]);
        data.extend_from_slice(format!(" binary AKIA{t}\n").as_bytes());
        fs::write(&p, data).unwrap();
        let f = scan_file(key, &p).unwrap();
        assert_eq!(f.iter().map(|x| x.line).collect::<Vec<_>>(), vec![2, 4]);
        assert!(f[0].context.contains("accessKeyId"));
        assert!(scan_file(key, &d.join("missing")).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
