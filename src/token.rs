//! Signed canary tokens. A token is 16 base32 characters: 5 random bytes and a 5 byte MAC over them,
//! so a token we minted can be recognised from the text alone, and a guessed one is rejected.

use crate::hash::{b32_decode, b32_encode, ct_eq, hmac_sha256};
use std::fs::File;
use std::io::Read;

pub const TOKEN_LEN: usize = 16;

pub fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(b)
}

fn mac(key: &[u8], rand: &[u8]) -> [u8; 5] {
    let mut m = b"cg1".to_vec();
    m.extend_from_slice(rand);
    let full = hmac_sha256(key, &m);
    [full[0], full[1], full[2], full[3], full[4]]
}

pub fn mint_with(key: &[u8], rand: [u8; 5]) -> String {
    let mut raw = rand.to_vec();
    raw.extend_from_slice(&mac(key, &rand));
    b32_encode(&raw)
}

pub fn mint(key: &[u8]) -> Result<String, String> {
    Ok(mint_with(key, random_bytes::<5>()?))
}

/// True when `t` is a token produced with this key.
pub fn verify(key: &[u8], t: &str) -> bool {
    if t.len() != TOKEN_LEN {
        return false;
    }
    match b32_decode(t) {
        Some(raw) if raw.len() == 10 => ct_eq(&raw[5..], &mac(key, &raw[..5])),
        _ => false,
    }
}

/// A fake 40 character secret derived from the token, so the same decoy always carries the same secret.
pub fn fake_secret(key: &[u8], t: &str) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let h = hmac_sha256(key, format!("secret|{t}").as_bytes());
    let mut out = String::new();
    for i in 0..40 {
        out.push(ALPHA[(h[i % 32].wrapping_add((i as u8).wrapping_mul(7)) & 63) as usize] as char);
    }
    out
}

/// Candidate tokens in free text: 16 base32 characters that stand alone or follow `AKIA` or `/t/`.
/// Each candidate is verified, so ordinary text does not produce hits.
pub fn find_in_text<'a>(key: &[u8], line: &'a str) -> Vec<(usize, &'a str)> {
    let b = line.as_bytes();
    let is32 = |c: u8| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c);
    let mut out = Vec::new();
    let mut i = 0;
    while i + TOKEN_LEN <= b.len() {
        if is32(b[i]) {
            let mut j = i;
            while j < b.len() && is32(b[j]) {
                j += 1;
            }
            // the run may be a whole token, or a token after the AKIA prefix inside a longer run
            let run = &line[i..j];
            if run.len() >= TOKEN_LEN {
                for start in 0..=(run.len() - TOKEN_LEN) {
                    let cand = &run[start..start + TOKEN_LEN];
                    let at_edge = start == 0 || start == run.len() - TOKEN_LEN;
                    if at_edge && verify(key, cand) {
                        out.push((i + start, &line[i + start..i + start + TOKEN_LEN]));
                        break;
                    }
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-key-0123456789";

    #[test]
    fn minted_tokens_verify() {
        let t = mint_with(KEY, [1, 2, 3, 4, 5]);
        assert_eq!(t.len(), 16);
        assert!(verify(KEY, &t));
        assert!(!verify(b"other key", &t));
    }

    #[test]
    fn tampering_and_guessing_fail() {
        let t = mint_with(KEY, [9, 9, 9, 9, 9]);
        let mut chars: Vec<char> = t.chars().collect();
        chars[3] = if chars[3] == 'A' { 'B' } else { 'A' };
        assert!(!verify(KEY, &chars.iter().collect::<String>()));
        assert!(!verify(KEY, "AAAAAAAAAAAAAAAA"));
        assert!(!verify(KEY, &t[..15]));
        assert!(!verify(KEY, &format!("{t}A")));
        assert!(!verify(KEY, "aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn random_mint_is_unique() {
        assert_ne!(mint(KEY).unwrap(), mint(KEY).unwrap());
    }

    #[test]
    fn secret_is_stable_and_shaped() {
        let t = mint_with(KEY, [1, 1, 1, 1, 1]);
        assert_eq!(fake_secret(KEY, &t), fake_secret(KEY, &t));
        assert_eq!(fake_secret(KEY, &t).len(), 40);
    }

    #[test]
    fn finds_tokens_in_text() {
        let t = mint_with(KEY, [7, 7, 7, 7, 7]);
        let line = format!("\"accessKeyId\": \"AKIA{t}\", url=http://h/t/{t}/x.gif");
        let hits = find_in_text(KEY, &line);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(hits.iter().all(|(_, h)| *h == t));
    }

    #[test]
    fn ordinary_text_has_no_hits() {
        for line in [
            "AKIAIOSFODNN7EXAMPLE",
            "THISISALONGUPPERCASEWORDWITHNODIGITS",
            "2222222222222222",
            "plain text here",
        ] {
            assert!(find_in_text(KEY, line).is_empty(), "{line}");
        }
    }
}
