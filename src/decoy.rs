//! Decoy files. Each one carries the token in a place an attacker will use or a tool will open.

use crate::token::fake_secret;

pub const KINDS: [&str; 5] = ["aws", "env", "kube", "html", "url"];

pub fn url_for(host: &str, token: &str, slug: &str) -> String {
    format!("http://{host}/t/{token}/{slug}")
}

/// Returns (suggested file name, file content).
pub fn render(
    kind: &str,
    token: &str,
    key: &[u8],
    host: &str,
    label: &str,
) -> Result<(&'static str, String), String> {
    Ok(match kind {
        "aws" => (
            "credentials",
            format!("[default]\naws_access_key_id = AKIA{token}\naws_secret_access_key = {}\nregion = eu-west-1\n", fake_secret(key, token)),
        ),
        "env" => (
            ".env.production",
            format!(
                "NODE_ENV=production\nAWS_ACCESS_KEY_ID=AKIA{token}\nAWS_SECRET_ACCESS_KEY={}\nBACKUP_ENDPOINT={}\nADMIN_API_URL={}\n",
                fake_secret(key, token),
                url_for(host, token, "backup"),
                url_for(host, token, "admin")
            ),
        ),
        "kube" => (
            "kubeconfig-prod.yaml",
            format!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: prod\n  cluster:\n    server: {}\nusers:\n- name: ops-admin\n  user:\n    token: {}\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n    user: ops-admin\ncurrent-context: prod\n",
                url_for(host, token, "k8s"),
                fake_secret(key, token)
            ),
        ),
        "html" => (
            "salary-review-q4.html",
            format!(
                "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Salary review Q4</title></head>\n<body><h1>Salary review Q4</h1>\n<p>Confidential. Full spreadsheet: <a href=\"{}\">open</a></p>\n<img src=\"{}\" width=\"1\" height=\"1\" alt=\"\">\n</body></html>\n",
                url_for(host, token, "salaries.xlsx"),
                url_for(host, token, "pixel.gif"),
            ),
        ),
        "url" => ("url.txt", format!("{}\n", url_for(host, token, &slug(label)))),
        other => return Err(format!("unknown kind {other:?}; choose one of {}", KINDS.join(", "))),
    })
}

fn slug(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "link".into()
    } else {
        s.chars().take(40).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"k";

    #[test]
    fn aws_decoy_looks_like_a_credentials_file() {
        let (name, body) = render("aws", "ABCDEFGHIJKLMNOP", KEY, "h:1", "l").unwrap();
        assert_eq!(name, "credentials");
        assert!(body.contains("aws_access_key_id = AKIAABCDEFGHIJKLMNOP"));
        let secret = body
            .lines()
            .find(|l| l.starts_with("aws_secret_access_key"))
            .unwrap()
            .split(" = ")
            .nth(1)
            .unwrap();
        assert_eq!(secret.len(), 40);
    }

    #[test]
    fn every_kind_embeds_the_token() {
        for k in KINDS {
            let (_, body) = render(
                k,
                "ABCDEFGHIJKLMNOP",
                KEY,
                "canary.example:8088",
                "Finance share",
            )
            .unwrap();
            assert!(body.contains("ABCDEFGHIJKLMNOP"), "{k}");
        }
    }

    #[test]
    fn html_decoy_has_a_beacon_and_a_lure() {
        let (_, body) = render("html", "ABCDEFGHIJKLMNOP", KEY, "c:1", "x").unwrap();
        assert!(body.contains("/t/ABCDEFGHIJKLMNOP/pixel.gif") && body.contains("salaries.xlsx"));
    }

    #[test]
    fn unknown_kind_and_slug_rules() {
        assert!(render("pdf", "T", KEY, "h", "l").is_err());
        assert!(render("url", "T", KEY, "h", "../../etc/passwd")
            .unwrap()
            .1
            .contains("/t/T/etc-passwd"));
        assert!(render("url", "T", KEY, "h", "***")
            .unwrap()
            .1
            .contains("/t/T/link"));
    }
}
