use regex::Regex;
use std::sync::LazyLock;

static SECRET_RES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Private key blocks (including a truncated block with no END line).
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)",
        // Key/value pairs with optional quotes around the key and the value.
        r#"(?i)(["']?(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|token|password|passwd|secret)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}]+)"#,
        r"(?i)(bearer\s+)[A-Za-z0-9\-_.=+/]{8,}",
        r"(?i)(basic\s+)[A-Za-z0-9\-_.=+/]{8,}",
        r"(?i)(token\s+)[A-Za-z0-9\-_.=+/]{8,}",
        r"(?i)(digest\s+)[A-Za-z0-9\-_.=+/]{8,}",
        // URL-embedded credentials: prefix in $1 and trailing @ in $2 survive "$1[REDACTED]$2".
        r"(?i)([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@?#]+:)[^/\s]+(@)",
        r"sk-ant-[A-Za-z0-9\-_]{20,}",
        r"sk-[A-Za-z0-9\-_]{20,}",
        r"gh[pousr]_[A-Za-z0-9_]{30,}",
        r"github_pat_[A-Za-z0-9_]{30,}",
        r"xox[A-Za-z]-[A-Za-z0-9-]{10,}",
        r"AIza[0-9A-Za-z\-_]{20,}",
        r"glpat-[A-Za-z0-9\-_]{20,}",
        r"npm_[A-Za-z0-9]{20,}",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AKIA[0-9A-Z]{16}",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("redaction regex"))
    .collect()
});

static CANDIDATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_\-]{32,}").expect("redaction candidate regex"));

fn entropy(s: &str) -> f64 {
    let mut counts = [0usize; 128];
    let mut total = 0usize;
    for b in s.bytes() {
        if b < 128 {
            counts[b as usize] += 1;
            total += 1;
        }
    }
    if total == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

/// Redact opaque tokens that have no recognizable prefix: high-entropy
/// base64-ish runs mixing case, digits, and symbols.
fn redact_high_entropy(text: &str) -> String {
    CANDIDATE_RE
        .replace_all(text, |caps: &regex::Captures| {
            let m = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
            let has_lower = m.bytes().any(|b| b.is_ascii_lowercase());
            let has_upper = m.bytes().any(|b| b.is_ascii_uppercase());
            let has_digit = m.bytes().any(|b| b.is_ascii_digit());
            let categories = [has_lower, has_upper, has_digit]
                .iter()
                .filter(|v| **v)
                .count();
            if categories >= 2 && entropy(m) >= 4.3 {
                "[REDACTED]".to_string()
            } else {
                m.to_string()
            }
        })
        .to_string()
}

pub fn redact(text: &str) -> String {
    let mut out = text.to_owned();
    for re in SECRET_RES.iter() {
        out = re.replace_all(&out, "$1[REDACTED]$2").to_string();
    }
    redact_high_entropy(&out)
}

fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("api_key")
        || k.contains("apikey")
        || k.contains("api-key")
        || k.contains("secret")
        || k.contains("token")
        || k.contains("password")
        || k.contains("passwd")
        || k.contains("private_key")
        || k.contains("privatekey")
        || k.contains("credential")
        || k.contains("authorization")
        || k.contains("auth")
        || k.contains("cookie")
        || k.contains("session")
}

pub fn redact_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(redact(s)),
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(redact_value).collect())
        }
        serde_json::Value::Object(o) => serde_json::Value::Object(
            o.iter()
                .map(|(k, v)| {
                    // `session`/`sessionID` keys hold session *records* in
                    // exports; only a scalar value can carry a credential.
                    let secret = if k.to_ascii_lowercase().contains("session") {
                        !matches!(
                            v,
                            serde_json::Value::Object(_) | serde_json::Value::Array(_)
                        )
                    } else {
                        is_secret_key(k)
                    };
                    if secret {
                        (k.clone(), serde_json::Value::String("[REDACTED]".into()))
                    } else {
                        (k.clone(), redact_value(v))
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secrets() {
        assert!(redact("Bearer abc.def-123").contains("[REDACTED]"));
        assert!(redact("api_key=supersecret").contains("[REDACTED]"));
        assert_eq!(redact("hello world"), "hello world");
    }

    #[test]
    fn redacts_a_full_private_key_block() {
        let pem = "\x2d----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdef\nabcdef==\n\x2d----END RSA PRIVATE KEY-----\n";
        let out = redact(pem);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("MIIEowIBAAKCAQEA"), "{out}");
        assert!(!out.contains("-----END RSA PRIVATE KEY-----"), "{out}");
    }

    #[test]
    fn redacts_quoted_values_and_prefixed_tokens() {
        assert!(!redact(r#"{"api_key": "abcd1234"}"#).contains("abcd1234"));
        assert!(!redact(r#"api-key: 'abcd1234'"#).contains("abcd1234"));
        for token in [
            "xoxb-1234567890-abcdefghij",
            "AIzaSyD1234567890abcdefghijklmnopqrstuv",
            "glpat-abcdefghij1234567890",
            "npm_abcdefghijklmnopqrstuvwxyz0123456789",
        ] {
            assert!(redact(token).contains("[REDACTED]"), "{token}");
        }
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(!redact(jwt).contains("dozjgNry"));
    }

    #[test]
    fn redacts_high_entropy_blobs_only() {
        let blob = "Qm9ndXMgdG9rZW4gMTIzNDU2Nzg5MGFiY2RlZmdoaWo";
        assert!(redact(blob).contains("[REDACTED]"));
        assert_eq!(
            redact("src/components/session_transcript_panel.rs"),
            "src/components/session_transcript_panel.rs"
        );
    }
}
