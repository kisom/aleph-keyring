//! Secrets are never logged (spec §6 "Logging"): no `tracing` call in the
//! daemon may pass a value whose name says it is a secret. Messages may
//! mention passwords; arguments may not carry them. (The redacted `Debug`
//! of every secret type is the second line of defence.)

use std::path::Path;

const MACROS: &[&str] = &["trace!(", "debug!(", "info!(", "warn!(", "error!("];
const FORBIDDEN: &[&str] = &["password", "pin", "secret", "kek", "key", "mk", "recovery"];

/// The source of every `tracing` macro call in `text`, string literals
/// blanked out.
fn calls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in MACROS {
        let mut rest = text;
        while let Some(i) = rest.find(m) {
            let body = &rest[i + m.len()..];
            let (mut depth, mut in_str, mut end) = (1, false, body.len());
            let mut chars = body.char_indices().peekable();
            let mut call = String::new();
            while let Some((j, c)) = chars.next() {
                match (in_str, c) {
                    (true, '\\') => {
                        chars.next();
                        continue;
                    }
                    (true, '"') => in_str = false,
                    (true, _) => continue,
                    (false, '"') => in_str = true,
                    (false, '(') => depth += 1,
                    (false, ')') => {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break;
                        }
                    }
                    _ => {}
                }
                if !in_str && c != '"' {
                    call.push(c);
                }
            }
            let _ = end;
            out.push(call);
            rest = &body[1..];
        }
    }
    out
}

fn identifiers(call: &str) -> impl Iterator<Item = String> + '_ {
    call.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_logging_call_passes_a_secret() {
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut offenders = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        for call in calls(&text) {
            for word in identifiers(&call) {
                if FORBIDDEN
                    .iter()
                    .any(|bad| word.split('_').any(|part| part == *bad))
                {
                    offenders.push(format!("{}: {word} in `{}`", f.display(), call.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "logging calls that may leak secrets:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_lint_catches_a_leak() {
    let bad = r#"tracing::info!(password = %pw, "unlocking");"#;
    let words: Vec<String> = calls(bad)
        .iter()
        .flat_map(|c| identifiers(c).collect::<Vec<_>>())
        .collect();
    assert!(words.contains(&"password".to_string()));
    let fine = r#"tracing::warn!(slot = %id, "rejected the login password");"#;
    let words: Vec<String> = calls(fine)
        .iter()
        .flat_map(|c| identifiers(c).collect::<Vec<_>>())
        .collect();
    assert!(!words.iter().any(|w| w == "password"), "{words:?}");
}
