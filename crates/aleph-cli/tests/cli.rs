//! The `aleph` binary against a daemon on a private bus. Prompts are
//! answered on standard input (`ALEPH_NO_TTY=1`).

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

use aleph_daemon::testing::*;

fn aleph(d: &Daemon, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aleph"));
    cmd.args(args)
        .env("DBUS_SESSION_BUS_ADDRESS", &d.bus.address)
        .env("ALEPH_NO_TTY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Run `aleph args` with `stdin`: `(success, stdout, stderr)`.
async fn run(d: &Daemon, args: &[&str], stdin: &str) -> (bool, String, String) {
    let mut cmd = aleph(d, args);
    let stdin = stdin.to_string();
    tokio::task::spawn_blocking(move || {
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    })
    .await
    .unwrap()
}

/// Read the child's stderr until it contains `needle`; return all of it.
fn read_until(child: &mut Child, seen: &mut String, needle: &str) {
    let err = child.stderr.as_mut().unwrap();
    let mut buf = [0u8; 256];
    while !seen.contains(needle) {
        let n = err.read(&mut buf).unwrap();
        assert!(n > 0, "stderr closed before {needle:?}; got: {seen}");
        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
}

/// `aleph setup`, answering the recovery-key check by reading the key it
/// shows, as a person would.
async fn setup(d: &Daemon) -> String {
    let mut cmd = aleph(d, &["setup"]);
    tokio::task::spawn_blocking(move || {
        let mut child = cmd.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "1\n{PW}").unwrap();
        let mut seen = String::new();
        read_until(&mut child, &mut seen, "Type group ");
        let key = seen
            .lines()
            .map(str::trim)
            .find(|l| l.matches('-').count() == 13)
            .expect("the recovery key was shown")
            .to_string();
        let groups: Vec<&str> = key.split('-').collect();
        for _ in 0..2 {
            let at = seen.rfind("Type group ").unwrap() + "Type group ".len();
            let n: usize = seen[at..]
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap();
            writeln!(stdin, "{}", groups[n - 1]).unwrap();
            let mark = seen.len();
            if seen[mark..].is_empty() {
                // Wait for the next prompt (or the end).
                let mut buf = [0u8; 256];
                let err = child.stderr.as_mut().unwrap();
                while !seen[mark..].contains("Type group ") && !seen[mark..].contains("ready") {
                    let n = err.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            }
        }
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        seen.push_str(&String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "setup failed: {seen}");
        seen
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_creates_the_keyring_and_status_shows_it() {
    let d = daemon(false, vec![]).await;
    let (_, out, _) = run(&d, &["status"], "").await;
    assert!(out.contains("keyring: none"), "{out}");
    let log = setup(&d).await;
    assert!(log.contains("The keyring is ready."), "{log}");
    assert!(
        log.contains("not available yet"),
        "setup should say what is missing: {log}"
    );
    let (ok, out, _) = run(&d, &["status", "--json"], "").await;
    assert!(ok);
    let s: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (s["vault"].clone(), s["locked"].clone()),
        (true.into(), false.into())
    );
    let kinds: Vec<&str> = s["keyslots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["recovery", "tpm"]);
    // A second setup changes nothing.
    let (ok, _, err) = run(&d, &["setup"], "").await;
    assert!(ok && err.contains("already exists"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn store_get_search_and_delete() {
    let d = daemon(true, vec![]).await;
    let (ok, _, err) = run(
        &d,
        &["store", "--label", "Mail", "service=mail", "user=alice"],
        "s3cret\n",
    )
    .await;
    assert!(ok, "{err}");
    let (ok, out, _) = run(&d, &["get", "service=mail"], "").await;
    assert!(ok);
    assert_eq!(out, "s3cret");
    let (ok, out, _) = run(&d, &["search", "user=alice"], "").await;
    assert!(ok);
    assert!(
        out.contains("Mail") && out.contains("service = mail"),
        "{out}"
    );
    let (ok, out, _) = run(&d, &["ls"], "").await;
    assert!(ok && out.contains("1 items"), "{out}");
    let (ok, _, _) = run(&d, &["delete", "service=mail"], "").await;
    assert!(ok);
    let (ok, out, _) = run(&d, &["get", "service=mail"], "").await;
    assert!(!ok && out.is_empty());
    // Refuses to delete everything, and bad pairs.
    let (ok, _, err) = run(&d, &["delete"], "").await;
    assert!(!ok && err.contains("refusing"), "{err}");
    let (ok, _, err) = run(&d, &["get", "service"], "").await;
    assert!(!ok && err.contains("attr=value"), "{err}");
}

/// A read while locked unlocks in the terminal first.
#[tokio::test(flavor = "multi_thread")]
async fn a_locked_get_unlocks_in_the_terminal() {
    let d = daemon(true, vec![]).await;
    run(&d, &["store", "--label", "X", "k=v"], "val").await;
    let (ok, _, _) = run(&d, &["lock"], "").await;
    assert!(ok);
    let (ok, out, _) = run(&d, &["status"], "").await;
    assert!(ok && out.contains("keyring: locked"), "{out}");
    let (ok, out, err) = run(&d, &["get", "k=v"], &format!("typo\n{PW}\n")).await;
    assert!(ok, "{err}");
    assert_eq!(out, "val");
    assert!(err.contains("wrong password"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn config_set_reauthenticates() {
    let d = daemon(true, vec![]).await;
    let (ok, _, err) = run(
        &d,
        &["config", "set", "lock.idle_timeout", "900"],
        &format!("{PW}\n"),
    )
    .await;
    assert!(ok, "{err}");
    assert!(err.contains("confirm it is you"), "{err}");
    let (ok, out, _) = run(&d, &["config", "get", "lock.idle_timeout"], "").await;
    assert!(ok);
    assert_eq!(out.trim(), "900");
    let (ok, _, err) = run(&d, &["config", "set", "lock.nope", "1"], "").await;
    assert!(!ok && err.contains("unknown key"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn keyslot_list_and_retry_by_prefix() {
    let d = daemon(true, vec![]).await;
    let (ok, out, _) = run(&d, &["keyslot", "list", "--json"], "").await;
    assert!(ok);
    let slots: serde_json::Value = serde_json::from_str(&out).unwrap();
    let tpm = slots
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == "tpm")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (ok, _, err) = run(&d, &["keyslot", "retry", &tpm[..8]], "").await;
    assert!(ok, "{err}");
    let (ok, _, err) = run(&d, &["keyslot", "retry", "zzzz"], "").await;
    assert!(!ok && err.contains("no keyslot"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn completions_are_generated() {
    let d = daemon(false, vec![]).await;
    for shell in ["bash", "zsh", "fish"] {
        let (ok, out, _) = run(&d, &["completions", shell], "").await;
        assert!(ok && out.contains("aleph"), "{shell}");
    }
}

/// Review I2: with no more input, the terminal prompter cancels; it never
/// answers with empty passwords in a loop.
#[tokio::test(flavor = "multi_thread")]
async fn end_of_input_cancels_instead_of_looping() {
    let d = daemon(true, vec![]).await;
    run(&d, &["lock"], "").await;
    let t = std::time::Instant::now();
    let (ok, _, err) = run(&d, &["unlock"], "").await;
    assert!(!ok, "{err}");
    assert!(err.contains("cancelled"), "{err}");
    assert!(err.len() < 2000, "looped: {} bytes", err.len());
    assert!(t.elapsed() < std::time::Duration::from_secs(10));
    // The daemon is free for the next request.
    let (ok, _, err) = run(&d, &["unlock"], &format!("{PW}\n")).await;
    assert!(ok, "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_needs_attributes() {
    let d = daemon(true, vec![]).await;
    run(&d, &["store", "--label", "X", "k=v"], "val").await;
    let (ok, out, err) = run(&d, &["get"], "").await;
    assert!(
        !ok && out.is_empty() && err.contains("at least one"),
        "{err}"
    );
}
