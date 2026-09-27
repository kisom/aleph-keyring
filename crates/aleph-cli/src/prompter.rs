//! The terminal prompter (spec §6 "Prompter orchestration": the fallback
//! with no Wayland display, in the style of `systemd-ask-password`).
//!
//! The CLI keeps one end of a socketpair, hands the other to `alephd`
//! with the request, and answers the daemon's questions here. Secrets are
//! read from the terminal with echo off. With `ALEPH_NO_TTY=1` (scripts,
//! tests) each answer is one line of standard input instead.

use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::os::unix::net::UnixStream;

use aleph_prompt_proto::{FromPrompter, Method, Purpose, Secret, ToPrompter};

/// Where answers come from.
pub struct Terminal {
    /// Answers are lines of standard input (`ALEPH_NO_TTY=1`). The stdin
    /// lock is taken per line, never held: two `Terminal`s may coexist.
    scripted: bool,
}

impl Terminal {
    pub fn new() -> Self {
        let scripted = std::env::var_os("ALEPH_NO_TTY").is_some_and(|v| v == "1");
        Self { scripted }
    }

    pub fn line(&mut self, prompt: &str) -> std::io::Result<String> {
        eprint!("{prompt}");
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            // No more input: the caller cancels rather than answers.
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if self.scripted {
            eprintln!();
        }
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }

    fn secret(&mut self, prompt: &str) -> std::io::Result<Secret> {
        let secret = if self.scripted {
            self.line(prompt)?
        } else {
            rpassword::prompt_password(prompt)?
        };
        // Nothing typed (or Ctrl-D): no password or PIN is empty; cancel.
        if secret.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        Ok(Secret::new(secret))
    }

    fn yes(&mut self, question: &str, default: bool) -> std::io::Result<bool> {
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        let answer = self.line(&format!("{question} {hint} "))?;
        Ok(is_yes(&answer, default))
    }
}

/// A yes/no answer: empty takes `default`, anything but yes is no.
fn is_yes(answer: &str, default: bool) -> bool {
    match answer.trim() {
        "" => default,
        a => matches!(a, "y" | "Y" | "yes"),
    }
}

/// What the conversation ended with.
pub struct Outcome {
    pub ok: bool,
    pub message: Option<String>,
}

fn send(stream: &mut UnixStream, reply: &FromPrompter) -> std::io::Result<()> {
    // Zeroizing: a reply may carry a password, PIN, or recovery groups.
    let mut line =
        zeroize::Zeroizing::new(serde_json::to_vec(reply).map_err(std::io::Error::other)?);
    line.push(b'\n');
    stream.write_all(&line)
}

/// Answer the daemon on `stream` until it says `Done`.
pub fn converse(stream: UnixStream, term: &mut Terminal) -> std::io::Result<Outcome> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let interactive = !term.scripted && std::io::stdin().is_terminal();
    // Zeroizing: a message may carry the recovery key.
    let mut line = zeroize::Zeroizing::new(String::new());
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(std::io::Error::other("alephd closed the conversation"));
        }
        let msg: ToPrompter = serde_json::from_str(&line).map_err(std::io::Error::other)?;
        if let ToPrompter::Done { ok, message } = msg {
            return Ok(Outcome { ok, message });
        }
        let reply = match answer(msg, term, interactive) {
            Ok(reply) => reply,
            // No more input (end of file, Ctrl-D): cancel, never answer.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                Some(FromPrompter::Cancel {})
            }
            Err(e) => return Err(e),
        };
        if let Some(r) = reply {
            send(&mut writer, &r)?;
        }
    }
}

/// The reply (if any) to one message.
fn answer(
    msg: ToPrompter,
    term: &mut Terminal,
    interactive: bool,
) -> std::io::Result<Option<FromPrompter>> {
    Ok(match msg {
        ToPrompter::Begin {
            purpose, operation, ..
        } => {
            let why = match purpose {
                Purpose::Unlock => "",
                Purpose::Reauth => " (confirm it is you)",
                Purpose::Create => "",
                Purpose::Recover => " (with the recovery key)",
            };
            eprintln!("aleph: {operation}{why}");
            None
        }
        ToPrompter::Ask {
            methods,
            error,
            retry_after,
        } => {
            if let Some(e) = error {
                match retry_after {
                    Some(s) if !e.contains("retry in") => eprintln!("aleph: {e} (retry in {s} s)"),
                    _ => eprintln!("aleph: {e}"),
                }
            }
            let method = if methods.len() > 1 {
                let pick = term.line("Use your login [p]assword or a security [k]ey? ")?;
                if pick.trim().starts_with('k') {
                    Method::Fido2
                } else {
                    Method::Password
                }
            } else {
                methods.first().copied().unwrap_or(Method::Password)
            };
            Some(match method {
                Method::Password => FromPrompter::Password {
                    password: term.secret("Login password: ")?,
                },
                Method::Fido2 => FromPrompter::Fido2 {},
            })
        }
        ToPrompter::OldPassword { error } => {
            match error {
                Some(e) => eprintln!("aleph: {e}"),
                None => eprintln!(
                    "aleph: your login password was changed without aleph; enter the previous \
                     one to update the TPM keyslot (a wrong one costs a TPM attempt)"
                ),
            }
            Some(FromPrompter::Password {
                password: term.secret("Previous login password: ")?,
            })
        }
        ToPrompter::RecoveryKey { error } => {
            if let Some(e) = error {
                eprintln!("aleph: {e}");
            }
            Some(FromPrompter::RecoveryKey {
                key: term.secret("Recovery key (14 groups of 4): ")?,
            })
        }
        ToPrompter::Fido2Pin { key, error } => {
            if let Some(e) = error {
                eprintln!("aleph: {e}");
            }
            Some(FromPrompter::Pin {
                pin: term.secret(&format!("PIN for {key}: "))?,
            })
        }
        ToPrompter::InsertKey { key } => {
            // (The terminal cannot skip one key while waiting; Ctrl-C ends the
            // whole operation. The GUI prompter offers "skip".)
            eprintln!("aleph: insert {key} (Ctrl-C cancels the whole operation)");
            None
        }
        ToPrompter::Touch { key } => {
            eprintln!("aleph: touch {key}");
            None
        }
        ToPrompter::Confirm { text, default } => Some(FromPrompter::Confirm {
            yes: term.yes(&text, default)?,
        }),
        ToPrompter::ShowRecoveryKey { key, check, error } => {
            if let Some(e) = error {
                eprintln!("aleph: {e}");
            }
            eprintln!("\nYour recovery key. Write it down and keep it somewhere safe;");
            eprintln!("it is shown only this once, and it is the only way back in");
            eprintln!("if every other unlock method is lost:\n");
            eprintln!("    {}\n", key.expose());
            if interactive {
                let _ = term.line("Press Enter once you have written it down. ")?;
                // Clear the screen so the key does not linger in scrollback.
                eprint!("\x1b[2J\x1b[3J\x1b[H");
            }
            let a = term.line(&format!("Type group {} of your recovery key: ", check[0]))?;
            let b = term.line(&format!("Type group {} of your recovery key: ", check[1]))?;
            Some(FromPrompter::RecoveryCheck {
                groups: [Secret::new(a), Secret::new(b)],
            })
        }
        ToPrompter::Done { .. } => None,
    })
}

#[cfg(test)]
mod tests {
    use super::is_yes;

    #[test]
    fn enter_takes_the_default() {
        assert!(is_yes("", true));
        assert!(!is_yes("  ", false));
        assert!(is_yes("y", false));
        assert!(!is_yes("n", true));
        assert!(!is_yes("maybe", true));
    }
}
