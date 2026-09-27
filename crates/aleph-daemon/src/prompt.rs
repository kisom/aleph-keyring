//! The prompter protocol (spec §6 "Prompter orchestration").
//!
//! `alephd` talks to a prompter over one end of a socketpair, one JSON
//! object per line. The prompter is either `aleph-gui prompt`, spawned by
//! the daemon with the other end as `ALEPH_PROMPT_FD`, or the `aleph` CLI,
//! which passes its end to the daemon over D-Bus (the terminal fallback).
//! Secrets travel only over this socket, never in D-Bus message bodies.
//!
//! The messages are in `aleph-prompt-proto`; this module is the daemon's
//! side: the [`Channel`] it talks through and the [`Launcher`]s that start
//! prompters.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

pub use aleph_prompt_proto::*;

/// The daemon's end of a prompter conversation. Blocking; every read is
/// bounded by the prompt timeout.
pub struct Channel {
    stream: UnixStream,
    /// Received bytes not yet parsed (answers carry passwords and PINs).
    /// Allocated once at its full size and never grown, so no reallocation
    /// leaves plaintext behind; consumed bytes are wiped, and the rest on
    /// drop.
    buf: Zeroizing<Vec<u8>>,
    timeout: Duration,
}

impl Channel {
    pub fn new(stream: UnixStream, timeout: Duration) -> Result<Self> {
        // A prompter's fd may arrive non-blocking (async runtimes set the
        // flag, and it travels with the fd), which would turn every read
        // into an instant "timed out". Writes are bounded too: a prompter
        // that stops reading must not block the daemon.
        stream.set_nonblocking(false)?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(Self {
            stream,
            // A full line and its newline.
            buf: Zeroizing::new(Vec::with_capacity(MAX_LINE + 1)),
            timeout,
        })
    }

    pub fn from_fd(fd: OwnedFd, timeout: Duration) -> Result<Self> {
        Self::new(UnixStream::from(fd), timeout)
    }

    pub fn send(&mut self, msg: &ToPrompter) -> Result<()> {
        // Zeroizing: a message may carry the recovery key.
        let mut line =
            Zeroizing::new(serde_json::to_vec(msg).map_err(|e| Error::Prompt(e.to_string()))?);
        line.push(b'\n');
        (&self.stream)
            .write_all(&line)
            .map_err(|e| Error::Prompt(format!("prompter went away: {e}")))?;
        Ok(())
    }

    /// Send a message that needs a reply and wait for it (up to the
    /// timeout). `Cancel` becomes `Error::Cancelled`.
    pub fn ask(&mut self, msg: &ToPrompter) -> Result<FromPrompter> {
        debug_assert!(msg.needs_reply());
        self.send(msg)?;
        match self.recv(Some(self.timeout))? {
            Some(FromPrompter::Cancel {}) => Err(Error::Cancelled),
            Some(reply) => Ok(reply),
            None => Err(Error::Prompt("the prompt timed out".into())),
        }
    }

    /// True if the prompter has cancelled (checked without waiting), for
    /// use while polling for a key.
    pub fn cancelled(&mut self) -> Result<bool> {
        Ok(matches!(
            self.recv(Some(Duration::from_millis(1)))?,
            Some(FromPrompter::Cancel {})
        ))
    }

    /// End the conversation.
    pub fn done(&mut self, ok: bool, message: Option<String>) {
        let _ = self.send(&ToPrompter::Done { ok, message });
    }

    fn recv(&mut self, wait: Option<Duration>) -> Result<Option<FromPrompter>> {
        let deadline = wait.map(|w| Instant::now() + w);
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let parsed = serde_json::from_slice(&self.buf[..i]);
                self.consume(i + 1);
                // Never quote the message: the bad value may be a secret.
                return parsed.map(Some).map_err(|e| {
                    Error::Prompt(format!(
                        "bad prompter message ({:?} error at column {})",
                        e.classify(),
                        e.column()
                    ))
                });
            }
            if self.buf.len() > MAX_LINE {
                return Err(Error::Prompt("prompter message too long".into()));
            }
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if remaining.is_some_and(|r| r.is_zero()) {
                return Ok(None);
            }
            self.stream.set_read_timeout(remaining)?;
            let start = self.buf.len();
            // Within capacity: no reallocation.
            self.buf.resize(MAX_LINE + 1, 0);
            let read = (&self.stream).read(&mut self.buf[start..]);
            self.buf.truncate(start + *read.as_ref().unwrap_or(&0));
            match read {
                Ok(0) => return Err(Error::Prompt("the prompter closed".into())),
                Ok(_) => {}
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Ok(None);
                }
                Err(e) => return Err(Error::Prompt(e.to_string())),
            }
        }
    }

    /// Drop the first `n` bytes of `buf`, wiping every copy.
    fn consume(&mut self, n: usize) {
        let len = self.buf.len();
        self.buf.copy_within(n.., 0);
        self.buf[len - n..].zeroize();
        self.buf.truncate(len - n);
    }
}

/// Starts prompters.
pub trait Launcher: Send + Sync {
    fn launch(&self) -> Result<Channel>;
}

/// Runs `<program> prompt` with its end of a socketpair as
/// `ALEPH_PROMPT_FD` (via `std::process::Command`: fork and exec, with only
/// an `fcntl` between them, never a bare fork).
pub struct ProgramLauncher {
    /// Read at each launch, so `prompt.program` and `prompt.timeout`
    /// changes apply to the next prompt without a restart.
    pub config: std::sync::Arc<std::sync::Mutex<crate::config::Config>>,
}

impl Launcher for ProgramLauncher {
    fn launch(&self) -> Result<Channel> {
        if std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return Err(Error::NoPrompter);
        }
        // Both ends close-on-exec.
        let (ours, theirs) = UnixStream::pair()?;
        let fd = theirs.as_raw_fd();
        let (program, timeout) = {
            let c = self.config.lock().unwrap_or_else(|e| e.into_inner());
            (
                c.prompt.program.clone(),
                Duration::from_secs(c.prompt.timeout),
            )
        };
        let mut command = std::process::Command::new(&program);
        command.arg("prompt").env("ALEPH_PROMPT_FD", fd.to_string());
        // The child's end must survive the exec, but become inheritable
        // only in the child: cleared here in the daemon, a child another
        // thread spawns meanwhile (a second prompter, PAM's helper) would
        // inherit it too, and this prompter exiting would then never read
        // as the end of its conversation.
        // SAFETY: runs in the forked child just before exec; fcntl is
        // async-signal-safe and touches only the descriptor we pass.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn();
        drop(theirs);
        match child {
            Ok(child) => {
                // Reap it in the background; the conversation is on the socket.
                std::thread::spawn(move || {
                    let mut child = child;
                    let _ = child.wait();
                });
                Channel::new(ours, timeout)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Err(Error::NoPrompter),
            Err(e) => Err(Error::Prompt(format!("cannot start {program}: {e}"))),
        }
    }
}

/// A scripted prompter for tests: answers each message that needs a
/// reply with the next of `replies`, and records everything it was sent.
pub mod scripted {
    use super::*;
    use std::sync::{Arc, Mutex};

    pub struct Scripted {
        pub sent: Arc<Mutex<Vec<ToPrompter>>>,
        pub replies: Arc<Mutex<Vec<FromPrompter>>>,
    }

    impl Scripted {
        pub fn new(replies: Vec<FromPrompter>) -> Self {
            Self {
                sent: Arc::default(),
                replies: Arc::new(Mutex::new(replies)),
            }
        }

        pub fn sent(&self) -> Vec<ToPrompter> {
            self.sent.lock().unwrap().clone()
        }

        /// Replies not yet used.
        pub fn left(&self) -> usize {
            self.replies.lock().unwrap().len()
        }
    }

    impl Launcher for Scripted {
        fn launch(&self) -> Result<Channel> {
            let (ours, theirs) = UnixStream::pair()?;
            let (sent, replies) = (self.sent.clone(), self.replies.clone());
            std::thread::spawn(move || {
                let mut reader = BufReader::new(theirs.try_clone().unwrap());
                let mut writer = theirs;
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    let msg: ToPrompter = serde_json::from_str(&line).unwrap();
                    line.clear();
                    let (reply, done) = (msg.needs_reply(), matches!(msg, ToPrompter::Done { .. }));
                    sent.lock().unwrap().push(msg);
                    if reply {
                        let next = {
                            let mut r = replies.lock().unwrap();
                            if r.is_empty() {
                                FromPrompter::Cancel {}
                            } else {
                                r.remove(0)
                            }
                        };
                        let mut out = serde_json::to_vec(&next).unwrap();
                        out.push(b'\n');
                        if writer.write_all(&out).is_err() {
                            break;
                        }
                    }
                    if done {
                        break;
                    }
                }
            });
            Channel::new(ours, Duration::from_secs(10))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prompter built on an async runtime passes a non-blocking fd (the
    /// flag travels with SCM_RIGHTS): the channel must still wait for its
    /// answers, not read "no data yet" as a timeout.
    #[test]
    fn a_non_blocking_prompter_fd_still_waits_for_the_answer() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let mut ch = Channel::new(ours, Duration::from_secs(5)).unwrap();
        let peer = std::thread::spawn(move || {
            let mut question = String::new();
            BufReader::new(theirs.try_clone().unwrap())
                .read_line(&mut question)
                .unwrap();
            std::thread::sleep(Duration::from_millis(100));
            theirs
                .write_all(b"{\"type\":\"confirm\",\"yes\":true}\n")
                .unwrap();
        });
        let reply = ch.ask(&ToPrompter::Confirm { text: "ok?".into() }).unwrap();
        assert_eq!(reply, FromPrompter::Confirm { yes: true });
        peer.join().unwrap();
    }

    /// Answers arriving together are read one at a time, in order.
    #[test]
    fn answers_arriving_together_are_read_in_order() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let mut ch = Channel::new(ours, Duration::from_secs(5)).unwrap();
        theirs
            .write_all(
                b"{\"type\":\"confirm\",\"yes\":true}\n{\"type\":\"confirm\",\"yes\":false}\n",
            )
            .unwrap();
        let q = ToPrompter::Confirm { text: "?".into() };
        assert_eq!(ch.ask(&q).unwrap(), FromPrompter::Confirm { yes: true });
        assert_eq!(ch.ask(&q).unwrap(), FromPrompter::Confirm { yes: false });
    }

    #[test]
    fn an_over_long_answer_is_refused() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let mut ch = Channel::new(ours, Duration::from_secs(5)).unwrap();
        let writer = std::thread::spawn(move || {
            let _ = theirs.write_all(&vec![b'x'; MAX_LINE + 10]);
            theirs
        });
        let err = ch
            .ask(&ToPrompter::Confirm { text: "?".into() })
            .unwrap_err()
            .to_string();
        assert!(err.contains("too long"), "{err}");
        drop(writer.join());
    }

    /// A malformed answer is refused without quoting it: the error is
    /// logged, and the bad value may be a PIN sent with the wrong type.
    #[test]
    fn a_malformed_answer_is_not_quoted_in_the_error() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let mut ch = Channel::new(ours, Duration::from_secs(5)).unwrap();
        theirs
            .write_all(b"{\"type\":\"pin\",\"pin\":918273}\n")
            .unwrap();
        let err = ch
            .ask(&ToPrompter::Fido2Pin {
                key: "k".into(),
                error: None,
            })
            .unwrap_err()
            .to_string();
        assert!(!err.contains("918273"), "{err}");
        assert!(err.contains("bad prompter message"), "{err}");
    }

    /// A prompter that stops reading cannot block the daemon forever (it
    /// holds the conversation lock while it writes).
    #[test]
    fn a_prompter_that_stops_reading_times_out_writes() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let mut ch = Channel::new(ours, Duration::from_millis(200)).unwrap();
        let text = "x".repeat(8 * 1024);
        let started = Instant::now();
        // Fill the socket buffer; a write then fails instead of blocking.
        while ch.send(&ToPrompter::Confirm { text: text.clone() }).is_ok() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "never timed out"
            );
        }
    }

    #[test]
    fn a_scripted_prompter_answers_in_order() {
        let s = scripted::Scripted::new(vec![FromPrompter::Fido2 {}]);
        let mut ch = s.launch().unwrap();
        let reply = ch
            .ask(&ToPrompter::Ask {
                methods: vec![Method::Fido2],
                error: None,
                retry_after: None,
            })
            .unwrap();
        assert_eq!(reply, FromPrompter::Fido2 {});
        // Out of replies: the script cancels.
        assert!(matches!(
            ch.ask(&ToPrompter::Confirm { text: "ok?".into() }),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn a_silent_prompter_times_out_and_a_long_line_is_refused() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let mut ch = Channel::new(ours, Duration::from_millis(50)).unwrap();
        let t = Instant::now();
        assert!(matches!(
            ch.ask(&ToPrompter::Confirm { text: "?".into() }),
            Err(Error::Prompt(m)) if m.contains("timed out")
        ));
        assert!(t.elapsed() < Duration::from_secs(2));
        let mut theirs = theirs;
        theirs.write_all(&vec![b'x'; MAX_LINE + 10]).unwrap();
        theirs.write_all(b"\n").unwrap();
        assert!(matches!(
            ch.ask(&ToPrompter::Confirm { text: "?".into() }),
            Err(Error::Prompt(m)) if m.contains("too long")
        ));
    }
}
