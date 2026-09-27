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

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub use aleph_prompt_proto::*;

/// The daemon's end of a prompter conversation. Blocking; every read is
/// bounded by the prompt timeout.
pub struct Channel {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
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
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
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
        self.writer
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
        let mut line = Zeroizing::new(Vec::new());
        loop {
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if remaining.is_some_and(|r| r.is_zero()) {
                return Ok(None);
            }
            self.reader.get_ref().set_read_timeout(remaining)?;
            let buf = match self.reader.fill_buf() {
                Ok([]) => return Err(Error::Prompt("the prompter closed".into())),
                Ok(buf) => buf,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Ok(None);
                }
                Err(e) => return Err(Error::Prompt(e.to_string())),
            };
            let (chunk, end) = match buf.iter().position(|&b| b == b'\n') {
                Some(i) => (&buf[..i], Some(i + 1)),
                None => (buf, None),
            };
            if line.len() + chunk.len() > MAX_LINE {
                return Err(Error::Prompt("prompter message too long".into()));
            }
            line.extend_from_slice(chunk);
            let used = end.unwrap_or(chunk.len());
            self.reader.consume(used);
            if end.is_some() {
                return serde_json::from_slice(&line)
                    .map(Some)
                    .map_err(|e| Error::Prompt(format!("bad prompter message: {e}")));
            }
        }
    }
}

/// Starts prompters.
pub trait Launcher: Send + Sync {
    fn launch(&self) -> Result<Channel>;
}

/// Runs `<program> prompt` with its end of a socketpair as
/// `ALEPH_PROMPT_FD` (spawned via `std::process::Command`, i.e.
/// posix_spawn/exec, never a bare fork).
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
        let (ours, theirs) = UnixStream::pair()?;
        // The child's end must survive exec; ours must not.
        let fd = theirs.as_raw_fd();
        // SAFETY: fcntl on a descriptor we own.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }
        let (program, timeout) = {
            let c = self.config.lock().unwrap_or_else(|e| e.into_inner());
            (
                c.prompt.program.clone(),
                Duration::from_secs(c.prompt.timeout),
            )
        };
        let child = std::process::Command::new(&program)
            .arg("prompt")
            .env("ALEPH_PROMPT_FD", fd.to_string())
            .spawn();
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
