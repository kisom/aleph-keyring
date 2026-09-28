//! The prompter's end of the socketpair alephd spawned it with
//! (`ALEPH_PROMPT_FD`): one JSON message per line each way.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender, channel};

use aleph_prompt_proto::{FromPrompter, MAX_LINE, ToPrompter};
use zeroize::{Zeroize, Zeroizing};

/// What the reader thread passes on.
#[derive(Debug)]
pub enum Event {
    Message(ToPrompter),
    /// alephd closed its end (the conversation is over, or it exited).
    Closed,
    /// Unreadable input; the conversation cannot go on.
    Broken(String),
}

/// Take the socket named by `ALEPH_PROMPT_FD` (removing the variable, so
/// nothing this process starts learns of it). Refuses anything but a
/// socket above standard error, and marks it close-on-exec.
pub fn take_from_env() -> Result<UnixStream, String> {
    let value = std::env::var("ALEPH_PROMPT_FD")
        .map_err(|_| "ALEPH_PROMPT_FD is not set: alephd starts the prompter".to_string())?;
    // SAFETY: single-threaded at this point (called first thing in main).
    unsafe { std::env::remove_var("ALEPH_PROMPT_FD") };
    let fd: RawFd = value
        .trim()
        .parse()
        .map_err(|_| format!("ALEPH_PROMPT_FD is not a descriptor: {value:?}"))?;
    if fd <= 2 {
        return Err(format!("ALEPH_PROMPT_FD {fd} is a standard stream"));
    }
    // SAFETY: fstat and fcntl only inspect and flag the descriptor; a
    // closed or foreign number fails the checks and is never adopted.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return Err(format!("ALEPH_PROMPT_FD {fd} is not open"));
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err(format!("ALEPH_PROMPT_FD {fd} is not a socket"));
        }
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(format!("ALEPH_PROMPT_FD {fd}: cannot set close-on-exec"));
        }
        Ok(UnixStream::from(OwnedFd::from_raw_fd(fd)))
    }
}

/// Read alephd's messages on a thread, passing each on and calling `wake`
/// (the window repaints) after every event.
pub fn spawn_reader(
    stream: UnixStream,
    wake: impl Fn() + Send + 'static,
) -> std::io::Result<Receiver<Event>> {
    let (tx, rx) = channel();
    stream.set_nonblocking(false)?;
    std::thread::Builder::new()
        .name("alephd-link".into())
        .spawn(move || read_loop(stream, &tx, &wake))?;
    Ok(rx)
}

fn read_loop(mut stream: UnixStream, tx: &Sender<Event>, wake: &dyn Fn()) {
    // Allocated once at its full size, never grown; consumed bytes are
    // wiped (a message may carry a new recovery key).
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_LINE + 1));
    loop {
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let parsed: Result<ToPrompter, _> = serde_json::from_slice(&buf[..i]);
            let len = buf.len();
            buf.copy_within(i + 1.., 0);
            buf[len - i - 1..].zeroize();
            buf.truncate(len - i - 1);
            let event = match parsed {
                Ok(msg) => Event::Message(msg),
                // Never quote it: it may hold a secret.
                Err(e) => Event::Broken(format!("bad message from alephd ({:?})", e.classify())),
            };
            let broken = matches!(event, Event::Broken(_));
            if tx.send(event).is_err() {
                return;
            }
            wake();
            if broken {
                return;
            }
            continue;
        }
        if buf.len() > MAX_LINE {
            let _ = tx.send(Event::Broken("message from alephd too long".into()));
            wake();
            return;
        }
        let start = buf.len();
        buf.resize(MAX_LINE + 1, 0);
        let read = stream.read(&mut buf[start..]);
        buf.truncate(start + *read.as_ref().unwrap_or(&0));
        match read {
            Ok(0) => {
                let _ = tx.send(Event::Closed);
                wake();
                return;
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                let _ = tx.send(Event::Closed);
                wake();
                return;
            }
        }
    }
}

/// Send one answer.
pub fn send(mut stream: &UnixStream, reply: &FromPrompter) -> std::io::Result<()> {
    // Zeroizing: answers carry passwords, PINs, and recovery groups.
    let mut line = Zeroizing::new(serde_json::to_vec(reply).map_err(std::io::Error::other)?);
    line.push(b'\n');
    stream.write_all(&line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_prompt_proto::Secret;
    use std::io::{BufRead, BufReader};
    use std::time::Duration;

    #[test]
    fn messages_arrive_in_order_then_closed() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let rx = spawn_reader(ours, || {}).unwrap();
        theirs
            .write_all(
                b"{\"type\":\"touch\",\"key\":\"a\"}\n{\"type\":\"done\",\"ok\":true,\"message\":null}\n",
            )
            .unwrap();
        drop(theirs);
        let t = Duration::from_secs(5);
        assert!(matches!(
            rx.recv_timeout(t).unwrap(),
            Event::Message(ToPrompter::Touch { .. })
        ));
        assert!(matches!(
            rx.recv_timeout(t).unwrap(),
            Event::Message(ToPrompter::Done { ok: true, .. })
        ));
        assert!(matches!(rx.recv_timeout(t).unwrap(), Event::Closed));
    }

    /// A malformed message ends the link without quoting it (it may be a
    /// recovery key with a wrong field).
    #[test]
    fn a_malformed_message_is_not_quoted() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let rx = spawn_reader(ours, || {}).unwrap();
        theirs
            .write_all(b"{\"type\":\"show_recovery_key\",\"key\":\"SECRET-KEY\"}\n")
            .unwrap();
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Broken(m) => assert!(!m.contains("SECRET"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_over_long_message_breaks_the_link() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let rx = spawn_reader(ours, || {}).unwrap();
        let writer = std::thread::spawn(move || {
            let _ = theirs.write_all(&vec![b'x'; MAX_LINE + 10]);
            theirs
        });
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Broken(m) => assert!(m.contains("too long"), "{m}"),
            other => panic!("{other:?}"),
        }
        drop(writer.join());
    }

    #[test]
    fn an_answer_is_one_line() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        send(
            &ours,
            &FromPrompter::Pin {
                pin: Secret::new("1234"),
            },
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(theirs).read_line(&mut line).unwrap();
        assert_eq!(line, "{\"type\":\"pin\",\"pin\":\"1234\"}\n");
    }
}
