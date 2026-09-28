//! Copying a secret (the manager spec): offered with the hint
//! clipboard-history tools honor (`x-kde-passwordManagerHint: secret`),
//! and cleared after 30 s if the clipboard still holds it. The clearing
//! runs on a timer thread of its own, not with the window's frames: a
//! window on a hidden workspace draws none.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroizing;

/// How long a copied secret stays on the clipboard.
pub const KEEP: Duration = Duration::from_secs(30);

/// The MIME type clipboard-history tools (cliphist, KDE's Klipper,
/// others) check, and the value that tells them to skip the copy.
pub const HINT_TYPE: &str = "x-kde-passwordManagerHint";
pub const HINT: &[u8] = b"secret";

/// The clipboard itself.
pub trait Backend: Send + 'static {
    /// Offer `secret` as text (with the hint).
    fn offer(&mut self, secret: Zeroizing<Vec<u8>>) -> Result<(), String>;
    /// Whether the clipboard still holds our offer.
    fn still_ours(&self) -> bool;
    fn clear(&mut self);
}

/// Copies with an expiry.
pub struct Clipboard<B: Backend> {
    backend: Arc<Mutex<B>>,
    /// Which copy is the latest (a timer clears only its own).
    copies: Arc<AtomicU64>,
    keep: Duration,
}

impl<B: Backend> Clipboard<B> {
    pub fn new(backend: B) -> Self {
        Self::with_keep(backend, KEEP)
    }

    /// With another expiry (the tests').
    pub fn with_keep(backend: B, keep: Duration) -> Self {
        Self {
            backend: Arc::new(Mutex::new(backend)),
            copies: Arc::default(),
            keep,
        }
    }

    /// Offer `secret`, and clear it after the expiry if it is still ours
    /// and nothing was copied through here since.
    pub fn copy(&self, secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
        // (Offered and numbered under the backend's lock, and checked under
        // it: an older timer can never clear this copy.)
        let this = {
            let mut b = self.backend.lock().unwrap_or_else(|e| e.into_inner());
            b.offer(secret)?;
            self.copies.fetch_add(1, Ordering::SeqCst) + 1
        };
        let (backend, copies, keep) = (self.backend.clone(), self.copies.clone(), self.keep);
        std::thread::Builder::new()
            .name("aleph-clipboard".into())
            .spawn(move || {
                std::thread::sleep(keep);
                let mut b = backend.lock().unwrap_or_else(|e| e.into_inner());
                if copies.load(Ordering::SeqCst) != this {
                    return;
                }
                if b.still_ours() {
                    b.clear();
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// The Wayland clipboard (the wlr data-control protocol, which Hyprland
/// has). The offer is served from a thread until another program takes
/// the clipboard or it is cleared (or the manager exits: the copy goes
/// with it); the served copy is the crate's, and is not zeroized (the
/// manager spec: not guaranteed).
#[derive(Default)]
pub struct Wayland {
    serving: Arc<std::sync::atomic::AtomicBool>,
}

impl Backend for Wayland {
    fn offer(&mut self, secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
        use wl_clipboard_rs::copy::{MimeSource, MimeType, Options, Source};
        let sources = vec![
            MimeSource {
                source: Source::Bytes(secret.to_vec().into_boxed_slice()),
                mime_type: MimeType::Text,
            },
            MimeSource {
                source: Source::Bytes(HINT.into()),
                mime_type: MimeType::Specific(HINT_TYPE.into()),
            },
        ];
        let mut options = Options::new();
        options.foreground(true);
        let prepared = options
            .prepare_copy_multi(sources)
            .map_err(|e| e.to_string())?;
        let serving = Arc::new(std::sync::atomic::AtomicBool::new(true));
        self.serving = serving.clone();
        std::thread::spawn(move || {
            // Returns once the offer is replaced or cleared.
            let _ = prepared.serve();
            serving.store(false, Ordering::SeqCst);
        });
        Ok(())
    }

    fn still_ours(&self) -> bool {
        self.serving.load(Ordering::SeqCst)
    }

    fn clear(&mut self) {
        use wl_clipboard_rs::copy::{ClipboardType, Seat, clear};
        let _ = clear(ClipboardType::Regular, Seat::All);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct State {
        held: Option<Vec<u8>>,
        replaced: bool,
        cleared: usize,
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<State>>);

    impl Backend for Fake {
        fn offer(&mut self, secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
            let mut s = self.0.lock().unwrap();
            s.held = Some(secret.to_vec());
            s.replaced = false;
            Ok(())
        }
        fn still_ours(&self) -> bool {
            let s = self.0.lock().unwrap();
            s.held.is_some() && !s.replaced
        }
        fn clear(&mut self) {
            let mut s = self.0.lock().unwrap();
            s.held = None;
            s.cleared += 1;
        }
    }

    const KEEP: Duration = Duration::from_millis(60);

    /// Cleared by its own timer: no frame, no call, needed.
    #[test]
    fn a_copy_is_cleared_after_its_time_without_the_window() {
        let fake = Fake::default();
        let c = Clipboard::with_keep(fake.clone(), KEEP);
        c.copy(Zeroizing::new(b"pw".to_vec())).unwrap();
        assert!(fake.0.lock().unwrap().held.is_some());
        std::thread::sleep(KEEP * 3);
        let s = fake.0.lock().unwrap();
        assert!(s.held.is_none());
        assert_eq!(s.cleared, 1);
    }

    /// Something another program copied since is not cleared.
    #[test]
    fn a_copy_replaced_since_is_left_alone() {
        let fake = Fake::default();
        let c = Clipboard::with_keep(fake.clone(), KEEP);
        c.copy(Zeroizing::new(b"pw".to_vec())).unwrap();
        fake.0.lock().unwrap().replaced = true;
        std::thread::sleep(KEEP * 3);
        assert_eq!(fake.0.lock().unwrap().cleared, 0);
    }

    /// A newer copy is not cleared by an older copy's timer.
    #[test]
    fn a_newer_copy_keeps_its_own_time() {
        let fake = Fake::default();
        let c = Clipboard::with_keep(fake.clone(), KEEP);
        c.copy(Zeroizing::new(b"one".to_vec())).unwrap();
        std::thread::sleep(KEEP / 2);
        c.copy(Zeroizing::new(b"two".to_vec())).unwrap();
        std::thread::sleep(KEEP * 3 / 4);
        // (The first timer fired: the second copy stays.)
        assert_eq!(fake.0.lock().unwrap().held.as_deref(), Some(&b"two"[..]));
        std::thread::sleep(KEEP * 2);
        assert!(fake.0.lock().unwrap().held.is_none());
    }
}
