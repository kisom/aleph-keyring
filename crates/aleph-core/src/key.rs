//! Key types. `KeyHandle` is the only holder of the vault master key and
//! is the seam for v2 privilege separation: callers ask it to wrap, seal,
//! open, and MAC, and never see the key bytes.

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use zeroize::Zeroize;

use crate::crypto::{self, KEY_LEN, MAC_LEN, NONCE_LEN};
use crate::error::{Error, Result};

/// A key-encryption key produced by an unlock method (TPM, FIDO2, Argon2).
pub struct Kek(SecretBox<[u8; KEY_LEN]>);

/// Build a 32-byte secret by filling its (heap, zeroize-on-drop) buffer in
/// place, so it never exists as a by-value array on the stack. The only
/// way secrets of this size are constructed.
pub(crate) fn try_init_secret(
    fill: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<()>,
) -> Result<SecretBox<[u8; KEY_LEN]>> {
    let mut secret = SecretBox::<[u8; KEY_LEN]>::init_with_mut(|_| ());
    fill(secret.expose_secret_mut())?;
    Ok(secret)
}

impl Kek {
    /// Build a KEK in place; see `try_init_secret`.
    pub fn try_init(fill: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<()>) -> Result<Self> {
        try_init_secret(fill).map(Self)
    }

    pub fn generate() -> Result<Self> {
        Self::try_init(|buf| crypto::fill_random(buf))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek([REDACTED])")
    }
}

/// The vault master key, wrapped by a KEK: what a keyslot stores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// One key in its own private, page-locked, never-dumped page.
///
/// A dedicated page per key matters because `mlock` does not nest: if two
/// keys shared a page, unlocking one on drop would unlock the other.
struct LockedPage {
    page: *mut u8,
    len: usize,
}

// SAFETY: the page is exclusively owned; it is only read through `&self`
// and written through `&mut self`, like a `Box<[u8; KEY_LEN]>`.
unsafe impl Send for LockedPage {}
unsafe impl Sync for LockedPage {}

impl LockedPage {
    fn new() -> Result<Self> {
        // SAFETY: sysconf has no preconditions.
        let len = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let len = usize::try_from(len)
            .ok()
            .filter(|&l| l >= KEY_LEN)
            .unwrap_or(4096);
        // SAFETY: anonymous private mapping; the result is checked below.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if page == libc::MAP_FAILED {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: `page` is a valid mapping of `len` bytes. All calls are
        // best effort: failure (e.g. RLIMIT_MEMLOCK exhausted) is not fatal.
        // mlock is not inherited across fork, so WIPEONFORK gives a forked
        // child zeroes rather than an unlocked copy of the key.
        unsafe {
            libc::mlock(page, len);
            libc::madvise(page, len, libc::MADV_DONTDUMP);
            libc::madvise(page, len, libc::MADV_WIPEONFORK);
        }
        Ok(Self {
            page: page.cast(),
            len,
        })
    }

    fn key(&self) -> &[u8; KEY_LEN] {
        // SAFETY: the mapping is at least KEY_LEN bytes, page-aligned, and
        // lives as long as `self`.
        unsafe { &*self.page.cast::<[u8; KEY_LEN]>() }
    }

    fn key_mut(&mut self) -> &mut [u8; KEY_LEN] {
        // SAFETY: as in `key`, with exclusive access through `&mut self`.
        unsafe { &mut *self.page.cast::<[u8; KEY_LEN]>() }
    }

    #[cfg(test)]
    fn as_ptr(&self) -> *const u8 {
        self.page
    }
}

impl Drop for LockedPage {
    fn drop(&mut self) {
        self.key_mut().zeroize();
        // SAFETY: unmapping the mapping created in `new`, exactly once.
        // munmap also releases the page's mlock.
        unsafe {
            libc::munmap(self.page.cast(), self.len);
        }
    }
}

/// Holds the master key in its own page-locked page.
pub struct KeyHandle {
    mk: LockedPage,
}

impl KeyHandle {
    pub fn generate() -> Result<Self> {
        let mut mk = LockedPage::new()?;
        crypto::fill_random(mk.key_mut())?;
        Ok(Self { mk })
    }

    /// Wrap the master key for storage in a keyslot.
    pub fn wrap(&self, kek: &Kek, aad: &[u8]) -> Result<WrappedKey> {
        let (nonce, ciphertext) = crypto::seal(kek.expose(), aad, self.mk.key())?;
        Ok(WrappedKey { nonce, ciphertext })
    }

    /// Whether `kek` opens `wrapped` *and* the key inside is the one with
    /// fingerprint `expected_id`, without mapping a page for it.
    pub fn unwraps_to(kek: &Kek, wrapped: &WrappedKey, aad: &[u8], expected_id: &[u8; 16]) -> bool {
        crypto::open(kek.expose(), &wrapped.nonce, aad, &wrapped.ciphertext)
            .is_some_and(|pt| pt.len() == KEY_LEN && id_of(&pt) == *expected_id)
    }

    /// Whether `kek` opens `wrapped`, without mapping a page for the
    /// result: for checks that discard the key.
    pub fn unwraps(kek: &Kek, wrapped: &WrappedKey, aad: &[u8]) -> bool {
        crypto::open(kek.expose(), &wrapped.nonce, aad, &wrapped.ciphertext)
            .is_some_and(|pt| pt.len() == KEY_LEN)
    }

    /// Recover the master key from a keyslot.
    pub fn unwrap(kek: &Kek, wrapped: &WrappedKey, aad: &[u8]) -> Result<Self> {
        let pt = crypto::open(kek.expose(), &wrapped.nonce, aad, &wrapped.ciphertext)
            .ok_or(Error::UnwrapFailed)?;
        if pt.len() != KEY_LEN {
            return Err(Error::UnwrapFailed);
        }
        let mut mk = LockedPage::new()?;
        mk.key_mut().copy_from_slice(&pt);
        Ok(Self { mk })
    }

    pub fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        crypto::seal(&self.derive(info), aad, plaintext)
    }

    pub fn open(
        &self,
        info: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        crypto::open(&self.derive(info), nonce, aad, ct)
    }

    pub fn mac(&self, info: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
        crypto::hmac_sha256(&self.derive(info), data)
    }

    pub fn verify_mac(&self, info: &[u8], data: &[u8], tag: &[u8; MAC_LEN]) -> bool {
        crypto::hmac_sha256_verify(&self.derive(info), data, tag)
    }

    /// A public fingerprint of this master key: `HKDF(MK, "aleph mk id v1")`
    /// truncated to 16 bytes. Changes whenever MK rotates.
    pub fn id(&self) -> [u8; 16] {
        id_of(self.mk.key())
    }

    fn derive(&self, info: &[u8]) -> zeroize::Zeroizing<[u8; KEY_LEN]> {
        crypto::hkdf(self.mk.key(), info)
    }
}

fn id_of(mk: &[u8]) -> [u8; 16] {
    let okm = crypto::hkdf(mk, b"aleph mk id v1");
    let mut id = [0u8; 16];
    id.copy_from_slice(&okm[..16]);
    id
}

impl std::fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyHandle([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip_preserves_key() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        let back = KeyHandle::unwrap(&kek, &wrapped, b"slot-aad").unwrap();
        // Same master key => same derived MAC.
        assert_eq!(mk.mac(b"x", b"data"), back.mac(b"x", b"data"));
    }

    #[test]
    fn unwrap_fails_with_wrong_kek_or_aad() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        assert!(matches!(
            KeyHandle::unwrap(&Kek::generate().unwrap(), &wrapped, b"slot-aad"),
            Err(Error::UnwrapFailed)
        ));
        assert!(matches!(
            KeyHandle::unwrap(&kek, &wrapped, b"other-aad"),
            Err(Error::UnwrapFailed)
        ));
    }

    #[test]
    fn id_is_stable_per_key_and_differs_between_keys() {
        let a = KeyHandle::generate().unwrap();
        let b = KeyHandle::generate().unwrap();
        assert_eq!(a.id(), a.id());
        assert_ne!(a.id(), b.id());
        // The fingerprint is not the key: it cannot unwrap anything.
        assert_ne!(a.id(), [0u8; 16]);
    }

    #[test]
    fn unwraps_to_also_checks_which_master_key_it_is() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        assert!(KeyHandle::unwraps_to(&kek, &wrapped, b"slot-aad", &mk.id()));
        let other = KeyHandle::generate().unwrap();
        assert!(!KeyHandle::unwraps_to(
            &kek,
            &wrapped,
            b"slot-aad",
            &other.id()
        ));
        assert!(!KeyHandle::unwraps_to(
            &kek,
            &wrapped,
            b"other-aad",
            &mk.id()
        ));
    }

    #[test]
    fn unwraps_agrees_with_unwrap() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        assert!(KeyHandle::unwraps(&kek, &wrapped, b"slot-aad"));
        assert!(!KeyHandle::unwraps(&kek, &wrapped, b"other-aad"));
        assert!(!KeyHandle::unwraps(
            &Kek::generate().unwrap(),
            &wrapped,
            b"slot-aad"
        ));
    }

    /// Address of the master key bytes (test-only view of internals).
    fn key_addr(k: &KeyHandle) -> usize {
        k.mk.as_ptr() as usize
    }

    /// `Locked:` (kB) of the mapping in /proc/self/smaps containing `addr`.
    fn locked_kib(addr: usize) -> u64 {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut in_range = false;
        for line in smaps.lines() {
            let first = line.split_whitespace().next().unwrap_or("");
            if let Some((lo, hi)) = first.split_once('-')
                && let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            {
                in_range = (lo..hi).contains(&addr);
            } else if in_range && let Some(rest) = line.strip_prefix("Locked:") {
                return rest.trim().trim_end_matches("kB").trim().parse().unwrap();
            }
        }
        panic!("no mapping contains {addr:#x}");
    }

    /// Whether this process may mlock another page, probed on a scratch
    /// mapping so a key that is merely *not* locked still fails the test.
    fn mlock_is_permitted() -> bool {
        let len = 4096;
        // SAFETY: a fresh anonymous mapping, unmapped before returning.
        unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(p, libc::MAP_FAILED);
            let ok = libc::mlock(p, len) == 0;
            libc::munmap(p, len);
            ok
        }
    }

    /// mlock does not nest: unlocking one key's page must never unlock a
    /// page that another live key still relies on.
    #[test]
    fn dropping_one_key_keeps_another_key_locked() {
        let a = KeyHandle::generate().unwrap();
        let b = KeyHandle::generate().unwrap();
        if locked_kib(key_addr(&b)) == 0 && !mlock_is_permitted() {
            // mlock is best effort by design; e.g. RLIMIT_MEMLOCK = 0 in CI.
            eprintln!("skipping: this environment does not permit mlock");
            return;
        }
        assert!(locked_kib(key_addr(&b)) > 0, "key not locked at all");
        drop(a);
        assert!(
            locked_kib(key_addr(&b)) > 0,
            "live key unlocked by dropping another"
        );
    }

    /// A forked child (the daemon spawning a prompter or swtpm) must not
    /// inherit a copy of the master key: its copy would not be mlocked.
    #[test]
    fn forked_child_sees_a_zeroed_key() {
        let k = KeyHandle::generate().unwrap();
        assert_ne!(k.mk.key(), &[0u8; KEY_LEN]);
        // SAFETY: the child only reads memory and calls `_exit`, both
        // async-signal-safe, so forking a multithreaded test is sound.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let wiped = k.mk.key() == &[0u8; KEY_LEN];
            unsafe { libc::_exit(if wiped { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waiting on the child forked above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        assert_eq!(libc::WEXITSTATUS(status), 0, "child saw the master key");
    }

    /// The daemon shares the unlocked vault across async tasks; the raw
    /// page pointer must not silently make `KeyHandle` thread-bound.
    #[test]
    fn key_handle_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KeyHandle>();
        assert_send_sync::<crate::vault::UnlockedVault>();
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(
            format!("{:?}", KeyHandle::generate().unwrap()),
            "KeyHandle([REDACTED])"
        );
        assert_eq!(format!("{:?}", Kek::generate().unwrap()), "Kek([REDACTED])");
    }
}
