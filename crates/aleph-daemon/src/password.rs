//! Checking a typed login password before it reaches the TPM.
//!
//! A TPM slot's auth value comes from the login password, and every
//! failed unseal spends the TPM's shared dictionary-attack budget: on a
//! real TPM (recovery time 7200 s) two typos would block TPM unlock for
//! hours (`docs/hardware-log.md`). So a password typed into a prompt is
//! first checked with PAM (the `aleph-check` service, `pam_unix` only, as
//! a screen locker checks it), and only a password PAM accepts is offered
//! to the TPM. Passwords from `pam_aleph` (Plan 4) were already accepted
//! by the login stack and skip this.
//!
//! Typed attempts are also limited locally: at most
//! [`TYPED_FAILURES`] wrong passwords per [`TYPED_WINDOW`].

use std::collections::VecDeque;
use std::ffi::CStr;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

pub const PAM_SERVICE: &str = "aleph-check";
pub const TYPED_FAILURES: usize = 5;
pub const TYPED_WINDOW: Duration = Duration::from_secs(60);

/// Says whether a password is the user's current login password.
pub trait PasswordCheck: Send + Sync {
    fn check(&self, password: &str) -> Result<bool>;
}

/// The real check, through PAM as the daemon's own user.
pub struct PamCheck {
    user: String,
    /// Where the service file lives (`/etc/pam.d` unless a test says).
    confdir: Option<std::path::PathBuf>,
}

impl PamCheck {
    pub fn for_current_user() -> Result<Self> {
        Ok(Self {
            user: current_user()?,
            confdir: None,
        })
    }

    /// Read the service file from `confdir` instead of `/etc/pam.d`
    /// (Linux-PAM's `pam_start_confdir`), so tests can use real modules
    /// without installing anything.
    pub fn with_confdir(confdir: &Path) -> Result<Self> {
        Ok(Self {
            user: current_user()?,
            confdir: Some(confdir.to_path_buf()),
        })
    }
}

impl PasswordCheck for PamCheck {
    fn check(&self, password: &str) -> Result<bool> {
        // Without the service file PAM falls back to `other`, which denies
        // everything: that must not read as "wrong password".
        let dir = self.confdir.as_deref().unwrap_or(Path::new("/etc/pam.d"));
        if !dir.join(PAM_SERVICE).exists() {
            return Err(Error::PasswordCheckUnavailable);
        }
        pam::authenticate(PAM_SERVICE, &self.user, password, self.confdir.as_deref())
    }
}

/// The few libpam calls needed, declared directly (the binding crates
/// need bindgen at build time).
mod pam {
    use std::ffi::{CStr, CString, c_char, c_int, c_void};

    use crate::error::{Error, Result};

    const PAM_SUCCESS: c_int = 0;
    const PAM_BUF_ERR: c_int = 5;
    const PAM_AUTH_ERR: c_int = 7;
    const PAM_CONV_ERR: c_int = 19;
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    const PAM_PROMPT_ECHO_ON: c_int = 2;

    #[repr(C)]
    struct Message {
        style: c_int,
        msg: *const c_char,
    }

    #[repr(C)]
    struct Response {
        resp: *mut c_char,
        retcode: c_int,
    }

    #[repr(C)]
    struct Conv {
        conv: extern "C" fn(c_int, *mut *const Message, *mut *mut Response, *mut c_void) -> c_int,
        appdata: *mut c_void,
    }

    #[link(name = "pam")]
    unsafe extern "C" {
        fn pam_start(
            service: *const c_char,
            user: *const c_char,
            conv: *const Conv,
            handle: *mut *mut c_void,
        ) -> c_int;
        fn pam_start_confdir(
            service: *const c_char,
            user: *const c_char,
            conv: *const Conv,
            confdir: *const c_char,
            handle: *mut *mut c_void,
        ) -> c_int;
        fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
        fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
        fn pam_strerror(handle: *mut c_void, errnum: c_int) -> *const c_char;
    }

    /// Answers the password prompt with `appdata` (a `CStr`), refuses any
    /// other prompt, and ignores informational messages.
    extern "C" fn converse(
        n: c_int,
        msgs: *mut *const Message,
        out: *mut *mut Response,
        appdata: *mut c_void,
    ) -> c_int {
        let Ok(n) = usize::try_from(n) else {
            return PAM_CONV_ERR;
        };
        // SAFETY: PAM frees the array and each `resp` with free(), so both
        // come from calloc/strdup. `msgs` holds `n` message pointers
        // (Linux-PAM's layout) and `appdata` is the CStr passed below.
        unsafe {
            let responses = libc::calloc(n, std::mem::size_of::<Response>()).cast::<Response>();
            if responses.is_null() {
                return PAM_BUF_ERR;
            }
            let password = appdata.cast::<c_char>();
            for i in 0..n {
                match (*(*msgs.add(i))).style {
                    PAM_PROMPT_ECHO_OFF => {
                        let copy = libc::strdup(password);
                        if copy.is_null() {
                            free_responses(responses, n);
                            return PAM_BUF_ERR;
                        }
                        (*responses.add(i)).resp = copy;
                    }
                    PAM_PROMPT_ECHO_ON => {
                        free_responses(responses, n);
                        return PAM_CONV_ERR;
                    }
                    _ => {}
                }
            }
            *out = responses;
        }
        PAM_SUCCESS
    }

    /// SAFETY: `responses` is a calloc'd array of `n` responses whose
    /// `resp` fields are null or strdup'd.
    unsafe fn free_responses(responses: *mut Response, n: usize) {
        for i in 0..n {
            // SAFETY: as documented above; the password copies are wiped.
            unsafe {
                let resp = (*responses.add(i)).resp;
                if !resp.is_null() {
                    let len = libc::strlen(resp);
                    std::ptr::write_bytes(resp, 0, len);
                    libc::free(resp.cast());
                }
            }
        }
        // SAFETY: allocated by calloc in `converse`.
        unsafe { libc::free(responses.cast()) };
    }

    pub fn authenticate(
        service: &str,
        user: &str,
        password: &str,
        confdir: Option<&std::path::Path>,
    ) -> Result<bool> {
        let bad = |what| Error::PasswordCheck(format!("{what} contains a NUL byte"));
        let service = CString::new(service).map_err(|_| bad("service"))?;
        let user = CString::new(user).map_err(|_| bad("user name"))?;
        let password = zeroize::Zeroizing::new(
            CString::new(password)
                .map_err(|_| Error::WrongPassword)?
                .into_bytes_with_nul(),
        );
        let conv = Conv {
            conv: converse,
            appdata: password.as_ptr() as *mut c_void,
        };
        let confdir = confdir
            .map(|d| CString::new(d.as_os_str().as_encoded_bytes()).map_err(|_| bad("confdir")))
            .transpose()?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: all pointers outlive the PAM transaction, which ends with
        // pam_end below on every path.
        unsafe {
            let rc = match &confdir {
                Some(dir) => pam_start_confdir(
                    service.as_ptr(),
                    user.as_ptr(),
                    &conv,
                    dir.as_ptr(),
                    &mut handle,
                ),
                None => pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle),
            };
            if rc != PAM_SUCCESS {
                return Err(Error::PasswordCheck(format!("pam_start failed ({rc})")));
            }
            let rc = pam_authenticate(handle, 0);
            let result = match rc {
                PAM_SUCCESS => Ok(true),
                PAM_AUTH_ERR => Ok(false),
                other => Err(Error::PasswordCheck(
                    CStr::from_ptr(pam_strerror(handle, other))
                        .to_string_lossy()
                        .into_owned(),
                )),
            };
            pam_end(handle, rc);
            result
        }
    }
}

fn current_user() -> Result<String> {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let mut buf = vec![0u8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the sizes given; getpwuid_r writes
    // only into `pwd` and `buf`.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return Err(Error::Environment("cannot look up the current user"));
    }
    // SAFETY: on success pw_name points to a NUL-terminated string in `buf`.
    let name = unsafe { CStr::from_ptr(pwd.pw_name) };
    Ok(name.to_string_lossy().into_owned())
}

/// At most [`TYPED_FAILURES`] wrong typed passwords per [`TYPED_WINDOW`].
#[derive(Default)]
pub struct TypedLimiter {
    failures: VecDeque<Instant>,
}

impl TypedLimiter {
    /// `Some(wait)` if typing is blocked now.
    pub fn blocked(&mut self, now: Instant) -> Option<Duration> {
        while self
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) >= TYPED_WINDOW)
        {
            self.failures.pop_front();
        }
        (self.failures.len() >= TYPED_FAILURES)
            .then(|| TYPED_WINDOW.saturating_sub(now.duration_since(self.failures[0])))
    }

    pub fn record_failure(&mut self, now: Instant) {
        self.failures.push_back(now);
    }
}

/// A fixed answer (tests, and machines configured without PAM checking).
pub struct Fixed(pub fn(&str) -> bool);

impl PasswordCheck for Fixed {
    fn check(&self, password: &str) -> Result<bool> {
        Ok((self.0)(password))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_attempts_are_limited_per_window() {
        let t0 = Instant::now();
        let mut l = TypedLimiter::default();
        for _ in 0..TYPED_FAILURES {
            assert_eq!(l.blocked(t0), None);
            l.record_failure(t0);
        }
        assert_eq!(l.blocked(t0), Some(TYPED_WINDOW));
        assert_eq!(
            l.blocked(t0 + Duration::from_secs(20)),
            Some(TYPED_WINDOW - Duration::from_secs(20))
        );
        assert_eq!(l.blocked(t0 + TYPED_WINDOW), None);
    }

    fn confdir(service_file: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PAM_SERVICE), service_file).unwrap();
        dir
    }

    /// The real PAM path, with a private service directory: `pam_unix`
    /// asks for the password through our conversation and rejects a wrong
    /// one (no faillock, no delay, no root needed).
    #[test]
    fn pam_rejects_a_wrong_password() {
        let dir = confdir("auth required pam_unix.so nodelay\n");
        let check = PamCheck::with_confdir(dir.path()).unwrap();
        assert!(
            !check
                .check("definitely not the password \u{1F512}")
                .unwrap()
        );
    }

    #[test]
    fn pam_accepts_what_its_modules_accept() {
        let dir = confdir("auth required pam_permit.so\n");
        assert!(
            PamCheck::with_confdir(dir.path())
                .unwrap()
                .check("x")
                .unwrap()
        );
    }

    /// The service file aleph ships works with real PAM.
    #[test]
    fn the_shipped_service_file_checks_passwords() {
        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/pam/aleph-check");
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(&shipped, dir.path().join(PAM_SERVICE)).unwrap();
        let check = PamCheck::with_confdir(dir.path()).unwrap();
        assert!(!check.check("definitely not the password").unwrap());
    }

    #[test]
    fn a_missing_service_is_unavailable_not_wrong() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            PamCheck::with_confdir(dir.path()).unwrap().check("x"),
            Err(Error::PasswordCheckUnavailable)
        ));
    }

    #[test]
    fn the_current_user_is_known() {
        assert!(!current_user().unwrap().is_empty());
    }
}
