//! `pam_aleph`: hands the login password to `alephd` (spec §6 "PAM
//! integration").
//!
//! Stacked after `pam_unix` in the display manager's `auth` and `session`
//! stacks, the screen locker's `auth` stack, and `passwd`'s `password`
//! stack (as `-auth optional pam_aleph.so` and so on: with `-`, a missing
//! module is skipped), so it only ever sees a password the login stack
//! accepted. What each phase does is in
//! [`module`]; how a request reaches the user's daemon is in [`deliver`].
//! It always returns `PAM_IGNORE`, and logs to syslog, never a password.
//!
//! Module arguments: `socket=<path>` sends to that socket instead of
//! `/run/user/<uid>/aleph/pam.sock` (for tests).

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::PathBuf;
use std::time::Duration;

use aleph_pam_proto::Request;
use zeroize::Zeroizing;

pub mod deliver;
pub mod module;

/// How long the host program waits for a delivery, at most (§6).
pub const TIMEOUT: Duration = Duration::from_secs(5);

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_USER: c_int = 2;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_UPDATE_AUTHTOK: c_int = 0x2000;
const LOG_INFO: c_int = 6;

/// The `pam_set_data` name for the kept password.
const KEPT: &CStr = c"aleph_password";

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

type Cleanup = unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int);

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_set_data(
        pamh: *mut PamHandle,
        name: *const c_char,
        data: *mut c_void,
        cleanup: Option<Cleanup>,
    ) -> c_int;
    fn pam_get_data(pamh: *const PamHandle, name: *const c_char, data: *mut *const c_void)
    -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

/// Frees a kept password (zeroizing it) when PAM ends or it is replaced.
unsafe extern "C" fn drop_kept(_: *mut PamHandle, data: *mut c_void, _: c_int) {
    if !data.is_null() {
        // SAFETY: `data` came from `Box::into_raw` in `keep`, and PAM calls
        // the cleanup once.
        drop(unsafe { Box::from_raw(data.cast::<Zeroizing<Vec<u8>>>()) });
    }
}

/// The real PAM handle.
struct Handle(*mut PamHandle);

impl Handle {
    fn item(&self, which: c_int) -> Option<Zeroizing<Vec<u8>>> {
        let mut value = std::ptr::null();
        // SAFETY: a valid handle and out-pointer; string items are
        // NUL-terminated strings owned by PAM.
        unsafe {
            if pam_get_item(self.0, which, &mut value) != PAM_SUCCESS || value.is_null() {
                return None;
            }
            Some(Zeroizing::new(
                CStr::from_ptr(value.cast()).to_bytes().to_vec(),
            ))
        }
    }
}

impl module::Pam for Handle {
    fn user(&self) -> Option<String> {
        String::from_utf8(self.item(PAM_USER)?.to_vec()).ok()
    }

    fn authtok(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.item(PAM_AUTHTOK).filter(|p| !p.is_empty())
    }

    fn old_authtok(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.item(PAM_OLDAUTHTOK).filter(|p| !p.is_empty())
    }

    fn keep(&mut self, password: Zeroizing<Vec<u8>>) {
        let data = Box::into_raw(Box::new(password)).cast::<c_void>();
        // SAFETY: PAM owns `data` from here and frees it with `drop_kept`
        // (also when it replaces it).
        if unsafe { pam_set_data(self.0, KEPT.as_ptr(), data, Some(drop_kept)) } != PAM_SUCCESS {
            // SAFETY: PAM did not take it.
            unsafe { drop_kept(self.0, data, 0) };
        }
    }

    fn take_kept(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let mut data = std::ptr::null();
        // SAFETY: a valid handle; the data is our boxed password.
        unsafe {
            if pam_get_data(self.0, KEPT.as_ptr(), &mut data) != PAM_SUCCESS || data.is_null() {
                return None;
            }
            let password = (*data.cast::<Zeroizing<Vec<u8>>>()).clone();
            // Replacing it frees (and zeroizes) the kept copy.
            pam_set_data(self.0, KEPT.as_ptr(), std::ptr::null_mut(), None);
            Some(password)
        }
    }

    fn log(&self, message: &str) {
        let Ok(message) = CString::new(format!("pam_aleph: {message}")) else {
            return;
        };
        // SAFETY: a "%s" format with one C string argument.
        unsafe { pam_syslog(self.0, LOG_INFO, c"%s".as_ptr(), message.as_ptr()) };
    }
}

/// Delivers to the user's `pam.sock` (or the `socket=` argument).
struct SocketCourier {
    socket: Option<PathBuf>,
}

impl SocketCourier {
    fn path(&self, target: deliver::Target) -> PathBuf {
        self.socket
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}/aleph/pam.sock", target.uid)))
    }
}

impl module::Courier for SocketCourier {
    fn ready(&self, user: &str) -> bool {
        deliver::target(user).is_some_and(|t| self.path(t).exists())
    }

    fn deliver(&self, user: &str, request: &Request) -> deliver::Outcome {
        let Some(target) = deliver::target(user) else {
            return deliver::Outcome::NoPrivileges;
        };
        let Ok(frame) = request.encode() else {
            return deliver::Outcome::Failed;
        };
        deliver::deliver(target, &self.path(target), &frame, TIMEOUT)
    }
}

fn courier(argc: c_int, argv: *const *const c_char) -> SocketCourier {
    let mut socket = None;
    for i in 0..usize::try_from(argc).unwrap_or(0) {
        // SAFETY: PAM passes `argc` valid C strings.
        let arg = unsafe { CStr::from_ptr(*argv.add(i)) };
        if let Some(path) = arg.to_bytes().strip_prefix(b"socket=") {
            socket = Some(PathBuf::from(String::from_utf8_lossy(path).into_owned()));
        }
    }
    SocketCourier { socket }
}

/// Run a phase; whatever happens (a panic included), answer `PAM_IGNORE`.
fn run(
    pamh: *mut PamHandle,
    argc: c_int,
    argv: *const *const c_char,
    phase: fn(&mut Handle, &SocketCourier),
) -> c_int {
    if pamh.is_null() {
        return PAM_IGNORE;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        phase(&mut Handle(pamh), &courier(argc, argv))
    }));
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    run(pamh, argc, argv, |h, c| module::authenticate(h, c))
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    run(pamh, argc, argv, |h, c| module::open_session(h, c))
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let update = flags & PAM_UPDATE_AUTHTOK != 0;
    if !update {
        return PAM_IGNORE;
    }
    run(pamh, argc, argv, |h, c| module::change_password(h, c, true))
}
