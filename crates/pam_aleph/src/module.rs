//! What the module does in each PAM phase, over small traits so it can be
//! tested without libpam (`lib.rs` adapts the real handle).
//!
//! - **auth:** read the password (`PAM_AUTHTOK`, set by `pam_unix` before
//!   us). If the user's `pam.sock` exists (a screen locker, or a second
//!   login), deliver it now; otherwise, or if no daemon answered there,
//!   keep it (`pam_set_data`, zeroized on cleanup) for session open, when
//!   the user's systemd instance is up. A daemon that refused, or did not
//!   answer in time, is not asked again: the host waits the timeout once.
//! - **session open:** deliver a kept password.
//! - **password (chauthtok):** in the update phase, deliver the old and new
//!   passwords, only when both are known (root changing another user's
//!   password supplies no old one, and nothing is sent).
//!
//! Every phase returns `PAM_IGNORE`: the module never decides or blocks a
//! login. It never prompts either: without a password it does nothing.

use aleph_pam_proto::{Password, Request};
use zeroize::Zeroizing;

use crate::deliver::Outcome;

/// The PAM handle, as the module uses it.
pub trait Pam {
    /// `PAM_USER`.
    fn user(&self) -> Option<String>;
    /// `PAM_AUTHTOK`.
    fn authtok(&self) -> Option<Zeroizing<Vec<u8>>>;
    /// `PAM_OLDAUTHTOK`.
    fn old_authtok(&self) -> Option<Zeroizing<Vec<u8>>>;
    /// Keep the password until session open (replacing any kept one).
    fn keep(&mut self, password: Zeroizing<Vec<u8>>);
    /// Take the kept password, if any (it is no longer kept).
    fn take_kept(&mut self) -> Option<Zeroizing<Vec<u8>>>;
    fn log(&self, message: &str);
}

/// Where requests go.
pub trait Courier {
    /// The user's daemon is listening (its socket exists).
    fn ready(&self, user: &str) -> bool;
    fn deliver(&self, user: &str, request: &Request) -> Outcome;
}

fn send(
    pam: &dyn Pam,
    courier: &dyn Courier,
    user: &str,
    request: &Request,
    what: &str,
) -> Outcome {
    let outcome = courier.deliver(user, request);
    match outcome {
        Outcome::Accepted => pam.log(&format!("{what}: done")),
        other => pam.log(&format!("{what}: not done ({other:?})")),
    }
    outcome
}

pub fn authenticate(pam: &mut dyn Pam, courier: &dyn Courier) {
    let (Some(user), Some(password)) = (pam.user(), pam.authtok()) else {
        return;
    };
    if courier.ready(&user) {
        let request = Request::Unlock {
            password: Password::new(&password),
        };
        match send(pam, courier, &user, &request, "unlock") {
            // Not there yet (a stale socket file), or it failed on our
            // side: try again at session open.
            Outcome::Unreachable | Outcome::Failed => {}
            // Done, refused, or no answer in time (the host has waited the
            // timeout once already): nothing more.
            _ => return,
        }
    }
    // Not up yet (a login), or no daemon answered: try at session open.
    pam.keep(password);
}

pub fn open_session(pam: &mut dyn Pam, courier: &dyn Courier) {
    let (Some(user), Some(password)) = (pam.user(), pam.take_kept()) else {
        return;
    };
    let request = Request::Unlock {
        password: Password::new(&password),
    };
    send(pam, courier, &user, &request, "unlock at login");
}

/// `update`: `PAM_UPDATE_AUTHTOK` is set (the change has been made by the
/// modules before this one).
pub fn change_password(pam: &mut dyn Pam, courier: &dyn Courier, update: bool) {
    if !update {
        return;
    }
    let (Some(user), Some(old), Some(new)) = (pam.user(), pam.old_authtok(), pam.authtok()) else {
        return;
    };
    let request = Request::ChangePassword {
        old: Password::new(&old),
        new: Password::new(&new),
    };
    send(pam, courier, &user, &request, "password change");
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct FakePam {
        authtok: Option<&'static str>,
        old: Option<&'static str>,
        kept: Option<Zeroizing<Vec<u8>>>,
        logs: RefCell<Vec<String>>,
    }

    impl Pam for FakePam {
        fn user(&self) -> Option<String> {
            Some("alice".into())
        }
        fn authtok(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.authtok.map(|s| Zeroizing::new(s.as_bytes().to_vec()))
        }
        fn old_authtok(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.old.map(|s| Zeroizing::new(s.as_bytes().to_vec()))
        }
        fn keep(&mut self, password: Zeroizing<Vec<u8>>) {
            self.kept = Some(password);
        }
        fn take_kept(&mut self) -> Option<Zeroizing<Vec<u8>>> {
            self.kept.take()
        }
        fn log(&self, message: &str) {
            self.logs.borrow_mut().push(message.into());
        }
    }

    struct FakeCourier {
        ready: bool,
        answer: Outcome,
        sent: RefCell<Vec<Request>>,
    }

    impl FakeCourier {
        fn new(ready: bool) -> Self {
            Self {
                ready,
                answer: Outcome::Accepted,
                sent: RefCell::default(),
            }
        }
    }

    impl Courier for FakeCourier {
        fn ready(&self, _: &str) -> bool {
            self.ready
        }
        fn deliver(&self, user: &str, request: &Request) -> Outcome {
            assert_eq!(user, "alice");
            self.sent.borrow_mut().push(request.clone());
            self.answer
        }
    }

    fn unlock(pw: &str) -> Request {
        Request::Unlock {
            password: Password::new(pw.as_bytes()),
        }
    }

    #[test]
    fn with_the_daemon_up_auth_delivers_at_once() {
        let mut pam = FakePam {
            authtok: Some("pw"),
            ..Default::default()
        };
        let courier = FakeCourier::new(true);
        authenticate(&mut pam, &courier);
        assert_eq!(*courier.sent.borrow(), [unlock("pw")]);
        assert!(pam.kept.is_none());
    }

    #[test]
    fn at_login_the_password_waits_for_session_open() {
        let mut pam = FakePam {
            authtok: Some("pw"),
            ..Default::default()
        };
        let courier = FakeCourier::new(false);
        authenticate(&mut pam, &courier);
        assert!(courier.sent.borrow().is_empty());
        open_session(&mut pam, &courier);
        assert_eq!(*courier.sent.borrow(), [unlock("pw")]);
        // Delivered once, and no longer kept.
        open_session(&mut pam, &courier);
        assert_eq!(courier.sent.borrow().len(), 1);
        assert!(pam.kept.is_none());
    }

    #[test]
    fn without_a_password_nothing_is_sent_or_asked() {
        let mut pam = FakePam::default();
        let courier = FakeCourier::new(true);
        authenticate(&mut pam, &courier);
        open_session(&mut pam, &courier);
        change_password(&mut pam, &courier, true);
        assert!(courier.sent.borrow().is_empty());
    }

    #[test]
    fn a_password_change_is_sent_once_both_passwords_are_known() {
        let mut pam = FakePam {
            authtok: Some("new"),
            old: Some("old"),
            ..Default::default()
        };
        let courier = FakeCourier::new(true);
        change_password(&mut pam, &courier, false);
        assert!(courier.sent.borrow().is_empty());
        change_password(&mut pam, &courier, true);
        assert_eq!(
            *courier.sent.borrow(),
            [Request::ChangePassword {
                old: Password::new(b"old"),
                new: Password::new(b"new"),
            }]
        );
        // Root setting another user's password: no old one, nothing sent.
        let mut pam = FakePam {
            authtok: Some("new"),
            ..Default::default()
        };
        let courier = FakeCourier::new(true);
        change_password(&mut pam, &courier, true);
        assert!(courier.sent.borrow().is_empty());
    }

    /// A delivery at auth that found no daemon (a stale socket file) is
    /// tried again at session open.
    #[test]
    fn a_failed_delivery_at_auth_is_tried_again_at_session_open() {
        let mut pam = FakePam {
            authtok: Some("pw"),
            ..Default::default()
        };
        let mut courier = FakeCourier::new(true);
        courier.answer = Outcome::Unreachable;
        authenticate(&mut pam, &courier);
        assert!(pam.kept.is_some());
        courier.answer = Outcome::Accepted;
        open_session(&mut pam, &courier);
        assert_eq!(*courier.sent.borrow(), [unlock("pw"), unlock("pw")]);
    }

    /// A daemon that answered (refused) or did not answer in time is not
    /// asked again at session open: the host program waits at most the
    /// timeout once, and a refusal is not spent twice.
    #[test]
    fn a_refused_or_timed_out_delivery_is_not_retried() {
        for answer in [Outcome::TimedOut, Outcome::Refused] {
            let mut pam = FakePam {
                authtok: Some("pw"),
                ..Default::default()
            };
            let mut courier = FakeCourier::new(true);
            courier.answer = answer;
            authenticate(&mut pam, &courier);
            assert!(pam.kept.is_none(), "{answer:?}");
            open_session(&mut pam, &courier);
            assert_eq!(courier.sent.borrow().len(), 1, "{answer:?}");
        }
    }

    #[test]
    fn failures_are_logged_without_the_password() {
        let mut pam = FakePam {
            authtok: Some("hunter2"),
            ..Default::default()
        };
        let mut courier = FakeCourier::new(true);
        courier.answer = Outcome::Unreachable;
        authenticate(&mut pam, &courier);
        let logs = pam.logs.borrow();
        assert!(logs.iter().any(|l| l.contains("Unreachable")), "{logs:?}");
        assert!(!logs.iter().any(|l| l.contains("hunter2")));
    }
}
