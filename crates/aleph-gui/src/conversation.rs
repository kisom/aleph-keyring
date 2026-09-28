//! One prompter conversation with `alephd` (spec §6 "Prompter
//! orchestration"), without any drawing: what the window shows, and which
//! answers it may send.
//!
//! alephd sends [`ToPrompter`] messages; the ones that need a reply get
//! exactly one [`FromPrompter`], and `Cancel` may be sent at any time. The
//! conversation starts with `Begin` and ends with `Done`.

use std::time::{Duration, Instant};

use aleph_prompt_proto::{Caller, FromPrompter, Method, Purpose, Secret, ToPrompter};

/// What the window shows.
#[derive(Debug, PartialEq)]
pub enum Screen {
    /// Before the first question, and after an answer until the next
    /// message (alephd is checking it).
    Working,
    /// Choose a method: the login password and/or a security key.
    Ask {
        methods: Vec<Method>,
        error: Option<String>,
        /// When a typed password can be tried again (a TPM or attempt
        /// back-off); until then only a security key can be used.
        retry_at: Option<Instant>,
    },
    /// The login password changed without aleph: the previous one.
    OldPassword {
        error: Option<String>,
    },
    Pin {
        key: String,
        error: Option<String>,
    },
    InsertKey {
        key: String,
    },
    Touch {
        key: String,
    },
    Confirm {
        text: String,
        default: bool,
    },
    /// The recovery key (a recovery conversation only).
    RecoveryKey {
        error: Option<String>,
    },
    /// A new recovery key, shown once; then two of its groups are typed
    /// back (`checking`).
    ShowRecoveryKey {
        key: Secret,
        check: [usize; 2],
        error: Option<String>,
        checking: bool,
    },
    /// The conversation is over.
    Finished {
        ok: bool,
        message: Option<String>,
    },
}

/// What the person did.
#[derive(Debug, PartialEq)]
pub enum Action {
    Password(Secret),
    Fido2,
    Pin(Secret),
    Confirm(bool),
    RecoveryKey(Secret),
    /// "I have written it down": show the check.
    RecoveryKeyWritten,
    RecoveryCheck([Secret; 2]),
    Cancel,
    /// Close the window once the conversation is over.
    Close,
}

/// The longest text shown for a title, a key's or a caller's name.
const NAME: usize = 80;
/// The longest question, error, or closing message shown.
const TEXT: usize = 400;

/// Text from alephd as shown: control characters (newlines included) and
/// runs of white space become one space, and it is cut to `max`
/// characters. Collection labels and process names come from other
/// programs; they must not be able to draw a fake prompt inside the real
/// one (lines of their own), or push its buttons out of view.
pub fn shown(s: &str, max: usize) -> String {
    let clean = s
        .split(|c: char| c.is_control() || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let clean = clean.as_str();
    match clean.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &clean[..cut]),
        None => clean.to_string(),
    }
}

fn shown_opt(s: Option<String>, max: usize) -> Option<String> {
    s.map(|s| shown(&s, max))
}

pub struct Conversation {
    pub purpose: Option<Purpose>,
    pub operation: String,
    pub caller: Option<Caller>,
    pub screen: Screen,
    /// A question is waiting for its one answer.
    awaiting: bool,
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
    }
}

impl Conversation {
    pub fn new() -> Self {
        Self {
            purpose: None,
            operation: String::new(),
            caller: None,
            screen: Screen::Working,
            awaiting: false,
        }
    }

    pub fn finished(&self) -> bool {
        matches!(self.screen, Screen::Finished { .. })
    }

    /// Take a message from alephd. Returns an answer to send at once, if
    /// the message must be refused (a recovery-key question outside a
    /// recovery conversation, anything before `Begin`).
    pub fn receive(&mut self, msg: ToPrompter, now: Instant) -> Option<FromPrompter> {
        if self.finished() {
            return None;
        }
        let begun = self.purpose.is_some();
        let refuse = |this: &mut Self, why: &str| {
            this.screen = Screen::Finished {
                ok: false,
                message: Some(why.into()),
            };
            this.awaiting = false;
            Some(FromPrompter::Cancel {})
        };
        let needs_reply = msg.needs_reply();
        self.screen = match msg {
            ToPrompter::Begin {
                purpose,
                operation,
                caller,
            } => {
                if begun {
                    return refuse(self, "alephd started a second conversation");
                }
                self.purpose = Some(purpose);
                self.operation = shown(&operation, NAME);
                self.caller = caller.map(|c| Caller {
                    name: shown_opt(c.name, NAME),
                    pid: c.pid,
                });
                Screen::Working
            }
            _ if !begun => return refuse(self, "alephd skipped the start of the conversation"),
            // Keeping the root credential off routine prompts makes fake
            // prompts less useful for phishing (spec §5).
            ToPrompter::RecoveryKey { .. } if self.purpose != Some(Purpose::Recover) => {
                return refuse(
                    self,
                    "alephd asked for the recovery key outside a recovery; nothing was sent",
                );
            }
            ToPrompter::RecoveryKey { error } => Screen::RecoveryKey {
                error: shown_opt(error, TEXT),
            },
            ToPrompter::Ask {
                methods,
                error,
                retry_after,
            } => Screen::Ask {
                methods,
                error: shown_opt(error, TEXT),
                retry_at: retry_after
                    .filter(|s| *s > 0)
                    .map(|s| now + Duration::from_secs(s)),
            },
            ToPrompter::OldPassword { error } => Screen::OldPassword {
                error: shown_opt(error, TEXT),
            },
            ToPrompter::Fido2Pin { key, error } => Screen::Pin {
                key: shown(&key, NAME),
                error: shown_opt(error, TEXT),
            },
            ToPrompter::InsertKey { key } => Screen::InsertKey {
                key: shown(&key, NAME),
            },
            ToPrompter::Touch { key } => Screen::Touch {
                key: shown(&key, NAME),
            },
            ToPrompter::Confirm { text, default } => Screen::Confirm {
                text: shown(&text, TEXT),
                default,
            },
            ToPrompter::ShowRecoveryKey { key, check, error } => Screen::ShowRecoveryKey {
                key,
                check,
                error: shown_opt(error, TEXT),
                checking: false,
            },
            ToPrompter::Done { ok, message } => Screen::Finished {
                ok,
                message: shown_opt(message, TEXT),
            },
        };
        self.awaiting = needs_reply;
        None
    }

    /// Act on what the person did. Returns the answer to send, if the
    /// action answers the question on screen (or cancels).
    pub fn act(&mut self, action: Action, now: Instant) -> Option<FromPrompter> {
        if self.finished() {
            return None;
        }
        if action == Action::Cancel {
            self.awaiting = false;
            self.screen = Screen::Finished {
                ok: false,
                message: None,
            };
            return Some(FromPrompter::Cancel {});
        }
        if !self.awaiting {
            return None;
        }
        let reply = match (&mut self.screen, action) {
            (
                Screen::Ask {
                    methods, retry_at, ..
                },
                Action::Password(password),
            ) if methods.contains(&Method::Password) && retry_at.is_none_or(|at| now >= at) => {
                FromPrompter::Password { password }
            }
            (Screen::Ask { methods, .. }, Action::Fido2) if methods.contains(&Method::Fido2) => {
                FromPrompter::Fido2 {}
            }
            (Screen::OldPassword { .. }, Action::Password(password)) => {
                FromPrompter::Password { password }
            }
            (Screen::Pin { .. }, Action::Pin(pin)) => FromPrompter::Pin { pin },
            (Screen::Confirm { .. }, Action::Confirm(yes)) => FromPrompter::Confirm { yes },
            (Screen::RecoveryKey { .. }, Action::RecoveryKey(key)) => {
                FromPrompter::RecoveryKey { key }
            }
            (Screen::ShowRecoveryKey { checking, .. }, Action::RecoveryKeyWritten) => {
                *checking = true;
                return None;
            }
            (Screen::ShowRecoveryKey { checking: true, .. }, Action::RecoveryCheck(groups)) => {
                FromPrompter::RecoveryCheck { groups }
            }
            _ => return None,
        };
        self.awaiting = false;
        self.screen = Screen::Working;
        Some(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begun(purpose: Purpose) -> Conversation {
        let mut c = Conversation::new();
        assert_eq!(
            c.receive(
                ToPrompter::Begin {
                    purpose,
                    operation: "Unlock the keyring".into(),
                    caller: None,
                },
                Instant::now(),
            ),
            None
        );
        c
    }

    fn ask(methods: Vec<Method>, retry_after: Option<u64>) -> ToPrompter {
        ToPrompter::Ask {
            methods,
            error: None,
            retry_after,
        }
    }

    #[test]
    fn a_password_answers_the_question_once() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        c.receive(ask(vec![Method::Password], None), now);
        let reply = c.act(Action::Password(Secret::new("pw")), now);
        assert_eq!(
            reply,
            Some(FromPrompter::Password {
                password: Secret::new("pw")
            })
        );
        assert_eq!(c.screen, Screen::Working);
        // A second answer to the same question is not sent.
        assert_eq!(c.act(Action::Password(Secret::new("pw")), now), None);
    }

    /// Only the methods offered can answer.
    #[test]
    fn a_method_not_offered_does_not_answer() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        c.receive(ask(vec![Method::Password], None), now);
        assert_eq!(c.act(Action::Fido2, now), None);
        c.receive(ask(vec![Method::Fido2], None), now);
        assert_eq!(c.act(Action::Password(Secret::new("pw")), now), None);
        assert_eq!(c.act(Action::Fido2, now), Some(FromPrompter::Fido2 {}));
    }

    /// While a typed password must wait, it is not sent; a key can still
    /// be used.
    #[test]
    fn a_password_waits_out_the_back_off_but_a_key_does_not() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        c.receive(ask(vec![Method::Password, Method::Fido2], Some(30)), now);
        assert_eq!(c.act(Action::Password(Secret::new("pw")), now), None);
        let later = now + Duration::from_secs(30);
        assert!(c.act(Action::Password(Secret::new("pw")), later).is_some());
        c.receive(ask(vec![Method::Password, Method::Fido2], Some(30)), now);
        assert_eq!(c.act(Action::Fido2, now), Some(FromPrompter::Fido2 {}));
    }

    /// Cancel is always possible, even with no question (waiting for a
    /// key or a touch), and ends the conversation.
    #[test]
    fn cancel_is_sent_while_waiting_for_a_key() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        c.receive(
            ToPrompter::InsertKey {
                key: "yubikey".into(),
            },
            now,
        );
        assert_eq!(c.act(Action::Fido2, now), None);
        assert_eq!(c.act(Action::Cancel, now), Some(FromPrompter::Cancel {}));
        assert!(c.finished());
        assert_eq!(c.act(Action::Cancel, now), None);
    }

    /// The recovery key is only ever asked in a recovery conversation
    /// (spec §5); anywhere else the question is refused unanswered.
    #[test]
    fn the_recovery_key_is_refused_outside_a_recovery() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        let reply = c.receive(ToPrompter::RecoveryKey { error: None }, now);
        assert_eq!(reply, Some(FromPrompter::Cancel {}));
        assert!(matches!(c.screen, Screen::Finished { ok: false, .. }));

        let mut c = begun(Purpose::Recover);
        assert_eq!(
            c.receive(ToPrompter::RecoveryKey { error: None }, now),
            None
        );
        assert_eq!(
            c.act(Action::RecoveryKey(Secret::new("K")), now),
            Some(FromPrompter::RecoveryKey {
                key: Secret::new("K")
            })
        );
    }

    /// Text from other programs (a collection label, a process name) can
    /// neither break lines nor run on.
    #[test]
    fn shown_text_has_no_line_breaks_and_is_cut() {
        assert_eq!(shown("a\nb\tc", 10), "a b c");
        // Padding cannot push text onto a line of its own.
        assert_eq!(
            shown(&format!("a{}Wrong password", " ".repeat(300)), 40),
            "a Wrong password"
        );
        assert_eq!(shown(&"x".repeat(500), 5), "xxxxx…");
        assert_eq!(shown("ééé", 2), "éé…");
        let mut c = begun(Purpose::Reauth);
        c.receive(
            ToPrompter::Confirm {
                text: format!("Delete the collection '{}\n\nUnlock'?", "w".repeat(1000)),
                default: false,
            },
            Instant::now(),
        );
        let Screen::Confirm { text, .. } = &c.screen else {
            panic!("{:?}", c.screen)
        };
        assert!(!text.contains('\n'));
        assert!(text.chars().count() <= TEXT + 1);
    }

    #[test]
    fn a_question_before_begin_is_refused() {
        let mut c = Conversation::new();
        let reply = c.receive(ask(vec![Method::Password], None), Instant::now());
        assert_eq!(reply, Some(FromPrompter::Cancel {}));
        assert!(c.finished());
    }

    /// The new recovery key is shown first; the check comes after "written
    /// down", and only then answers.
    #[test]
    fn the_recovery_check_follows_the_key() {
        let now = Instant::now();
        let mut c = begun(Purpose::Create);
        c.receive(
            ToPrompter::ShowRecoveryKey {
                key: Secret::new("ABCD-EFGH"),
                check: [2, 9],
                error: None,
            },
            now,
        );
        let groups = || [Secret::new("a"), Secret::new("b")];
        assert_eq!(c.act(Action::RecoveryCheck(groups()), now), None);
        assert_eq!(c.act(Action::RecoveryKeyWritten, now), None);
        assert!(matches!(
            c.screen,
            Screen::ShowRecoveryKey { checking: true, .. }
        ));
        assert_eq!(
            c.act(Action::RecoveryCheck(groups()), now),
            Some(FromPrompter::RecoveryCheck { groups: groups() })
        );
    }

    #[test]
    fn done_finishes_with_its_message() {
        let mut c = begun(Purpose::Unlock);
        c.receive(
            ToPrompter::Done {
                ok: true,
                message: Some("note".into()),
            },
            Instant::now(),
        );
        assert_eq!(
            c.screen,
            Screen::Finished {
                ok: true,
                message: Some("note".into())
            }
        );
        // Nothing more is taken once it is over.
        assert_eq!(
            c.receive(ask(vec![Method::Password], None), Instant::now()),
            None
        );
    }
}
