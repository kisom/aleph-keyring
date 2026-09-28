//! The prompter's screens, driven as a person would (egui_kittest), and a
//! snapshot of each in both themes (spec §9 "GUI").

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use aleph_gui::app::PromptApp;
use aleph_gui::link;
use aleph_gui::settings::{Settings, ThemeChoice};
use aleph_prompt_proto::{Caller, FromPrompter, Method, Purpose, Secret, ToPrompter};
use egui::Key;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

/// alephd's side of a conversation with a prompt window.
struct Daemon {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Daemon {
    fn say(&mut self, msg: &ToPrompter) {
        let mut line = serde_json::to_vec(msg).unwrap();
        line.push(b'\n');
        self.stream.write_all(&line).unwrap();
    }

    /// The next answer (failing after 5 s rather than hang).
    fn heard(&mut self) -> FromPrompter {
        self.stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("an answer");
        serde_json::from_str(&line).unwrap()
    }

    /// Nothing was sent (within a short wait).
    fn heard_nothing(&mut self) -> bool {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut line = String::new();
        let silent = self.reader.read_line(&mut line).is_err();
        self.stream.set_read_timeout(None).unwrap();
        silent
    }
}

fn window(theme: ThemeChoice) -> (Harness<'static, PromptApp>, Daemon) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let events = link::spawn_reader(ours.try_clone().unwrap(), || {}).unwrap();
    let settings = Settings {
        theme,
        scanlines: true,
    };
    // A fixed home: auto reads the Omarchy fixture from it.
    let home = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/home");
    let mut app = PromptApp::new(ours, events, settings, Some(home), true);
    // (Typed at once, as the tests do; `the_first_keys_after_a_screen_appears_are_ignored`
    // checks the guard.)
    app.input_guard = Duration::ZERO;
    let palette = app.ui.palette.clone();
    let harness = Harness::builder()
        .with_size(egui::Vec2::from(aleph_gui::screens::SIZE))
        .build_ui_state(|ui, app: &mut PromptApp| app.frame(ui), app);
    aleph_gui::theme::apply(&harness.ctx, &palette);
    let reader = BufReader::new(theirs.try_clone().unwrap());
    (
        harness,
        Daemon {
            stream: theirs,
            reader,
        },
    )
}

/// Deliver what alephd said (the reader thread is asynchronous).
fn settle(h: &mut Harness<'static, PromptApp>) {
    for _ in 0..40 {
        h.step();
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Focus a field and type into it (kittest types into the focused widget).
fn type_into(h: &mut Harness<'static, PromptApp>, label: &str, text: &str) {
    h.get_by_label(label).focus();
    frames(h);
    h.get_by_label(label).type_text(text);
    frames(h);
}

/// A few frames (some screens repaint on a timer: `run` would not settle).
fn frames(h: &mut Harness<'static, PromptApp>) {
    h.run_steps(4);
}

fn begin(d: &mut Daemon, purpose: Purpose, operation: &str) {
    d.say(&ToPrompter::Begin {
        purpose,
        operation: operation.into(),
        caller: Some(Caller {
            name: Some("secret-tool".into()),
            pid: Some(4242),
        }),
    });
}

fn ask(methods: Vec<Method>, error: Option<&str>, retry_after: Option<u64>) -> ToPrompter {
    ToPrompter::Ask {
        methods,
        error: error.map(Into::into),
        retry_after,
    }
}

#[test]
fn a_typed_password_and_enter_answer_the_question() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password], None, None));
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(Key::Enter);
    frames(&mut h);
    assert_eq!(
        d.heard(),
        FromPrompter::Password {
            password: Secret::new("hunter2")
        }
    );
    // The field is cleared once sent.
    assert!(h.state().ui.secret.is_empty());
}

#[test]
fn the_security_key_button_answers_fido2() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password, Method::Fido2], None, None));
    settle(&mut h);
    h.get_by_label("Use security key").click();
    frames(&mut h);
    assert_eq!(d.heard(), FromPrompter::Fido2 {});
}

/// Escape cancels, and the window closes.
#[test]
fn escape_cancels_and_closes() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Touch {
        key: "yubikey".into(),
    });
    settle(&mut h);
    h.key_press(Key::Escape);
    frames(&mut h);
    assert_eq!(d.heard(), FromPrompter::Cancel {});
    assert!(h.state().closed);
}

/// Enter gives the confirmation's default (no, unless alephd says yes).
#[test]
fn enter_gives_the_confirmation_default() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Reauth, "Delete the collection 'work'?");
    d.say(&ToPrompter::Confirm {
        text: "Delete the collection 'work' and all its items?".into(),
        default: false,
    });
    settle(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    assert_eq!(d.heard(), FromPrompter::Confirm { yes: false });
}

/// During a back-off the password is not sent, even with Enter.
#[test]
fn a_password_is_held_during_the_back_off() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(
        vec![Method::Password],
        Some("too many attempts"),
        Some(60),
    ));
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(Key::Enter);
    frames(&mut h);
    assert!(d.heard_nothing());
}

/// The recovery key is refused outside a recovery (spec §5), unanswered.
#[test]
fn a_recovery_key_question_outside_recovery_is_cancelled() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::RecoveryKey { error: None });
    settle(&mut h);
    assert_eq!(d.heard(), FromPrompter::Cancel {});
}

/// The new recovery key is shown, then two groups typed back.
#[test]
fn the_recovery_key_is_shown_then_checked() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Create, "Create the keyring");
    d.say(&ToPrompter::ShowRecoveryKey {
        key: Secret::new(KEY),
        check: [3, 11],
        error: None,
    });
    settle(&mut h);
    h.get_by_label("I have written it down").click();
    frames(&mut h);
    type_into(&mut h, "Group 3 of your recovery key", "CCCC");
    type_into(&mut h, "Group 11 of your recovery key", "LLLL");
    frames(&mut h);
    h.get_by_label("Continue").click();
    frames(&mut h);
    let got = d.heard();
    assert_eq!(
        got,
        FromPrompter::RecoveryCheck {
            groups: [Secret::new("CCCC"), Secret::new("LLLL")]
        }
    );
}

/// alephd ending the conversation closes the window; a message stays up
/// until read.
#[test]
fn done_closes_unless_there_is_a_message() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Done {
        ok: true,
        message: None,
    });
    settle(&mut h);
    assert!(h.state().closed);

    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Done {
        ok: false,
        message: Some("The keyring was unlocked meanwhile.".into()),
    });
    drop(d);
    settle(&mut h);
    assert!(!h.state().closed);
    h.get_by_label("Close").click();
    frames(&mut h);
    assert!(h.state().closed);
}

/// alephd going away (restarted, killed) closes the window.
#[test]
fn alephd_going_away_closes_the_window() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password], None, None));
    settle(&mut h);
    assert!(!h.state().closed);
    drop(d);
    settle(&mut h);
    assert!(h.state().closed);
}

/// After a wrong password the field is empty and has the focus again: the
/// next password is typed straight in.
#[test]
fn after_a_wrong_password_the_field_is_ready_again() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password], None, None));
    settle(&mut h);
    type_into(&mut h, "Login password", "wrong");
    h.key_press(Key::Enter);
    frames(&mut h);
    assert!(matches!(d.heard(), FromPrompter::Password { .. }));
    d.say(&ask(vec![Method::Password], Some("wrong password"), None));
    settle(&mut h);
    assert!(h.state().ui.secret.is_empty());
    // No click, no focus call: the field took the focus itself.
    h.get_by_label("Login password").type_text("right");
    frames(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    assert_eq!(
        d.heard(),
        FromPrompter::Password {
            password: Secret::new("right")
        }
    );
}

/// Keys arriving just as a screen appears (typed into another window)
/// are ignored: they never become an answer.
#[test]
fn the_first_keys_after_a_screen_appears_are_ignored() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    h.state_mut().input_guard = Duration::from_secs(60);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password], None, None));
    settle(&mut h);
    h.get_by_label("Login password").type_text("hunter2");
    frames(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    assert!(h.state().ui.secret.is_empty());
    assert!(d.heard_nothing());
}

/// The guard starts again when the window gets the keyboard (a prompt that
/// opened behind the lock screen, or unfocused): what was being typed for
/// another window is not taken as an answer.
#[test]
fn keys_arriving_with_the_focus_are_ignored() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    h.state_mut().input_guard = Duration::from_millis(300);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password], None, None));
    settle(&mut h);
    std::thread::sleep(Duration::from_millis(400));
    frames(&mut h);
    h.event(egui::Event::WindowFocused(true));
    h.get_by_label("Login password").type_text("hunter2");
    frames(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    assert!(h.state().ui.secret.is_empty());
    assert!(d.heard_nothing());
}

/// A message alephd sends that cannot be read (a version mismatch after an
/// upgrade) is prompter trouble: the window closes without answering, so
/// the prompt waits (a Cancel would dismiss it).
#[test]
fn an_unreadable_message_closes_without_answering() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.stream
        .write_all(b"{\"type\":\"from_the_future\"}\n")
        .unwrap();
    settle(&mut h);
    assert!(h.state().closed);
    assert!(d.heard_nothing());
}

/// However long an error (up to the 400 characters shown), the field and
/// the buttons stay on the window.
#[test]
fn a_long_error_never_pushes_the_buttons_off() {
    let (mut h, mut d) = window(ThemeChoice::Auto);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    let error = "W".repeat(1000);
    d.say(&ask(
        vec![Method::Password, Method::Fido2],
        Some(&error),
        None,
    ));
    settle(&mut h);
    let unlock = h.get_by_label("Unlock").rect();
    let field = h.get_by_label("Login password").rect();
    assert!(
        unlock.bottom() <= aleph_gui::screens::SIZE[1],
        "the buttons are off the window: {unlock:?}"
    );
    assert!(field.bottom() <= unlock.top(), "{field:?} {unlock:?}");
}

/// A note after a successful unlock (a pending rotation, say) goes sooner
/// than a failure's message: the window holds the keyboard while it is up.
#[test]
fn a_note_after_success_closes_sooner() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    h.state_mut().message_for = Duration::from_secs(60);
    h.state_mut().note_for = Duration::from_millis(100);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Done {
        ok: true,
        message: Some("a password change still needs the master key rotated".into()),
    });
    settle(&mut h);
    std::thread::sleep(Duration::from_millis(150));
    frames(&mut h);
    assert!(h.state().closed);
}

/// Enter in an empty PIN field leaves the keyboard on it: what is typed
/// next still lands there.
#[test]
fn enter_in_an_empty_pin_field_keeps_the_keyboard() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Fido2Pin {
        key: "yubikey".into(),
        error: None,
    });
    settle(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    h.get_by_label("PIN for yubikey").type_text("1234");
    frames(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    assert_eq!(
        d.heard(),
        FromPrompter::Pin {
            pin: Secret::new("1234")
        }
    );
}

/// A closing message closes itself: the window holds the keyboard while it
/// is open.
#[test]
fn a_closing_message_closes_itself() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    h.state_mut().message_for = Duration::from_millis(100);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Done {
        ok: false,
        message: Some("too many attempts".into()),
    });
    settle(&mut h);
    std::thread::sleep(Duration::from_millis(150));
    frames(&mut h);
    assert!(h.state().closed);
}

/// Enter during the back-off holds the password; once it ends, Enter sends
/// it (the field kept the keyboard).
#[test]
fn a_held_password_is_sent_once_the_back_off_ends() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(
        vec![Method::Password],
        Some("too many attempts"),
        Some(1),
    ));
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(Key::Enter);
    frames(&mut h);
    assert!(d.heard_nothing());
    std::thread::sleep(Duration::from_millis(1100));
    frames(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    assert_eq!(
        d.heard(),
        FromPrompter::Password {
            password: Secret::new("hunter2")
        }
    );
}

/// However wide a confirmation's text (a collection label is another
/// program's choice), it stays above the buttons: they can be read and
/// clicked, never drawn over.
#[test]
fn a_long_confirmation_never_covers_the_buttons() {
    let (mut h, mut d) = window(ThemeChoice::Auto);
    begin(&mut d, Purpose::Reauth, "Delete the collection?");
    d.say(&ToPrompter::Confirm {
        text: format!("Delete the collection '{}'?", "W".repeat(1000)),
        default: false,
    });
    settle(&mut h);
    let no = h.get_by_label("No").rect();
    let text = h.get_by_label_contains("WWWW").rect();
    assert!(
        no.bottom() <= aleph_gui::screens::SIZE[1],
        "the buttons are off the window: {no:?}"
    );
    assert!(
        text.bottom() <= no.top(),
        "the text {text:?} runs into the buttons {no:?}"
    );
}

const KEY: &str = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-LLLL-MMMM-NNNN-PPPP";

/// Every screen, in both themes.
#[test]
fn snapshots() {
    let screens: Vec<(&str, Purpose, Vec<ToPrompter>)> = vec![
        ("working", Purpose::Unlock, vec![]),
        (
            "ask_password",
            Purpose::Unlock,
            vec![ask(vec![Method::Password], None, None)],
        ),
        (
            "ask_both_error",
            Purpose::Unlock,
            vec![ask(
                vec![Method::Password, Method::Fido2],
                Some("wrong password"),
                None,
            )],
        ),
        (
            "ask_key",
            Purpose::Unlock,
            vec![ask(vec![Method::Fido2], None, None)],
        ),
        (
            "ask_back_off",
            Purpose::Unlock,
            vec![ask(
                vec![Method::Password, Method::Fido2],
                Some("too many attempts"),
                Some(30),
            )],
        ),
        (
            "old_password",
            Purpose::Unlock,
            vec![ToPrompter::OldPassword { error: None }],
        ),
        (
            "pin",
            Purpose::Unlock,
            vec![ToPrompter::Fido2Pin {
                key: "yubikey".into(),
                error: Some("wrong PIN (4 tries left)".into()),
            }],
        ),
        (
            "insert_key",
            Purpose::Unlock,
            vec![ToPrompter::InsertKey {
                key: "yubikey".into(),
            }],
        ),
        (
            "touch",
            Purpose::Unlock,
            vec![ToPrompter::Touch {
                key: "yubikey".into(),
            }],
        ),
        (
            "confirm",
            Purpose::Reauth,
            vec![ToPrompter::Confirm {
                text: "Delete the collection 'work' and all its items?".into(),
                default: false,
            }],
        ),
        (
            "recovery_key",
            Purpose::Recover,
            vec![ToPrompter::RecoveryKey { error: None }],
        ),
        (
            "show_recovery_key",
            Purpose::Create,
            vec![ToPrompter::ShowRecoveryKey {
                key: Secret::new(KEY),
                check: [3, 11],
                error: None,
            }],
        ),
        (
            "confirm_long_label",
            Purpose::Reauth,
            vec![ToPrompter::Confirm {
                text: format!(
                    "Delete the collection '{}' and all its items?",
                    "w".repeat(600)
                ),
                default: false,
            }],
        ),
        (
            "finished_message",
            Purpose::Unlock,
            vec![ToPrompter::Done {
                ok: false,
                message: Some("The keyring was unlocked meanwhile.".into()),
            }],
        ),
    ];
    let mut failures = Vec::new();
    for (theme, suffix) in [(ThemeChoice::Neon, "neon"), (ThemeChoice::Auto, "omarchy")] {
        for (name, purpose, msgs) in &screens {
            let (mut h, mut d) = window(theme);
            begin(
                &mut d,
                *purpose,
                match purpose {
                    Purpose::Unlock => "Unlock the keyring",
                    Purpose::Reauth => "Delete the collection 'work'?",
                    Purpose::Create => "Create the keyring",
                    Purpose::Recover => "Recover the keyring",
                },
            );
            for m in msgs {
                d.say(m);
            }
            settle(&mut h);
            if let Err(e) = h.try_snapshot(format!("{name}_{suffix}")) {
                failures.push(e.to_string());
            }
            // The key's second step: typing two groups back.
            if *name == "show_recovery_key" {
                h.get_by_label("I have written it down").click();
                frames(&mut h);
                if let Err(e) = h.try_snapshot(format!("recovery_check_{suffix}")) {
                    failures.push(e.to_string());
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
