# Custody Implementation Plan (Plan 4b)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the keyring with the recovery key (from a backup, the current vault, or its backup copy), fall back to `vault.aleph.bak`, accept a rolled-back or replaced file deliberately, and write backups that hold only the recovery slot.

**Architecture:**
- **Engine (`keyring/custody.rs`):** `recover`, `restore_from_bak`, `accept_rollback`, and `backup` on `Keyring`, each one conversation with the prompter. Every restore or acceptance writes past every generation this machine has recorded (core `advance_generation_past`), keeps the file it replaces, and records the vault as the one this machine expects.
- **Trust:** a `vault-id` file in the state directory; a vault with a different id at the path is not trusted until restored or accepted.
- **Prompt protocol:** the recovery key is its own question (`recovery_key`), refused by `Channel::ask` and asked only by the recovery conversation; `Confirm` carries the answer Enter gives.
- **Admin and CLI:** `Recover`, `RestoreBackup`, `RestoreFromBak`, `AcceptRollback`, and `Backup` on `io.aleph.Admin1`; backup and restore files travel as descriptors the CLI opened. `aleph backup [--force] <path>`, `aleph restore [--from-bak | --accept-rollback] [<path>]`.

**Tech Stack:** Rust 1.98, `zbus` 5 (descriptors as `OwnedFd`), `libc` (`O_NOFOLLOW`) in the CLI.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` revision 2 (§4 "File", "Generation and high-water mark"; §5 "Recovery key"; §7 `aleph backup`, `aleph restore`). Task 6 updates the spec with what this plan settled. Decisions: `DECISIONS.md` E7, E8 (the reviewed design), F1 (this plan's scope), and F2 (this document's pre-execution review); Task 6 adds F1 and F2.

**Plan series:** 1, 1b, 2, 3, 4a (done) → **4b custody (this plan)** → 4c setup (gnome-keyring import and export, switchover and `setup --revert`, PAM changes, the wizard, lockoutAuth, Omarchy's lock) → 5 `aleph-gui` → 6 packaging and CI.

**Base:** the executed Plan 4a (`feat/aleph-session`, or `master` once it lands there).

**Prerequisites:** as for Plan 4a.

## Decisions made while prototyping

Every task was prototyped, then replayed from this document on a fresh clone: red, then green, then clippy and fmt clean, with the final tree identical to the prototype. The properties below were each checked by reverting them (the "teeth" step of the owning task).

- **The split** (F1): custody depends on nothing in 4c, and 4c's emergency-revert docs depend on custody.
- **No lowering of the high-water mark, ever** (E7): a restored or accepted vault is written at `max(recorded, found) + 1`.
- **Proof** (E7, F2): recovering the vault this machine expects needs only its recovery key. Anything else that replaces the vault needs the expected vault's method (re-authentication, or opening it; a corrupt one whose slot opens counts) or, where the expected vault is missing, unreadable, or not the file there, the login password checked with PAM. A planted vault's own methods prove nothing, for `restore`, `--from-bak`, and `--accept-rollback` alike. Only a machine with no vault and none expected needs no proof.
- **The replaced file is kept** (`vault.aleph.replaced-<time>`, `.corrupt-<time>`), linked under that name before the write: a crash in between leaves the old vault in place. `.bak` is kept the same way before every custody write (F2). Names never collide (`-<n>`), and the copy fallback writes only new files.
- **An older backup of the same vault** asks first, naming both generations (Enter says no).
- **The expected vault id** is written at create, at restore and acceptance, and at the first unlock of a vault without one (never by setup).
- **A plain `restore`** on an unreadable vault falls back to `.bak`, and is refused while the vault is unlocked and trusted. `--from-bak` opens `.bak` with the normal methods.
- **Recovery** keeps only the recovery slot, enrolls one fresh method (the login password, PAM-checked, or a security key), rotates MK, and offers a new recovery key (Enter says yes); accepting a rollback defaults to no.
- **Backups** (E8) go to a descriptor the CLI opened (`O_NOFOLLOW`, new, `0600`; `--force` writes a temporary file and renames it), which the daemon checks is an empty regular file outside aleph's directories. The daemon never opens a path it was given, and reads a restore file only if it is a regular file, off the async runtime, at most 64 MiB.
- **Sleep:** a restore that finishes after the pre-sleep lock writes nothing.
- **Not in this plan:** everything in 4c; the GUI's "Recover…" (Plan 5).

## Global Constraints

- Rust stable 1.98, edition 2024; every crate `license = "Apache-2.0"`.
- The recovery key is asked for only in the recovery conversation (`Channel::ask` refuses `RecoveryKey`); it travels only in zeroizing types and is never logged.
- Nothing custody does deletes a vault file or lowers the high-water mark.
- **Exact names:** prompter messages `{"type":"recovery_key","error":...}` and replies `{"type":"recovery_key","key":...}`; `Confirm` gains `"default"` (absent means `false`); `Purpose::Recover`; files `vault.aleph.replaced-<unix time>`, `vault.aleph.corrupt-<unix time>`, `$XDG_STATE_HOME/aleph/vault-id`; Admin methods `Recover`, `RestoreBackup`, `RestoreFromBak`, `AcceptRollback`, `Backup`.
- `cargo fmt` default; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **A same-user process holding an old backup and its recovery key** (the threat E7 names) must not be able to swap it in by moving the vault away, planting a vault or `.bak` whose method it knows, or acting while the keyring is unlocked. → Task 4 `a_missing_vault_does_not_skip_the_proof`, `a_planted_vault_does_not_prove_the_right_to_replace_it`, `an_unlocked_keyring_is_replaced_only_after_reauthentication`, `a_planted_backup_copy_needs_the_login_password`, `a_planted_vault_is_not_accepted_with_its_own_password`, `replacing_a_vault_that_opens_needs_its_method`.
2. **A crash, a full disk, or a cancel at any point of a restore** must leave a good copy (the old vault, its `.bak`, or the new vault) on disk, never lower the mark, and never write into a kept file. → Task 3 `a_vault_kept_aside_survives_its_replacement`, `copies_kept_in_the_same_second_never_overwrite_each_other`; Task 4 `the_recovery_key_recovers_the_current_vault` and `the_backup_copy_replaces_an_unreadable_vault` (`.bak` kept), `a_wrong_recovery_key_changes_nothing`, `a_corrupt_vault_is_replaced_after_its_method_opens_its_slot`. An injected write failure is not tested: the kept links make the old files independent of the write.
3. **An older backup of the same vault** restored over a newer one must ask first, say what is lost, keep the newer file, and leave it detectable as rolled back afterwards. → Task 4 `an_older_backup_of_this_vault_asks_first_and_the_newer_file_stays_detectable`, `an_accepted_rollback_never_lowers_the_mark`, `a_different_vault_at_the_path_is_not_trusted`.
4. **A file that is not a backup, or a hostile target:** garbage, a truncated backup, a pipe given as a restore file; an existing file, a symlink, a hard link to the vault, or a path inside `~/.local/share/aleph` given as a backup target. Each is refused and changes nothing. → Task 4 `a_file_that_is_not_a_backup_changes_nothing`; Task 5 `only_a_regular_file_is_read_as_a_backup`, `a_backup_target_must_be_empty_and_outside_aleph`, `backup_and_restore_through_the_cli` (existing file left unchanged, symlink not followed, a target inside aleph refused).
5. **Clients after a restore** must see the restored items and not the ones written after the backup. → Task 5 `backup_and_restore_through_the_cli` (`aleph get` through the Secret Service after the restore).

## File Structure

```
crates/aleph-core/src/vault.rs               advance_generation_past
crates/aleph-prompt-proto/src/lib.rs         Purpose::Recover, ToPrompter::RecoveryKey, FromPrompter::RecoveryKey, Confirm.default
crates/aleph-daemon/src/prompt.rs            Channel::ask refuses RecoveryKey; ask_recovery_key
crates/aleph-daemon/src/paths.rs             bak(), expected_vault()
crates/aleph-daemon/src/store.rs             recorded, read_bak, keep_aside, expected_vault_id, expect_vault_id
crates/aleph-daemon/src/keyring.rs           NewMethod, choose_new_method, add_method; trust checks the expected id
crates/aleph-daemon/src/keyring/custody.rs   recover, restore_from_bak, accept_rollback, backup
crates/aleph-daemon/src/admin.rs             Recover, RestoreBackup, RestoreFromBak, AcceptRollback, Backup
crates/aleph-daemon/src/secret/service.rs    Confirm default
crates/aleph-daemon/tests/{custody,keyring,launcher}.rs
crates/aleph-cli/src/{client,prompter,main}.rs  Args::File, recovery-key and default answers, backup and restore commands
crates/aleph-cli/tests/cli.rs
docs: spec (§4, §5, §6, §7), testing.md, README.md, DECISIONS.md
```

---

### Task 1: advancing the generation past a recorded one

**Interfaces:**
- Produces: `aleph_core::UnlockedVault::advance_generation_past(&self, u64)` (the next write's generation is at least one more; never lowers it)

- [ ] **Step 1: Write the failing tests**

Apply this patch with `git apply` (save it as `/tmp/t1-tests.patch`):

```diff
--- a/crates/aleph-core/tests/vault.rs
+++ b/crates/aleph-core/tests/vault.rs
@@ -456,6 +456,20 @@
         v.remove_keyslot_keeping_mk(Uuid::new_v4()),
         Err(Error::NoSuchKeyslot(_))
     ));
+}
+
+/// A restored or accepted vault is written past every generation this
+/// machine has seen: the next write is one more than the highest given,
+/// and advancing never lowers the generation.
+#[test]
+fn the_generation_can_be_advanced_but_never_lowered() {
+    let (v, ..) = sample();
+    let dir = tempfile::tempdir().unwrap();
+    let path = dir.path().join("vault.aleph");
+    v.advance_generation_past(41);
+    assert_eq!(v.write(&path).unwrap().generation, 42);
+    v.advance_generation_past(5);
+    assert_eq!(v.write(&path).unwrap().generation, 43);
 }
 
 #[test]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-core --test vault`
Expected: the build fails: `advance_generation_past` does not exist yet.

- [ ] **Step 3: Implement**

Apply this patch with `git apply` (save it as `/tmp/t1-impl.patch`):

```diff
--- a/crates/aleph-core/src/vault.rs
+++ b/crates/aleph-core/src/vault.rs
@@ -363,6 +363,14 @@
 
     pub fn unknown_keyslots(&self) -> impl Iterator<Item = &UnknownSlot> {
         unknown(&self.entries)
+    }
+
+    /// Make the next write's generation at least `generation + 1`: for a
+    /// restored or accepted file, written past every generation this
+    /// machine has seen, so every older copy stays detectable. It never
+    /// lowers the generation.
+    pub fn advance_generation_past(&self, generation: u64) {
+        self.generation.fetch_max(generation, Ordering::SeqCst);
     }
 
     /// Identity of the last-read or last-written generation.
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 59 passed | ok. 1 passed | ok. 29 passed | ok. 11 passed | ok. 1 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **the generation is never lowered** (`crates/aleph-core/src/vault.rs`), test `cargo test -p aleph-core --test vault never_lowered`:

  replace

  ```rust
  u64) {
  self.generation.fetch_max(generation, Ordering::SeqCst);
  ```

  with

  ```rust
  u64) {
  self.generation.store(generation, Ordering::SeqCst);
  ```


- [ ] **Step 6: Commit**

```bash
git add crates/aleph-core
git commit -m "feat(core): advance the generation past a recorded one" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: the recovery-key question and confirmation defaults

**Interfaces:**
- Produces:
  - `aleph_prompt_proto::{Purpose::Recover, ToPrompter::RecoveryKey { error: Option<String> }, FromPrompter::RecoveryKey { key: Secret }}`; `ToPrompter::Confirm { text, default: bool }` (`#[serde(default)]`)
  - `Channel::ask` refuses `ToPrompter::RecoveryKey` (`Error::Prompt`); the private `Channel::ask_any` asks anything
  - CLI prompter: answers `RecoveryKey`; `[Y/n]` or `[y/N]` from `default`; `is_yes(&str, bool) -> bool`

- [ ] **Step 1: Write the failing tests**

Apply this patch with `git apply` (save it as `/tmp/t2-tests.patch`):

```diff
--- a/crates/aleph-prompt-proto/src/lib.rs
+++ b/crates/aleph-prompt-proto/src/lib.rs
@@ -171,6 +171,21 @@
         assert!(!format!("{p:?}").contains("hunter2"));
     }
 
+    /// The recovery-key question and answer: fixed wire forms, the key
+    /// never printed.
+    #[test]
+    fn the_recovery_key_travels_as_a_secret() {
+        let q = ToPrompter::RecoveryKey { error: None };
+        assert!(q.needs_reply());
+        assert_eq!(
+            serde_json::to_string(&q).unwrap(),
+            r#"{"type":"recovery_key","error":null}"#
+        );
+        let a: FromPrompter =
+            serde_json::from_str(r#"{"type":"recovery_key","key":"ABCD-EFGH"}"#).unwrap();
+        assert!(!format!("{a:?}").contains("ABCD"));
+    }
+
     /// The previous-password question expects an answer, and its wire form
     /// is fixed (prompters in other programs match on it).
     #[test]
--- a/crates/aleph-daemon/src/prompt.rs
+++ b/crates/aleph-daemon/src/prompt.rs
@@ -321,7 +321,12 @@
                 .write_all(b"{\"type\":\"confirm\",\"yes\":true}\n")
                 .unwrap();
         });
-        let reply = ch.ask(&ToPrompter::Confirm { text: "ok?".into() }).unwrap();
+        let reply = ch
+            .ask(&ToPrompter::Confirm {
+                text: "ok?".into(),
+                default: false,
+            })
+            .unwrap();
         assert_eq!(reply, FromPrompter::Confirm { yes: true });
         peer.join().unwrap();
     }
@@ -336,7 +341,10 @@
                 b"{\"type\":\"confirm\",\"yes\":true}\n{\"type\":\"confirm\",\"yes\":false}\n",
             )
             .unwrap();
-        let q = ToPrompter::Confirm { text: "?".into() };
+        let q = ToPrompter::Confirm {
+            text: "?".into(),
+            default: false,
+        };
         assert_eq!(ch.ask(&q).unwrap(), FromPrompter::Confirm { yes: true });
         assert_eq!(ch.ask(&q).unwrap(), FromPrompter::Confirm { yes: false });
     }
@@ -350,11 +358,26 @@
             theirs
         });
         let err = ch
-            .ask(&ToPrompter::Confirm { text: "?".into() })
+            .ask(&ToPrompter::Confirm {
+                text: "?".into(),
+                default: false,
+            })
             .unwrap_err()
             .to_string();
         assert!(err.contains("too long"), "{err}");
         drop(writer.join());
+    }
+
+    /// Only the recovery conversation can ask for the recovery key.
+    #[test]
+    fn the_recovery_key_is_not_asked_by_ordinary_questions() {
+        let (ours, _theirs) = UnixStream::pair().unwrap();
+        let mut ch = Channel::new(ours, Duration::from_secs(5)).unwrap();
+        let err = ch
+            .ask(&ToPrompter::RecoveryKey { error: None })
+            .unwrap_err()
+            .to_string();
+        assert!(err.contains("only when recovering"), "{err}");
     }
 
     /// A malformed answer is refused without quoting it: the error is
@@ -386,7 +409,13 @@
         let text = "x".repeat(8 * 1024);
         let started = Instant::now();
         // Fill the socket buffer; a write then fails instead of blocking.
-        while ch.send(&ToPrompter::Confirm { text: text.clone() }).is_ok() {
+        while ch
+            .send(&ToPrompter::Confirm {
+                text: text.clone(),
+                default: false,
+            })
+            .is_ok()
+        {
             assert!(
                 started.elapsed() < Duration::from_secs(10),
                 "never timed out"
@@ -408,7 +437,10 @@
         assert_eq!(reply, FromPrompter::Fido2 {});
         // Out of replies: the script cancels.
         assert!(matches!(
-            ch.ask(&ToPrompter::Confirm { text: "ok?".into() }),
+            ch.ask(&ToPrompter::Confirm {
+                text: "ok?".into(),
+                default: false
+            }),
             Err(Error::Cancelled)
         ));
     }
@@ -419,7 +451,7 @@
         let mut ch = Channel::new(ours, Duration::from_millis(50)).unwrap();
         let t = Instant::now();
         assert!(matches!(
-            ch.ask(&ToPrompter::Confirm { text: "?".into() }),
+            ch.ask(&ToPrompter::Confirm { text: "?".into(), default: false }),
             Err(Error::Prompt(m)) if m.contains("timed out")
         ));
         assert!(t.elapsed() < Duration::from_secs(2));
@@ -427,7 +459,7 @@
         theirs.write_all(&vec![b'x'; MAX_LINE + 10]).unwrap();
         theirs.write_all(b"\n").unwrap();
         assert!(matches!(
-            ch.ask(&ToPrompter::Confirm { text: "?".into() }),
+            ch.ask(&ToPrompter::Confirm { text: "?".into(), default: false }),
             Err(Error::Prompt(m)) if m.contains("too long")
         ));
     }
--- a/crates/aleph-daemon/tests/launcher.rs
+++ b/crates/aleph-daemon/tests/launcher.rs
@@ -31,7 +31,10 @@
     };
     let mut chan = launcher.launch().unwrap();
     let reply = chan
-        .ask(&ToPrompter::Confirm { text: "ok?".into() })
+        .ask(&ToPrompter::Confirm {
+            text: "ok?".into(),
+            default: false,
+        })
         .unwrap();
     assert_eq!(reply, FromPrompter::Confirm { yes: true });
 }
--- a/crates/aleph-daemon/tests/keyring.rs
+++ b/crates/aleph-daemon/tests/keyring.rs
@@ -903,10 +903,9 @@
     ));
     assert_eq!(k.status().unwrap().keyslots, before);
     assert!(
-        decline
-            .sent()
-            .iter()
-            .any(|m| matches!(m, ToPrompter::Confirm { text } if text.contains("security key")))
+        decline.sent().iter().any(
+            |m| matches!(m, ToPrompter::Confirm { text, .. } if text.contains("security key"))
+        )
     );
     // Accept: both FIDO2 slots are gone; the TPM slot still works.
     let accept = Interactive::new(vec![
@@ -1242,7 +1241,7 @@
         .sent()
         .into_iter()
         .find_map(|m| match m {
-            ToPrompter::Confirm { text } => Some(text),
+            ToPrompter::Confirm { text, .. } => Some(text),
             _ => None,
         })
         .unwrap();
@@ -1490,7 +1489,7 @@
         .sent()
         .iter()
         .find_map(|m| match m {
-            ToPrompter::Confirm { text } => Some(text.clone()),
+            ToPrompter::Confirm { text, .. } => Some(text.clone()),
             _ => None,
         })
         .unwrap();
--- a/crates/aleph-cli/src/prompter.rs
+++ b/crates/aleph-cli/src/prompter.rs
@@ -201,3 +201,17 @@
         ToPrompter::Done { .. } => None,
     })
 }
+
+#[cfg(test)]
+mod tests {
+    use super::is_yes;
+
+    #[test]
+    fn enter_takes_the_default() {
+        assert!(is_yes("", true));
+        assert!(!is_yes("  ", false));
+        assert!(is_yes("y", false));
+        assert!(!is_yes("n", true));
+        assert!(!is_yes("maybe", true));
+    }
+}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-prompt-proto -p aleph-daemon -p aleph-cli`
Expected: the build fails: `ToPrompter::RecoveryKey`, `Confirm`'s `default`, and `is_yes` do not exist yet.

- [ ] **Step 3: Implement**

Apply this patch with `git apply` (save it as `/tmp/t2-impl.patch`):

```diff
--- a/crates/aleph-prompt-proto/src/lib.rs
+++ b/crates/aleph-prompt-proto/src/lib.rs
@@ -48,6 +48,9 @@
     Reauth,
     /// Create the vault.
     Create,
+    /// Recover the vault with the recovery key (`aleph restore`, the GUI's
+    /// "Recover…"): the only conversation that asks for it.
+    Recover,
 }
 
 #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
@@ -105,6 +108,16 @@
     /// Reply `Confirm`.
     Confirm {
         text: String,
+        /// The answer Enter gives (the GUI's focused button): yes only
+        /// where declining is the riskier choice.
+        #[serde(default)]
+        default: bool,
+    },
+    /// The recovery key, in a recovery conversation only (reply
+    /// `RecoveryKey`). Keeping the root credential off routine prompts
+    /// makes fake prompts less useful for phishing (spec §5).
+    RecoveryKey {
+        error: Option<String>,
     },
     /// Show the new recovery key once; reply `RecoveryCheck` with the
     /// groups at the 1-based positions in `check`.
@@ -125,6 +138,7 @@
             self,
             Self::Ask { .. }
                 | Self::OldPassword { .. }
+                | Self::RecoveryKey { .. }
                 | Self::Fido2Pin { .. }
                 | Self::Confirm { .. }
                 | Self::ShowRecoveryKey { .. }
@@ -140,6 +154,7 @@
     Pin { pin: Secret },
     Confirm { yes: bool },
     RecoveryCheck { groups: [Secret; 2] },
+    RecoveryKey { key: Secret },
     Cancel {},
 }
 
--- a/crates/aleph-daemon/src/prompt.rs
+++ b/crates/aleph-daemon/src/prompt.rs
@@ -69,9 +69,19 @@
     }
 
     /// Send a message that needs a reply and wait for it (up to the
-    /// timeout). `Cancel` becomes `Error::Cancelled`.
+    /// timeout). `Cancel` becomes `Error::Cancelled`. Never the recovery-key
+    /// question: only the recovery conversation asks it.
     pub fn ask(&mut self, msg: &ToPrompter) -> Result<FromPrompter> {
         debug_assert!(msg.needs_reply());
+        if matches!(msg, ToPrompter::RecoveryKey { .. }) {
+            return Err(Error::Prompt(
+                "the recovery key is asked for only when recovering".into(),
+            ));
+        }
+        self.ask_any(msg)
+    }
+
+    fn ask_any(&mut self, msg: &ToPrompter) -> Result<FromPrompter> {
         self.send(msg)?;
         match self.recv(Some(self.timeout))? {
             Some(FromPrompter::Cancel {}) => Err(Error::Cancelled),
--- a/crates/aleph-daemon/src/secret/service.rs
+++ b/crates/aleph-daemon/src/secret/service.rs
@@ -776,7 +776,12 @@
             operation: text.into(),
             caller,
         })
-        .and_then(|()| chan.ask(&ToPrompter::Confirm { text: text.into() }))
+        .and_then(|()| {
+            chan.ask(&ToPrompter::Confirm {
+                text: text.into(),
+                default: false,
+            })
+        })
         .is_ok_and(|r| r == FromPrompter::Confirm { yes: true });
     chan.done(yes, None);
     yes
--- a/crates/aleph-daemon/src/keyring.rs
+++ b/crates/aleph-daemon/src/keyring.rs
@@ -1092,6 +1092,7 @@
                     "These keyslots cannot be kept and will be removed: {}. Continue?",
                     names.join(", ")
                 ),
+                default: false,
             })?;
             if reply != (FromPrompter::Confirm { yes: true }) {
                 return Err(Error::Cancelled);
--- a/crates/aleph-cli/src/prompter.rs
+++ b/crates/aleph-cli/src/prompter.rs
@@ -50,9 +50,18 @@
         Ok(Secret::new(secret))
     }
 
-    fn yes(&mut self, question: &str) -> std::io::Result<bool> {
-        let answer = self.line(&format!("{question} [y/N] "))?;
-        Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
+    fn yes(&mut self, question: &str, default: bool) -> std::io::Result<bool> {
+        let hint = if default { "[Y/n]" } else { "[y/N]" };
+        let answer = self.line(&format!("{question} {hint} "))?;
+        Ok(is_yes(&answer, default))
+    }
+}
+
+/// A yes/no answer: empty takes `default`, anything but yes is no.
+fn is_yes(answer: &str, default: bool) -> bool {
+    match answer.trim() {
+        "" => default,
+        a => matches!(a, "y" | "Y" | "yes"),
     }
 }
 
@@ -114,6 +123,7 @@
                 Purpose::Unlock => "",
                 Purpose::Reauth => " (confirm it is you)",
                 Purpose::Create => "",
+                Purpose::Recover => " (with the recovery key)",
             };
             eprintln!("aleph: {operation}{why}");
             None
@@ -158,6 +168,14 @@
                 password: term.secret("Previous login password: ")?,
             })
         }
+        ToPrompter::RecoveryKey { error } => {
+            if let Some(e) = error {
+                eprintln!("aleph: {e}");
+            }
+            Some(FromPrompter::RecoveryKey {
+                key: term.secret("Recovery key (14 groups of 4): ")?,
+            })
+        }
         ToPrompter::Fido2Pin { key, error } => {
             if let Some(e) = error {
                 eprintln!("aleph: {e}");
@@ -176,8 +194,8 @@
             eprintln!("aleph: touch {key}");
             None
         }
-        ToPrompter::Confirm { text } => Some(FromPrompter::Confirm {
-            yes: term.yes(&text)?,
+        ToPrompter::Confirm { text, default } => Some(FromPrompter::Confirm {
+            yes: term.yes(&text, default)?,
         }),
         ToPrompter::ShowRecoveryKey { key, check, error } => {
             if let Some(e) = error {
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-prompt-proto -p aleph-daemon -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 1 passed | ok. 8 passed | ok. 30 passed | ok. 3 passed | ok. 51 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed | ok. 3 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **the recovery key is asked only when recovering** (`crates/aleph-daemon/src/prompt.rs`), test `cargo test -p aleph-daemon --lib the_recovery_key_is_not_asked`: replace `if matches!(msg, ToPrompter::RecoveryKey { .. }) {` with `if false {`.
- **Enter takes the default** (`crates/aleph-cli/src/prompter.rs`), test `cargo test -p aleph-cli --bin aleph enter_takes_the_default`: replace `"" => default,` with `"" => false,`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-prompt-proto crates/aleph-daemon crates/aleph-cli
git commit -m "feat(prompt): the recovery-key question and confirmation defaults" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: custody files in the store

**Interfaces:**
- Produces: `Paths::{bak(), expected_vault()}`; `Store::{recorded(Uuid) -> Result<Option<Mark>>, read_bak() -> Result<LockedVault>, keep_aside(&str) -> Result<PathBuf>, keep_bak_aside() -> Result<Option<PathBuf>>, expected_vault_id() -> Option<Uuid>, expect_vault_id(Uuid) -> Result<()>}`

- [ ] **Step 1: Write the failing tests**

Apply this patch with `git apply` (save it as `/tmp/t3-tests.patch`):

```diff
--- a/crates/aleph-daemon/src/store.rs
+++ b/crates/aleph-daemon/src/store.rs
@@ -140,6 +140,64 @@
         assert_eq!(mode(&paths.data_dir), 0o700);
     }
 
+    /// A vault about to be replaced is kept under another name first, and
+    /// stays in place until the replacement's rename (a crash before it
+    /// leaves the old vault); the expected vault id is remembered.
+    #[test]
+    fn a_vault_kept_aside_survives_its_replacement() {
+        let dir = tempfile::tempdir().unwrap();
+        let paths = Paths::under(dir.path());
+        let store = Store::open(&paths).unwrap();
+        std::fs::write(paths.vault(), b"old vault").unwrap();
+        let kept = store.keep_aside("replaced").unwrap();
+        assert!(store.exists());
+        let tmp = paths.data_dir.join("new");
+        std::fs::write(&tmp, b"new vault").unwrap();
+        std::fs::rename(&tmp, paths.vault()).unwrap();
+        assert_eq!(std::fs::read(&kept).unwrap(), b"old vault");
+        assert!(
+            kept.file_name()
+                .unwrap()
+                .to_str()
+                .unwrap()
+                .starts_with("vault.aleph.replaced-")
+        );
+        assert_eq!(store.expected_vault_id(), None);
+        let id = Uuid::new_v4();
+        store.expect_vault_id(id).unwrap();
+        assert_eq!(store.expected_vault_id(), Some(id));
+        assert!(matches!(store.read_bak(), Err(Error::Invalid(_))));
+    }
+
+    /// Two copies kept in the same second get different names: the second
+    /// never writes into the first (which is the old vault's own file).
+    #[test]
+    fn copies_kept_in_the_same_second_never_overwrite_each_other() {
+        let dir = tempfile::tempdir().unwrap();
+        let paths = Paths::under(dir.path());
+        let store = Store::open(&paths).unwrap();
+        std::fs::write(paths.vault(), b"first").unwrap();
+        let a = store.keep_aside("replaced").unwrap();
+        let tmp = paths.data_dir.join("new");
+        std::fs::write(&tmp, b"second").unwrap();
+        std::fs::rename(&tmp, paths.vault()).unwrap();
+        let b = store.keep_aside("replaced").unwrap();
+        assert_ne!(a, b);
+        assert_eq!(std::fs::read(&a).unwrap(), b"first");
+        assert_eq!(std::fs::read(&b).unwrap(), b"second");
+        assert!(store.keep_bak_aside().unwrap().is_none());
+        std::fs::write(paths.bak(), b"bak").unwrap();
+        let c = store.keep_bak_aside().unwrap().unwrap();
+        assert_eq!(std::fs::read(&c).unwrap(), b"bak");
+        assert!(
+            c.file_name()
+                .unwrap()
+                .to_str()
+                .unwrap()
+                .starts_with("vault.aleph.bak-")
+        );
+    }
+
     #[test]
     fn a_missing_vault_is_no_vault() {
         let dir = tempfile::tempdir().unwrap();
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon --lib store`
Expected: the build fails: `keep_aside`, `keep_bak_aside`, `expect_vault_id`, `expected_vault_id`, and `read_bak` do not exist yet.

- [ ] **Step 3: Implement**

Apply this patch with `git apply` (save it as `/tmp/t3-impl.patch`):

```diff
--- a/crates/aleph-daemon/src/store.rs
+++ b/crates/aleph-daemon/src/store.rs
@@ -10,9 +10,10 @@
 
 use std::fs::{File, OpenOptions, TryLockError};
 use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
-use std::path::Path;
+use std::path::{Path, PathBuf};
 
 use aleph_core::{HighWater, LockedVault, Mark, Standing, UnlockedVault};
+use uuid::Uuid;
 
 use crate::error::{Error, Result};
 use crate::paths::Paths;
@@ -76,6 +77,95 @@
 
     pub fn write(&self, vault: &UnlockedVault) -> Result<Mark> {
         Ok(vault.write_recorded(&self.paths.vault(), &self.highwater)?)
+    }
+
+    /// What this machine last recorded for `vault_id`.
+    pub fn recorded(&self, vault_id: Uuid) -> Result<Option<Mark>> {
+        Ok(self.highwater.load(vault_id)?)
+    }
+
+    /// The backup copy every write keeps (`vault.aleph.bak`).
+    pub fn read_bak(&self) -> Result<LockedVault> {
+        match LockedVault::read(&self.paths.bak()) {
+            Err(aleph_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Err(
+                Error::Invalid("there is no backup copy (vault.aleph.bak)".into()),
+            ),
+            other => Ok(other?),
+        }
+    }
+
+    /// Keep the vault file also as `vault.aleph.<what>-<unix time>`, before
+    /// a write replaces it: a hard link (a copy where links fail), so the
+    /// vault stays in place until the replacement's rename, and a crash in
+    /// between leaves it. Returns the kept name.
+    pub fn keep_aside(&self, what: &str) -> Result<PathBuf> {
+        self.keep(&self.paths.vault(), what)
+    }
+
+    /// Keep `vault.aleph.bak` as well (`vault.aleph.bak-<unix time>`), if
+    /// there is one: a custody write replaces it, and it may be the only
+    /// good copy.
+    pub fn keep_bak_aside(&self) -> Result<Option<PathBuf>> {
+        let bak = self.paths.bak();
+        if std::fs::symlink_metadata(&bak).is_err() {
+            return Ok(None);
+        }
+        Ok(Some(self.keep(&bak, "bak")?))
+    }
+
+    /// Keep `from` as `vault.aleph.<what>-<unix time>[-<n>]`, never over an
+    /// existing name: a hard link, or a synced copy where links fail.
+    fn keep(&self, from: &Path, what: &str) -> Result<PathBuf> {
+        use std::io::Write;
+        let secs = std::time::SystemTime::now()
+            .duration_since(std::time::UNIX_EPOCH)
+            .map(|d| d.as_secs())
+            .unwrap_or(0);
+        for n in 0..1000 {
+            let name = match n {
+                0 => format!("vault.aleph.{what}-{secs}"),
+                n => format!("vault.aleph.{what}-{secs}-{n}"),
+            };
+            let to = self.paths.data_dir.join(name);
+            match std::fs::hard_link(from, &to) {
+                Ok(()) => return Ok(to),
+                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
+                Err(_) => {}
+            }
+            let bytes = std::fs::read(from)?;
+            let mut file = match OpenOptions::new()
+                .write(true)
+                .create_new(true)
+                .mode(0o600)
+                .open(&to)
+            {
+                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
+                other => other?,
+            };
+            file.write_all(&bytes)?;
+            file.sync_all()?;
+            return Ok(to);
+        }
+        Err(Error::Invalid("too many kept copies of the vault".into()))
+    }
+
+    /// The vault this machine expects at the path, if one was recorded.
+    pub fn expected_vault_id(&self) -> Option<Uuid> {
+        std::fs::read_to_string(self.paths.expected_vault())
+            .ok()
+            .and_then(|s| Uuid::try_parse(s.trim()).ok())
+    }
+
+    /// Record the vault this machine expects at the path.
+    pub fn expect_vault_id(&self, id: Uuid) -> Result<()> {
+        let path = self.paths.expected_vault();
+        if let Some(dir) = path.parent() {
+            std::fs::create_dir_all(dir)?;
+        }
+        let tmp = path.with_extension("tmp");
+        std::fs::write(&tmp, id.to_string())?;
+        std::fs::rename(&tmp, &path)?;
+        Ok(())
     }
 }
 
--- a/crates/aleph-daemon/src/paths.rs
+++ b/crates/aleph-daemon/src/paths.rs
@@ -71,6 +71,17 @@
         self.state_dir.join("slots.json")
     }
 
+    /// The previous version of the vault, kept by every write (§4).
+    pub fn bak(&self) -> PathBuf {
+        self.data_dir.join("vault.aleph.bak")
+    }
+
+    /// The id of the vault this machine expects at the path (recorded at
+    /// create and restore; a different vault there is not trusted).
+    pub fn expected_vault(&self) -> PathBuf {
+        self.state_dir.join("vault-id")
+    }
+
     /// Where `pam_aleph` hands over the login password (§6).
     pub fn pam_socket(&self) -> PathBuf {
         self.runtime_dir.join("pam.sock")
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon --lib && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 32 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **copies kept in the same second never overwrite** (`crates/aleph-daemon/src/store.rs`), test `cargo test -p aleph-daemon --lib copies_kept_in_the_same_second`:

  replace

  ```rust
  Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
  Err(_) => {}
  ```

  with

  ```rust
  Err(e) if false => continue,
  Err(_) => {}
  ```


  replace

  ```rust
  .create_new(true)
  .mode(0o600)
  ```

  with

  ```rust
  .create(true)
  .truncate(true)
  .mode(0o600)
  ```

- **a kept file stays until the replacement** (`crates/aleph-daemon/src/store.rs`), test `cargo test -p aleph-daemon --lib a_vault_kept_aside_survives`: replace `match std::fs::hard_link(from, &to) {` with `match std::fs::rename(from, &to) {`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-daemon
git commit -m "feat(daemon): custody files in the store" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: custody in the engine

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `Keyring::{recover(&mut Channel, Option<&[u8]>) -> Result<()>, restore_from_bak(&mut Channel) -> Result<()>, accept_rollback(&mut Channel) -> Result<()>, backup(&mut Channel, impl FnOnce(&[u8]) -> Result<()>) -> Result<()>}`; `Channel::ask_recovery_key(Option<String>) -> Result<Secret>` (`pub(crate)`)

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-daemon/tests/custody.rs`:

```rust
//! Custody: recovery with the recovery key, restoring a backup, the backup
//! copy, accepting a rollback, and writing backups (keyring on swtpm).

use aleph_daemon::testing::*;

/// Create the vault with the login password and return its recovery key
/// (the scripted prompter was shown it).
fn create_capturing_key(k: &Keyring) -> String {
    let p = Interactive::new(vec![password(PW)]);
    k.create(&mut p.channel(), Method::Password).unwrap();
    p.sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::ShowRecoveryKey { key, .. } => Some(key.expose().to_string()),
            _ => None,
        })
        .unwrap()
}

/// A vault someone else made (its only method a login password this
/// machine's PAM does not accept): the file, its recovery key, and a backup.
fn foreign_vault() -> (Vec<u8>, String, Vec<u8>) {
    let there = env();
    let k = keyring_with(
        &there,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == "attacker")),
    );
    let p = Interactive::new(vec![password("attacker")]);
    k.create(&mut p.channel(), Method::Password).unwrap();
    let key = p
        .sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::ShowRecoveryKey { key, .. } => Some(key.expose().to_string()),
            _ => None,
        })
        .unwrap();
    let mut backup = Vec::new();
    k.backup(
        &mut Interactive::new(vec![password("attacker")]).channel(),
        |b| {
            backup = b.to_vec();
            Ok(())
        },
    )
    .unwrap();
    (std::fs::read(there.paths.vault()).unwrap(), key, backup)
}

/// This machine's keyring (TPM and login password), locked, with the
/// attacker's own security key plugged in.
fn victim(env: &Env) -> Keyring {
    let k = keyring(env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    create_capturing_key(&k);
    k.lock();
    k
}

/// What an attacker holding a backup and its recovery key answers: the key,
/// then its own security key as the new method.
fn attacker_answers(key: &str) -> Vec<FromPrompter> {
    vec![recovery(key), FromPrompter::Fido2 {}, pin(PIN), no()]
}

fn recovery(key: &str) -> FromPrompter {
    FromPrompter::RecoveryKey {
        key: Secret::new(key),
    }
}

fn yes() -> FromPrompter {
    FromPrompter::Confirm { yes: true }
}

fn no() -> FromPrompter {
    FromPrompter::Confirm { yes: false }
}

fn kinds(k: &Keyring) -> Vec<String> {
    k.status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect()
}

/// Files in the data directory whose names start with `prefix`.
fn kept(env: &Env, prefix: &str) -> usize {
    std::fs::read_dir(&env.paths.data_dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(prefix)
        })
        .count()
}

/// A backup of `k` (unlocked), after re-authentication with the password.
fn backup_of(k: &Keyring) -> Vec<u8> {
    let mut bytes = Vec::new();
    k.backup(&mut Interactive::new(vec![password(PW)]).channel(), |b| {
        bytes = b.to_vec();
        Ok(())
    })
    .unwrap();
    bytes
}

fn write_item(k: &Keyring, label: &str) {
    k.modify(|b| {
        b.collections[0].upsert(
            aleph_core::Item::new(
                label,
                [("id".to_string(), label.to_string())].into(),
                aleph_core::SecretBytes::new(b"s".to_vec()),
                "text/plain",
            ),
            false,
        );
        Ok(())
    })
    .unwrap();
}

/// The login password forgotten (or the TPM slot unusable): the recovery
/// key opens the vault, every other slot is replaced by a fresh unlock
/// method, and the replaced file is kept.
#[test]
fn the_recovery_key_recovers_the_current_vault() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    let key = create_capturing_key(&k);
    write_item(&k, "kept");
    let before = k.status().unwrap().keyslots;
    k.lock();
    login.set("new");
    let p = Interactive::new(vec![recovery(&key), yes(), password("new"), no()]);
    k.recover(&mut p.channel(), None).unwrap();
    // Enter keeps the old slots (the question is a warning) and takes the
    // new recovery key (E7).
    let defaults: Vec<bool> = p
        .sent()
        .into_iter()
        .filter_map(|m| match m {
            ToPrompter::Confirm { default, .. } => Some(default),
            _ => None,
        })
        .collect();
    assert_eq!(defaults, [false, true]);
    assert_eq!(kinds(&k), ["recovery", "tpm"]);
    // A fresh TPM slot (the recovery slot keeps its id).
    let tpm = |slots: &[aleph_daemon::keyring::SlotInfo]| {
        slots.iter().find(|s| s.kind == "tpm").unwrap().id
    };
    assert_ne!(tpm(&k.status().unwrap().keyslots), tpm(&before));
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    assert_eq!(kept(&env, "vault.aleph.replaced-"), 1);
    // The .bak it had is kept too (the rotation's write replaces .bak).
    assert_eq!(kept(&env, "vault.aleph.bak-"), 1);
    k.lock();
    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
        .unwrap();
}

/// A backup holds only the recovery slot, and restores on a new machine
/// (another TPM) with the recovery key and a fresh unlock method.
#[test]
fn a_backup_restores_on_a_new_machine() {
    let old = env();
    let k = keyring(&old, MockKeys::default());
    let key = create_capturing_key(&k);
    write_item(&k, "carried over");
    let bytes = backup_of(&k);
    let backup = aleph_core::LockedVault::from_bytes(&bytes).unwrap();
    assert!(
        backup
            .keyslots()
            .all(|s| matches!(s.kind, aleph_core::SlotKind::Recovery(_)))
    );
    let new = env();
    let k = keyring(&new, MockKeys::default());
    let p = Interactive::new(vec![recovery(&key), password(PW), no()]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert_eq!(kinds(&k), ["recovery", "tpm"]);
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    k.lock();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
}

/// A restore that finishes after the pre-sleep lock writes nothing and
/// leaves nothing unlocked; after the resume it works.
#[test]
fn nothing_is_restored_while_the_system_sleeps() {
    let old = env();
    let k = keyring(&old, MockKeys::default());
    let key = create_capturing_key(&k);
    let bytes = backup_of(&k);
    let new = env();
    let k = keyring(&new, MockKeys::default());
    k.set_sleeping(true);
    let p = Interactive::new(vec![recovery(&key), password(PW), no()]);
    assert!(matches!(
        k.recover(&mut p.channel(), Some(&bytes)),
        Err(aleph_daemon::Error::Sleeping)
    ));
    assert!(k.is_locked());
    assert!(!new.paths.vault().exists());
    k.set_sleeping(false);
    let p = Interactive::new(vec![recovery(&key), password(PW), no()]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert!(!k.is_locked());
}

/// Replacing a vault that still opens needs its current method first:
/// declined, nothing changes; proven, the old file is kept.
#[test]
fn replacing_a_vault_that_opens_needs_its_method() {
    let other = env();
    let k2 = keyring(&other, MockKeys::default());
    let key2 = create_capturing_key(&k2);
    let bytes = backup_of(&k2);
    let here = env();
    let k = keyring(&here, MockKeys::default());
    create_capturing_key(&k);
    k.lock();
    let file = std::fs::read(here.paths.vault()).unwrap();
    // Answering the later questions without the method changes nothing.
    let p = Interactive::new(vec![recovery(&key2), password(PW), no()]);
    assert!(k.recover(&mut p.channel(), Some(&bytes)).is_err());
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), file);
    let p = Interactive::new(vec![password(PW), recovery(&key2), password(PW), no()]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert_eq!(kept(&here, "vault.aleph.replaced-"), 1);
}

/// Wrong recovery keys (malformed, or another vault's) change nothing.
#[test]
fn a_wrong_recovery_key_changes_nothing() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    k.lock();
    let file = std::fs::read(env.paths.vault()).unwrap();
    let other = aleph_core::RecoveryKey::generate().unwrap().format();
    let p = Interactive::new(vec![
        recovery("not a key"),
        recovery(&other),
        recovery(&other),
    ]);
    assert!(k.recover(&mut p.channel(), None).is_err());
    assert_eq!(std::fs::read(env.paths.vault()).unwrap(), file);
    assert!(k.is_locked());
}

/// An unreadable vault file is replaced by its backup copy, opened with
/// the usual method; the unreadable file is kept.
#[test]
fn the_backup_copy_replaces_an_unreadable_vault() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    write_item(&k, "first");
    write_item(&k, "second");
    drop(k);
    std::fs::write(env.paths.vault(), b"not a vault").unwrap();
    let bak = std::fs::read(env.paths.bak()).unwrap();
    let k = keyring(&env, MockKeys::default());
    let p = Interactive::new(vec![yes(), password(PW)]);
    k.restore_from_bak(&mut p.channel()).unwrap();
    // The good copy is kept whatever the write does to .bak.
    let kept_bak = std::fs::read_dir(&env.paths.data_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("vault.aleph.bak-")
        })
        .unwrap();
    assert_eq!(std::fs::read(kept_bak).unwrap(), bak);
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    assert_eq!(kept(&env, "vault.aleph.corrupt-"), 1);
    assert_eq!(k.status().unwrap().untrusted, None);
}

/// A rolled-back file is accepted only after re-authentication and a yes;
/// it is then written past everything recorded, so the newer copy that was
/// replaced now reads as rolled back itself (the mark never goes down).
#[test]
fn an_accepted_rollback_never_lowers_the_mark() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    let older = std::fs::read(env.paths.vault()).unwrap();
    write_item(&k, "later");
    let newer = std::fs::read(env.paths.vault()).unwrap();
    k.lock();
    std::fs::write(env.paths.vault(), &older).unwrap();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
    let decline = Interactive::new(vec![password(PW), no()]);
    assert!(matches!(
        k.accept_rollback(&mut decline.channel()),
        Err(Error::Cancelled)
    ));
    assert!(k.status().unwrap().untrusted.is_some());
    // Enter declines the acceptance (E7).
    assert!(
        decline
            .sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::Confirm { default: false, .. }))
    );
    let accept = Interactive::new(vec![password(PW), yes()]);
    k.accept_rollback(&mut accept.channel()).unwrap();
    assert_eq!(k.status().unwrap().untrusted, None);
    let newer_generation = aleph_core::LockedVault::from_bytes(&newer)
        .unwrap()
        .mark()
        .generation;
    assert!(
        aleph_core::LockedVault::read(&env.paths.vault())
            .unwrap()
            .mark()
            .generation
            > newer_generation
    );
    write_item(&k, "after acceptance");
    k.lock();
    std::fs::write(env.paths.vault(), &newer).unwrap();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
}

/// A vault from before the vault-id file existed gets one at its first
/// unlock (setup never writes it), so a vault swapped in later is caught.
#[test]
fn a_vault_without_a_recorded_id_gets_one_at_unlock() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    k.lock();
    std::fs::remove_file(env.paths.expected_vault()).unwrap();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert!(env.paths.expected_vault().exists());
    assert_eq!(k.status().unwrap().untrusted, None);
}

/// A different vault put at the path is not trusted (its history is not
/// this machine's) until accepted.
#[test]
fn a_different_vault_at_the_path_is_not_trusted() {
    let here = env();
    let k = keyring_with(
        &here,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_capturing_key(&k);
    drop(k);
    let there = env();
    let k2 = keyring_with(
        &there,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_capturing_key(&k2);
    drop(k2);
    std::fs::copy(there.paths.vault(), here.paths.vault()).unwrap();
    let k = keyring_with(
        &here,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let why = k.status().unwrap().untrusted.unwrap();
    assert!(why.contains("different vault"), "{why}");
    // Its own method, then the login password (PAM), then yes.
    k.accept_rollback(&mut Interactive::new(vec![password(PW), password(PW), yes()]).channel())
        .unwrap();
    assert_eq!(k.status().unwrap().untrusted, None);
}

/// E7 against a same-user process that holds a backup and its recovery
/// key: moving the vault away does not skip the proof.
#[test]
fn a_missing_vault_does_not_skip_the_proof() {
    let (_, key, backup) = foreign_vault();
    let here = env();
    let k = victim(&here);
    std::fs::remove_file(here.paths.vault()).unwrap();
    assert!(
        k.recover(
            &mut Interactive::new(attacker_answers(&key)).channel(),
            Some(&backup)
        )
        .is_err()
    );
    assert!(!here.paths.vault().exists());
    // The user, with the login password, can.
    let mut answers = vec![password(PW)];
    answers.extend(attacker_answers(&key));
    k.recover(&mut Interactive::new(answers).channel(), Some(&backup))
        .unwrap();
}

/// A planted vault proves nothing with its own methods.
#[test]
fn a_planted_vault_does_not_prove_the_right_to_replace_it() {
    let (planted, key, backup) = foreign_vault();
    let here = env();
    let k = victim(&here);
    std::fs::write(here.paths.vault(), &planted).unwrap();
    let mut answers = vec![password("attacker")];
    answers.extend(attacker_answers(&key));
    assert!(
        k.recover(&mut Interactive::new(answers).channel(), Some(&backup))
            .is_err()
    );
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), planted);
    // Nor through its own recovery key, with no backup given (yes to
    // dropping its slot).
    let mut answers = vec![recovery(&key), yes()];
    answers.extend(attacker_answers(&key).into_iter().skip(1));
    assert!(
        k.recover(&mut Interactive::new(answers).channel(), None)
            .is_err()
    );
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), planted);
}

/// While the keyring is unlocked, a missing file does not skip the proof.
#[test]
fn an_unlocked_keyring_is_replaced_only_after_reauthentication() {
    let (_, key, backup) = foreign_vault();
    let here = env();
    let k = victim(&here);
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    std::fs::remove_file(here.paths.vault()).unwrap();
    assert!(
        k.recover(
            &mut Interactive::new(attacker_answers(&key)).channel(),
            Some(&backup)
        )
        .is_err()
    );
    assert!(!here.paths.vault().exists());
}

/// A planted backup copy is not restored with its own methods.
#[test]
fn a_planted_backup_copy_needs_the_login_password() {
    let (planted, _, _) = foreign_vault();
    let here = env();
    let k = victim(&here);
    let file = std::fs::read(here.paths.vault()).unwrap();
    std::fs::write(here.paths.bak(), &planted).unwrap();
    let p = Interactive::new(vec![yes(), password("attacker")]);
    assert!(k.restore_from_bak(&mut p.channel()).is_err());
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), file);
}

/// A planted vault, unlocked with its own password, is not accepted with
/// it: accepting a different vault needs this machine's login password.
#[test]
fn a_planted_vault_is_not_accepted_with_its_own_password() {
    let (planted, _, _) = foreign_vault();
    let here = env();
    let k = keyring_with(
        &here,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_capturing_key(&k);
    k.lock();
    std::fs::write(here.paths.vault(), &planted).unwrap();
    k.unlock(
        &mut Interactive::new(vec![password("attacker")]).channel(),
        None,
    )
    .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
    let p = Interactive::new(vec![password("attacker"), yes()]);
    assert!(k.accept_rollback(&mut p.channel()).is_err());
    assert!(k.status().unwrap().untrusted.is_some());
}

/// A planted vault unlocked with its own method (the attacker's security
/// key) proves nothing for a restore: re-authenticating against it is not
/// proof.
#[test]
fn an_unlocked_planted_vault_proves_nothing() {
    let here = env();
    let k = keyring(&here, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    // The attacker's vault, on the attacker's key, made before this
    // machine's own.
    let p = Interactive::new(vec![pin(PIN)]);
    k.create(&mut p.channel(), Method::Fido2).unwrap();
    let key = p
        .sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::ShowRecoveryKey { key, .. } => Some(key.expose().to_string()),
            _ => None,
        })
        .unwrap();
    k.lock();
    let planted = std::fs::read(here.paths.vault()).unwrap();
    std::fs::remove_file(here.paths.vault()).unwrap();
    std::fs::remove_file(here.paths.expected_vault()).unwrap();
    create_capturing_key(&k);
    k.lock();
    std::fs::write(here.paths.vault(), &planted).unwrap();
    k.unlock(
        &mut Interactive::new(vec![FromPrompter::Fido2 {}, pin(PIN)]).channel(),
        None,
    )
    .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
    // Its own key for the proof, its recovery key, yes to dropping its
    // slot, and its key again as the new method.
    let answers = vec![
        FromPrompter::Fido2 {},
        pin(PIN),
        recovery(&key),
        yes(),
        FromPrompter::Fido2 {},
        pin(PIN),
        no(),
    ];
    assert!(
        k.recover(&mut Interactive::new(answers).channel(), None)
            .is_err()
    );
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), planted);
}

/// A file that is not a backup (garbage, a truncated backup) changes nothing.
#[test]
fn a_file_that_is_not_a_backup_changes_nothing() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    let key = create_capturing_key(&k);
    let bytes = backup_of(&k);
    k.lock();
    let file = std::fs::read(env.paths.vault()).unwrap();
    for junk in [b"not a vault".to_vec(), bytes[..bytes.len() / 2].to_vec()] {
        let p = Interactive::new(vec![password(PW), recovery(&key), password(PW), no()]);
        assert!(k.recover(&mut p.channel(), Some(&junk)).is_err());
        assert_eq!(std::fs::read(env.paths.vault()).unwrap(), file);
    }
}

/// Restoring an older backup of this vault says what is lost and asks
/// first (Enter says no); restored, it is written past the newer file,
/// which then reads as rolled back.
#[test]
fn an_older_backup_of_this_vault_asks_first_and_the_newer_file_stays_detectable() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    let key = create_capturing_key(&k);
    let bytes = backup_of(&k);
    write_item(&k, "written after the backup");
    let newer = std::fs::read(env.paths.vault()).unwrap();
    k.lock();
    let p = Interactive::new(vec![password(PW), no()]);
    assert!(matches!(
        k.recover(&mut p.channel(), Some(&bytes)),
        Err(Error::Cancelled)
    ));
    assert!(p.sent().iter().any(|m| matches!(
        m,
        ToPrompter::Confirm { text, default: false } if text.contains("not in it")
    )));
    assert_eq!(std::fs::read(env.paths.vault()).unwrap(), newer);
    let p = Interactive::new(vec![
        password(PW),
        yes(),
        recovery(&key),
        password(PW),
        no(),
    ]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 0);
    let newer_generation = aleph_core::LockedVault::from_bytes(&newer)
        .unwrap()
        .mark()
        .generation;
    assert!(
        aleph_core::LockedVault::read(&env.paths.vault())
            .unwrap()
            .mark()
            .generation
            > newer_generation
    );
    k.lock();
    std::fs::write(env.paths.vault(), &newer).unwrap();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
}

/// A vault whose slot opens but whose contents fail authentication
/// (corrupt) is proven by its method once, and replaced; it is kept.
#[test]
fn a_corrupt_vault_is_replaced_after_its_method_opens_its_slot() {
    let other = env();
    let k2 = keyring(&other, MockKeys::default());
    let key2 = create_capturing_key(&k2);
    let bytes = backup_of(&k2);
    let here = env();
    let k = keyring(&here, MockKeys::default());
    create_capturing_key(&k);
    k.lock();
    let mut file = std::fs::read(here.paths.vault()).unwrap();
    let last = file.len() - 1;
    file[last] ^= 1;
    std::fs::write(here.paths.vault(), &file).unwrap();
    let p = Interactive::new(vec![password(PW), recovery(&key2), password(PW), no()]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert_eq!(kept(&here, "vault.aleph.replaced-"), 1);
}

/// A backup needs re-authentication; declined, nothing is written.
#[test]
fn a_backup_needs_reauthentication() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    let mut written = false;
    let result = k.backup(
        &mut Interactive::new(vec![FromPrompter::Cancel {}]).channel(),
        |_| {
            written = true;
            Ok(())
        },
    );
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(!written);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon --test custody`
Expected: the build fails: `Keyring::recover`, `restore_from_bak`, `accept_rollback`, and `backup` do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-daemon/src/keyring/custody.rs`:

```rust
//! Custody (spec §4 "File", "Generation and high-water mark"; §5 "Recovery
//! key"; §7 `aleph backup`, `aleph restore`): recovering with the recovery
//! key, restoring a backup, falling back to the backup copy, accepting a
//! rolled-back or replaced file, and writing backups.
//!
//! - Every restore and acceptance writes the vault past every generation
//!   this machine has seen (`advance_generation_past`): the high-water mark
//!   is never lowered, so no older copy can come back unnoticed.
//! - A replaced vault file is kept (`vault.aleph.replaced-<time>`, or
//!   `.corrupt-<time>`), never deleted.
//! - Replacing a vault that still opens needs its current method as well as
//!   the backup's recovery key: otherwise a same-user process could swap in
//!   a backup whose recovery key it holds (DECISIONS.md E7).
//! - The recovery key is asked for only here ([`Channel::ask_recovery_key`]).

use super::*;

/// Tries at the recovery key in one conversation.
const RECOVERY_ATTEMPTS: usize = 3;

impl Keyring {
    /// Recover with the recovery key: the current vault (or, if it cannot be
    /// read, its backup copy) when `backup` is `None`, else a backup file's
    /// bytes (`aleph restore [<file>]`). Every slot but the recovery slot is
    /// replaced by one fresh unlock method, and MK rotates; then a new
    /// recovery key is offered.
    pub fn recover(&self, chan: &mut Channel, backup: Option<&[u8]>) -> Result<()> {
        let _op = self.begin(chan)?;
        converse(chan, |chan| {
            chan.send(&ToPrompter::Begin {
                purpose: Purpose::Recover,
                operation: match backup {
                    Some(_) => "Restore the keyring from a backup",
                    None => "Recover the keyring with the recovery key",
                }
                .into(),
                caller: None,
            })?;
            let local = lock(&self.inner).store.read();
            let source = match backup {
                Some(bytes) => LockedVault::from_bytes(bytes)?,
                None => {
                    if !self.is_locked() && lock(&self.inner).untrusted.is_none() {
                        return Err(Error::Invalid(
                            "the keyring is unlocked and in order: nothing to recover \
                             (`aleph keyslot` changes unlock methods)"
                                .into(),
                        ));
                    }
                    match lock(&self.inner).store.read() {
                        Ok(file) => file,
                        Err(_) => lock(&self.inner).store.read_bak()?,
                    }
                }
            };
            // E7: recovering the vault this machine expects needs only its
            // recovery key; replacing anything (a backup over whatever is
            // here, or a file that is not the expected vault) needs proof.
            let expected = lock(&self.inner).store.expected_vault_id();
            if backup.is_some() || expected != Some(source.vault_id()) {
                self.prove_local(chan, local.as_ref().ok())?;
            }
            // An older backup of this same vault: say what is lost.
            if backup.is_some()
                && let Ok(here) = &local
                && here.vault_id() == source.vault_id()
                && source.mark().generation < here.mark().generation
            {
                let reply = chan.ask(&ToPrompter::Confirm {
                    text: format!(
                        "This backup is generation {} of this keyring, and the file here is generation {}: anything written since the backup is not in it (the current file is kept). Restore it?",
                        source.mark().generation,
                        here.mark().generation
                    ),
                    default: false,
                })?;
                if reply != (FromPrompter::Confirm { yes: true }) {
                    return Err(Error::Cancelled);
                }
            }
            let recovery = source
                .keyslots()
                .find(|k| matches!(k.kind, SlotKind::Recovery(_)))
                .map(|k| k.id)
                .ok_or_else(|| Error::Invalid("this vault has no recovery slot".into()))?;
            let mut vault = self.open_with_recovery_key(chan, &source, recovery)?;
            let old: Vec<(Uuid, String)> = vault
                .keyslots()
                .filter(|k| !matches!(k.kind, SlotKind::Recovery(_)))
                .map(|k| (k.id, format!("{} ({})", k.label, kind_name(&k.kind))))
                .chain(vault.unknown_keyslots().map(|u| {
                    (
                        u.id.unwrap_or_default(),
                        format!("{} (unknown type)", u.label.clone().unwrap_or_default()),
                    )
                }))
                .collect();
            if !old.is_empty() {
                let names: Vec<&str> = old.iter().map(|(_, n)| n.as_str()).collect();
                let reply = chan.ask(&ToPrompter::Confirm {
                    text: format!(
                        "These keyslots will be removed: {}. You will set up a new unlock method now. Continue?",
                        names.join(", ")
                    ),
                    default: false,
                })?;
                if reply != (FromPrompter::Confirm { yes: true }) {
                    return Err(Error::Cancelled);
                }
            }
            let method = self.choose_new_method(chan)?;
            let (slot, kek) = self.add_method(chan, &mut vault, method)?;
            let drop: Vec<Uuid> = vault
                .keyslots()
                .filter(|k| k.id != slot && !matches!(k.kind, SlotKind::Recovery(_)))
                .map(|k| k.id)
                .collect();
            vault.rotate_master(&[(slot, &kek)], &drop)?;
            let local_generation = local
                .as_ref()
                .ok()
                .filter(|l| l.vault_id() == vault.vault_id())
                .map(|l| l.mark().generation)
                .unwrap_or(0);
            let kept = self.put_in_place(
                vault,
                source.mark().generation.max(local_generation),
                local.is_ok(),
            )?;
            let reissued = self.offer_new_recovery_key(chan, slot, &kek)?;
            Ok(Some(done_message(
                "The keyring is restored",
                &kept,
                reissued,
            )))
        })
    }

    /// Replace a vault file that does not open (or should not) with its
    /// backup copy (`aleph restore --from-bak`), opened with the normal
    /// unlock methods.
    pub fn restore_from_bak(&self, chan: &mut Channel) -> Result<()> {
        let _op = self.begin(chan)?;
        converse(chan, |chan| {
            chan.send(&ToPrompter::Begin {
                purpose: Purpose::Recover,
                operation: "Restore the keyring from its backup copy (vault.aleph.bak)".into(),
                caller: None,
            })?;
            if !self.is_locked() {
                return Err(Error::Invalid(
                    "the keyring is unlocked: its vault file is in order".into(),
                ));
            }
            let (bak, current) = {
                let inner = lock(&self.inner);
                (inner.store.read_bak()?, inner.store.read())
            };
            let what = match &current {
                Ok(c) => format!(
                    "vault.aleph (generation {}) will be set aside and replaced by its backup copy (generation {})",
                    c.mark().generation,
                    bak.mark().generation
                ),
                Err(e) => format!(
                    "vault.aleph cannot be read ({e}); it will be set aside and replaced by its backup copy (generation {})",
                    bak.mark().generation
                ),
            };
            let reply = chan.ask(&ToPrompter::Confirm {
                text: format!("{what}. Continue?"),
                default: false,
            })?;
            if reply != (FromPrompter::Confirm { yes: true }) {
                return Err(Error::Cancelled);
            }
            // A backup copy that is not the vault this machine expects
            // proves nothing with its own methods (E7).
            if lock(&self.inner).store.expected_vault_id() != Some(bak.vault_id()) {
                self.ask_password(chan)?;
            }
            let Opened { vault, .. } = self.choose_and_open(chan, &bak)?;
            let current_generation = current
                .as_ref()
                .ok()
                .filter(|c| c.vault_id() == vault.vault_id())
                .map(|c| c.mark().generation)
                .unwrap_or(0);
            let kept = self.put_in_place(
                vault,
                bak.mark().generation.max(current_generation),
                current.is_ok(),
            )?;
            Ok(Some(done_message(
                "Restored from the backup copy",
                &kept,
                false,
            )))
        })
    }

    /// Accept the unlocked vault file as current although it was rolled
    /// back, replaced, or re-keyed elsewhere (`aleph restore
    /// --accept-rollback`): after re-authentication and an explicit yes, it
    /// is written past the recorded generation, and writes are allowed
    /// again.
    pub fn accept_rollback(&self, chan: &mut Channel) -> Result<()> {
        let _op = self.begin(chan)?;
        converse(chan, |chan| {
            let why = {
                let inner = lock(&self.inner);
                if inner.vault.is_none() {
                    return Err(Error::Locked);
                }
                inner.untrusted.ok_or_else(|| {
                    Error::Invalid("nothing to accept: the vault file is trusted".into())
                })?
            };
            self.reauth(chan, "Accept the vault file as it is")?;
            // A vault that is not the one this machine expects proves
            // nothing with its own methods: the login password too.
            if !self.open_vault_is_expected() {
                self.ask_password(chan)?;
            }
            let (found, recorded) = {
                let inner = lock(&self.inner);
                let v = inner.vault.as_ref().ok_or(Error::Locked)?;
                (v.mark(), inner.store.recorded(v.vault_id())?)
            };
            let before = match recorded {
                Some(r) if r.mk_id != found.mk_id => {
                    format!("generation {} under a different master key", r.generation)
                }
                Some(r) => format!("generation {}", r.generation),
                None => "nothing for this vault".into(),
            };
            let reply = chan.ask(&ToPrompter::Confirm {
                text: format!(
                    "The vault file was {why}: this machine last recorded {before}, and the file is generation {}. Accept the file as current? Anything written here after it is lost.",
                    found.generation
                ),
                default: false,
            })?;
            if reply != (FromPrompter::Confirm { yes: true }) {
                return Err(Error::Cancelled);
            }
            let mut inner = lock(&self.inner);
            // The write replaces .bak, which may be the newest copy left.
            let kept: Vec<_> = inner.store.keep_bak_aside()?.into_iter().collect();
            let v = inner.vault.as_ref().ok_or(Error::Locked)?;
            v.advance_generation_past(recorded.map(|r| r.generation).unwrap_or(0));
            inner.store.write(v)?;
            inner.store.expect_vault_id(v.vault_id())?;
            inner.untrusted = None;
            Ok(Some(done_message(
                "The vault file is accepted as current",
                &kept,
                false,
            )))
        })
    }

    /// Write a backup (`aleph backup`) through `write`, after
    /// re-authentication: a copy with only the recovery slot, checked to
    /// parse before it is written.
    pub fn backup(
        &self,
        chan: &mut Channel,
        write: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let _op = self.begin(chan)?;
        converse(chan, |chan| {
            self.reauth(chan, "Write a backup of the keyring")?;
            let bytes = lock(&self.inner)
                .vault
                .as_ref()
                .ok_or(Error::Locked)?
                .to_backup_bytes()?;
            let mark = LockedVault::from_bytes(&bytes)?.mark();
            write(&bytes)?;
            Ok(Some(format!(
                "Backup written: vault {}, generation {}. It holds only the recovery slot: it opens with your recovery key and nothing else.",
                mark.vault_id, mark.generation
            )))
        })
    }

    /// Whether the unlocked vault is the one this machine expects.
    fn open_vault_is_expected(&self) -> bool {
        let inner = lock(&self.inner);
        let expected = inner.store.expected_vault_id();
        expected.is_some() && inner.vault.as_ref().map(|v| v.vault_id()) == expected
    }

    /// Prove the right to replace what is at the path (E7). The method of
    /// the vault this machine expects proves it: re-authentication while it
    /// is unlocked, or opening `file` if that is it (a file that fails
    /// authentication after its slot opened, corrupt, counts: the
    /// credential was right). Anything else (no file where a vault was
    /// expected, an unreadable or different one, a file where none was
    /// recorded) needs the login password, checked with PAM: a planted
    /// vault's own methods prove nothing. Only a machine with no vault and
    /// none expected has nothing to prove.
    fn prove_local(&self, chan: &mut Channel, file: Option<&LockedVault>) -> Result<()> {
        let (expected, exists) = {
            let inner = lock(&self.inner);
            (inner.store.expected_vault_id(), inner.store.exists())
        };
        let proven = if !self.is_locked() {
            if !self.open_vault_is_expected() {
                return self.ask_password(chan).map(|_| ());
            }
            self.reauth(chan, "Replace the keyring with a backup")
                .map(|_| ())
        } else {
            match (file, expected) {
                (Some(f), Some(id)) if f.vault_id() == id => {
                    self.choose_and_open(chan, f).map(|_| ())
                }
                (None, None) if !exists => Ok(()),
                _ => return self.ask_password(chan).map(|_| ()),
            }
        };
        match proven {
            Ok(())
            | Err(Error::Core(
                aleph_core::Error::HeaderTampered | aleph_core::Error::BodyTampered,
            )) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Open `source` with its recovery slot, asking for the key a few times.
    fn open_with_recovery_key(
        &self,
        chan: &mut Channel,
        source: &LockedVault,
        slot: Uuid,
    ) -> Result<UnlockedVault> {
        let mut error = None;
        for _ in 0..RECOVERY_ATTEMPTS {
            let typed = chan.ask_recovery_key(error.take())?;
            match RecoveryKey::parse(typed.expose()) {
                Err(_) => {
                    error = Some("that is not a recovery key (check each group of four)".into())
                }
                Ok(key) => match source.unlock_recovery(slot, &key) {
                    Ok(v) => return Ok(v),
                    Err(_) => error = Some("that recovery key does not open this vault".into()),
                },
            }
        }
        Err(Error::Invalid("the recovery key was not accepted".into()))
    }

    /// Write a restored vault in place: past `found` and every generation
    /// recorded for it, keeping the file it replaces (`replaced` if that
    /// file could be read, else `corrupt`). Then it is the unlocked vault,
    /// trusted, and the expected one. Returns the kept files (the replaced
    /// one, and `.bak`).
    fn put_in_place(
        &self,
        vault: UnlockedVault,
        found: u64,
        readable: bool,
    ) -> Result<Vec<std::path::PathBuf>> {
        let mut inner = lock(&self.inner);
        // Going to sleep: the pre-sleep lock has run, so nothing is
        // written or left unlocked (the backup is still there to re-run).
        if self.sleeping.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::Sleeping);
        }
        let recorded = inner
            .store
            .recorded(vault.vault_id())?
            .map(|m| m.generation)
            .unwrap_or(0);
        vault.advance_generation_past(recorded.max(found));
        let mut kept = Vec::new();
        if inner.store.exists() {
            kept.push(
                inner
                    .store
                    .keep_aside(if readable { "replaced" } else { "corrupt" })?,
            );
        }
        // The write may replace .bak (always after a rotation), and .bak may
        // be the only good copy.
        kept.extend(inner.store.keep_bak_aside()?);
        inner.store.write(&vault)?;
        inner.store.expect_vault_id(vault.vault_id())?;
        let ids: HashSet<Uuid> = vault.keyslots().map(|k| k.id).collect();
        inner.state.retain(|id| ids.contains(&id))?;
        inner.state.set_rotation_pending(false)?;
        inner.vault = Some(vault);
        inner.untrusted = None;
        Ok(kept)
    }

    /// After recovery, offer a new recovery key (the old one was just typed
    /// in, and may have been seen). `slot` and `kek` are the fresh unlock
    /// method's, which the rotation needs.
    fn offer_new_recovery_key(&self, chan: &mut Channel, slot: Uuid, kek: &Kek) -> Result<bool> {
        let reply = chan.ask(&ToPrompter::Confirm {
            text: "Your recovery key was just typed in. Issue a new one now? The old one then stops opening this keyring (it still opens older backups and the kept files)."
                .into(),
            default: true,
        })?;
        if reply != (FromPrompter::Confirm { yes: true }) {
            return Ok(false);
        }
        let key = RecoveryKey::generate()?;
        show_recovery_key(chan, &key)?;
        self.modify_vault(|v| {
            let old: Vec<Uuid> = v
                .keyslots()
                .filter(|k| matches!(k.kind, SlotKind::Recovery(_)))
                .map(|k| k.id)
                .collect();
            v.add_recovery_slot("recovery", &key.recipient().public_key())?;
            Ok(v.rotate_master(&[(slot, kek)], &old)?)
        })
        .map_err(|e| Error::RecoveryNotInstalled(Box::new(e)))?;
        Ok(true)
    }
}

fn done_message(what: &str, kept: &[std::path::PathBuf], reissued: bool) -> String {
    let mut m = format!("{what}.");
    if !kept.is_empty() {
        let names: Vec<String> = kept.iter().map(|p| p.display().to_string()).collect();
        m.push_str(&format!(
            " Kept: {}. They still open with the old recovery key and the old unlock methods: delete them once you have checked the keyring.",
            names.join(", ")
        ));
    }
    if reissued {
        m.push_str(" A new recovery key was issued: the old one no longer opens this keyring.");
    }
    m
}
```

Apply this patch with `git apply` (save it as `/tmp/t4-impl.patch`):

```diff
--- a/crates/aleph-daemon/src/keyring.rs
+++ b/crates/aleph-daemon/src/keyring.rs
@@ -27,6 +27,8 @@
 use crate::prompt::{Caller, Channel, FromPrompter, Method, Purpose, Secret, ToPrompter};
 use crate::state::SlotState;
 use crate::store::Store;
+
+mod custody;
 
 /// The TPM, as the engine uses it (the real one is `aleph_unlock::TpmClient`).
 pub trait Tpm: Send {
@@ -121,6 +123,13 @@
     login: Option<Zeroizing<String>>,
     /// The FIDO2 slot touched, and its KEK.
     fido2: Option<(Uuid, Kek)>,
+}
+
+/// A fresh unlock method to set up (create, recovery).
+enum NewMethod {
+    /// The login password, which PAM accepted.
+    Password(Zeroizing<String>),
+    Fido2,
 }
 
 /// The result of opening the vault file with one slot.
@@ -516,6 +525,7 @@
                 // Waiting is not something to retry at once, and a key's
                 // PIN budget for this conversation is spent (each wrong
                 // PIN costs one of the key's lifetime retries).
+                // (A corrupt file does not open by asking again, either.)
                 Err(
                     e @ (Error::Cancelled
                     | Error::Prompt(_)
@@ -523,7 +533,10 @@
                     | Error::UnlockedElsewhere
                     | Error::Sleeping
                     | Error::TooManyAttempts { .. }
-                    | Error::Unlock(aleph_unlock::Error::Fido2PinInvalid)),
+                    | Error::Unlock(aleph_unlock::Error::Fido2PinInvalid)
+                    | Error::Core(
+                        aleph_core::Error::HeaderTampered | aleph_core::Error::BodyTampered,
+                    )),
                 ) => {
                     return Err(e);
                 }
@@ -878,6 +891,9 @@
             }
         };
         let untrusted = trust(&inner.store, &vault)?;
+        if inner.store.expected_vault_id().is_none() {
+            inner.store.expect_vault_id(vault.vault_id())?;
+        }
         let ids: HashSet<Uuid> = vault.keyslots().map(|k| k.id).collect();
         inner.state.retain(|id| ids.contains(&id))?;
         inner.vault = Some(vault);
@@ -1381,6 +1397,72 @@
         Err(Error::WrongPassword)
     }
 
+    /// Ask which fresh unlock method to set up (recovery): the login
+    /// password (checked with PAM, as for create) or a security key.
+    fn choose_new_method(&self, chan: &mut Channel) -> Result<NewMethod> {
+        let mut error = Some("choose the new unlock method".to_string());
+        for _ in 0..MAX_ATTEMPTS {
+            let reply = chan.ask(&ToPrompter::Ask {
+                methods: vec![Method::Password, Method::Fido2],
+                error: error.take(),
+                retry_after: None,
+            })?;
+            match reply {
+                FromPrompter::Fido2 {} => return Ok(NewMethod::Fido2),
+                FromPrompter::Password { password } => {
+                    let now = Instant::now();
+                    if let Some(wait) = lock(&self.inner).typed.blocked(now) {
+                        return Err(Error::TooManyAttempts { retry_after: wait });
+                    }
+                    if lock(&self.hw).password.check(password.expose())? {
+                        return Ok(NewMethod::Password(Zeroizing::new(
+                            password.expose().to_string(),
+                        )));
+                    }
+                    lock(&self.inner).typed.record_failure(now);
+                    error = Some(Error::WrongPassword.to_string());
+                }
+                other => return Err(Error::Prompt(format!("unexpected reply {other:?}"))),
+            }
+        }
+        Err(Error::Invalid("too many attempts".into()))
+    }
+
+    /// Add a fresh unlock method's slot to `vault`: a TPM slot sealed under
+    /// the login password (a login-password slot without a usable TPM), or
+    /// a security key. Returns the slot and its KEK (for a rotation).
+    fn add_method(
+        &self,
+        chan: &mut Channel,
+        vault: &mut UnlockedVault,
+        method: NewMethod,
+    ) -> Result<(Uuid, Kek)> {
+        match method {
+            NewMethod::Password(password) => {
+                let hw = lock(&self.hw);
+                if hw.tpm.usable() {
+                    let (kek, slot) = hw.tpm.seal(password.as_bytes())?;
+                    Ok((vault.add_keyslot("tpm", SlotKind::Tpm(slot), &kek)?, kek))
+                } else {
+                    drop(hw);
+                    let id = vault.add_login_password_slot(
+                        "login password",
+                        password.as_bytes(),
+                        self.argon2,
+                    )?;
+                    Ok((id, vault.login_password_kek(id, password.as_bytes())?))
+                }
+            }
+            NewMethod::Fido2 => {
+                let (kek, slot) = self.enroll_key(chan, false)?;
+                Ok((
+                    vault.add_keyslot("security key", SlotKind::Fido2(slot), &kek)?,
+                    kek,
+                ))
+            }
+        }
+    }
+
     /// Create the vault with a recovery slot and one unlock method.
     pub fn create(&self, chan: &mut Channel, method: Method) -> Result<()> {
         let _op = self.begin(chan)?;
@@ -1396,29 +1478,15 @@
             let mut vault = UnlockedVault::create()?;
             let key = RecoveryKey::generate()?;
             vault.add_recovery_slot("recovery", &key.recipient().public_key())?;
-            match method {
-                Method::Password => {
-                    let password = self.ask_password(chan)?;
-                    let hw = lock(&self.hw);
-                    if hw.tpm.usable() {
-                        let (kek, slot) = hw.tpm.seal(password.as_bytes())?;
-                        vault.add_keyslot("tpm", SlotKind::Tpm(slot), &kek)?;
-                    } else {
-                        vault.add_login_password_slot(
-                            "login password",
-                            password.as_bytes(),
-                            self.argon2,
-                        )?;
-                    }
-                }
-                Method::Fido2 => {
-                    let (kek, slot) = self.enroll_key(chan, false)?;
-                    vault.add_keyslot("security key", SlotKind::Fido2(slot), &kek)?;
-                }
-            }
+            let method = match method {
+                Method::Password => NewMethod::Password(self.ask_password(chan)?),
+                Method::Fido2 => NewMethod::Fido2,
+            };
+            self.add_method(chan, &mut vault, method)?;
             show_recovery_key(chan, &key)?;
             let mut inner = lock(&self.inner);
             inner.store.write(&vault)?;
+            inner.store.expect_vault_id(vault.vault_id())?;
             inner.untrusted = None;
             // Going to sleep: the file is written, but nothing is left
             // unlocked through it.
@@ -1631,6 +1699,15 @@
 /// rolled back, replaced, or re-keyed elsewhere (§4 "Generation and
 /// high-water mark"). Raises the mark otherwise.
 fn trust(store: &Store, vault: &UnlockedVault) -> Result<Option<&'static str>> {
+    // A different vault at the path (its own history unknown here) is
+    // never trusted by default; restore, create, and an accepted rollback
+    // change which vault is expected.
+    if store
+        .expected_vault_id()
+        .is_some_and(|id| id != vault.vault_id())
+    {
+        return Ok(Some("a different vault than this machine last used"));
+    }
     Ok(match store.raise(vault)? {
         Standing::Unrecorded | Standing::Current | Standing::Newer => None,
         Standing::Pending => {
--- a/crates/aleph-daemon/src/prompt.rs
+++ b/crates/aleph-daemon/src/prompt.rs
@@ -70,7 +70,8 @@
 
     /// Send a message that needs a reply and wait for it (up to the
     /// timeout). `Cancel` becomes `Error::Cancelled`. Never the recovery-key
-    /// question: only the recovery conversation asks it.
+    /// question: that goes through [`Channel::ask_recovery_key`], which only
+    /// the recovery conversation calls.
     pub fn ask(&mut self, msg: &ToPrompter) -> Result<FromPrompter> {
         debug_assert!(msg.needs_reply());
         if matches!(msg, ToPrompter::RecoveryKey { .. }) {
@@ -79,6 +80,14 @@
             ));
         }
         self.ask_any(msg)
+    }
+
+    /// Ask for the recovery key (the recovery conversation only).
+    pub(crate) fn ask_recovery_key(&mut self, error: Option<String>) -> Result<Secret> {
+        match self.ask_any(&ToPrompter::RecoveryKey { error })? {
+            FromPrompter::RecoveryKey { key } => Ok(key),
+            other => Err(Error::Prompt(format!("unexpected reply {other:?}"))),
+        }
     }
 
     fn ask_any(&mut self, msg: &ToPrompter) -> Result<FromPrompter> {
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 32 passed | ok. 3 passed | ok. 19 passed | ok. 51 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **an accepted file is written past the recorded generation** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody an_accepted_rollback_never_lowers_the_mark`:

  replace

  ```rust
  v.advance_generation_past(recorded.map(|r| r.generation).unwrap_or(0));
  ```

  with

  ```rust
  // (nothing)
  ```

- **a restored file is written past the generations seen** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody`:

  replace

  ```rust
  vault.advance_generation_past(recorded.max(found));
  ```

  with

  ```rust
  // (nothing)
  ```

- **replacing a vault that opens needs its method** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody replacing_a_vault_that_opens_needs_its_method`:

  replace

  ```rust
  self.prove_local(chan, local.as_ref().ok())?;
  ```

  with

  ```rust
  // (nothing)
  ```

- **a replaced file is kept** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody`:

  replace

  ```rust
  kept.push(
      inner
          .store
          .keep_aside(if readable { "replaced" } else { "corrupt" })?,
  );
  ```

  with

  ```rust
  // (nothing)
  ```

- **a different vault at the path is not trusted** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test custody a_different_vault_at_the_path_is_not_trusted`: replace `.is_some_and(|id| id != vault.vault_id())` with `.is_some_and(|_| false)`.
- **a vault without a recorded id gets one at unlock** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test custody a_vault_without_a_recorded_id_gets_one_at_unlock`:

  replace

  ```rust
  if inner.store.expected_vault_id().is_none() {
      inner.store.expect_vault_id(vault.vault_id())?;
  }
  ```

  with

  ```rust
  // (nothing)
  ```

- **a backup needs re-authentication** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody a_backup_needs_reauthentication`:

  replace

  ```rust
  self.reauth(chan, "Write a backup of the keyring")?;
  ```

  with

  ```rust
  // (nothing)
  ```

- **accepting a rollback needs re-authentication** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody an_accepted_rollback_never_lowers_the_mark`:

  replace

  ```rust
  self.reauth(chan, "Accept the vault file as it is")?;
  ```

  with

  ```rust
  // (nothing)
  ```

- **nothing is restored during sleep** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody nothing_is_restored_while_the_system_sleeps`:

  replace

  ```rust
  if self.sleeping.load(std::sync::atomic::Ordering::SeqCst) {
  return Err(Error::Sleeping);
  ```

  with

  ```rust
  if false {
  return Err(Error::Sleeping);
  ```

- **the new recovery key offer defaults to yes** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody the_recovery_key_recovers_the_current_vault`:

  replace

  ```rust
  default: true,
  })?;
  ```

  with

  ```rust
  default: false,
  })?;
  ```

- **a corrupt vault ends the method choice** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test custody`:

  replace

  ```rust
  | Error::Unlock(aleph_unlock::Error::Fido2PinInvalid)
      | Error::Core(
          aleph_core::Error::HeaderTampered | aleph_core::Error::BodyTampered,
      )),
  ) => {
  ```

  with

  ```rust
  | Error::Unlock(aleph_unlock::Error::Fido2PinInvalid)),
  ) => {
  ```

- **a corrupt vault counts as proven** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody`:

  replace

  ```rust
  Ok(())
  | Err(Error::Core(
      aleph_core::Error::HeaderTampered | aleph_core::Error::BodyTampered,
  )) => Ok(()),
  ```

  with

  ```rust
  Ok(()) => Ok(()),
  ```

- **a planted vault proves nothing** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody a_missing_vault_does_not_skip`:

  replace

  ```rust
  _ => return self.ask_password(chan).map(|_| ()),
  }
  ```

  with

  ```rust
  _ => Ok(()),
  }
  ```

- **a planted vault proves nothing, with no backup given** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody a_planted_vault_does_not_prove`:

  replace

  ```rust
  _ => return self.ask_password(chan).map(|_| ()),
  }
  ```

  with

  ```rust
  _ => Ok(()),
  }
  ```

- **a planted open vault proves nothing** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody an_unlocked_planted_vault_proves_nothing`:

  replace

  ```rust
  if !self.open_vault_is_expected() {
      return self.ask_password(chan).map(|_| ());
  }
  ```

  with

  ```rust
  // (nothing)
  ```

- **a planted backup copy needs the login password** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody a_planted_backup_copy_needs_the_login_password`: replace `if lock(&self.inner).store.expected_vault_id() != Some(bak.vault_id()) {` with `if false {`.
- **a planted vault is not accepted with its own method** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody a_planted_vault_is_not_accepted_with_its_own_password`:

  replace

  ```rust
  if !self.open_vault_is_expected() {
  self.ask_password(chan)?;
  ```

  with

  ```rust
  if false {
  self.ask_password(chan)?;
  ```

- **an older backup of this vault asks first** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody an_older_backup_of_this_vault_asks_first`: replace `&& source.mark().generation < here.mark().generation` with `&& false`.
- **custody keeps .bak** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-daemon --test custody`:

  replace

  ```rust
  kept.extend(inner.store.keep_bak_aside()?);
  ```

  with

  ```rust
  // (nothing)
  ```


- [ ] **Step 6: Commit**

```bash
git add crates/aleph-daemon
git commit -m "feat(daemon): recovery, the backup copy, accepting a rollback, and backups" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 5: aleph backup and aleph restore

**Interfaces:**
- Consumes: Task 4.
- Produces: Admin methods `Recover(h)`, `RestoreBackup(h, h)`, `RestoreFromBak(h)`, `AcceptRollback(h)`, `Backup(h, h)` (prompter descriptor first, then the file's); CLI `client::Args::File(File)`, `aleph backup [--force] <path>`, `aleph restore [--from-bak | --accept-rollback] [<path>]`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-cli/Cargo.toml`:

```toml
[package]
name = "aleph-cli"
description = "aleph: the command-line client for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "aleph"
path = "src/main.rs"

[dependencies]
aleph-prompt-proto = { path = "../aleph-prompt-proto" }
clap = { version = "4", features = ["derive"] }
clap_complete = "4"
rpassword = "7"
serde.workspace = true
serde_json.workspace = true
tokio = { version = "1", features = ["rt", "macros"] }
zbus = { version = "5", default-features = false, features = ["tokio"] }
zeroize.workspace = true

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-daemon = { path = "../aleph-daemon", features = ["testing"] }
tempfile.workspace = true
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Write `crates/aleph-cli/tests/cli.rs`:

```rust
//! The `aleph` binary against a daemon on a private bus. Prompts are
//! answered on standard input (`ALEPH_NO_TTY=1`).

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

use aleph_daemon::testing::*;

fn aleph(d: &Daemon, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aleph"));
    cmd.args(args)
        .env("DBUS_SESSION_BUS_ADDRESS", &d.bus.address)
        .env("ALEPH_NO_TTY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Run `aleph args` with `stdin`: `(success, stdout, stderr)`.
async fn run(d: &Daemon, args: &[&str], stdin: &str) -> (bool, String, String) {
    let mut cmd = aleph(d, args);
    let stdin = stdin.to_string();
    tokio::task::spawn_blocking(move || {
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    })
    .await
    .unwrap()
}

/// Read the child's stderr until it contains `needle`; return all of it.
fn read_until(child: &mut Child, seen: &mut String, needle: &str) {
    let err = child.stderr.as_mut().unwrap();
    let mut buf = [0u8; 256];
    while !seen.contains(needle) {
        let n = err.read(&mut buf).unwrap();
        assert!(n > 0, "stderr closed before {needle:?}; got: {seen}");
        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
}

/// `aleph setup`, answering the recovery-key check by reading the key it
/// shows, as a person would.
async fn setup(d: &Daemon) -> String {
    let mut cmd = aleph(d, &["setup"]);
    tokio::task::spawn_blocking(move || {
        let mut child = cmd.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "1\n{PW}").unwrap();
        let mut seen = String::new();
        read_until(&mut child, &mut seen, "Type group ");
        let key = seen
            .lines()
            .map(str::trim)
            .find(|l| l.matches('-').count() == 13)
            .expect("the recovery key was shown")
            .to_string();
        let groups: Vec<&str> = key.split('-').collect();
        for _ in 0..2 {
            let at = seen.rfind("Type group ").unwrap() + "Type group ".len();
            let n: usize = seen[at..]
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap();
            writeln!(stdin, "{}", groups[n - 1]).unwrap();
            let mark = seen.len();
            if seen[mark..].is_empty() {
                // Wait for the next prompt (or the end).
                let mut buf = [0u8; 256];
                let err = child.stderr.as_mut().unwrap();
                while !seen[mark..].contains("Type group ") && !seen[mark..].contains("ready") {
                    let n = err.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            }
        }
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        seen.push_str(&String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "setup failed: {seen}");
        seen
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_creates_the_keyring_and_status_shows_it() {
    let d = daemon(false, vec![]).await;
    let (_, out, _) = run(&d, &["status"], "").await;
    assert!(out.contains("keyring: none"), "{out}");
    let log = setup(&d).await;
    assert!(log.contains("The keyring is ready."), "{log}");
    assert!(
        log.contains("not available yet"),
        "setup should say what is missing: {log}"
    );
    let (ok, out, _) = run(&d, &["status", "--json"], "").await;
    assert!(ok);
    let s: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (s["vault"].clone(), s["locked"].clone()),
        (true.into(), false.into())
    );
    let kinds: Vec<&str> = s["keyslots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["recovery", "tpm"]);
    // A second setup changes nothing.
    let (ok, _, err) = run(&d, &["setup"], "").await;
    assert!(ok && err.contains("already exists"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn store_get_search_and_delete() {
    let d = daemon(true, vec![]).await;
    let (ok, _, err) = run(
        &d,
        &["store", "--label", "Mail", "service=mail", "user=alice"],
        "s3cret\n",
    )
    .await;
    assert!(ok, "{err}");
    let (ok, out, _) = run(&d, &["get", "service=mail"], "").await;
    assert!(ok);
    assert_eq!(out, "s3cret");
    let (ok, out, _) = run(&d, &["search", "user=alice"], "").await;
    assert!(ok);
    assert!(
        out.contains("Mail") && out.contains("service = mail"),
        "{out}"
    );
    let (ok, out, _) = run(&d, &["ls"], "").await;
    assert!(ok && out.contains("1 items"), "{out}");
    let (ok, _, _) = run(&d, &["delete", "service=mail"], "").await;
    assert!(ok);
    let (ok, out, _) = run(&d, &["get", "service=mail"], "").await;
    assert!(!ok && out.is_empty());
    // Refuses to delete everything, and bad pairs.
    let (ok, _, err) = run(&d, &["delete"], "").await;
    assert!(!ok && err.contains("refusing"), "{err}");
    let (ok, _, err) = run(&d, &["get", "service"], "").await;
    assert!(!ok && err.contains("attr=value"), "{err}");
}

/// A read while locked unlocks in the terminal first.
#[tokio::test(flavor = "multi_thread")]
async fn a_locked_get_unlocks_in_the_terminal() {
    let d = daemon(true, vec![]).await;
    run(&d, &["store", "--label", "X", "k=v"], "val").await;
    let (ok, _, _) = run(&d, &["lock"], "").await;
    assert!(ok);
    let (ok, out, _) = run(&d, &["status"], "").await;
    assert!(ok && out.contains("keyring: locked"), "{out}");
    let (ok, out, err) = run(&d, &["get", "k=v"], &format!("typo\n{PW}\n")).await;
    assert!(ok, "{err}");
    assert_eq!(out, "val");
    assert!(err.contains("wrong password"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn config_set_reauthenticates() {
    let d = daemon(true, vec![]).await;
    let (ok, _, err) = run(
        &d,
        &["config", "set", "lock.idle_timeout", "900"],
        &format!("{PW}\n"),
    )
    .await;
    assert!(ok, "{err}");
    assert!(err.contains("confirm it is you"), "{err}");
    let (ok, out, _) = run(&d, &["config", "get", "lock.idle_timeout"], "").await;
    assert!(ok);
    assert_eq!(out.trim(), "900");
    let (ok, _, err) = run(&d, &["config", "set", "lock.nope", "1"], "").await;
    assert!(!ok && err.contains("unknown key"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn keyslot_list_and_retry_by_prefix() {
    let d = daemon(true, vec![]).await;
    let (ok, out, _) = run(&d, &["keyslot", "list", "--json"], "").await;
    assert!(ok);
    let slots: serde_json::Value = serde_json::from_str(&out).unwrap();
    let tpm = slots
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == "tpm")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (ok, _, err) = run(&d, &["keyslot", "retry", &tpm[..8]], "").await;
    assert!(ok, "{err}");
    let (ok, _, err) = run(&d, &["keyslot", "retry", "zzzz"], "").await;
    assert!(!ok && err.contains("no keyslot"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn completions_are_generated() {
    let d = daemon(false, vec![]).await;
    for shell in ["bash", "zsh", "fish"] {
        let (ok, out, _) = run(&d, &["completions", shell], "").await;
        assert!(ok && out.contains("aleph"), "{shell}");
    }
}

/// Review I2: with no more input, the terminal prompter cancels; it never
/// answers with empty passwords in a loop.
#[tokio::test(flavor = "multi_thread")]
async fn end_of_input_cancels_instead_of_looping() {
    let d = daemon(true, vec![]).await;
    run(&d, &["lock"], "").await;
    let t = std::time::Instant::now();
    let (ok, _, err) = run(&d, &["unlock"], "").await;
    assert!(!ok, "{err}");
    assert!(err.contains("cancelled"), "{err}");
    assert!(err.len() < 2000, "looped: {} bytes", err.len());
    assert!(t.elapsed() < std::time::Duration::from_secs(10));
    // The daemon is free for the next request.
    let (ok, _, err) = run(&d, &["unlock"], &format!("{PW}\n")).await;
    assert!(ok, "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_needs_attributes() {
    let d = daemon(true, vec![]).await;
    run(&d, &["store", "--label", "X", "k=v"], "val").await;
    let (ok, out, err) = run(&d, &["get"], "").await;
    assert!(
        !ok && out.is_empty() && err.contains("at least one"),
        "{err}"
    );
}

/// The recovery key `aleph setup` showed (in its output).
fn recovery_key_in(log: &str) -> String {
    log.lines()
        .map(str::trim)
        .find(|l| l.matches('-').count() == 13)
        .expect("the recovery key was shown")
        .to_string()
}

/// `aleph backup` writes a file holding only the recovery slot, never over
/// an existing file without `--force`, never inside aleph's own directory;
/// `aleph restore <file>` restores it with the recovery key.
#[tokio::test(flavor = "multi_thread")]
async fn backup_and_restore_through_the_cli() {
    let d = daemon(false, vec![]).await;
    let key = recovery_key_in(&setup(&d).await);
    run(&d, &["store", "--label", "Kept", "k=kept"], "in the backup").await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("keyring.backup");
    let f = file.to_str().unwrap();
    let (ok, _, err) = run(&d, &["backup", f], &format!("{PW}\n")).await;
    assert!(ok, "{err}");
    let first = std::fs::read(&file).unwrap();
    let backup = aleph_core::LockedVault::read(&file).unwrap();
    assert!(
        backup
            .keyslots()
            .all(|s| matches!(s.kind, aleph_core::SlotKind::Recovery(_)))
    );
    let (ok, _, _) = run(&d, &["backup", f], &format!("{PW}\n")).await;
    assert!(!ok, "an existing file is not replaced without --force");
    assert_eq!(std::fs::read(&file).unwrap(), first);
    // A symlink is never followed.
    let target = dir.path().join("elsewhere");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (ok, _, _) = run(&d, &["backup", link.to_str().unwrap()], &format!("{PW}\n")).await;
    assert!(!ok);
    assert!(!target.exists());
    let (ok, _, err) = run(&d, &["backup", "--force", f], &format!("{PW}\n")).await;
    assert!(ok, "{err}");
    let inside = d.env.paths.data_dir.join("copy");
    let (ok, _, err) = run(
        &d,
        &["backup", inside.to_str().unwrap()],
        &format!("{PW}\n"),
    )
    .await;
    assert!(!ok && err.contains("cannot go inside"), "{err}");
    assert!(!inside.exists());
    run(
        &d,
        &["store", "--label", "Later", "k=later"],
        "written after the backup",
    )
    .await;
    d.secrets.lock().await.unwrap();
    // The current vault's password, yes to losing what came after the
    // backup, the recovery key, a new method (the password), and no new
    // recovery key.
    let (ok, _, err) = run(
        &d,
        &["restore", f],
        &format!("{PW}\ny\n{key}\np\n{PW}\nn\n"),
    )
    .await;
    assert!(ok && err.contains("The keyring is restored"), "{err}");
    // Secret Service clients see the restored items, and not the later one.
    let (ok, out, _) = run(&d, &["get", "k=kept"], "").await;
    assert!(ok && out.contains("in the backup"), "{out}");
    let (ok, _, _) = run(&d, &["get", "k=later"], "").await;
    assert!(!ok);
}

/// Restore says when there is nothing to do.
#[tokio::test(flavor = "multi_thread")]
async fn restore_says_when_there_is_nothing_to_do() {
    let d = daemon(true, vec![]).await;
    let (ok, _, err) = run(&d, &["restore"], "").await;
    assert!(!ok && err.contains("nothing to recover"), "{err}");
    let (ok, _, err) = run(&d, &["restore", "--accept-rollback"], "").await;
    assert!(!ok && err.contains("nothing to accept"), "{err}");
}
```

Apply this patch with `git apply` (save it as `/tmp/t5-tests.patch`):

```diff
--- a/crates/aleph-daemon/src/admin.rs
+++ b/crates/aleph-daemon/src/admin.rs
@@ -175,3 +175,43 @@
         })
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    /// A pipe (or a terminal, a socket) is never read as a backup: it
+    /// could hold a daemon thread until the other end closes.
+    #[test]
+    fn only_a_regular_file_is_read_as_a_backup() {
+        let (r, w) = std::io::pipe().unwrap();
+        drop(w);
+        let f = std::fs::File::from(OwnedFd::from(r));
+        assert!(read_backup(f).is_err());
+    }
+
+    /// A backup goes only into a new, empty regular file outside aleph's
+    /// directories (a hard link to the vault elsewhere is not empty).
+    #[test]
+    fn a_backup_target_must_be_empty_and_outside_aleph() {
+        let dir = tempfile::tempdir().unwrap();
+        let paths = Paths::under(&dir.path().join("aleph"));
+        std::fs::create_dir_all(&paths.data_dir).unwrap();
+        let outside = dir.path().join("backup");
+        std::fs::write(&outside, b"").unwrap();
+        let f = std::fs::OpenOptions::new()
+            .write(true)
+            .open(&outside)
+            .unwrap();
+        assert!(check_backup_target(&paths, &f).is_ok());
+        std::fs::write(&outside, b"a vault").unwrap();
+        assert!(check_backup_target(&paths, &f).is_err());
+        let inside = paths.data_dir.join("copy");
+        std::fs::write(&inside, b"").unwrap();
+        let f = std::fs::OpenOptions::new()
+            .write(true)
+            .open(&inside)
+            .unwrap();
+        assert!(check_backup_target(&paths, &f).is_err());
+    }
+}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon --lib admin`
Expected: the build fails: `read_backup` and `check_backup_target` do not exist yet. (`cargo test -q -p aleph-cli --test cli` also fails: `aleph` has no `backup` or `restore` command yet.)

- [ ] **Step 3: Implement**

Write `crates/aleph-cli/Cargo.toml`:

```toml
[package]
name = "aleph-cli"
description = "aleph: the command-line client for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "aleph"
path = "src/main.rs"

[dependencies]
aleph-prompt-proto = { path = "../aleph-prompt-proto" }
clap = { version = "4", features = ["derive"] }
clap_complete = "4"
libc.workspace = true
rpassword = "7"
serde.workspace = true
serde_json.workspace = true
tokio = { version = "1", features = ["rt", "macros"] }
zbus = { version = "5", default-features = false, features = ["tokio"] }
zeroize.workspace = true

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-daemon = { path = "../aleph-daemon", features = ["testing"] }
tempfile.workspace = true
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Apply this patch with `git apply` (save it as `/tmp/t5-impl.patch`):

```diff
--- a/crates/aleph-daemon/src/admin.rs
+++ b/crates/aleph-daemon/src/admin.rs
@@ -40,6 +40,59 @@
 fn slot_id(id: &str) -> zbus::fdo::Result<Uuid> {
     Uuid::try_parse(id)
         .map_err(|_| zbus::fdo::Error::InvalidArgs(format!("not a keyslot id: {id:?}")))
+}
+
+/// The largest backup file read (a vault this size holds a great deal).
+const MAX_BACKUP: u64 = 64 * 1024 * 1024;
+
+/// A restore file's bytes: a regular file only (a pipe, terminal, or socket
+/// could hold the reading thread indefinitely), at most `MAX_BACKUP`.
+fn read_backup(file: std::fs::File) -> zbus::fdo::Result<Vec<u8>> {
+    use std::io::Read;
+    if !file.metadata().map_err(failed)?.is_file() {
+        return Err(zbus::fdo::Error::InvalidArgs(
+            "a backup is read only from a regular file".into(),
+        ));
+    }
+    let mut bytes = Vec::new();
+    file.take(MAX_BACKUP + 1)
+        .read_to_end(&mut bytes)
+        .map_err(failed)?;
+    if bytes.len() as u64 > MAX_BACKUP {
+        return Err(zbus::fdo::Error::InvalidArgs(
+            "that file is too large to be a backup".into(),
+        ));
+    }
+    Ok(bytes)
+}
+
+/// Refuse a backup target that is not a new (empty) regular file, or lies
+/// inside aleph's data or state directory. (A hard link to the vault
+/// elsewhere is not empty.)
+fn check_backup_target(paths: &Paths, file: &std::fs::File) -> zbus::fdo::Result<()> {
+    use std::os::fd::AsRawFd;
+    let meta = file.metadata().map_err(failed)?;
+    if !meta.is_file() {
+        return Err(zbus::fdo::Error::InvalidArgs(
+            "the backup target is not a regular file".into(),
+        ));
+    }
+    if meta.len() != 0 {
+        return Err(zbus::fdo::Error::InvalidArgs(
+            "the backup target is not empty (a backup goes only into a new file)".into(),
+        ));
+    }
+    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(failed)?;
+    for dir in [&paths.data_dir, &paths.state_dir] {
+        let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
+        if path.starts_with(&dir) {
+            return Err(zbus::fdo::Error::InvalidArgs(format!(
+                "a backup cannot go inside {}",
+                dir.display()
+            )));
+        }
+    }
+    Ok(())
 }
 
 impl Admin {
@@ -141,6 +194,57 @@
         prompter: zbus::zvariant::OwnedFd,
     ) -> zbus::fdo::Result<()> {
         self.converse(prompter, |k, chan| k.reissue_recovery(chan))
+    }
+
+    /// Recover the current vault with the recovery key (`aleph restore`).
+    async fn recover(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
+        self.converse(prompter, |k, chan| k.recover(chan, None))
+    }
+
+    /// Restore the backup file `file` (opened by the caller) with its
+    /// recovery key (`aleph restore <file>`).
+    async fn restore_backup(
+        &self,
+        prompter: zbus::zvariant::OwnedFd,
+        file: zbus::zvariant::OwnedFd,
+    ) -> zbus::fdo::Result<()> {
+        let file = std::fs::File::from(OwnedFd::from(file));
+        let bytes = tokio::task::spawn_blocking(move || read_backup(file))
+            .await
+            .map_err(failed)??;
+        self.converse(prompter, move |k, chan| k.recover(chan, Some(&bytes)))
+    }
+
+    /// Replace an unreadable vault file with its backup copy
+    /// (`aleph restore --from-bak`).
+    async fn restore_from_bak(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
+        self.converse(prompter, |k, chan| k.restore_from_bak(chan))
+    }
+
+    /// Accept a rolled-back, replaced, or different vault file
+    /// (`aleph restore --accept-rollback`).
+    async fn accept_rollback(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
+        self.converse(prompter, |k, chan| k.accept_rollback(chan))
+    }
+
+    /// Write a backup into `file`, which the caller opened: a regular file
+    /// outside aleph's own directories (a backup over the live vault would
+    /// leave only the recovery slot).
+    async fn backup(
+        &self,
+        prompter: zbus::zvariant::OwnedFd,
+        file: zbus::zvariant::OwnedFd,
+    ) -> zbus::fdo::Result<()> {
+        let file = std::fs::File::from(OwnedFd::from(file));
+        check_backup_target(&self.paths, &file)?;
+        self.converse(prompter, move |k, chan| {
+            k.backup(chan, |bytes| {
+                use std::io::Write;
+                (&file).write_all(bytes)?;
+                file.sync_all()?;
+                Ok(())
+            })
+        })
     }
 
     /// Clear a keyslot's stale mark so it is tried again.
--- a/crates/aleph-cli/src/client.rs
+++ b/crates/aleph-cli/src/client.rs
@@ -56,6 +56,8 @@
     Str(&'a str),
     Bool(bool),
     Str2(&'a str, &'a str),
+    /// A file the daemon reads or writes (passed as a descriptor).
+    File(std::fs::File),
 }
 
 pub struct Client {
@@ -149,6 +151,10 @@
             Args::Str(a) => admin.call_method(method, &(fd, a)).await,
             Args::Bool(b) => admin.call_method(method, &(fd, b)).await,
             Args::Str2(a, b) => admin.call_method(method, &(fd, a, b)).await,
+            Args::File(f) => {
+                let f = zbus::zvariant::OwnedFd::from(OwnedFd::from(f));
+                admin.call_method(method, &(fd, f)).await
+            }
         }
         .map_err(|e| format!("cannot reach alephd: {e}"))?;
         tokio::task::spawn_blocking(move || prompter::converse(ours, &mut Terminal::new()))
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -38,6 +38,23 @@
     Keyslot(KeyslotCmd),
     #[command(subcommand)]
     Recovery(RecoveryCmd),
+    /// Write a backup (only the recovery slot: it opens with the recovery key).
+    Backup {
+        path: std::path::PathBuf,
+        /// Replace an existing file.
+        #[arg(long)]
+        force: bool,
+    },
+    /// Recover with the recovery key: this vault, or a backup file.
+    Restore {
+        path: Option<std::path::PathBuf>,
+        /// Replace an unreadable vault file with its backup copy.
+        #[arg(long, conflicts_with_all = ["path", "accept_rollback"])]
+        from_bak: bool,
+        /// Accept a rolled-back, replaced, or different vault file as current.
+        #[arg(long, conflicts_with = "path")]
+        accept_rollback: bool,
+    },
     /// Print the secret of the item matching attr=value pairs.
     Get {
         attributes: Vec<String>,
@@ -229,6 +246,24 @@
         },
         Cmd::Recovery(RecoveryCmd::Reissue) => {
             outcome(c.converse("ReissueRecoveryKey", Args::None).await?)?
+        }
+        Cmd::Backup { path, force } => backup(&c, &path, force).await?,
+        Cmd::Restore {
+            path,
+            from_bak,
+            accept_rollback,
+        } => {
+            let result = match (path, from_bak, accept_rollback) {
+                (Some(p), _, _) => {
+                    let file =
+                        std::fs::File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
+                    c.converse("RestoreBackup", Args::File(file)).await?
+                }
+                (None, true, _) => c.converse("RestoreFromBak", Args::None).await?,
+                (None, _, true) => c.converse("AcceptRollback", Args::None).await?,
+                (None, false, false) => c.converse("Recover", Args::None).await?,
+            };
+            outcome(result)?
         }
         Cmd::Get { attributes: pairs } => {
             let attrs = attributes(&pairs)?;
@@ -328,6 +363,51 @@
     Ok(ExitCode::SUCCESS)
 }
 
+/// `aleph backup`: the CLI creates the file (never following a symlink,
+/// never replacing one without `--force`, which writes a temporary file and
+/// renames it over the target once the daemon is done) and passes it.
+async fn backup(c: &Client, path: &std::path::Path, force: bool) -> Result<()> {
+    use std::os::unix::fs::OpenOptionsExt;
+    let target = if force {
+        let name = path
+            .file_name()
+            .ok_or("the backup path has no file name")?
+            .to_string_lossy();
+        path.with_file_name(format!(".{name}.aleph-tmp"))
+    } else {
+        path.to_path_buf()
+    };
+    let file = std::fs::OpenOptions::new()
+        .write(true)
+        .create_new(true)
+        .mode(0o600)
+        .custom_flags(libc::O_NOFOLLOW)
+        .open(&target)
+        .map_err(|e| {
+            if force && e.kind() == std::io::ErrorKind::AlreadyExists {
+                format!(
+                    "{}: left by an interrupted `aleph backup --force`; remove it and try again",
+                    target.display()
+                )
+            } else {
+                format!("{}: {e}", target.display())
+            }
+        })?;
+    let result = c.converse("Backup", Args::File(file)).await;
+    let ok = matches!(&result, Ok(o) if o.ok);
+    if force && ok {
+        std::fs::rename(&target, path).map_err(|e| format!("{}: {e}", path.display()))?;
+    } else if !ok {
+        let _ = std::fs::remove_file(&target);
+    }
+    outcome(result?)?;
+    eprintln!(
+        "aleph: note: copies of ~/.local/share/aleph made any other way hold every keyslot \
+         (including a login-password slot on machines without a TPM); `aleph backup` holds only the recovery slot"
+    );
+    Ok(())
+}
+
 fn term_line(term: &mut prompter::Terminal, prompt: &str) -> Result<String> {
     term.line(prompt).map_err(|e| e.to_string())
 }
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 1 passed | ok. 10 passed | ok. 34 passed | ok. 3 passed | ok. 19 passed | ok. 51 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **a backup cannot go inside aleph's directories** (`crates/aleph-daemon/src/admin.rs`), test `cargo test -p aleph-cli --test cli backup_and_restore_through_the_cli`: replace `if path.starts_with(&dir) {` with `if false {`.
- **a plain restore of a vault in order is refused** (`crates/aleph-daemon/src/keyring/custody.rs`), test `cargo test -p aleph-cli --test cli restore_says_when_there_is_nothing_to_do`: replace `if !self.is_locked() && lock(&self.inner).untrusted.is_none() {` with `if false {`.
- **only a regular file is read as a backup** (`crates/aleph-daemon/src/admin.rs`), test `cargo test -p aleph-daemon --lib only_a_regular_file_is_read`: replace `if !file.metadata().map_err(failed)?.is_file() {` with `if false {`.
- **a backup goes only into an empty file** (`crates/aleph-daemon/src/admin.rs`), test `cargo test -p aleph-daemon --lib a_backup_target_must_be_empty`: replace `if meta.len() != 0 {` with `if false {`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-daemon crates/aleph-cli
git commit -m "feat(cli): aleph backup and aleph restore" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 6: spec, docs, decisions

**Interfaces:**
- Consumes: everything above (documentation only).

- [ ] **Step 1: Update the documents**

Apply this patch with `git apply` (save it as `/tmp/t6-docs.patch`):

~~~~diff
--- a/docs/superpowers/specs/2026-09-26-aleph-design.md
+++ b/docs/superpowers/specs/2026-09-26-aleph-design.md
@@ -176,6 +176,15 @@
 - If `vault.aleph` fails to parse or authenticate and `vault.aleph.bak`
   opens, `alephd` does not switch over automatically. It reports the
   problem and offers `aleph restore --from-bak`.
+- A file that a restore or `--from-bak` replaces is kept as
+  `vault.aleph.replaced-<time>` (or `.corrupt-<time>` if it could not be
+  read), never deleted. It is linked under that name before the write,
+  so a crash in between leaves it in place as `vault.aleph`. `.bak` is
+  kept the same way (`vault.aleph.bak-<time>`) before every custody
+  write, since the write replaces it and it may be the only good copy.
+  Kept files still open with the old recovery key and the old unlock
+  methods; `aleph` names them and says to delete them once the keyring
+  has been checked.
 
 ### Layout
 
@@ -219,6 +228,18 @@
 - **Higher `generation` with a different `mk_id`:** MK changed somewhere
   other than this daemon, or someone holding an old MK is replaying it
   under a forged generation (`Rekeyed`). Same handling.
+
+`alephd` also records the ID of the vault this machine uses
+(`$XDG_STATE_HOME/aleph/vault-id`, written at create and restore, or at
+the first unlock if missing). A vault with a different ID at the path is
+not trusted, with the same handling, even with no mark for its ID. (A
+crash between a restore's write and recording its ID makes the next
+unlock report a different vault; `aleph restore --accept-rollback`
+settles it.)
+
+A restore or an acceptance writes the vault at generation
+`max(recorded, found) + 1`, so the mark is never lowered and every older
+copy stays detectable.
 
 Only the daemon's own writes move the mark to a new MK. The daemon writes
 with `write_recorded`, which notes the intended mark before the rename
@@ -689,7 +710,7 @@
   ```
 
 - **Which services get them**, with setup editing each and keeping a
-  backup (Plan 4b; by hand until then, `docs/testing.md`):
+  backup (Plan 4c; by hand until then, `docs/testing.md`):
 
   | Service | Change |
   |---|---|
@@ -773,8 +794,9 @@
   whether MK is `mlock`ed, TPM usability, keyslots with stale marks),
   `Lock`, `Unlock`, `Create`, `EnrollTpm`, `EnrollFido2`,
   `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`, `RetryKeyslot`,
-  `GetConfig`, `SetConfig`, and (Plan 4b) `ImportGnomeKeyring`,
-  `ExportToGnomeKeyring`, `Backup`, `Restore`.
+  `GetConfig`, `SetConfig`, (Plan 4b) `Backup`, `Recover`,
+  `RestoreBackup`, `RestoreFromBak`, `AcceptRollback`, and (Plan 4c)
+  `ImportGnomeKeyring`, `ExportToGnomeKeyring`.
 - **Methods that need the user take a prompter:** one end of a
   socketpair, passed as a Unix fd, speaking the prompter protocol. The
   CLI answers it in the terminal, `aleph-gui` in its windows. The call
@@ -823,7 +845,7 @@
   directed signal). Omarchy's own lock (`omarchy-system-lock`, a Quickshell
   session lock, used by its idle service and key binding) does not tell
   logind, so on Omarchy the vault does not yet lock with the screen. How
-  setup wires it is Plan 4b's to decide (DECISIONS.md D13); until then,
+  setup wires it is Plan 4c's to decide (DECISIONS.md D13, F1); until then,
   bind `aleph lock` next to the lock, or use `lock.idle_timeout`.
 - **Idle:** no secret read or written for `idle_timeout` seconds.
 - Without a system bus or logind, `alephd` runs without the sleep and
@@ -877,7 +899,7 @@
 aleph import gnome-keyring
 aleph export gnome-keyring
 aleph config get|set <key> [value]
-aleph backup <path>
+aleph backup [--force] <path>
 aleph restore [--from-bak | --accept-rollback] [<path>]
 ```
 
@@ -894,7 +916,7 @@
   6. system changes (sudo)
 
   Plan 3 implements steps 1, 2, and 4 (creating the vault) and says that
-  the rest is not available yet; Plan 4b adds 3, 5, and 6.
+  the rest is not available yet; Plan 4c adds 3, 5, and 6.
 - **Import** reads every collection and item through the Secret Service
   API while gnome-keyring still owns the bus name. That covers everything
   shown in Seahorse's Passwords view.
@@ -902,10 +924,38 @@
   the recovery slot**, with its MK wrap. It also warns that generic backups
   of `~/.local/share/aleph/` contain every slot, including
   `login-password` on machines without a TPM.
+- **`aleph backup <path>`** needs re-authentication. The CLI creates the
+  file (new, mode `0600`, never following a symlink; with `--force`, a
+  temporary file renamed over `<path>` once the backup is written) and
+  hands the descriptor to `alephd`, which writes to it only if it is an
+  empty regular file outside aleph's data and state directories; the
+  daemon never opens a path it was given, and reads a restore file only
+  if it is a regular file.
 - **`aleph restore`** goes through `alephd`. The daemon opens the backup
-  with the recovery key, rotates MK, drops slots from the old machine,
-  enrolls this machine's slots, resets the high-water mark, and writes the
-  result.
+  (a descriptor, as above), or with no path the current vault (or `.bak`
+  if the vault cannot be read), with the recovery key. It keeps only the
+  recovery slot, enrolls one fresh unlock method for this machine,
+  rotates MK, writes the result past every recorded generation (§4), and
+  offers a new recovery key. A plain `restore` is refused while the
+  vault is unlocked and trusted.
+- **Proof.** Recovering the vault this machine expects needs only its
+  recovery key. Anything else that replaces the vault (a backup, or a
+  file that is not the expected vault) needs proof, so a same-user
+  process holding an old backup and its recovery key cannot swap it in:
+  the expected vault's method (re-authentication while it is unlocked,
+  or opening it; a corrupt one whose slot opens counts), or, where the
+  expected vault is missing, unreadable, or not the file there, the login
+  password checked with PAM, since a planted vault's own methods prove
+  nothing. Only a machine with no vault and none expected needs no proof.
+- An **older backup of the same vault** is restored only after a
+  question naming both generations and saying that anything written
+  since the backup is not in it (Enter says no).
+- **`aleph restore --from-bak`** replaces the vault with `.bak`, opened
+  with the normal methods; a `.bak` that is not the expected vault also
+  needs the login password. **`aleph restore --accept-rollback`**
+  accepts the unlocked, untrusted vault as current, after
+  re-authentication (plus the login password for a vault that is not the
+  expected one) and an explicit yes naming what is accepted.
 
 ### GUI (`aleph-gui`, eframe/egui)
 
--- a/docs/testing.md
+++ b/docs/testing.md
@@ -127,7 +127,7 @@
    stored for the user ("Store the password only for this user"), lock,
    reconnect, and unlock when asked: the connection must come up without
    asking for the Wi-Fi password again.
-6. **Login and screen unlock** (Plan 4a; setup's PAM edits come in 4b, so
+6. **Login and screen unlock** (Plan 4a; setup's PAM edits come in 4c, so
    by hand for now, keeping backups):
    - `install -Dm755 target/debug/libpam_aleph.so /usr/lib/security/pam_aleph.so`
    - `/etc/pam.d/sddm`: `-auth optional pam_aleph.so` after `auth include
@@ -152,6 +152,26 @@
    `aleph keyslot rotate-master`); suspend and resume (locked).
 7. `aleph status` shows the keyslots; `journalctl --user` (or the
    terminal) shows no secrets.
+8. **Backup and restore** (Plan 4b):
+   - `aleph backup ~/aleph.bak` (re-authenticate): the file is mode
+     `0600`, and running it again refuses to overwrite it.
+   - On a second test account (or after moving `~/.local/share/aleph/`
+     and `~/.local/state/aleph/` aside), `aleph restore ~/aleph.bak`: type
+     the recovery key, choose an unlock method, and decline or accept a
+     new recovery key. `secret-tool lookup service aleph-check` prints the
+     secret; `aleph status` shows one unlock method and the recovery slot.
+   - Back on the first account, copy an older `vault.aleph` over the
+     current one (daemon stopped): the next unlock reports a rollback and
+     `aleph status` says writes are refused. `aleph restore
+     --accept-rollback` accepts it, after re-authentication, keeping the
+     previous `.bak` as `vault.aleph.bak-<time>`.
+   - Truncate `vault.aleph` (daemon stopped): `aleph restore --from-bak`
+     brings back the previous version, keeping the broken file as
+     `vault.aleph.corrupt-<time>`.
+   - Move `vault.aleph` away (daemon stopped) and `aleph restore` another
+     account's backup: it asks for the login password before the recovery
+     key. Delete the kept `vault.aleph.*-<time>` files afterwards (they
+     still open with the old recovery key).
 
 Record the results, and the libsecret, Chromium, and NetworkManager
 versions, in `hardware-log.md`.
--- a/README.md
+++ b/README.md
@@ -14,11 +14,13 @@
 
 Login and screen unlock (`pam_aleph`), `passwd` changes, and locking on
 sleep, screen lock, or idle are in place (Plan 4a). `aleph setup` does not
-yet edit PAM, take over from gnome-keyring, or import its items (Plan 4b):
+yet edit PAM, take over from gnome-keyring, or import its items (Plan 4c):
 see [docs/testing.md](docs/testing.md) for the lines to add by hand. If
 the login password is changed outside aleph, the next unlock asks for the
-previous one to update the TPM keyslot. Design decisions made along the
-way are in [DECISIONS.md](DECISIONS.md).
+previous one to update the TPM keyslot. `aleph backup` and `aleph restore`
+(with the recovery key, from `.bak`, or accepting a rolled-back file) are
+in place (Plan 4b). Design decisions made along the way are in
+[DECISIONS.md](DECISIONS.md).
 
 ## Crates
 
--- a/DECISIONS.md
+++ b/DECISIONS.md
@@ -5,6 +5,82 @@
 session with the spec and the code, and no part in writing them). Newest
 first. The spec (`docs/superpowers/specs/2026-09-26-aleph-design.md`)
 is updated to match wherever a decision changes it.
+
+## 2026-09-27: Plan 4b split into custody (4b) and setup (4c)
+
+### F2. The pre-execution review of the Plan 4b document: fixes adopted
+
+Two critical and three important findings, each fixed with a test that
+failed first:
+- **E7's proof could be skipped.** Moving the vault away, planting a
+  vault (or a `.bak`) whose only method was the planter's own password,
+  or restoring while unlocked with the file gone, let a same-user process
+  holding a backup and its recovery key swap it in. Proof now comes only
+  from the vault this machine expects (re-authentication, or opening it),
+  or else from the login password checked with PAM; a planted vault's
+  methods prove nothing, for `restore`, `--from-bak`, and
+  `--accept-rollback` alike.
+- **Custody writes could destroy `.bak`**, sometimes the only good copy
+  (a rotation's write removes it; `--from-bak` and an acceptance replace
+  it). `.bak` is now kept aside by a hard link before every custody
+  write.
+- **Two kept copies in the same second** collided, and the copy fallback
+  wrote into the first (the old vault's own file). Names now take a
+  `-<n>` suffix, and the fallback copies only into a new file, synced.
+- **A restore file was read on the async runtime from any descriptor**
+  (a pipe could hold a worker). Only a regular file is read, off the
+  runtime.
+- **Tests** for the Review Focus lines that lacked them: a file that is
+  not a backup, a symlink and a refused overwrite, an older backup of the
+  same vault, clients seeing the restored items, and a corrupt vault
+  replaced after its slot opened; the plan's mappings are corrected.
+
+Minor fixes adopted: kept files are named in the result, with a warning
+that they still open with the old recovery key and methods; an older
+backup of the same vault asks first, naming both generations; a backup
+goes only into an empty file (a hard link to the vault elsewhere is
+refused), and a stale `--force` temporary file is named. The crash
+window between a restore's write and recording its ID is documented
+(the next unlock asks for `--accept-rollback`).
+
+
+### F1. Plan 4b is custody only; setup's system changes become Plan 4c — Accepted with changes
+
+- **4b, custody:** `aleph restore` with the recovery key (from a backup,
+  the current vault, or its `.bak`), `--from-bak`, `--accept-rollback`,
+  and `aleph backup` (E7, E8, and their tests from E11). Nothing outside
+  the user's own files; no root, no gnome-keyring.
+- **4c, setup:** import and export (E1, E2), switchover and revert (E3,
+  E9), PAM changes (E4–E6), step checks (E10), the wizard, explaining
+  lockoutAuth (D9), and how Omarchy's screen lock reaches alephd (D13).
+  4c has daemon tasks of its own: E1's queued import and E3's write
+  freeze touch the keyring engine and the Admin interface.
+
+Custody depends on nothing in 4c: the vault-id file is written at create,
+at restore, and at the first unlock of a vault without one, never by
+setup. 4c depends on custody: its emergency-revert docs name `aleph
+restore` and `--from-bak`. Restore is not what protects a login from a
+bad PAM edit (the `-` prefix, `optional`, E4's verify-and-roll-back, and
+the TTY are); it helps when a bad switchover leaves the vault unreachable
+by its methods.
+
+Changes adopted:
+- `Confirm` carries the answer Enter gives, so the new-recovery-key offer
+  defaults to yes and everything else (accepting a rollback included)
+  to no, as E7 says; the terminal shows `[Y/n]` or `[y/N]`.
+- A test pins that a vault with no vault-id file gets one at unlock.
+- The GUI's "Recover…" belongs to the GUI plan; `aleph restore` is the
+  only recovery path until then.
+- The spec's Admin method list and setup-step numbering now say 4c
+  where setup is meant.
+
+Also added while preparing 4b:
+- A restore that finishes after the pre-sleep lock writes nothing and
+  fails with "going to sleep", the counterpart of D13's rule for unlocks.
+- The file a restore replaces is kept by a hard link made before the
+  write (a copy where links fail), not moved away first: a crash between
+  the two leaves the old vault in place, where a rename would have left
+  no vault at all, and a later `setup` would have created an empty one.
 
 ## 2026-09-27: Plan 4b (custody and setup), design
 
@@ -175,7 +251,8 @@
 
 ### E12. Task list
 
-Nine tasks, with the additions above. The switchover-and-revert task and
+Nine tasks, with the additions above. (Split by F1: custody is Plan 4b,
+the rest Plan 4c.) The switchover-and-revert task and
 the wizard task are separate, and the docs task adds an emergency
 manual-revert section.
 
@@ -194,7 +271,8 @@
   setup's system changes and `setup --revert`, and lockoutAuth.
 
 4b's setup installs the PAM lines 4a's module needs. Until then, 4a's docs
-give the lines to add by hand, marked provisional.
+give the lines to add by hand, marked provisional. (Setup later moved to
+Plan 4c: F1.)
 
 ### D2. `passwd` without FIDO2 slots rotates MK; with them, it keeps MK and marks a rotation pending — Accepted with changes
 
~~~~

- [ ] **Step 2: Run the tests, clippy, and fmt**

Run: `cargo test -q && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 1 passed | ok. 10 passed | ok. 59 passed | ok. 1 passed | ok. 29 passed | ok. 11 passed | ok. 1 passed | ok. 34 passed | ok. 3 passed | ok. 19 passed | ok. 51 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed | ok. 3 passed | ok. 3 passed | ok. 6 passed | ok. 5 passed | ok. 21 passed | ok. 5 passed | ok. 2 passed | ok. 23 passed | ok. 9 passed | ok. 7 passed | ok. 6 passed | ok. 3 passed | ok. 1 passed.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-09-26-aleph-design.md docs/testing.md README.md DECISIONS.md
git commit -m "docs: spec, testing, README, and decisions for custody" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
