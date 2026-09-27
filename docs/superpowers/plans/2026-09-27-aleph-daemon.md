# alephd and the aleph CLI Implementation Plan (Plan 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `alephd`, the keyring daemon (the freedesktop Secret Service plus the `io.aleph.Admin1` interface, unlocking with the TPM, a FIDO2 key, or the login password), and `aleph`, the command-line client.

**Architecture:**
- **`aleph-daemon`** (bin `alephd`) owns the vault file and its lock state.
  - Its keyring engine unlocks through a *prompter*: a peer on a socketpair speaking newline-delimited JSON (`aleph-prompt-proto`). The engine enrolls and removes keyslots, rotating the master key and re-proving every remaining slot, and refuses writes to a rolled-back file.
  - A typed login password is checked with PAM before it reaches the TPM, so typos never spend the TPM's dictionary-attack budget.
  - The Secret Service is served on `zbus`. While locked, a search returns a placeholder that libsecret unlocks, and unlock prompts wait (never time out, never block a call).
  - Admin methods take the caller's prompter as a Unix fd and return at once; the outcome arrives on the prompter.
- **`aleph-cli`** (bin `aleph`) is a thin client: admin calls with a terminal prompter, and item commands over the Secret Service.

**Tech Stack:** Rust 1.98, `zbus` 5 (tokio), `tokio` 1, libpam (declared directly), `aes`/`cbc`/`num-bigint` (the DH session libsecret needs), `clap` 4, `rpassword` 7, `tracing` with journald. Tests need `dbus-daemon`, `secret-tool` (libsecret 0.21), `swtpm`, and Linux-PAM ≥ 1.4.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` revision 2 (§4 "Locked search", "Memory hygiene"; §5 unlock order and rate limiting; §6 daemon; §7 CLI). Task 8 updates the spec with what prototyping this plan settled.

**Plan series:** 1 core, 1b core revision 2, 2 aleph-tpmd + aleph-unlock (all done) → **3 alephd + CLI (this plan)** → 4 session integration (PAM module, lock policy, setup's system changes, import/export, backup/restore) → 5 `aleph-gui` → 6 packaging and CI.

**Prerequisites** (once per machine): `sudo pacman -S --needed swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.

## Decisions made while prototyping

Every task was prototyped, then replayed from this document on a fresh clone of `master`: red, then green, then clippy and fmt clean, with the final tree identical to the prototype. The properties below were each checked by reverting them (Step 5 of the owning task).

- **Typed passwords are checked with PAM before the TPM.** The real TPM on the development machine has a 7200 s recovery time, so with Plan 2's per-uid pacing two typos would block TPM unlock for up to 4 hours (`docs/hardware-log.md`). `alephd` checks a typed password with the PAM service `aleph-check` (`pam_unix` only, no faillock; the file ships in `packaging/pam/`) and only offers one PAM accepts to the TPM. Typed attempts are also limited to 5 per minute.
  - libpam is declared directly (about 70 lines): the binding crates need bindgen, whose libclang loading clashes with `tss-esapi`'s in the same workspace.
  - Tests run real PAM through `pam_start_confdir` with a private service directory: `pam_unix` rejecting a wrong password, and the shipped file itself.
  - A missing service file is `PasswordCheckUnavailable`, never "wrong password" (PAM would fall back to `other`, which denies everything).
- **Stale slots.** Only `TpmAuthFailed`/`TpmWrongUser` mark a TPM slot stale (kept in `$XDG_STATE_HOME/aleph/slots.json`, since it changes while locked); stale slots are not offered; `aleph keyslot retry` clears the mark.
- **Locked search: a placeholder, not an error.** Answering `IsLocked` was tested first: libsecret 0.21.7's `secret-tool lookup` reported an error and never unlocked, which a client like Chromium could take as "no key". Now a locked `SearchItems` returns a placeholder item in its `locked` list; libsecret unlocks it, and the prompt's result lists the items the search really finds.
- **Unlock prompts wait.** With no prompter (no graphical session; `aleph-gui` is Plan 5), an unlock prompt is not dismissed: it completes when the vault is unlocked some other way (`aleph unlock`, or PAM in Plan 4).
- **A dismissed prompt carries a typed empty result** (`ao` for an unlock): libsecret checks the type even on dismissal, and with `s` it hit an internal GTask bug and hung.
- **`Item.GetSecret` returns one struct argument**, `((oayays))`: zbus sends a returned tuple as several arguments, which libsecret rejects, so it returns a 1-tuple.
- **Admin methods take the caller's prompter** (a Unix fd) and return at once; the outcome arrives as `Done`. No call waits for the user or meets a bus reply timeout, and secrets never travel in D-Bus bodies. The CLI's terminal prompter and (Plan 5) the GUI use the same protocol, which lives in its own crate, `aleph-prompt-proto`, so the CLI does not link the daemon.
- **Concurrency.** Reads take only a briefly held state lock, so they never wait for a prompt; conversations are serialized separately; the hardware (TPM, FIDO2, PAM) lock is always taken before the state lock, and `Status` only *tries* it (`tpm: null` when busy).
- **Rotation re-proves every slot** (spec §4): the re-authentication password unseals TPM slots and derives login-password KEKs; each FIDO2 key needs its touch (cancelling one key's wait skips it); slots that cannot be presented are removed only after the user confirms. A change that would leave only the recovery slot is refused (`LastMethod`).
- **A failed write never leaves memory ahead of the file.** Body edits are rolled back from a snapshot; a failed keyslot write locks the vault (the next unlock reads the disk).
- **`retry_after`** now travels with `RateLimited` (seconds until the oldest failure leaves the window) and `Exhausted` (an upper bound; `None` = waiting will not help) and is shown in the prompter.
- **`fido2::present`** (a no-touch preflight) lets the daemon ask the right key's PIN before the touch; `Libfido2Keys` is `Send` so the daemon can keep it behind a mutex.
- **`mlock` is reported.** Core records whether MK's page was locked (`UnlockedVault::memory_locked`); `aleph status` warns if not.
- **`aleph setup` in this plan** creates the vault only (TPM + login password by default when the TPM is usable, else login password or a FIDO2 key; recovery key shown once and confirmed) and says that login unlock, the gnome-keyring switchover, and import are not available yet (Plan 4).
- **CLI scripting:** with `ALEPH_NO_TTY=1` each prompt answer is one line of standard input (the terminal takes the stdin lock per line; holding it deadlocked `setup`). End of input, or an empty secret, answers `Cancel`: never an empty password.
- **A plan review changed these** (each has a regression test and a Step 5 check):
  - **Rotations stop on TPM refusals that say nothing about the slot** (`Busy`, `RateLimited`, `Exhausted`, helper unavailable) instead of offering to drop a working slot; `reissue` also refuses to leave only the recovery slot. (Before, a brief `Busy` during `aleph recovery reissue` plus "yes" left a vault nothing in Plan 3 could unlock.) Every gathered KEK must unwrap MK before it counts; the confirmation says why each slot goes.
  - **TPM slots are tried newest first**, and the first `AuthFailed` with a PAM-accepted password marks it and all older TPM slots stale: one dictionary-attack failure, not one per slot. Rotation never unseals a stale slot.
  - **If PAM cannot check** (no service file, an account `pam_unix` cannot verify), the TPM slots are skipped but login-password slots are still tried. `enroll_tpm` seals only a password PAM accepts now.
  - **Conversations are bounded:** 10 answers at most, and `TooManyAttempts` ends one rather than re-asking at once (a prompter at end of input spun the daemon and held its operation lock).
  - **A placeholder's query is captured when `Unlock` is called**, unknown `/search/` paths are dropped (never echoed as items), and `Lock` while already locked is a no-op: a redundant lock had closed a waiting `secret-tool`'s session and turned its lookup into "not found".
  - **A client's sessions and waiting prompts are freed when it disconnects** (`NameOwnerChanged`); waiting prompts are capped (8 per client, 128 in all) and a prompt starts once.
  - Minors: vault writes and `Status` run on blocking threads; Argon2 for rotation runs outside the state lock; `ItemCreated` comes from the collection's own path and a replacing `CreateItem` sends `ItemChanged`; `CollectionCreated`/`Deleted` are sent; `prompt.timeout` is capped at a day (a huge value made every conversation panic); `prompt.program` changes apply to the next prompt; prompter messages and DH secrets use zeroizing buffers; the CLI closes its sessions, refuses `get` without attributes, retries a search that raced a lock, and never matches an unknown slot's nil id; the spec documents libpam's `unix_chkpwd` fork and that item objects vanish while locked.
  - Deferred: the terminal prompter cannot skip one absent FIDO2 key during a rotation (Ctrl-C cancels the whole operation); the GUI prompter (Plan 5) offers "skip".
- **A second review changed these** (each with a regression test and a teeth check; the first review's untested claims now have tests too):
  - **Sessions outlive locks.** A real lock had closed every session, and libsecret keeps one session per process, so every long-lived client (nm-applet, Evolution, keytar) failed after each lock until restarted (confirmed with a Python `gi.Secret` client). Sessions hold only transport keys; they go on `Close`, disconnect, or exit (32 per client).
  - **Reissue shows the new recovery key last**, after everything that can fail (KEK gathering, the last-method check): the user never writes down a key that was not installed.
  - **Waiting prompts are answered only while unlocked** (a lock racing `unlocked()` had completed them with an empty, "not found" result).
  - **TPM slots only ever see a PAM-accepted password**, also in rotations (a login-password slot's password may be outdated); rotation also tries TPM slots newest first with the one-rejection rule, and ties within a second go to the later-added slot.
  - **Prompts are registered with their owner** and freed on disconnect (started or not), checked against a disconnect that raced their creation, and finish exactly once; while one unlock conversation runs, other unlock prompts wait for it instead of each opening a prompter.
  - **Wrong FIDO2 PINs: 3 per conversation** (each spends one of the key's lifetime retries).
  - The CLI reports a search that raced a lock as an error, not "not found"; the spec no longer says locking closes sessions.
- **Not in this plan:** `pam_aleph` and `pam.sock`, lock policy enforcement (suspend, screen lock, idle), setup's system changes and revert, import/export, backup/restore (all Plan 4); the GUI prompter (Plan 5). **Plan 4 must** guard `pam_aleph`'s socket writes against SIGPIPE (it runs inside another process), and its re-seal of a stale TPM slot must use the *old* password without the PAM check (knowingly spending one attempt).

## Global Constraints

- Rust stable 1.98, edition 2024; every crate `license = "Apache-2.0"`.
- Only `aleph-tpmd` opens the TPM; the daemon uses `aleph_unlock::TpmClient`.
- **Exact names and paths:**
  - bus names `org.freedesktop.secrets` and `io.aleph.Keyring`; admin object `/io/aleph/Admin`, interface `io.aleph.Admin1`
  - Secret Service paths `/org/freedesktop/secrets/{collection/<uuid-simple>[/<uuid-simple>], aliases/<name>, session/s<n>, prompt/p<n>, search/q<n>}`
  - vault `$XDG_DATA_HOME/aleph/vault.aleph`, daemon lock `vault.aleph.daemon`, stale marks `$XDG_STATE_HOME/aleph/slots.json`, config `$XDG_CONFIG_HOME/aleph/config.toml`
  - PAM service `aleph-check`; prompter env `ALEPH_PROMPT_FD`; CLI scripting env `ALEPH_NO_TTY=1`
  - session algorithms `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7` (RFC 2409 group 2; HKDF-SHA-256, no salt, no info, 16 bytes; AES-128-CBC, PKCS#7, IV = parameters)
- No D-Bus method waits for the user. Secrets travel only in zeroizing types and over socketpairs, never in D-Bus bodies (except Secret Service secrets, which the spec's sessions carry), and are never logged (a lint test enforces this).
- Children are started only with `std::process::Command` (posix_spawn/exec), never a bare fork.
- `cargo fmt` default; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **A client asking for a secret while the vault is locked** (Chromium at startup, `secret-tool lookup`) must neither get a false "not found" nor fail: it must wait for an unlock (prompter, `aleph unlock`) and then get the secret, even if something locks again meanwhile; cancelling ends it cleanly. → Task 5 `a_locked_lookup_prompts_once_and_finds_the_secret`, `without_a_prompter_a_locked_lookup_waits_for_an_unlock_elsewhere`, `a_redundant_lock_does_not_strand_a_waiting_lookup`, `a_session_survives_lock_and_unlock`, `a_placeholder_query_is_captured_when_unlock_is_called`, `waiting_prompts_are_not_answered_while_locked`, `cancelling_the_prompt_ends_the_lookup_empty_handed`, `storing_while_locked_unlocks_first`.
2. **Typing the login password wrong** (even repeatedly) must never reach the TPM, and must be slowed, with the wait shown. → Task 4 `typos_never_reach_the_tpm`, `too_many_typos_are_refused_with_a_wait`; Task 3 `pam_rejects_a_wrong_password`, `the_shipped_service_file_checks_passwords`.
3. **A password changed outside aleph** must mark the TPM slots stale for one failed attempt in total, while refusals that say nothing about a slot (`Exhausted`, `RateLimited`, `Busy`) must not. → Task 4 `a_slot_that_rejects_the_current_password_goes_stale`, `stale_tpm_slots_cost_one_failure_and_rotation_skips_them`, `the_newest_tpm_slot_is_tried_first`, `a_rotation_offers_the_tpm_only_a_pam_accepted_password`, `an_exhausted_tpm_does_not_make_the_slot_stale`.
4. **Removing a keyslot, rotating, or reissuing the recovery key while a key is absent or the TPM is busy** must not silently drop a slot, must stop on a transient TPM refusal, and must never leave only the recovery key. → Task 4 `removing_a_slot_rotates_and_drops_absent_keys_only_on_confirmation`, `a_busy_tpm_stops_a_rotation_instead_of_dropping_the_slot`, `reissue_never_leaves_only_the_recovery_key`, `the_last_unlock_method_cannot_be_removed`, `the_last_recovery_slot_cannot_be_removed`.
5. **A slow, silent, or exhausted prompter, a long FIDO2 wait, or many clients** must not stall other callers or grow without bound: reads and `Status` answer at once, conversations end, sessions and waiting prompts are freed. → Task 4 `reads_do_not_wait_for_a_prompt`, `status_does_not_wait_while_a_key_is_awaited`, `too_many_typos_are_refused_with_a_wait`; Task 5 `sessions_are_freed_when_their_client_leaves`, `waiting_prompts_are_capped_and_dropped_with_their_client`, `a_prompt_runs_once`; Task 4 `wrong_pins_end_the_conversation_after_three`; Task 7 `end_of_input_cancels_instead_of_looping`.

## File Structure

```
crates/aleph-prompt-proto/src/lib.rs     prompter messages (ToPrompter, FromPrompter, Secret, Method, Purpose, Caller)
crates/aleph-daemon/
  Cargo.toml                             bin alephd; feature `testing`
  src/lib.rs, main.rs                    alephd: logging, backends, bus names, serve
  src/error.rs, paths.rs, config.rs      errors (user-facing), XDG paths, config.toml
  src/state.rs, store.rs                 stale marks; vault ownership (daemon lock, private dir, high-water)
  src/password.rs                        PAM check (libpam FFI), typed-attempt limiter
  src/prompt.rs                          Channel (daemon end), Launcher, ProgramLauncher, scripted prompter
  src/keyring.rs                         the engine: unlock, create, enroll, remove/rotate, reissue, status
  src/secret/{session,service}.rs        Secret Service sessions and objects
  src/admin.rs, daemon.rs                io.aleph.Admin1; putting it together
  src/testing.rs                         fixtures (feature `testing`): swtpm helper, keyring, bus, prompters, daemon
  tests/keyring.rs, secret_service.rs, admin.rs, logging.rs
crates/aleph-cli/src/main.rs, client.rs, prompter.rs; tests/cli.rs
packaging/pam/aleph-check, packaging/systemd/alephd.service, packaging/dbus/*.service
earlier crates: retry_after (tpm-proto, tpmd, unlock), fido2::present, Libfido2Keys: Send, memory_locked (core)
docs: spec (§3, §4, §5, §6, §7, §11), testing.md, README.md
```

---

### Task 1: groundwork in earlier crates

**Interfaces:**
- Produces:
  - `aleph_tpm_proto::Failure::{{RateLimited {{ retry_after: u32 }}, Exhausted {{ retry_after: Option<u32> }}}}`
  - `aleph_tpmd::limiter::RateLimiter::retry_after(uid, now, window) -> Duration`
  - `aleph_unlock::Error::{{TpmRateLimited {{ retry_after: Duration }}, TpmExhausted {{ retry_after: Option<Duration> }}}}`
  - `aleph_unlock::fido2::present(&mut dyn Keys, &Fido2Slot) -> Result<bool>`; `Libfido2Keys: Send`
  - `aleph_core::KeyHandle::memory_locked()`, `UnlockedVault::memory_locked() -> bool`

- [ ] **Step 1: Write the failing tests**

Apply this patch with `git apply` (save it as `/tmp/t1-tests.patch`):

```diff
--- a/crates/aleph-tpmd/tests/helper.rs
+++ b/crates/aleph-tpmd/tests/helper.rs
@@ -175,7 +175,12 @@
         );
     }
     // Blocked now, even with the right password: the TPM is not asked.
-    assert_eq!(attempt(PW, UID, t0), Response::Failed(Failure::RateLimited));
+    assert_eq!(
+        attempt(PW, UID, t0),
+        Response::Failed(Failure::RateLimited {
+            retry_after: window(600).as_secs() as u32
+        })
+    );
     // Another user is unaffected.
     let (other, _) = seal(&h, UID + 1, PW);
     assert!(matches!(
@@ -335,8 +340,11 @@
                         at,
                     );
                     match reply {
-                        Response::Failed(Failure::AuthFailed | Failure::RateLimited) => {}
-                        Response::Failed(Failure::Exhausted) => exhausted += 1,
+                        Response::Failed(Failure::AuthFailed | Failure::RateLimited { .. }) => {}
+                        // At the threshold, one recovery time frees a try.
+                        Response::Failed(Failure::Exhausted {
+                            retry_after: Some(600),
+                        }) => exhausted += 1,
                         other => panic!("max_tries {max_tries}: {other:?}"),
                     }
                 }
@@ -375,7 +383,10 @@
     for _ in 0..FAILURES_PER_UID {
         assert_eq!(attempt(), Response::Failed(Failure::WrongUser));
     }
-    assert_eq!(attempt(), Response::Failed(Failure::RateLimited));
+    assert!(matches!(
+        attempt(),
+        Response::Failed(Failure::RateLimited { .. })
+    ));
 }
 
 #[test]
@@ -450,7 +461,7 @@
                 secret: Secret(PW.to_vec())
             }
         ),
-        Response::Failed(Failure::Exhausted)
+        Response::Failed(Failure::Exhausted { retry_after: None })
     );
     sw.set_da_parameters(1, 0, 0);
     let (object, kek) = seal(&h, UID, PW);
--- a/crates/aleph-unlock/tests/tpm_client.rs
+++ b/crates/aleph-unlock/tests/tpm_client.rs
@@ -1,5 +1,6 @@
 use std::os::unix::net::UnixListener;
 use std::sync::Arc;
+use std::time::Duration;
 
 use aleph_core::{LockedVault, RecoveryKey, SlotKind, UnlockedVault};
 use aleph_tpmd::server::Policy;
@@ -78,7 +79,10 @@
     let sw = SwTpm::start();
     sw.set_da_parameters(1, 600, 86400);
     let h = helper_with(sw, Policy::allow_all());
-    assert!(matches!(h.client.seal(PW), Err(Error::TpmExhausted)));
+    assert!(matches!(
+        h.client.seal(PW),
+        Err(Error::TpmExhausted { retry_after: None })
+    ));
 
     // With the reserve reached (2 failures of 3, spent directly on the
     // TPM), unseals are refused before they reach it.
@@ -92,7 +96,7 @@
     let (_, slot) = h.client.seal(PW).unwrap();
     assert!(matches!(
         h.client.unseal(&slot, PW),
-        Err(Error::TpmExhausted)
+        Err(Error::TpmExhausted { retry_after: Some(d) }) if d == Duration::from_secs(600)
     ));
 
     // SAFETY: getuid has no preconditions.
--- a/crates/aleph-unlock/tests/fido2.rs
+++ b/crates/aleph-unlock/tests/fido2.rs
@@ -317,6 +317,26 @@
     ));
 }
 
+/// `present` tells which slot's key is plugged in, without a touch.
+#[test]
+fn present_finds_the_slots_key_without_a_touch() {
+    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
+    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
+    let touches = keys.devices[0].touches;
+    assert!(fido2::present(&mut keys, &slot).unwrap());
+    assert_eq!(keys.devices[0].touches, touches);
+    let mut other = MockKeys::one(MockAuthenticator::with_pin(PIN));
+    assert!(!fido2::present(&mut other, &slot).unwrap());
+    assert!(!fido2::present(&mut MockKeys::default(), &slot).unwrap());
+}
+
+/// Libfido2Keys can be kept by a daemon that serves requests on threads.
+#[test]
+fn libfido2_keys_can_move_between_threads() {
+    fn send<T: Send>() {}
+    send::<aleph_unlock::fido2::libfido2::Libfido2Keys>();
+}
+
 #[test]
 fn any_present_reflects_connected_keys() {
     assert!(!MockKeys::default().any_present());
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-tpmd -p aleph-unlock`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Apply this patch with `git apply` (save it as `/tmp/t1-impl.patch`):

```diff
--- a/crates/aleph-core/src/key.rs
+++ b/crates/aleph-core/src/key.rs
@@ -57,6 +57,8 @@
 struct LockedPage {
     page: *mut u8,
     len: usize,
+    /// Whether `mlock` succeeded (best effort; `aleph status` reports it).
+    mlocked: bool,
 }
 
 // SAFETY: the page is exclusively owned; it is only read through `&self`
@@ -90,14 +92,16 @@
         // best effort: failure (e.g. RLIMIT_MEMLOCK exhausted) is not fatal.
         // mlock is not inherited across fork, so WIPEONFORK gives a forked
         // child zeroes rather than an unlocked copy of the key.
-        unsafe {
-            libc::mlock(page, len);
+        let mlocked = unsafe {
+            let ok = libc::mlock(page, len) == 0;
             libc::madvise(page, len, libc::MADV_DONTDUMP);
             libc::madvise(page, len, libc::MADV_WIPEONFORK);
-        }
+            ok
+        };
         Ok(Self {
             page: page.cast(),
             len,
+            mlocked,
         })
     }
 
@@ -139,6 +143,12 @@
         let mut mk = LockedPage::new()?;
         crypto::fill_random(mk.key_mut())?;
         Ok(Self { mk })
+    }
+
+    /// Whether the master key's page is locked in RAM (`mlock` is best
+    /// effort, e.g. RLIMIT_MEMLOCK may forbid it).
+    pub fn memory_locked(&self) -> bool {
+        self.mk.mlocked
     }
 
     /// Wrap the master key for storage in a keyslot.
@@ -360,6 +370,13 @@
         );
     }
 
+    /// `memory_locked` reports what really happened to the page.
+    #[test]
+    fn memory_locked_reports_the_page_state() {
+        let k = KeyHandle::generate().unwrap();
+        assert_eq!(k.memory_locked(), locked_kib(key_addr(&k)) > 0);
+    }
+
     /// A forked child (the daemon spawning a prompter or swtpm) must not
     /// inherit a copy of the master key: its copy would not be mlocked.
     #[test]
--- a/crates/aleph-core/src/vault.rs
+++ b/crates/aleph-core/src/vault.rs
@@ -349,6 +349,11 @@
 
     pub fn vault_id(&self) -> Uuid {
         self.vault_id
+    }
+
+    /// Whether MK's page is locked in RAM (§4 "Memory hygiene").
+    pub fn memory_locked(&self) -> bool {
+        self.key.memory_locked()
     }
 
     pub fn keyslots(&self) -> impl Iterator<Item = &Keyslot> {
--- a/crates/aleph-tpm-proto/src/lib.rs
+++ b/crates/aleph-tpm-proto/src/lib.rs
@@ -96,8 +96,10 @@
     AuthFailed,
     #[error("the TPM is in dictionary-attack lockout")]
     Lockout,
-    #[error("too many failed attempts from this user; wait for the TPM's recovery time")]
-    RateLimited,
+    /// This uid used its failure budget; `retry_after` seconds until the
+    /// oldest failure leaves the window.
+    #[error("too many failed attempts from this user; retry in {retry_after} s")]
+    RateLimited { retry_after: u32 },
     /// Transient: this user already has a request in progress, or the
     /// helper is at its connection limit. Retry shortly.
     #[error("the TPM helper is busy; retry shortly")]
@@ -105,8 +107,11 @@
     /// The TPM's shared failure budget is spent (the rest is kept for
     /// disk unlock), or the TPM allows too few failures for aleph to use.
     /// Lasts until the TPM forgets failures, one per recovery time.
+    /// `retry_after` is an upper bound in seconds on when the TPM will have
+    /// forgotten enough failures; `None` means waiting will not help (the
+    /// TPM allows too few failures for aleph to use at all).
     #[error("the TPM is not accepting password attempts now; try later or use another method")]
-    Exhausted,
+    Exhausted { retry_after: Option<u32> },
     #[error("this user may not use the TPM helper (not a login uid)")]
     NotPermitted,
     #[error("this sealed object belongs to another user")]
@@ -223,9 +228,12 @@
         for f in [
             Failure::AuthFailed,
             Failure::Lockout,
-            Failure::RateLimited,
+            Failure::RateLimited { retry_after: 1200 },
             Failure::Busy,
-            Failure::Exhausted,
+            Failure::Exhausted {
+                retry_after: Some(7200),
+            },
+            Failure::Exhausted { retry_after: None },
             Failure::NotPermitted,
             Failure::WrongUser,
             Failure::ParentMismatch,
--- a/crates/aleph-tpmd/src/limiter.rs
+++ b/crates/aleph-tpmd/src/limiter.rs
@@ -49,6 +49,18 @@
             .is_some_and(|f| f.len() >= FAILURES_PER_UID)
     }
 
+    /// How long until `uid` may try again: until its oldest failure leaves
+    /// the window (zero if it is not blocked).
+    pub fn retry_after(&mut self, uid: u32, now: Instant, window: Duration) -> Duration {
+        self.prune(now, window);
+        match self.failures.get(&uid) {
+            Some(f) if f.len() >= FAILURES_PER_UID => {
+                window.saturating_sub(now.duration_since(f[0]))
+            }
+            _ => Duration::ZERO,
+        }
+    }
+
     /// Record a failed unseal by `uid`.
     pub fn record_failure(&mut self, uid: u32, now: Instant, window: Duration) {
         self.prune(now, window);
@@ -91,6 +103,21 @@
     }
 
     #[test]
+    fn retry_after_counts_down_from_the_oldest_failure() {
+        let t0 = Instant::now();
+        let mut l = RateLimiter::default();
+        assert_eq!(l.retry_after(1000, t0, W), Duration::ZERO);
+        l.record_failure(1000, t0, W);
+        l.record_failure(1000, t0 + Duration::from_secs(5), W);
+        assert_eq!(l.retry_after(1000, t0, W), W);
+        assert_eq!(
+            l.retry_after(1000, t0 + Duration::from_secs(10), W),
+            W - Duration::from_secs(10)
+        );
+        assert_eq!(l.retry_after(1000, t0 + W, W), Duration::ZERO);
+    }
+
+    #[test]
     fn uids_are_limited_independently() {
         let t0 = Instant::now();
         let mut l = RateLimiter::default();
--- a/crates/aleph-tpmd/src/server.rs
+++ b/crates/aleph-tpmd/src/server.rs
@@ -176,7 +176,7 @@
                 // never be opened: refuse it now rather than at unlock.
                 match tpm.da_counters() {
                     Ok((_, max, recovery)) if recovery > 0 && reserve_threshold(max) == 0 => {
-                        return Response::Failed(Failure::Exhausted);
+                        return Response::Failed(Failure::Exhausted { retry_after: None });
                     }
                     Ok(_) => {}
                     Err(e) => return Response::Failed(failure(e)),
@@ -197,13 +197,21 @@
                 let window = window(recovery);
                 let mut limiter = lock(&self.limiter);
                 if limiter.blocked(uid, now, window) {
-                    return Response::Failed(Failure::RateLimited);
+                    let wait = limiter.retry_after(uid, now, window);
+                    return Response::Failed(Failure::RateLimited {
+                        retry_after: secs_ceil(wait),
+                    });
                 }
                 // Never spend the TPM's reserve: that is what keeps aleph
                 // from ever locking the TPM out. A recovery time of zero
                 // turns dictionary-attack counting off: nothing to protect.
                 if recovery > 0 && failed >= reserve_threshold(max) {
-                    return Response::Failed(Failure::Exhausted);
+                    // The TPM forgets one failure per recovery time; this
+                    // many must go before the count is under the threshold.
+                    let needed = failed - reserve_threshold(max) + 1;
+                    return Response::Failed(Failure::Exhausted {
+                        retry_after: Some(needed.saturating_mul(recovery)),
+                    });
                 }
                 match tpm.unseal(uid, &object, &secret.0) {
                     Ok(kek) => Response::Unsealed {
@@ -227,6 +235,12 @@
     }
 }
 
+/// Whole seconds, rounded up (a client told 0 would retry too early).
+fn secs_ceil(d: Duration) -> u32 {
+    let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
+    u32::try_from(secs).unwrap_or(u32::MAX)
+}
+
 fn failure(e: TpmError) -> Failure {
     match e {
         TpmError::AuthFailed => Failure::AuthFailed,
--- a/crates/aleph-unlock/src/error.rs
+++ b/crates/aleph-unlock/src/error.rs
@@ -13,10 +13,8 @@
     #[error("the TPM is in dictionary-attack lockout; wait and retry")]
     TpmLockout,
 
-    #[error(
-        "too many failed TPM attempts; wait before trying again (up to the TPM's recovery time)"
-    )]
-    TpmRateLimited,
+    #[error("too many failed TPM attempts; retry in {} s", retry_after.as_secs())]
+    TpmRateLimited { retry_after: std::time::Duration },
 
     /// The helper stayed busy (another request from this user, or its
     /// connection limit) through the client's retries.
@@ -27,7 +25,10 @@
     /// disk unlock), or the TPM allows too few failures for aleph to use.
     /// Not a reason to mark the slot stale.
     #[error("the TPM is not accepting password attempts now; try later or use another method")]
-    TpmExhausted,
+    TpmExhausted {
+        /// `None`: waiting will not help (this TPM allows too few failures).
+        retry_after: Option<std::time::Duration>,
+    },
 
     #[error("aleph-tpmd serves login users only")]
     TpmNotPermitted,
--- a/crates/aleph-unlock/src/tpm.rs
+++ b/crates/aleph-unlock/src/tpm.rs
@@ -137,9 +137,13 @@
         Response::Failed(f) => match f {
             Failure::AuthFailed => Error::TpmAuthFailed,
             Failure::Lockout => Error::TpmLockout,
-            Failure::RateLimited => Error::TpmRateLimited,
+            Failure::RateLimited { retry_after } => Error::TpmRateLimited {
+                retry_after: Duration::from_secs(retry_after.into()),
+            },
             Failure::Busy => Error::TpmBusy,
-            Failure::Exhausted => Error::TpmExhausted,
+            Failure::Exhausted { retry_after } => Error::TpmExhausted {
+                retry_after: retry_after.map(|s| Duration::from_secs(s.into())),
+            },
             Failure::NotPermitted => Error::TpmNotPermitted,
             Failure::WrongUser => Error::TpmWrongUser,
             Failure::ParentMismatch => Error::TpmParentMismatch,
--- a/crates/aleph-unlock/src/fido2/mod.rs
+++ b/crates/aleph-unlock/src/fido2/mod.rs
@@ -244,6 +244,24 @@
     Err(first_error.unwrap_or(Error::Fido2NoCredential))
 }
 
+/// Whether a connected key holds `slot`'s credential: the same no-touch,
+/// no-PIN preflight `unlock` uses, so a caller can ask for the right key's
+/// PIN before the touch. A lone key that cannot answer counts as present
+/// (`unlock` then asks it directly).
+pub fn present(keys: &mut dyn Keys, slot: &Fido2Slot) -> Result<bool> {
+    let mut devices = keys.devices()?;
+    let lone = devices.len() == 1;
+    for device in devices.iter_mut() {
+        match device.has_credential(RP_ID, &slot.credential_id) {
+            Ok(true) => return Ok(true),
+            Ok(false) => {}
+            Err(_) if lone => return Ok(true),
+            Err(_) => {}
+        }
+    }
+    Ok(false)
+}
+
 fn derive_kek(secret: &[u8; 32]) -> Result<Kek> {
     Ok(Kek::try_init(|buf| {
         buf.copy_from_slice(aleph_core::crypto::hkdf(secret, KEK_INFO).as_slice());
--- a/crates/aleph-unlock/src/fido2/libfido2.rs
+++ b/crates/aleph-unlock/src/fido2/libfido2.rs
@@ -126,6 +126,11 @@
         Self::default()
     }
 }
+
+// SAFETY: libfido2 device handles are not tied to the thread that opened
+// them; users of `Libfido2Keys` (the daemon keeps it behind a mutex) never
+// touch one from two threads at once, which `&mut self` already enforces.
+unsafe impl Send for Libfido2Keys {}
 
 impl Keys for Libfido2Keys {
     fn devices(&mut self) -> Result<Vec<&mut dyn Authenticator>> {
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-core -p aleph-tpm-proto -p aleph-tpmd -p aleph-unlock && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 59 passed | ok. 1 passed | ok. 27 passed | ok. 10 passed | ok. 1 passed | ok. 6 passed | ok. 5 passed | ok. 21 passed | ok. 5 passed | ok. 1 passed | ok. 23 passed | ok. 8 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **retry_after counts down** (`crates/aleph-tpmd/src/limiter.rs`), test `cargo test -p aleph-tpmd --lib retry_after_counts_down`: replace `window.saturating_sub(now.duration_since(f[0]))` with `Duration::ZERO`.
- **present finds the slot's key** (`crates/aleph-unlock/src/fido2/mod.rs`), test `cargo test -p aleph-unlock --test fido2 present_finds`: replace `Ok(true) => return Ok(true),` with `Ok(true) => {}`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-core crates/aleph-tpm-proto crates/aleph-tpmd crates/aleph-unlock
git commit -m "feat: retry_after on TPM refusals, fido2::present, mlock reporting" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: aleph-prompt-proto

**Interfaces:**
- Produces: `aleph_prompt_proto::{{MAX_LINE, Secret, Purpose {{ Unlock, Reauth, Create }}, Method {{ Password, Fido2 }}, Caller, ToPrompter {{ Begin, Ask, Fido2Pin, InsertKey, Touch, Confirm, ShowRecoveryKey, Done }}, FromPrompter {{ Password, Fido2, Pin, Confirm, RecoveryCheck, Cancel }}}}`, `ToPrompter::needs_reply()`

- [ ] **Step 1: Write the failing tests**

Write `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-tpm-proto", "crates/aleph-tpmd", "crates/aleph-unlock", "crates/aleph-prompt-proto"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "Apache-2.0"
rust-version = "1.98"

[workspace.dependencies]
argon2 = "0.6"
chacha20poly1305 = "0.11"
ciborium = "0.2"
fido2-rs = "0.6"
getrandom = "0.4"
hkdf = "0.13"
hex = "0.4"
hybrid-array = { version = "0.4", features = ["zeroize"] }
hmac = "0.13"
libc = "0.2"
proptest = "1"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
serde_json = "1"
sha2 = "0.11"
tempfile = "3"
thiserror = "2"
tss-esapi = "7.7"
uuid = { version = "1", features = ["v4", "serde"] }
# Pinned exactly: recovery keys must open vaults forever, and the crate
# tracks a draft (the local KATs against the draft vectors are the tripwire).
x-wing = { version = "=0.1.0", features = ["zeroize"] }
zeroize = { version = "1.9", features = ["derive"] }

# Argon2, the AEAD, X-Wing (ML-KEM, X25519, SHA-3), and CBOR parsing are
# unusably slow unoptimized; keep tests fast.
[profile.dev.package.argon2]
opt-level = 3
[profile.dev.package.blake2]
opt-level = 3
[profile.dev.package.chacha20poly1305]
opt-level = 3
[profile.dev.package.chacha20]
opt-level = 3
[profile.dev.package.poly1305]
opt-level = 3
[profile.dev.package.ml-kem]
opt-level = 3
[profile.dev.package.module-lattice]
opt-level = 3
[profile.dev.package.x25519-dalek]
opt-level = 3
[profile.dev.package.curve25519-dalek]
opt-level = 3
[profile.dev.package.sha3]
opt-level = 3
[profile.dev.package.keccak]
opt-level = 3
[profile.dev.package.shake]
opt-level = 3
[profile.dev.package.ciborium]
opt-level = 3
[profile.dev.package.ciborium-ll]
opt-level = 3
```

Write `crates/aleph-prompt-proto/Cargo.toml`:

```toml
[package]
name = "aleph-prompt-proto"
description = "The prompter protocol between alephd and its prompters (GUI or terminal)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
serde.workspace = true
zeroize.workspace = true

[dev-dependencies]
serde_json.workspace = true
```

Write `crates/aleph-prompt-proto/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_and_reject_unknown_fields() {
        let msgs = [
            ToPrompter::Ask {
                methods: vec![Method::Password, Method::Fido2],
                error: Some("wrong password".into()),
                retry_after: Some(30),
            },
            ToPrompter::ShowRecoveryKey {
                key: Secret::new("ABCD-EFGH"),
                check: [2, 9],
                error: None,
            },
        ];
        for m in msgs {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<ToPrompter>(&json).unwrap(), m);
        }
        assert!(serde_json::from_str::<FromPrompter>(r#"{"type":"cancel","x":1}"#).is_err());
        let p: FromPrompter =
            serde_json::from_str(r#"{"type":"password","password":"hunter2"}"#).unwrap();
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-prompt-proto`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-prompt-proto/src/lib.rs`:

```rust
//! The protocol between `alephd` and a prompter (spec §6 "Prompter
//! orchestration"): one JSON object per line over a socketpair. Shared by
//! the daemon, the `aleph` CLI (its terminal prompter), and `aleph-gui`.
//!
//! A conversation starts with [`ToPrompter::Begin`] and ends with
//! [`ToPrompter::Done`]. Messages for which [`ToPrompter::needs_reply`] is
//! true expect exactly one [`FromPrompter`] answer; the prompter may send
//! `Cancel` at any time.

use serde::{Deserialize, Serialize};

/// Longest line either side accepts.
pub const MAX_LINE: usize = 16 * 1024;

/// A secret string in a message: zeroized on drop, never printed.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Unlock the vault.
    Unlock,
    /// Prove an enrolled method again before a sensitive operation.
    Reauth,
    /// Create the vault.
    Create,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// The login password (TPM or login-password slots).
    Password,
    /// A FIDO2 security key.
    Fido2,
}

/// Who asked, for display only (it can be spoofed).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub name: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToPrompter {
    Begin {
        purpose: Purpose,
        /// What is being done, e.g. "Unlock the keyring" or "Remove keyslot 'yubikey'".
        operation: String,
        caller: Option<Caller>,
    },
    /// Choose one of `methods` (reply `Password` or `Fido2`).
    Ask {
        methods: Vec<Method>,
        error: Option<String>,
        /// Seconds until trying again can succeed, when known.
        retry_after: Option<u64>,
    },
    /// The key `key` needs its PIN (reply `Pin`).
    Fido2Pin {
        key: String,
        error: Option<String>,
    },
    /// Waiting for a FIDO2 key to be plugged in.
    InsertKey {
        key: String,
    },
    /// Touch the key `key` now.
    Touch {
        key: String,
    },
    /// Reply `Confirm`.
    Confirm {
        text: String,
    },
    /// Show the new recovery key once; reply `RecoveryCheck` with the
    /// groups at the 1-based positions in `check`.
    ShowRecoveryKey {
        key: Secret,
        check: [usize; 2],
        error: Option<String>,
    },
    Done {
        ok: bool,
        message: Option<String>,
    },
}

impl ToPrompter {
    pub fn needs_reply(&self) -> bool {
        matches!(
            self,
            Self::Ask { .. }
                | Self::Fido2Pin { .. }
                | Self::Confirm { .. }
                | Self::ShowRecoveryKey { .. }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FromPrompter {
    Password { password: Secret },
    Fido2 {},
    Pin { pin: Secret },
    Confirm { yes: bool },
    RecoveryCheck { groups: [Secret; 2] },
    Cancel {},
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_and_reject_unknown_fields() {
        let msgs = [
            ToPrompter::Ask {
                methods: vec![Method::Password, Method::Fido2],
                error: Some("wrong password".into()),
                retry_after: Some(30),
            },
            ToPrompter::ShowRecoveryKey {
                key: Secret::new("ABCD-EFGH"),
                check: [2, 9],
                error: None,
            },
        ];
        for m in msgs {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<ToPrompter>(&json).unwrap(), m);
        }
        assert!(serde_json::from_str::<FromPrompter>(r#"{"type":"cancel","x":1}"#).is_err());
        let p: FromPrompter =
            serde_json::from_str(r#"{"type":"password","password":"hunter2"}"#).unwrap();
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-prompt-proto && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 1 passed.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-prompt-proto
git commit -m "feat(prompt-proto): the prompter protocol" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: daemon foundation

**Interfaces:**
- Consumes: `aleph_core::{{HighWater, LockedVault, Mark, Standing, UnlockedVault}}`.
- Produces:
  - `aleph_daemon::{{Error, Result}}` (variants as in `error.rs`)
  - `paths::Paths {{ data_dir, state_dir, config_file, runtime_dir; from_env(), under(root), vault(), daemon_lock(), slot_state() }}`
  - `config::{{Config {{ lock, prompt }}, KEYS, MAX_PROMPT_TIMEOUT = 86400; load, save, get, set}}`
  - `state::SlotState {{ load, is_stale, stale, mark_stale, clear, retain }}`
  - `store::Store {{ open, exists, read, check, raise, record, write }}`
  - `password::{{PAM_SERVICE = "aleph-check", TYPED_FAILURES = 5, TYPED_WINDOW = 60 s, PasswordCheck, PamCheck {{ for_current_user, with_confdir }}, TypedLimiter, Fixed}}`

- [ ] **Step 1: Write the failing tests**

Write `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-tpm-proto", "crates/aleph-tpmd", "crates/aleph-unlock", "crates/aleph-prompt-proto", "crates/aleph-daemon"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "Apache-2.0"
rust-version = "1.98"

[workspace.dependencies]
argon2 = "0.6"
chacha20poly1305 = "0.11"
ciborium = "0.2"
fido2-rs = "0.6"
getrandom = "0.4"
hkdf = "0.13"
hex = "0.4"
hybrid-array = { version = "0.4", features = ["zeroize"] }
hmac = "0.13"
libc = "0.2"
proptest = "1"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
serde_json = "1"
sha2 = "0.11"
tempfile = "3"
thiserror = "2"
tss-esapi = "7.7"
uuid = { version = "1", features = ["v4", "serde"] }
# Pinned exactly: recovery keys must open vaults forever, and the crate
# tracks a draft (the local KATs against the draft vectors are the tripwire).
x-wing = { version = "=0.1.0", features = ["zeroize"] }
zeroize = { version = "1.9", features = ["derive"] }

# Argon2, the AEAD, X-Wing (ML-KEM, X25519, SHA-3), and CBOR parsing are
# unusably slow unoptimized; keep tests fast.
[profile.dev.package.argon2]
opt-level = 3
[profile.dev.package.blake2]
opt-level = 3
[profile.dev.package.chacha20poly1305]
opt-level = 3
[profile.dev.package.chacha20]
opt-level = 3
[profile.dev.package.poly1305]
opt-level = 3
[profile.dev.package.ml-kem]
opt-level = 3
[profile.dev.package.module-lattice]
opt-level = 3
[profile.dev.package.x25519-dalek]
opt-level = 3
[profile.dev.package.curve25519-dalek]
opt-level = 3
[profile.dev.package.sha3]
opt-level = 3
[profile.dev.package.keccak]
opt-level = 3
[profile.dev.package.shake]
opt-level = 3
[profile.dev.package.ciborium]
opt-level = 3
[profile.dev.package.ciborium-ll]
opt-level = 3
```

Write `crates/aleph-daemon/Cargo.toml`:

```toml
[package]
name = "aleph-daemon"
description = "alephd: the aleph keyring daemon (Secret Service and admin interface)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "alephd"
path = "src/main.rs"

[dependencies]
aleph-core = { path = "../aleph-core" }
aleph-unlock = { path = "../aleph-unlock" }
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
toml = "1"
tracing = "0.1"
uuid.workspace = true
zeroize.workspace = true

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
tempfile.workspace = true
serde.workspace = true
```

Write `crates/aleph-daemon/src/lib.rs`:

```rust
//! `alephd`, the aleph keyring daemon (spec §6).

pub mod config;
pub mod error;
pub mod password;
pub mod paths;
pub mod state;
pub mod store;

pub use error::{Error, Result};
```

Create `crates/aleph-daemon/src/main.rs` containing only `fn main() {}`.

Write `crates/aleph-daemon/src/error.rs`:

```rust
use std::time::Duration;

/// Daemon errors. Their messages are shown to users (CLI, prompter), so
/// they say what happened and, where there is one, what to do.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] aleph_core::Error),

    #[error(transparent)]
    Unlock(#[from] aleph_unlock::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Environment(&'static str),

    #[error("another alephd already owns this vault")]
    AlreadyRunning,

    #[error("no vault yet; run `aleph setup`")]
    NoVault,

    #[error("a vault already exists")]
    VaultExists,

    #[error("the vault is locked")]
    Locked,

    #[error("wrong password")]
    WrongPassword,

    #[error(
        "the TPM keyslot '{0}' no longer accepts your password (was it changed?); it is marked stale: re-enroll it with `aleph keyslot add tpm`"
    )]
    Stale(String),

    #[error("too many wrong passwords; retry in {} s", .retry_after.as_secs())]
    TooManyAttempts { retry_after: Duration },

    #[error(
        "cannot check passwords: /etc/pam.d/aleph-check is missing (`aleph setup` installs it)"
    )]
    PasswordCheckUnavailable,

    #[error("password check failed: {0}")]
    PasswordCheck(String),

    #[error("no enrolled method could unlock the vault{}", .0.as_deref().map(|m| format!(": {m}")).unwrap_or_default())]
    NoMethodWorked(Option<String>),

    #[error("cancelled")]
    Cancelled,

    #[error("the prompter failed: {0}")]
    Prompt(String),

    #[error("no prompter is available (no graphical session?); run `aleph unlock` in a terminal")]
    NoPrompter,

    #[error(
        "the vault file was {0}; writes are refused until you confirm it (`aleph restore --accept-rollback`)"
    )]
    Untrusted(&'static str),

    #[error("no such keyslot {0}")]
    NoSuchKeyslot(uuid::Uuid),

    #[error("the recovery slot cannot be removed")]
    RecoverySlotRequired,

    #[error("that would leave only the recovery key; add another unlock method first")]
    LastMethod,

    #[error("no such item or collection")]
    NotFound,

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("invalid request: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;
```

Write `crates/aleph-daemon/src/paths.rs`:

```rust
//! Where aleph keeps its files (spec §4 "File", §6 "Lock policy").
//!
//! | What | Where |
//! |---|---|
//! | vault | `$XDG_DATA_HOME/aleph/vault.aleph` |
//! | high-water marks, slot state | `$XDG_STATE_HOME/aleph/` |
//! | configuration | `$XDG_CONFIG_HOME/aleph/config.toml` |
//! | sockets | `$XDG_RUNTIME_DIR/aleph/` |

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub config_file: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Paths {
    /// From the XDG environment variables, with the XDG defaults under
    /// `$HOME`. Relative XDG values are ignored, as the XDG spec requires.
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let home = var("HOME").ok_or(Error::Environment("HOME is not set"))?;
        let runtime = var("XDG_RUNTIME_DIR").ok_or(Error::Environment(
            "XDG_RUNTIME_DIR is not set (not in a login session?)",
        ))?;
        Ok(Self {
            data_dir: var("XDG_DATA_HOME")
                .unwrap_or_else(|| home.join(".local/share"))
                .join("aleph"),
            state_dir: var("XDG_STATE_HOME")
                .unwrap_or_else(|| home.join(".local/state"))
                .join("aleph"),
            config_file: var("XDG_CONFIG_HOME")
                .unwrap_or_else(|| home.join(".config"))
                .join("aleph/config.toml"),
            runtime_dir: runtime.join("aleph"),
        })
    }

    /// Everything under one directory (tests).
    pub fn under(root: &Path) -> Self {
        Self {
            data_dir: root.join("data/aleph"),
            state_dir: root.join("state/aleph"),
            config_file: root.join("config/aleph/config.toml"),
            runtime_dir: root.join("run/aleph"),
        }
    }

    pub fn vault(&self) -> PathBuf {
        self.data_dir.join("vault.aleph")
    }

    /// Held by the running daemon for its whole lifetime.
    pub fn daemon_lock(&self) -> PathBuf {
        self.data_dir.join("vault.aleph.daemon")
    }

    /// Which slots are stale (§5), kept outside the vault because it
    /// changes while the vault is locked.
    pub fn slot_state(&self) -> PathBuf {
        self.state_dir.join("slots.json")
    }
}
```

Write `crates/aleph-daemon/src/config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_gives_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::load(&dir.path().join("none.toml")).unwrap();
        assert_eq!(c, Config::default());
        assert!(c.lock.on_suspend && c.lock.on_screen_lock);
        assert_eq!(c.lock.idle_timeout, 0);
    }

    #[test]
    fn set_get_and_save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aleph/config.toml");
        let mut c = Config::default();
        c.set("lock.idle_timeout", "900").unwrap();
        c.set("lock.on_suspend", "false").unwrap();
        c.save(&path).unwrap();
        let back = Config::load(&path).unwrap();
        assert_eq!(back.get("lock.idle_timeout").unwrap(), "900");
        assert_eq!(back.get("lock.on_suspend").unwrap(), "false");
        for key in KEYS {
            back.get(key).unwrap();
        }
    }

    #[test]
    fn bad_keys_values_and_files_are_errors() {
        let mut c = Config::default();
        assert!(c.set("lock.idle", "1").is_err());
        assert!(c.set("lock.on_suspend", "yes").is_err());
        assert!(c.set("prompt.timeout", "0").is_err());
        assert!(c.set("prompt.timeout", "86401").is_err());
        assert!(c.set("prompt.timeout", &u64::MAX.to_string()).is_err());
        assert!(c.get("nope").is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "[lock]\non_suspnd = false\n").unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::write(&path, "[prompt]\ntimeout = 18446744073709551615\n").unwrap();
        assert!(Config::load(&path).is_err());
    }
}
```

Write `crates/aleph-daemon/src/state.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_marks_persist_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/slots.json");
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut s = SlotState::load(&path);
        assert!(!s.is_stale(a));
        s.mark_stale(a).unwrap();
        s.mark_stale(b).unwrap();
        let mut s = SlotState::load(&path);
        assert!(s.is_stale(a) && s.is_stale(b));
        s.clear(a).unwrap();
        s.retain(|id| id != b).unwrap();
        let s = SlotState::load(&path);
        assert!(!s.is_stale(a) && !s.is_stale(b));
    }

    #[test]
    fn a_corrupt_file_means_nothing_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slots.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(SlotState::load(&path).stale().count(), 0);
    }
}
```

Write `crates/aleph-daemon/src/store.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_daemon_may_own_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let first = Store::open(&paths).unwrap();
        assert!(matches!(Store::open(&paths), Err(Error::AlreadyRunning)));
        drop(first);
        // Retry briefly: a process forked meanwhile by another test (PAM
        // runs unix_chkpwd) holds a copy of the lock's descriptor until
        // its exec closes it.
        let mut again = Store::open(&paths);
        for _ in 0..100 {
            if again.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            again = Store::open(&paths);
        }
        again.unwrap();
    }

    #[test]
    fn the_data_directory_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        drop(Store::open(&paths).unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&paths.data_dir), 0o700);
        std::fs::set_permissions(&paths.data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(Store::open(&paths).unwrap());
        assert_eq!(mode(&paths.data_dir), 0o700);
    }

    #[test]
    fn a_missing_vault_is_no_vault() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&Paths::under(dir.path())).unwrap();
        assert!(!store.exists());
        assert!(matches!(store.read(), Err(Error::NoVault)));
    }
}
```

Write `crates/aleph-daemon/src/password.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-daemon/src/config.rs`:

```rust
//! `~/.config/aleph/config.toml` (spec §6 "Lock policy").
//!
//! Unknown keys are errors, so a typo is reported rather than silently
//! ignored. `aleph config get|set` addresses values as `section.key`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub lock: LockConfig,
    pub prompt: PromptConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LockConfig {
    /// Lock on suspend (hibernate always locks).
    pub on_suspend: bool,
    /// Lock when the session is locked (logind `Session.Lock`).
    pub on_screen_lock: bool,
    /// Seconds without secret access before locking; 0 disables.
    pub idle_timeout: u64,
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            on_suspend: true,
            on_screen_lock: true,
            idle_timeout: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PromptConfig {
    /// The prompter program, run as `<program> prompt`.
    pub program: String,
    /// Seconds a prompt may stay open before it is dismissed.
    pub timeout: u64,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            program: "aleph-gui".into(),
            timeout: 300,
        }
    }
}

/// The longest prompt timeout accepted (a day): larger values would
/// overflow deadline arithmetic.
pub const MAX_PROMPT_TIMEOUT: u64 = 86_400;

/// The keys `get`/`set` accept.
pub const KEYS: &[&str] = &[
    "lock.on_suspend",
    "lock.on_screen_lock",
    "lock.idle_timeout",
    "prompt.program",
    "prompt.timeout",
];

impl Config {
    /// The file's configuration, or the defaults if it does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let c: Self = toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))?;
                if c.prompt.timeout == 0 || c.prompt.timeout > MAX_PROMPT_TIMEOUT {
                    return Err(Error::Config(format!(
                        "prompt.timeout must be 1 to {MAX_PROMPT_TIMEOUT} seconds"
                    )));
                }
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Write atomically (temp file, then rename), creating the directory.
    pub fn save(&self, path: &Path) -> Result<()> {
        let dir = path
            .parent()
            .ok_or(Error::Config("configuration path has no directory".into()))?;
        std::fs::create_dir_all(dir)?;
        let text = toml::to_string(self).map_err(|e| Error::Config(e.to_string()))?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<String> {
        Ok(match key {
            "lock.on_suspend" => self.lock.on_suspend.to_string(),
            "lock.on_screen_lock" => self.lock.on_screen_lock.to_string(),
            "lock.idle_timeout" => self.lock.idle_timeout.to_string(),
            "prompt.program" => self.prompt.program.clone(),
            "prompt.timeout" => self.prompt.timeout.to_string(),
            _ => return Err(unknown(key)),
        })
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let bad = |what: &str| Error::Config(format!("{key} must be {what}, not {value:?}"));
        match key {
            "lock.on_suspend" => {
                self.lock.on_suspend = value.parse().map_err(|_| bad("true or false"))?
            }
            "lock.on_screen_lock" => {
                self.lock.on_screen_lock = value.parse().map_err(|_| bad("true or false"))?;
            }
            "lock.idle_timeout" => {
                self.lock.idle_timeout = value.parse().map_err(|_| bad("a number of seconds"))?;
            }
            "prompt.program" if value.trim().is_empty() => return Err(bad("a program name")),
            "prompt.program" => self.prompt.program = value.to_string(),
            "prompt.timeout" => match value.parse() {
                Ok(n @ 1..=MAX_PROMPT_TIMEOUT) => self.prompt.timeout = n,
                _ => return Err(bad("1 to 86400 seconds")),
            },
            _ => return Err(unknown(key)),
        }
        Ok(())
    }
}

fn unknown(key: &str) -> Error {
    Error::Config(format!(
        "unknown key {key:?}; known keys: {}",
        KEYS.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_gives_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::load(&dir.path().join("none.toml")).unwrap();
        assert_eq!(c, Config::default());
        assert!(c.lock.on_suspend && c.lock.on_screen_lock);
        assert_eq!(c.lock.idle_timeout, 0);
    }

    #[test]
    fn set_get_and_save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aleph/config.toml");
        let mut c = Config::default();
        c.set("lock.idle_timeout", "900").unwrap();
        c.set("lock.on_suspend", "false").unwrap();
        c.save(&path).unwrap();
        let back = Config::load(&path).unwrap();
        assert_eq!(back.get("lock.idle_timeout").unwrap(), "900");
        assert_eq!(back.get("lock.on_suspend").unwrap(), "false");
        for key in KEYS {
            back.get(key).unwrap();
        }
    }

    #[test]
    fn bad_keys_values_and_files_are_errors() {
        let mut c = Config::default();
        assert!(c.set("lock.idle", "1").is_err());
        assert!(c.set("lock.on_suspend", "yes").is_err());
        assert!(c.set("prompt.timeout", "0").is_err());
        assert!(c.set("prompt.timeout", "86401").is_err());
        assert!(c.set("prompt.timeout", &u64::MAX.to_string()).is_err());
        assert!(c.get("nope").is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "[lock]\non_suspnd = false\n").unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::write(&path, "[prompt]\ntimeout = 18446744073709551615\n").unwrap();
        assert!(Config::load(&path).is_err());
    }
}
```

Write `crates/aleph-daemon/src/state.rs`:

```rust
//! Which keyslots are stale (spec §5, "Rate limiting").
//!
//! A TPM slot that answered `AuthFailed` or `WrongUser` is marked stale and
//! is not tried automatically again until it is re-enrolled or the user
//! retries it explicitly, so an outdated password cannot keep spending the
//! TPM's dictionary-attack budget. The mark changes while the vault is
//! locked, so it lives in its own file, not in the (MACed) vault header.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    stale: BTreeSet<Uuid>,
}

#[derive(Debug)]
pub struct SlotState {
    path: PathBuf,
    stale: BTreeSet<Uuid>,
}

impl SlotState {
    /// Load the state; a missing or unreadable file means "nothing stale"
    /// (the worst case is one extra attempt per slot).
    pub fn load(path: &Path) -> Self {
        let stale = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<File>(&b).ok())
            .map(|f| f.stale)
            .unwrap_or_default();
        Self {
            path: path.to_path_buf(),
            stale,
        }
    }

    pub fn is_stale(&self, slot: Uuid) -> bool {
        self.stale.contains(&slot)
    }

    pub fn stale(&self) -> impl Iterator<Item = &Uuid> {
        self.stale.iter()
    }

    pub fn mark_stale(&mut self, slot: Uuid) -> Result<()> {
        if self.stale.insert(slot) {
            self.save()?;
        }
        Ok(())
    }

    pub fn clear(&mut self, slot: Uuid) -> Result<()> {
        if self.stale.remove(&slot) {
            self.save()?;
        }
        Ok(())
    }

    /// Forget slots that no longer exist.
    pub fn retain(&mut self, exists: impl Fn(Uuid) -> bool) -> Result<()> {
        let before = self.stale.len();
        self.stale.retain(|s| exists(*s));
        if self.stale.len() != before {
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec(&File {
                stale: self.stale.clone(),
            })
            .expect("serializable"),
        )?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_marks_persist_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/slots.json");
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut s = SlotState::load(&path);
        assert!(!s.is_stale(a));
        s.mark_stale(a).unwrap();
        s.mark_stale(b).unwrap();
        let mut s = SlotState::load(&path);
        assert!(s.is_stale(a) && s.is_stale(b));
        s.clear(a).unwrap();
        s.retain(|id| id != b).unwrap();
        let s = SlotState::load(&path);
        assert!(!s.is_stale(a) && !s.is_stale(b));
    }

    #[test]
    fn a_corrupt_file_means_nothing_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slots.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(SlotState::load(&path).stale().count(), 0);
    }
}
```

Write `crates/aleph-daemon/src/store.rs`:

```rust
//! The vault file as the daemon owns it (spec §4 "File", "Generation and
//! high-water mark").
//!
//! - The daemon holds `vault.aleph.daemon` for its lifetime, so a second
//!   daemon (or anything else that honours the lock) refuses to run.
//! - The data directory is created `0700`; an existing one that is group-
//!   or world-accessible is tightened, with a warning.
//! - Writes go through `UnlockedVault::write_recorded`, so the high-water
//!   mark follows the daemon's own writes.

use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use aleph_core::{HighWater, LockedVault, Mark, Standing, UnlockedVault};

use crate::error::{Error, Result};
use crate::paths::Paths;

pub struct Store {
    paths: Paths,
    highwater: HighWater,
    _daemon_lock: File,
}

impl Store {
    /// Take ownership of the vault location.
    pub fn open(paths: &Paths) -> Result<Self> {
        ensure_private_dir(&paths.data_dir)?;
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(paths.daemon_lock())?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Error::AlreadyRunning),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        Ok(Self {
            paths: paths.clone(),
            highwater: HighWater::new(&paths.state_dir),
            _daemon_lock: lock,
        })
    }

    pub fn exists(&self) -> bool {
        self.paths.vault().symlink_metadata().is_ok()
    }

    pub fn read(&self) -> Result<LockedVault> {
        match LockedVault::read(&self.paths.vault()) {
            Err(aleph_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NoVault)
            }
            other => Ok(other?),
        }
    }

    /// How a file read from disk compares with the recorded mark. The
    /// header is not yet authenticated: this may only warn, never raise.
    pub fn check(&self, vault: &LockedVault) -> Result<Standing> {
        Ok(self.highwater.check(&vault.mark())?)
    }

    /// Raise the mark for an unlocked (authenticated) vault.
    pub fn raise(&self, vault: &UnlockedVault) -> Result<Standing> {
        Ok(self.highwater.raise(vault)?)
    }

    /// Record a mark (a `Pending` own write, or an accepted rollback).
    pub fn record(&self, mark: &Mark) -> Result<()> {
        Ok(self.highwater.record(mark)?)
    }

    pub fn write(&self, vault: &UnlockedVault) -> Result<Mark> {
        Ok(vault.write_recorded(&self.paths.vault(), &self.highwater)?)
    }
}

/// Create `dir` as `0700`, or tighten an existing group- or
/// world-accessible one (warning, since someone loosened it).
fn ensure_private_dir(dir: &Path) -> Result<()> {
    match std::fs::metadata(dir) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    dir = %dir.display(),
                    mode = format!("{mode:o}"),
                    "vault directory was group- or world-accessible; tightened to 0700"
                );
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_daemon_may_own_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let first = Store::open(&paths).unwrap();
        assert!(matches!(Store::open(&paths), Err(Error::AlreadyRunning)));
        drop(first);
        // Retry briefly: a process forked meanwhile by another test (PAM
        // runs unix_chkpwd) holds a copy of the lock's descriptor until
        // its exec closes it.
        let mut again = Store::open(&paths);
        for _ in 0..100 {
            if again.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            again = Store::open(&paths);
        }
        again.unwrap();
    }

    #[test]
    fn the_data_directory_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        drop(Store::open(&paths).unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&paths.data_dir), 0o700);
        std::fs::set_permissions(&paths.data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(Store::open(&paths).unwrap());
        assert_eq!(mode(&paths.data_dir), 0o700);
    }

    #[test]
    fn a_missing_vault_is_no_vault() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&Paths::under(dir.path())).unwrap();
        assert!(!store.exists());
        assert!(matches!(store.read(), Err(Error::NoVault)));
    }
}
```

Write `crates/aleph-daemon/src/password.rs`:

```rust
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
```

Write `packaging/pam/aleph-check`:

```
#%PAM-1.0
# alephd checks a typed login password with this service before offering
# it to the TPM, so typos never spend the TPM's dictionary-attack budget
# (spec §5). pam_unix only: no faillock, so a typo in an aleph prompt does
# not count against the account; alephd limits typed attempts itself.
auth      required  pam_unix.so
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 14 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **missing PAM service is not a wrong password** (`crates/aleph-daemon/src/password.rs`), test `cargo test -p aleph-daemon --lib a_missing_service_is_unavailable`: replace `if !dir.join(PAM_SERVICE).exists() {` with `if false {`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-daemon packaging/pam
git commit -m "feat(daemon): paths, config, stale marks, vault store, PAM password check" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: prompter channel and keyring engine

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces:
  - `prompt::{{Channel {{ new, from_fd, send, ask, cancelled, done }}, Launcher, ProgramLauncher, scripted::Scripted}}` (re-exports the protocol)
  - `keyring::{{Tpm, Backends {{ tpm, keys, password }}, SlotInfo, Status {{ vault, locked, untrusted, memory_locked, tpm, keyslots }}, Keyring}}` with `new(&Paths, Backends)`, `from_store(Store, &Paths, Backends)`, `status`, `is_locked`, `lock`, `read`, `modify`, `unlock(&mut Channel, Option<Caller>)`, `unlock_with_login_password`, `create(&mut Channel, Method)`, `enroll_tpm`, `enroll_fido2(chan, touch_only)`, `remove_keyslot(chan, Uuid)`, `rotate_master`, `reissue_recovery`, `retry_slot`, `with_reauth(chan, op, f)`, pub fields `argon2`, `key_wait`
  - feature `testing` → `testing::{{PW, PIN, Env, env(), keyring(&Env, MockKeys), keyring_with(&Env, Box<dyn Tpm>, MockKeys, Box<dyn PasswordCheck>), NoTpm, FlakyTpm {{ inner, ok, then }}, Accepting {{ new, set }}, Unavailable, password(), pin(), create_with_password(), Interactive {{ new, channel, respond, sent }}, InteractiveLauncher}}`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-daemon/Cargo.toml`:

```toml
[package]
name = "aleph-daemon"
description = "alephd: the aleph keyring daemon (Secret Service and admin interface)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "alephd"
path = "src/main.rs"

[features]
testing = ["dep:aleph-tpmd", "dep:tempfile", "aleph-core/insecure-test-params"]

[dependencies]
aleph-core = { path = "../aleph-core" }
aleph-prompt-proto = { path = "../aleph-prompt-proto" }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
aleph-unlock = { path = "../aleph-unlock" }
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
toml = "1"
tracing = "0.1"
uuid.workspace = true
zeroize.workspace = true
aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"], optional = true }
tempfile = { workspace = true, optional = true }

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-daemon = { path = ".", features = ["testing"] }
tempfile.workspace = true
serde.workspace = true
```

Write `crates/aleph-daemon/src/lib.rs`:

```rust
//! `alephd`, the aleph keyring daemon (spec §6).

pub mod config;
pub mod error;
pub mod keyring;
pub mod password;
pub mod paths;
pub mod prompt;
pub mod state;
pub mod store;

#[cfg(feature = "testing")]
pub mod testing;

pub use error::{Error, Result};
```

Write `crates/aleph-daemon/src/prompt.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
```

Write `crates/aleph-daemon/src/keyring.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::Launcher;
    use crate::prompt::scripted::Scripted;

    fn check(a: &str, b: &str) -> FromPrompter {
        FromPrompter::RecoveryCheck {
            groups: [Secret::new(a), Secret::new(b)],
        }
    }

    /// The recovery key counts as recorded only if the user types back the
    /// groups asked for; three wrong answers fail the operation.
    #[test]
    fn a_wrong_recovery_confirmation_is_refused() {
        let key = RecoveryKey::generate().unwrap();
        let p = Scripted::new(vec![check("0000", "0000"); 3]);
        let mut chan = p.launch().unwrap();
        assert!(matches!(
            show_recovery_key(&mut chan, &key),
            Err(Error::Invalid(_))
        ));
        let shown = p
            .sent()
            .into_iter()
            .filter(|m| matches!(m, ToPrompter::ShowRecoveryKey { .. }))
            .count();
        assert_eq!(shown, 3);
    }

    #[test]
    fn recovery_groups_are_normalized_like_recovery_input() {
        assert_eq!(normalize(" o1il "), "0111");
        assert_eq!(normalize("ab2c"), "AB2C");
    }
}
```

Create `crates/aleph-daemon/src/testing.rs` containing only `// implemented in step 3`.

Write `crates/aleph-daemon/tests/keyring.rs`:

```rust
//! The keyring engine against a real TPM helper (swtpm), mock FIDO2 keys,
//! a fixed password check, and a scripted prompter.

use aleph_daemon::testing::*;

fn asks(sent: &[ToPrompter]) -> Vec<(Option<String>, Option<u64>)> {
    sent.iter()
        .filter_map(|m| match m {
            ToPrompter::Ask {
                error, retry_after, ..
            } => Some((error.clone(), *retry_after)),
            _ => None,
        })
        .collect()
}

#[test]
fn create_then_unlock_with_the_login_password() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let s = k.status().unwrap();
    assert!(s.vault && !s.locked);
    let kinds: Vec<&str> = s.keyslots.iter().map(|k| k.kind.as_str()).collect();
    assert_eq!(kinds, ["recovery", "tpm"]);
    k.modify(|b| {
        b.collections[0].upsert(
            aleph_core::Item::new(
                "x",
                Default::default(),
                aleph_core::SecretBytes::new(b"s3cret".to_vec()),
                "text/plain",
            ),
            false,
        );
        Ok(())
    })
    .unwrap();
    k.lock();
    assert!(matches!(k.read(|_| ()), Err(Error::Locked)));
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    assert!(matches!(
        p.sent().last(),
        Some(ToPrompter::Done { ok: true, .. })
    ));
}

/// The point of the PAM check: a mistyped password is refused before the
/// TPM sees it, so it costs no dictionary-attack budget.
#[test]
fn typos_never_reach_the_tpm() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    let p = Interactive::new(vec![password("typo"), password("tpyo"), password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    let errors = asks(&p.sent());
    assert_eq!(errors.len(), 3);
    assert_eq!(errors[1].0.as_deref(), Some("wrong password"));
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
}

#[test]
fn too_many_typos_are_refused_with_a_wait() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    let mut replies: Vec<_> = (0..5).map(|_| password("typo")).collect();
    replies.push(password(PW));
    let p = Interactive::new(replies);
    // The sixth attempt (the right password) is refused too: blocked, and
    // the conversation ends rather than asking again at once.
    assert!(matches!(
        k.unlock(&mut p.channel(), None),
        Err(Error::TooManyAttempts { .. })
    ));
    let sent = p.sent();
    assert_eq!(asks(&sent).len(), 6);
    assert!(matches!(
        sent.last(),
        Some(ToPrompter::Done { ok: false, message: Some(m) }) if m.contains("too many")
    ));
}

/// A TPM slot that rejects a password PAM accepts (the password changed
/// elsewhere) is marked stale and no longer offered; retrying clears it.
#[test]
fn a_slot_that_rejects_the_current_password_goes_stale() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    // The login password "changed": PAM now accepts only the new one.
    drop(k);
    let backends = Backends {
        tpm: Box::new(TpmClient::new(env.socket.clone())),
        keys: Box::new(MockKeys::default()),
        password: Box::new(Fixed(|p| p == "new password")),
    };
    let k = Keyring::new(&env.paths, backends).unwrap();
    let p = Interactive::new(vec![password("new password")]);
    assert!(k.unlock(&mut p.channel(), None).is_err());
    let errors = asks(&p.sent());
    assert!(
        errors[1].0.as_deref().unwrap().contains("stale"),
        "{errors:?}"
    );
    let tpm = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .find(|s| s.kind == "tpm")
        .unwrap();
    assert!(tpm.stale);
    // With the only password slot stale, there is nothing to offer.
    let p = Interactive::new(vec![]);
    assert!(matches!(
        k.unlock(&mut p.channel(), None),
        Err(Error::NoMethodWorked(_))
    ));
    k.retry_slot(tpm.id).unwrap();
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
}

/// Refusals that say nothing about the slot (here the TPM's reserve)
/// leave it alone, and the prompter is told when to retry.
#[test]
fn an_exhausted_tpm_does_not_make_the_slot_stale() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    env.sw.set_da_parameters(3, 600, 86400);
    let (object, _) = env.sw.tpm().seal(0, b"other").unwrap();
    for _ in 0..2 {
        assert!(env.sw.tpm().unseal(0, &object, b"wrong").is_err());
    }
    let p = Interactive::new(vec![password(PW)]);
    assert!(k.unlock(&mut p.channel(), None).is_err());
    let errors = asks(&p.sent());
    assert!(
        errors.iter().any(|(_, wait)| *wait == Some(600)),
        "{errors:?}"
    );
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
}

#[test]
fn a_fido2_keyring_unlocks_with_the_pin_and_retries_a_wrong_one() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let p = Interactive::new(vec![pin(PIN)]);
    k.create(&mut p.channel(), Method::Fido2).unwrap();
    k.lock();
    let p = Interactive::new(vec![FromPrompter::Fido2 {}, pin("000000"), pin(PIN)]);
    k.unlock(&mut p.channel(), None).unwrap();
    let pins: Vec<Option<String>> = p
        .sent()
        .iter()
        .filter_map(|m| match m {
            ToPrompter::Fido2Pin { error, .. } => Some(error.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(pins, [None, Some("wrong PIN (2 more tries here)".into())]);
    assert!(
        p.sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::Touch { .. }))
    );
}

/// Removing a slot rotates MK: every other slot is re-proven (the password
/// from re-authentication, each key's touch), and one that cannot be
/// presented is dropped only after the user confirms.
#[test]
fn removing_a_slot_rotates_and_drops_absent_keys_only_on_confirmation() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    create_with_password(&k);
    let p = Interactive::new(vec![password(PW), pin(PIN)]);
    k.enroll_fido2(&mut p.channel(), false).unwrap();
    drop(k);
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    let p = Interactive::new(vec![password(PW), pin(PIN)]);
    k.enroll_fido2(&mut p.channel(), false).unwrap();
    let before = k.status().unwrap().keyslots;
    let fido: Vec<_> = before
        .iter()
        .filter(|s| s.kind == "fido2")
        .map(|s| s.id)
        .collect();
    assert_eq!((before.len(), fido.len()), (4, 2));
    // Unplug both keys, then remove the first: the second cannot be
    // re-wrapped.
    drop(k);
    let k = keyring(&env, MockKeys::default());
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    // Re-auth, skip the absent key, decline: nothing changes.
    let decline = Interactive::new(vec![
        password(PW),
        FromPrompter::Cancel {},
        FromPrompter::Confirm { yes: false },
    ]);
    assert!(matches!(
        k.remove_keyslot(&mut decline.channel(), fido[0]),
        Err(Error::Cancelled)
    ));
    assert_eq!(k.status().unwrap().keyslots, before);
    assert!(
        decline
            .sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::Confirm { text } if text.contains("security key")))
    );
    // Accept: both FIDO2 slots are gone; the TPM slot still works.
    let accept = Interactive::new(vec![
        password(PW),
        FromPrompter::Cancel {},
        FromPrompter::Confirm { yes: true },
    ]);
    k.remove_keyslot(&mut accept.channel(), fido[0]).unwrap();
    let kinds: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(kinds, ["recovery", "tpm"]);
    k.lock();
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
}

/// Removing the only unlock method would leave only the recovery key.
#[test]
fn the_last_unlock_method_cannot_be_removed() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let tpm = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .find(|s| s.kind == "tpm")
        .unwrap();
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(
        k.remove_keyslot(&mut p.channel(), tpm.id),
        Err(Error::LastMethod)
    ));
    assert_eq!(k.status().unwrap().keyslots.len(), 2);
}

#[test]
fn rotation_keeps_every_presented_slot_working() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let before = k.status().unwrap().keyslots;
    let p = Interactive::new(vec![password(PW)]);
    k.rotate_master(&mut p.channel()).unwrap();
    assert_eq!(k.status().unwrap().keyslots.len(), before.len());
    k.lock();
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
}

#[test]
fn the_last_recovery_slot_cannot_be_removed() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let recovery = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .find(|s| s.kind == "recovery")
        .unwrap();
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(
        k.remove_keyslot(&mut p.channel(), recovery.id),
        Err(Error::RecoverySlotRequired)
    ));
    assert_eq!(k.status().unwrap().keyslots.len(), 2);
}

#[test]
fn reissuing_the_recovery_key_replaces_the_slot() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let old = k.status().unwrap().keyslots;
    let p = Interactive::new(vec![password(PW)]);
    k.reissue_recovery(&mut p.channel()).unwrap();
    let new = k.status().unwrap().keyslots;
    let rec = |s: &[aleph_daemon::keyring::SlotInfo]| {
        s.iter()
            .filter(|x| x.kind == "recovery")
            .map(|x| x.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(rec(&new).len(), 1);
    assert_ne!(rec(&new), rec(&old));
}

/// A failed write leaves memory matching the file.
#[test]
fn a_failed_write_restores_the_body() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let vault = env.paths.vault();
    std::fs::rename(&vault, vault.with_extension("moved")).unwrap();
    std::os::unix::fs::symlink(vault.with_extension("moved"), &vault).unwrap();
    let result = k.modify(|b| {
        b.collections[0].upsert(
            aleph_core::Item::new(
                "x",
                Default::default(),
                aleph_core::SecretBytes::new(b"s".to_vec()),
                "text/plain",
            ),
            false,
        );
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 0);
}

/// A rolled-back file opens but refuses writes.
#[test]
fn a_rolled_back_file_is_read_only() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let vault = env.paths.vault();
    let old = std::fs::read(&vault).unwrap();
    k.modify(|_| Ok(())).unwrap();
    k.lock();
    std::fs::write(&vault, old).unwrap();
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
    assert!(matches!(k.modify(|_| Ok(())), Err(Error::Untrusted(_))));
    assert!(matches!(
        p.sent().last(),
        Some(ToPrompter::Done { ok: true, message: Some(m) }) if m.contains("rolled back")
    ));
}

/// Reads never wait for a prompt: while an unlock waits on the user,
/// `read` answers `Locked` at once.
#[test]
fn reads_do_not_wait_for_a_prompt() {
    let env = env();
    let k = Arc::new(keyring(&env, MockKeys::default()));
    create_with_password(&k);
    k.lock();
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut silent =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(3)).unwrap();
    let waiting = {
        let k = k.clone();
        std::thread::spawn(move || k.unlock(&mut silent, None))
    };
    std::thread::sleep(std::time::Duration::from_millis(200));
    let t = std::time::Instant::now();
    assert!(matches!(k.read(|_| ()), Err(Error::Locked)));
    assert!(k.status().unwrap().locked);
    assert!(t.elapsed() < std::time::Duration::from_millis(500));
    assert!(waiting.join().unwrap().is_err());
}

/// `status` never waits for the hardware: while a FIDO2 unlock waits for
/// the key to be plugged in (holding the hardware), it answers at once,
/// with the TPM's usability unknown.
#[test]
fn status_does_not_wait_while_a_key_is_awaited() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let p = Interactive::new(vec![pin(PIN)]);
    k.create(&mut p.channel(), Method::Fido2).unwrap();
    drop(k);
    let k = Arc::new(keyring(&env, MockKeys::default()));
    let waiting = {
        let k = k.clone();
        std::thread::spawn(move || {
            let p = Interactive::new(vec![FromPrompter::Fido2 {}]);
            k.unlock(&mut p.channel(), None)
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(150));
    let t = std::time::Instant::now();
    let s = k.status().unwrap();
    assert!(
        t.elapsed() < std::time::Duration::from_millis(100),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(s.tpm, None);
    assert!(waiting.join().unwrap().is_err());
}

/// Review C1: a TPM refusal that says nothing about the slot (Busy) stops
/// the rotation; it must never offer to drop a working slot, and reissue
/// must never leave only the recovery key.
#[test]
fn a_busy_tpm_stops_a_rotation_instead_of_dropping_the_slot() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    drop(k);
    // Good for the unlock and the re-authentication; Busy after that.
    let flaky = FlakyTpm {
        inner: TpmClient::new(env.socket.clone()),
        ok: 2.into(),
        then: || aleph_unlock::Error::TpmBusy,
    };
    let k = keyring_with(
        &env,
        Box::new(flaky),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let before = k.status().unwrap().keyslots;
    let p = Interactive::new(vec![password(PW), FromPrompter::Confirm { yes: true }]);
    assert!(matches!(
        k.reissue_recovery(&mut p.channel()),
        Err(Error::Unlock(aleph_unlock::Error::TpmBusy))
    ));
    assert_eq!(k.status().unwrap().keyslots, before);
    let sent = p.sent();
    assert!(!sent.iter().any(|m| matches!(m, ToPrompter::Confirm { .. })));
    // Review I-B: the new recovery key is never shown for a reissue that
    // then fails.
    assert!(
        !sent
            .iter()
            .any(|m| matches!(m, ToPrompter::ShowRecoveryKey { .. }))
    );
}

/// Review C1: reissuing the recovery key never leaves only the recovery
/// slot, even when the user agrees to drop a slot that rejects the
/// password.
#[test]
fn reissue_never_leaves_only_the_recovery_key() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    drop(k);
    let flaky = FlakyTpm {
        inner: TpmClient::new(env.socket.clone()),
        ok: 2.into(),
        then: || aleph_unlock::Error::TpmAuthFailed,
    };
    let k = keyring_with(
        &env,
        Box::new(flaky),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let before: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    let p = Interactive::new(vec![password(PW), FromPrompter::Confirm { yes: true }]);
    assert!(matches!(
        k.reissue_recovery(&mut p.channel()),
        Err(Error::LastMethod)
    ));
    let after: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(after, before);
}

/// Review I5: with a PAM-accepted password, once the newest TPM slot
/// rejects it the older ones are marked stale without being tried (one
/// dictionary-attack failure, not one per slot), and a rotation never
/// unseals a stale slot.
#[test]
fn stale_tpm_slots_cost_one_failure_and_rotation_skips_them() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::one(MockAuthenticator::with_pin(PIN)),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.enroll_tpm(&mut Interactive::new(vec![password(PW)]).channel())
        .unwrap();
    k.enroll_fido2(
        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
        false,
    )
    .unwrap();
    k.lock();
    // The login password changed elsewhere: PAM now accepts "new".
    login.set("new");
    assert!(
        k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
            .is_err()
    );
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
    let stale: Vec<_> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .filter(|s| s.stale)
        .collect();
    assert_eq!(stale.len(), 2);
    // Unlock with the key, rotate: the stale slots are offered for removal
    // without another TPM attempt.
    k.unlock(
        &mut Interactive::new(vec![FromPrompter::Fido2 {}, pin(PIN)]).channel(),
        None,
    )
    .unwrap();
    let p = Interactive::new(vec![
        FromPrompter::Fido2 {},
        pin(PIN),
        // (Both TPM slots are stale: no password is asked for.)
        FromPrompter::Confirm { yes: true },
    ]);
    k.rotate_master(&mut p.channel()).unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
    let confirm = p
        .sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::Confirm { text } => Some(text),
            _ => None,
        })
        .unwrap();
    assert!(confirm.contains("stale"), "{confirm}");
}

/// Review I6: when PAM cannot check a password, TPM slots are skipped but
/// a login-password slot still opens the vault.
#[test]
fn without_pam_a_login_password_slot_still_unlocks() {
    let env = env();
    // A vault with a login-password slot and (added later) a TPM slot.
    let k = keyring_with(
        &env,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_with_password(&k);
    drop(k);
    let k = keyring(&env, MockKeys::default());
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    k.enroll_tpm(&mut Interactive::new(vec![password(PW)]).channel())
        .unwrap();
    let kinds: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(kinds, ["recovery", "login-password", "tpm"]);
    drop(k);
    // PAM cannot check: the TPM is not risked, the login-password slot opens.
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(Unavailable),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
}

/// A TPM slot is sealed only with the current login password, even when
/// re-authentication used an (outdated) login-password slot.
#[test]
fn a_tpm_slot_is_sealed_only_with_the_current_login_password() {
    let env = env();
    let k = keyring_with(
        &env,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_with_password(&k);
    drop(k);
    // The login password changed; the vault still opens with the old one.
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(Fixed(|p| p == "new")),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(
        k.enroll_tpm(&mut p.channel()),
        Err(Error::Invalid(_))
    ));
    assert_eq!(k.status().unwrap().keyslots.len(), 2);
}

/// Review minors 3 and 4: TPM slots are tried newest first, and within
/// one second the later-added slot counts as newer: the current slot opens
/// the vault without spending an attempt on the outdated one.
#[test]
fn the_newest_tpm_slot_is_tried_first() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::one(MockAuthenticator::with_pin(PIN)),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.enroll_fido2(
        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
        false,
    )
    .unwrap();
    // The password changes; a new TPM slot is sealed with it (same second).
    login.set("new");
    let p = Interactive::new(vec![FromPrompter::Fido2 {}, pin(PIN), password("new")]);
    k.enroll_tpm(&mut p.channel()).unwrap();
    k.lock();
    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
        .unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
}

/// Review minor 2: a rotation never offers the TPM a password PAM has not
/// accepted (here PAM cannot check at all, so it stops instead).
#[test]
fn a_rotation_offers_the_tpm_only_a_pam_accepted_password() {
    let env = env();
    let k = keyring_with(
        &env,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_with_password(&k);
    drop(k);
    let k = keyring(&env, MockKeys::default());
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    k.enroll_tpm(&mut Interactive::new(vec![password(PW)]).channel())
        .unwrap();
    drop(k);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(Unavailable),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let before = k.status().unwrap().keyslots;
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(
        k.rotate_master(&mut p.channel()),
        Err(Error::PasswordCheckUnavailable)
    ));
    assert_eq!(k.status().unwrap().keyslots, before);
}

/// Review minor 10: wrong FIDO2 PINs have a small budget per conversation,
/// so typos cannot burn the key's lifetime PIN retries.
#[test]
fn wrong_pins_end_the_conversation_after_three() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    k.create(
        &mut Interactive::new(vec![pin(PIN)]).channel(),
        Method::Fido2,
    )
    .unwrap();
    k.lock();
    let p = Interactive::new(vec![
        FromPrompter::Fido2 {},
        pin("000000"),
        pin("000000"),
        pin("000000"),
        pin(PIN),
    ]);
    assert!(k.unlock(&mut p.channel(), None).is_err());
    let asked = p
        .sent()
        .iter()
        .filter(|m| matches!(m, ToPrompter::Fido2Pin { .. }))
        .count();
    assert_eq!(asked, 3);
}

#[test]
fn creating_twice_is_refused() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let p = Scripted::new(vec![]);
    assert!(matches!(
        k.create(&mut p.launch().unwrap(), Method::Password),
        Err(Error::VaultExists)
    ));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-daemon/src/prompt.rs`:

```rust
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
```

Write `crates/aleph-daemon/src/keyring.rs`:

```rust
//! The keyring engine: the vault's lock state, unlocking with enrolled
//! methods, and keyslot management (spec §4 "Rotation and revocation", §5,
//! §6).
//!
//! Concurrency: reads (the Secret Service) take only `inner`, briefly, so
//! they never wait for a prompt (§4 "Locked search": no call blocks on the
//! user). Prompter conversations are serialized by `ops`. Hardware (TPM,
//! FIDO2, PAM) sits behind `hw`, which is always taken before `inner`.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use aleph_core::{
    Argon2Params, Body, Kek, Keyslot, LockedVault, RecoveryKey, SlotKind, Standing, TpmSlot,
    UnlockedVault,
};
use aleph_tpm_proto::Parent;
use aleph_unlock::fido2::{self, Keys, Verification};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::password::{PasswordCheck, TypedLimiter};
use crate::paths::Paths;
use crate::prompt::{Caller, Channel, FromPrompter, Method, Purpose, Secret, ToPrompter};
use crate::state::SlotState;
use crate::store::Store;

/// The TPM, as the engine uses it (the real one is `aleph_unlock::TpmClient`).
pub trait Tpm: Send {
    fn seal(&self, password: &[u8]) -> aleph_unlock::Result<(Kek, TpmSlot)>;
    fn unseal(&self, slot: &TpmSlot, password: &[u8]) -> aleph_unlock::Result<Kek>;
    /// Whether new TPM slots can be sealed here.
    fn usable(&self) -> bool;
}

impl Tpm for aleph_unlock::TpmClient {
    fn seal(&self, password: &[u8]) -> aleph_unlock::Result<(Kek, TpmSlot)> {
        aleph_unlock::TpmClient::seal(self, password)
    }

    fn unseal(&self, slot: &TpmSlot, password: &[u8]) -> aleph_unlock::Result<Kek> {
        aleph_unlock::TpmClient::unseal(self, slot, password)
    }

    fn usable(&self) -> bool {
        self.status().is_ok_and(|s| s.parent != Parent::Unavailable)
    }
}

pub struct Backends {
    pub tpm: Box<dyn Tpm>,
    pub keys: Box<dyn Keys + Send>,
    pub password: Box<dyn PasswordCheck>,
}

/// One keyslot as `Status` reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotInfo {
    pub id: Uuid,
    pub label: String,
    /// `tpm`, `fido2`, `recovery`, `login-password`, or an unknown type.
    pub kind: String,
    pub created: u64,
    pub stale: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// A vault exists.
    pub vault: bool,
    pub locked: bool,
    /// Why writes are refused, if they are (a rolled-back or replaced file).
    pub untrusted: Option<String>,
    /// Whether MK's page is locked in RAM (`None` while locked).
    pub memory_locked: Option<bool>,
    /// Whether new TPM slots can be sealed; `None` if unknown right now
    /// (the hardware is busy with a prompt, and status never waits).
    pub tpm: Option<bool>,
    pub keyslots: Vec<SlotInfo>,
}

/// Answers a conversation accepts before giving up.
const MAX_ATTEMPTS: usize = 10;
/// Wrong FIDO2 PINs a conversation accepts (as CTAP allows per power
/// cycle); every wrong PIN spends one of the key's lifetime retries.
const PIN_ATTEMPTS: usize = 3;

/// KEKs gathered for a rotation, by slot.
type Keks = Vec<(Uuid, Kek)>;

/// What a successful re-authentication proved, kept only for the
/// operation that asked for it.
pub struct Proof {
    /// The password that opened the vault, if that was the method (it may
    /// be outdated if it opened a login-password slot without PAM).
    password: Option<Zeroizing<String>>,
    /// The current login password (PAM accepted it): the only one ever
    /// offered to the TPM.
    login: Option<Zeroizing<String>>,
    /// The FIDO2 slot touched, and its KEK.
    fido2: Option<(Uuid, Kek)>,
}

/// The result of opening the vault file with one slot.
struct Opened {
    vault: UnlockedVault,
    slot: Uuid,
    kek: Option<Kek>,
}

struct Inner {
    store: Store,
    state: SlotState,
    vault: Option<UnlockedVault>,
    /// `Some(reason)` if the unlocked file is not trusted for writing.
    untrusted: Option<&'static str>,
    typed: TypedLimiter,
}

pub struct Keyring {
    inner: Mutex<Inner>,
    hw: Mutex<Backends>,
    ops: Mutex<()>,
    /// Argon2 parameters for new login-password slots.
    pub argon2: Argon2Params,
    /// How long to wait for a FIDO2 key to be plugged in.
    pub key_wait: Duration,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn kind_name(kind: &SlotKind) -> String {
    kind.type_name().to_string()
}

impl Keyring {
    pub fn new(paths: &Paths, backends: Backends) -> Result<Self> {
        Ok(Self::from_store(Store::open(paths)?, paths, backends))
    }

    /// A keyring on an already opened store.
    pub fn from_store(store: Store, paths: &Paths, backends: Backends) -> Self {
        Self {
            inner: Mutex::new(Inner {
                store,
                state: SlotState::load(&paths.slot_state()),
                vault: None,
                untrusted: None,
                typed: TypedLimiter::default(),
            }),
            hw: Mutex::new(backends),
            ops: Mutex::new(()),
            argon2: Argon2Params::LOGIN_PASSWORD_FLOOR,
            key_wait: Duration::from_secs(120),
        }
    }

    pub fn is_locked(&self) -> bool {
        lock(&self.inner).vault.is_none()
    }

    pub fn status(&self) -> Result<Status> {
        // Try, never wait: the hardware may be held by a prompt (a FIDO2
        // touch can take a while), and taking `hw` after `inner` would
        // invert the lock order.
        let tpm = self.hw.try_lock().ok().map(|hw| hw.tpm.usable());
        let inner = lock(&self.inner);
        let slot = |k: &Keyslot| SlotInfo {
            id: k.id,
            label: k.label.clone(),
            kind: kind_name(&k.kind),
            created: k.created,
            stale: inner.state.is_stale(k.id),
        };
        let unknown = |u: &aleph_core::UnknownSlot| SlotInfo {
            id: u.id.unwrap_or_default(),
            label: u.label.clone().unwrap_or_default(),
            kind: u.slot_type.clone(),
            created: 0,
            stale: false,
        };
        let keyslots = match &inner.vault {
            Some(v) => v
                .keyslots()
                .map(slot)
                .chain(v.unknown_keyslots().map(unknown))
                .collect(),
            None if inner.store.exists() => {
                let v = inner.store.read()?;
                v.keyslots()
                    .map(slot)
                    .chain(v.unknown_keyslots().map(unknown))
                    .collect()
            }
            None => Vec::new(),
        };
        Ok(Status {
            vault: inner.store.exists(),
            locked: inner.vault.is_none(),
            untrusted: inner.untrusted.map(str::to_string),
            memory_locked: inner.vault.as_ref().map(UnlockedVault::memory_locked),
            tpm,
            keyslots,
        })
    }

    /// Lock: drop (and so zeroize) MK and the decrypted body.
    pub fn lock(&self) {
        let mut inner = lock(&self.inner);
        inner.vault = None;
        inner.untrusted = None;
    }

    /// Read the unlocked body.
    pub fn read<T>(&self, f: impl FnOnce(&Body) -> T) -> Result<T> {
        let inner = lock(&self.inner);
        inner
            .vault
            .as_ref()
            .map(|v| f(v.body()))
            .ok_or(Error::Locked)
    }

    /// Change the body and write the vault. If `f` or the write fails, the
    /// in-memory body is restored, so memory never runs ahead of the file.
    pub fn modify<T>(&self, f: impl FnOnce(&mut Body) -> Result<T>) -> Result<T> {
        let mut inner = lock(&self.inner);
        let Inner {
            store,
            vault,
            untrusted,
            ..
        } = &mut *inner;
        if let Some(reason) = untrusted {
            return Err(Error::Untrusted(reason));
        }
        let vault = vault.as_mut().ok_or(Error::Locked)?;
        let snapshot = vault.body().clone();
        let result = f(vault.body_mut()).and_then(|out| store.write(vault).map(|_| out));
        if result.is_err() {
            *vault.body_mut() = snapshot;
        }
        result
    }

    /// Change keyslots and write. A keyslot change cannot be undone in
    /// memory, so if the write fails the vault is locked instead: the next
    /// unlock reads what is really on disk.
    fn modify_vault<T>(&self, f: impl FnOnce(&mut UnlockedVault) -> Result<T>) -> Result<T> {
        let mut inner = lock(&self.inner);
        if let Some(reason) = inner.untrusted {
            return Err(Error::Untrusted(reason));
        }
        let Inner { store, vault, .. } = &mut *inner;
        let v = vault.as_mut().ok_or(Error::Locked)?;
        let result = f(v).and_then(|out| store.write(v).map(|_| out));
        if result.is_err() {
            inner.vault = None;
        }
        result
    }

    /// The methods the prompter may offer for `vault`: the login password
    /// if a usable password slot exists, FIDO2 if a FIDO2 slot does. Never
    /// recovery (§5: recovery is its own flow).
    fn methods(&self, vault: &LockedVault) -> Vec<Method> {
        let inner = lock(&self.inner);
        let mut password = false;
        let mut fido = false;
        for k in vault.keyslots() {
            match &k.kind {
                SlotKind::Tpm(_) if !inner.state.is_stale(k.id) => password = true,
                SlotKind::LoginPassword(_) => password = true,
                SlotKind::Fido2(_) => fido = true,
                _ => {}
            }
        }
        let mut methods = Vec::new();
        if password {
            methods.push(Method::Password);
        }
        if fido {
            methods.push(Method::Fido2);
        }
        methods
    }

    /// Unlock through the prompter.
    pub fn unlock(&self, chan: &mut Channel, caller: Option<Caller>) -> Result<()> {
        let _op = lock(&self.ops);
        converse(chan, |chan| {
            chan.send(&ToPrompter::Begin {
                purpose: Purpose::Unlock,
                operation: "Unlock the keyring".into(),
                caller,
            })?;
            if !self.is_locked() {
                return Ok(None);
            }
            let locked = lock(&self.inner).store.read()?;
            let opened = self.choose_and_open(chan, &locked)?;
            self.install(opened.vault)
        })
    }

    /// Unlock with a password the login stack already accepted (from
    /// `pam_aleph`, Plan 4): no PAM check, no typed-attempt accounting.
    pub fn unlock_with_login_password(&self, password: &str) -> Result<()> {
        let _op = lock(&self.ops);
        if !self.is_locked() {
            return Ok(());
        }
        let locked = lock(&self.inner).store.read()?;
        let opened = self.open_with_password(&locked, password, false)?;
        self.install(opened.vault).map(|_| ())
    }

    /// Ask for a method until one opens `vault` (or the user cancels).
    fn choose_and_open(&self, chan: &mut Channel, vault: &LockedVault) -> Result<Opened> {
        let methods = self.methods(vault);
        if methods.is_empty() {
            return Err(Error::NoMethodWorked(Some(
                "every enrolled unlock method is stale; `aleph keyslot retry` or re-enroll".into(),
            )));
        }
        let mut error: Option<String> = None;
        let mut retry_after = None;
        for _ in 0..MAX_ATTEMPTS {
            let reply = chan.ask(&ToPrompter::Ask {
                methods: methods.clone(),
                error: error.take(),
                retry_after: retry_after.take(),
            })?;
            let attempt = match reply {
                FromPrompter::Password { password } if methods.contains(&Method::Password) => {
                    self.open_with_password(vault, password.expose(), true)
                }
                FromPrompter::Fido2 {} if methods.contains(&Method::Fido2) => {
                    self.open_with_fido2(chan, vault, None)
                }
                other => return Err(Error::Prompt(format!("unexpected reply {other:?}"))),
            };
            match attempt {
                Ok(opened) => return Ok(opened),
                // Waiting is not something to retry at once.
                Err(e @ (Error::Cancelled | Error::Prompt(_) | Error::TooManyAttempts { .. })) => {
                    return Err(e);
                }
                Err(e) => {
                    retry_after = retry_after_of(&e);
                    error = Some(e.to_string());
                }
            }
        }
        Err(Error::Invalid("too many attempts".into()))
    }

    /// Try `password` on the usable password slots: TPM slots first (after
    /// a PAM check if it was typed, so typos never reach the TPM), then
    /// login-password slots. A TPM slot that rejects a password PAM
    /// accepted is marked stale.
    fn open_with_password(
        &self,
        vault: &LockedVault,
        password: &str,
        typed: bool,
    ) -> Result<Opened> {
        let now = Instant::now();
        let (tpm_slots, password_slots): (Vec<_>, Vec<_>) = {
            let mut inner = lock(&self.inner);
            if typed && let Some(wait) = inner.typed.blocked(now) {
                return Err(Error::TooManyAttempts { retry_after: wait });
            }
            vault
                .keyslots()
                .filter(|k| match &k.kind {
                    SlotKind::Tpm(_) => !inner.state.is_stale(k.id),
                    SlotKind::LoginPassword(_) => true,
                    _ => false,
                })
                .partition(|k| matches!(k.kind, SlotKind::Tpm(_)))
        };
        if tpm_slots.is_empty() && password_slots.is_empty() {
            return Err(Error::NoMethodWorked(Some(
                "no usable password keyslot".into(),
            )));
        }
        let hw = lock(&self.hw);
        let mut last = None;
        let mut use_tpm = !tpm_slots.is_empty();
        if typed && use_tpm {
            match hw.password.check(password) {
                Ok(true) => {}
                Ok(false) => {
                    lock(&self.inner).typed.record_failure(now);
                    return Err(Error::WrongPassword);
                }
                // PAM cannot check it: keep it away from the TPM (it may be
                // a typo), but login-password slots check it themselves.
                Err(e) => {
                    use_tpm = false;
                    last = Some(e);
                }
            }
        }
        if use_tpm {
            // Newest first: the most recently enrolled slot is the one most
            // likely sealed with the current password. Once one rejects it,
            // the older ones are stale too; they are marked without
            // spending more of the TPM's dictionary-attack budget.
            // (Ties, within a second: the later-added slot is newer.)
            let mut tpm_slots: Vec<(usize, &Keyslot)> = tpm_slots.into_iter().enumerate().collect();
            tpm_slots.sort_by_key(|(i, k)| std::cmp::Reverse((k.created, *i)));
            let tpm_slots: Vec<&Keyslot> = tpm_slots.into_iter().map(|(_, k)| k).collect();
            for (i, k) in tpm_slots.iter().enumerate() {
                let SlotKind::Tpm(slot) = &k.kind else {
                    unreachable!()
                };
                match hw.tpm.unseal(slot, password.as_bytes()) {
                    Ok(kek) => {
                        return Ok(Opened {
                            vault: vault.unlock(k.id, &kek)?,
                            slot: k.id,
                            kek: Some(kek),
                        });
                    }
                    // Only these say something about the slot (Plan 2): the
                    // password it was sealed with is not this one.
                    Err(aleph_unlock::Error::TpmAuthFailed | aleph_unlock::Error::TpmWrongUser) => {
                        let mut inner = lock(&self.inner);
                        for older in &tpm_slots[i..] {
                            inner.state.mark_stale(older.id)?;
                        }
                        tracing::warn!(slot = %k.id, "TPM keyslot rejected the login password; marked stale");
                        last = Some(Error::Stale(k.label.clone()));
                        break;
                    }
                    Err(e) => last = Some(e.into()),
                }
            }
        }
        for k in password_slots {
            match vault.unlock_login_password(k.id, password.as_bytes()) {
                Ok(v) => {
                    return Ok(Opened {
                        vault: v,
                        slot: k.id,
                        kek: None,
                    });
                }
                Err(aleph_core::Error::UnwrapFailed) => {
                    if typed {
                        lock(&self.inner).typed.record_failure(now);
                    }
                    last = Some(Error::WrongPassword);
                }
                Err(e) => last = Some(e.into()),
            }
        }
        Err(last.unwrap_or(Error::NoMethodWorked(None)))
    }

    /// Open `vault` with a FIDO2 slot: wait for a key holding one (or only
    /// `only`), ask its PIN if needed, then the touch.
    fn open_with_fido2(
        &self,
        chan: &mut Channel,
        vault: &LockedVault,
        only: Option<Uuid>,
    ) -> Result<Opened> {
        let slots: Vec<(Uuid, String, aleph_core::Fido2Slot)> = vault
            .keyslots()
            .filter(|k| only.is_none_or(|id| id == k.id))
            .filter_map(|k| match &k.kind {
                SlotKind::Fido2(s) => Some((k.id, k.label.clone(), s.clone())),
                _ => None,
            })
            .collect();
        if slots.is_empty() {
            return Err(Error::NoMethodWorked(Some("no FIDO2 keyslot".into())));
        }
        let mut hw = lock(&self.hw);
        let names = slots
            .iter()
            .map(|s| s.1.as_str())
            .collect::<Vec<_>>()
            .join(" or ");
        let (id, label, slot) = self.wait_for_key(chan, &mut hw, &slots, &names)?;
        let mut error = None;
        let mut wrong_pins = 0;
        loop {
            let pin = if slot.pin_required {
                match chan.ask(&ToPrompter::Fido2Pin {
                    key: label.clone(),
                    error: error.take(),
                })? {
                    FromPrompter::Pin { pin } => Some(pin),
                    other => return Err(Error::Prompt(format!("unexpected reply {other:?}"))),
                }
            } else {
                None
            };
            chan.send(&ToPrompter::Touch { key: label.clone() })?;
            match fido2::unlock(&mut *hw.keys, &slot, pin.as_ref().map(Secret::expose)) {
                Ok(kek) => {
                    return Ok(Opened {
                        vault: vault.unlock(id, &kek)?,
                        slot: id,
                        kek: Some(kek),
                    });
                }
                Err(aleph_unlock::Error::Fido2PinInvalid) if slot.pin_required => {
                    wrong_pins += 1;
                    if wrong_pins >= PIN_ATTEMPTS {
                        return Err(aleph_unlock::Error::Fido2PinInvalid.into());
                    }
                    error = Some(format!(
                        "wrong PIN ({} more tries here)",
                        PIN_ATTEMPTS - wrong_pins
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Wait until a connected key holds one of `slots`, telling the
    /// prompter to show "insert your key" meanwhile.
    fn wait_for_key(
        &self,
        chan: &mut Channel,
        hw: &mut Backends,
        slots: &[(Uuid, String, aleph_core::Fido2Slot)],
        names: &str,
    ) -> Result<(Uuid, String, aleph_core::Fido2Slot)> {
        let deadline = Instant::now() + self.key_wait;
        let mut asked = false;
        loop {
            for s in slots {
                if fido2::present(&mut *hw.keys, &s.2)? {
                    return Ok(s.clone());
                }
            }
            if !asked {
                chan.send(&ToPrompter::InsertKey { key: names.into() })?;
                asked = true;
            }
            if chan.cancelled()? {
                return Err(Error::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Error::Prompt("timed out waiting for a security key".into()));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Make an opened vault the unlocked one, after the high-water check.
    /// Returns the warning to show if the file is not trusted for writes.
    fn install(&self, vault: UnlockedVault) -> Result<Option<String>> {
        let mut inner = lock(&self.inner);
        let untrusted = match inner.store.raise(&vault)? {
            Standing::Unrecorded | Standing::Current | Standing::Newer => None,
            Standing::Pending => {
                inner.store.record(&vault.mark())?;
                None
            }
            Standing::RolledBack { .. } => Some("rolled back to an older version"),
            Standing::Replaced => Some("replaced by a different vault"),
            Standing::Rekeyed => Some("re-keyed somewhere else"),
        };
        let ids: HashSet<Uuid> = vault.keyslots().map(|k| k.id).collect();
        inner.state.retain(|id| ids.contains(&id))?;
        inner.vault = Some(vault);
        inner.untrusted = untrusted;
        Ok(untrusted.map(|why| Error::Untrusted(why).to_string()))
    }

    /// Prove an enrolled method again (spec §6: every keyslot, config, or
    /// custody change requires it).
    fn reauth(&self, chan: &mut Channel, operation: &str) -> Result<Proof> {
        if self.is_locked() {
            return Err(Error::Locked);
        }
        chan.send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: operation.into(),
            caller: None,
        })?;
        let current = lock(&self.inner).store.read()?;
        let methods = self.methods(&current);
        if methods.is_empty() {
            return Err(Error::NoMethodWorked(None));
        }
        let mut error = None;
        let mut retry_after = None;
        for _ in 0..MAX_ATTEMPTS {
            let reply = chan.ask(&ToPrompter::Ask {
                methods: methods.clone(),
                error: error.take(),
                retry_after: retry_after.take(),
            })?;
            let (attempt, password) = match reply {
                FromPrompter::Password { password } if methods.contains(&Method::Password) => (
                    self.open_with_password(&current, password.expose(), true),
                    Some(Zeroizing::new(password.expose().to_string())),
                ),
                FromPrompter::Fido2 {} if methods.contains(&Method::Fido2) => {
                    (self.open_with_fido2(chan, &current, None), None)
                }
                other => return Err(Error::Prompt(format!("unexpected reply {other:?}"))),
            };
            match attempt {
                Ok(opened) => {
                    let fido2 = match (&password, opened.kek) {
                        (None, Some(kek)) => Some((opened.slot, kek)),
                        _ => None,
                    };
                    return Ok(Proof {
                        password,
                        login: None,
                        fido2,
                    });
                }
                Err(e @ (Error::Cancelled | Error::Prompt(_) | Error::TooManyAttempts { .. })) => {
                    return Err(e);
                }
                Err(e) => {
                    retry_after = retry_after_of(&e);
                    error = Some(e.to_string());
                }
            }
        }
        Err(Error::Invalid("too many attempts".into()))
    }

    /// Ask for the login password (PAM-checked) until it is right.
    fn ask_password(&self, chan: &mut Channel) -> Result<Zeroizing<String>> {
        let mut error = None;
        let mut retry_after = None;
        for _ in 0..MAX_ATTEMPTS {
            let reply = chan.ask(&ToPrompter::Ask {
                methods: vec![Method::Password],
                error: error.take(),
                retry_after: retry_after.take(),
            })?;
            let FromPrompter::Password { password } = reply else {
                return Err(Error::Prompt(format!("unexpected reply {reply:?}")));
            };
            let now = Instant::now();
            let hw = lock(&self.hw);
            let mut inner = lock(&self.inner);
            if let Some(wait) = inner.typed.blocked(now) {
                return Err(Error::TooManyAttempts { retry_after: wait });
            }
            drop(inner);
            if hw.password.check(password.expose())? {
                return Ok(Zeroizing::new(password.expose().to_string()));
            }
            lock(&self.inner).typed.record_failure(now);
            error = Some(Error::WrongPassword.to_string());
        }
        Err(Error::Invalid("too many attempts".into()))
    }

    /// Gather a KEK for every slot a rotation keeps (all but `drop`).
    /// Password slots use the proof's password (asked for if the proof was
    /// a FIDO2 touch); each FIDO2 slot needs its key. Slots that cannot be
    /// presented, and slots of unknown type, are removed only after the
    /// user confirms. Returns the KEKs and the full drop list.
    fn rotation_keks(
        &self,
        chan: &mut Channel,
        proof: &mut Proof,
        drop: &[Uuid],
    ) -> Result<(Keks, Vec<Uuid>)> {
        let (slots, unknown, vault_id, mk_id): (Vec<Keyslot>, Vec<String>, Uuid, [u8; 16]) = {
            let inner = lock(&self.inner);
            let v = inner.vault.as_ref().ok_or(Error::Locked)?;
            (
                v.keyslots()
                    .filter(|k| !drop.contains(&k.id))
                    .cloned()
                    .collect(),
                v.unknown_keyslots()
                    .map(|u| u.label.clone().unwrap_or_else(|| u.slot_type.clone()))
                    .collect(),
                v.vault_id(),
                v.mark().mk_id,
            )
        };
        // A KEK counts only if it really unwraps the slot's MK.
        let proves = |k: &Keyslot, kek: &Kek| {
            aleph_core::KeyHandle::unwraps_to(
                kek,
                &k.wrapped(),
                &Keyslot::aad(vault_id, k.id, &k.kind),
                &mk_id,
            )
        };
        // TPM slots newest first (ties: the later-added), after the rest.
        let (tpm, rest): (Vec<_>, Vec<_>) = slots
            .iter()
            .enumerate()
            .partition(|(_, k)| matches!(k.kind, SlotKind::Tpm(_)));
        let mut tpm = tpm;
        tpm.sort_by_key(|(i, k)| std::cmp::Reverse((k.created, *i)));
        let ordered: Vec<&Keyslot> = rest.into_iter().chain(tpm).map(|(_, k)| k).collect();
        // Once one TPM slot rejects the current password, the older ones
        // are stale too: mark them without trying.
        let mut tpm_rejected = false;
        let mut keks = Vec::new();
        // Slots that cannot be re-wrapped, and why.
        let mut missing: Vec<(Uuid, String, &str)> = Vec::new();
        for k in ordered {
            match &k.kind {
                SlotKind::Recovery(_) => {}
                // A stale slot is not tried again (it would spend one of the
                // TPM's dictionary-attack attempts to fail).
                SlotKind::Tpm(_) if tpm_rejected || lock(&self.inner).state.is_stale(k.id) => {
                    lock(&self.inner).state.mark_stale(k.id)?;
                    missing.push((k.id, k.label.clone(), "stale"));
                }
                SlotKind::Tpm(slot) => {
                    let password = self.tpm_password(chan, proof)?;
                    match lock(&self.hw).tpm.unseal(slot, password.as_bytes()) {
                        Ok(kek) if proves(k, &kek) => keks.push((k.id, kek)),
                        Ok(_) => missing.push((k.id, k.label.clone(), "does not open the vault")),
                        Err(
                            aleph_unlock::Error::TpmAuthFailed | aleph_unlock::Error::TpmWrongUser,
                        ) => {
                            lock(&self.inner).state.mark_stale(k.id)?;
                            tpm_rejected = true;
                            missing.push((k.id, k.label.clone(), "rejects your password"));
                        }
                        // Busy, rate-limited, exhausted, unreachable: says
                        // nothing about the slot. Stop rather than offer to
                        // drop a slot that works.
                        Err(e) => return Err(e.into()),
                    }
                }
                SlotKind::LoginPassword(params) => {
                    let password = self.proof_password(chan, proof)?;
                    // Argon2 outside any lock: it takes a while.
                    let kek =
                        aleph_core::derive_kek(password.as_bytes(), &params.salt, &params.params)?;
                    if proves(k, &kek) {
                        keks.push((k.id, kek));
                    } else {
                        missing.push((k.id, k.label.clone(), "rejects your password"));
                    }
                }
                SlotKind::Fido2(_) => match proof.fido2.take() {
                    Some((id, kek)) if id == k.id => keks.push((id, kek)),
                    other => {
                        proof.fido2 = other;
                        let current = lock(&self.inner).store.read()?;
                        match self.open_with_fido2(chan, &current, Some(k.id)) {
                            Ok(opened) => keks.push((k.id, opened.kek.expect("fido2 kek"))),
                            // Cancelling one key's wait means "skip it".
                            Err(Error::Cancelled) => {
                                missing.push((k.id, k.label.clone(), "key not presented"))
                            }
                            Err(e) => return Err(e),
                        }
                    }
                },
            }
        }
        let mut drops = drop.to_vec();
        if !missing.is_empty() || !unknown.is_empty() {
            let names: Vec<String> = missing
                .iter()
                .map(|(_, l, why)| format!("{l} ({why})"))
                .chain(unknown.iter().map(|u| format!("{u} (unknown type)")))
                .collect();
            let reply = chan.ask(&ToPrompter::Confirm {
                text: format!(
                    "These keyslots cannot be kept and will be removed: {}. Continue?",
                    names.join(", ")
                ),
            })?;
            if reply != (FromPrompter::Confirm { yes: true }) {
                return Err(Error::Cancelled);
            }
            drops.extend(missing.iter().map(|(id, _, _)| *id));
        }
        Ok((keks, drops))
    }

    /// Refuse a change that would leave only the recovery key: routine
    /// unlock would then be impossible (recovery is its own flow, §5).
    fn keeps_a_method(&self, drops: &[Uuid]) -> Result<()> {
        let inner = lock(&self.inner);
        let v = inner.vault.as_ref().ok_or(Error::Locked)?;
        let left = v
            .keyslots()
            .filter(|k| !drops.contains(&k.id))
            .any(|k| !matches!(k.kind, SlotKind::Recovery(_)));
        if left { Ok(()) } else { Err(Error::LastMethod) }
    }

    /// The password to offer TPM slots: one PAM accepts, never merely the
    /// one that opened the vault (it may be outdated, and each TPM
    /// rejection spends one of the TPM's dictionary-attack attempts).
    fn tpm_password<'a>(&self, chan: &mut Channel, proof: &'a mut Proof) -> Result<&'a str> {
        if proof.login.is_none() {
            let accepted = match &proof.password {
                Some(pw) => lock(&self.hw).password.check(pw)?,
                None => false,
            };
            proof.login = Some(if accepted {
                proof.password.clone().expect("checked above")
            } else {
                self.ask_password(chan)?
            });
        }
        Ok(proof.login.as_deref().expect("just set"))
    }

    fn proof_password<'a>(&self, chan: &mut Channel, proof: &'a mut Proof) -> Result<&'a str> {
        if proof.password.is_none() {
            proof.password = Some(self.ask_password(chan)?);
        }
        Ok(proof.password.as_deref().expect("just set"))
    }

    fn rotate(&self, chan: &mut Channel, proof: &mut Proof, drop: &[Uuid]) -> Result<()> {
        self.keeps_a_method(drop)?;
        let (keks, drops) = self.rotation_keks(chan, proof, drop)?;
        self.keeps_a_method(&drops)?;
        let refs: Vec<(Uuid, &Kek)> = keks.iter().map(|(id, k)| (*id, k)).collect();
        self.modify_vault(|v| Ok(v.rotate_master(&refs, &drops)?))?;
        let mut inner = lock(&self.inner);
        for id in &drops {
            inner.state.clear(*id)?;
        }
        Ok(())
    }

    /// Create the vault with a recovery slot and one unlock method.
    pub fn create(&self, chan: &mut Channel, method: Method) -> Result<()> {
        let _op = lock(&self.ops);
        converse(chan, |chan| {
            if lock(&self.inner).store.exists() {
                return Err(Error::VaultExists);
            }
            chan.send(&ToPrompter::Begin {
                purpose: Purpose::Create,
                operation: "Create the keyring".into(),
                caller: None,
            })?;
            let mut vault = UnlockedVault::create()?;
            let key = RecoveryKey::generate()?;
            vault.add_recovery_slot("recovery", &key.recipient().public_key())?;
            match method {
                Method::Password => {
                    let password = self.ask_password(chan)?;
                    let hw = lock(&self.hw);
                    if hw.tpm.usable() {
                        let (kek, slot) = hw.tpm.seal(password.as_bytes())?;
                        vault.add_keyslot("tpm", SlotKind::Tpm(slot), &kek)?;
                    } else {
                        vault.add_login_password_slot(
                            "login password",
                            password.as_bytes(),
                            self.argon2,
                        )?;
                    }
                }
                Method::Fido2 => {
                    let (kek, slot) = self.enroll_key(chan, false)?;
                    vault.add_keyslot("security key", SlotKind::Fido2(slot), &kek)?;
                }
            }
            show_recovery_key(chan, &key)?;
            let mut inner = lock(&self.inner);
            inner.store.write(&vault)?;
            inner.vault = Some(vault);
            inner.untrusted = None;
            Ok(Some("The keyring is ready.".into()))
        })
    }

    /// Enroll the one connected FIDO2 key (asking its PIN if it has one).
    fn enroll_key(
        &self,
        chan: &mut Channel,
        touch_only: bool,
    ) -> Result<(Kek, aleph_core::Fido2Slot)> {
        let mut hw = lock(&self.hw);
        let deadline = Instant::now() + self.key_wait;
        let mut asked = false;
        while !hw.keys.any_present() {
            if !asked {
                chan.send(&ToPrompter::InsertKey {
                    key: "your security key".into(),
                })?;
                asked = true;
            }
            if chan.cancelled()? {
                return Err(Error::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Error::Prompt("timed out waiting for a security key".into()));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let policy = if touch_only {
            Verification::TouchOnly
        } else {
            Verification::PinOrUv
        };
        let mut pin: Option<Secret> = None;
        let mut error = None;
        let mut wrong_pins = 0;
        loop {
            if let Some(e) = error.take() {
                pin = match chan.ask(&ToPrompter::Fido2Pin {
                    key: "your security key".into(),
                    error: Some(e),
                })? {
                    FromPrompter::Pin { pin } => Some(pin),
                    other => return Err(Error::Prompt(format!("unexpected reply {other:?}"))),
                };
            }
            chan.send(&ToPrompter::Touch {
                key: "your security key".into(),
            })?;
            match fido2::enroll(&mut *hw.keys, pin.as_ref().map(Secret::expose), policy) {
                Ok(done) => return Ok(done),
                Err(aleph_unlock::Error::Fido2PinRequired) => {
                    error = Some("enter the key's PIN".into())
                }
                Err(aleph_unlock::Error::Fido2PinInvalid) => {
                    wrong_pins += 1;
                    if wrong_pins >= PIN_ATTEMPTS {
                        return Err(aleph_unlock::Error::Fido2PinInvalid.into());
                    }
                    error = Some(format!(
                        "wrong PIN ({} more tries here)",
                        PIN_ATTEMPTS - wrong_pins
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub fn enroll_tpm(&self, chan: &mut Channel) -> Result<()> {
        let _op = lock(&self.ops);
        converse(chan, |chan| {
            let mut proof = self.reauth(chan, "Add a TPM keyslot")?;
            let password = self.proof_password(chan, &mut proof)?.to_string();
            let password = Zeroizing::new(password);
            let (kek, slot) = {
                let hw = lock(&self.hw);
                if !hw.tpm.usable() {
                    return Err(Error::Invalid("no usable TPM (see `aleph status`)".into()));
                }
                // Re-authentication may have used a login-password slot,
                // whose password could be outdated: seal only the current
                // login password, or the slot would be stale at once.
                if !hw.password.check(&password)? {
                    return Err(Error::Invalid(
                        "that password opens the keyring but is not your current login password"
                            .into(),
                    ));
                }
                hw.tpm.seal(password.as_bytes())?
            };
            self.modify_vault(|v| Ok(v.add_keyslot("tpm", SlotKind::Tpm(slot), &kek)?))?;
            Ok(Some("TPM keyslot added.".into()))
        })
    }

    pub fn enroll_fido2(&self, chan: &mut Channel, touch_only: bool) -> Result<()> {
        let _op = lock(&self.ops);
        converse(chan, |chan| {
            self.reauth(chan, "Add a security key")?;
            let (kek, slot) = self.enroll_key(chan, touch_only)?;
            self.modify_vault(|v| {
                Ok(v.add_keyslot("security key", SlotKind::Fido2(slot), &kek)?)
            })?;
            Ok(Some("Security key added.".into()))
        })
    }

    /// Remove a keyslot, rotating MK (§4).
    pub fn remove_keyslot(&self, chan: &mut Channel, id: Uuid) -> Result<()> {
        let _op = lock(&self.ops);
        converse(chan, |chan| {
            let label = {
                let inner = lock(&self.inner);
                let v = inner.vault.as_ref().ok_or(Error::Locked)?;
                let known = v.keyslots().find(|k| k.id == id).map(|k| k.label.clone());
                let unknown = v
                    .unknown_keyslots()
                    .find(|u| u.id == Some(id))
                    .map(|u| u.slot_type.clone());
                known.or(unknown).ok_or(Error::NoSuchKeyslot(id))?
            };
            let mut proof = self.reauth(chan, &format!("Remove keyslot '{label}'"))?;
            match self.rotate(chan, &mut proof, &[id]) {
                Err(Error::Core(aleph_core::Error::RecoveryRequired)) => {
                    Err(Error::RecoverySlotRequired)
                }
                other => other,
            }?;
            Ok(Some(format!(
                "Keyslot '{label}' removed; the master key was rotated."
            )))
        })
    }

    pub fn rotate_master(&self, chan: &mut Channel) -> Result<()> {
        let _op = lock(&self.ops);
        converse(chan, |chan| {
            let mut proof = self.reauth(chan, "Rotate the master key")?;
            self.rotate(chan, &mut proof, &[])?;
            Ok(Some("The master key was rotated.".into()))
        })
    }

    /// Replace the recovery key: the old one stops working (§5).
    pub fn reissue_recovery(&self, chan: &mut Channel) -> Result<()> {
        let _op = lock(&self.ops);
        converse(chan, |chan| {
            let mut proof = self.reauth(chan, "Issue a new recovery key")?;
            let old: Vec<Uuid> = {
                let inner = lock(&self.inner);
                let v = inner.vault.as_ref().ok_or(Error::Locked)?;
                v.keyslots()
                    .filter(|k| matches!(k.kind, SlotKind::Recovery(_)))
                    .map(|k| k.id)
                    .collect()
            };
            // Everything that can fail comes before the new key is shown:
            // the user must never write down a key that was not installed.
            let (keks, drops) = self.rotation_keks(chan, &mut proof, &old)?;
            self.keeps_a_method(&drops)?;
            let key = RecoveryKey::generate()?;
            show_recovery_key(chan, &key)?;
            let refs: Vec<(Uuid, &Kek)> = keks.iter().map(|(id, k)| (*id, k)).collect();
            self.modify_vault(|v| {
                v.add_recovery_slot("recovery", &key.recipient().public_key())?;
                Ok(v.rotate_master(&refs, &drops)?)
            })?;
            Ok(Some(
                "New recovery key issued; the old one no longer works.".into(),
            ))
        })
    }

    /// Clear a slot's stale mark so it is tried again.
    pub fn retry_slot(&self, id: Uuid) -> Result<()> {
        lock(&self.inner).state.clear(id)
    }

    /// Re-authenticate, then run `f` (for changes outside the vault, such
    /// as configuration, that still require it, §6).
    pub fn with_reauth(
        &self,
        chan: &mut Channel,
        operation: &str,
        f: impl FnOnce() -> Result<Option<String>>,
    ) -> Result<()> {
        let _op = lock(&self.ops);
        converse(chan, |chan| {
            self.reauth(chan, operation)?;
            f()
        })
    }
}

/// Run a conversation and end it with `Done` either way.
fn converse(
    chan: &mut Channel,
    f: impl FnOnce(&mut Channel) -> Result<Option<String>>,
) -> Result<()> {
    match f(chan) {
        Ok(message) => {
            chan.done(true, message);
            Ok(())
        }
        Err(e) => {
            chan.done(false, Some(e.to_string()));
            Err(e)
        }
    }
}

fn retry_after_of(e: &Error) -> Option<u64> {
    match e {
        Error::TooManyAttempts { retry_after } => Some(retry_after.as_secs()),
        Error::Unlock(aleph_unlock::Error::TpmRateLimited { retry_after }) => {
            Some(retry_after.as_secs())
        }
        Error::Unlock(aleph_unlock::Error::TpmExhausted { retry_after }) => {
            retry_after.map(|d| d.as_secs())
        }
        _ => None,
    }
}

/// Show a new recovery key and have the user type back two groups, to
/// confirm it was recorded (§5).
fn show_recovery_key(chan: &mut Channel, key: &RecoveryKey) -> Result<()> {
    let formatted = key.format();
    let groups: Vec<&str> = formatted.split('-').collect();
    let mut error = None;
    for _ in 0..3 {
        let mut pick = [0u8; 2];
        aleph_core::crypto::fill_random(&mut pick)?;
        let a = usize::from(pick[0]) % groups.len();
        let b = (a + 1 + usize::from(pick[1]) % (groups.len() - 1)) % groups.len();
        let check = [a.min(b) + 1, a.max(b) + 1];
        let reply = chan.ask(&ToPrompter::ShowRecoveryKey {
            key: Secret::new(formatted.as_str()),
            check,
            error: error.take(),
        })?;
        let FromPrompter::RecoveryCheck { groups: typed } = reply else {
            return Err(Error::Prompt(format!("unexpected reply {reply:?}")));
        };
        if normalize(typed[0].expose()) == groups[check[0] - 1]
            && normalize(typed[1].expose()) == groups[check[1] - 1]
        {
            return Ok(());
        }
        error = Some("those groups do not match; check what you wrote down".into());
    }
    Err(Error::Invalid("the recovery key was not confirmed".into()))
}

/// Recovery-key input rules (§5): case-insensitive, O→0, I/L→1.
fn normalize(group: &str) -> String {
    group
        .trim()
        .chars()
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::Launcher;
    use crate::prompt::scripted::Scripted;

    fn check(a: &str, b: &str) -> FromPrompter {
        FromPrompter::RecoveryCheck {
            groups: [Secret::new(a), Secret::new(b)],
        }
    }

    /// The recovery key counts as recorded only if the user types back the
    /// groups asked for; three wrong answers fail the operation.
    #[test]
    fn a_wrong_recovery_confirmation_is_refused() {
        let key = RecoveryKey::generate().unwrap();
        let p = Scripted::new(vec![check("0000", "0000"); 3]);
        let mut chan = p.launch().unwrap();
        assert!(matches!(
            show_recovery_key(&mut chan, &key),
            Err(Error::Invalid(_))
        ));
        let shown = p
            .sent()
            .into_iter()
            .filter(|m| matches!(m, ToPrompter::ShowRecoveryKey { .. }))
            .count();
        assert_eq!(shown, 3);
    }

    #[test]
    fn recovery_groups_are_normalized_like_recovery_input() {
        assert_eq!(normalize(" o1il "), "0111");
        assert_eq!(normalize("ab2c"), "AB2C");
    }
}
```

Write `crates/aleph-daemon/src/testing.rs`:

```rust
//! Test support (feature `testing`), shared by this crate's and the CLI's
//! integration tests: a TPM helper on swtpm, a keyring on it, a private
//! session bus, and scripted prompters. Nothing here is used in production.
#![allow(dead_code, unused_imports)]

use std::os::unix::net::UnixListener;
pub use std::sync::Arc;

pub use crate::Error;
pub use crate::keyring::{Backends, Keyring, Tpm};
pub use crate::password::Fixed;
pub use crate::paths::Paths;
pub use crate::prompt::scripted::Scripted;
pub use crate::prompt::{FromPrompter, Launcher, Method, Secret, ToPrompter};
pub use aleph_tpmd::server::Policy;
pub use aleph_tpmd::testing::SwTpm;
pub use aleph_unlock::TpmClient;
pub use aleph_unlock::fido2::mock::{MockAuthenticator, MockKeys};

pub const PW: &str = "correct horse";
pub const PIN: &str = "123456";

pub struct Env {
    pub sw: SwTpm,
    _dir: tempfile::TempDir,
    pub paths: Paths,
    pub socket: std::path::PathBuf,
}

pub fn env() -> Env {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let helper = Arc::new(sw.helper_with(Policy::allow_all()));
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));
    let paths = Paths::under(dir.path());
    Env {
        sw,
        _dir: dir,
        paths,
        socket,
    }
}

pub fn keyring(env: &Env, keys: MockKeys) -> Keyring {
    keyring_with(
        env,
        Box::new(TpmClient::new(env.socket.clone())),
        keys,
        Box::new(Fixed(|p| p == PW)),
    )
}

/// A keyring with the given TPM and password check (test parameters).
pub fn keyring_with(
    env: &Env,
    tpm: Box<dyn Tpm>,
    keys: MockKeys,
    password: Box<dyn crate::password::PasswordCheck>,
) -> Keyring {
    let backends = Backends {
        tpm,
        keys: Box::new(keys),
        password,
    };
    // Tests reopen the vault right after dropping a keyring. A process
    // another test forks meanwhile (swtpm, unix_chkpwd) briefly holds a copy
    // of the daemon lock's descriptor until its exec closes it: retry.
    let mut store = crate::store::Store::open(&env.paths);
    for _ in 0..200 {
        if !matches!(store, Err(crate::Error::AlreadyRunning)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        store = crate::store::Store::open(&env.paths);
    }
    let mut k = Keyring::from_store(store.unwrap(), &env.paths, backends);
    k.argon2 = aleph_core::Argon2Params::INSECURE_TEST;
    k.key_wait = std::time::Duration::from_millis(600);
    k
}

/// A machine without a usable TPM.
pub struct NoTpm;

impl Tpm for NoTpm {
    fn seal(&self, _: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
        Err(aleph_unlock::Error::TpmUnavailable("no TPM".into()))
    }

    fn unseal(&self, _: &aleph_core::TpmSlot, _: &[u8]) -> aleph_unlock::Result<aleph_core::Kek> {
        Err(aleph_unlock::Error::TpmUnavailable("no TPM".into()))
    }

    fn usable(&self) -> bool {
        false
    }
}

/// A TPM whose unseals succeed `ok` times, then fail with `then()`
/// (`Busy`, or `AuthFailed` as if the password had changed).
pub struct FlakyTpm {
    pub inner: TpmClient,
    pub ok: std::sync::atomic::AtomicUsize,
    pub then: fn() -> aleph_unlock::Error,
}

impl Tpm for FlakyTpm {
    fn seal(&self, pw: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
        self.inner.seal(pw)
    }

    fn unseal(
        &self,
        slot: &aleph_core::TpmSlot,
        pw: &[u8],
    ) -> aleph_unlock::Result<aleph_core::Kek> {
        use std::sync::atomic::Ordering;
        if self.ok.load(Ordering::SeqCst) == 0 {
            return Err((self.then)());
        }
        self.ok.fetch_sub(1, Ordering::SeqCst);
        self.inner.unseal(slot, pw)
    }

    fn usable(&self) -> bool {
        true
    }
}

/// A password check accepting whatever the shared value currently is (the
/// login password can "change" mid-test).
#[derive(Clone)]
pub struct Accepting(pub Arc<std::sync::Mutex<String>>);

impl Accepting {
    pub fn new(pw: &str) -> Self {
        Self(Arc::new(std::sync::Mutex::new(pw.to_string())))
    }

    pub fn set(&self, pw: &str) {
        *self.0.lock().unwrap() = pw.to_string();
    }
}

impl crate::password::PasswordCheck for Accepting {
    fn check(&self, pw: &str) -> crate::Result<bool> {
        Ok(*self.0.lock().unwrap() == pw)
    }
}

/// A password check that cannot run (no PAM service file).
pub struct Unavailable;

impl crate::password::PasswordCheck for Unavailable {
    fn check(&self, _: &str) -> crate::Result<bool> {
        Err(crate::Error::PasswordCheckUnavailable)
    }
}

pub fn password(p: &str) -> FromPrompter {
    FromPrompter::Password {
        password: Secret::new(p),
    }
}

pub fn pin(p: &str) -> FromPrompter {
    FromPrompter::Pin {
        pin: Secret::new(p),
    }
}

/// Answers a `ShowRecoveryKey` by reading the key it was shown: the
/// scripted prompter cannot know the key in advance, so these tests use a
/// prompter thread that fills the check in.
fn recovery_answer(sent: &[ToPrompter]) -> Option<FromPrompter> {
    sent.iter().rev().find_map(|m| match m {
        ToPrompter::ShowRecoveryKey { key, check, .. } => {
            let groups: Vec<&str> = key.expose().split('-').collect();
            Some(FromPrompter::RecoveryCheck {
                groups: [
                    Secret::new(groups[check[0] - 1].to_lowercase()),
                    Secret::new(groups[check[1] - 1]),
                ],
            })
        }
        _ => None,
    })
}

/// A prompter that answers `Ask`/`Fido2Pin`/`Confirm` from `replies` and
/// confirms any recovery key it is shown.
pub struct Interactive {
    replies: std::sync::Mutex<Vec<FromPrompter>>,
    sent: Arc<std::sync::Mutex<Vec<ToPrompter>>>,
}

impl Interactive {
    pub fn new(replies: Vec<FromPrompter>) -> Self {
        Self {
            replies: std::sync::Mutex::new(replies),
            sent: Arc::default(),
        }
    }

    /// Everything sent, once the conversation has ended (`Done`).
    pub fn sent(&self) -> Vec<ToPrompter> {
        for _ in 0..200 {
            let sent = self.sent.lock().unwrap().clone();
            if matches!(sent.last(), Some(ToPrompter::Done { .. })) {
                return sent;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        self.sent.lock().unwrap().clone()
    }

    pub fn channel(&self) -> crate::prompt::Channel {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        self.respond(theirs);
        crate::prompt::Channel::new(ours, std::time::Duration::from_secs(10)).unwrap()
    }

    /// Answer the conversation arriving on `theirs` (the prompter's end).
    pub fn respond(&self, theirs: std::os::unix::net::UnixStream) {
        use std::io::{BufRead, BufReader, Write};
        let replies: Vec<FromPrompter> = std::mem::take(&mut *self.replies.lock().unwrap());
        let sent = self.sent.clone();
        std::thread::spawn(move || {
            let mut replies = replies.into_iter().peekable();
            let mut reader = BufReader::new(theirs.try_clone().unwrap());
            let mut writer = theirs;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let msg: ToPrompter = serde_json::from_str(&line).unwrap();
                line.clear();
                sent.lock().unwrap().push(msg.clone());
                let reply = match &msg {
                    ToPrompter::ShowRecoveryKey { .. } => {
                        recovery_answer(std::slice::from_ref(&msg))
                    }
                    // A scripted Cancel may answer "insert your key" (skip).
                    ToPrompter::InsertKey { .. }
                        if replies.peek() == Some(&FromPrompter::Cancel {}) =>
                    {
                        replies.next()
                    }
                    m if m.needs_reply() => Some(replies.next().unwrap_or(FromPrompter::Cancel {})),
                    ToPrompter::Done { .. } => break,
                    _ => None,
                };
                if let Some(r) = reply {
                    let mut out = serde_json::to_vec(&r).unwrap();
                    out.push(b'\n');
                    if writer.write_all(&out).is_err() {
                        break;
                    }
                }
            }
        });
    }
}

pub fn create_with_password(k: &Keyring) {
    let p = Interactive::new(vec![password(PW)]);
    k.create(&mut p.channel(), Method::Password).unwrap();
}

/// A launcher handing out `Interactive` channels, each answering from its
/// own reply list (tests push one list per expected prompt).
pub struct InteractiveLauncher {
    pub scripts: std::sync::Mutex<Vec<Vec<FromPrompter>>>,
    pub launched: std::sync::atomic::AtomicUsize,
}

impl InteractiveLauncher {
    pub fn new(scripts: Vec<Vec<FromPrompter>>) -> Self {
        Self {
            scripts: std::sync::Mutex::new(scripts),
            launched: Default::default(),
        }
    }
}

impl Launcher for InteractiveLauncher {
    fn launch(&self) -> crate::Result<crate::prompt::Channel> {
        self.launched
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut scripts = self.scripts.lock().unwrap();
        if scripts.is_empty() {
            return Err(crate::Error::NoPrompter);
        }
        Ok(Interactive::new(scripts.remove(0)).channel())
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 18 passed | ok. 24 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **PAM check before the TPM** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring typos_never_reach_the_tpm`:

  replace

  ```rust
  Ok(false) => {
      lock(&self.inner).typed.record_failure(now);
      return Err(Error::WrongPassword);
  }
  ```

  with

  ```rust
  Ok(false) => {}
  ```

- **typed attempts limited** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring too_many_typos`: replace `if typed && let Some(wait) = inner.typed.blocked(now) {` with `if false && typed && let Some(wait) = inner.typed.blocked(now) {`.
- **only AuthFailed/WrongUser mark stale** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring an_exhausted_tpm_does_not_make_the_slot_stale`:

  replace

  ```rust
  // password it was sealed with is not this one.
  Err(aleph_unlock::Error::TpmAuthFailed | aleph_unlock::Error::TpmWrongUser) => {
  ```

  with

  ```rust
  // password it was sealed with is not this one.
  Err(_) => {
  ```

- **a rejecting slot is marked stale** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_slot_that_rejects_the_current_password`: replace `inner.state.mark_stale(older.id)?;` with `let _ = older;`.
- **stale slots are not offered** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_slot_that_rejects_the_current_password`: replace `SlotKind::Tpm(_) if !inner.state.is_stale(k.id) => password = true,` with `SlotKind::Tpm(_) => password = true,`.
- **absent slots dropped only on confirmation** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring removing_a_slot_rotates`: replace `if reply != (FromPrompter::Confirm { yes: true }) {` with `if false {`.
- **the last unlock method stays** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring the_last_unlock_method`: replace `self.keeps_a_method(drop)?;` with `(nothing)`.

  replace

  ```rust
  let (keks, drops) = self.rotation_keks(chan, proof, drop)?;
  self.keeps_a_method(&drops)?;
  ```

  with

  ```rust
  let (keks, drops) = self.rotation_keks(chan, proof, drop)?;
  ```

- **a failed write restores the body** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_failed_write_restores_the_body`: replace `*vault.body_mut() = snapshot;` with `let _ = snapshot;`.
- **an untrusted file refuses writes** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_rolled_back_file_is_read_only`: replace `if let Some(reason) = untrusted {` with `if let Some(reason) = untrusted.filter(|_| false) {`.
- **status never waits for the hardware** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring status_does_not_wait`: replace `let tpm = self.hw.try_lock().ok().map(|hw| hw.tpm.usable());` with `let tpm = Some(lock(&self.hw).tpm.usable());`.
- **recovery confirmation checked** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --lib a_wrong_recovery_confirmation`: replace `if normalize(typed[0].expose()) == groups[check[0] - 1]` with `if true || normalize(typed[0].expose()) == groups[check[0] - 1]`.
- **the new recovery key is shown last** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_busy_tpm_stops_a_rotation`: replace `let (keks, drops) = self.rotation_keks(chan, &mut proof, &old)?;` with `show_recovery_key(chan, &RecoveryKey::generate()?)?;
            let (keks, drops) = self.rotation_keks(chan, &mut proof, &old)?;`.
- **newest TPM slot first, ties to the later-added** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring the_newest_tpm_slot_is_tried_first`: replace `tpm_slots.sort_by_key(|(i, k)| std::cmp::Reverse((k.created, *i)));` with `tpm_slots.sort_by_key(|(_, k)| std::cmp::Reverse(k.created));`.
- **TPM offered only a PAM-accepted password** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_rotation_offers_the_tpm_only`: replace `Some(pw) => lock(&self.hw).password.check(pw)?,` with `Some(_) => true,`.
- **wrong PINs capped per conversation** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring wrong_pins_end_the_conversation`:

  replace

  ```rust
  Err(aleph_unlock::Error::Fido2PinInvalid) if slot.pin_required => {
  wrong_pins += 1;
  if wrong_pins >= PIN_ATTEMPTS {
  ```

  with

  ```rust
  Err(aleph_unlock::Error::Fido2PinInvalid) if slot.pin_required => {
  wrong_pins += 1;
  if false {
  ```

- **reissue keeps an unlock method** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring reissue_never_leaves_only_the_recovery_key`:

  replace

  ```rust
  let (keks, drops) = self.rotation_keks(chan, &mut proof, &old)?;
  self.keeps_a_method(&drops)?;
  ```

  with

  ```rust
  let (keks, drops) = self.rotation_keks(chan, &mut proof, &old)?;
  ```

- **a busy TPM stops a rotation** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_busy_tpm_stops_a_rotation`:

  replace

  ```rust
  // drop a slot that works.
  Err(e) => return Err(e.into())
  ```

  with

  ```rust
  // drop a slot that works.
  Err(_) => missing.push((k.id, k.label.clone(), "unavailable"))
  ```

- **TooManyAttempts ends the conversation** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring too_many_typos`:

  replace

  ```rust
  // Waiting is not something to retry at once.
  Err(e @ (Error::Cancelled | Error::Prompt(_) | Error::TooManyAttempts { .. })) => {
  ```

  with

  ```rust
  Err(e @ (Error::Cancelled | Error::Prompt(_))) => {
  ```

- **one failed attempt for stale TPM slots** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring stale_tpm_slots_cost_one_failure`:

  replace

  ```rust
  last = Some(Error::Stale(k.label.clone()));
  break;
  ```

  with

  ```rust
  last = Some(Error::Stale(k.label.clone()));
  ```

- **rotation skips stale TPM slots** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring stale_tpm_slots_cost_one_failure`: replace `SlotKind::Tpm(_) if tpm_rejected || lock(&self.inner).state.is_stale(k.id) =>` with `SlotKind::Tpm(_) if tpm_rejected =>`.
- **without PAM, login-password slots still work** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring without_pam_a_login_password_slot`:

  replace

  ```rust
  use_tpm = false;
  last = Some(e);
  ```

  with

  ```rust
  return Err(e);
  ```

- **TPM sealed only with the current login password** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_tpm_slot_is_sealed_only_with_the_current`: replace `if !hw.password.check(&password)? {` with `if false {`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-daemon
git commit -m "feat(daemon): prompter channel and keyring engine" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 5: Secret Service

**Interfaces:**
- Consumes: Task 4.
- Produces: `secret::session::{{Session, SessionError, PLAIN, DH}}`; `secret::service::{{SecretService {{ new, serve, sync, lock (keeps sessions), unlocked, modify, forget_client, session_count, waiting_count }}, collection_path, item_path, alias_path, SERVICE_PATH, SecretError}}`; `testing::{{Bus, bus()}}`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-daemon/Cargo.toml`:

```toml
[package]
name = "aleph-daemon"
description = "alephd: the aleph keyring daemon (Secret Service and admin interface)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "alephd"
path = "src/main.rs"

[features]
testing = ["dep:aleph-tpmd", "dep:tempfile", "aleph-core/insecure-test-params"]

[dependencies]
aes = "0.9"
cbc = { version = "0.2", features = ["alloc"] }
futures-util = { version = "0.3", default-features = false }
hkdf.workspace = true
num-bigint = "0.4"
sha2.workspace = true
aleph-core = { path = "../aleph-core" }
aleph-prompt-proto = { path = "../aleph-prompt-proto" }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
aleph-unlock = { path = "../aleph-unlock" }
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time"] }
toml = "1"
tracing = "0.1"
uuid.workspace = true
zbus = { version = "5", default-features = false, features = ["tokio"] }
zeroize.workspace = true
aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"], optional = true }
tempfile = { workspace = true, optional = true }

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-daemon = { path = ".", features = ["testing"] }
tempfile.workspace = true
serde.workspace = true
```

Write `crates/aleph-daemon/src/lib.rs`:

```rust
//! `alephd`, the aleph keyring daemon (spec §6).

pub mod config;
pub mod error;
pub mod keyring;
pub mod password;
pub mod paths;
pub mod prompt;
pub mod secret;
pub mod state;
pub mod store;

#[cfg(feature = "testing")]
pub mod testing;

pub use error::{Error, Result};
```

Write `crates/aleph-daemon/src/secret/mod.rs`:

```rust
pub mod service;
pub mod session;
```

Write `crates/aleph-daemon/src/secret/session.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// A client doing its half of the exchange, as libsecret does.
    fn client_key(server_public: &[u8], x: &BigUint) -> [u8; 16] {
        let shared = BigUint::from_bytes_be(server_public)
            .modpow(x, &prime())
            .to_bytes_be();
        let mut ikm = [0u8; PRIME_LEN];
        ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
        let mut key = [0u8; 16];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut key)
            .unwrap();
        key
    }

    #[test]
    fn both_sides_derive_the_same_key_and_secrets_round_trip() {
        let x = BigUint::from_bytes_be(&[0x5a; 64]);
        let client_public = BigUint::from(2u8).modpow(&x, &prime()).to_bytes_be();
        let (session, server_public) = Session::open(DH, &client_public).unwrap();
        let key = client_key(&server_public, &x);
        let Session::Dh { key: server_key } = &session else {
            panic!()
        };
        assert_eq!(**server_key, key);
        let (iv, ct) = session.encrypt(b"s3cret").unwrap();
        assert_eq!(iv.len(), 16);
        assert_ne!(&ct[..], b"s3cret");
        assert_eq!(&**session.decrypt(&iv, &ct).unwrap(), b"s3cret");
        assert_eq!(session.decrypt(&iv[..8], &ct), Err(SessionError::Decrypt));
    }

    #[test]
    fn plain_passes_through_and_bad_inputs_are_refused() {
        let (plain, out) = Session::open(PLAIN, &[]).unwrap();
        assert!(out.is_empty());
        assert_eq!(plain.encrypt(b"x").unwrap(), (vec![], b"x".to_vec()));
        assert!(Session::open(PLAIN, b"junk").is_err());
        assert_eq!(Session::open(DH, &[1]).unwrap_err(), SessionError::BadInput);
        assert_eq!(
            Session::open(DH, &[0xff; 129]).unwrap_err(),
            SessionError::BadInput
        );
        let p_minus_1 = (prime() - BigUint::from(1u8)).to_bytes_be();
        assert_eq!(
            Session::open(DH, &p_minus_1).unwrap_err(),
            SessionError::BadInput
        );
        assert!(matches!(
            Session::open("rot13", &[]),
            Err(SessionError::Unsupported(_))
        ));
    }
}
```

Create `crates/aleph-daemon/src/secret/service.rs` containing only `// implemented in step 3`.

Write `crates/aleph-daemon/tests/secret_service.rs`:

```rust
//! The Secret Service against real clients: a private `dbus-daemon`, the
//! daemon served in-process, and libsecret's `secret-tool`.

use std::io::Write;
use std::process::{Command, Stdio};

use aleph_daemon::secret::service::SecretService;
use aleph_daemon::testing::*;

struct Served {
    _bus: Bus,
    address: String,
    svc: Arc<SecretService>,
    launcher: Arc<InteractiveLauncher>,
    _conn: zbus::Connection,
    _env: Env,
}

/// A daemon with a fresh, unlocked vault, serving on a private bus.
async fn served(prompts: Vec<Vec<FromPrompter>>) -> Served {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let bus = bus();
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .build()
        .await
        .unwrap();
    let launcher = Arc::new(InteractiveLauncher::new(prompts));
    let svc = SecretService::new(Arc::new(k), launcher.clone());
    svc.serve(&conn).await.unwrap();
    Served {
        address: bus.address.clone(),
        _bus: bus,
        svc,
        launcher,
        _conn: conn,
        _env: env,
    }
}

/// Run secret-tool on the private bus: `(exit ok, stdout, stderr)`.
async fn secret_tool(s: &Served, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let (address, args, stdin) = (
        s.address.clone(),
        args.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        stdin.map(str::to_string),
    );
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new("secret-tool")
            .args(&args)
            .env("DBUS_SESSION_BUS_ADDRESS", address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("secret-tool (Arch: pacman -S libsecret)");
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        drop(child.stdin.take());
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

#[tokio::test(flavor = "multi_thread")]
async fn secret_tool_stores_looks_up_searches_and_clears() {
    let s = served(vec![]).await;
    let (ok, _, err) = secret_tool(
        &s,
        &[
            "store",
            "--label=Test entry",
            "service",
            "aleph-test",
            "user",
            "alice",
        ],
        Some("hunter2"),
    )
    .await;
    assert!(ok, "store: {err}");
    let (ok, out, err) = secret_tool(
        &s,
        &["lookup", "service", "aleph-test", "user", "alice"],
        None,
    )
    .await;
    assert!(ok, "lookup: {err}");
    assert_eq!(out, "hunter2");
    // (secret-tool prints attributes, and any error, on stderr.)
    let (ok, out, err) = secret_tool(&s, &["search", "--all", "service", "aleph-test"], None).await;
    assert!(ok);
    assert!(out.contains("label = Test entry"), "{out}");
    assert!(out.contains("secret = hunter2"), "{out}{err}");
    assert!(err.contains("attribute.user = alice"), "{err}");
    let (ok, _, err) = secret_tool(
        &s,
        &["clear", "service", "aleph-test", "user", "alice"],
        None,
    )
    .await;
    assert!(ok, "clear: {err}");
    let (ok, out, _) = secret_tool(
        &s,
        &["lookup", "service", "aleph-test", "user", "alice"],
        None,
    )
    .await;
    assert!(!ok && out.is_empty());
}

fn launched(s: &Served) -> usize {
    s.launcher
        .launched
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// §4 "Locked search": a lookup while locked is not a false "not found".
/// libsecret unlocks the placeholder the search returns, the prompter runs
/// once, and the lookup gets the secret.
#[tokio::test(flavor = "multi_thread")]
async fn a_locked_lookup_prompts_once_and_finds_the_secret() {
    let s = served(vec![vec![password(PW)]]).await;
    let stored = secret_tool(
        &s,
        &["store", "--label=T", "service", "x", "user", "a"],
        Some("pw"),
    )
    .await;
    assert!(stored.0, "{stored:?}");
    s.svc.lock().await.unwrap();
    let (ok, out, err) = secret_tool(&s, &["lookup", "service", "x", "user", "a"], None).await;
    assert!(ok, "{err}");
    assert_eq!(out, "pw");
    assert_eq!(launched(&s), 1);
}

/// With no prompter (no graphical session), the lookup waits rather than
/// failing, and completes when the vault is unlocked some other way.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_prompter_a_locked_lookup_waits_for_an_unlock_elsewhere() {
    let s = served(vec![]).await;
    secret_tool(
        &s,
        &["store", "--label=T", "service", "x", "user", "a"],
        Some("pw"),
    )
    .await;
    s.svc.lock().await.unwrap();
    let lookup = {
        let (address, svc) = (s.address.clone(), s.svc.clone());
        let _ = svc;
        tokio::task::spawn_blocking(move || {
            Command::new("secret-tool")
                .args(["lookup", "service", "x", "user", "a"])
                .env("DBUS_SESSION_BUS_ADDRESS", address)
                .stdin(Stdio::null())
                .output()
                .unwrap()
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(!lookup.is_finished(), "the lookup should be waiting");
    // "aleph unlock" in a terminal: unlock through another channel.
    let keyring = s.svc.keyring.clone();
    tokio::task::spawn_blocking(move || {
        keyring.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
    })
    .await
    .unwrap()
    .unwrap();
    s.svc.unlocked().await.unwrap();
    let out = tokio::time::timeout(std::time::Duration::from_secs(10), lookup)
        .await
        .expect("the lookup completes after the unlock")
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "pw");
}

/// Cancelling the prompter dismisses the prompt: the lookup ends without a
/// secret (as with gnome-keyring when the user cancels).
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_the_prompt_ends_the_lookup_empty_handed() {
    let s = served(vec![vec![FromPrompter::Cancel {}]]).await;
    secret_tool(
        &s,
        &["store", "--label=T", "service", "x", "user", "a"],
        Some("pw"),
    )
    .await;
    s.svc.lock().await.unwrap();
    let (ok, out, _) = secret_tool(&s, &["lookup", "service", "x", "user", "a"], None).await;
    assert!(!ok && out.is_empty());
    assert!(s.svc.keyring.is_locked());
}

/// Storing while locked unlocks first (libsecret unlocks the default
/// collection), then stores.
#[tokio::test(flavor = "multi_thread")]
async fn storing_while_locked_unlocks_first() {
    let s = served(vec![vec![password(PW)]]).await;
    s.svc.lock().await.unwrap();
    let (ok, _, err) = secret_tool(&s, &["store", "--label=T", "service", "y"], Some("pw2")).await;
    assert!(ok, "{err}");
    assert!(!s.svc.keyring.is_locked());
    let (_, out, _) = secret_tool(&s, &["lookup", "service", "y"], None).await;
    assert_eq!(out, "pw2");
}

/// Review I1: a second `Lock` while a lookup waits must not strand it: the
/// lookup still gets the secret once the vault is unlocked.
#[tokio::test(flavor = "multi_thread")]
async fn a_redundant_lock_does_not_strand_a_waiting_lookup() {
    let s = served(vec![]).await;
    secret_tool(
        &s,
        &["store", "--label=T", "service", "x", "user", "a"],
        Some("pw"),
    )
    .await;
    s.svc.lock().await.unwrap();
    let address = s.address.clone();
    let lookup = tokio::task::spawn_blocking(move || {
        Command::new("secret-tool")
            .args(["lookup", "service", "x", "user", "a"])
            .env("DBUS_SESSION_BUS_ADDRESS", address)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    s.svc.lock().await.unwrap();
    let keyring = s.svc.keyring.clone();
    tokio::task::spawn_blocking(move || {
        keyring.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
    })
    .await
    .unwrap()
    .unwrap();
    s.svc.unlocked().await.unwrap();
    let out = tokio::time::timeout(std::time::Duration::from_secs(10), lookup)
        .await
        .expect("the lookup completes")
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "pw");
}

async fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if done() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    done()
}

/// Review I3: a client's sessions are freed when it disconnects (libsecret
/// never closes its own).
#[tokio::test(flavor = "multi_thread")]
async fn sessions_are_freed_when_their_client_leaves() {
    let s = served(vec![]).await;
    secret_tool(&s, &["store", "--label=T", "service", "x"], Some("pw")).await;
    secret_tool(&s, &["lookup", "service", "x"], None).await;
    assert!(
        wait_until(|| s.svc.session_count() == 0).await,
        "{}",
        s.svc.session_count()
    );
}

/// Review I4: with no prompter, one client's waiting unlock prompts are
/// capped, and they go when the client leaves.
#[tokio::test(flavor = "multi_thread")]
async fn waiting_prompts_are_capped_and_dropped_with_their_client() {
    let s = served(vec![]).await;
    s.svc.lock().await.unwrap();
    let client = zbus::connection::Builder::address(s.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let service = zbus::Proxy::new(
        &client,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    for _ in 0..12 {
        let (_, prompt): (
            Vec<zbus::zvariant::OwnedObjectPath>,
            zbus::zvariant::OwnedObjectPath,
        ) = service
            .call(
                "Unlock",
                &(vec![
                    zbus::zvariant::ObjectPath::try_from(
                        "/org/freedesktop/secrets/aliases/default",
                    )
                    .unwrap(),
                ],),
            )
            .await
            .unwrap();
        let p = zbus::Proxy::new(
            &client,
            "org.freedesktop.secrets",
            prompt,
            "org.freedesktop.Secret.Prompt",
        )
        .await
        .unwrap();
        // A second Prompt() on the same object is ignored.
        p.call_method("Prompt", &("",)).await.unwrap();
        // (Past the cap the prompt is dismissed and gone at once.)
        let _ = p.call_method("Prompt", &("",)).await;
    }
    assert!(
        wait_until(|| s.svc.waiting_count() == 8).await,
        "{}",
        s.svc.waiting_count()
    );
    drop(service);
    drop(client);
    assert!(
        wait_until(|| s.svc.waiting_count() == 0).await,
        "{}",
        s.svc.waiting_count()
    );
}

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};

async fn client(s: &Served) -> zbus::Connection {
    zbus::connection::Builder::address(s.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap()
}

async fn service(c: &zbus::Connection) -> zbus::Proxy<'static> {
    zbus::Proxy::new(
        c,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap()
}

async fn unlock_elsewhere(s: &Served) {
    let keyring = s.svc.keyring.clone();
    tokio::task::spawn_blocking(move || {
        keyring.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
    })
    .await
    .unwrap()
    .unwrap();
    s.svc.unlocked().await.unwrap();
}

/// Review I-A: a lock keeps sessions, so a long-lived client (libsecret
/// keeps one session per process) still reads secrets after lock and
/// unlock.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_survives_lock_and_unlock() {
    let s = served(vec![]).await;
    secret_tool(&s, &["store", "--label=T", "service", "x"], Some("pw")).await;
    let c = client(&s).await;
    let svc = service(&c).await;
    let (_, session): (OwnedValue, OwnedObjectPath) = svc
        .call("OpenSession", &("plain", zbus::zvariant::Value::from("")))
        .await
        .unwrap();
    s.svc.lock().await.unwrap();
    unlock_elsewhere(&s).await;
    let attrs: std::collections::HashMap<&str, &str> = [("service", "x")].into();
    let (found, _): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        svc.call("SearchItems", &(attrs,)).await.unwrap();
    let item = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        found[0].clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let (secret,): ((OwnedObjectPath, Vec<u8>, Vec<u8>, String),) =
        item.call("GetSecret", &(session,)).await.unwrap();
    assert_eq!(secret.2, b"pw");
}

/// Review minor 1: `unlocked()` while (again) locked answers nobody with
/// an empty result: waiting prompts keep waiting.
#[tokio::test(flavor = "multi_thread")]
async fn waiting_prompts_are_not_answered_while_locked() {
    let s = served(vec![]).await;
    s.svc.lock().await.unwrap();
    let c = client(&s).await;
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service(&c)
        .await
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
            ],),
        )
        .await
        .unwrap();
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    assert!(wait_until(|| s.svc.waiting_count() == 1).await);
    s.svc.unlocked().await.unwrap();
    assert_eq!(s.svc.waiting_count(), 1);
}

/// Review I1 (captured query): the answer to a locked search survives its
/// placeholder being evicted between `Unlock` and the prompt; an unknown
/// search path is never echoed back.
#[tokio::test(flavor = "multi_thread")]
async fn a_placeholder_query_is_captured_when_unlock_is_called() {
    use futures_util::StreamExt;
    let s = served(vec![vec![password(PW)]]).await;
    secret_tool(&s, &["store", "--label=T", "service", "x"], Some("pw")).await;
    s.svc.lock().await.unwrap();
    let c = client(&s).await;
    let svc = service(&c).await;
    let attrs: std::collections::HashMap<&str, &str> = [("service", "x")].into();
    let (_, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        svc.call("SearchItems", &(attrs.clone(),)).await.unwrap();
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) =
        svc.call("Unlock", &(locked,)).await.unwrap();
    // Evict the placeholder (more than 256 newer searches).
    let other: std::collections::HashMap<&str, &str> = [("service", "y")].into();
    for _ in 0..260 {
        let _: (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
            svc.call("SearchItems", &(other.clone(),)).await.unwrap();
    }
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let mut completed = p.receive_signal("Completed").await.unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    let msg = tokio::time::timeout(std::time::Duration::from_secs(10), completed.next())
        .await
        .unwrap()
        .unwrap();
    let (dismissed, result): (bool, OwnedValue) = msg.body().deserialize().unwrap();
    assert!(!dismissed);
    let items: Vec<OwnedObjectPath> = result.try_into().unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(items[0].as_str().contains("/collection/"));
    // Unlocked now: an unknown search path yields nothing, not itself.
    let (unlocked, _): (Vec<OwnedObjectPath>, OwnedObjectPath) = svc
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/search/q999999").unwrap(),
            ],),
        )
        .await
        .unwrap();
    assert!(unlocked.is_empty());
}

/// Review I4: `Prompt()` runs once; a repeated call does not start a
/// second prompter.
#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_runs_once() {
    let s = served(vec![
        vec![FromPrompter::Cancel {}],
        vec![FromPrompter::Cancel {}],
    ])
    .await;
    s.svc.lock().await.unwrap();
    let c = client(&s).await;
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service(&c)
        .await
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
            ],),
        )
        .await
        .unwrap();
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    let _ = p.call_method("Prompt", &("",)).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(launched(&s), 1);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-daemon/src/secret/session.rs`:

```rust
//! Secret Service transfer sessions (spec §6 "Secret Service").
//!
//! - `plain`: secrets travel as-is on the (per-user) session bus.
//! - `dh-ietf1024-sha256-aes128-cbc-pkcs7`, which libsecret requires:
//!   Diffie-Hellman in the 1024-bit MODP group of RFC 2409 §6.2, the
//!   shared secret (big-endian, zero-padded to 128 bytes) through
//!   HKDF-SHA-256 with no salt and no info to a 16-byte key, then
//!   AES-128-CBC with PKCS#7 padding and a random IV as the parameters.
//!   Weak by modern standards, acceptable on a per-user local bus, and
//!   documented as such. The modular exponentiation is not constant-time;
//!   each session's key is ephemeral.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const PLAIN: &str = "plain";
pub const DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// RFC 2409 §6.2, "Second Oakley Group".
const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);
const PRIME_LEN: usize = 128;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("unsupported session algorithm {0:?}")]
    Unsupported(String),
    #[error("invalid session input")]
    BadInput,
    #[error("cannot decrypt the secret (wrong session or corrupt data)")]
    Decrypt,
    #[error("system randomness unavailable")]
    Random,
}

pub enum Session {
    Plain,
    Dh { key: Zeroizing<[u8; 16]> },
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Plain => "Session::Plain",
            Self::Dh { .. } => "Session::Dh(<key>)",
        })
    }
}

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid prime")
}

fn random<const N: usize>() -> Result<[u8; N], SessionError> {
    aleph_core::crypto::random_array::<N>().map_err(|_| SessionError::Random)
}

impl Session {
    /// Negotiate a session: returns it and the output for the client (our
    /// DH public value, or nothing for `plain`).
    pub fn open(algorithm: &str, input: &[u8]) -> Result<(Self, Vec<u8>), SessionError> {
        match algorithm {
            PLAIN if input.is_empty() => Ok((Self::Plain, Vec::new())),
            PLAIN => Err(SessionError::BadInput),
            DH => {
                let p = prime();
                let peer = BigUint::from_bytes_be(input);
                let one = BigUint::from(1u8);
                if input.len() > PRIME_LEN || peer <= one || peer >= &p - &one {
                    return Err(SessionError::BadInput);
                }
                let x = BigUint::from_bytes_be(&*Zeroizing::new(random::<PRIME_LEN>()?))
                    % (&p - BigUint::from(3u8))
                    + BigUint::from(2u8);
                let public = BigUint::from(2u8).modpow(&x, &p);
                // The byte forms are zeroized; num-bigint cannot zeroize
                // its own limbs (the exponent and shared value), which is
                // accepted for an ephemeral per-session key.
                let shared = Zeroizing::new(peer.modpow(&x, &p).to_bytes_be());
                let mut ikm = Zeroizing::new([0u8; PRIME_LEN]);
                ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
                let mut key = Zeroizing::new([0u8; 16]);
                Hkdf::<Sha256>::new(None, &*ikm)
                    .expand(&[], &mut *key)
                    .expect("16 bytes is a valid HKDF length");
                Ok((Self::Dh { key }, public.to_bytes_be()))
            }
            other => Err(SessionError::Unsupported(other.into())),
        }
    }

    /// Encrypt a secret for the client: `(parameters, value)`.
    pub fn encrypt(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SessionError> {
        match self {
            Self::Plain => Ok((Vec::new(), secret.to_vec())),
            Self::Dh { key } => {
                let iv = random::<16>()?;
                let ct = cbc::Encryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .encrypt_padded_vec::<Pkcs7>(secret);
                Ok((iv.to_vec(), ct))
            }
        }
    }

    /// Decrypt a secret from the client.
    pub fn decrypt(
        &self,
        parameters: &[u8],
        value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        match self {
            Self::Plain => Ok(Zeroizing::new(value.to_vec())),
            Self::Dh { key } => {
                let iv: [u8; 16] = parameters.try_into().map_err(|_| SessionError::Decrypt)?;
                cbc::Decryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .decrypt_padded_vec::<Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| SessionError::Decrypt)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client doing its half of the exchange, as libsecret does.
    fn client_key(server_public: &[u8], x: &BigUint) -> [u8; 16] {
        let shared = BigUint::from_bytes_be(server_public)
            .modpow(x, &prime())
            .to_bytes_be();
        let mut ikm = [0u8; PRIME_LEN];
        ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
        let mut key = [0u8; 16];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut key)
            .unwrap();
        key
    }

    #[test]
    fn both_sides_derive_the_same_key_and_secrets_round_trip() {
        let x = BigUint::from_bytes_be(&[0x5a; 64]);
        let client_public = BigUint::from(2u8).modpow(&x, &prime()).to_bytes_be();
        let (session, server_public) = Session::open(DH, &client_public).unwrap();
        let key = client_key(&server_public, &x);
        let Session::Dh { key: server_key } = &session else {
            panic!()
        };
        assert_eq!(**server_key, key);
        let (iv, ct) = session.encrypt(b"s3cret").unwrap();
        assert_eq!(iv.len(), 16);
        assert_ne!(&ct[..], b"s3cret");
        assert_eq!(&**session.decrypt(&iv, &ct).unwrap(), b"s3cret");
        assert_eq!(session.decrypt(&iv[..8], &ct), Err(SessionError::Decrypt));
    }

    #[test]
    fn plain_passes_through_and_bad_inputs_are_refused() {
        let (plain, out) = Session::open(PLAIN, &[]).unwrap();
        assert!(out.is_empty());
        assert_eq!(plain.encrypt(b"x").unwrap(), (vec![], b"x".to_vec()));
        assert!(Session::open(PLAIN, b"junk").is_err());
        assert_eq!(Session::open(DH, &[1]).unwrap_err(), SessionError::BadInput);
        assert_eq!(
            Session::open(DH, &[0xff; 129]).unwrap_err(),
            SessionError::BadInput
        );
        let p_minus_1 = (prime() - BigUint::from(1u8)).to_bytes_be();
        assert_eq!(
            Session::open(DH, &p_minus_1).unwrap_err(),
            SessionError::BadInput
        );
        assert!(matches!(
            Session::open("rot13", &[]),
            Err(SessionError::Unsupported(_))
        ));
    }
}
```

Write `crates/aleph-daemon/src/secret/service.rs`:

```rust
//! The freedesktop Secret Service on D-Bus (spec §6 "Secret Service", §4
//! "Locked search").
//!
//! Object layout:
//!
//! | Path | Interface |
//! |---|---|
//! | `/org/freedesktop/secrets` | `Service` |
//! | `…/collection/<id>` and `…/aliases/<name>` | `Collection` |
//! | `…/collection/<id>/<item>` | `Item` |
//! | `…/session/<n>` | `Session` |
//! | `…/prompt/<n>` | `Prompt` |
//!
//! The vault encrypts collection names and item attributes, so while it is
//! locked only the `default` alias exists, as a locked collection, and a
//! search cannot be answered. Instead of a false "not found" (§4 "Locked
//! search"), a locked `SearchItems` returns a placeholder item
//! (`…/search/<n>`) in its `locked` list. libsecret then calls `Unlock` on
//! it, and the prompt's result lists the real matching items. Reads of the
//! body (`GetSecrets`, `GetSecret`, …) answer `IsLocked`.
//!
//! No method waits for the user. An unlock prompt with no prompter to run
//! (no graphical session) is not dismissed: it waits until the vault is
//! unlocked some other way (`aleph unlock`, PAM), then completes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aleph_core::{Body, Collection, Item, SecretBytes};
use uuid::Uuid;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, interface};

use crate::error::Error;
use crate::keyring::Keyring;
use crate::prompt::{Caller, Launcher};
use crate::secret::session::Session;

pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLLECTION_PREFIX: &str = "/org/freedesktop/secrets/collection/";
const ALIAS_PREFIX: &str = "/org/freedesktop/secrets/aliases/";
const SEARCH_PREFIX: &str = "/org/freedesktop/secrets/search/";
/// Placeholder searches kept at once; the oldest go first.
const MAX_SEARCHES: usize = 256;
const LABEL: &str = "org.freedesktop.Secret.Collection.Label";
const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

/// `(session, parameters, value, content_type)`.
pub type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretError {
    #[zbus(error)]
    ZBus(zbus::Error),
    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
}

type Result<T> = std::result::Result<T, SecretError>;

impl From<Error> for SecretError {
    fn from(e: Error) -> Self {
        match e {
            Error::Locked => Self::IsLocked("the keyring is locked".into()),
            Error::NotFound => Self::NoSuchObject("no such object".into()),
            other => Self::ZBus(zbus::Error::Failure(other.to_string())),
        }
    }
}

fn path(s: String) -> OwnedObjectPath {
    OwnedObjectPath::try_from(s).expect("valid object path")
}

pub fn collection_path(id: Uuid) -> OwnedObjectPath {
    path(format!("{COLLECTION_PREFIX}{}", id.simple()))
}

pub fn item_path(collection: Uuid, item: Uuid) -> OwnedObjectPath {
    path(format!(
        "{COLLECTION_PREFIX}{}/{}",
        collection.simple(),
        item.simple()
    ))
}

pub fn alias_path(name: &str) -> OwnedObjectPath {
    path(format!("{ALIAS_PREFIX}{name}"))
}

fn root() -> OwnedObjectPath {
    path("/".into())
}

/// Aliases name a collection; only letters, digits, and `_` fit in a path.
fn valid_alias(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// What a prompt does when the user answers it.
#[derive(Clone, Debug)]
enum Action {
    Unlock(Vec<Target>),
    CreateCollection { label: String, alias: String },
    DeleteCollection(Uuid),
}

struct Waiting {
    prompt: OwnedObjectPath,
    client: Option<String>,
    targets: Vec<Target>,
}

/// Sessions one client may hold open at once.
const MAX_SESSIONS_PER_CLIENT: usize = 32;

/// Waiting unlock prompts allowed per client, and in all.
const MAX_WAITING_PER_CLIENT: usize = 8;
const MAX_WAITING: usize = 128;

/// The daemon state the D-Bus objects share.
pub struct SecretService {
    pub keyring: Arc<Keyring>,
    pub launcher: Arc<dyn Launcher>,
    /// Open sessions and the client (unique bus name) that opened each.
    sessions: Mutex<HashMap<OwnedObjectPath, (Session, Option<String>)>>,
    next: AtomicU64,
    /// Collection, alias, and item paths currently served.
    served: tokio::sync::Mutex<HashSet<OwnedObjectPath>>,
    /// Placeholder items for searches made while locked, oldest first.
    searches: Mutex<Vec<(OwnedObjectPath, HashMap<String, String>)>>,
    /// Unlock prompts waiting for an unlock from elsewhere, with the
    /// client that started each.
    waiting: Mutex<Vec<Waiting>>,
    /// Every live prompt object and the client that asked for it.
    prompts: Mutex<HashMap<OwnedObjectPath, Option<String>>>,
    /// An unlock conversation is running.
    unlock_running: std::sync::atomic::AtomicBool,
    conn: std::sync::OnceLock<Connection>,
}

impl SecretService {
    pub fn new(keyring: Arc<Keyring>, launcher: Arc<dyn Launcher>) -> Arc<Self> {
        Arc::new(Self {
            keyring,
            launcher,
            sessions: Mutex::default(),
            next: AtomicU64::new(1),
            served: tokio::sync::Mutex::default(),
            searches: Mutex::default(),
            waiting: Mutex::default(),
            prompts: Mutex::default(),
            unlock_running: Default::default(),
            conn: std::sync::OnceLock::new(),
        })
    }

    /// Serve on `conn` (which should own `org.freedesktop.secrets`).
    pub async fn serve(self: &Arc<Self>, conn: &Connection) -> zbus::Result<()> {
        let _ = self.conn.set(conn.clone());
        self.watch_clients().await?;
        conn.object_server()
            .at(SERVICE_PATH, ServiceObj { svc: self.clone() })
            .await?;
        self.sync().await
    }

    fn conn(&self) -> &Connection {
        self.conn.get().expect("serving")
    }

    fn next_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Register exactly the collection, alias, and item objects the
    /// current state has, and drop the rest.
    pub async fn sync(self: &Arc<Self>) -> zbus::Result<()> {
        let mut want: HashMap<OwnedObjectPath, Obj> = HashMap::new();
        match self.keyring.read(|b| {
            let mut out = Vec::new();
            for c in &b.collections {
                out.push((collection_path(c.id), Obj::Collection(Target::Id(c.id))));
                for i in &c.items {
                    out.push((item_path(c.id, i.id), Obj::Item(c.id, i.id)));
                }
            }
            for name in b.aliases.keys().filter(|n| valid_alias(n)) {
                out.push((
                    alias_path(name),
                    Obj::Collection(Target::Alias(name.clone())),
                ));
            }
            out
        }) {
            Ok(objs) => want.extend(objs),
            // Locked: only the default alias, as a locked collection.
            Err(_) => {
                want.insert(
                    alias_path("default"),
                    Obj::Collection(Target::Alias("default".into())),
                );
            }
        }
        let server = self.conn().object_server();
        let mut served = self.served.lock().await;
        for p in served.iter().filter(|p| !want.contains_key(*p)) {
            let _ = server.remove::<ItemObj, _>(p.as_ref()).await;
            let _ = server.remove::<CollectionObj, _>(p.as_ref()).await;
        }
        served.retain(|p| want.contains_key(p));
        for (p, obj) in want {
            if served.contains(&p) {
                continue;
            }
            match obj {
                Obj::Collection(target) => {
                    server
                        .at(
                            p.as_ref(),
                            CollectionObj {
                                svc: self.clone(),
                                target,
                            },
                        )
                        .await?;
                }
                Obj::Item(c, i) => {
                    server
                        .at(
                            p.as_ref(),
                            ItemObj {
                                svc: self.clone(),
                                collection: c,
                                item: i,
                            },
                        )
                        .await?;
                }
            }
            served.insert(p);
        }
        Ok(())
    }

    /// Free what a client leaves behind when it disconnects: its sessions
    /// (and their keys) and its waiting prompts. libsecret never closes
    /// its session, so without this they would pile up until lock.
    async fn watch_clients(self: &Arc<Self>) -> zbus::Result<()> {
        use futures_util::StreamExt;
        let dbus = zbus::fdo::DBusProxy::new(self.conn()).await?;
        let mut changes = dbus.receive_name_owner_changed().await?;
        let svc = Arc::downgrade(self);
        tokio::spawn(async move {
            while let Some(change) = changes.next().await {
                let Ok(args) = change.args() else { continue };
                let name = args.name().to_string();
                if !name.starts_with(':') || args.new_owner().is_some() {
                    continue;
                }
                let Some(svc) = svc.upgrade() else { break };
                svc.forget_client(&name).await;
            }
        });
        Ok(())
    }

    pub async fn forget_client(self: &Arc<Self>, client: &str) {
        let sessions: Vec<OwnedObjectPath> = {
            let mut map = self.sessions.lock().unwrap();
            let gone: Vec<_> = map
                .iter()
                .filter(|(_, (_, owner))| owner.as_deref() == Some(client))
                .map(|(p, _)| p.clone())
                .collect();
            for p in &gone {
                map.remove(p);
            }
            gone
        };
        for p in sessions {
            let _ = self
                .conn()
                .object_server()
                .remove::<SessionObj, _>(p.as_ref())
                .await;
        }
        self.waiting
            .lock()
            .unwrap()
            .retain(|w| w.client.as_deref() != Some(client));
        let prompts: Vec<OwnedObjectPath> = {
            let mut all = self.prompts.lock().unwrap();
            let gone: Vec<_> = all
                .iter()
                .filter(|(_, owner)| owner.as_deref() == Some(client))
                .map(|(p, _)| p.clone())
                .collect();
            for p in &gone {
                all.remove(p);
            }
            gone
        };
        for p in prompts {
            let _ = self
                .conn()
                .object_server()
                .remove::<PromptObj, _>(p.as_ref())
                .await;
        }
    }

    /// Unlock prompts waiting now (tests).
    pub fn waiting_count(&self) -> usize {
        self.waiting.lock().unwrap().len()
    }

    /// Sessions open now (tests).
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// `Keyring::modify` on a blocking thread: it encrypts, writes, and
    /// fsyncs, which must not stall the async runtime.
    pub async fn modify<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Body) -> std::result::Result<T, Error> + Send + 'static,
    ) -> std::result::Result<T, Error> {
        let keyring = self.keyring.clone();
        tokio::task::spawn_blocking(move || keyring.modify(f))
            .await
            .unwrap_or_else(|e| Err(Error::Invalid(e.to_string())))
    }

    /// Lock: drop MK and the decrypted body (§4).
    pub async fn lock(self: &Arc<Self>) -> zbus::Result<()> {
        // Already locked: nothing to do. In particular a second `Lock` must
        // not close the sessions of clients waiting for an unlock, or drop
        // the placeholders their searches returned.
        if self.keyring.is_locked() {
            return Ok(());
        }
        // Sessions stay open: they hold only transport keys, nothing is
        // readable through them while locked, and libsecret clients keep
        // theirs for the life of the process (closing them would break
        // every long-lived client at each screen lock). They are freed on
        // `Close`, when their client disconnects, and at exit.
        self.keyring.lock();
        let searches: Vec<_> = self
            .searches
            .lock()
            .unwrap()
            .drain(..)
            .map(|(p, _)| p)
            .collect();
        for p in searches {
            let _ = self
                .conn()
                .object_server()
                .remove::<PlaceholderObj, _>(p.as_ref())
                .await;
        }
        self.sync().await?;
        self.announce_all().await
    }

    /// The vault was unlocked (by a prompt, `aleph unlock`, or PAM): serve
    /// its objects and complete every waiting unlock prompt.
    pub async fn unlocked(self: &Arc<Self>) -> zbus::Result<()> {
        self.sync().await?;
        self.announce_all().await?;
        let waiting: Vec<_> = self.waiting.lock().unwrap().drain(..).collect();
        for w in waiting {
            match self.unlocked_value(&w.targets) {
                Some(value) => finish(self, &w.prompt, Some(value), empty_paths()).await,
                // Locked again meanwhile: keep waiting, never answer empty.
                None => self.waiting.lock().unwrap().push(w),
            }
        }
        Ok(())
    }

    /// A placeholder item standing for `query` while the vault is locked.
    async fn placeholder(
        self: &Arc<Self>,
        query: HashMap<String, String>,
    ) -> Result<OwnedObjectPath> {
        let p = path(format!("{SEARCH_PREFIX}q{}", self.next_id()));
        self.conn()
            .object_server()
            .at(
                p.as_ref(),
                PlaceholderObj {
                    query: query.clone(),
                },
            )
            .await?;
        let evicted = {
            let mut searches = self.searches.lock().unwrap();
            searches.push((p.clone(), query));
            if searches.len() > MAX_SEARCHES {
                Some(searches.remove(0).0)
            } else {
                None
            }
        };
        if let Some(old) = evicted {
            let _ = self
                .conn()
                .object_server()
                .remove::<PlaceholderObj, _>(old.as_ref())
                .await;
        }
        Ok(p)
    }

    /// What an unlock of `objects` yields once the vault is open: each
    /// placeholder becomes the items its search now finds.
    /// What `Unlock(objects)` is about, captured when it is called: each
    /// placeholder's query is copied now, so it survives the placeholder
    /// being evicted or cleared before the prompt completes.
    fn targets(&self, objects: Vec<OwnedObjectPath>) -> Vec<Target> {
        let searches = self.searches.lock().unwrap();
        objects
            .into_iter()
            .map(|o| match searches.iter().find(|(p, _)| *p == o) {
                Some((_, query)) => Target::Search(query.clone()),
                None => Target::Path(o),
            })
            .collect()
    }

    /// The unlocked objects `targets` stand for, once the vault is open.
    /// A search path that is no longer known is dropped, never echoed back
    /// (a client would take it for an item).
    /// `None` if the vault is locked (it cannot be answered yet).
    fn resolve_unlocked(&self, targets: &[Target]) -> Option<Vec<OwnedObjectPath>> {
        if self.keyring.is_locked() {
            return None;
        }
        let mut out: Vec<OwnedObjectPath> = Vec::new();
        for t in targets {
            match t {
                Target::Search(query) => {
                    out.extend(self.keyring.read(|b| matching(b, query)).ok()?)
                }
                Target::Path(p) if p.as_str().starts_with(SEARCH_PREFIX) => {}
                Target::Path(p) => out.push(p.clone()),
                Target::Id(_) | Target::Alias(_) => {}
            }
        }
        let mut seen = HashSet::new();
        out.retain(|p| seen.insert(p.clone()));
        Some(out)
    }

    fn unlocked_value(&self, targets: &[Target]) -> Option<OwnedValue> {
        OwnedValue::try_from(Value::from(self.resolve_unlocked(targets)?)).ok()
    }

    /// Tell clients every collection changed (after lock or unlock).
    async fn announce_all(self: &Arc<Self>) -> zbus::Result<()> {
        let paths: Vec<OwnedObjectPath> = self
            .served
            .lock()
            .await
            .iter()
            .filter(|p| !is_item(p))
            .cloned()
            .collect();
        let emitter = SignalEmitter::new(self.conn(), SERVICE_PATH)?;
        for p in paths {
            ServiceObj::collection_changed(&emitter, p.as_ref()).await?;
        }
        Ok(())
    }

    fn resolve(&self, target: &Target) -> std::result::Result<Uuid, Error> {
        self.keyring.read(|b| match target {
            Target::Id(id) => b.collection(*id).map(|c| c.id).ok_or(Error::NotFound),
            Target::Alias(name) => b.resolve_alias(name).map(|c| c.id).ok_or(Error::NotFound),
            Target::Path(_) | Target::Search(_) => Err(Error::NotFound),
        })?
    }

    fn session(&self, p: &ObjectPath<'_>) -> Result<SessionGuard<'_>> {
        let sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(&OwnedObjectPath::from(p.to_owned())) {
            return Err(SecretError::NoSession(format!("no session {p}")));
        }
        Ok(SessionGuard {
            sessions,
            path: OwnedObjectPath::from(p.to_owned()),
        })
    }

    fn secret_for(&self, session: &ObjectPath<'_>, item: &Item) -> Result<SecretStruct> {
        let guard = self.session(session)?;
        let (params, value) = guard
            .get()
            .encrypt(item.secret.expose())
            .map_err(|e| SecretError::ZBus(zbus::Error::Failure(e.to_string())))?;
        Ok((
            OwnedObjectPath::from(session.to_owned()),
            params,
            value,
            item.content_type.clone(),
        ))
    }

    fn decrypt(&self, secret: &SecretStruct) -> Result<SecretBytes> {
        let guard = self.session(&secret.0.as_ref())?;
        let plain = guard
            .get()
            .decrypt(&secret.1, &secret.2)
            .map_err(|e| SecretError::ZBus(zbus::Error::Failure(e.to_string())))?;
        Ok(SecretBytes::new(plain.to_vec()))
    }

    /// Create a prompt object for `action` and return its path.
    async fn prompt(
        self: &Arc<Self>,
        action: Action,
        owner: Option<String>,
    ) -> Result<OwnedObjectPath> {
        let p = path(format!("{SERVICE_PATH}/prompt/p{}", self.next_id()));
        self.prompts
            .lock()
            .unwrap()
            .insert(p.clone(), owner.clone());
        self.conn()
            .object_server()
            .at(
                p.as_ref(),
                PromptObj {
                    svc: self.clone(),
                    path: p.clone(),
                    action,
                    started: Default::default(),
                },
            )
            .await?;
        self.gone_already(owner.as_deref()).await;
        Ok(p)
    }

    /// If `client` disconnected while we were creating something for it
    /// (its `NameOwnerChanged` already handled), free what it left.
    async fn gone_already(self: &Arc<Self>, client: Option<&str>) {
        let Some(client) = client else { return };
        let Ok(dbus) = zbus::fdo::DBusProxy::new(self.conn()).await else {
            return;
        };
        let Ok(name) = zbus::names::BusName::try_from(client.to_string()) else {
            return;
        };
        if !dbus.name_has_owner(name).await.unwrap_or(true) {
            self.forget_client(client).await;
        }
    }

    /// Run `action` through the prompter (blocking; call from a blocking
    /// task).
    fn run(self: &Arc<Self>, action: &Action, caller: Option<Caller>) -> Outcome {
        if let Action::Unlock(targets) = action {
            // Unlocked meanwhile: answer without a prompter.
            if let Some(v) = self.unlocked_value(targets) {
                return Outcome::Done(v);
            }
            // One unlock conversation at a time: the others wait for it
            // (and complete when it unlocks), rather than each opening a
            // prompter window.
            if self.unlock_running.swap(true, Ordering::SeqCst) {
                return Outcome::Wait;
            }
            let outcome = self.run_unlock(targets, caller);
            self.unlock_running.store(false, Ordering::SeqCst);
            return outcome;
        }
        let mut chan = match self.launcher.launch() {
            Ok(chan) => chan,
            Err(e) => {
                // (Unlocks never get here: see `run_unlock`, which waits.)
                tracing::info!("no prompter: {e}");
                return Outcome::Dismissed;
            }
        };
        let value = match action {
            Action::Unlock(_) => unreachable!("handled above"),
            Action::CreateCollection { label, alias } => {
                let confirmed = confirm(
                    &mut chan,
                    &format!("Create the collection '{label}'?"),
                    caller,
                );
                if !confirmed {
                    return Outcome::Dismissed;
                }
                let (label, alias) = (label.clone(), alias.clone());
                self.keyring
                    .modify(move |b| {
                        let c = Collection::new(label);
                        let id = c.id;
                        b.collections.push(c);
                        if valid_alias(&alias) {
                            b.aliases.insert(alias, id);
                        }
                        Ok(id)
                    })
                    .ok()
                    .map(|id| path_value(collection_path(id)))
            }
            Action::DeleteCollection(id) => {
                let Some(label) = self
                    .keyring
                    .read(|b| b.collection(*id).map(|c| c.label.clone()))
                    .ok()
                    .flatten()
                else {
                    return Outcome::Dismissed;
                };
                if !confirm(
                    &mut chan,
                    &format!("Delete the collection '{label}' and all its items?"),
                    caller,
                ) {
                    return Outcome::Dismissed;
                }
                let id = *id;
                self.keyring
                    .modify(move |b| {
                        b.remove_collection(id).ok_or(Error::NotFound)?;
                        b.aliases.retain(|_, c| *c != id);
                        Ok(())
                    })
                    .ok()
                    .map(|()| path_value(root()))
            }
        };
        match value {
            Some(v) => Outcome::Done(v),
            None => Outcome::Dismissed,
        }
    }
}

impl SecretService {
    fn run_unlock(self: &Arc<Self>, targets: &[Target], caller: Option<Caller>) -> Outcome {
        let mut chan = match self.launcher.launch() {
            Ok(chan) => chan,
            Err(e) => {
                tracing::info!("no prompter: {e}");
                return Outcome::Wait;
            }
        };
        match self.keyring.unlock(&mut chan, caller) {
            Ok(()) => match self.unlocked_value(targets) {
                Some(v) => Outcome::Done(v),
                None => Outcome::Wait,
            },
            Err(_) => Outcome::Dismissed,
        }
    }
}

/// How a prompt ended.
enum Outcome {
    Done(OwnedValue),
    Dismissed,
    /// No prompter could start: wait for an unlock from elsewhere.
    Wait,
}

fn path_value(p: OwnedObjectPath) -> OwnedValue {
    OwnedValue::try_from(Value::from(p)).expect("an object path is a value")
}

fn is_item(p: &OwnedObjectPath) -> bool {
    p.as_str()
        .strip_prefix(COLLECTION_PREFIX)
        .is_some_and(|rest| rest.contains('/'))
}

/// Ask a yes/no question through the prompter and end the conversation.
fn confirm(chan: &mut crate::prompt::Channel, text: &str, caller: Option<Caller>) -> bool {
    use crate::prompt::{FromPrompter, Purpose, ToPrompter};
    let yes = chan
        .send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: text.into(),
            caller,
        })
        .and_then(|()| chan.ask(&ToPrompter::Confirm { text: text.into() }))
        .is_ok_and(|r| r == FromPrompter::Confirm { yes: true });
    chan.done(yes, None);
    yes
}

struct SessionGuard<'a> {
    sessions: std::sync::MutexGuard<'a, HashMap<OwnedObjectPath, (Session, Option<String>)>>,
    path: OwnedObjectPath,
}

impl SessionGuard<'_> {
    fn get(&self) -> &Session {
        &self.sessions[&self.path].0
    }
}

#[derive(Clone, Debug)]
enum Target {
    Id(Uuid),
    Alias(String),
    /// An object to report back as unlocked.
    Path(OwnedObjectPath),
    /// A locked search's placeholder: the items its query finds.
    Search(HashMap<String, String>),
}

enum Obj {
    Collection(Target),
    Item(Uuid, Uuid),
}

/// The caller's pid and name, for the prompt (display only).
async fn caller(conn: &Connection, hdr: &zbus::message::Header<'_>) -> Option<Caller> {
    let sender = hdr.sender()?.to_owned();
    let dbus = zbus::fdo::DBusProxy::new(conn).await.ok()?;
    let pid = dbus
        .get_connection_unix_process_id(zbus::names::BusName::Unique(sender))
        .await
        .ok()?;
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string());
    Some(Caller {
        name,
        pid: Some(pid),
    })
}

fn matching(b: &Body, attributes: &HashMap<String, String>) -> Vec<OwnedObjectPath> {
    let query: BTreeMap<String, String> = attributes.clone().into_iter().collect();
    b.collections
        .iter()
        .flat_map(|c| {
            c.items
                .iter()
                .filter(|i| i.matches(&query))
                .map(|i| item_path(c.id, i.id))
        })
        .collect()
}

/// Parse `…/collection/<c>/<i>` into ids.
fn parse_item(p: &ObjectPath<'_>) -> Option<(Uuid, Uuid)> {
    let rest = p.as_str().strip_prefix(COLLECTION_PREFIX)?;
    let (c, i) = rest.split_once('/')?;
    Some((Uuid::try_parse(c).ok()?, Uuid::try_parse(i).ok()?))
}

struct ServiceObj {
    svc: Arc<SecretService>,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl ServiceObj {
    async fn open_session(
        &self,
        algorithm: String,
        input: OwnedValue,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
        let bytes: Vec<u8> =
            Vec::<u8>::try_from(input.try_clone().map_err(zbus::Error::from)?).unwrap_or_default();
        let (session, output) = Session::open(&algorithm, &bytes).map_err(|e| {
            SecretError::ZBus(zbus::Error::FDO(Box::new(zbus::fdo::Error::NotSupported(
                e.to_string(),
            ))))
        })?;
        let p = path(format!("{SERVICE_PATH}/session/s{}", self.svc.next_id()));
        let client = hdr.sender().map(|s| s.to_string());
        {
            let mut sessions = self.svc.sessions.lock().unwrap();
            let mine = sessions
                .values()
                .filter(|(_, owner)| *owner == client)
                .count();
            if mine >= MAX_SESSIONS_PER_CLIENT {
                return Err(SecretError::ZBus(zbus::Error::Failure(
                    "too many open sessions for this client".into(),
                )));
            }
            sessions.insert(p.clone(), (session, client.clone()));
        }
        self.svc
            .conn()
            .object_server()
            .at(
                p.as_ref(),
                SessionObj {
                    svc: self.svc.clone(),
                    path: p.clone(),
                },
            )
            .await?;
        self.svc.gone_already(client.as_deref()).await;
        let output = if algorithm == crate::secret::session::PLAIN {
            OwnedValue::from(zbus::zvariant::Str::from(""))
        } else {
            OwnedValue::try_from(Value::from(output)).map_err(zbus::Error::from)?
        };
        Ok((output, p))
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let existing = self
            .svc
            .keyring
            .read(|b| b.resolve_alias(&alias).map(|c| c.id))
            .map_err(SecretError::from)?;
        if let (Some(id), false) = (existing, alias.is_empty()) {
            return Ok((collection_path(id), root()));
        }
        let label = properties
            .get(LABEL)
            .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let owner = hdr.sender().map(|s| s.to_string());
        let prompt = self
            .svc
            .prompt(Action::CreateCollection { label, alias }, owner)
            .await?;
        Ok((root(), prompt))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        match self.svc.keyring.read(|b| matching(b, &attributes)) {
            Ok(found) => Ok((found, Vec::new())),
            Err(Error::Locked) => Ok((Vec::new(), vec![self.svc.placeholder(attributes).await?])),
            Err(e) => Err(e.into()),
        }
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let targets = self.svc.targets(objects);
        if let Some(unlocked) = self.svc.resolve_unlocked(&targets) {
            return Ok((unlocked, root()));
        }
        let owner = hdr.sender().map(|s| s.to_string());
        Ok((
            Vec::new(),
            self.svc.prompt(Action::Unlock(targets), owner).await?,
        ))
    }

    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        self.svc.lock().await?;
        Ok((objects, root()))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>> {
        let found: Vec<(OwnedObjectPath, Item)> = self.svc.keyring.read(|b| {
            items
                .iter()
                .filter_map(|p| {
                    let (c, i) = parse_item(&p.as_ref())?;
                    let item = b.collection(c)?.items.iter().find(|x| x.id == i)?;
                    Some((p.clone(), item.clone()))
                })
                .collect()
        })?;
        let mut out = HashMap::new();
        for (p, item) in found {
            out.insert(p, self.svc.secret_for(&session.as_ref(), &item)?);
        }
        Ok(out)
    }

    async fn read_alias(&self, name: String) -> Result<OwnedObjectPath> {
        match self
            .svc
            .keyring
            .read(|b| b.resolve_alias(&name).map(|c| c.id))
        {
            Ok(Some(id)) => Ok(collection_path(id)),
            Ok(None) => Ok(root()),
            // Locked: the default alias stands for its collection.
            Err(_) if name == "default" => Ok(alias_path("default")),
            Err(_) => Ok(root()),
        }
    }

    async fn set_alias(&self, name: String, collection: OwnedObjectPath) -> Result<()> {
        if !valid_alias(&name) {
            return Err(SecretError::ZBus(zbus::Error::Failure(format!(
                "invalid alias {name:?}"
            ))));
        }
        let target = collection
            .as_str()
            .strip_prefix(COLLECTION_PREFIX)
            .and_then(|s| Uuid::try_parse(s).ok());
        self.svc
            .modify(move |b| {
                match target {
                    Some(id) if b.collection(id).is_some() => {
                        b.aliases.insert(name, id);
                    }
                    None if collection.as_str() == "/" => {
                        b.aliases.remove(&name);
                    }
                    _ => return Err(Error::NotFound),
                }
                Ok(())
            })
            .await?;
        self.svc.sync().await?;
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.svc
            .keyring
            .read(|b| {
                b.collections
                    .iter()
                    .map(|c| collection_path(c.id))
                    .collect()
            })
            .unwrap_or_else(|_| vec![alias_path("default")])
    }

    #[zbus(signal)]
    async fn collection_created(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

struct CollectionObj {
    svc: Arc<SecretService>,
    target: Target,
}

impl CollectionObj {
    fn id(&self) -> Result<Uuid> {
        Ok(self.svc.resolve(&self.target)?)
    }

    fn with<T>(&self, f: impl FnOnce(&Collection) -> T) -> Result<T> {
        let id = self.id()?;
        Ok(self
            .svc
            .keyring
            .read(|b| b.collection(id).map(f))?
            .ok_or(Error::NotFound)?)
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionObj {
    async fn delete(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<OwnedObjectPath> {
        let id = self.id()?;
        let owner = hdr.sender().map(|s| s.to_string());
        self.svc.prompt(Action::DeleteCollection(id), owner).await
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>> {
        if self.svc.keyring.is_locked() {
            return Ok(vec![self.svc.placeholder(attributes).await?]);
        }
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        self.with(|c| {
            c.items
                .iter()
                .filter(|i| i.matches(&query))
                .map(|i| item_path(c.id, i.id))
                .collect()
        })
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let id = self.id()?;
        let label = properties
            .get(ITEM_LABEL)
            .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let attributes: BTreeMap<String, String> = properties
            .get(ITEM_ATTRIBUTES)
            .and_then(|v| HashMap::<String, String>::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let value = self.svc.decrypt(&secret)?;
        let item = Item::new(label, attributes, value, secret.3.clone());
        let before: HashSet<Uuid> = self
            .svc
            .keyring
            .read(|b| {
                b.collection(id)
                    .map(|c| c.items.iter().map(|i| i.id).collect())
            })?
            .unwrap_or_default();
        let item_id = self
            .svc
            .modify(move |b| {
                let c = b.collection_mut(id).ok_or(Error::NotFound)?;
                Ok(c.upsert(item, replace))
            })
            .await?;
        self.svc.sync().await?;
        let p = item_path(id, item_id);
        // From the collection's own path, even if called through an alias.
        let emitter = SignalEmitter::new(self.svc.conn(), collection_path(id))?;
        if before.contains(&item_id) {
            Self::item_changed(&emitter, p.as_ref()).await?;
        } else {
            Self::item_created(&emitter, p.as_ref()).await?;
        }
        Ok((p, root()))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        self.with(|c| c.items.iter().map(|i| item_path(c.id, i.id)).collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.with(|c| c.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> zbus::fdo::Result<()> {
        let id = self
            .id()
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:?}")))?;
        self.svc
            .modify(move |b| {
                b.collection_mut(id).ok_or(Error::NotFound)?.label = label;
                Ok(())
            })
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.svc.keyring.is_locked()
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.with(|c| c.created).unwrap_or_default()
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.with(|c| c.modified).unwrap_or_default()
    }

    #[zbus(signal)]
    async fn item_created(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;
}

struct ItemObj {
    svc: Arc<SecretService>,
    collection: Uuid,
    item: Uuid,
}

impl ItemObj {
    fn with<T>(&self, f: impl FnOnce(&Item) -> T) -> Result<T> {
        let (c, i) = (self.collection, self.item);
        Ok(self
            .svc
            .keyring
            .read(|b| {
                b.collection(c)
                    .and_then(|c| c.items.iter().find(|x| x.id == i))
                    .map(f)
            })?
            .ok_or(Error::NotFound)?)
    }

    async fn edit(
        &self,
        f: impl FnOnce(&mut Item) + Send + 'static,
    ) -> std::result::Result<(), Error> {
        let (c, i) = (self.collection, self.item);
        self.svc
            .modify(move |b| {
                let item = b
                    .collection_mut(c)
                    .and_then(|c| c.items.iter_mut().find(|x| x.id == i))
                    .ok_or(Error::NotFound)?;
                f(item);
                item.modified = aleph_core::model::now();
                Ok(())
            })
            .await
    }

    async fn changed(&self) -> zbus::Result<()> {
        let emitter = SignalEmitter::new(self.svc.conn(), collection_path(self.collection))?;
        CollectionObj::item_changed(&emitter, item_path(self.collection, self.item).as_ref()).await
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemObj {
    async fn delete(&self) -> Result<OwnedObjectPath> {
        let (c, i) = (self.collection, self.item);
        self.svc
            .modify(move |b| {
                b.collection_mut(c)
                    .and_then(|c| c.remove(i))
                    .ok_or(Error::NotFound)?;
                Ok(())
            })
            .await?;
        self.svc.sync().await?;
        let emitter = SignalEmitter::new(self.svc.conn(), collection_path(c))?;
        CollectionObj::item_deleted(&emitter, item_path(c, i).as_ref()).await?;
        Ok(root())
    }

    /// One struct out-argument, `((oayays))`: a bare tuple would be sent as
    /// four arguments, which libsecret rejects.
    #[zbus(out_args("secret"))]
    async fn get_secret(&self, session: OwnedObjectPath) -> Result<(SecretStruct,)> {
        let item = self.with(Item::clone)?;
        Ok((self.svc.secret_for(&session.as_ref(), &item)?,))
    }

    async fn set_secret(&self, secret: SecretStruct) -> Result<()> {
        let value = self.svc.decrypt(&secret)?;
        let content_type = secret.3.clone();
        self.edit(move |i| {
            i.secret = value;
            i.content_type = content_type;
        })
        .await?;
        self.changed().await?;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.svc.keyring.is_locked()
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        self.with(|i| i.attributes.clone().into_iter().collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_attributes(
        &mut self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<()> {
        self.edit(move |i| i.attributes = attributes.into_iter().collect())
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let _ = self.changed().await;
        Ok(())
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.with(|i| i.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> zbus::fdo::Result<()> {
        self.edit(move |i| i.label = label)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let _ = self.changed().await;
        Ok(())
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.with(|i| i.created).unwrap_or_default()
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.with(|i| i.modified).unwrap_or_default()
    }
}

/// A locked search's stand-in: an item that is always locked. `Unlock` on
/// it resolves to the items the search finds once the vault is open.
struct PlaceholderObj {
    query: HashMap<String, String>,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl PlaceholderObj {
    async fn delete(&self) -> Result<OwnedObjectPath> {
        Err(SecretError::IsLocked("the keyring is locked".into()))
    }

    async fn get_secret(&self, _session: OwnedObjectPath) -> Result<(SecretStruct,)> {
        Err(SecretError::IsLocked("the keyring is locked".into()))
    }

    async fn set_secret(&self, _secret: SecretStruct) -> Result<()> {
        Err(SecretError::IsLocked("the keyring is locked".into()))
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        true
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        self.query.clone()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        "Locked keyring".into()
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        0
    }
}

struct SessionObj {
    svc: Arc<SecretService>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionObj {
    async fn close(&self, #[zbus(object_server)] server: &zbus::ObjectServer) -> Result<()> {
        self.svc.sessions.lock().unwrap().remove(&self.path);
        server.remove::<SessionObj, _>(self.path.as_ref()).await?;
        Ok(())
    }
}

struct PromptObj {
    svc: Arc<SecretService>,
    path: OwnedObjectPath,
    action: Action,
    /// `Prompt` runs once; a repeated call is ignored.
    started: std::sync::atomic::AtomicBool,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptObj {
    /// Start the prompt; the answer arrives as `Completed`.
    async fn prompt(
        &self,
        _window_id: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let client = hdr.sender().map(|s| s.to_string());
        let who = caller(conn, &hdr).await;
        let (svc, action, p) = (self.svc.clone(), self.action.clone(), self.path.clone());
        let unlocking = matches!(action, Action::Unlock(_));
        let empty = action.empty_result();
        tokio::spawn(async move {
            let run = svc.clone();
            let targets = match &action {
                Action::Unlock(targets) => targets.clone(),
                _ => Vec::new(),
            };
            let collection_signal = match &action {
                Action::DeleteCollection(id) => Some((false, collection_path(*id))),
                _ => None,
            };
            let creating = matches!(action, Action::CreateCollection { .. });
            let outcome = tokio::task::spawn_blocking(move || run.run(&action, who))
                .await
                .unwrap_or(Outcome::Dismissed);
            match outcome {
                Outcome::Done(value) if unlocking => {
                    // Serve the objects, then complete this prompt and any
                    // others that were waiting.
                    let _ = svc.unlocked().await;
                    finish(&svc, &p, Some(value), empty).await;
                }
                Outcome::Done(value) => {
                    let _ = svc.sync().await;
                    let signal = if creating {
                        value
                            .try_clone()
                            .ok()
                            .and_then(|v| OwnedObjectPath::try_from(v).ok())
                            .map(|c| (true, c))
                    } else {
                        collection_signal
                    };
                    if let (Some((created, c)), Ok(emitter)) =
                        (signal, SignalEmitter::new(svc.conn(), SERVICE_PATH))
                    {
                        let _ = if created {
                            ServiceObj::collection_created(&emitter, c.as_ref()).await
                        } else {
                            ServiceObj::collection_deleted(&emitter, c.as_ref()).await
                        };
                    }
                    finish(&svc, &p, Some(value), empty).await;
                }
                Outcome::Dismissed => finish(&svc, &p, None, empty).await,
                Outcome::Wait => {
                    let admitted = {
                        let mut waiting = svc.waiting.lock().unwrap();
                        let mine = waiting.iter().filter(|w| w.client == client).count();
                        let ok = mine < MAX_WAITING_PER_CLIENT && waiting.len() < MAX_WAITING;
                        if ok {
                            waiting.push(Waiting {
                                prompt: p.clone(),
                                client: client.clone(),
                                targets,
                            });
                        }
                        ok
                    };
                    if !admitted {
                        finish(&svc, &p, None, empty).await;
                        return;
                    }
                    svc.gone_already(client.as_deref()).await;
                    // Unlocked meanwhile? Then complete now.
                    if !svc.keyring.is_locked() {
                        let _ = svc.unlocked().await;
                    }
                }
            }
        });
        Ok(())
    }

    async fn dismiss(&self) -> Result<()> {
        self.svc
            .waiting
            .lock()
            .unwrap()
            .retain(|w| w.prompt != self.path);
        finish(&self.svc, &self.path, None, self.action.empty_result()).await;
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

impl Action {
    /// The result a dismissed prompt carries: an empty value of the type a
    /// completed one would. libsecret checks the type even when dismissed,
    /// and a mismatch (e.g. `s` for an unlock's `ao`) hangs it.
    fn empty_result(&self) -> OwnedValue {
        match self {
            Action::Unlock(_) => empty_paths(),
            Action::CreateCollection { .. } | Action::DeleteCollection(_) => path_value(root()),
        }
    }
}

fn empty_paths() -> OwnedValue {
    OwnedValue::try_from(Value::from(Vec::<OwnedObjectPath>::new())).expect("ao is a value")
}

/// Emit `Completed` (with `result`, or dismissed with `empty`) and retire
/// the prompt object.
async fn finish(
    svc: &Arc<SecretService>,
    p: &OwnedObjectPath,
    result: Option<OwnedValue>,
    empty: OwnedValue,
) {
    // Exactly once: a prompt dismissed while it runs is already finished.
    if svc.prompts.lock().unwrap().remove(p).is_none() {
        return;
    }
    if let Ok(emitter) = SignalEmitter::new(svc.conn(), p.as_ref()) {
        let (dismissed, value) = match result {
            Some(v) => (false, Value::from(v)),
            None => (true, Value::from(empty)),
        };
        let _ = PromptObj::completed(&emitter, dismissed, value).await;
    }
    let _ = svc
        .conn()
        .object_server()
        .remove::<PromptObj, _>(p.as_ref())
        .await;
}
```

Write `crates/aleph-daemon/src/testing.rs`:

```rust
//! Test support (feature `testing`), shared by this crate's and the CLI's
//! integration tests: a TPM helper on swtpm, a keyring on it, a private
//! session bus, and scripted prompters. Nothing here is used in production.
#![allow(dead_code, unused_imports)]

use std::os::unix::net::UnixListener;
pub use std::sync::Arc;

pub use crate::Error;
pub use crate::keyring::{Backends, Keyring, Tpm};
pub use crate::password::Fixed;
pub use crate::paths::Paths;
pub use crate::prompt::scripted::Scripted;
pub use crate::prompt::{FromPrompter, Launcher, Method, Secret, ToPrompter};
pub use aleph_tpmd::server::Policy;
pub use aleph_tpmd::testing::SwTpm;
pub use aleph_unlock::TpmClient;
pub use aleph_unlock::fido2::mock::{MockAuthenticator, MockKeys};

pub const PW: &str = "correct horse";
pub const PIN: &str = "123456";

pub struct Env {
    pub sw: SwTpm,
    _dir: tempfile::TempDir,
    pub paths: Paths,
    pub socket: std::path::PathBuf,
}

pub fn env() -> Env {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let helper = Arc::new(sw.helper_with(Policy::allow_all()));
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));
    let paths = Paths::under(dir.path());
    Env {
        sw,
        _dir: dir,
        paths,
        socket,
    }
}

pub fn keyring(env: &Env, keys: MockKeys) -> Keyring {
    keyring_with(
        env,
        Box::new(TpmClient::new(env.socket.clone())),
        keys,
        Box::new(Fixed(|p| p == PW)),
    )
}

/// A keyring with the given TPM and password check (test parameters).
pub fn keyring_with(
    env: &Env,
    tpm: Box<dyn Tpm>,
    keys: MockKeys,
    password: Box<dyn crate::password::PasswordCheck>,
) -> Keyring {
    let backends = Backends {
        tpm,
        keys: Box::new(keys),
        password,
    };
    // Tests reopen the vault right after dropping a keyring. A process
    // another test forks meanwhile (swtpm, unix_chkpwd) briefly holds a copy
    // of the daemon lock's descriptor until its exec closes it: retry.
    let mut store = crate::store::Store::open(&env.paths);
    for _ in 0..200 {
        if !matches!(store, Err(crate::Error::AlreadyRunning)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        store = crate::store::Store::open(&env.paths);
    }
    let mut k = Keyring::from_store(store.unwrap(), &env.paths, backends);
    k.argon2 = aleph_core::Argon2Params::INSECURE_TEST;
    k.key_wait = std::time::Duration::from_millis(600);
    k
}

/// A machine without a usable TPM.
pub struct NoTpm;

impl Tpm for NoTpm {
    fn seal(&self, _: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
        Err(aleph_unlock::Error::TpmUnavailable("no TPM".into()))
    }

    fn unseal(&self, _: &aleph_core::TpmSlot, _: &[u8]) -> aleph_unlock::Result<aleph_core::Kek> {
        Err(aleph_unlock::Error::TpmUnavailable("no TPM".into()))
    }

    fn usable(&self) -> bool {
        false
    }
}

/// A TPM whose unseals succeed `ok` times, then fail with `then()`
/// (`Busy`, or `AuthFailed` as if the password had changed).
pub struct FlakyTpm {
    pub inner: TpmClient,
    pub ok: std::sync::atomic::AtomicUsize,
    pub then: fn() -> aleph_unlock::Error,
}

impl Tpm for FlakyTpm {
    fn seal(&self, pw: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
        self.inner.seal(pw)
    }

    fn unseal(
        &self,
        slot: &aleph_core::TpmSlot,
        pw: &[u8],
    ) -> aleph_unlock::Result<aleph_core::Kek> {
        use std::sync::atomic::Ordering;
        if self.ok.load(Ordering::SeqCst) == 0 {
            return Err((self.then)());
        }
        self.ok.fetch_sub(1, Ordering::SeqCst);
        self.inner.unseal(slot, pw)
    }

    fn usable(&self) -> bool {
        true
    }
}

/// A password check accepting whatever the shared value currently is (the
/// login password can "change" mid-test).
#[derive(Clone)]
pub struct Accepting(pub Arc<std::sync::Mutex<String>>);

impl Accepting {
    pub fn new(pw: &str) -> Self {
        Self(Arc::new(std::sync::Mutex::new(pw.to_string())))
    }

    pub fn set(&self, pw: &str) {
        *self.0.lock().unwrap() = pw.to_string();
    }
}

impl crate::password::PasswordCheck for Accepting {
    fn check(&self, pw: &str) -> crate::Result<bool> {
        Ok(*self.0.lock().unwrap() == pw)
    }
}

/// A password check that cannot run (no PAM service file).
pub struct Unavailable;

impl crate::password::PasswordCheck for Unavailable {
    fn check(&self, _: &str) -> crate::Result<bool> {
        Err(crate::Error::PasswordCheckUnavailable)
    }
}

pub fn password(p: &str) -> FromPrompter {
    FromPrompter::Password {
        password: Secret::new(p),
    }
}

pub fn pin(p: &str) -> FromPrompter {
    FromPrompter::Pin {
        pin: Secret::new(p),
    }
}

/// Answers a `ShowRecoveryKey` by reading the key it was shown: the
/// scripted prompter cannot know the key in advance, so these tests use a
/// prompter thread that fills the check in.
fn recovery_answer(sent: &[ToPrompter]) -> Option<FromPrompter> {
    sent.iter().rev().find_map(|m| match m {
        ToPrompter::ShowRecoveryKey { key, check, .. } => {
            let groups: Vec<&str> = key.expose().split('-').collect();
            Some(FromPrompter::RecoveryCheck {
                groups: [
                    Secret::new(groups[check[0] - 1].to_lowercase()),
                    Secret::new(groups[check[1] - 1]),
                ],
            })
        }
        _ => None,
    })
}

/// A prompter that answers `Ask`/`Fido2Pin`/`Confirm` from `replies` and
/// confirms any recovery key it is shown.
pub struct Interactive {
    replies: std::sync::Mutex<Vec<FromPrompter>>,
    sent: Arc<std::sync::Mutex<Vec<ToPrompter>>>,
}

impl Interactive {
    pub fn new(replies: Vec<FromPrompter>) -> Self {
        Self {
            replies: std::sync::Mutex::new(replies),
            sent: Arc::default(),
        }
    }

    /// Everything sent, once the conversation has ended (`Done`).
    pub fn sent(&self) -> Vec<ToPrompter> {
        for _ in 0..200 {
            let sent = self.sent.lock().unwrap().clone();
            if matches!(sent.last(), Some(ToPrompter::Done { .. })) {
                return sent;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        self.sent.lock().unwrap().clone()
    }

    pub fn channel(&self) -> crate::prompt::Channel {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        self.respond(theirs);
        crate::prompt::Channel::new(ours, std::time::Duration::from_secs(10)).unwrap()
    }

    /// Answer the conversation arriving on `theirs` (the prompter's end).
    pub fn respond(&self, theirs: std::os::unix::net::UnixStream) {
        use std::io::{BufRead, BufReader, Write};
        let replies: Vec<FromPrompter> = std::mem::take(&mut *self.replies.lock().unwrap());
        let sent = self.sent.clone();
        std::thread::spawn(move || {
            let mut replies = replies.into_iter().peekable();
            let mut reader = BufReader::new(theirs.try_clone().unwrap());
            let mut writer = theirs;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let msg: ToPrompter = serde_json::from_str(&line).unwrap();
                line.clear();
                sent.lock().unwrap().push(msg.clone());
                let reply = match &msg {
                    ToPrompter::ShowRecoveryKey { .. } => {
                        recovery_answer(std::slice::from_ref(&msg))
                    }
                    // A scripted Cancel may answer "insert your key" (skip).
                    ToPrompter::InsertKey { .. }
                        if replies.peek() == Some(&FromPrompter::Cancel {}) =>
                    {
                        replies.next()
                    }
                    m if m.needs_reply() => Some(replies.next().unwrap_or(FromPrompter::Cancel {})),
                    ToPrompter::Done { .. } => break,
                    _ => None,
                };
                if let Some(r) = reply {
                    let mut out = serde_json::to_vec(&r).unwrap();
                    out.push(b'\n');
                    if writer.write_all(&out).is_err() {
                        break;
                    }
                }
            }
        });
    }
}

pub fn create_with_password(k: &Keyring) {
    let p = Interactive::new(vec![password(PW)]);
    k.create(&mut p.channel(), Method::Password).unwrap();
}

/// A launcher handing out `Interactive` channels, each answering from its
/// own reply list (tests push one list per expected prompt).
pub struct InteractiveLauncher {
    pub scripts: std::sync::Mutex<Vec<Vec<FromPrompter>>>,
    pub launched: std::sync::atomic::AtomicUsize,
}

impl InteractiveLauncher {
    pub fn new(scripts: Vec<Vec<FromPrompter>>) -> Self {
        Self {
            scripts: std::sync::Mutex::new(scripts),
            launched: Default::default(),
        }
    }
}

impl Launcher for InteractiveLauncher {
    fn launch(&self) -> crate::Result<crate::prompt::Channel> {
        self.launched
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut scripts = self.scripts.lock().unwrap();
        if scripts.is_empty() {
            return Err(crate::Error::NoPrompter);
        }
        Ok(Interactive::new(scripts.remove(0)).channel())
    }
}

/// A private session bus, killed on drop.
pub struct Bus {
    child: std::process::Child,
    pub address: String,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn bus() -> Bus {
    let mut child = std::process::Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("dbus-daemon (Arch: pacman -S dbus)");
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.take().unwrap()),
        &mut line,
    )
    .unwrap();
    Bus {
        child,
        address: line.trim().to_string(),
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 20 passed | ok. 24 passed | ok. 12 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **locked search returns a placeholder** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service a_locked_lookup_prompts_once`: replace `Err(Error::Locked) => Ok((Vec::new(), vec![self.svc.placeholder(attributes).await?])),` with `Err(Error::Locked) => Err(Error::Locked.into()),`.
- **no prompter: wait, not dismiss** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service without_a_prompter`:

  replace

  ```rust
  tracing::info!("no prompter: {e}");
  return Outcome::Wait;
  ```

  with

  ```rust
  tracing::info!("no prompter: {e}");
  return Outcome::Dismissed;
  ```

- **dismissal carries a typed empty result** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service cancelling_the_prompt`: replace `Action::Unlock(_) => empty_paths(),` with `Action::Unlock(_) => OwnedValue::from(zbus::zvariant::Str::from("")),`.
- **sessions outlive locks** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service a_session_survives_lock_and_unlock`:

  replace

  ```rust
  self.keyring.lock();
  let searches
  ```

  with

  ```rust
  self.keyring.lock();
  self.sessions.lock().unwrap().clear();
  let searches
  ```

- **no empty answers while locked** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service waiting_prompts_are_not_answered_while_locked`: replace `None => self.waiting.lock().unwrap().push(w)` with `None => finish(self, &w.prompt, None, empty_paths()).await`.
- **placeholder query captured at Unlock** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service a_placeholder_query_is_captured`: replace `Some((_, query)) => Target::Search(query.clone()),` with `Some(_) => Target::Path(o),`.
- **unknown search paths dropped** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service a_placeholder_query_is_captured`: replace `Target::Path(p) if p.as_str().starts_with(SEARCH_PREFIX) => {}` with `(nothing)`.
- **a prompt runs once** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service a_prompt_runs_once`: replace `if self.started.swap(true, Ordering::SeqCst) {` with `if false && self.started.swap(true, Ordering::SeqCst) {`.
- **sessions freed on disconnect** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service sessions_are_freed`: replace `if !name.starts_with(':') || args.new_owner().is_some() {` with `if true {`.
- **waiting prompts capped** (`crates/aleph-daemon/src/secret/service.rs`), test `cargo test -p aleph-daemon --test secret_service waiting_prompts_are_capped`: replace `let ok = mine < MAX_WAITING_PER_CLIENT && waiting.len() < MAX_WAITING;` with `let ok = mine < usize::MAX;`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-daemon
git commit -m "feat(daemon): Secret Service with locked-search placeholders" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 6: admin interface, alephd, units

**Interfaces:**
- Consumes: Tasks 4–5.
- Produces: `admin::{{Admin, ADMIN_PATH, BUS_NAME}}` (methods `Status`, `Lock`, `Unlock(h)`, `Create(h, s)`, `EnrollTpm(h)`, `EnrollFido2(h, b)`, `RemoveKeyslot(h, s)`, `RotateMaster(h)`, `ReissueRecoveryKey(h)`, `RetryKeyslot(s)`, `GetConfig(s)`, `SetConfig(h, s, s)`); `daemon::serve(&Connection, Arc<Keyring>, Arc<dyn Launcher>, Arc<Mutex<Config>>, Paths)`; `prompt::ProgramLauncher {{ config: Arc<Mutex<Config>> }}` (read at each launch); binary `alephd`; `testing::{{Daemon, daemon(create, prompts)}}`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-daemon/Cargo.toml`:

```toml
[package]
name = "aleph-daemon"
description = "alephd: the aleph keyring daemon (Secret Service and admin interface)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "alephd"
path = "src/main.rs"

[features]
testing = ["dep:aleph-tpmd", "dep:tempfile", "aleph-core/insecure-test-params"]

[dependencies]
aes = "0.9"
cbc = { version = "0.2", features = ["alloc"] }
futures-util = { version = "0.3", default-features = false }
hkdf.workspace = true
num-bigint = "0.4"
sha2.workspace = true
aleph-core = { path = "../aleph-core" }
aleph-prompt-proto = { path = "../aleph-prompt-proto" }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
aleph-unlock = { path = "../aleph-unlock" }
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "signal"] }
toml = "1"
tracing = "0.1"
tracing-journald = "0.3"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid.workspace = true
zbus = { version = "5", default-features = false, features = ["tokio"] }
zeroize.workspace = true
aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"], optional = true }
tempfile = { workspace = true, optional = true }

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-daemon = { path = ".", features = ["testing"] }
tempfile.workspace = true
serde.workspace = true
```

Write `crates/aleph-daemon/src/lib.rs`:

```rust
//! `alephd`, the aleph keyring daemon (spec §6).

pub mod admin;
pub mod config;
pub mod daemon;
pub mod error;
pub mod keyring;
pub mod password;
pub mod paths;
pub mod prompt;
pub mod secret;
pub mod state;
pub mod store;

#[cfg(feature = "testing")]
pub mod testing;

pub use error::{Error, Result};
```

Create `crates/aleph-daemon/src/admin.rs` containing only `// implemented in step 3`.

Create `crates/aleph-daemon/src/daemon.rs` containing only `// implemented in step 3`.

Write `crates/aleph-daemon/tests/admin.rs`:

```rust
//! `io.aleph.Admin1` over a private bus, with the test as the prompter on
//! its end of a socketpair (as the `aleph` CLI is).

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use aleph_daemon::config::Config;
use aleph_daemon::testing::*;
use serde_json::Value as Json;

struct Daemon {
    _bus: Bus,
    _env: Env,
    _conn: zbus::Connection,
    client: zbus::Connection,
    paths: Paths,
}

async fn daemon() -> Daemon {
    let env = env();
    let bus = bus();
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .name("io.aleph.Keyring")
        .unwrap()
        .build()
        .await
        .unwrap();
    let keyring = Arc::new(keyring(&env, MockKeys::default()));
    let launcher = Arc::new(InteractiveLauncher::new(vec![]));
    aleph_daemon::daemon::serve(
        &conn,
        keyring,
        launcher,
        Arc::new(std::sync::Mutex::new(Config::default())),
        env.paths.clone(),
    )
    .await
    .unwrap();
    let client = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    Daemon {
        paths: env.paths.clone(),
        _bus: bus,
        _env: env,
        _conn: conn,
        client,
    }
}

async fn admin(d: &Daemon) -> zbus::Proxy<'static> {
    zbus::Proxy::new(
        &d.client,
        "io.aleph.Keyring",
        "/io/aleph/Admin",
        "io.aleph.Admin1",
    )
    .await
    .unwrap()
}

/// Call a conversational method with a prompter answering `replies`;
/// returns what the prompter was sent, once the conversation is done.
async fn converse(
    d: &Daemon,
    method: &str,
    extra: &[&str],
    replies: Vec<FromPrompter>,
) -> Vec<ToPrompter> {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let prompter = Interactive::new(replies);
    prompter.respond(ours);
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    let proxy = admin(d).await;
    match extra {
        [] => proxy.call_method(method, &(fd,)).await,
        [a] => proxy.call_method(method, &(fd, *a)).await,
        [a, b] => proxy.call_method(method, &(fd, *a, *b)).await,
        _ => unreachable!(),
    }
    .unwrap();
    tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap()
}

async fn status(d: &Daemon) -> Json {
    let s: String = admin(d).await.call("Status", &()).await.unwrap();
    serde_json::from_str(&s).unwrap()
}

fn done(sent: &[ToPrompter]) -> (bool, Option<String>) {
    match sent.last() {
        Some(ToPrompter::Done { ok, message }) => (*ok, message.clone()),
        other => panic!("conversation did not finish: {other:?}"),
    }
}

async fn collections(d: &Daemon) -> Vec<String> {
    let p = zbus::Proxy::new(
        &d.client,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let v: Vec<zbus::zvariant::OwnedObjectPath> = p.get_property("Collections").await.unwrap();
    v.into_iter().map(|p| p.to_string()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn create_lock_and_unlock_through_the_admin_interface() {
    let d = daemon().await;
    assert_eq!(status(&d).await["vault"], false);
    let sent = converse(&d, "Create", &["password"], vec![password(PW)]).await;
    assert!(done(&sent).0, "{sent:?}");
    let s = status(&d).await;
    assert_eq!(
        (s["vault"].clone(), s["locked"].clone()),
        (true.into(), false.into())
    );
    // Unlocked: the real collections are served.
    assert!(collections(&d).await[0].contains("/collection/"));

    admin(&d).await.call_method("Lock", &()).await.unwrap();
    assert_eq!(status(&d).await["locked"], true);
    assert_eq!(
        collections(&d).await,
        ["/org/freedesktop/secrets/aliases/default"]
    );

    let sent = converse(&d, "Unlock", &[], vec![password("typo"), password(PW)]).await;
    assert!(done(&sent).0);
    assert_eq!(status(&d).await["locked"], false);
    assert!(collections(&d).await[0].contains("/collection/"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_unlock_reports_failure_and_stays_locked() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    admin(&d).await.call_method("Lock", &()).await.unwrap();
    let sent = converse(&d, "Unlock", &[], vec![FromPrompter::Cancel {}]).await;
    assert_eq!(done(&sent), (false, Some("cancelled".into())));
    assert_eq!(status(&d).await["locked"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn setting_config_reauthenticates_and_saves() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    // A bad key is refused at once, before any prompt.
    let (_, theirs) = UnixStream::pair().unwrap();
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    assert!(
        admin(&d)
            .await
            .call_method("SetConfig", &(fd, "lock.idel", "1"))
            .await
            .is_err()
    );
    let sent = converse(
        &d,
        "SetConfig",
        &["lock.idle_timeout", "900"],
        vec![password(PW)],
    )
    .await;
    assert!(done(&sent).0, "{sent:?}");
    assert!(sent.iter().any(|m| matches!(
        m,
        ToPrompter::Begin {
            purpose: aleph_daemon::prompt::Purpose::Reauth,
            ..
        }
    )));
    let v: String = admin(&d)
        .await
        .call("GetConfig", &("lock.idle_timeout",))
        .await
        .unwrap();
    assert_eq!(v, "900");
    assert_eq!(
        Config::load(&d.paths.config_file)
            .unwrap()
            .lock
            .idle_timeout,
        900
    );
}
```

Write `crates/aleph-daemon/tests/logging.rs`:

```rust
//! Secrets are never logged (spec §6 "Logging"): no `tracing` call in the
//! daemon may pass a value whose name says it is a secret. Messages may
//! mention passwords; arguments may not carry them. (The redacted `Debug`
//! of every secret type is the second line of defence.)

use std::path::Path;

const MACROS: &[&str] = &["trace!(", "debug!(", "info!(", "warn!(", "error!("];
const FORBIDDEN: &[&str] = &["password", "pin", "secret", "kek", "key", "mk", "recovery"];

/// The source of every `tracing` macro call in `text`, string literals
/// blanked out.
fn calls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in MACROS {
        let mut rest = text;
        while let Some(i) = rest.find(m) {
            let body = &rest[i + m.len()..];
            let (mut depth, mut in_str, mut end) = (1, false, body.len());
            let mut chars = body.char_indices().peekable();
            let mut call = String::new();
            while let Some((j, c)) = chars.next() {
                match (in_str, c) {
                    (true, '\\') => {
                        chars.next();
                        continue;
                    }
                    (true, '"') => in_str = false,
                    (true, _) => continue,
                    (false, '"') => in_str = true,
                    (false, '(') => depth += 1,
                    (false, ')') => {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break;
                        }
                    }
                    _ => {}
                }
                if !in_str && c != '"' {
                    call.push(c);
                }
            }
            let _ = end;
            out.push(call);
            rest = &body[1..];
        }
    }
    out
}

fn identifiers(call: &str) -> impl Iterator<Item = String> + '_ {
    call.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_logging_call_passes_a_secret() {
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut offenders = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        for call in calls(&text) {
            for word in identifiers(&call) {
                if FORBIDDEN
                    .iter()
                    .any(|bad| word.split('_').any(|part| part == *bad))
                {
                    offenders.push(format!("{}: {word} in `{}`", f.display(), call.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "logging calls that may leak secrets:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_lint_catches_a_leak() {
    let bad = r#"tracing::info!(password = %pw, "unlocking");"#;
    let words: Vec<String> = calls(bad)
        .iter()
        .flat_map(|c| identifiers(c).collect::<Vec<_>>())
        .collect();
    assert!(words.contains(&"password".to_string()));
    let fine = r#"tracing::warn!(slot = %id, "rejected the login password");"#;
    let words: Vec<String> = calls(fine)
        .iter()
        .flat_map(|c| identifiers(c).collect::<Vec<_>>())
        .collect();
    assert!(!words.iter().any(|w| w == "password"), "{words:?}");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-daemon/src/admin.rs`:

```rust
//! `io.aleph.Admin1` on the session bus (spec §6 "Admin interface").
//!
//! Methods that need the user take a prompter: one end of a socketpair,
//! passed as a Unix fd, speaking the protocol of [`crate::prompt`]. The
//! `aleph` CLI answers it in the terminal; `aleph-gui` in its own windows.
//! Such a method returns as soon as the request is accepted, and the
//! outcome arrives on the prompter as `Done`, so no D-Bus call ever waits
//! for the user (and none runs into a bus reply timeout).
//!
//! Every method that changes keyslots or configuration re-authenticates
//! first (the keyring engine does this).

use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;
use zbus::interface;

use crate::config::Config;
use crate::keyring::Keyring;
use crate::paths::Paths;
use crate::prompt::{Channel, Method};
use crate::secret::service::SecretService;

pub const ADMIN_PATH: &str = "/io/aleph/Admin";
pub const BUS_NAME: &str = "io.aleph.Keyring";

pub struct Admin {
    pub keyring: Arc<Keyring>,
    pub secrets: Arc<SecretService>,
    pub config: Arc<Mutex<Config>>,
    pub paths: Paths,
}

fn failed(msg: impl std::fmt::Display) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(msg.to_string())
}

fn slot_id(id: &str) -> zbus::fdo::Result<Uuid> {
    Uuid::try_parse(id)
        .map_err(|_| zbus::fdo::Error::InvalidArgs(format!("not a keyslot id: {id:?}")))
}

impl Admin {
    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.lock().unwrap().prompt.timeout)
    }

    /// Run a conversation on the caller's prompter in the background, then
    /// bring the Secret Service objects up to date.
    fn converse(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        work: impl FnOnce(&Keyring, &mut Channel) -> crate::Result<()> + Send + 'static,
    ) -> zbus::fdo::Result<()> {
        let mut chan = Channel::from_fd(OwnedFd::from(prompter), self.timeout()).map_err(failed)?;
        let (keyring, secrets) = (self.keyring.clone(), self.secrets.clone());
        tokio::spawn(async move {
            let k = keyring.clone();
            let result = tokio::task::spawn_blocking(move || work(&k, &mut chan)).await;
            if let Ok(Err(e)) = &result {
                tracing::info!("admin operation ended: {e}");
            }
            if keyring.is_locked() {
                let _ = secrets.sync().await;
            } else {
                let _ = secrets.unlocked().await;
            }
        });
        Ok(())
    }
}

#[interface(name = "io.aleph.Admin1")]
impl Admin {
    /// The keyring's state as JSON (`keyring::Status`).
    async fn status(&self) -> zbus::fdo::Result<String> {
        // Reads the vault header and asks the TPM helper: off the runtime.
        let keyring = self.keyring.clone();
        let status = tokio::task::spawn_blocking(move || keyring.status())
            .await
            .map_err(failed)?
            .map_err(failed)?;
        serde_json::to_string(&status).map_err(failed)
    }

    async fn lock(&self) -> zbus::fdo::Result<()> {
        self.secrets.lock().await.map_err(failed)
    }

    async fn unlock(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.unlock(chan, None))
    }

    /// Create the vault; `method` is `password` or `fido2`.
    async fn create(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        method: String,
    ) -> zbus::fdo::Result<()> {
        let method = match method.as_str() {
            "password" => Method::Password,
            "fido2" => Method::Fido2,
            other => {
                return Err(zbus::fdo::Error::InvalidArgs(format!(
                    "unknown method {other:?}"
                )));
            }
        };
        self.converse(prompter, move |k, chan| k.create(chan, method))
    }

    async fn enroll_tpm(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.enroll_tpm(chan))
    }

    async fn enroll_fido2(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        touch_only: bool,
    ) -> zbus::fdo::Result<()> {
        self.converse(prompter, move |k, chan| k.enroll_fido2(chan, touch_only))
    }

    async fn remove_keyslot(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        id: String,
    ) -> zbus::fdo::Result<()> {
        let id = slot_id(&id)?;
        self.converse(prompter, move |k, chan| k.remove_keyslot(chan, id))
    }

    async fn rotate_master(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.rotate_master(chan))
    }

    async fn reissue_recovery_key(
        &self,
        prompter: zbus::zvariant::OwnedFd,
    ) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.reissue_recovery(chan))
    }

    /// Clear a keyslot's stale mark so it is tried again.
    async fn retry_keyslot(&self, id: String) -> zbus::fdo::Result<()> {
        self.keyring.retry_slot(slot_id(&id)?).map_err(failed)
    }

    async fn get_config(&self, key: String) -> zbus::fdo::Result<String> {
        self.config.lock().unwrap().get(&key).map_err(failed)
    }

    /// Change a setting (after re-authentication) and save the file.
    async fn set_config(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        key: String,
        value: String,
    ) -> zbus::fdo::Result<()> {
        // Reject a bad key or value now, before asking the user anything.
        let mut preview = self.config.lock().unwrap().clone();
        preview.set(&key, &value).map_err(failed)?;
        let (config, file) = (self.config.clone(), self.paths.config_file.clone());
        self.converse(prompter, move |k, chan| {
            k.with_reauth(chan, &format!("Set {key} = {value}"), || {
                let mut current = config.lock().unwrap();
                let mut next = current.clone();
                next.set(&key, &value)?;
                next.save(&file)?;
                *current = next;
                Ok(Some(format!("{key} = {value}")))
            })
        })
    }
}
```

Write `crates/aleph-daemon/src/daemon.rs`:

```rust
//! Putting the daemon together: the keyring, the Secret Service, and the
//! admin interface on one bus connection. `main` uses this; so do the
//! integration tests, with a private bus and scripted prompters.

use std::sync::{Arc, Mutex};

use zbus::Connection;

use crate::admin::{ADMIN_PATH, Admin};
use crate::config::Config;
use crate::keyring::Keyring;
use crate::paths::Paths;
use crate::prompt::Launcher;
use crate::secret::service::SecretService;

/// Serve the Secret Service and `io.aleph.Admin1` on `conn`, which should
/// own `org.freedesktop.secrets` and `io.aleph.Keyring`.
pub async fn serve(
    conn: &Connection,
    keyring: Arc<Keyring>,
    launcher: Arc<dyn Launcher>,
    config: Arc<Mutex<Config>>,
    paths: Paths,
) -> zbus::Result<Arc<SecretService>> {
    let secrets = SecretService::new(keyring.clone(), launcher);
    secrets.serve(conn).await?;
    conn.object_server()
        .at(
            ADMIN_PATH,
            Admin {
                keyring,
                secrets: secrets.clone(),
                config,
                paths,
            },
        )
        .await?;
    Ok(secrets)
}
```

Write `crates/aleph-daemon/src/main.rs`:

```rust
//! `alephd`: the aleph keyring daemon (spec §6). Started by D-Bus
//! activation for `org.freedesktop.secrets` or `io.aleph.Keyring`, as the
//! systemd user service `alephd.service`.

use std::process::ExitCode;
use std::sync::Arc;

use aleph_daemon::admin::BUS_NAME;
use aleph_daemon::config::Config;
use aleph_daemon::keyring::{Backends, Keyring};
use aleph_daemon::password::PamCheck;
use aleph_daemon::paths::Paths;
use aleph_daemon::prompt::ProgramLauncher;
use aleph_unlock::TpmClient;
use aleph_unlock::fido2::libfido2::Libfido2Keys;

const SECRETS_NAME: &str = "org.freedesktop.secrets";

fn init_logging() {
    use tracing_subscriber::prelude::*;
    let registry = tracing_subscriber::registry().with(
        tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("info".parse().expect("valid directive")),
    );
    match tracing_journald::layer() {
        Ok(journald) => registry.with(journald).init(),
        Err(_) => registry
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .init(),
    }
}

async fn run() -> Result<(), String> {
    let paths = Paths::from_env().map_err(|e| e.to_string())?;
    let config = Config::load(&paths.config_file).map_err(|e| e.to_string())?;
    let backends = Backends {
        tpm: Box::new(TpmClient::from_env()),
        keys: Box::new(Libfido2Keys::new()),
        password: Box::new(PamCheck::for_current_user().map_err(|e| e.to_string())?),
    };
    let keyring = Arc::new(Keyring::new(&paths, backends).map_err(|e| e.to_string())?);
    let config = Arc::new(std::sync::Mutex::new(config));
    let launcher = Arc::new(ProgramLauncher {
        config: config.clone(),
    });
    let conn = zbus::connection::Builder::session()
        .and_then(|b| b.name(SECRETS_NAME))
        .and_then(|b| b.name(BUS_NAME))
        .map_err(|e| e.to_string())?
        .build()
        .await
        .map_err(|e| {
            format!("cannot own {SECRETS_NAME} on the session bus (is gnome-keyring still running?): {e}")
        })?;
    aleph_daemon::daemon::serve(&conn, keyring, launcher, config, paths)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}");
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    tracing::info!("stopping");
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    // No core dumps and no same-uid ptrace: this process holds MK (§4).
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no memory-safety preconditions.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    init_logging();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("alephd: {e}");
            ExitCode::FAILURE
        }
    }
}
```

Write `crates/aleph-daemon/src/testing.rs`:

```rust
//! Test support (feature `testing`), shared by this crate's and the CLI's
//! integration tests: a TPM helper on swtpm, a keyring on it, a private
//! session bus, and scripted prompters. Nothing here is used in production.
#![allow(dead_code, unused_imports)]

use std::os::unix::net::UnixListener;
pub use std::sync::Arc;

pub use crate::Error;
pub use crate::keyring::{Backends, Keyring, Tpm};
pub use crate::password::Fixed;
pub use crate::paths::Paths;
pub use crate::prompt::scripted::Scripted;
pub use crate::prompt::{FromPrompter, Launcher, Method, Secret, ToPrompter};
pub use aleph_tpmd::server::Policy;
pub use aleph_tpmd::testing::SwTpm;
pub use aleph_unlock::TpmClient;
pub use aleph_unlock::fido2::mock::{MockAuthenticator, MockKeys};

pub const PW: &str = "correct horse";
pub const PIN: &str = "123456";

pub struct Env {
    pub sw: SwTpm,
    _dir: tempfile::TempDir,
    pub paths: Paths,
    pub socket: std::path::PathBuf,
}

pub fn env() -> Env {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let helper = Arc::new(sw.helper_with(Policy::allow_all()));
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));
    let paths = Paths::under(dir.path());
    Env {
        sw,
        _dir: dir,
        paths,
        socket,
    }
}

pub fn keyring(env: &Env, keys: MockKeys) -> Keyring {
    keyring_with(
        env,
        Box::new(TpmClient::new(env.socket.clone())),
        keys,
        Box::new(Fixed(|p| p == PW)),
    )
}

/// A keyring with the given TPM and password check (test parameters).
pub fn keyring_with(
    env: &Env,
    tpm: Box<dyn Tpm>,
    keys: MockKeys,
    password: Box<dyn crate::password::PasswordCheck>,
) -> Keyring {
    let backends = Backends {
        tpm,
        keys: Box::new(keys),
        password,
    };
    // Tests reopen the vault right after dropping a keyring. A process
    // another test forks meanwhile (swtpm, unix_chkpwd) briefly holds a copy
    // of the daemon lock's descriptor until its exec closes it: retry.
    let mut store = crate::store::Store::open(&env.paths);
    for _ in 0..200 {
        if !matches!(store, Err(crate::Error::AlreadyRunning)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        store = crate::store::Store::open(&env.paths);
    }
    let mut k = Keyring::from_store(store.unwrap(), &env.paths, backends);
    k.argon2 = aleph_core::Argon2Params::INSECURE_TEST;
    k.key_wait = std::time::Duration::from_millis(600);
    k
}

/// A machine without a usable TPM.
pub struct NoTpm;

impl Tpm for NoTpm {
    fn seal(&self, _: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
        Err(aleph_unlock::Error::TpmUnavailable("no TPM".into()))
    }

    fn unseal(&self, _: &aleph_core::TpmSlot, _: &[u8]) -> aleph_unlock::Result<aleph_core::Kek> {
        Err(aleph_unlock::Error::TpmUnavailable("no TPM".into()))
    }

    fn usable(&self) -> bool {
        false
    }
}

/// A TPM whose unseals succeed `ok` times, then fail with `then()`
/// (`Busy`, or `AuthFailed` as if the password had changed).
pub struct FlakyTpm {
    pub inner: TpmClient,
    pub ok: std::sync::atomic::AtomicUsize,
    pub then: fn() -> aleph_unlock::Error,
}

impl Tpm for FlakyTpm {
    fn seal(&self, pw: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
        self.inner.seal(pw)
    }

    fn unseal(
        &self,
        slot: &aleph_core::TpmSlot,
        pw: &[u8],
    ) -> aleph_unlock::Result<aleph_core::Kek> {
        use std::sync::atomic::Ordering;
        if self.ok.load(Ordering::SeqCst) == 0 {
            return Err((self.then)());
        }
        self.ok.fetch_sub(1, Ordering::SeqCst);
        self.inner.unseal(slot, pw)
    }

    fn usable(&self) -> bool {
        true
    }
}

/// A password check accepting whatever the shared value currently is (the
/// login password can "change" mid-test).
#[derive(Clone)]
pub struct Accepting(pub Arc<std::sync::Mutex<String>>);

impl Accepting {
    pub fn new(pw: &str) -> Self {
        Self(Arc::new(std::sync::Mutex::new(pw.to_string())))
    }

    pub fn set(&self, pw: &str) {
        *self.0.lock().unwrap() = pw.to_string();
    }
}

impl crate::password::PasswordCheck for Accepting {
    fn check(&self, pw: &str) -> crate::Result<bool> {
        Ok(*self.0.lock().unwrap() == pw)
    }
}

/// A password check that cannot run (no PAM service file).
pub struct Unavailable;

impl crate::password::PasswordCheck for Unavailable {
    fn check(&self, _: &str) -> crate::Result<bool> {
        Err(crate::Error::PasswordCheckUnavailable)
    }
}

pub fn password(p: &str) -> FromPrompter {
    FromPrompter::Password {
        password: Secret::new(p),
    }
}

pub fn pin(p: &str) -> FromPrompter {
    FromPrompter::Pin {
        pin: Secret::new(p),
    }
}

/// Answers a `ShowRecoveryKey` by reading the key it was shown: the
/// scripted prompter cannot know the key in advance, so these tests use a
/// prompter thread that fills the check in.
fn recovery_answer(sent: &[ToPrompter]) -> Option<FromPrompter> {
    sent.iter().rev().find_map(|m| match m {
        ToPrompter::ShowRecoveryKey { key, check, .. } => {
            let groups: Vec<&str> = key.expose().split('-').collect();
            Some(FromPrompter::RecoveryCheck {
                groups: [
                    Secret::new(groups[check[0] - 1].to_lowercase()),
                    Secret::new(groups[check[1] - 1]),
                ],
            })
        }
        _ => None,
    })
}

/// A prompter that answers `Ask`/`Fido2Pin`/`Confirm` from `replies` and
/// confirms any recovery key it is shown.
pub struct Interactive {
    replies: std::sync::Mutex<Vec<FromPrompter>>,
    sent: Arc<std::sync::Mutex<Vec<ToPrompter>>>,
}

impl Interactive {
    pub fn new(replies: Vec<FromPrompter>) -> Self {
        Self {
            replies: std::sync::Mutex::new(replies),
            sent: Arc::default(),
        }
    }

    /// Everything sent, once the conversation has ended (`Done`).
    pub fn sent(&self) -> Vec<ToPrompter> {
        for _ in 0..200 {
            let sent = self.sent.lock().unwrap().clone();
            if matches!(sent.last(), Some(ToPrompter::Done { .. })) {
                return sent;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        self.sent.lock().unwrap().clone()
    }

    pub fn channel(&self) -> crate::prompt::Channel {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        self.respond(theirs);
        crate::prompt::Channel::new(ours, std::time::Duration::from_secs(10)).unwrap()
    }

    /// Answer the conversation arriving on `theirs` (the prompter's end).
    pub fn respond(&self, theirs: std::os::unix::net::UnixStream) {
        use std::io::{BufRead, BufReader, Write};
        let replies: Vec<FromPrompter> = std::mem::take(&mut *self.replies.lock().unwrap());
        let sent = self.sent.clone();
        std::thread::spawn(move || {
            let mut replies = replies.into_iter().peekable();
            let mut reader = BufReader::new(theirs.try_clone().unwrap());
            let mut writer = theirs;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let msg: ToPrompter = serde_json::from_str(&line).unwrap();
                line.clear();
                sent.lock().unwrap().push(msg.clone());
                let reply = match &msg {
                    ToPrompter::ShowRecoveryKey { .. } => {
                        recovery_answer(std::slice::from_ref(&msg))
                    }
                    // A scripted Cancel may answer "insert your key" (skip).
                    ToPrompter::InsertKey { .. }
                        if replies.peek() == Some(&FromPrompter::Cancel {}) =>
                    {
                        replies.next()
                    }
                    m if m.needs_reply() => Some(replies.next().unwrap_or(FromPrompter::Cancel {})),
                    ToPrompter::Done { .. } => break,
                    _ => None,
                };
                if let Some(r) = reply {
                    let mut out = serde_json::to_vec(&r).unwrap();
                    out.push(b'\n');
                    if writer.write_all(&out).is_err() {
                        break;
                    }
                }
            }
        });
    }
}

pub fn create_with_password(k: &Keyring) {
    let p = Interactive::new(vec![password(PW)]);
    k.create(&mut p.channel(), Method::Password).unwrap();
}

/// A launcher handing out `Interactive` channels, each answering from its
/// own reply list (tests push one list per expected prompt).
pub struct InteractiveLauncher {
    pub scripts: std::sync::Mutex<Vec<Vec<FromPrompter>>>,
    pub launched: std::sync::atomic::AtomicUsize,
}

impl InteractiveLauncher {
    pub fn new(scripts: Vec<Vec<FromPrompter>>) -> Self {
        Self {
            scripts: std::sync::Mutex::new(scripts),
            launched: Default::default(),
        }
    }
}

impl Launcher for InteractiveLauncher {
    fn launch(&self) -> crate::Result<crate::prompt::Channel> {
        self.launched
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut scripts = self.scripts.lock().unwrap();
        if scripts.is_empty() {
            return Err(crate::Error::NoPrompter);
        }
        Ok(Interactive::new(scripts.remove(0)).channel())
    }
}

/// A private session bus, killed on drop.
pub struct Bus {
    child: std::process::Child,
    pub address: String,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn bus() -> Bus {
    let mut child = std::process::Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("dbus-daemon (Arch: pacman -S dbus)");
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.take().unwrap()),
        &mut line,
    )
    .unwrap();
    Bus {
        child,
        address: line.trim().to_string(),
    }
}

/// A daemon (Secret Service and admin interface) on a private bus, with a
/// keyring on a swtpm TPM helper. `create` makes the vault (unlocked);
/// `prompts` answer Secret Service prompts, one list per prompt.
pub struct Daemon {
    pub secrets: Arc<crate::secret::service::SecretService>,
    pub keyring: Arc<Keyring>,
    pub bus: Bus,
    pub conn: zbus::Connection,
    pub env: Env,
}

pub async fn daemon(create: bool, prompts: Vec<Vec<FromPrompter>>) -> Daemon {
    let env = env();
    let keyring = Arc::new(keyring(&env, MockKeys::default()));
    if create {
        create_with_password(&keyring);
    }
    let bus = bus();
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .name(crate::admin::BUS_NAME)
        .unwrap()
        .build()
        .await
        .unwrap();
    let launcher = Arc::new(InteractiveLauncher::new(prompts));
    let secrets = crate::daemon::serve(
        &conn,
        keyring.clone(),
        launcher,
        Arc::new(std::sync::Mutex::new(crate::config::Config::default())),
        env.paths.clone(),
    )
    .await
    .unwrap();
    Daemon {
        secrets,
        keyring,
        bus,
        conn,
        env,
    }
}
```

Write `packaging/systemd/alephd.service`:

```ini
[Unit]
Description=aleph keyring daemon
Documentation=https://github.com/kisom/aleph-keyring

[Service]
# Started by D-Bus activation (org.freedesktop.secrets, io.aleph.Keyring).
Type=dbus
BusName=org.freedesktop.secrets
ExecStart=/usr/lib/aleph/alephd
Restart=on-failure
# alephd holds the master key while unlocked: no core dumps (it also sets
# PR_SET_DUMPABLE=0 itself).
LimitCORE=0
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
SystemCallArchitectures=native
# Not NoNewPrivileges: checking the login password with pam_unix runs the
# setuid unix_chkpwd helper.
```

Write `packaging/dbus/org.freedesktop.secrets.service`:

```ini
[D-BUS Service]
Name=org.freedesktop.secrets
Exec=/usr/lib/aleph/alephd
SystemdService=alephd.service
```

Write `packaging/dbus/io.aleph.Keyring.service`:

```ini
[D-BUS Service]
Name=io.aleph.Keyring
Exec=/usr/lib/aleph/alephd
SystemdService=alephd.service
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 20 passed | ok. 3 passed | ok. 24 passed | ok. 2 passed | ok. 12 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **reauth before config changes** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test admin setting_config_reauthenticates`: replace `self.reauth(chan, operation)?;` with `(nothing)`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-daemon packaging/systemd/alephd.service packaging/dbus
git commit -m "feat(daemon): io.aleph.Admin1, alephd, units, logging lint" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 7: aleph CLI

**Interfaces:**
- Consumes: Task 2 protocol; Task 6 admin interface (tests: `aleph_daemon::testing::daemon`).
- Produces: binary `aleph` with `setup`, `status`, `lock`, `unlock`, `keyslot {{list, add tpm, add fido2 [--touch-only], remove, rotate-master, retry}}`, `recovery reissue`, `get`, `search`, `store --label`, `delete`, `ls`, `config {{get, set}}`, `completions`, global `--json`

- [ ] **Step 1: Write the failing tests**

Write `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-tpm-proto", "crates/aleph-tpmd", "crates/aleph-unlock", "crates/aleph-prompt-proto", "crates/aleph-daemon", "crates/aleph-cli"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "Apache-2.0"
rust-version = "1.98"

[workspace.dependencies]
argon2 = "0.6"
chacha20poly1305 = "0.11"
ciborium = "0.2"
fido2-rs = "0.6"
getrandom = "0.4"
hkdf = "0.13"
hex = "0.4"
hybrid-array = { version = "0.4", features = ["zeroize"] }
hmac = "0.13"
libc = "0.2"
proptest = "1"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
serde_json = "1"
sha2 = "0.11"
tempfile = "3"
thiserror = "2"
tss-esapi = "7.7"
uuid = { version = "1", features = ["v4", "serde"] }
# Pinned exactly: recovery keys must open vaults forever, and the crate
# tracks a draft (the local KATs against the draft vectors are the tripwire).
x-wing = { version = "=0.1.0", features = ["zeroize"] }
zeroize = { version = "1.9", features = ["derive"] }

# Argon2, the AEAD, X-Wing (ML-KEM, X25519, SHA-3), and CBOR parsing are
# unusably slow unoptimized; keep tests fast.
[profile.dev.package.argon2]
opt-level = 3
[profile.dev.package.blake2]
opt-level = 3
[profile.dev.package.chacha20poly1305]
opt-level = 3
[profile.dev.package.chacha20]
opt-level = 3
[profile.dev.package.poly1305]
opt-level = 3
[profile.dev.package.ml-kem]
opt-level = 3
[profile.dev.package.module-lattice]
opt-level = 3
[profile.dev.package.x25519-dalek]
opt-level = 3
[profile.dev.package.curve25519-dalek]
opt-level = 3
[profile.dev.package.sha3]
opt-level = 3
[profile.dev.package.keccak]
opt-level = 3
[profile.dev.package.shake]
opt-level = 3
[profile.dev.package.ciborium]
opt-level = 3
[profile.dev.package.ciborium-ll]
opt-level = 3
```

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
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Create `crates/aleph-cli/src/main.rs` containing only `fn main() {}`.

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-cli`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-cli/src/main.rs`:

```rust
//! `aleph`, the command-line client (spec §7 "CLI").
//!
//! Everything goes through the running `alephd`: `io.aleph.Admin1` for the
//! keyring, the Secret Service for items. Prompts the daemon needs are
//! answered in this terminal. Secrets are read from standard input, never
//! from the command line.

mod client;
mod prompter;

use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

use client::{Args, Client, Result};

#[derive(Parser)]
#[command(name = "aleph", version, about = "The aleph keyring")]
struct Cli {
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the keyring (system integration comes in a later release).
    Setup,
    /// Show the keyring's state and keyslots.
    Status,
    Lock,
    Unlock,
    #[command(subcommand)]
    Keyslot(KeyslotCmd),
    #[command(subcommand)]
    Recovery(RecoveryCmd),
    /// Print the secret of the item matching attr=value pairs.
    Get {
        attributes: Vec<String>,
    },
    /// List items matching attr=value pairs.
    Search {
        attributes: Vec<String>,
    },
    /// Store a secret (read from standard input) with a label and attributes.
    Store {
        #[arg(long)]
        label: String,
        attributes: Vec<String>,
    },
    /// Delete the items matching attr=value pairs.
    Delete {
        attributes: Vec<String>,
    },
    /// List collections, or the items of one.
    Ls {
        collection: Option<String>,
    },
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Print shell completions.
    Completions {
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum KeyslotCmd {
    List,
    #[command(subcommand)]
    Add(AddCmd),
    /// Remove a keyslot (rotates the master key).
    Remove {
        id: String,
    },
    RotateMaster,
    /// Try a stale keyslot again.
    Retry {
        id: String,
    },
}

#[derive(Subcommand)]
enum AddCmd {
    /// The TPM, unlocked with your login password.
    Tpm,
    /// A FIDO2 security key.
    Fido2 {
        /// Unlock with a touch alone (anyone holding the key can unlock).
        #[arg(long)]
        touch_only: bool,
    },
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Issue a new recovery key; the old one stops working.
    Reissue,
}

#[derive(Subcommand)]
enum ConfigCmd {
    Get { key: String },
    Set { key: String, value: String },
}

/// Parse `attr=value` pairs.
fn attributes(pairs: &[String]) -> Result<HashMap<String, String>> {
    pairs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("expected attr=value, not {p:?}"))
        })
        .collect()
}

fn print_json(v: &impl serde::Serialize) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(v).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// Report a conversation's outcome; failure is an error.
fn outcome(o: prompter::Outcome) -> Result<()> {
    match (o.ok, o.message) {
        (true, Some(m)) => {
            eprintln!("aleph: {m}");
            Ok(())
        }
        (true, None) => Ok(()),
        (false, m) => Err(m.unwrap_or_else(|| "failed".into())),
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    if let Cmd::Completions { shell } = cli.cmd {
        clap_complete::generate(shell, &mut Cli::command(), "aleph", &mut std::io::stdout());
        return Ok(ExitCode::SUCCESS);
    }
    let c = Client::connect().await?;
    match cli.cmd {
        Cmd::Completions { .. } => unreachable!(),
        Cmd::Setup => {
            let status = c.status().await?;
            if status.vault {
                eprintln!("aleph: a keyring already exists (see `aleph status`)");
                return Ok(ExitCode::SUCCESS);
            }
            let tpm = status.tpm.unwrap_or(false);
            let first = if tpm {
                "the TPM and your login password (recommended)"
            } else {
                "your login password"
            };
            eprintln!("How should the keyring unlock?\n  1) {first}\n  2) a FIDO2 security key");
            let mut term = prompter::Terminal::new();
            let choice = term_line(&mut term, "Choice [1]: ")?;
            let method = if choice.trim() == "2" {
                "fido2"
            } else {
                "password"
            };
            outcome(c.converse("Create", Args::Str(method)).await?)?;
            eprintln!(
                "aleph: note: login unlock, taking over from gnome-keyring, and importing its items are not available yet"
            );
        }
        Cmd::Status => {
            let s = c.status().await?;
            if cli.json {
                print_json(&s)?;
            } else {
                let state = match (s.vault, s.locked) {
                    (false, _) => "none (run `aleph setup`)",
                    (true, true) => "locked",
                    (true, false) => "unlocked",
                };
                println!("keyring: {state}");
                if let Some(why) = &s.untrusted {
                    println!("warning: the vault file was {why}; writes are refused");
                }
                if s.memory_locked == Some(false) {
                    println!(
                        "warning: the master key could not be locked in RAM (mlock); it may be swapped"
                    );
                }
                print_slots(&s.keyslots);
            }
        }
        Cmd::Lock => c.lock().await?,
        Cmd::Unlock => outcome(c.converse("Unlock", Args::None).await?)?,
        Cmd::Keyslot(k) => match k {
            KeyslotCmd::List => {
                let s = c.status().await?;
                if cli.json {
                    print_json(&s.keyslots)?;
                } else {
                    print_slots(&s.keyslots);
                }
            }
            KeyslotCmd::Add(AddCmd::Tpm) => outcome(c.converse("EnrollTpm", Args::None).await?)?,
            KeyslotCmd::Add(AddCmd::Fido2 { touch_only }) => {
                if touch_only {
                    eprintln!(
                        "aleph: warning: anyone holding a touch-only key can unlock the keyring"
                    );
                }
                outcome(c.converse("EnrollFido2", Args::Bool(touch_only)).await?)?;
            }
            KeyslotCmd::Remove { id } => outcome(
                c.converse("RemoveKeyslot", Args::Str(&full_id(&c, &id).await?))
                    .await?,
            )?,
            KeyslotCmd::RotateMaster => outcome(c.converse("RotateMaster", Args::None).await?)?,
            KeyslotCmd::Retry { id } => c.retry_keyslot(&full_id(&c, &id).await?).await?,
        },
        Cmd::Recovery(RecoveryCmd::Reissue) => {
            outcome(c.converse("ReissueRecoveryKey", Args::None).await?)?
        }
        Cmd::Get { attributes: pairs } => {
            let attrs = attributes(&pairs)?;
            if attrs.is_empty() {
                return Err("get needs at least one attr=value pair".into());
            }
            let items = c.search(&attrs).await?;
            let Some(item) = items.first() else {
                return Ok(ExitCode::FAILURE);
            };
            let secret = c.secret(&item.path).await?;
            let mut out = std::io::stdout().lock();
            out.write_all(&secret).map_err(|e| e.to_string())?;
            if std::io::stdout().is_terminal() {
                writeln!(out).map_err(|e| e.to_string())?;
            }
        }
        Cmd::Search { attributes: pairs } => {
            let items = c.search(&attributes(&pairs)?).await?;
            if cli.json {
                print_json(&items)?;
            } else {
                for item in &items {
                    print_item(item);
                }
            }
            if items.is_empty() {
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Store {
            label,
            attributes: pairs,
        } => {
            let attrs = attributes(&pairs)?;
            if attrs.is_empty() {
                return Err("store needs at least one attr=value pair".into());
            }
            let secret = read_secret()?;
            c.store(&label, &attrs, &secret).await?;
        }
        Cmd::Delete { attributes: pairs } => {
            let attrs = attributes(&pairs)?;
            if attrs.is_empty() {
                return Err(
                    "delete needs at least one attr=value pair (refusing to delete everything)"
                        .into(),
                );
            }
            let items = c.search(&attrs).await?;
            for item in &items {
                c.delete(&item.path).await?;
            }
            if items.is_empty() {
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Ls { collection } => {
            let collections = c.collections().await?;
            if cli.json {
                let v: Vec<_> = collections
                    .iter()
                    .filter(|(l, _)| collection.as_ref().is_none_or(|c| c == l))
                    .map(|(l, items)| serde_json::json!({ "label": l, "items": items }))
                    .collect();
                print_json(&v)?;
            } else {
                match collection {
                    None => {
                        for (label, items) in &collections {
                            println!("{label}\t{} items", items.len());
                        }
                    }
                    Some(want) => {
                        let (_, items) = collections
                            .iter()
                            .find(|(l, _)| *l == want)
                            .ok_or_else(|| format!("no collection {want:?}"))?;
                        for item in items {
                            print_item(item);
                        }
                    }
                }
            }
        }
        Cmd::Config(ConfigCmd::Get { key }) => println!("{}", c.get_config(&key).await?),
        Cmd::Config(ConfigCmd::Set { key, value }) => {
            outcome(c.converse("SetConfig", Args::Str2(&key, &value)).await?)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn term_line(term: &mut prompter::Terminal, prompt: &str) -> Result<String> {
    term.line(prompt).map_err(|e| e.to_string())
}

/// A keyslot id from its full form or a unique prefix (as `status` shows).
async fn full_id(c: &Client, prefix: &str) -> Result<String> {
    let slots = c.status().await?.keyslots;
    // Unknown slots without an id report the nil UUID; never match those.
    let nil = "00000000-0000-0000-0000-000000000000";
    let matches: Vec<&client::SlotInfo> = slots
        .iter()
        .filter(|s| s.id != nil && s.id.starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => Err(format!("no keyslot {prefix:?}")),
        _ => Err(format!(
            "{prefix:?} matches several keyslots; give more of the id"
        )),
    }
}

fn print_slots(slots: &[client::SlotInfo]) {
    for s in slots {
        let stale = if s.stale { "  (stale)" } else { "" };
        println!(
            "  {}  {:<15} {}{stale}",
            &s.id[..8.min(s.id.len())],
            s.kind,
            s.label
        );
    }
}

fn print_item(item: &client::ItemInfo) {
    println!("{}", item.label);
    let mut attrs: Vec<_> = item.attributes.iter().collect();
    attrs.sort();
    for (k, v) in attrs {
        println!("  {k} = {v}");
    }
}

/// The secret to store: typed with echo off at a terminal, else all of
/// standard input (a single trailing newline is dropped, as `secret-tool`
/// does).
fn read_secret() -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if std::io::stdin().is_terminal() {
        let s = rpassword::prompt_password("Secret: ").map_err(|e| e.to_string())?;
        return Ok(zeroize::Zeroizing::new(s.into_bytes()));
    }
    // Reserved up front so ordinary secrets never reallocate (a
    // reallocation would leave an unzeroized copy behind).
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(64 * 1024));
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    Ok(buf)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aleph: {e}");
            ExitCode::FAILURE
        }
    }
}
```

Write `crates/aleph-cli/src/client.rs`:

```rust
//! Talking to `alephd` on the session bus: `io.aleph.Admin1` for the
//! keyring itself, and the freedesktop Secret Service for items (spec §7).

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use serde::Deserialize;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::prompter::{self, Outcome, Terminal};

pub type Result<T> = std::result::Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct SlotInfo {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub created: u64,
    pub stale: bool,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct Status {
    pub vault: bool,
    pub locked: bool,
    pub untrusted: Option<String>,
    pub memory_locked: Option<bool>,
    pub tpm: Option<bool>,
    pub keyslots: Vec<SlotInfo>,
}

/// One item, as the CLI shows it.
#[derive(Debug, serde::Serialize)]
pub struct ItemInfo {
    #[serde(skip)]
    pub path: OwnedObjectPath,
    pub label: String,
    pub attributes: HashMap<String, String>,
}

/// `(session, parameters, value, content_type)`, as the Secret Service
/// sends a secret.
type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// Extra arguments of a conversational admin method (after the fd).
pub enum Args<'a> {
    None,
    Str(&'a str),
    Bool(bool),
    Str2(&'a str, &'a str),
}

pub struct Client {
    conn: zbus::Connection,
}

impl Client {
    pub async fn connect() -> Result<Self> {
        let conn = zbus::Connection::session()
            .await
            .map_err(|e| format!("cannot reach the session bus: {e}"))?;
        Ok(Self { conn })
    }

    async fn admin(&self) -> Result<zbus::Proxy<'static>> {
        zbus::Proxy::new(
            &self.conn,
            "io.aleph.Keyring",
            "/io/aleph/Admin",
            "io.aleph.Admin1",
        )
        .await
        .map_err(err)
    }

    async fn service(&self) -> Result<zbus::Proxy<'static>> {
        zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .await
        .map_err(err)
    }

    async fn proxy(
        &self,
        path: &OwnedObjectPath,
        iface: &'static str,
    ) -> Result<zbus::Proxy<'static>> {
        zbus::Proxy::new(&self.conn, "org.freedesktop.secrets", path.clone(), iface)
            .await
            .map_err(err)
    }

    pub async fn status(&self) -> Result<Status> {
        let json: String = self
            .admin()
            .await?
            .call("Status", &())
            .await
            .map_err(|e| format!("cannot reach alephd: {e}"))?;
        serde_json::from_str(&json).map_err(err)
    }

    pub async fn lock(&self) -> Result<()> {
        self.admin()
            .await?
            .call_method("Lock", &())
            .await
            .map_err(err)?;
        Ok(())
    }

    pub async fn get_config(&self, key: &str) -> Result<String> {
        self.admin()
            .await?
            .call("GetConfig", &(key,))
            .await
            .map_err(err)
    }

    pub async fn retry_keyslot(&self, id: &str) -> Result<()> {
        self.admin()
            .await?
            .call_method("RetryKeyslot", &(id,))
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Call an admin method that needs the user, answering its prompts in
    /// the terminal. The call returns at once; the outcome comes as `Done`.
    pub async fn converse(&self, method: &str, args: Args<'_>) -> Result<Outcome> {
        let (ours, theirs) = UnixStream::pair().map_err(err)?;
        let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
        let admin = self.admin().await?;
        match args {
            Args::None => admin.call_method(method, &(fd,)).await,
            Args::Str(a) => admin.call_method(method, &(fd, a)).await,
            Args::Bool(b) => admin.call_method(method, &(fd, b)).await,
            Args::Str2(a, b) => admin.call_method(method, &(fd, a, b)).await,
        }
        .map_err(|e| format!("cannot reach alephd: {e}"))?;
        tokio::task::spawn_blocking(move || prompter::converse(ours, &mut Terminal::new()))
            .await
            .map_err(err)?
            .map_err(err)
    }

    /// Unlock first (in the terminal) if the keyring is locked.
    pub async fn ensure_unlocked(&self) -> Result<()> {
        let status = self.status().await?;
        if !status.vault {
            return Err("no keyring yet; run `aleph setup`".into());
        }
        if status.locked {
            let outcome = self.converse("Unlock", Args::None).await?;
            if !outcome.ok {
                return Err(outcome.message.unwrap_or_else(|| "unlock failed".into()));
            }
        }
        Ok(())
    }

    async fn session(&self) -> Result<OwnedObjectPath> {
        let (_, session): (OwnedValue, OwnedObjectPath) = self
            .service()
            .await?
            .call("OpenSession", &("plain", Value::from("")))
            .await
            .map_err(err)?;
        Ok(session)
    }

    pub async fn search(&self, attributes: &HashMap<String, String>) -> Result<Vec<ItemInfo>> {
        let mut unlocked = Vec::new();
        let mut still_locked = false;
        // Twice at most: if the keyring was locked again between the
        // unlock and the search, the search answers with a placeholder in
        // `locked`, which must not read as "nothing found".
        for _ in 0..2 {
            self.ensure_unlocked().await?;
            let (found, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = self
                .service()
                .await?
                .call("SearchItems", &(attributes,))
                .await
                .map_err(err)?;
            unlocked = found;
            still_locked = !locked.is_empty();
            if !still_locked {
                break;
            }
        }
        if still_locked {
            return Err("the keyring was locked again during the search; try again".into());
        }
        let mut items = Vec::new();
        for path in unlocked {
            let item = self.proxy(&path, "org.freedesktop.Secret.Item").await?;
            items.push(ItemInfo {
                label: item.get_property("Label").await.map_err(err)?,
                attributes: item.get_property("Attributes").await.map_err(err)?,
                path,
            });
        }
        Ok(items)
    }

    pub async fn secret(&self, item: &OwnedObjectPath) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let session = self.session().await?;
        let result: Result<(SecretStruct,)> = self
            .proxy(item, "org.freedesktop.Secret.Item")
            .await?
            .call("GetSecret", &(session.clone(),))
            .await
            .map_err(err);
        self.close(&session).await;
        Ok(zeroize::Zeroizing::new(result?.0.2))
    }

    /// Close a session we opened (the daemon also frees it when we exit).
    async fn close(&self, session: &OwnedObjectPath) {
        if let Ok(s) = self.proxy(session, "org.freedesktop.Secret.Session").await {
            let _ = s.call_method("Close", &()).await;
        }
    }

    /// Store in the default collection, replacing an item with the same
    /// attributes (as `secret-tool store` does).
    pub async fn store(
        &self,
        label: &str,
        attributes: &HashMap<String, String>,
        secret: &[u8],
    ) -> Result<()> {
        self.ensure_unlocked().await?;
        let session = self.session().await?;
        let mut props: HashMap<&str, Value<'_>> = HashMap::new();
        props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        props.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(attributes.clone()),
        );
        let secret = (
            session.clone(),
            Vec::<u8>::new(),
            secret.to_vec(),
            "text/plain",
        );
        let default: OwnedObjectPath = self
            .service()
            .await?
            .call("ReadAlias", &("default",))
            .await
            .map_err(err)?;
        let result: Result<(OwnedObjectPath, OwnedObjectPath)> = self
            .proxy(&default, "org.freedesktop.Secret.Collection")
            .await?
            .call("CreateItem", &(props, secret, true))
            .await
            .map_err(err);
        self.close(&session).await;
        result.map(|_| ())
    }

    pub async fn delete(&self, item: &OwnedObjectPath) -> Result<()> {
        let _: OwnedObjectPath = self
            .proxy(item, "org.freedesktop.Secret.Item")
            .await?
            .call("Delete", &())
            .await
            .map_err(err)?;
        Ok(())
    }

    /// `(label, items)` for every collection.
    pub async fn collections(&self) -> Result<Vec<(String, Vec<ItemInfo>)>> {
        self.ensure_unlocked().await?;
        let paths: Vec<OwnedObjectPath> = self
            .service()
            .await?
            .get_property("Collections")
            .await
            .map_err(err)?;
        let mut out = Vec::new();
        for path in paths {
            let c = self
                .proxy(&path, "org.freedesktop.Secret.Collection")
                .await?;
            let label: String = c.get_property("Label").await.map_err(err)?;
            let item_paths: Vec<OwnedObjectPath> = c.get_property("Items").await.map_err(err)?;
            let mut items = Vec::new();
            for p in item_paths {
                let item = self.proxy(&p, "org.freedesktop.Secret.Item").await?;
                items.push(ItemInfo {
                    label: item.get_property("Label").await.map_err(err)?,
                    attributes: item.get_property("Attributes").await.map_err(err)?,
                    path: p,
                });
            }
            out.push((label, items));
        }
        Ok(out)
    }
}
```

Write `crates/aleph-cli/src/prompter.rs`:

```rust
//! The terminal prompter (spec §6 "Prompter orchestration": the fallback
//! with no Wayland display, in the style of `systemd-ask-password`).
//!
//! The CLI keeps one end of a socketpair, hands the other to `alephd`
//! with the request, and answers the daemon's questions here. Secrets are
//! read from the terminal with echo off. With `ALEPH_NO_TTY=1` (scripts,
//! tests) each answer is one line of standard input instead.

use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::os::unix::net::UnixStream;

use aleph_prompt_proto::{FromPrompter, Method, Purpose, Secret, ToPrompter};

/// Where answers come from.
pub struct Terminal {
    /// Answers are lines of standard input (`ALEPH_NO_TTY=1`). The stdin
    /// lock is taken per line, never held: two `Terminal`s may coexist.
    scripted: bool,
}

impl Terminal {
    pub fn new() -> Self {
        let scripted = std::env::var_os("ALEPH_NO_TTY").is_some_and(|v| v == "1");
        Self { scripted }
    }

    pub fn line(&mut self, prompt: &str) -> std::io::Result<String> {
        eprint!("{prompt}");
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            // No more input: the caller cancels rather than answers.
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if self.scripted {
            eprintln!();
        }
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }

    fn secret(&mut self, prompt: &str) -> std::io::Result<Secret> {
        let secret = if self.scripted {
            self.line(prompt)?
        } else {
            rpassword::prompt_password(prompt)?
        };
        // Nothing typed (or Ctrl-D): no password or PIN is empty; cancel.
        if secret.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        Ok(Secret::new(secret))
    }

    fn yes(&mut self, question: &str) -> std::io::Result<bool> {
        let answer = self.line(&format!("{question} [y/N] "))?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
    }
}

/// What the conversation ended with.
pub struct Outcome {
    pub ok: bool,
    pub message: Option<String>,
}

fn send(stream: &mut UnixStream, reply: &FromPrompter) -> std::io::Result<()> {
    // Zeroizing: a reply may carry a password, PIN, or recovery groups.
    let mut line =
        zeroize::Zeroizing::new(serde_json::to_vec(reply).map_err(std::io::Error::other)?);
    line.push(b'\n');
    stream.write_all(&line)
}

/// Answer the daemon on `stream` until it says `Done`.
pub fn converse(stream: UnixStream, term: &mut Terminal) -> std::io::Result<Outcome> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let interactive = !term.scripted && std::io::stdin().is_terminal();
    // Zeroizing: a message may carry the recovery key.
    let mut line = zeroize::Zeroizing::new(String::new());
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(std::io::Error::other("alephd closed the conversation"));
        }
        let msg: ToPrompter = serde_json::from_str(&line).map_err(std::io::Error::other)?;
        if let ToPrompter::Done { ok, message } = msg {
            return Ok(Outcome { ok, message });
        }
        let reply = match answer(msg, term, interactive) {
            Ok(reply) => reply,
            // No more input (end of file, Ctrl-D): cancel, never answer.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                Some(FromPrompter::Cancel {})
            }
            Err(e) => return Err(e),
        };
        if let Some(r) = reply {
            send(&mut writer, &r)?;
        }
    }
}

/// The reply (if any) to one message.
fn answer(
    msg: ToPrompter,
    term: &mut Terminal,
    interactive: bool,
) -> std::io::Result<Option<FromPrompter>> {
    Ok(match msg {
        ToPrompter::Begin {
            purpose, operation, ..
        } => {
            let why = match purpose {
                Purpose::Unlock => "",
                Purpose::Reauth => " (confirm it is you)",
                Purpose::Create => "",
            };
            eprintln!("aleph: {operation}{why}");
            None
        }
        ToPrompter::Ask {
            methods,
            error,
            retry_after,
        } => {
            if let Some(e) = error {
                match retry_after {
                    Some(s) if !e.contains("retry in") => eprintln!("aleph: {e} (retry in {s} s)"),
                    _ => eprintln!("aleph: {e}"),
                }
            }
            let method = if methods.len() > 1 {
                let pick = term.line("Use your login [p]assword or a security [k]ey? ")?;
                if pick.trim().starts_with('k') {
                    Method::Fido2
                } else {
                    Method::Password
                }
            } else {
                methods.first().copied().unwrap_or(Method::Password)
            };
            Some(match method {
                Method::Password => FromPrompter::Password {
                    password: term.secret("Login password: ")?,
                },
                Method::Fido2 => FromPrompter::Fido2 {},
            })
        }
        ToPrompter::Fido2Pin { key, error } => {
            if let Some(e) = error {
                eprintln!("aleph: {e}");
            }
            Some(FromPrompter::Pin {
                pin: term.secret(&format!("PIN for {key}: "))?,
            })
        }
        ToPrompter::InsertKey { key } => {
            // (The terminal cannot skip one key while waiting; Ctrl-C ends the
            // whole operation. The GUI prompter offers "skip".)
            eprintln!("aleph: insert {key} (Ctrl-C cancels the whole operation)");
            None
        }
        ToPrompter::Touch { key } => {
            eprintln!("aleph: touch {key}");
            None
        }
        ToPrompter::Confirm { text } => Some(FromPrompter::Confirm {
            yes: term.yes(&text)?,
        }),
        ToPrompter::ShowRecoveryKey { key, check, error } => {
            if let Some(e) = error {
                eprintln!("aleph: {e}");
            }
            eprintln!("\nYour recovery key. Write it down and keep it somewhere safe;");
            eprintln!("it is shown only this once, and it is the only way back in");
            eprintln!("if every other unlock method is lost:\n");
            eprintln!("    {}\n", key.expose());
            if interactive {
                let _ = term.line("Press Enter once you have written it down. ")?;
                // Clear the screen so the key does not linger in scrollback.
                eprint!("\x1b[2J\x1b[3J\x1b[H");
            }
            let a = term.line(&format!("Type group {} of your recovery key: ", check[0]))?;
            let b = term.line(&format!("Type group {} of your recovery key: ", check[1]))?;
            Some(FromPrompter::RecoveryCheck {
                groups: [Secret::new(a), Secret::new(b)],
            })
        }
        ToPrompter::Done { .. } => None,
    })
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 8 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **CLI prompter never holds the stdin lock** (`crates/aleph-cli/src/prompter.rs`), test `cargo test -p aleph-cli --test cli setup_creates`: replace `Self { scripted }` with `{ std::mem::forget(std::io::stdin().lock()); Self { scripted } }`.
- **end of input cancels** (`crates/aleph-cli/src/prompter.rs`), test `cargo test -p aleph-cli --test cli end_of_input_cancels`:

  replace

  ```rust
  Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
      Some(FromPrompter::Cancel {})
  }
  ```

  with

  ```rust
  // (nothing)
  ```


- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-cli
git commit -m "feat(cli): the aleph command-line client" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 8: spec, docs

**Interfaces:**
- Consumes: everything above (documentation only).

- [ ] **Step 1: Update the documents**

Apply this patch with `git apply` (save it as `/tmp/t8-docs.patch`):

~~~~diff
--- a/docs/superpowers/specs/2026-09-26-aleph-design.md
+++ b/docs/superpowers/specs/2026-09-26-aleph-design.md
@@ -135,9 +135,10 @@
 | `aleph-tpm-proto` | lib | The `aleph-tpmd` wire protocol: request/response types and framing. | `serde`, `ciborium` |
 | `aleph-tpmd` | bin | TPM helper: seal and unseal per uid, SRK verification, rate limiting, `Status`. | `aleph-tpm-proto`, `tss-esapi` |
 | `aleph-unlock` | lib | Produces a KEK per hardware keyslot: the TPM client (talks to `aleph-tpmd`) and FIDO2 (`Authenticator` trait, `libfido2` backend, mock). | `aleph-core`, `aleph-tpm-proto`, `fido2-rs` |
-| `alephd` | bin | Secret Service and admin D-Bus interfaces, PAM socket, lock policy, prompter orchestration. | `aleph-core`, `aleph-unlock`, `zbus`, `tokio`, `tracing`, `tracing-journald` |
+| `aleph-prompt-proto` | lib | The prompter protocol (newline-delimited JSON) shared by `alephd`, the CLI's terminal prompter, and `aleph-gui`. | `serde`, `zeroize` |
+| `aleph-daemon` (bin `alephd`) | bin | Secret Service and admin D-Bus interfaces, PAM socket, lock policy, prompter orchestration. | `aleph-core`, `aleph-unlock`, `aleph-prompt-proto`, `zbus`, `tokio`, `tracing`, `tracing-journald`, libpam |
 | `pam_aleph` | cdylib | PAM module: forwards passwords to `alephd` after dropping to the user's uid. Minimal, no async runtime. | PAM FFI, std |
-| `aleph` | bin | CLI. | `zbus`, `clap` |
+| `aleph-cli` (bin `aleph`) | bin | CLI. | `aleph-prompt-proto`, `zbus`, `clap` |
 | `aleph-gui` | bin | egui manager and prompter. | `eframe`, `egui`, `zbus`, `notify`, Wayland clipboard crate |
 
 **Seam for privilege separation:** only `KeyHandle` touches MK. Callers
@@ -299,7 +300,8 @@
 - **on `aleph keyslot rotate-master`**
 
 Re-wrapping needs a KEK for every slot. The daemon never keeps
-passwords, so the KEKs come from these sources:
+passwords, so the KEKs come from these sources (each is checked to
+unwrap MK before it counts):
 
 - **The recovery slot:** re-wrapped to its public key, with no secret
   needed.
@@ -310,8 +312,15 @@
 - **Each FIDO2 slot:** needs that key's touch. The prompter walks through
   them in turn.
 
-A slot that cannot be presented is removed, after the user confirms. A
-rotation never leaves a slot wrapping the old MK.
+A slot that cannot be presented is removed, after the user confirms: a
+FIDO2 key that is not presented, a TPM or login-password slot that
+rejects the password, or a stale TPM slot (which is not tried again). A
+TPM refusal that says nothing about the slot (`Busy`, `RateLimited`,
+`Exhausted`, helper unavailable) stops the rotation instead. TPM slots
+are only ever offered a password PAM accepted, newest slot first. A
+rotation never leaves a slot wrapping the old MK, and never leaves only
+the recovery slot. Reissuing the recovery key does everything that can
+fail before it shows the new key.
 
 ### Body
 
@@ -334,17 +343,45 @@
 results would make some clients (Chromium's safe-storage key is the
 classic case) create a new key that orphans their existing data.
 
-- `SearchItems`, `GetSecrets`, `Item.GetSecret`, and every other read that
-  needs the body return `org.freedesktop.Secret.Error.IsLocked` while the
-  vault is locked. Clients then call `Unlock()`, which goes through the
-  normal `Prompt` flow with no reply timeout.
-- No method call ever blocks waiting for the user.
-- Plan 3 must verify this against real clients before it is final:
-  libsecret's `secret_password_lookup` with and without
-  `SECRET_SEARCH_UNLOCK`, Chromium's safe-storage lookup, and
-  NetworkManager. If a client treats `IsLocked` as "not found", the
-  fallback is an unlock-triggering placeholder in the `locked` list, and
-  that choice is recorded in §11.
+- **While locked, a search returns a placeholder.** `SearchItems` puts
+  one placeholder item (`/org/freedesktop/secrets/search/<n>`, always
+  `Locked`) in its `locked` list, and `Collection.SearchItems` returns it.
+  libsecret then calls `Unlock()` on it, and the prompt's result lists the
+  items the search really finds once the vault is open. The first design,
+  answering `IsLocked`, was tested against libsecret 0.21.7 in Plan 3:
+  `secret-tool lookup` reported an error and never unlocked, which a
+  client like Chromium could treat as "no key".
+- `GetSecrets`, `Item.GetSecret`, and every other read of the body return
+  `org.freedesktop.Secret.Error.IsLocked` while the vault is locked.
+- While locked, only the `default` alias exists, as a locked collection
+  (collection names are encrypted too). `ReadAlias("default")` returns
+  it; libsecret stores to it after unlocking it. Item and collection
+  objects exist only while unlocked: a client holding an item path across
+  a lock gets `UnknownObject`, and searches again.
+- A placeholder's query is captured when `Unlock` is called, so the
+  answer survives the placeholder being cleared. A `Lock` while already
+  locked changes nothing (it does not close waiting clients' sessions).
+- No method call ever blocks waiting for the user. `Unlock()` returns a
+  prompt with no reply timeout. If no prompter can start (no graphical
+  session), the prompt is not dismissed: it waits until the vault is
+  unlocked some other way (`aleph unlock`, PAM), then completes. At
+  most 8 prompts per client, and 128 in all, may wait; a prompt starts
+  once; while one unlock conversation runs, other unlock prompts wait for
+  it instead of opening more prompter windows.
+- **Sessions outlive locks.** A session holds only its transport key, and
+  nothing is readable through it while locked; libsecret keeps one session
+  for the life of each process, so closing sessions at lock would break
+  every long-lived client at each screen lock. A session is freed on
+  `Close`, when its client disconnects, or at exit; a client may hold 32.
+  A client's prompts are freed when it disconnects too.
+- A dismissed prompt carries an empty value of the type a completed one
+  would (`ao` for an unlock). libsecret checks the type even on
+  dismissal, and hangs on a mismatch.
+- Verified with `secret-tool` on a private bus (Plan 3 tests): store,
+  lookup, search, and clear; a locked lookup prompts once and returns the
+  secret; with no prompter it waits for an unlock elsewhere; cancelling
+  ends it without a secret. Chromium's safe-storage lookup and
+  NetworkManager are on the manual checklist (`docs/testing.md`).
 
 ### Memory hygiene
 
@@ -358,9 +395,13 @@
   use, and decoded without intermediate copies. Plaintext secrets
   (`SecretBytes`) are zeroized on drop.
 - Children are started only via `posix_spawn`/`exec`
-  (`std::process::Command`), never a bare `fork`.
-- Locking zeroizes MK, derived keys, and the decrypted body, and closes all
-  Secret Service sessions.
+  (`std::process::Command`), never a bare `fork`. One exception is outside
+  aleph's code: checking a typed password, libpam's `pam_unix` forks and
+  execs `unix_chkpwd`. MK's page is `MADV_WIPEONFORK`, so the child never
+  sees it; the decrypted body is shared copy-on-write until the exec.
+- Locking zeroizes MK, derived keys, and the decrypted body. Secret
+  Service sessions stay open (§4 "Locked search"): they hold only
+  transport keys.
 
 What is not guaranteed: labels and attributes are ordinary strings and are
 not zeroized. zbus, libsecret, and the GUI make their own copies of
@@ -448,6 +489,21 @@
     (at least 60 s), then `RateLimited`. One uid guessing without pause
     thus adds failures no faster than the TPM forgets them; it takes
     several uids to hold the reserve at its limit.
+  - **A typed password is checked with PAM first.** Before a password
+    typed into a prompt reaches the TPM, `alephd` checks it with the PAM
+    service `aleph-check` (`pam_unix` only, no faillock), so a typo never
+    spends the TPM's budget: on a TPM with a 7200 s recovery time, two
+    typos would otherwise block TPM unlock for hours. At most 5 wrong
+    typed passwords are accepted per minute. If PAM cannot check at all
+    (no `/etc/pam.d/aleph-check`, or an account `pam_unix` cannot verify),
+    the TPM slots are skipped rather than risked, while login-password
+    slots are still tried; TPM slots therefore need `pam_unix` accounts.
+    Passwords from `pam_aleph` were accepted by the login stack and skip
+    the check.
+  - **TPM slots are tried newest first.** Once one rejects a password PAM
+    accepted, it and every older TPM slot are marked stale without being
+    tried, so a changed password costs one failed attempt, not one per
+    slot.
   - After an `AuthFailed` or `WrongUser` failure, the daemon marks the
     slot `stale` and stops trying it automatically until the user
     re-enrolls it or explicitly retries it, so an outdated password does
@@ -642,17 +698,29 @@
 
 ### Admin interface `io.aleph.Admin1`
 
-- On the session bus only.
-- Methods: `Status`, `Lock`, `Unlock`, `ListKeyslots`, `EnrollTpm`,
-  `EnrollFido2`, `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`,
-  `GetConfig`, `SetConfig`, `ImportGnomeKeyring`, `ExportToGnomeKeyring`,
-  `Backup`, `Restore`.
+- On the session bus only: bus name `io.aleph.Keyring`, object
+  `/io/aleph/Admin`.
+- Methods: `Status` (JSON: vault present, locked, untrusted reason,
+  whether MK is `mlock`ed, TPM usability, keyslots with stale marks),
+  `Lock`, `Unlock`, `Create`, `EnrollTpm`, `EnrollFido2`,
+  `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`, `RetryKeyslot`,
+  `GetConfig`, `SetConfig`, and (Plan 4) `ImportGnomeKeyring`,
+  `ExportToGnomeKeyring`, `Backup`, `Restore`.
+- **Methods that need the user take a prompter:** one end of a
+  socketpair, passed as a Unix fd, speaking the prompter protocol. The
+  CLI answers it in the terminal, `aleph-gui` in its windows. The call
+  returns once the request is accepted; the outcome arrives on the
+  prompter as `Done`, so no call waits for the user or runs into a bus
+  reply timeout.
+- A keyslot change that would leave only the recovery slot is refused:
+  routine unlock would then be impossible.
 - **Fresh re-authentication through the prompter** is required for every
   method that changes keyslots, configuration, or data custody:
   `Enroll*`, `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`,
   `SetConfig`, `Backup`, `Restore`, and `Export*`. Re-authentication means
   proving an enrolled method: a FIDO2 touch, or the login password
-  checked through a TPM unseal.
+  (checked with PAM, then through a TPM unseal or the login-password
+  slot).
 - **"Reveal" in the GUI** also re-authenticates. That is a UX guard, not
   security, because any same-user process can call `GetSecrets`. This is
   documented.
@@ -680,16 +748,23 @@
 
 ### Prompter orchestration
 
-- `alephd` spawns `aleph-gui prompt` with one end of a socketpair and
-  exchanges newline-delimited JSON messages.
+- For Secret Service prompts, `alephd` spawns `<prompt.program> prompt`
+  (default `aleph-gui`) with one end of a socketpair as `ALEPH_PROMPT_FD`
+  and exchanges newline-delimited JSON messages (`aleph-prompt-proto`).
+  Admin methods use the caller's own prompter instead (above).
 - **What the prompt shows:** the requesting operation and, where
   available, the calling process's name and pid, from D-Bus
   `GetConnectionUnixProcessID`. This is advisory, since it can be spoofed.
-- **Where the prompt runs:** it runs only as a child of `alephd`. A window
-  claiming `aleph-prompt` that `alephd` did not spawn gets nothing, because
-  secrets only ever travel over the socketpair.
-- With no Wayland display, it falls back to a terminal prompt via
-  `aleph unlock`, in the style of `systemd-ask-password`.
+- **Where the prompt runs:** a Secret Service prompt runs only as a
+  child of `alephd`. A window claiming `aleph-prompt` that `alephd` did
+  not spawn gets nothing, because secrets only ever travel over a
+  socketpair, never in D-Bus message bodies.
+- With no Wayland display, Secret Service prompts wait (§4), and
+  `aleph unlock` unlocks in the terminal, in the style of
+  `systemd-ask-password`. With `ALEPH_NO_TTY=1` its answers are lines of
+  standard input (scripts, tests).
+- The prompter settings are `prompt.program` and `prompt.timeout`
+  (seconds before an unanswered prompt ends) in `config.toml`.
 
 ### Logging
 
@@ -709,6 +784,7 @@
 aleph keyslot add fido2 [--touch-only]
 aleph keyslot remove <slot-id>             # rotates MK
 aleph keyslot rotate-master
+aleph keyslot retry <slot-id>              # try a stale slot again
 aleph recovery reissue                     # new recovery key; old one stops working
 aleph get attr=val…                        # secret-tool compatible semantics
 aleph search attr=val…
@@ -723,7 +799,8 @@
 ```
 
 - Global flags: `--json`. Shell completions are generated for bash, zsh,
-  and fish.
+  and fish (`aleph completions <shell>`). Keyslot ids may be given as a
+  unique prefix, as `aleph status` shows them.
 - **`aleph setup`** is an interactive wizard:
   1. TPM status (§5)
   2. unlock method: TPM + login password (the default when a TPM is
@@ -732,6 +809,9 @@
   4. the recovery key, shown once and confirmed
   5. live import from gnome-keyring
   6. system changes (sudo)
+
+  Plan 3 implements steps 1, 2, and 4 (creating the vault) and says that
+  the rest is not available yet; Plan 4 adds 3, 5, and 6.
 - **Import** reads every collection and item through the Secret Service
   API while gnome-keyring still owns the bus name. That covers everything
   shown in Seahorse's Passwords view.
@@ -910,15 +990,19 @@
   `draft-connolly-cfrg-xwing-kem-06`. Plan 1b either adopts it, if it
   matches the published test vectors, or implements the combiner directly
   over `ml-kem` and `x25519-dalek`, pinned by those known-answer tests.
-- **`oo7`/`oo7-daemon`:** check its maturity before Plan 3. It could host
-  the Secret Service server instead of writing one from scratch.
+
 - **Persistent SRK:** check how common `0x81000001` is on Omarchy installs
   where `systemd-cryptenroll --tpm2` has been used (systemd creates it),
   and how often `ownerAuth` is set. Together these decide how often the
   AES-128 fallback is used.
-- **Locked search:** verify how clients react to `IsLocked` (§4) before
-  Plan 3 fixes the behaviour.
 
 **Resolved:**
 - FIDO2 bindings: `fido2-rs` (Plan 2).
 - The Omarchy PAM stack: §6, verified on 2026-09-26.
+- Locked search (Plan 3): a placeholder in the `locked` list, prompts that
+  wait for an unlock, typed empty results on dismissal (§4), verified
+  against libsecret 0.21.7.
+- `oo7-daemon` (Plan 3): not adopted. The server is written directly on
+  `zbus`, because aleph's locked behaviour (encrypted names and
+  attributes, placeholder searches, waiting prompts) needs control over
+  search and prompts. `oo7-daemon` was not evaluated in depth.
--- a/docs/testing.md
+++ b/docs/testing.md
@@ -16,12 +16,26 @@
 - **`tpm2-tools`**: the fixture uses `tpm2_dictionarylockout` to give
   swtpm realistic dictionary-attack parameters (tss-esapi 7.7 lacks
   `TPM2_DictionaryAttackParameters`).
-- **`tpm2-tss`** and **`libfido2`**: build-time libraries.
-- Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2`.
-  Nix: `swtpm tpm2-tools tpm2-tss libfido2`.
+- **`tpm2-tss`**, **`libfido2`**, and **`pam`**: build-time libraries.
+- **`dbus`** (`dbus-daemon`) and **`libsecret`** (`secret-tool`): the
+  daemon and CLI tests run `alephd`'s interfaces on a private session bus
+  and drive them with the real libsecret client and the real `aleph`
+  binary. They never touch your session bus or keyring.
+- PAM is exercised for real through a private service directory
+  (`pam_start_confdir`, Linux-PAM 1.4+): `pam_unix` rejecting a wrong
+  password, and the shipped `packaging/pam/aleph-check`. Nothing is
+  installed and no root is needed.
+- Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.
+  Nix: `swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.
 
 FIDO2 logic is tested against `aleph_unlock::fido2::mock::MockKeys`; no
-test in the default run needs a security key.
+test in the default run needs a security key. Prompts are answered by
+scripted prompters (`aleph_daemon::testing`), and the CLI reads its answers
+from standard input under `ALEPH_NO_TTY=1`.
+
+`alephd`'s user unit is checked with
+`systemd-analyze verify --user packaging/systemd/alephd.service` (same
+`ExecStart` caveat as below).
 
 The systemd units in `packaging/systemd/` are checked with:
 
@@ -84,3 +98,32 @@
    `aleph status`.)
 4. Undo: `systemctl disable --now aleph-tpmd.socket aleph-tpmd.service`
    and remove the installed files.
+
+### alephd with real clients
+
+Needs a vault on a test account (or a spare user), since it takes over
+the Secret Service for the session. As root, install the PAM service
+once: `install -Dm644 packaging/pam/aleph-check /etc/pam.d/aleph-check`.
+Then, with gnome-keyring stopped (`systemctl --user stop
+gnome-keyring-daemon.service gnome-keyring-daemon.socket`):
+
+1. Run `target/debug/alephd` in one terminal and `target/debug/aleph setup`
+   in another; choose the TPM (or a key) and confirm the recovery key.
+2. `secret-tool store --label=t service aleph-check` (type a secret), then
+   `secret-tool lookup service aleph-check` prints it.
+3. `aleph lock`, then `secret-tool lookup service aleph-check`: it waits
+   (no graphical prompter yet). In the other terminal, `aleph unlock`: the
+   lookup then prints the secret.
+4. **Chromium:** start it with `--password-store=gnome-libsecret`, save a
+   site password, quit, `aleph lock`, start Chromium again, and
+   `aleph unlock` when it waits. Saved passwords must still be there
+   (Chromium did not create a new safe-storage key).
+5. **NetworkManager:** with `nmcli` and a Wi-Fi network whose password is
+   stored for the user ("Store the password only for this user"), lock,
+   reconnect, and unlock when asked: the connection must come up without
+   asking for the Wi-Fi password again.
+6. `aleph status` shows the keyslots; `journalctl --user` (or the
+   terminal) shows no secrets.
+
+Record the results, and the libsecret, Chromium, and NetworkManager
+versions, in `hardware-log.md`.
--- a/README.md
+++ b/README.md
@@ -20,11 +20,15 @@
 | `aleph-tpm-proto` | Wire protocol between `alephd` and the TPM helper |
 | `aleph-tpmd` | The TPM helper service (the only process that talks to the TPM) |
 | `aleph-unlock` | TPM client and FIDO2 unlock methods that produce keyslot KEKs |
+| `aleph-prompt-proto` | Protocol between `alephd` and its prompters (GUI or terminal) |
+| `aleph-daemon` | `alephd`: the Secret Service and the `io.aleph.Admin1` interface |
+| `aleph-cli` | `aleph`: the command-line client |
 
 ## Development
 
-Tests need `swtpm`, `tpm2-tools`, `tpm2-tss` and `libfido2` (Arch:
-`pacman -S swtpm tpm2-tools tpm2-tss libfido2`). Hardware tests are opt-in;
+Tests need `swtpm`, `tpm2-tools`, `tpm2-tss`, `libfido2`, `pam`, `dbus`
+and `libsecret` (Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam
+dbus libsecret`). Hardware tests are opt-in;
 see [docs/testing.md](docs/testing.md).
 
 ~~~sh
~~~~

- [ ] **Step 2: Run the tests, clippy, and fmt**

Run: `cargo test -q && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 8 passed | ok. 59 passed | ok. 1 passed | ok. 27 passed | ok. 10 passed | ok. 1 passed | ok. 20 passed | ok. 3 passed | ok. 24 passed | ok. 2 passed | ok. 12 passed | ok. 1 passed | ok. 6 passed | ok. 5 passed | ok. 21 passed | ok. 5 passed | ok. 1 passed | ok. 23 passed | ok. 8 passed.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-09-26-aleph-design.md docs/testing.md README.md
git commit -m "docs: spec, testing, and README for alephd and the CLI" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
