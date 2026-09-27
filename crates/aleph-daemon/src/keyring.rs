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
            return Err(Error::NoMethodWorked(Some(crate::error::ALL_STALE.into())));
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
                // Waiting is not something to retry at once, and a key's
                // PIN budget for this conversation is spent (each wrong
                // PIN costs one of the key's lifetime retries).
                Err(
                    e @ (Error::Cancelled
                    | Error::Prompt(_)
                    | Error::TooManyAttempts { .. }
                    | Error::Unlock(aleph_unlock::Error::Fido2PinInvalid)),
                ) => {
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
                Err(
                    e @ (Error::Cancelled
                    | Error::Prompt(_)
                    | Error::TooManyAttempts { .. }
                    | Error::Unlock(aleph_unlock::Error::Fido2PinInvalid)),
                ) => {
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
