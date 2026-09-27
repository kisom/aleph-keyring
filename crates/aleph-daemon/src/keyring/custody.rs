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
                    // (A binding: a guard in a `match` scrutinee lives
                    // through the arms, and the fallback locks again.)
                    let read = lock(&self.inner).store.read();
                    match read {
                        Ok(file) => file,
                        Err(_) => lock(&self.inner).store.read_bak()?,
                    }
                }
            };
            let (expected, recorded) = {
                let inner = lock(&self.inner);
                (
                    inner.store.expected_vault_id(),
                    inner.store.recorded(source.vault_id())?,
                )
            };
            // A backup replaces whatever is here: proof first (E7).
            if backup.is_some() {
                self.prove_local(chan, local.as_ref().ok())?;
                self.confirm_older_backup(chan, &source, local.as_ref().ok(), recorded)?;
            }
            let recovery = source
                .keyslots()
                .find(|k| matches!(k.kind, SlotKind::Recovery(_)))
                .map(|k| k.id)
                .ok_or_else(|| Error::Invalid("this vault has no recovery slot".into()))?;
            let mut vault = self.open_with_recovery_key(chan, &source, recovery)?;
            // Recovering the vault this machine expects, as it last recorded
            // it, needs only its recovery key. Anything else (another vault,
            // or an older copy of this one, whose old recovery key may be
            // all an attacker has) needs proof too (E7).
            if backup.is_none() && !is_current(expected, recorded, &vault) {
                self.prove_local(chan, local.as_ref().ok())?;
            }
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
            // The keyring is restored whatever happens to the offer.
            let (reissued, note) = match self.offer_new_recovery_key(chan, slot, &kek) {
                Ok(reissued) => (reissued, ""),
                Err(e) => {
                    tracing::info!("new recovery key not installed: {e}");
                    (
                        false,
                        " The new recovery key was not installed; the old one still works (`aleph recovery reissue` issues a new one).",
                    )
                }
            };
            Ok(Some(
                done_message("The keyring is restored", &kept, reissued) + note,
            ))
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
            let recorded = match lock(&self.inner).store.recorded(bak.vault_id())? {
                Some(r) => format!("; this machine last recorded generation {}", r.generation),
                None => String::new(),
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
                text: format!("{what}{recorded}. Continue?"),
                default: false,
            })?;
            if reply != (FromPrompter::Confirm { yes: true }) {
                return Err(Error::Cancelled);
            }
            let Opened { vault, .. } = self.choose_and_open(chan, &bak)?;
            // A backup copy that is not the vault this machine expects, under
            // the master key it recorded and at most one write behind, proves
            // nothing with its own methods (a planted one, an old one, or one
            // forged with this vault's id): E7.
            let (expected, recorded) = {
                let inner = lock(&self.inner);
                (
                    inner.store.expected_vault_id(),
                    inner.store.recorded(vault.vault_id())?,
                )
            };
            if expected != Some(vault.vault_id())
                || !recorded.is_some_and(|r| {
                    r.mk_id == vault.mark().mk_id && vault.mark().generation + 1 >= r.generation
                })
            {
                self.ask_password(chan)?;
            }
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
            // An untrusted vault is never the one this machine expects: its
            // own methods (an older copy may hold a since-removed key) prove
            // nothing alone. The login password too.
            self.ask_password(chan)?;
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
            let mut m = format!(
                "Backup written: vault {}, generation {}. It holds only the recovery slot: it opens with your recovery key and nothing else.",
                mark.vault_id, mark.generation
            );
            if let Some(why) = lock(&self.inner).untrusted {
                m.push_str(&format!(
                    " Note: this vault file is not trusted (it was {why}); the backup holds it as it is."
                ));
            }
            Ok(Some(m))
        })
    }

    /// Whether the unlocked vault is the one this machine expects.
    fn open_vault_is_expected(&self) -> bool {
        let inner = lock(&self.inner);
        let expected = inner.store.expected_vault_id();
        expected.is_some() && inner.vault.as_ref().map(|v| v.vault_id()) == expected
    }

    /// Prove the right to replace what is at the path (E7). The method of
    /// the vault this machine expects, as it last recorded it, proves it:
    /// re-authentication while it is unlocked and trusted, or opening
    /// `file` if that is it (same master key as recorded, not behind the
    /// mark). Anything else needs the login password, checked with PAM: no
    /// file where a vault was expected, an unreadable or different one, a
    /// file where none was recorded, an older copy, one forged with this
    /// vault's id, or one whose contents fail authentication. A vault's own
    /// methods prove nothing unless it is the recorded one. Only a machine
    /// that has never had a vault (no files, no records, none seen since
    /// the daemon started) has nothing to prove.
    fn prove_local(&self, chan: &mut Channel, file: Option<&LockedVault>) -> Result<()> {
        let (expected, history, trusted) = {
            let inner = lock(&self.inner);
            (
                inner.store.expected_vault_id(),
                inner.store.has_history(),
                inner.untrusted.is_none(),
            )
        };
        let fresh = !history && !self.seen_vault.load(std::sync::atomic::Ordering::SeqCst);
        if !self.is_locked() {
            if self.open_vault_is_expected() && trusted {
                return self
                    .reauth(chan, "Replace the keyring with a backup")
                    .map(|_| ());
            }
            return self.ask_password(chan).map(|_| ());
        }
        match (file, expected) {
            (Some(f), Some(id)) if f.vault_id() == id => {
                let recorded = lock(&self.inner).store.recorded(id)?;
                match self.choose_and_open(chan, f) {
                    Ok(opened) if is_current(expected, recorded, &opened.vault) => Ok(()),
                    Ok(_)
                    | Err(Error::Core(
                        aleph_core::Error::HeaderTampered | aleph_core::Error::BodyTampered,
                    )) => self.ask_password(chan).map(|_| ()),
                    Err(e) => Err(e),
                }
            }
            (None, None) if fresh => Ok(()),
            _ => self.ask_password(chan).map(|_| ()),
        }
    }

    /// Before an older backup of this vault replaces a newer one (the file
    /// here, or the generation recorded for it, even with the file gone):
    /// say what is lost, and name a newer `.bak`. Enter says no.
    fn confirm_older_backup(
        &self,
        chan: &mut Channel,
        source: &LockedVault,
        local: Option<&LockedVault>,
        recorded: Option<aleph_core::Mark>,
    ) -> Result<()> {
        let id = source.vault_id();
        let backup = source.mark().generation;
        let newest = local
            .filter(|l| l.vault_id() == id)
            .map(|l| l.mark().generation)
            .into_iter()
            .chain(recorded.map(|r| r.generation))
            .max();
        let Some(newest) = newest.filter(|&n| backup < n) else {
            return Ok(());
        };
        let bak = match lock(&self.inner).store.read_bak() {
            Ok(b) if b.vault_id() == id && b.mark().generation > backup => format!(
                " vault.aleph.bak is generation {} and may be the better choice (`aleph restore --from-bak`).",
                b.mark().generation
            ),
            _ => String::new(),
        };
        let reply = chan.ask(&ToPrompter::Confirm {
            text: format!(
                "This backup is generation {backup} of this keyring, and this machine has seen generation {newest}: anything written since the backup is not in it (the current file is kept).{bak} Restore it?"
            ),
            default: false,
        })?;
        if reply != (FromPrompter::Confirm { yes: true }) {
            return Err(Error::Cancelled);
        }
        Ok(())
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
        self.seen_vault
            .store(true, std::sync::atomic::Ordering::SeqCst);
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

/// Whether `vault` (opened, so authenticated) is the vault this machine
/// expects, under the master key it recorded, and not behind the mark.
fn is_current(
    expected: Option<Uuid>,
    recorded: Option<aleph_core::Mark>,
    vault: &UnlockedVault,
) -> bool {
    let m = vault.mark();
    expected == Some(m.vault_id)
        && recorded.is_some_and(|r| r.mk_id == m.mk_id && m.generation >= r.generation)
}
