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
