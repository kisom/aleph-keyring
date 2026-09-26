# aleph-core revision 2 Implementation Plan (Plan 1b)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `aleph-core` in line with spec revision 2:
- the recovery slot becomes an X-Wing public-key recipient
- removing a slot rotates MK
- the header gains `generation` and `mk_id`, backed by a high-water mark
- unknown slot types are preserved
- Argon2 floors are enforced at enrollment
- the cut slot types (passphrase, `auth=none`/PIN/PCR TPM) are removed

**Architecture:**
- **Recovery:** the recovery key seeds an X-Wing key pair (`HKDF(recovery key, "aleph recovery xwing seed v1")`). The slot stores the public key and an encapsulation, and MK is wrapped under `HKDF(shared secret, "aleph recovery v1")`. Re-wrapping needs only the public key, so `rotate_master` never needs the paper key.
- **Slot storage:** each keyslot is stored in the header as its own CBOR byte string. Known types parse strictly (`deny_unknown_fields`). Unknown types are kept as their exact bytes and re-emitted unchanged.
- **Generations:** every serialization is a new generation. A `HighWater` store outside the vault detects rollback and replacement.

**Tech Stack:** Rust 1.98; adds `x-wing` `=0.1.0` (RustCrypto, Apache-2.0 OR MIT: ML-KEM-768 + X25519) and `hybrid-array` 0.4 (to pass secrets to it without copies); dev: `hex`, `serde_json`.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` revision 2 (§4 Layout, Generation and high-water mark, Master key and keyslots, Rotation and revocation; §5 Recovery key; §9 aleph-core tests).

**Plan series (revised):** 1 core (done) → **1b core revision 2 (this plan)** → 2 `aleph-tpmd` + `aleph-unlock` (rewrite) → 3 `alephd` + CLI basics → 4 session integration (PAM, lock policy, setup/revert, import/export, backup/restore) → 5 `aleph-gui` → 6 packaging and CI.

## Decisions made while prototyping

Every task was prototyped, then replayed from this document on a fresh clone of `master` (`179f1d2`): red, then green, then clippy and fmt clean.

- **X-Wing via the `x-wing` crate.** This resolves the spec §11 open item. The crate's bundled test vectors are byte-identical to the draft authors' published vectors (`github.com/dconnolly/draft-connolly-cfrg-xwing-kem`, `spec/test-vectors.json`, compared on 2026-09-26). aleph copies those vectors into `tests/data/` and checks keygen, deterministic encapsulation, and decapsulation against them in its own tests. Randomness for real encapsulations comes from the OS CSPRNG via `encapsulate_deterministic` with 64 fresh random bytes, which avoids a second `rand_core` version.
- **Header keyslots are a list of byte strings, each holding one slot's CBOR.** This is what makes byte-for-byte preservation of unknown slots possible. Task 4 updates the spec §4 wording ("each element is one keyslot" becomes "each element is a byte string holding one keyslot's CBOR").
- **`LockedVault::keyslots()` / `UnlockedVault::keyslots()` now return iterators over known slots.** `unknown_keyslots()` lists the rest.
- **`add_keyslot` accepts only TPM and FIDO2 kinds.** Recovery and login-password slots have dedicated constructors that derive their own KEKs.
- **Only the login-password slot uses Argon2.** `RECOVERY_KEY` and `PASSPHRASE_FLOOR` are removed. The KAT moves to `LOGIN_PASSWORD_FLOOR`, verified with the reference C implementation (`printf "aleph known answer" | argon2 BBBBBBBBBBBBBBBB -id -t 2 -m 16 -p 4 -l 32 -r` → `70f16ec9…0cbb`). `INSECURE_TEST` exists only under `cfg(test)` or the `insecure-test-params` feature. The crate's integration tests enable that feature through a self dev-dependency, and it also gates a hidden `vault::testing` hook.
- **Test speed:** X-Wing and CBOR parsing are slow unoptimized, so the workspace builds `ml-kem`, `x25519-dalek`, `sha3`, `ciborium`, and a few others at `opt-level = 3` in dev and test profiles (alongside the existing Argon2/AEAD overrides). The round-trip proptest runs 64 cases. The exhaustive bit-flip test (about 25k flips over a 3 KB file) unlocks through a raw-KEK slot, so it needs no Argon2.
- **Changes from the plan review** (`docs/reviews`-style review of this plan and its prototype, 2026-09-26). Each is pinned by a test that was checked to fail when the fix is reverted:
  - **Replaying an old MK under a forged higher generation is now caught (Critical).** Before, a higher generation was accepted as `Newer` even with a different `mk_id`. Anyone holding an old MK (an old file plus a removed credential) could re-serialize the old vault with any generation and slip past the high-water check. This left review finding 7 open.
    - The new `Standing::Rekeyed` covers "higher generation, different MK" and is not ok.
    - `HighWater::raise` (for files the daemon *reads*) stores only acceptable marks and returns the `Standing`.
    - `HighWater::record` (for the daemon's *own* writes and user-accepted rollbacks) stores unconditionally.
    - Generation arithmetic is checked (`GenerationOverflow`).
    - Task 4 amends spec §4 to match.
  - **`write()` returns the `Mark` it wrote.** It chooses and serializes the generation while holding `vault.aleph.lock`, and commits it only after the rename. Concurrent writers get distinct generations, the file on disk equals the vault's mark, and a failed write does not advance it.
  - **A test pins the `mk_id` check.** A header carrying another MK's `mk_id`, MAC'd under the real key, fails with `HeaderTampered`.
  - **End-to-end rollback tests.** Real files go through `HighWater`: a restored older file shows as `RolledBack`, and a forged higher generation under the old MK shows as `Rekeyed`.
  - **Minor fixes:**
    - the first write after a rotation also replaces `.bak`, so the pre-rotation file (old MK, removed slot) does not linger
    - trailing bytes after a slot are rejected
    - `Rotation.dropped` lists each known slot once, and unknown slots appear only in `dropped_unknown`
    - backups never carry generation 0
    - `WrongSlotType`'s message is fixed
    - `x-wing` is pinned to `=0.1.0`
    - secrets are passed to `x-wing` by reference (`as_array_ref`) and its outputs are zeroized
    - rotation checks each KEK against the *current* MK's fingerprint (`KeyHandle::unwraps_to`)
    - a structured proptest runs slot maps through `SlotEntry::decode`
    - the high-water file is decoded strictly
    - the test vectors come from a commit-pinned URL
  - **Deferred:** splitting Task 4 into smaller red/green steps. It replays cleanly, and splitting it would mean building intermediate file states.
  - **For Plan 6:** CI must also run a plain `cargo build --workspace`. `cargo test --workspace` enables `insecure-test-params` for every crate in the build, so it could go green while a release build fails.
- **Out of this plan:**
  - the daemon-lifetime lock (`vault.aleph.daemon`) and logging the directory-tightening warning (Plan 3)
  - recovery-key confirmation at setup (Plan 4)
  - the core already refuses to write through a symlink and tightens a loose vault directory

## Global Constraints

- Rust stable 1.98, edition 2024; `license = "Apache-2.0"`.
- `aleph-core`: no D-Bus, no hardware access. The only global state is the Argon2 serialization lock.
- **Exact strings (HKDF infos):**
  - `"aleph header v1"`, `"aleph body v1"` (unchanged)
  - `"aleph mk id v1"` (the MK fingerprint, first 16 bytes)
  - `"aleph recovery xwing seed v1"` (recovery key → X-Wing seed)
  - `"aleph recovery v1"` (X-Wing shared secret → KEK)
  - slot types `tpm`, `fido2`, `recovery`, `login-password`
  - magic `b"ALEPH\0"`, `FORMAT_VERSION = 1` (v1 unreleased; Task 4 regenerates the golden file)
- **Invariants:**
  - a vault cannot be serialized without a recovery slot (`RecoveryRequired`)
  - the `Mark` returned by `write` is exactly the file on disk
  - only marks from the daemon's own writes (or explicit user acceptance) may move the high-water mark to a new MK
  - `rotate_master` changes nothing unless every non-recovery slot kept has a correct KEK
  - removing a slot always rotates MK
- Secrets never print: `Debug` is redacted on `Recipient`, `Kek`, `KeyHandle`, `RecoveryKey`, `SecretBytes`.
- `cargo fmt` default, `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **A removed credential plus an old copy of the file** must never open a file written after the removal. The removed slot is gone, and splicing its old entry back in fails. → Task 4 `removing_a_slot_rotates_so_it_cannot_open_later_files`.
2. **A rotation where some slot cannot be presented** must fail cleanly and leave the vault unchanged. The recovery slot must be re-wrapped without the paper key. → Task 4 `rotation_needs_correct_keks_for_every_non_recovery_slot_and_changes_nothing_on_error`, `reissuing_the_recovery_key_retires_the_old_one`.
3. **A file rolled back, replaced, or re-keyed elsewhere** (a sync peer, an old backup, or someone replaying an old MK under a forged higher generation) must be distinguishable from the current one. The recorded mark must never move backwards, or to another MK, except through the daemon's own writes or explicit acceptance. → Task 3 `a_higher_generation_under_a_different_mk_is_rekeyed_not_newer`, `raise_stores_only_acceptable_marks_and_reports_the_standing`; Task 4 `restoring_an_older_file_is_detected_as_rolled_back`, `a_replayed_old_mk_with_a_forged_higher_generation_is_rekeyed`, `a_header_claiming_another_mk_id_is_rejected`, and (write side) `concurrent_writers_never_corrupt_the_vault`, `a_failed_write_does_not_advance_the_generation`.
4. **A slot written by a newer aleph** must survive an older aleph's rewrite byte-for-byte. A known slot with an unexpected field must be rejected, not silently truncated. → Task 4 `unknown_slot_types_survive_writes_and_are_dropped_by_rotation`, keyslot unit tests.
5. **A leaked `aleph backup` file** must hold only the recovery slot. A login-password slot with weak parameters must be refused at enrollment. → Task 4 `backup_copy_contains_only_the_recovery_slot`, `only_hardware_slots_take_a_raw_kek_and_weak_params_are_refused`; Task 2 `enrollment_requires_the_floor`.

## File Structure

```
Cargo.toml                          + x-wing, hex, serde_json; opt-level overrides for X-Wing/CBOR deps
crates/aleph-core/
  Cargo.toml                        + x-wing; feature insecure-test-params; dev: self (feature), hex, serde_json
  src/xwing.rs          (new)       Recipient (X-Wing decapsulation key), encapsulate
  src/recovery.rs                   + RecoveryKey::recipient(); as_bytes becomes private
  src/kdf.rs                        login-password floor only; INSECURE_TEST gated; meets/enrollable
  src/highwater.rs      (new)       Mark, Standing, compare, HighWater store
  src/key.rs                        + KeyHandle::id() (MK fingerprint)
  src/keyslot.rs                    SlotKind v2 (Tpm/Fido2/Recovery/LoginPassword), SlotEntry, UnknownSlot
  src/vault.rs                      header v2, recovery/login-password constructors & unlocks,
                                    rotate_master(keks, drop), remove = rotate, backup bytes,
                                    symlink refusal, dir tightening, write_small_file, testing hook
  src/error.rs                      + RecoveryRequired, WeakParams, NotAHardwareSlot (− LastKeyslot)
  src/lib.rs                        module list + re-exports
  tests/data/xwing-draft-vectors.json   the draft authors' X-Wing vectors
  tests/common/mod.rs, vault.rs, write.rs, zeroize.rs, golden.rs   rewritten for the new API
  tests/golden/v1.aleph             regenerated
```

---
### Task 1: X-Wing recipient for the recovery key

**Files:**
- Modify: `Cargo.toml`, `crates/aleph-core/Cargo.toml`, `crates/aleph-core/src/lib.rs`, `crates/aleph-core/src/recovery.rs`
- Create: `crates/aleph-core/src/xwing.rs`, `crates/aleph-core/tests/data/xwing-draft-vectors.json`

**Interfaces:**
- Consumes: `crypto::{hkdf, fill_random, KEY_LEN}`, `Error::Malformed`.
- Produces:
  - `xwing::{PUBLIC_KEY_LEN = 1216, CIPHERTEXT_LEN = 1120}`
  - `xwing::Recipient::from_seed(&Zeroizing<[u8; 32]>) -> Recipient`, `.public_key() -> Vec<u8>`, `.decapsulate(&[u8]) -> Result<Zeroizing<[u8; 32]>>`
  - `xwing::encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)>`
  - `RecoveryKey::recipient(&self) -> Recipient`. `as_bytes` stays public until Task 4, because the old recovery slot still uses it.

- [ ] **Step 1: Add dependencies, the vectors, and failing tests**

Replace the workspace `Cargo.toml` with:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "Apache-2.0"
rust-version = "1.98"

[workspace.dependencies]
argon2 = "0.6"
chacha20poly1305 = "0.11"
ciborium = "0.2"
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

Replace `crates/aleph-core/Cargo.toml` with:

```toml
[package]
name = "aleph-core"
description = "Vault format and cryptography for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
argon2.workspace = true
chacha20poly1305.workspace = true
ciborium.workspace = true
getrandom.workspace = true
hkdf.workspace = true
hmac.workspace = true
hybrid-array.workspace = true
libc.workspace = true
secrecy.workspace = true
serde.workspace = true
serde_bytes.workspace = true
sha2.workspace = true
thiserror.workspace = true
uuid.workspace = true
x-wing.workspace = true
zeroize.workspace = true

[dev-dependencies]
hex.workspace = true
proptest.workspace = true
serde_json.workspace = true
tempfile.workspace = true
```

Replace `crates/aleph-core/src/lib.rs` with:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod key;
pub mod keyslot;
pub mod model;
pub mod recovery;
pub mod vault;
pub mod xwing;

pub use error::{Error, Result};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
pub use keyslot::{Argon2Kind, Argon2Slot, Fido2Slot, Keyslot, SlotKind, TpmAuth, TpmSlot};
pub use model::{Body, Collection, Item, SecretBytes};
pub use recovery::RecoveryKey;
pub use vault::{LockedVault, UnlockedVault};
```

Create `crates/aleph-core/tests/data/xwing-draft-vectors.json` from the draft authors' published vectors, pinned to commit `984c2f7`. Download them and check the digest:

```bash
curl -sSL -o crates/aleph-core/tests/data/xwing-draft-vectors.json \
  https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/test-vectors.json
sha256sum crates/aleph-core/tests/data/xwing-draft-vectors.json
```

Expected digest: `409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d` (three vectors with keys `seed`, `eseed`, `ss`, `sk`, `pk`, `ct`).

Create `crates/aleph-core/src/xwing.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        seed: String,
        eseed: String,
        ss: String,
        pk: String,
        ct: String,
    }

    /// The draft authors' test vectors
    /// (github.com/dconnolly/draft-connolly-cfrg-xwing-kem, spec/test-vectors.json).
    fn vectors() -> Vec<Vector> {
        serde_json::from_str(include_str!("../tests/data/xwing-draft-vectors.json")).unwrap()
    }

    fn seed32(hex_str: &str) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(hex::decode(hex_str).unwrap().try_into().unwrap())
    }

    #[test]
    fn keygen_and_decapsulation_match_the_draft_vectors() {
        let vs = vectors();
        assert_eq!(vs.len(), 3);
        for v in vs {
            let r = Recipient::from_seed(&seed32(&v.seed));
            assert_eq!(hex::encode(r.public_key()), v.pk);
            let ss = r.decapsulate(&hex::decode(&v.ct).unwrap()).unwrap();
            assert_eq!(hex::encode(ss.as_slice()), v.ss);
        }
    }

    #[test]
    fn deterministic_encapsulation_matches_the_draft_vectors() {
        for v in vectors() {
            let ek = EncapsulationKey::try_from(hex::decode(&v.pk).unwrap().as_slice()).unwrap();
            let eseed: [u8; 64] = hex::decode(&v.eseed).unwrap().try_into().unwrap();
            let (ct, ss) = ek.encapsulate_deterministic(&eseed.into());
            assert_eq!(hex::encode(ct.as_slice()), v.ct);
            assert_eq!(hex::encode(ss.as_slice()), v.ss);
        }
    }

    #[test]
    fn encapsulate_round_trips_and_is_randomized() {
        let r = Recipient::from_seed(&Zeroizing::new([7u8; KEY_LEN]));
        let pk = r.public_key();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        let (ct1, ss1) = encapsulate(&pk).unwrap();
        let (ct2, ss2) = encapsulate(&pk).unwrap();
        assert_eq!(ct1.len(), CIPHERTEXT_LEN);
        assert_ne!(ct1, ct2);
        assert_ne!(*ss1, *ss2);
        assert_eq!(*r.decapsulate(&ct1).unwrap(), *ss1);
    }

    #[test]
    fn wrong_recipient_gets_a_different_secret() {
        let (ct, ss) =
            encapsulate(&Recipient::from_seed(&Zeroizing::new([1u8; 32])).public_key()).unwrap();
        let other = Recipient::from_seed(&Zeroizing::new([2u8; 32]));
        assert_ne!(*other.decapsulate(&ct).unwrap(), *ss);
    }

    #[test]
    fn malformed_inputs_are_errors() {
        assert!(matches!(encapsulate(&[0u8; 10]), Err(Error::Malformed(_))));
        let r = Recipient::from_seed(&Zeroizing::new([1u8; 32]));
        assert!(matches!(
            r.decapsulate(&[0u8; 10]),
            Err(Error::Malformed(_))
        ));
    }
}
```

In `crates/aleph-core/src/recovery.rs`, add this test inside `mod tests`, directly above `fn parse_round_trips_format`:

```rust
    #[test]
    fn recipient_is_determined_by_the_key() {
        let k = RecoveryKey::generate().unwrap();
        let same = RecoveryKey::parse(&k.format()).unwrap();
        let other = RecoveryKey::generate().unwrap();
        assert_eq!(k.recipient().public_key(), same.recipient().public_key());
        assert_ne!(k.recipient().public_key(), other.recipient().public_key());
        assert_eq!(
            k.recipient().public_key().len(),
            crate::xwing::PUBLIC_KEY_LEN
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core --lib`
Expected: the build fails because `Recipient`, `encapsulate`, and `RecoveryKey::recipient` do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `crates/aleph-core/src/xwing.rs`:

```rust
//! The recovery slot's public-key recipient: X-Wing (X25519 + ML-KEM-768,
//! draft-connolly-cfrg-xwing-kem), via RustCrypto's `x-wing` crate.
//!
//! A recipient's key pair is derived from a 32-byte seed (for aleph, from
//! the recovery key), so the daemon can wrap MK to the public key without
//! ever holding the recovery key.

use hybrid_array::AsArrayRef;
use x_wing::{Decapsulate, DecapsulationKey, Decapsulator, EncapsulationKey, KeyExport, KeyInit};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KEY_LEN};
use crate::error::{Error, Result};

pub const PUBLIC_KEY_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
pub const CIPHERTEXT_LEN: usize = x_wing::CIPHERTEXT_SIZE;

/// An X-Wing decapsulation key, zeroized on drop.
pub struct Recipient(DecapsulationKey);

impl Recipient {
    /// The key pair determined by `seed`, per the X-Wing spec's KeyGen.
    pub fn from_seed(seed: &Zeroizing<[u8; KEY_LEN]>) -> Self {
        // Borrowed as an `Array` without copying; the key copies it into its
        // own zeroize-on-drop storage.
        Self(DecapsulationKey::new(seed.as_array_ref()))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.encapsulation_key().to_bytes().to_vec()
    }

    /// Recover the shared secret from an encapsulation. X-Wing decapsulation
    /// never fails outright; a wrong key yields an unrelated secret, which
    /// the keyslot AEAD then rejects.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let ct = x_wing::Ciphertext::try_from(ciphertext)
            .map_err(|_| Error::Malformed("X-Wing ciphertext has the wrong length".into()))?;
        let mut ss = self.0.decapsulate(&ct);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        out.copy_from_slice(&ss);
        ss.zeroize();
        Ok(out)
    }
}

impl std::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Recipient([REDACTED])")
    }
}

/// Encapsulate a fresh shared secret to `public_key`. Returns
/// `(ciphertext, shared_secret)`.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; KEY_LEN]>)> {
    let ek = EncapsulationKey::try_from(public_key)
        .map_err(|_| Error::Malformed("invalid X-Wing public key".into()))?;
    let mut randomness = Zeroizing::new([0u8; x_wing::ENCAPSULATION_RANDOMNESS_SIZE]);
    crypto::fill_random(randomness.as_mut())?;
    let (ct, mut ss) = ek.encapsulate_deterministic(randomness.as_array_ref());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&ss);
    ss.zeroize();
    Ok((ct.to_vec(), out))
}
```

In `crates/aleph-core/src/recovery.rs`, add below `use crate::key::try_init_secret;`:

```rust
use crate::xwing::Recipient;

const XWING_SEED_INFO: &[u8] = b"aleph recovery xwing seed v1";
```

and add this method to `impl RecoveryKey`, directly after `as_bytes`:

```rust
    /// This key's X-Wing recipient: the key pair whose seed is
    /// `HKDF(recovery key, "aleph recovery xwing seed v1")`. No Argon2:
    /// the recovery key already has full entropy.
    pub fn recipient(&self) -> Recipient {
        Recipient::from_seed(&crypto::hkdf(self.as_bytes(), XWING_SEED_INFO))
    }
```

Also change `as_bytes`'s doc comment to read `/// The bytes fed to Argon2id by today's recovery slot (private again` / `/// once the X-Wing recovery slot replaces it).`.

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected:
- unit tests: `43 passed`, including the five `xwing::tests`, which match all three draft vectors, and `recipient_is_determined_by_the_key`
- the integration tests: unchanged and passing

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-core
git commit -m "feat(core): X-Wing recipient derived from the recovery key" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: Argon2 only for login passwords, with an enrollment floor

**Files:**
- Modify: `crates/aleph-core/Cargo.toml` (feature `insecure-test-params`, self dev-dependency), `crates/aleph-core/src/kdf.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `Argon2Params::LOGIN_PASSWORD_FLOOR` (64 MiB, t = 2, p = 4)
  - `Argon2Params::INSECURE_TEST`, only under `cfg(test)` or feature `insecure-test-params`
  - `Argon2Params::meets(&self, floor: &Self) -> bool`
  - `Argon2Params::enrollable(&self) -> bool`: at least the floor, or `INSECURE_TEST` when the feature is on
  - `RECOVERY_KEY` and `PASSPHRASE_FLOOR` are removed

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/Cargo.toml` with:

```toml
[package]
name = "aleph-core"
description = "Vault format and cryptography for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
argon2.workspace = true
chacha20poly1305.workspace = true
ciborium.workspace = true
getrandom.workspace = true
hkdf.workspace = true
hmac.workspace = true
hybrid-array.workspace = true
libc.workspace = true
secrecy.workspace = true
serde.workspace = true
serde_bytes.workspace = true
sha2.workspace = true
thiserror.workspace = true
uuid.workspace = true
x-wing.workspace = true
zeroize.workspace = true

[features]
# Exposes `Argon2Params::INSECURE_TEST` and lets vaults be built with it.
# Only for tests (this crate's own integration tests enable it below).
insecure-test-params = []

[dev-dependencies]
aleph-core = { path = ".", features = ["insecure-test-params"] }
hex.workspace = true
proptest.workspace = true
serde_json.workspace = true
tempfile.workspace = true
```

In `crates/aleph-core/src/kdf.rs`, replace the whole `#[cfg(test)] mod tests { … }` block with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_and_salted() {
        let p = Argon2Params::INSECURE_TEST;
        let a = derive_kek(b"pw", &[1; SALT_LEN], &p).unwrap();
        let b = derive_kek(b"pw", &[1; SALT_LEN], &p).unwrap();
        let c = derive_kek(b"pw", &[2; SALT_LEN], &p).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    /// Known answer for the login-password floor. If this changes,
    /// existing login-password slots can no longer be opened. Verified
    /// against the reference C implementation:
    /// `printf "aleph known answer" | argon2 BBBBBBBBBBBBBBBB -id -t 2 -m 16 -p 4 -l 32 -r`
    #[test]
    fn login_password_floor_known_answer() {
        let kek = derive_kek(
            b"aleph known answer",
            &[0x42; SALT_LEN],
            &Argon2Params::LOGIN_PASSWORD_FLOOR,
        )
        .unwrap();
        assert_eq!(
            hex(kek.expose()),
            "70f16ec941691d57b88ca192c0b7d38373c5cee7adbe788a52e3f5d4b1860cbb"
        );
    }

    #[test]
    fn enrollment_requires_the_floor() {
        let floor = Argon2Params::LOGIN_PASSWORD_FLOOR;
        assert!(floor.enrollable());
        assert!(Argon2Params { t: 5, ..floor }.enrollable());
        assert!(
            !Argon2Params {
                m_kib: 1024,
                ..floor
            }
            .enrollable()
        );
        assert!(!Argon2Params { t: 1, ..floor }.enrollable());
        assert!(!Argon2Params { p: 1, ..floor }.enrollable());
        // Test parameters are enrollable only because cfg(test) is on here.
        assert!(Argon2Params::INSECURE_TEST.enrollable());
    }

    #[test]
    fn tune_never_goes_below_floor() {
        let floor = Argon2Params {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        let tuned = tune(floor, Duration::from_millis(5)).unwrap();
        assert!(tuned.t >= floor.t);
        assert_eq!(tuned.m_kib, floor.m_kib);
        assert_eq!(tuned.p, floor.p);
    }

    #[test]
    fn invalid_params_are_an_error_not_a_panic() {
        let bad = Argon2Params {
            m_kib: 1,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &bad),
            Err(Error::Kdf(_))
        ));
    }

    #[test]
    fn params_needing_more_memory_than_the_limit_are_rejected() {
        // A corrupt slot asking for 1 GiB on a 512 MiB machine must be a
        // distinct error, not an OOM kill and not a generic KDF failure.
        assert!(matches!(
            check_memory(1024 * 1024, Some(512 * 1024)),
            Err(Error::InsufficientMemory {
                needed_kib: 1_048_576,
                limit_kib: 524_288
            })
        ));
        assert!(check_memory(1024 * 1024, Some(2 * 1024 * 1024)).is_ok());
        // Unknown limit (no /proc) falls back to the fixed caps.
        assert!(check_memory(1024 * 1024, None).is_ok());
    }

    /// The limit is capacity (RAM + swap), not the momentary MemAvailable:
    /// a busy desktop with little free RAM must still unlock.
    #[test]
    fn system_limit_is_total_ram_plus_swap_not_available() {
        let meminfo = "MemTotal:        8000000 kB\nMemFree:  100 kB\n\
                       MemAvailable:     900000 kB\nSwapTotal:       4000000 kB\n";
        assert_eq!(parse_system_limit(meminfo), Some(12_000_000));
        let no_swap = "MemTotal:        8000000 kB\nMemAvailable: 1 kB\n";
        assert_eq!(parse_system_limit(no_swap), Some(8_000_000));
        assert_eq!(parse_system_limit("SwapTotal: 1 kB\n"), None);
        assert!(check_memory(1024 * 1024, parse_system_limit(meminfo)).is_ok());
    }

    #[test]
    fn cgroup_v2_path_is_parsed() {
        assert_eq!(
            parse_cgroup_path("0::/user.slice/user@1000.service/app.slice/alephd.service\n"),
            Some("/user.slice/user@1000.service/app.slice/alephd.service")
        );
        // cgroup v1 hierarchies only: no unified path.
        assert_eq!(parse_cgroup_path("4:memory:/user.slice\n"), None);
    }

    #[test]
    fn cgroup_limit_is_memory_plus_swap_and_max_is_unlimited() {
        // MemoryMax=512M, MemorySwapMax=256M.
        assert_eq!(
            parse_cgroup_limit("536870912\n", Some("268435456\n")),
            Some(768 * 1024)
        );
        assert_eq!(
            parse_cgroup_limit("536870912\n", Some("0\n")),
            Some(512 * 1024)
        );
        assert_eq!(parse_cgroup_limit("max\n", Some("0\n")), None);
        // Unlimited or unaccounted swap: the system-wide limit covers it.
        assert_eq!(parse_cgroup_limit("536870912\n", Some("max\n")), None);
        assert_eq!(parse_cgroup_limit("536870912\n", None), None);
        assert_eq!(parse_cgroup_limit("garbage", Some("0")), None);
    }

    /// The tightest cgroup on the path to the root wins: a slice-level
    /// MemoryMax binds a service inside it.
    #[test]
    fn cgroup_limit_is_the_tightest_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let slice = root.path().join("user.slice");
        let service = slice.join("alephd.service");
        std::fs::create_dir_all(&service).unwrap();
        std::fs::write(slice.join("memory.max"), "536870912\n").unwrap();
        std::fs::write(slice.join("memory.swap.max"), "0\n").unwrap();
        std::fs::write(service.join("memory.max"), "max\n").unwrap();
        std::fs::write(service.join("memory.swap.max"), "0\n").unwrap();
        assert_eq!(
            cgroup_limit_kib(root.path(), "/user.slice/alephd.service"),
            Some(512 * 1024)
        );
        assert_eq!(cgroup_limit_kib(root.path(), "/"), None);
    }

    #[test]
    fn this_machine_has_a_memory_limit() {
        assert!(memory_limit_kib().is_some_and(|l| l > 0));
    }

    #[test]
    fn oversized_params_are_rejected_before_allocating() {
        let huge = Argon2Params {
            m_kib: u32::MAX,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &huge),
            Err(Error::Kdf(_))
        ));
        let slow = Argon2Params {
            m_kib: 64,
            t: u32::MAX,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &slow),
            Err(Error::Kdf(_))
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core --lib`
Expected: the build fails because `enrollable` does not exist yet. The new KAT would also fail, since `LOGIN_PASSWORD_FLOOR`'s known answer is new.

- [ ] **Step 3: Implement**

Replace everything above the `#[cfg(test)]` line in `crates/aleph-core/src/kdf.rs` with:

```rust
//! Argon2id key derivation for the login-password keyslot (the only
//! slot type whose KEK comes from a secret the user types).

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::key::Kek;

pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters, stored in each keyslot so they can change
/// per slot and over time without a format change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Argon2Params {
    /// Floor for the no-TPM login-password fallback; `tune` raises `t` to
    /// about 0.3 s. Enrollment refuses anything weaker.
    pub const LOGIN_PASSWORD_FLOOR: Self = Self {
        m_kib: 64 * 1024,
        t: 2,
        p: 4,
    };
    /// Only for tests: fast, and never valid in a real vault. Exists only
    /// under `cfg(test)` or the `insecure-test-params` feature.
    #[cfg(any(test, feature = "insecure-test-params"))]
    pub const INSECURE_TEST: Self = Self {
        m_kib: 32,
        t: 1,
        p: 1,
    };

    /// Upper bounds accepted from a vault file. A corrupt or hostile slot
    /// must produce an error, not a multi-terabyte allocation.
    pub const MAX: Self = Self {
        m_kib: 4 * 1024 * 1024,
        t: 64,
        p: 16,
    };

    /// True if every cost is at least `floor`'s.
    pub fn meets(&self, floor: &Self) -> bool {
        self.m_kib >= floor.m_kib && self.t >= floor.t && self.p >= floor.p
    }

    /// Whether enrollment may use these parameters: at least the floor, or
    /// the test parameters when the `insecure-test-params` feature is on.
    pub fn enrollable(&self) -> bool {
        #[cfg(any(test, feature = "insecure-test-params"))]
        if *self == Self::INSECURE_TEST {
            return true;
        }
        self.meets(&Self::LOGIN_PASSWORD_FLOOR)
    }

    fn argon2(&self) -> Result<argon2::Argon2<'static>> {
        if self.m_kib > Self::MAX.m_kib || self.t > Self::MAX.t || self.p > Self::MAX.p {
            return Err(Error::Kdf(format!("parameters exceed limits: {self:?}")));
        }
        check_memory(self.m_kib, memory_limit_kib())?;
        let params = argon2::Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// Refuse a derivation that needs more memory than this process can ever
/// get. Under Linux overcommit the allocation itself succeeds and the OOM
/// killer ends the process mid-derivation, so this check is the only way a
/// corrupt slot's `m_kib` becomes an error instead of a dead daemon.
/// `None` (limit unknown) falls back to the fixed `Argon2Params::MAX` cap.
fn check_memory(m_kib: u32, limit_kib: Option<u64>) -> Result<()> {
    match limit_kib {
        Some(limit_kib) if u64::from(m_kib) > limit_kib => Err(Error::InsufficientMemory {
            needed_kib: m_kib.into(),
            limit_kib,
        }),
        _ => Ok(()),
    }
}

/// The most memory a derivation in this process can use: RAM plus swap,
/// lowered by any cgroup v2 limit on the way to the root.
///
/// Deliberately capacity, not `MemAvailable`: that is a momentary figure
/// (it excludes swap and drops when a browser is open) and would turn a
/// busy desktop into a failed unlock indistinguishable from a bad slot.
fn memory_limit_kib() -> Option<u64> {
    let system = parse_system_limit(&std::fs::read_to_string("/proc/meminfo").ok()?);
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| {
            let path = parse_cgroup_path(&s)?.to_owned();
            cgroup_limit_kib(Path::new("/sys/fs/cgroup"), &path)
        });
    match (system, cgroup) {
        (Some(s), Some(c)) => Some(s.min(c)),
        (s, c) => s.or(c),
    }
}

fn meminfo_kib(meminfo: &str, field: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix(field)?.strip_prefix(':'))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
}

fn parse_system_limit(meminfo: &str) -> Option<u64> {
    let ram = meminfo_kib(meminfo, "MemTotal")?;
    Some(ram + meminfo_kib(meminfo, "SwapTotal").unwrap_or(0))
}

/// The unified (v2) hierarchy's path from `/proc/self/cgroup`.
fn parse_cgroup_path(proc_cgroup: &str) -> Option<&str> {
    proc_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
}

/// One cgroup's limit from its `memory.max` and `memory.swap.max`. `None`
/// when either is `max` (or swap is unaccounted): the cgroup then imposes
/// nothing beyond the system-wide limit.
fn parse_cgroup_limit(memory_max: &str, swap_max: Option<&str>) -> Option<u64> {
    let bytes = |s: &str| s.trim().parse::<u64>().ok();
    Some((bytes(memory_max)? + bytes(swap_max?)?) / 1024)
}

/// The tightest limit among the cgroup at `path` and its ancestors.
fn cgroup_limit_kib(root: &Path, path: &str) -> Option<u64> {
    let mut dir = root.join(path.trim_start_matches('/'));
    let mut tightest: Option<u64> = None;
    while dir.starts_with(root) && dir != root {
        if let Ok(max) = std::fs::read_to_string(dir.join("memory.max")) {
            let swap = std::fs::read_to_string(dir.join("memory.swap.max")).ok();
            if let Some(limit) = parse_cgroup_limit(&max, swap.as_deref()) {
                tightest = Some(tightest.map_or(limit, |t| t.min(limit)));
            }
        }
        if !dir.pop() {
            break;
        }
    }
    tightest
}

/// Held for every derivation. `check_memory` vets one derivation against
/// the limit; running them one at a time keeps two concurrent unlocks from
/// jointly exceeding it. Derivations take ~1 s, so async callers must
/// already be on a blocking thread.
static DERIVE_LOCK: Mutex<()> = Mutex::new(());

/// Derive a KEK from a password-like secret.
pub fn derive_kek(secret: &[u8], salt: &[u8; SALT_LEN], params: &Argon2Params) -> Result<Kek> {
    let argon2 = params.argon2()?;
    // A panic mid-derivation leaves no state behind to protect.
    let _serialized = DERIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    Kek::try_init(|out| {
        argon2
            .hash_password_into(secret, salt, out)
            .map_err(|e| Error::Kdf(e.to_string()))
    })
}

/// Raise the pass count from `floor` until one derivation takes at least
/// `target` on this machine. Memory and lanes stay at the floor.
pub fn tune(floor: Argon2Params, target: Duration) -> Result<Argon2Params> {
    let salt = [0u8; SALT_LEN];
    let mut params = floor;
    loop {
        let start = Instant::now();
        derive_kek(b"aleph tune", &salt, &params)?;
        let elapsed = start.elapsed();
        if elapsed >= target || params.t >= 64 {
            return Ok(params);
        }
        // Scale passes proportionally, always making progress.
        let scale = target.as_secs_f64() / elapsed.as_secs_f64().max(1e-6);
        params.t = ((params.t as f64 * scale).ceil() as u32).clamp(params.t + 1, 64);
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: unit tests `44 passed`. The integration tests still pass: they get `INSECURE_TEST` through the self dev-dependency with `insecure-test-params`.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-core/Cargo.toml Cargo.lock crates/aleph-core/src/kdf.rs
git commit -m "feat(core): Argon2 for login passwords only, with an enrollment floor" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: High-water mark

**Files:**
- Create: `crates/aleph-core/src/highwater.rs`
- Modify: `crates/aleph-core/src/lib.rs`, `crates/aleph-core/src/vault.rs` (append `write_small_file`)

**Interfaces:**
- Consumes: `vault::{sibling, write_file_synced}` (private helpers in the same crate).
- Produces:
  - `Mark { vault_id: Uuid, generation: u64, mk_id: [u8; 16] }` (serde)
  - `Standing { Unrecorded, Current, Newer, RolledBack { recorded }, Replaced, Rekeyed }` and `.is_ok()`, which is true only for `Unrecorded`, `Current`, and `Newer`. `Newer` requires the same `mk_id`, and a higher generation under a different MK is `Rekeyed`.
  - `highwater::compare(recorded: Option<&Mark>, found: &Mark) -> Standing`
  - `HighWater::new(dir)` with:
    - `.load(vault_id)`: strict decode
    - `.check(&Mark) -> Result<Standing>`
    - `.raise(&Mark) -> Result<Standing>`: for files the daemon reads; stores only acceptable marks
    - `.record(&Mark)`: unconditional; for the daemon's own writes and user-accepted rollbacks
  - `pub(crate) vault::write_small_file(path, bytes)`: 0600 file in a 0700 directory, temp file then rename

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/src/lib.rs` with:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod highwater;
pub mod kdf;
pub mod key;
pub mod keyslot;
pub mod model;
pub mod recovery;
pub mod vault;
pub mod xwing;

pub use error::{Error, Result};
pub use highwater::{HighWater, Mark, Standing};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
pub use keyslot::{Argon2Kind, Argon2Slot, Fido2Slot, Keyslot, SlotKind, TpmAuth, TpmSlot};
pub use model::{Body, Collection, Item, SecretBytes};
pub use recovery::RecoveryKey;
pub use vault::{LockedVault, UnlockedVault};
```

Create `crates/aleph-core/src/highwater.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn mark(generation: u64, mk: u8) -> Mark {
        Mark {
            vault_id: Uuid::from_bytes([9; 16]),
            generation,
            mk_id: [mk; 16],
        }
    }

    #[test]
    fn compare_classifies_every_case() {
        assert_eq!(compare(None, &mark(5, 1)), Standing::Unrecorded);
        assert_eq!(compare(Some(&mark(5, 1)), &mark(5, 1)), Standing::Current);
        assert_eq!(compare(Some(&mark(5, 1)), &mark(6, 1)), Standing::Newer);
        assert_eq!(
            compare(Some(&mark(5, 1)), &mark(4, 1)),
            Standing::RolledBack { recorded: 5 }
        );
        assert_eq!(compare(Some(&mark(5, 1)), &mark(5, 2)), Standing::Replaced);
        assert_eq!(compare(Some(&mark(5, 1)), &mark(6, 2)), Standing::Rekeyed);
        assert!(Standing::Newer.is_ok());
        for s in [
            Standing::Replaced,
            Standing::Rekeyed,
            Standing::RolledBack { recorded: 1 },
        ] {
            assert!(!s.is_ok(), "{s:?}");
        }
    }

    /// Someone holding the old MK can re-serialize an old file with any
    /// generation. A higher generation under a different MK than recorded
    /// is therefore not "newer": it must not be accepted or recorded.
    #[test]
    fn a_higher_generation_under_a_different_mk_is_rekeyed_not_newer() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path());
        hw.record(&mark(5, 1)).unwrap();
        assert_eq!(hw.raise(&mark(u64::MAX, 2)).unwrap(), Standing::Rekeyed);
        assert_eq!(hw.load(mark(1, 1).vault_id).unwrap(), Some(mark(5, 1)));
    }

    #[test]
    fn raise_stores_only_acceptable_marks_and_reports_the_standing() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path().join("state"));
        assert_eq!(hw.load(mark(1, 1).vault_id).unwrap(), None);
        assert_eq!(hw.raise(&mark(5, 1)).unwrap(), Standing::Unrecorded);
        assert_eq!(
            hw.raise(&mark(3, 1)).unwrap(),
            Standing::RolledBack { recorded: 5 }
        );
        assert_eq!(hw.raise(&mark(5, 2)).unwrap(), Standing::Replaced);
        assert_eq!(hw.raise(&mark(6, 1)).unwrap(), Standing::Newer);
        assert_eq!(hw.load(mark(1, 1).vault_id).unwrap(), Some(mark(6, 1)));
    }

    /// `record` is for marks the daemon itself wrote (including its own
    /// rotations) and for rollbacks the user accepted: stored unconditionally.
    #[test]
    fn record_stores_unconditionally() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path());
        hw.record(&mark(5, 1)).unwrap();
        hw.record(&mark(6, 2)).unwrap(); // own rotation
        assert_eq!(hw.check(&mark(6, 2)).unwrap(), Standing::Current);
        hw.record(&mark(3, 2)).unwrap(); // accepted rollback
        assert_eq!(hw.check(&mark(3, 2)).unwrap(), Standing::Current);
    }

    #[test]
    fn corrupt_foreign_or_padded_record_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path());
        let m = mark(1, 1);
        std::fs::write(hw.path(m.vault_id), b"garbage").unwrap();
        assert!(matches!(hw.load(m.vault_id), Err(Error::Malformed(_))));

        hw.record(&m).unwrap();
        let mut padded = std::fs::read(hw.path(m.vault_id)).unwrap();
        padded.push(0);
        std::fs::write(hw.path(m.vault_id), padded).unwrap();
        assert!(matches!(hw.load(m.vault_id), Err(Error::Malformed(_))));

        let other = Mark {
            vault_id: Uuid::from_bytes([1; 16]),
            ..m
        };
        hw.record(&other).unwrap();
        std::fs::rename(hw.path(other.vault_id), hw.path(m.vault_id)).unwrap();
        assert!(matches!(hw.load(m.vault_id), Err(Error::Malformed(_))));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core --lib`
Expected: the build fails because `Mark`, `Standing`, `HighWater`, and `compare` do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `crates/aleph-core/src/highwater.rs`:

```rust
//! The high-water mark: the newest `(generation, mk_id)` seen for each
//! vault, kept outside the vault's directory (`$XDG_STATE_HOME/aleph/`) so
//! backups and sync do not carry it (spec §4).
//!
//! Comparing a file's mark against the recorded one reveals a vault that
//! was rolled back (lower generation), replaced (same generation, different
//! MK), or re-keyed elsewhere (higher generation, different MK). The last
//! case matters because anyone holding an old MK (an old file plus a since-
//! removed credential) can re-serialize the old vault with any generation.
//! Only the daemon's own writes may move the mark to a new MK, via
//! `record`. It is not tamper-proof against an attacker who can also write
//! the state directory.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

/// One generation of one vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mark {
    pub vault_id: Uuid,
    pub generation: u64,
    #[serde(with = "serde_bytes")]
    pub mk_id: [u8; 16],
}

/// How a file's mark stands against the recorded high-water mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Nothing recorded for this vault yet.
    Unrecorded,
    /// Exactly the recorded generation.
    Current,
    /// Newer than recorded, under the same master key.
    Newer,
    /// Older than recorded: the file was rolled back.
    RolledBack { recorded: u64 },
    /// Same generation as recorded but a different master key: the file
    /// was replaced.
    Replaced,
    /// Higher generation than recorded but a different master key: MK was
    /// changed somewhere other than this daemon, or an old MK is being
    /// replayed under a forged generation.
    Rekeyed,
}

impl Standing {
    /// Whether the daemon may proceed without asking the user.
    pub fn is_ok(self) -> bool {
        matches!(
            self,
            Standing::Unrecorded | Standing::Current | Standing::Newer
        )
    }
}

/// Compare a vault file's mark with what was recorded for that vault.
pub fn compare(recorded: Option<&Mark>, found: &Mark) -> Standing {
    match recorded {
        None => Standing::Unrecorded,
        Some(r) if found.generation < r.generation => Standing::RolledBack {
            recorded: r.generation,
        },
        Some(r) => match (found.generation == r.generation, found.mk_id == r.mk_id) {
            (true, true) => Standing::Current,
            (true, false) => Standing::Replaced,
            (false, true) => Standing::Newer,
            (false, false) => Standing::Rekeyed,
        },
    }
}

/// High-water marks stored as one small file per vault in a directory.
pub struct HighWater {
    dir: PathBuf,
}

impl HighWater {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, vault_id: Uuid) -> PathBuf {
        self.dir.join(format!("highwater-{vault_id}"))
    }

    pub fn load(&self, vault_id: Uuid) -> Result<Option<Mark>> {
        match fs::read(self.path(vault_id)) {
            Ok(bytes) => {
                let malformed = |m: String| Error::Malformed(format!("high-water mark: {m}"));
                let mut cursor = std::io::Cursor::new(bytes.as_slice());
                let mark: Mark =
                    ciborium::from_reader(&mut cursor).map_err(|e| malformed(e.to_string()))?;
                if cursor.position() != bytes.len() as u64 {
                    return Err(malformed("trailing data".into()));
                }
                if mark.vault_id != vault_id {
                    return Err(Error::Malformed("high-water mark for another vault".into()));
                }
                Ok(Some(mark))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// How `found` stands against this store's record for its vault.
    pub fn check(&self, found: &Mark) -> Result<Standing> {
        Ok(compare(self.load(found.vault_id)?.as_ref(), found))
    }

    /// Record `mark` if it stands acceptably (`Standing::is_ok`) against
    /// the current record, and report how it stood. Use for marks of files
    /// the daemon *read*. Never lowers the mark or moves it to another MK.
    pub fn raise(&self, mark: &Mark) -> Result<Standing> {
        let standing = self.check(mark)?;
        if standing.is_ok() && standing != Standing::Current {
            self.store(mark)?;
        }
        Ok(standing)
    }

    /// Record `mark` unconditionally. Use only for marks the daemon itself
    /// wrote (the `Mark` returned by `UnlockedVault::write`, including after
    /// its own rotations) and for a rollback or replacement the user
    /// explicitly accepted.
    pub fn record(&self, mark: &Mark) -> Result<()> {
        self.store(mark)
    }

    fn store(&self, mark: &Mark) -> Result<()> {
        let mut bytes = Vec::new();
        ciborium::into_writer(mark, &mut bytes).map_err(|e| Error::Malformed(e.to_string()))?;
        crate::vault::write_small_file(&self.path(mark.vault_id), &bytes)
    }
}
```

Append to the end of `crates/aleph-core/src/vault.rs`:

```rust
/// Atomically write a small private file (0600, in a 0700 directory it
/// creates if needed): temp file, fsync, rename. No backup, no lock.
pub(crate) fn write_small_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let tmp = sibling(path, ".tmp")?;
    write_file_synced(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: unit tests `49 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-core
git commit -m "feat(core): high-water mark for rollback and replacement detection" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: Vault format v2: recovery recipient slot, rotation on removal, generations, unknown slots, backups

**Files:**
- Modify:
  - `crates/aleph-core/src/error.rs`, `crates/aleph-core/src/key.rs`, `crates/aleph-core/src/keyslot.rs`, `crates/aleph-core/src/vault.rs`, `crates/aleph-core/src/recovery.rs`, `crates/aleph-core/src/lib.rs`
  - `crates/aleph-core/tests/common/mod.rs`, `crates/aleph-core/tests/vault.rs`, `crates/aleph-core/tests/write.rs`, `crates/aleph-core/tests/zeroize.rs`, `crates/aleph-core/tests/golden.rs`
  - `docs/superpowers/specs/2026-09-26-aleph-design.md` (§4 keyslot encoding)
- Regenerate: `crates/aleph-core/tests/golden/v1.aleph`

**Interfaces:**
- Consumes: Tasks 1–3 (`xwing::{encapsulate, Recipient}`, `RecoveryKey::recipient`, `Argon2Params::enrollable`, `Mark`).
- Produces:
  - `KeyHandle::id() -> [u8; 16]`, and `KeyHandle::unwraps_to(kek, wrapped, aad, expected_id) -> bool` (opens *and* is the MK with that fingerprint)
  - `SlotKind`:
    - `Tpm(TpmSlot { public, private, auth_salt: [u8; 16], srk_name })`
    - `Fido2(Fido2Slot { credential_id, salt, uv_required, pin_required })` (no stored RP ID)
    - `Recovery(RecoverySlot { xwing_pk, xwing_ct })`
    - `LoginPassword(Argon2Slot { salt, params })`
  - `SlotEntry { Known(Keyslot), Unknown(UnknownSlot { raw, id, label, slot_type }) }` with `::decode(&[u8])` and `.encode()`
  - `LockedVault`:
    - `from_bytes`, `read`, `vault_id`, `keyslots()` (iterator), `unknown_keyslots()`, `mark()`
    - `unlock(id, &Kek)`, `unlock_login_password(id, &[u8])`, `unlock_recovery(id, &RecoveryKey)`
  - `UnlockedVault`:
    - `create()`, `vault_id()`, `keyslots()`, `unknown_keyslots()`, `mark()`, `body()`, `body_mut()`
    - `add_keyslot(label, SlotKind::Tpm | SlotKind::Fido2, &Kek)` (`Err(NotAHardwareSlot)` otherwise)
    - `add_recovery_slot(label, public_key: &[u8])`
    - `add_login_password_slot(label, password, params)` (`Err(WeakParams)`)
    - `login_password_kek(id, password)`
    - `remove_keyslot(id, keks) -> Result<Rotation>`
    - `rotate_master(keks: &[(Uuid, &Kek)], drop: &[Uuid]) -> Result<Rotation { dropped, dropped_unknown }>`
    - `to_bytes()`: the next generation; `Err(RecoveryRequired)` without a recovery slot, `Err(GenerationOverflow)` at `u64::MAX`
    - `to_backup_bytes()`: generation at least 1
    - `write(path) -> Result<Mark>`: the generation is chosen under the file lock and committed after the rename; the first write after a rotation also replaces `.bak`
  - `Error`: adds `RecoveryRequired`, `WeakParams`, `NotAHardwareSlot`, `GenerationOverflow`; removes `LastKeyslot`
  - `RecoveryKey::as_bytes` becomes private
  - hidden `vault::testing::{push_unknown, set_generation, to_bytes_with_mk_id}` (feature `insecure-test-params`)

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/tests/common/mod.rs` with:

```rust
//! Shared fixtures for aleph-core integration tests.
#![allow(dead_code)] // each test binary uses a different subset

use std::collections::BTreeMap;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{Argon2Params, Item, RecoveryKey, SecretBytes, UnlockedVault};
use ciborium::Value;
use uuid::Uuid;

pub const PASSWORD: &[u8] = b"correct horse";

pub const FAST: Argon2Params = Argon2Params::INSECURE_TEST;

/// A vault with a recovery slot, a login-password slot, and one item.
/// Returns `(vault, recovery key, recovery slot id, password slot id)`.
pub fn sample() -> (UnlockedVault, RecoveryKey, Uuid, Uuid) {
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::generate().unwrap();
    let rec = v
        .add_recovery_slot("recovery", &rk.recipient().public_key())
        .unwrap();
    let pw = v.add_login_password_slot("login", PASSWORD, FAST).unwrap();
    let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
    let attrs = BTreeMap::from([("service".to_string(), "github".to_string())]);
    v.body_mut().collection_mut(login).unwrap().upsert(
        Item::new(
            "GitHub token",
            attrs,
            SecretBytes::new(b"ghp_secret".to_vec()),
            "text/plain",
        ),
        false,
    );
    (v, rk, rec, pw)
}

pub fn first_secret(v: &UnlockedVault) -> Vec<u8> {
    v.body().resolve_alias(DEFAULT_ALIAS).unwrap().items[0]
        .secret
        .expose()
        .to_vec()
}

/// Decode the file's outer CBOR array (after the magic), let `f` edit it,
/// re-encode.
pub fn edit_outer(bytes: &[u8], f: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut value: Value = ciborium::from_reader(&bytes[6..]).unwrap();
    f(match &mut value {
        Value::Array(a) => a,
        _ => panic!("vault is a CBOR array"),
    });
    let mut out = bytes[..6].to_vec();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}

/// Decode the header (outer element 1, a byte string holding a CBOR map),
/// let `f` edit it, re-encode. Simulates an attacker rewriting the header.
pub fn edit_header(bytes: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    edit_outer(bytes, |outer| {
        let mut header: Value =
            ciborium::from_reader(outer[1].as_bytes().unwrap().as_slice()).unwrap();
        f(match &mut header {
            Value::Map(m) => m,
            _ => panic!("header is a CBOR map"),
        });
        outer[1] = Value::Bytes(encode(&header));
    })
}

/// Decode each keyslot (a byte string holding a CBOR map), let `f` edit
/// the list of decoded maps, re-encode them into the header.
pub fn edit_slots(bytes: &[u8], f: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    edit_header(bytes, |h| {
        let Value::Array(raw) = field(h, "keyslots") else {
            panic!("keyslots is an array")
        };
        let mut slots: Vec<Value> = raw
            .iter()
            .map(|b| ciborium::from_reader(b.as_bytes().unwrap().as_slice()).unwrap())
            .collect();
        f(&mut slots);
        *raw = slots.iter().map(|s| Value::Bytes(encode(s))).collect();
    })
}

pub fn encode(v: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).unwrap();
    buf
}

pub fn field<'a>(map: &'a mut [(Value, Value)], name: &str) -> &'a mut Value {
    &mut map
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(name))
        .unwrap()
        .1
}
```

Replace `crates/aleph-core/tests/vault.rs` with:

```rust
mod common;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{
    Error, Fido2Slot, HighWater, Item, Kek, LockedVault, RecoveryKey, SecretBytes, SlotKind,
    Standing, TpmSlot, UnlockedVault, highwater, vault,
};
use ciborium::Value;
use common::*;
use proptest::prelude::*;
use uuid::Uuid;

fn fido2_kind() -> SlotKind {
    SlotKind::Fido2(Fido2Slot {
        credential_id: vec![1; 16],
        salt: [2; 32],
        uv_required: true,
        pin_required: true,
    })
}

fn tpm_kind() -> SlotKind {
    SlotKind::Tpm(TpmSlot {
        public: vec![1],
        private: vec![2],
        auth_salt: [3; 16],
        srk_name: vec![4],
    })
}

#[test]
fn round_trip_through_bytes_with_recovery_key_or_password() {
    let (v, rk, rec, pw) = sample();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(locked.keyslots().count(), 2);
    assert_eq!(
        first_secret(&locked.unlock_recovery(rec, &rk).unwrap()),
        b"ghp_secret"
    );
    assert_eq!(
        first_secret(&locked.unlock_login_password(pw, PASSWORD).unwrap()),
        b"ghp_secret"
    );
}

#[test]
fn wrong_secrets_and_wrong_slot_types_are_rejected() {
    let (v, _, rec, pw) = sample();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        locked.unlock_login_password(pw, b"wrong"),
        Err(Error::UnwrapFailed)
    ));
    let other = RecoveryKey::generate().unwrap();
    assert!(matches!(
        locked.unlock_recovery(rec, &other),
        Err(Error::UnwrapFailed)
    ));
    assert!(matches!(
        locked.unlock_recovery(pw, &other),
        Err(Error::WrongSlotType(_))
    ));
    assert!(matches!(
        locked.unlock_login_password(rec, PASSWORD),
        Err(Error::WrongSlotType(_))
    ));
    assert!(matches!(
        locked.unlock_login_password(Uuid::new_v4(), PASSWORD),
        Err(Error::NoSuchKeyslot(_))
    ));
}

#[test]
fn a_vault_without_a_recovery_slot_cannot_be_written() {
    let mut v = UnlockedVault::create().unwrap();
    v.add_login_password_slot("login", PASSWORD, FAST).unwrap();
    assert!(matches!(v.to_bytes(), Err(Error::RecoveryRequired)));
}

#[test]
fn only_hardware_slots_take_a_raw_kek_and_weak_params_are_refused() {
    let (mut v, ..) = sample();
    let kek = Kek::generate().unwrap();
    v.add_keyslot("fido", fido2_kind(), &kek).unwrap();
    v.add_keyslot("tpm", tpm_kind(), &kek).unwrap();
    let rec_kind = v
        .keyslots()
        .find(|s| matches!(s.kind, SlotKind::Recovery(_)))
        .unwrap()
        .kind
        .clone();
    assert!(matches!(
        v.add_keyslot("r", rec_kind, &kek),
        Err(Error::NotAHardwareSlot)
    ));
    let weak = aleph_core::Argon2Params {
        m_kib: 1024,
        t: 1,
        p: 1,
    };
    assert!(matches!(
        v.add_login_password_slot("w", PASSWORD, weak),
        Err(Error::WeakParams)
    ));
}

#[test]
fn bad_magic_and_future_versions_are_rejected() {
    let (v, ..) = sample();
    let bytes = v.to_bytes().unwrap();
    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert!(matches!(
        LockedVault::from_bytes(&bad),
        Err(Error::BadMagic)
    ));
    let future = edit_outer(&bytes, |a| a[0] = Value::Integer(2.into()));
    assert!(matches!(
        LockedVault::from_bytes(&future),
        Err(Error::UnsupportedVersion(2))
    ));
}

#[test]
fn trailing_bytes_and_extra_elements_are_rejected() {
    let (v, ..) = sample();
    let bytes = v.to_bytes().unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        LockedVault::from_bytes(&trailing),
        Err(Error::Malformed(_))
    ));
    let extra = edit_outer(&bytes, |a| a.push(Value::Null));
    assert!(matches!(
        LockedVault::from_bytes(&extra),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn deleting_a_keyslot_from_the_file_is_detected() {
    let (v, _, _, pw) = sample();
    let edited = edit_slots(&v.to_bytes().unwrap(), |slots| {
        slots.remove(0); // the recovery slot
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    assert!(matches!(
        locked.unlock_login_password(pw, PASSWORD),
        Err(Error::HeaderTampered)
    ));
}

#[test]
fn lowering_the_generation_in_the_file_is_detected() {
    let (v, _, _, pw) = sample();
    let edited = edit_header(&v.to_bytes().unwrap(), |h| {
        *field(h, "generation") = Value::Integer(0.into());
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    assert!(matches!(
        locked.unlock_login_password(pw, PASSWORD),
        Err(Error::HeaderTampered)
    ));
}

/// Spec §9 "header rollback rejected": an older, validly MAC'd header
/// spliced onto a newer body must not open.
#[test]
fn old_header_spliced_onto_new_body_is_rejected() {
    let (mut v, _, _, pw) = sample();
    let old = v.to_bytes().unwrap();
    v.body_mut().collections[0].label = "NEW BODY".into();
    let new = v.to_bytes().unwrap();
    let old_outer: Value = ciborium::from_reader(&old[6..]).unwrap();
    let old_outer = old_outer.as_array().unwrap().clone();
    let spliced = edit_outer(&new, |a| {
        a[1] = old_outer[1].clone();
        a[2] = old_outer[2].clone();
    });
    let locked = LockedVault::from_bytes(&spliced).unwrap();
    assert!(matches!(
        locked.unlock_login_password(pw, PASSWORD),
        Err(Error::BodyTampered)
    ));
}

#[test]
fn wrapped_key_moved_to_another_slot_does_not_unwrap() {
    let (mut v, ..) = sample();
    let kek = Kek::generate().unwrap();
    let a = v.add_keyslot("a", fido2_kind(), &kek).unwrap();
    let b = v.add_keyslot("b", fido2_kind(), &kek).unwrap();
    // Same KEK, same type: only the slot id in the AAD differs.
    let edited = edit_slots(&v.to_bytes().unwrap(), |slots| {
        let src = slots[2].clone();
        let (Value::Map(src), Value::Map(dst)) = (&src, &mut slots[3]) else {
            panic!()
        };
        for name in ["nonce", "wrapped_mk"] {
            let val = src
                .iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .unwrap()
                .1
                .clone();
            *field(dst, name) = val;
        }
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    // Slot `a` is untouched, but any header edit fails the MAC for every
    // slot; only the moved wrap fails earlier, at unwrap.
    assert!(matches!(locked.unlock(a, &kek), Err(Error::HeaderTampered)));
    assert!(matches!(locked.unlock(b, &kek), Err(Error::UnwrapFailed)));
}

#[test]
fn every_write_is_a_new_generation_and_marks_track_it() {
    let (v, rk, rec, _) = sample();
    let first = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    let second = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(first.mark().generation + 1, second.mark().generation);
    assert_eq!(first.mark().mk_id, second.mark().mk_id);
    assert_eq!(v.mark(), second.mark());
    let reopened = second.unlock_recovery(rec, &rk).unwrap();
    assert_eq!(reopened.mark(), second.mark());
    let third = LockedVault::from_bytes(&reopened.to_bytes().unwrap()).unwrap();
    assert_eq!(third.mark().generation, second.mark().generation + 1);
}

/// The public `mk_id` in the header must match the key that unwrapped it.
/// Otherwise someone holding an old MK could stamp the current `mk_id` on a
/// forged file and pass the high-water check as `Current` or `Newer`.
#[test]
fn a_header_claiming_another_mk_id_is_rejected() {
    let (v, _, _, pw) = sample();
    let (other, ..) = sample();
    let forged = vault::testing::to_bytes_with_mk_id(&v, other.mark().mk_id).unwrap();
    let locked = LockedVault::from_bytes(&forged).unwrap();
    assert_eq!(locked.mark().mk_id, other.mark().mk_id);
    assert!(matches!(
        locked.unlock_login_password(pw, PASSWORD),
        Err(Error::HeaderTampered)
    ));
}

/// End to end through real files: a restored older copy is `RolledBack`.
#[test]
fn restoring_an_older_file_is_detected_as_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let hw = HighWater::new(dir.path().join("state"));
    let (v, ..) = sample();
    hw.record(&v.write(&path).unwrap()).unwrap();
    let old = std::fs::read(&path).unwrap();
    hw.record(&v.write(&path).unwrap()).unwrap();
    std::fs::write(&path, old).unwrap();
    let found = LockedVault::read(&path).unwrap().mark();
    assert!(matches!(
        hw.check(&found).unwrap(),
        Standing::RolledBack { .. }
    ));
}

/// Review finding: someone holding the old MK (an old file plus a removed
/// credential) re-serializes the old vault with a higher generation. It
/// must be flagged `Rekeyed`, not accepted as `Newer`.
#[test]
fn a_replayed_old_mk_with_a_forged_higher_generation_is_rekeyed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let hw = HighWater::new(dir.path().join("state"));
    let (mut v, _, _, pw) = sample();
    let rogue_kek = Kek::generate().unwrap();
    let rogue = v.add_keyslot("rogue", fido2_kind(), &rogue_kek).unwrap();
    hw.record(&v.write(&path).unwrap()).unwrap();
    let old = std::fs::read(&path).unwrap();

    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    v.remove_keyslot(rogue, &[(pw, &pw_kek)]).unwrap();
    hw.record(&v.write(&path).unwrap()).unwrap();

    // The attacker opens the old file with the revoked credential and
    // writes it back several generations ahead.
    let replay = LockedVault::from_bytes(&old)
        .unwrap()
        .unlock(rogue, &rogue_kek)
        .unwrap();
    for _ in 0..3 {
        replay.to_bytes().unwrap();
    }
    let forged = replay.to_bytes().unwrap();
    let found = LockedVault::from_bytes(&forged).unwrap();
    assert!(found.mark().generation > v.mark().generation);
    assert_eq!(hw.check(&found.mark()).unwrap(), Standing::Rekeyed);
    assert_eq!(hw.raise(&found.mark()).unwrap(), Standing::Rekeyed);
    assert_eq!(hw.check(&v.mark()).unwrap(), Standing::Current);
}

#[test]
fn highwater_detects_a_rolled_back_or_replaced_file() {
    let (v, ..) = sample();
    let old = LockedVault::from_bytes(&v.to_bytes().unwrap())
        .unwrap()
        .mark();
    let new = LockedVault::from_bytes(&v.to_bytes().unwrap())
        .unwrap()
        .mark();
    assert_eq!(
        highwater::compare(Some(&new), &old),
        Standing::RolledBack {
            recorded: new.generation
        }
    );
    let (other, ..) = sample();
    let mut replaced = LockedVault::from_bytes(&other.to_bytes().unwrap())
        .unwrap()
        .mark();
    replaced.vault_id = new.vault_id;
    replaced.generation = new.generation;
    assert_eq!(
        highwater::compare(Some(&new), &replaced),
        Standing::Replaced
    );
}

#[test]
fn removing_a_slot_rotates_so_it_cannot_open_later_files() {
    let (mut v, rk, rec, pw) = sample();
    let fido_kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &fido_kek).unwrap();
    let before = v.to_bytes().unwrap();
    let mk_before = v.mark().mk_id;

    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    let rotation = v.remove_keyslot(fido, &[(pw, &pw_kek)]).unwrap();
    assert_eq!(rotation.dropped, vec![fido]);
    let after = v.to_bytes().unwrap();
    assert_ne!(v.mark().mk_id, mk_before);

    // The removed credential still opens the old copy (unavoidable)...
    assert!(
        LockedVault::from_bytes(&before)
            .unwrap()
            .unlock(fido, &fido_kek)
            .is_ok()
    );
    // ...but not the new file: its slot is gone, and splicing the old slot
    // in (same id, old wrap of the old MK) fails authentication.
    let locked_after = LockedVault::from_bytes(&after).unwrap();
    assert!(matches!(
        locked_after.unlock(fido, &fido_kek),
        Err(Error::NoSuchKeyslot(_))
    ));
    let old_slot: Value = {
        let outer: Value = ciborium::from_reader(&before[6..]).unwrap();
        let h: Value =
            ciborium::from_reader(outer.as_array().unwrap()[1].as_bytes().unwrap().as_slice())
                .unwrap();
        let slots = h
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("keyslots"))
            .unwrap()
            .1
            .clone();
        ciborium::from_reader(slots.as_array().unwrap()[2].as_bytes().unwrap().as_slice()).unwrap()
    };
    let spliced = edit_slots(&after, |slots| slots.push(old_slot));
    let err = LockedVault::from_bytes(&spliced)
        .unwrap()
        .unlock(fido, &fido_kek);
    assert!(matches!(
        err,
        Err(Error::HeaderTampered) | Err(Error::UnwrapFailed)
    ));

    // Remaining slots still work, and recovery was re-wrapped without its key.
    assert!(locked_after.unlock_recovery(rec, &rk).is_ok());
    assert!(locked_after.unlock_login_password(pw, PASSWORD).is_ok());
}

#[test]
fn rotation_needs_correct_keks_for_every_non_recovery_slot_and_changes_nothing_on_error() {
    let (mut v, _, rec, pw) = sample();
    let fido_kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &fido_kek).unwrap();
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    let wrong = Kek::generate().unwrap();
    let before: Vec<Vec<u8>> = v.keyslots().map(|s| s.wrapped_mk.clone()).collect();

    assert!(
        matches!(v.rotate_master(&[(pw, &pw_kek)], &[]), Err(Error::MissingKek(id)) if id == fido)
    );
    assert!(
        matches!(v.rotate_master(&[(pw, &pw_kek), (fido, &wrong)], &[]), Err(Error::WrongKek(id)) if id == fido)
    );
    assert!(matches!(
        v.rotate_master(&[], &[Uuid::new_v4()]),
        Err(Error::NoSuchKeyslot(_))
    ));
    assert!(matches!(
        v.rotate_master(&[(pw, &pw_kek), (fido, &fido_kek)], &[rec]),
        Err(Error::RecoveryRequired)
    ));
    let after: Vec<Vec<u8>> = v.keyslots().map(|s| s.wrapped_mk.clone()).collect();
    assert_eq!(before, after);

    v.rotate_master(&[(pw, &pw_kek), (fido, &fido_kek)], &[])
        .unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert!(locked.unlock(fido, &fido_kek).is_ok());
}

#[test]
fn reissuing_the_recovery_key_retires_the_old_one() {
    let (mut v, old_rk, old_rec, pw) = sample();
    let new_rk = RecoveryKey::generate().unwrap();
    let new_rec = v
        .add_recovery_slot("recovery 2", &new_rk.recipient().public_key())
        .unwrap();
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    v.remove_keyslot(old_rec, &[(pw, &pw_kek)]).unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        locked.unlock_recovery(old_rec, &old_rk),
        Err(Error::NoSuchKeyslot(_))
    ));
    assert!(locked.unlock_recovery(new_rec, &new_rk).is_ok());
}

#[test]
fn unknown_slot_types_survive_writes_and_are_dropped_by_rotation() {
    let (v, rk, rec, pw) = sample();
    let future_id = Uuid::new_v4();
    let future = Value::Map(vec![
        (
            Value::Text("id".into()),
            Value::Bytes(future_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("label".into()),
            Value::Text("from aleph 9".into()),
        ),
        (
            Value::Text("kind".into()),
            Value::Map(vec![(
                Value::Text("slot_type".into()),
                Value::Text("quantum-dot".into()),
            )]),
        ),
    ]);
    let future_raw = encode(&future);
    // Simulate a newer aleph having written it: add the slot and re-MAC by
    // round-tripping through a vault that is then re-opened. The MAC check
    // uses the exact bytes, so inject before unlocking and expect
    // HeaderTampered; then check preservation through SlotEntry directly.
    let edited = edit_slots(&v.to_bytes().unwrap(), |slots| slots.push(future.clone()));
    let locked = LockedVault::from_bytes(&edited).unwrap();
    let unknown: Vec<_> = locked.unknown_keyslots().collect();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].slot_type, "quantum-dot");
    assert_eq!(unknown[0].id, Some(future_id));
    assert_eq!(unknown[0].raw, future_raw);
    assert!(matches!(
        locked.unlock_recovery(rec, &rk),
        Err(Error::HeaderTampered)
    ));

    // A legitimately written file with an unknown slot (produced by the
    // real serializer) keeps it byte-for-byte across writes.
    let mut unlocked = LockedVault::from_bytes(&v.to_bytes().unwrap())
        .unwrap()
        .unlock_recovery(rec, &rk)
        .unwrap();
    aleph_core::vault::testing::push_unknown(&mut unlocked, future_raw.clone());
    let rewritten = LockedVault::from_bytes(&unlocked.to_bytes().unwrap()).unwrap();
    let reopened = rewritten.unlock_recovery(rec, &rk).unwrap();
    assert_eq!(reopened.unknown_keyslots().next().unwrap().raw, future_raw);

    let pw_kek = unlocked.login_password_kek(pw, PASSWORD).unwrap();
    let rotation = unlocked.rotate_master(&[(pw, &pw_kek)], &[]).unwrap();
    assert_eq!(rotation.dropped_unknown.len(), 1);
    assert_eq!(unlocked.unknown_keyslots().count(), 0);
}

#[test]
fn rotation_reports_each_drop_once_and_unknown_slots_separately() {
    let (mut v, _, _, pw) = sample();
    let kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &kek).unwrap();
    let future_id = Uuid::new_v4();
    let future = encode(&Value::Map(vec![
        (
            Value::Text("id".into()),
            Value::Bytes(future_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("kind".into()),
            Value::Map(vec![(
                Value::Text("slot_type".into()),
                Value::Text("quantum-dot".into()),
            )]),
        ),
    ]));
    vault::testing::push_unknown(&mut v, future);
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    let rotation = v
        .rotate_master(&[(pw, &pw_kek)], &[fido, fido, future_id])
        .unwrap();
    assert_eq!(rotation.dropped, vec![fido]);
    assert_eq!(rotation.dropped_unknown.len(), 1);
    assert_eq!(rotation.dropped_unknown[0].id, Some(future_id));
}

#[test]
fn generation_overflow_is_an_error_not_a_panic() {
    let (v, ..) = sample();
    vault::testing::set_generation(&v, u64::MAX);
    assert!(matches!(v.to_bytes(), Err(Error::GenerationOverflow)));
}

#[test]
fn backup_copy_contains_only_the_recovery_slot() {
    let (v, rk, rec, pw) = sample();
    let backup = LockedVault::from_bytes(&v.to_backup_bytes().unwrap()).unwrap();
    // Generations start at 1, even for a backup of a never-written vault.
    assert_eq!(backup.mark().generation, 1);
    let kinds: Vec<&str> = backup.keyslots().map(|s| s.kind.type_name()).collect();
    assert_eq!(kinds, vec!["recovery"]);
    assert!(matches!(
        backup.unlock_login_password(pw, PASSWORD),
        Err(Error::NoSuchKeyslot(_))
    ));
    assert_eq!(
        first_secret(&backup.unlock_recovery(rec, &rk).unwrap()),
        b"ghp_secret"
    );
}

/// Flipping any single bit of the file must never yield a successfully
/// unlocked vault. Exhaustive over every bit, not sampled. Unlocks through
/// a raw-KEK slot so ~25k attempts need no Argon2; every other slot's bytes
/// are still covered by the header MAC.
#[test]
fn every_single_bit_flip_is_detected() {
    let (mut v, ..) = sample();
    let kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &kek).unwrap();
    let bytes = v.to_bytes().unwrap();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut b = bytes.clone();
            b[i] ^= 1 << bit;
            let unlocked = LockedVault::from_bytes(&b).and_then(|l| l.unlock(fido, &kek));
            assert!(
                unlocked.is_err(),
                "bit {bit} of byte {i} flipped undetected"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary input must be rejected with an error, never a panic.
    #[test]
    fn arbitrary_bytes_never_panic(tail in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut bytes = b"ALEPH\0".to_vec();
        bytes.extend(tail);
        let _ = LockedVault::from_bytes(&bytes);
    }

    // Each case builds a vault with an X-Wing recipient, hence 64 cases.
    #[test]
    fn body_round_trips(
        secret in prop::collection::vec(any::<u8>(), 0..256),
        label in ".{0,40}",
        collection_label in ".{0,40}",
        attributes in prop::collection::btree_map(".{0,20}", ".{0,40}", 0..6),
    ) {
        let (mut v, rk, rec, _) = sample();
        let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
        let c = v.body_mut().collection_mut(login).unwrap();
        c.label = collection_label;
        c.upsert(
            Item::new(label.clone(), attributes, SecretBytes::new(secret.clone()), "application/octet-stream"),
            false,
        );
        let back = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap().unlock_recovery(rec, &rk).unwrap();
        prop_assert_eq!(back.body(), v.body());
    }
}
```

Replace `crates/aleph-core/tests/write.rs` with:

```rust
mod common;

use std::os::unix::fs::PermissionsExt;

use aleph_core::LockedVault;
use common::*;

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A pre-existing temp file created by some other tool with loose
/// permissions must not hand those permissions to the vault or backup.
#[test]
fn world_readable_leftover_temp_files_do_not_loosen_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let (v, ..) = sample();
    v.write(&path).unwrap();
    for name in ["vault.aleph.tmp", "vault.aleph.bak.tmp"] {
        let p = dir.path().join(name);
        std::fs::write(&p, b"stale").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    v.write(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir.path().join("vault.aleph.bak")), 0o600);
}

#[test]
fn path_without_a_file_name_is_an_error_not_a_panic() {
    let (v, ..) = sample();
    for p in ["..", "/"] {
        assert!(
            matches!(
                v.write(std::path::Path::new(p)),
                Err(aleph_core::Error::Io(_))
            ),
            "{p}"
        );
    }
}

#[test]
fn write_is_atomic_private_and_keeps_a_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aleph").join("vault.aleph");
    let (mut v, rk, rec, _) = sample();

    v.write(&path).unwrap();
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!path.with_file_name("vault.aleph.bak").exists());

    let first = std::fs::read(&path).unwrap();
    v.body_mut().collections[0].label = "Renamed".into();
    v.write(&path).unwrap();

    let bak = path.with_file_name("vault.aleph.bak");
    assert_eq!(std::fs::read(&bak).unwrap(), first);
    assert_eq!(
        std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!path.with_file_name("vault.aleph.tmp").exists());

    let reopened = LockedVault::read(&path)
        .unwrap()
        .unlock_recovery(rec, &rk)
        .unwrap();
    assert_eq!(reopened.body().collections[0].label, "Renamed");
}

#[test]
fn stale_temp_file_from_a_crashed_write_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    std::fs::write(dir.path().join("vault.aleph.tmp"), b"half-written garbage").unwrap();
    let (v, _, _, pw) = sample();
    v.write(&path).unwrap();
    assert!(!dir.path().join("vault.aleph.tmp").exists());
    LockedVault::read(&path)
        .unwrap()
        .unlock_login_password(pw, PASSWORD)
        .unwrap();
}

/// Two writers (say, the daemon and a CLI run against the same file) must
/// not interleave: one could unlink the other's temp file and rename a
/// half-written one over the vault. Every write must succeed and leave an
/// intact vault and backup.
#[test]
fn concurrent_writers_never_corrupt_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let (mut v, _, _, pw) = sample();
    // A larger file widens the window between create and rename.
    v.body_mut().collections[0].label = "x".repeat(256 << 10);
    v.write(&path).unwrap();
    let v = std::sync::Arc::new(v);
    let writers: Vec<_> = (0..8)
        .map(|_| {
            let (v, path) = (v.clone(), path.clone());
            std::thread::spawn(move || (0..5).map(|_| v.write(&path).unwrap()).collect::<Vec<_>>())
        })
        .collect();
    let mut marks: Vec<_> = writers
        .into_iter()
        .flat_map(|w| w.join().unwrap())
        .collect();
    // Every write got its own generation, and the file on disk (and the
    // vault's own mark) is exactly the last one written.
    marks.sort_by_key(|m| m.generation);
    marks.dedup_by_key(|m| m.generation);
    assert_eq!(marks.len(), 40);
    let on_disk = LockedVault::read(&path).unwrap().mark();
    assert_eq!(on_disk, *marks.last().unwrap());
    assert_eq!(v.mark(), on_disk);
    for p in [path.clone(), dir.path().join("vault.aleph.bak")] {
        LockedVault::read(&p)
            .unwrap()
            .unlock_login_password(pw, PASSWORD)
            .unwrap();
    }
}

/// `rename` would replace a symlink (say, into a sync folder) with a
/// regular file, silently breaking the link. Refuse instead.
#[test]
fn a_symlinked_vault_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("synced.aleph");
    let (v, ..) = sample();
    v.write(&target).unwrap();
    let link = dir.path().join("vault.aleph");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(matches!(v.write(&link), Err(aleph_core::Error::Io(_))));
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn a_group_or_world_accessible_vault_directory_is_tightened() {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("aleph");
    std::fs::create_dir(&vault_dir).unwrap();
    std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (v, ..) = sample();
    v.write(&vault_dir.join("vault.aleph")).unwrap();
    assert_eq!(mode(&vault_dir), 0o700);
}

/// A failed write must not advance the vault's generation: otherwise the
/// daemon would record a generation that never reached the disk.
#[test]
fn a_failed_write_does_not_advance_the_generation() {
    let dir = tempfile::tempdir().unwrap();
    // A directory where the vault should be: serialization succeeds, then
    // the write itself fails.
    let path = dir.path().join("vault.aleph");
    std::fs::create_dir(&path).unwrap();
    let (v, ..) = sample();
    let before = v.mark();
    assert!(v.write(&path).is_err());
    assert_eq!(v.mark(), before);
}

/// After a rotation, the first write must not leave the pre-rotation file
/// (which still holds the removed slot and the old MK) in `.bak`.
#[test]
fn the_backup_after_a_rotation_does_not_keep_the_removed_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let (mut v, _, _, pw) = sample();
    let kek = aleph_core::Kek::generate().unwrap();
    let fido = v
        .add_keyslot(
            "yubikey",
            aleph_core::SlotKind::Fido2(aleph_core::Fido2Slot {
                credential_id: vec![1; 16],
                salt: [2; 32],
                uv_required: true,
                pin_required: true,
            }),
            &kek,
        )
        .unwrap();
    v.write(&path).unwrap();
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    v.remove_keyslot(fido, &[(pw, &pw_kek)]).unwrap();
    v.write(&path).unwrap();
    let bak = LockedVault::read(&path.with_file_name("vault.aleph.bak")).unwrap();
    assert!(bak.keyslots().all(|s| s.id != fido));
    // Ordinary writes still keep the previous version as the backup.
    let before = std::fs::read(&path).unwrap();
    v.write(&path).unwrap();
    assert_eq!(
        std::fs::read(path.with_file_name("vault.aleph.bak")).unwrap(),
        before
    );
}
```

Replace `crates/aleph-core/tests/zeroize.rs` with:

```rust
//! Plaintext secrets must not be left behind in freed heap memory when a
//! vault is serialized or unlocked (spec §4 "Memory hygiene").
//!
//! A counting global allocator scans every block as it is freed for a
//! marker placed inside an item's secret. Blocks that held the secret
//! must be zeroized before they are freed, so the marker count stays 0.
//! This binary contains a single test so no other thread allocates.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{Argon2Params, Item, LockedVault, RecoveryKey, SecretBytes, UnlockedVault};

const MARKER: &[u8; 16] = b"\xa5ALEPH-MARKER!\x5a\x5a";

static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);

struct ScanOnFree;

unsafe impl GlobalAlloc for ScanOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(MARKER.len()).any(|w| w == MARKER) {
                HITS.fetch_add(1, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
    // `realloc` is left as the default (alloc + copy + dealloc), so a block
    // abandoned by a growing Vec is scanned too.
}

#[global_allocator]
static ALLOC: ScanOnFree = ScanOnFree;

#[test]
fn serializing_and_unlocking_leave_no_secret_in_freed_memory() {
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::generate().unwrap();
    v.add_recovery_slot("recovery", &rk.recipient().public_key())
        .unwrap();
    let slot = v
        .add_login_password_slot("p", b"pw", Argon2Params::INSECURE_TEST)
        .unwrap();
    let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
    // Enough items that the encoder's buffer must grow several times
    // after the secret has been written into it.
    for i in 0..64 {
        let mut secret = Vec::with_capacity(MARKER.len() + 8);
        secret.extend_from_slice(MARKER);
        secret.extend_from_slice(&(i as u64).to_be_bytes());
        v.body_mut().collection_mut(login).unwrap().upsert(
            Item::new(
                format!("item {i}"),
                BTreeMap::new(),
                SecretBytes::new(secret),
                "text/plain",
            ),
            false,
        );
    }

    ARMED.store(true, Ordering::SeqCst);
    let bytes = v.to_bytes().unwrap();
    let encode_hits = HITS.swap(0, Ordering::SeqCst);
    let unlocked = LockedVault::from_bytes(&bytes)
        .unwrap()
        .unlock_login_password(slot, b"pw")
        .unwrap();
    let decode_hits = HITS.swap(0, Ordering::SeqCst);
    drop(unlocked);
    drop(v);
    let drop_hits = HITS.swap(0, Ordering::SeqCst);
    ARMED.store(false, Ordering::SeqCst);

    assert_eq!(
        (encode_hits, decode_hits, drop_hits),
        (0, 0, 0),
        "freed blocks still holding a secret (encode, decode, drop)"
    );
}
```

Replace `crates/aleph-core/tests/golden.rs` with:

```rust
//! Golden vault files. Every released format version gets a file here,
//! and every later release must still open it. Never regenerate a
//! released version's file; add a new one for a new version. (v1 is not
//! yet released: Plan 1b regenerated it for spec revision 2.)

use std::collections::BTreeMap;
use std::path::PathBuf;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{
    Argon2Params, Item, LockedVault, RecoveryKey, SecretBytes, SlotKind, UnlockedVault,
};

const RECOVERY_KEY: &str = "000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-CC6W";
const PASSWORD: &[u8] = b"aleph golden v1";

fn golden_path(version: u32) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/v{version}.aleph"))
}

#[test]
fn golden_v1_opens_with_recovery_key_and_login_password() {
    let locked = LockedVault::read(&golden_path(1)).expect("golden v1 file present");
    let slots: Vec<_> = locked.keyslots().collect();
    assert_eq!(slots.len(), 2);
    assert!(matches!(slots[0].kind, SlotKind::Recovery(_)));
    assert!(matches!(slots[1].kind, SlotKind::LoginPassword(_)));
    assert_eq!(locked.mark().generation, 1);

    let rk = RecoveryKey::parse(RECOVERY_KEY).unwrap();
    let opened = [
        locked.unlock_recovery(slots[0].id, &rk).unwrap(),
        locked.unlock_login_password(slots[1].id, PASSWORD).unwrap(),
    ];
    for v in &opened {
        assert_eq!(v.mark(), locked.mark());
        let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap();
        assert_eq!(login.label, "Login");
        assert_eq!(login.items.len(), 1);
        let item = &login.items[0];
        assert_eq!(item.label, "golden item");
        assert_eq!(
            item.attributes.get("service").map(String::as_str),
            Some("example")
        );
        assert_eq!(item.secret.expose(), b"golden secret");
    }
}

/// Run once, by hand, when introducing a new format version:
/// `cargo test -p aleph-core --test golden -- --ignored regenerate`
#[test]
#[ignore]
fn regenerate_golden_v1() {
    let path = golden_path(1);
    assert!(
        !path.exists(),
        "refusing to overwrite an existing golden file"
    );
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::parse(RECOVERY_KEY).unwrap();
    v.add_recovery_slot("recovery", &rk.recipient().public_key())
        .unwrap();
    v.add_login_password_slot("login", PASSWORD, Argon2Params::INSECURE_TEST)
        .unwrap();
    let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
    let attrs = BTreeMap::from([("service".to_string(), "example".to_string())]);
    v.body_mut().collection_mut(login).unwrap().upsert(
        Item::new(
            "golden item",
            attrs,
            SecretBytes::new(b"golden secret".to_vec()),
            "text/plain",
        ),
        false,
    );
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, v.to_bytes().unwrap()).unwrap();
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core --test vault`
Expected: the build fails because the new API (`add_recovery_slot`, `unlock_recovery`, `Standing`, `vault::testing`, …) does not exist yet.

- [ ] **Step 3: Implement**

Replace each of the following files with the content shown.

`crates/aleph-core/src/error.rs`:

```rust
use uuid::Uuid;

/// Everything that can go wrong opening, unlocking, or writing a vault.
///
/// Variants deliberately do not distinguish "wrong key" from "tampered
/// ciphertext": an AEAD failure is reported the same way in both cases.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not an aleph vault (bad magic)")]
    BadMagic,

    #[error("vault format version {0} is not supported")]
    UnsupportedVersion(u32),

    #[error("malformed vault: {0}")]
    Malformed(String),

    #[error("no keyslot with id {0}")]
    NoSuchKeyslot(Uuid),

    #[error("keyslot {0} is not the right type for this unlock method")]
    WrongSlotType(Uuid),

    #[error("keyslot could not be unlocked (wrong secret or tampered slot)")]
    UnwrapFailed,

    #[error("vault header failed authentication")]
    HeaderTampered,

    #[error("vault body failed authentication")]
    BodyTampered,

    #[error("vault generation counter would overflow")]
    GenerationOverflow,

    #[error("the vault must keep at least one recovery slot")]
    RecoveryRequired,

    #[error("Argon2 parameters are below the enrollment floor")]
    WeakParams,

    #[error("only TPM and FIDO2 slots can be added with a raw KEK")]
    NotAHardwareSlot,

    #[error("master key rotation needs a KEK for keyslot {0}")]
    MissingKek(Uuid),

    #[error("the KEK supplied for keyslot {0} does not unlock it")]
    WrongKek(Uuid),

    #[error("invalid recovery key: {0}")]
    InvalidRecoveryKey(&'static str),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    /// The slot's Argon2 memory cost exceeds what this machine (RAM plus
    /// swap, within this process's cgroup) can ever provide. Distinct from
    /// `Kdf` so callers can say so rather than report a corrupt slot.
    #[error("key derivation needs {needed_kib} KiB but this system allows at most {limit_kib} KiB")]
    InsufficientMemory { needed_kib: u64, limit_kib: u64 },

    #[error("system randomness unavailable")]
    Random,
}

pub type Result<T> = std::result::Result<T, Error>;
```

`crates/aleph-core/src/key.rs`:

```rust
//! Key types. `KeyHandle` is the only holder of the vault master key and
//! is the seam for v2 privilege separation: callers ask it to wrap, seal,
//! open, and MAC, and never see the key bytes.

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use zeroize::Zeroize;

use crate::crypto::{self, KEY_LEN, MAC_LEN, NONCE_LEN};
use crate::error::{Error, Result};

/// A key-encryption key produced by an unlock method (TPM, FIDO2, Argon2).
pub struct Kek(SecretBox<[u8; KEY_LEN]>);

/// Build a 32-byte secret by filling its (heap, zeroize-on-drop) buffer in
/// place, so it never exists as a by-value array on the stack. The only
/// way secrets of this size are constructed.
pub(crate) fn try_init_secret(
    fill: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<()>,
) -> Result<SecretBox<[u8; KEY_LEN]>> {
    let mut secret = SecretBox::<[u8; KEY_LEN]>::init_with_mut(|_| ());
    fill(secret.expose_secret_mut())?;
    Ok(secret)
}

impl Kek {
    /// Build a KEK in place; see `try_init_secret`.
    pub fn try_init(fill: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<()>) -> Result<Self> {
        try_init_secret(fill).map(Self)
    }

    pub fn generate() -> Result<Self> {
        Self::try_init(|buf| crypto::fill_random(buf))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek([REDACTED])")
    }
}

/// The vault master key, wrapped by a KEK: what a keyslot stores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// One key in its own private, page-locked, never-dumped page.
///
/// A dedicated page per key matters because `mlock` does not nest: if two
/// keys shared a page, unlocking one on drop would unlock the other.
struct LockedPage {
    page: *mut u8,
    len: usize,
}

// SAFETY: the page is exclusively owned; it is only read through `&self`
// and written through `&mut self`, like a `Box<[u8; KEY_LEN]>`.
unsafe impl Send for LockedPage {}
unsafe impl Sync for LockedPage {}

impl LockedPage {
    fn new() -> Result<Self> {
        // SAFETY: sysconf has no preconditions.
        let len = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let len = usize::try_from(len)
            .ok()
            .filter(|&l| l >= KEY_LEN)
            .unwrap_or(4096);
        // SAFETY: anonymous private mapping; the result is checked below.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if page == libc::MAP_FAILED {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: `page` is a valid mapping of `len` bytes. All calls are
        // best effort: failure (e.g. RLIMIT_MEMLOCK exhausted) is not fatal.
        // mlock is not inherited across fork, so WIPEONFORK gives a forked
        // child zeroes rather than an unlocked copy of the key.
        unsafe {
            libc::mlock(page, len);
            libc::madvise(page, len, libc::MADV_DONTDUMP);
            libc::madvise(page, len, libc::MADV_WIPEONFORK);
        }
        Ok(Self {
            page: page.cast(),
            len,
        })
    }

    fn key(&self) -> &[u8; KEY_LEN] {
        // SAFETY: the mapping is at least KEY_LEN bytes, page-aligned, and
        // lives as long as `self`.
        unsafe { &*self.page.cast::<[u8; KEY_LEN]>() }
    }

    fn key_mut(&mut self) -> &mut [u8; KEY_LEN] {
        // SAFETY: as in `key`, with exclusive access through `&mut self`.
        unsafe { &mut *self.page.cast::<[u8; KEY_LEN]>() }
    }

    #[cfg(test)]
    fn as_ptr(&self) -> *const u8 {
        self.page
    }
}

impl Drop for LockedPage {
    fn drop(&mut self) {
        self.key_mut().zeroize();
        // SAFETY: unmapping the mapping created in `new`, exactly once.
        // munmap also releases the page's mlock.
        unsafe {
            libc::munmap(self.page.cast(), self.len);
        }
    }
}

/// Holds the master key in its own page-locked page.
pub struct KeyHandle {
    mk: LockedPage,
}

impl KeyHandle {
    pub fn generate() -> Result<Self> {
        let mut mk = LockedPage::new()?;
        crypto::fill_random(mk.key_mut())?;
        Ok(Self { mk })
    }

    /// Wrap the master key for storage in a keyslot.
    pub fn wrap(&self, kek: &Kek, aad: &[u8]) -> Result<WrappedKey> {
        let (nonce, ciphertext) = crypto::seal(kek.expose(), aad, self.mk.key())?;
        Ok(WrappedKey { nonce, ciphertext })
    }

    /// Whether `kek` opens `wrapped` *and* the key inside is the one with
    /// fingerprint `expected_id`, without mapping a page for it.
    pub fn unwraps_to(kek: &Kek, wrapped: &WrappedKey, aad: &[u8], expected_id: &[u8; 16]) -> bool {
        crypto::open(kek.expose(), &wrapped.nonce, aad, &wrapped.ciphertext)
            .is_some_and(|pt| pt.len() == KEY_LEN && id_of(&pt) == *expected_id)
    }

    /// Whether `kek` opens `wrapped`, without mapping a page for the
    /// result: for checks that discard the key.
    pub fn unwraps(kek: &Kek, wrapped: &WrappedKey, aad: &[u8]) -> bool {
        crypto::open(kek.expose(), &wrapped.nonce, aad, &wrapped.ciphertext)
            .is_some_and(|pt| pt.len() == KEY_LEN)
    }

    /// Recover the master key from a keyslot.
    pub fn unwrap(kek: &Kek, wrapped: &WrappedKey, aad: &[u8]) -> Result<Self> {
        let pt = crypto::open(kek.expose(), &wrapped.nonce, aad, &wrapped.ciphertext)
            .ok_or(Error::UnwrapFailed)?;
        if pt.len() != KEY_LEN {
            return Err(Error::UnwrapFailed);
        }
        let mut mk = LockedPage::new()?;
        mk.key_mut().copy_from_slice(&pt);
        Ok(Self { mk })
    }

    pub fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        crypto::seal(&self.derive(info), aad, plaintext)
    }

    pub fn open(
        &self,
        info: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        crypto::open(&self.derive(info), nonce, aad, ct)
    }

    pub fn mac(&self, info: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
        crypto::hmac_sha256(&self.derive(info), data)
    }

    pub fn verify_mac(&self, info: &[u8], data: &[u8], tag: &[u8; MAC_LEN]) -> bool {
        crypto::hmac_sha256_verify(&self.derive(info), data, tag)
    }

    /// A public fingerprint of this master key: `HKDF(MK, "aleph mk id v1")`
    /// truncated to 16 bytes. Changes whenever MK rotates.
    pub fn id(&self) -> [u8; 16] {
        id_of(self.mk.key())
    }

    fn derive(&self, info: &[u8]) -> zeroize::Zeroizing<[u8; KEY_LEN]> {
        crypto::hkdf(self.mk.key(), info)
    }
}

fn id_of(mk: &[u8]) -> [u8; 16] {
    let okm = crypto::hkdf(mk, b"aleph mk id v1");
    let mut id = [0u8; 16];
    id.copy_from_slice(&okm[..16]);
    id
}

impl std::fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyHandle([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip_preserves_key() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        let back = KeyHandle::unwrap(&kek, &wrapped, b"slot-aad").unwrap();
        // Same master key => same derived MAC.
        assert_eq!(mk.mac(b"x", b"data"), back.mac(b"x", b"data"));
    }

    #[test]
    fn unwrap_fails_with_wrong_kek_or_aad() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        assert!(matches!(
            KeyHandle::unwrap(&Kek::generate().unwrap(), &wrapped, b"slot-aad"),
            Err(Error::UnwrapFailed)
        ));
        assert!(matches!(
            KeyHandle::unwrap(&kek, &wrapped, b"other-aad"),
            Err(Error::UnwrapFailed)
        ));
    }

    #[test]
    fn id_is_stable_per_key_and_differs_between_keys() {
        let a = KeyHandle::generate().unwrap();
        let b = KeyHandle::generate().unwrap();
        assert_eq!(a.id(), a.id());
        assert_ne!(a.id(), b.id());
        // The fingerprint is not the key: it cannot unwrap anything.
        assert_ne!(a.id(), [0u8; 16]);
    }

    #[test]
    fn unwraps_to_also_checks_which_master_key_it_is() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        assert!(KeyHandle::unwraps_to(&kek, &wrapped, b"slot-aad", &mk.id()));
        let other = KeyHandle::generate().unwrap();
        assert!(!KeyHandle::unwraps_to(
            &kek,
            &wrapped,
            b"slot-aad",
            &other.id()
        ));
        assert!(!KeyHandle::unwraps_to(
            &kek,
            &wrapped,
            b"other-aad",
            &mk.id()
        ));
    }

    #[test]
    fn unwraps_agrees_with_unwrap() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        assert!(KeyHandle::unwraps(&kek, &wrapped, b"slot-aad"));
        assert!(!KeyHandle::unwraps(&kek, &wrapped, b"other-aad"));
        assert!(!KeyHandle::unwraps(
            &Kek::generate().unwrap(),
            &wrapped,
            b"slot-aad"
        ));
    }

    /// Address of the master key bytes (test-only view of internals).
    fn key_addr(k: &KeyHandle) -> usize {
        k.mk.as_ptr() as usize
    }

    /// `Locked:` (kB) of the mapping in /proc/self/smaps containing `addr`.
    fn locked_kib(addr: usize) -> u64 {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut in_range = false;
        for line in smaps.lines() {
            let first = line.split_whitespace().next().unwrap_or("");
            if let Some((lo, hi)) = first.split_once('-')
                && let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            {
                in_range = (lo..hi).contains(&addr);
            } else if in_range && let Some(rest) = line.strip_prefix("Locked:") {
                return rest.trim().trim_end_matches("kB").trim().parse().unwrap();
            }
        }
        panic!("no mapping contains {addr:#x}");
    }

    /// Whether this process may mlock another page, probed on a scratch
    /// mapping so a key that is merely *not* locked still fails the test.
    fn mlock_is_permitted() -> bool {
        let len = 4096;
        // SAFETY: a fresh anonymous mapping, unmapped before returning.
        unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(p, libc::MAP_FAILED);
            let ok = libc::mlock(p, len) == 0;
            libc::munmap(p, len);
            ok
        }
    }

    /// mlock does not nest: unlocking one key's page must never unlock a
    /// page that another live key still relies on.
    #[test]
    fn dropping_one_key_keeps_another_key_locked() {
        let a = KeyHandle::generate().unwrap();
        let b = KeyHandle::generate().unwrap();
        if locked_kib(key_addr(&b)) == 0 && !mlock_is_permitted() {
            // mlock is best effort by design; e.g. RLIMIT_MEMLOCK = 0 in CI.
            eprintln!("skipping: this environment does not permit mlock");
            return;
        }
        assert!(locked_kib(key_addr(&b)) > 0, "key not locked at all");
        drop(a);
        assert!(
            locked_kib(key_addr(&b)) > 0,
            "live key unlocked by dropping another"
        );
    }

    /// A forked child (the daemon spawning a prompter or swtpm) must not
    /// inherit a copy of the master key: its copy would not be mlocked.
    #[test]
    fn forked_child_sees_a_zeroed_key() {
        let k = KeyHandle::generate().unwrap();
        assert_ne!(k.mk.key(), &[0u8; KEY_LEN]);
        // SAFETY: the child only reads memory and calls `_exit`, both
        // async-signal-safe, so forking a multithreaded test is sound.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let wiped = k.mk.key() == &[0u8; KEY_LEN];
            unsafe { libc::_exit(if wiped { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waiting on the child forked above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        assert_eq!(libc::WEXITSTATUS(status), 0, "child saw the master key");
    }

    /// The daemon shares the unlocked vault across async tasks; the raw
    /// page pointer must not silently make `KeyHandle` thread-bound.
    #[test]
    fn key_handle_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KeyHandle>();
        assert_send_sync::<crate::vault::UnlockedVault>();
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(
            format!("{:?}", KeyHandle::generate().unwrap()),
            "KeyHandle([REDACTED])"
        );
        assert_eq!(format!("{:?}", Kek::generate().unwrap()), "Kek([REDACTED])");
    }
}
```

`crates/aleph-core/src/keyslot.rs`:

```rust
//! Keyslots: one wrapped copy of the master key per unlock method.
//!
//! `aleph-core` stores slot parameters and does the wrapping. Producing a
//! hardware slot's KEK (TPM, FIDO2) is `aleph-unlock`'s job. The recovery
//! slot (X-Wing) and the login-password slot (Argon2id) are handled here,
//! so recovery works without any hardware.
//!
//! In the header each keyslot is stored as its own CBOR byte string. A slot
//! whose `slot_type` this build does not know is kept as those exact bytes
//! and re-emitted unchanged (spec §4, forward compatibility).

use ciborium::Value;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::NONCE_LEN;
use crate::error::{Error, Result};
use crate::kdf::{Argon2Params, SALT_LEN};
use crate::key::WrappedKey;

/// A 32-byte random KEK sealed by `aleph-tpmd`, bound to the caller's uid
/// and the login password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmSlot {
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    /// Per-slot salt for the auth-value derivation.
    #[serde(with = "serde_bytes")]
    pub auth_salt: [u8; 16],
    /// Name of the parent key the object was sealed under; `aleph-tpmd`
    /// verifies it before salting a session with that key.
    #[serde(with = "serde_bytes")]
    pub srk_name: Vec<u8>,
}

/// A FIDO2 `hmac-secret` credential. The RP ID is the constant `"aleph"`
/// and deliberately not stored (it would be read from an unauthenticated
/// header before unlock).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fido2Slot {
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub salt: [u8; 32],
    pub uv_required: bool,
    pub pin_required: bool,
}

/// The recovery recipient: MK is wrapped under `HKDF(ss)`, where `ss` is
/// encapsulated to `xwing_pk`. Re-wrapping needs only the public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySlot {
    #[serde(with = "serde_bytes")]
    pub xwing_pk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub xwing_ct: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Argon2Slot {
    #[serde(with = "serde_bytes")]
    pub salt: [u8; SALT_LEN],
    pub params: Argon2Params,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "slot_type", rename_all = "kebab-case")]
pub enum SlotKind {
    Tpm(TpmSlot),
    Fido2(Fido2Slot),
    Recovery(RecoverySlot),
    LoginPassword(Argon2Slot),
}

/// The `slot_type` strings this build understands.
pub const KNOWN_SLOT_TYPES: [&str; 4] = ["tpm", "fido2", "recovery", "login-password"];

impl SlotKind {
    /// Stable name, bound into the wrapped key's AAD.
    pub fn type_name(&self) -> &'static str {
        match self {
            SlotKind::Tpm(_) => "tpm",
            SlotKind::Fido2(_) => "fido2",
            SlotKind::Recovery(_) => "recovery",
            SlotKind::LoginPassword(_) => "login-password",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keyslot {
    pub id: Uuid,
    pub label: String,
    pub created: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")]
    pub wrapped_mk: Vec<u8>,
    pub kind: SlotKind,
}

impl Keyslot {
    pub fn wrapped(&self) -> WrappedKey {
        WrappedKey {
            nonce: self.nonce,
            ciphertext: self.wrapped_mk.clone(),
        }
    }

    /// AAD binding a wrapped master key to this vault, this slot id, and
    /// this slot type, so it cannot be transplanted elsewhere.
    pub fn aad(vault_id: Uuid, slot_id: Uuid, kind: &SlotKind) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + 16);
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(slot_id.as_bytes());
        aad.extend_from_slice(kind.type_name().as_bytes());
        aad
    }
}

/// A keyslot of a type this build does not understand, kept verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownSlot {
    /// The slot's exact encoded bytes, re-emitted unchanged on write.
    pub raw: Vec<u8>,
    /// Best-effort metadata for display; `None` if absent or malformed.
    pub id: Option<Uuid>,
    pub label: Option<String>,
    pub slot_type: String,
}

/// One entry of the header's keyslot list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotEntry {
    Known(Keyslot),
    Unknown(UnknownSlot),
}

impl SlotEntry {
    /// Decode one slot's bytes. A known `slot_type` must parse strictly
    /// (unknown fields are an error); an unknown one is preserved.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let malformed = |m: &str| Error::Malformed(format!("keyslot: {m}"));
        let mut cursor = std::io::Cursor::new(raw);
        let value: Value =
            ciborium::from_reader(&mut cursor).map_err(|e| malformed(&e.to_string()))?;
        if cursor.position() != raw.len() as u64 {
            return Err(malformed("trailing data"));
        }
        let map = value.as_map().ok_or_else(|| malformed("not a map"))?;
        let field = |name: &str| {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v)
        };
        let slot_type = field("kind")
            .and_then(Value::as_map)
            .and_then(|kind| kind.iter().find(|(k, _)| k.as_text() == Some("slot_type")))
            .and_then(|(_, v)| v.as_text())
            .ok_or_else(|| malformed("missing kind.slot_type"))?
            .to_string();
        if KNOWN_SLOT_TYPES.contains(&slot_type.as_str()) {
            let slot: Keyslot = value
                .deserialized()
                .map_err(|e| malformed(&e.to_string()))?;
            return Ok(SlotEntry::Known(slot));
        }
        Ok(SlotEntry::Unknown(UnknownSlot {
            raw: raw.to_vec(),
            id: field("id")
                .and_then(Value::as_bytes)
                .and_then(|b| Uuid::from_slice(b).ok()),
            label: field("label").and_then(Value::as_text).map(str::to_string),
            slot_type,
        }))
    }

    /// Encode for the header: known slots freshly, unknown ones verbatim.
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            SlotEntry::Known(slot) => {
                let mut buf = Vec::new();
                ciborium::into_writer(slot, &mut buf)
                    .map_err(|e| Error::Malformed(e.to_string()))?;
                Ok(buf)
            }
            SlotEntry::Unknown(u) => Ok(u.raw.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_slot() -> Keyslot {
        Keyslot {
            id: Uuid::new_v4(),
            label: "recovery".into(),
            created: 1,
            nonce: [0; NONCE_LEN],
            wrapped_mk: vec![1, 2, 3],
            kind: SlotKind::Recovery(RecoverySlot {
                xwing_pk: vec![4; 8],
                xwing_ct: vec![5; 8],
            }),
        }
    }

    fn encode_value(v: &Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).unwrap();
        buf
    }

    #[test]
    fn aad_differs_by_vault_slot_and_type() {
        let (v, s) = (Uuid::new_v4(), Uuid::new_v4());
        let rec = recovery_slot().kind;
        let a = Keyslot::aad(v, s, &rec);
        assert_ne!(a, Keyslot::aad(Uuid::new_v4(), s, &rec));
        assert_ne!(a, Keyslot::aad(v, Uuid::new_v4(), &rec));
        let lp = SlotKind::LoginPassword(Argon2Slot {
            salt: [0; SALT_LEN],
            params: Argon2Params::INSECURE_TEST,
        });
        assert_ne!(a, Keyslot::aad(v, s, &lp));
    }

    #[test]
    fn known_slot_round_trips_and_is_tagged() {
        let slot = recovery_slot();
        let entry = SlotEntry::Known(slot.clone());
        let raw = entry.encode().unwrap();
        assert_eq!(SlotEntry::decode(&raw).unwrap(), entry);
        let value: Value = ciborium::from_reader(raw.as_slice()).unwrap();
        let kind = value
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("kind"))
            .unwrap();
        let tag = kind
            .1
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("slot_type"))
            .unwrap();
        assert_eq!(tag.1.as_text(), Some("recovery"));
    }

    #[test]
    fn unknown_slot_type_is_preserved_byte_for_byte() {
        let id = Uuid::new_v4();
        let v = Value::Map(vec![
            (
                Value::Text("id".into()),
                Value::Bytes(id.as_bytes().to_vec()),
            ),
            (Value::Text("label".into()), Value::Text("future".into())),
            (
                Value::Text("kind".into()),
                Value::Map(vec![
                    (
                        Value::Text("slot_type".into()),
                        Value::Text("quantum-dot".into()),
                    ),
                    (Value::Text("whatever".into()), Value::Integer(7.into())),
                ]),
            ),
        ]);
        let raw = encode_value(&v);
        let entry = SlotEntry::decode(&raw).unwrap();
        let SlotEntry::Unknown(u) = &entry else {
            panic!("expected unknown")
        };
        assert_eq!(u.slot_type, "quantum-dot");
        assert_eq!(u.id, Some(id));
        assert_eq!(u.label.as_deref(), Some("future"));
        assert_eq!(entry.encode().unwrap(), raw);
    }

    #[test]
    fn known_slot_type_with_unknown_field_is_rejected() {
        let slot = recovery_slot();
        let raw = SlotEntry::Known(slot).encode().unwrap();
        let mut v: Value = ciborium::from_reader(raw.as_slice()).unwrap();
        v.as_map_mut()
            .unwrap()
            .push((Value::Text("surprise".into()), Value::Bool(true)));
        assert!(matches!(
            SlotEntry::decode(&encode_value(&v)),
            Err(Error::Malformed(_))
        ));

        // Also inside `kind`, where the tag is stripped before the variant
        // struct sees the remaining fields.
        let mut v: Value = ciborium::from_reader(raw.as_slice()).unwrap();
        let kind = v
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("kind"))
            .unwrap();
        kind.1
            .as_map_mut()
            .unwrap()
            .push((Value::Text("uv_marker".into()), Value::Bool(true)));
        assert!(matches!(
            SlotEntry::decode(&encode_value(&v)),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn trailing_bytes_after_a_slot_are_malformed() {
        let mut raw = SlotEntry::Known(recovery_slot()).encode().unwrap();
        raw.push(0);
        assert!(matches!(SlotEntry::decode(&raw), Err(Error::Malformed(_))));
    }

    fn arb_value() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        let leaf = prop_oneof![
            any::<i64>().prop_map(|i| Value::Integer(i.into())),
            any::<bool>().prop_map(Value::Bool),
            ".{0,8}".prop_map(Value::Text),
            proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
            Just(Value::Null),
        ];
        leaf.prop_recursive(3, 16, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                proptest::collection::vec((".{0,8}".prop_map(Value::Text), inner), 0..4)
                    .prop_map(Value::Map),
            ]
        })
    }

    proptest::proptest! {
        /// Slot maps with plausible structure (known and unknown types,
        /// arbitrary field values) never panic, and whatever decodes as a
        /// known slot re-encodes to something that decodes identically.
        #[test]
        fn structured_slot_maps_never_panic(
            slot_type in proptest::prop_oneof![
                proptest::strategy::Just("tpm".to_string()),
                proptest::strategy::Just("fido2".to_string()),
                proptest::strategy::Just("recovery".to_string()),
                proptest::strategy::Just("login-password".to_string()),
                "[a-z-]{0,12}",
            ],
            kind_fields in proptest::collection::vec((
                proptest::prop_oneof![
                    proptest::strategy::Just("public".to_string()),
                    proptest::strategy::Just("salt".to_string()),
                    proptest::strategy::Just("xwing_pk".to_string()),
                    ".{0,10}",
                ],
                arb_value(),
            ), 0..6),
            top in proptest::collection::vec((
                proptest::prop_oneof![
                    proptest::strategy::Just("id".to_string()),
                    proptest::strategy::Just("nonce".to_string()),
                    proptest::strategy::Just("wrapped_mk".to_string()),
                    ".{0,10}",
                ],
                arb_value(),
            ), 0..7),
        ) {
            let mut kind = vec![(Value::Text("slot_type".into()), Value::Text(slot_type))];
            kind.extend(kind_fields.into_iter().map(|(k, v)| (Value::Text(k), v)));
            let mut map: Vec<(Value, Value)> =
                top.into_iter().map(|(k, v)| (Value::Text(k), v)).collect();
            map.push((Value::Text("kind".into()), Value::Map(kind)));
            if let Ok(entry) = SlotEntry::decode(&encode_value(&Value::Map(map))) {
                let again = SlotEntry::decode(&entry.encode().unwrap()).unwrap();
                proptest::prop_assert_eq!(again, entry);
            }
        }
    }

    #[test]
    fn slot_without_a_type_is_malformed() {
        let v = Value::Map(vec![(Value::Text("id".into()), Value::Bytes(vec![0; 16]))]);
        assert!(matches!(
            SlotEntry::decode(&encode_value(&v)),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            SlotEntry::decode(&[0xff]),
            Err(Error::Malformed(_))
        ));
    }
}
```

`crates/aleph-core/src/vault.rs`:

~~~rust
//! The vault file.
//!
//! ```text
//! file       = MAGIC ‖ CBOR([format_version, header, header_mac, body_nonce, body_ct])
//! header     = CBOR({ vault_id, generation, mk_id, keyslots: [bstr(CBOR(slot)), …] })
//!                                                       (stored as a byte string)
//! header_mac = HMAC(HKDF(MK, "aleph header v1"), MAGIC ‖ be32(format_version) ‖ header)
//! body_ct    = XChaCha20-Poly1305(HKDF(MK, "aleph body v1"), CBOR(Body),
//!                                 aad = vault_id ‖ be32(format_version) ‖ header_mac)
//! ```
//!
//! - The MAC covers the header's exact stored bytes, never a re-encoding,
//!   so it cannot be affected by CBOR encoding choices. The outer container
//!   is an array, so there are no field names to alter.
//! - The body's AAD includes `header_mac`, binding each body to the exact
//!   header it was written with.
//! - `generation` rises on every write, and `mk_id` fingerprints MK. With a
//!   high-water mark kept outside the file (`highwater`), they reveal a
//!   rolled-back or replaced file.
//!
//! Removing a keyslot rotates MK (spec §4, "Rotation and revocation"), so a
//! removed credential plus an old copy of the file never opens a newer one.
//!
//! A `LockedVault` is the parsed file with nothing decrypted. Unlocking
//! one keyslot yields an `UnlockedVault`, which owns the master key and the
//! plaintext body and can re-serialize itself.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ciborium::Value;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, MAC_LEN, NONCE_LEN};
use crate::error::{Error, Result};
use crate::highwater::Mark;
use crate::kdf::{self, Argon2Params};
use crate::key::{Kek, KeyHandle};
use crate::keyslot::{Argon2Slot, Keyslot, RecoverySlot, SlotEntry, SlotKind, UnknownSlot};
use crate::model::{Body, now};
use crate::recovery::RecoveryKey;
use crate::xwing;

pub const MAGIC: &[u8; 6] = b"ALEPH\0";
pub const FORMAT_VERSION: u32 = 1;

const HEADER_MAC_INFO: &[u8] = b"aleph header v1";
const BODY_KEY_INFO: &[u8] = b"aleph body v1";
const RECOVERY_KEK_INFO: &[u8] = b"aleph recovery v1";

#[derive(Serialize, Deserialize)]
struct VaultFile(
    u32,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] [u8; MAC_LEN],
    #[serde(with = "serde_bytes")] [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    vault_id: Uuid,
    generation: u64,
    #[serde(with = "serde_bytes")]
    mk_id: [u8; 16],
    keyslots: Vec<serde_bytes::ByteBuf>,
}

fn mac_input(format_version: u32, header: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MAGIC.len() + 4 + header.len());
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&format_version.to_be_bytes());
    buf.extend_from_slice(header);
    buf
}

fn body_aad(vault_id: Uuid, format_version: u32, header_mac: &[u8; MAC_LEN]) -> Vec<u8> {
    let mut aad = vault_id.as_bytes().to_vec();
    aad.extend_from_slice(&format_version.to_be_bytes());
    aad.extend_from_slice(header_mac);
    aad
}

/// Strict CBOR decode: exactly one item, no trailing bytes, and (via
/// `check`) any structural constraint serde would silently tolerate.
fn decode_strict<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    check: impl FnOnce(&Value) -> bool,
) -> Result<T> {
    let malformed = |e: &dyn std::fmt::Display| Error::Malformed(e.to_string());
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor).map_err(|e| malformed(&e))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::Malformed("trailing data after CBOR item".into()));
    }
    if !check(&value) {
        return Err(Error::Malformed("unexpected CBOR structure".into()));
    }
    value.deserialized().map_err(|e| malformed(&e))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    decode_strict(bytes, |_| true)
}

fn encode<T: Serialize>(value: &T, out: &mut Vec<u8>) -> Result<()> {
    ciborium::into_writer(value, out).map_err(|e| Error::Malformed(e.to_string()))
}

/// Decode the plaintext body straight into `Body`: no intermediate
/// `ciborium::Value`, whose byte and text buffers would be freed without
/// being zeroized. Still rejects trailing bytes.
fn decode_body(bytes: &[u8]) -> Result<Body> {
    let mut cursor = std::io::Cursor::new(bytes);
    let body: Body =
        ciborium::from_reader(&mut cursor).map_err(|e| Error::Malformed(e.to_string()))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::Malformed("trailing data after CBOR item".into()));
    }
    Ok(body)
}

/// Counts bytes without storing them, to size the body buffer exactly.
struct CountingWriter(usize);

impl std::io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Encode the plaintext body into a buffer allocated once at its exact
/// size, so a growing `Vec` never frees a block holding plaintext.
fn encode_body(body: &Body) -> Result<Zeroizing<Vec<u8>>> {
    let malformed = |e: ciborium::ser::Error<std::io::Error>| Error::Malformed(e.to_string());
    let mut counter = CountingWriter(0);
    ciborium::into_writer(body, &mut counter).map_err(malformed)?;
    let mut pt = Zeroizing::new(Vec::with_capacity(counter.0));
    ciborium::into_writer(body, &mut *pt).map_err(malformed)?;
    debug_assert_eq!(pt.len(), pt.capacity());
    Ok(pt)
}

/// `KEK = HKDF(X-Wing shared secret, "aleph recovery v1")`.
fn recovery_kek(ss: &[u8; 32]) -> Result<Kek> {
    Kek::try_init(|buf| {
        buf.copy_from_slice(crypto::hkdf(ss, RECOVERY_KEK_INFO).as_slice());
        Ok(())
    })
}

fn known(entries: &[SlotEntry]) -> impl Iterator<Item = &Keyslot> {
    entries.iter().filter_map(|e| match e {
        SlotEntry::Known(k) => Some(k),
        SlotEntry::Unknown(_) => None,
    })
}

fn unknown(entries: &[SlotEntry]) -> impl Iterator<Item = &UnknownSlot> {
    entries.iter().filter_map(|e| match e {
        SlotEntry::Unknown(u) => Some(u),
        SlotEntry::Known(_) => None,
    })
}

fn find(entries: &[SlotEntry], id: Uuid) -> Result<&Keyslot> {
    known(entries)
        .find(|s| s.id == id)
        .ok_or(Error::NoSuchKeyslot(id))
}

pub struct LockedVault {
    file: VaultFile,
    vault_id: Uuid,
    generation: u64,
    mk_id: [u8; 16],
    entries: Vec<SlotEntry>,
}

impl LockedVault {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let rest = bytes
            .strip_prefix(MAGIC.as_slice())
            .ok_or(Error::BadMagic)?;
        // serde would accept a longer array and ignore the extra elements.
        let file: VaultFile = decode_strict(rest, |v| v.as_array().is_some_and(|a| a.len() == 5))?;
        if file.0 != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(file.0));
        }
        // Parsed before authentication so callers can list keyslots while
        // locked; `unlock` authenticates these exact bytes.
        let header: Header = decode(&file.1)?;
        let entries = header
            .keyslots
            .iter()
            .map(|raw| SlotEntry::decode(raw))
            .collect::<Result<_>>()?;
        Ok(Self {
            vault_id: header.vault_id,
            generation: header.generation,
            mk_id: header.mk_id,
            entries,
            file,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        Self::from_bytes(&fs::read(path)?)
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Slot metadata, readable while locked so callers can pick a method.
    /// Not yet authenticated: treat as untrusted until an unlock succeeds.
    pub fn keyslots(&self) -> impl Iterator<Item = &Keyslot> {
        known(&self.entries)
    }

    /// Slots of types this build does not understand (not unlockable).
    pub fn unknown_keyslots(&self) -> impl Iterator<Item = &UnknownSlot> {
        unknown(&self.entries)
    }

    /// The file's high-water identity. Unauthenticated until unlock.
    pub fn mark(&self) -> Mark {
        Mark {
            vault_id: self.vault_id,
            generation: self.generation,
            mk_id: self.mk_id,
        }
    }

    /// Unlock the login-password slot by running Argon2id over `password`
    /// with the slot's stored parameters.
    pub fn unlock_login_password(&self, slot_id: Uuid, password: &[u8]) -> Result<UnlockedVault> {
        let kek = login_password_kek(&self.entries, slot_id, password)?;
        self.unlock(slot_id, &kek)
    }

    /// Unlock a recovery slot with the recovery key.
    pub fn unlock_recovery(&self, slot_id: Uuid, key: &RecoveryKey) -> Result<UnlockedVault> {
        let slot = find(&self.entries, slot_id)?;
        let SlotKind::Recovery(r) = &slot.kind else {
            return Err(Error::WrongSlotType(slot_id));
        };
        let recipient = key.recipient();
        // Faster, clearer failure for a mistyped-but-valid key: its public
        // key will not match. (The AEAD would reject it anyway.)
        if recipient.public_key() != r.xwing_pk {
            return Err(Error::UnwrapFailed);
        }
        let ss = recipient.decapsulate(&r.xwing_ct)?;
        self.unlock(slot_id, &recovery_kek(&ss)?)
    }

    /// Unwrap the master key from one slot, authenticate the header, and
    /// decrypt the body.
    pub fn unlock(&self, slot_id: Uuid, kek: &Kek) -> Result<UnlockedVault> {
        let VaultFile(version, header_bytes, header_mac, body_nonce, body_ct) = &self.file;
        let slot = find(&self.entries, slot_id)?;
        let key = KeyHandle::unwrap(
            kek,
            &slot.wrapped(),
            &Keyslot::aad(self.vault_id, slot.id, &slot.kind),
        )?;
        if !key.verify_mac(
            HEADER_MAC_INFO,
            &mac_input(*version, header_bytes),
            header_mac,
        ) || key.id() != self.mk_id
        {
            return Err(Error::HeaderTampered);
        }
        let pt = key
            .open(
                BODY_KEY_INFO,
                body_nonce,
                &body_aad(self.vault_id, *version, header_mac),
                body_ct,
            )
            .ok_or(Error::BodyTampered)?;
        let body = decode_body(&pt)?;
        Ok(UnlockedVault {
            vault_id: self.vault_id,
            generation: AtomicU64::new(self.generation),
            rotated: AtomicBool::new(false),
            entries: self.entries.clone(),
            key,
            body,
        })
    }
}

fn login_password_kek(entries: &[SlotEntry], slot_id: Uuid, password: &[u8]) -> Result<Kek> {
    let slot = find(entries, slot_id)?;
    let SlotKind::LoginPassword(a) = &slot.kind else {
        return Err(Error::WrongSlotType(slot_id));
    };
    kdf::derive_kek(password, &a.salt, &a.params)
}

/// What a rotation did besides re-wrapping.
#[derive(Debug, Default)]
pub struct Rotation {
    /// Slots removed because the caller asked (`drop`).
    pub dropped: Vec<Uuid>,
    /// Slots of unknown types, removed because they cannot be re-wrapped.
    pub dropped_unknown: Vec<UnknownSlot>,
}

pub struct UnlockedVault {
    vault_id: Uuid,
    /// The generation last read or written; the next write uses one more.
    generation: AtomicU64,
    /// MK rotated since the last write: that write must not leave the
    /// pre-rotation file (old MK, removed slots) behind as `.bak`.
    rotated: AtomicBool,
    entries: Vec<SlotEntry>,
    key: KeyHandle,
    body: Body,
}

impl UnlockedVault {
    /// A new vault with a fresh master key, the default body, and no
    /// keyslots. Add a recovery slot (required) before serializing.
    pub fn create() -> Result<Self> {
        Ok(Self {
            vault_id: Uuid::new_v4(),
            generation: AtomicU64::new(0),
            rotated: AtomicBool::new(false),
            entries: Vec::new(),
            key: KeyHandle::generate()?,
            body: Body::default(),
        })
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    pub fn keyslots(&self) -> impl Iterator<Item = &Keyslot> {
        known(&self.entries)
    }

    pub fn unknown_keyslots(&self) -> impl Iterator<Item = &UnknownSlot> {
        unknown(&self.entries)
    }

    /// Identity of the last-read or last-written generation.
    pub fn mark(&self) -> Mark {
        Mark {
            vault_id: self.vault_id,
            generation: self.generation.load(Ordering::SeqCst),
            mk_id: self.key.id(),
        }
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    fn push(&mut self, label: String, kind: SlotKind, kek: &Kek) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let wrapped = self
            .key
            .wrap(kek, &Keyslot::aad(self.vault_id, id, &kind))?;
        self.entries.push(SlotEntry::Known(Keyslot {
            id,
            label,
            created: now(),
            nonce: wrapped.nonce,
            wrapped_mk: wrapped.ciphertext,
            kind,
        }));
        Ok(id)
    }

    /// Add a TPM or FIDO2 slot whose KEK the caller produced
    /// (`aleph-unlock`). Returns the slot id.
    pub fn add_keyslot(
        &mut self,
        label: impl Into<String>,
        kind: SlotKind,
        kek: &Kek,
    ) -> Result<Uuid> {
        if !matches!(kind, SlotKind::Tpm(_) | SlotKind::Fido2(_)) {
            return Err(Error::NotAHardwareSlot);
        }
        self.push(label.into(), kind, kek)
    }

    /// Add a recovery slot for the recipient `public_key` (from
    /// `RecoveryKey::recipient().public_key()`). Needs no secret.
    pub fn add_recovery_slot(
        &mut self,
        label: impl Into<String>,
        public_key: &[u8],
    ) -> Result<Uuid> {
        let (ct, ss) = xwing::encapsulate(public_key)?;
        let kind = SlotKind::Recovery(RecoverySlot {
            xwing_pk: public_key.to_vec(),
            xwing_ct: ct,
        });
        self.push(label.into(), kind, &recovery_kek(&ss)?)
    }

    /// Add a login-password slot (machines without a TPM). `params` must
    /// meet `Argon2Params::LOGIN_PASSWORD_FLOOR`.
    pub fn add_login_password_slot(
        &mut self,
        label: impl Into<String>,
        password: &[u8],
        params: Argon2Params,
    ) -> Result<Uuid> {
        if !params.enrollable() {
            return Err(Error::WeakParams);
        }
        let salt = crypto::random_array()?;
        let kek = kdf::derive_kek(password, &salt, &params)?;
        self.push(
            label.into(),
            SlotKind::LoginPassword(Argon2Slot { salt, params }),
            &kek,
        )
    }

    /// The KEK of a login-password slot, for supplying to a rotation.
    pub fn login_password_kek(&self, slot_id: Uuid, password: &[u8]) -> Result<Kek> {
        login_password_kek(&self.entries, slot_id, password)
    }

    /// Remove a keyslot and rotate MK, so the removed credential cannot
    /// open any file written from now on. `keks` must cover every remaining
    /// TPM, FIDO2, and login-password slot (see `rotate_master`).
    pub fn remove_keyslot(&mut self, id: Uuid, keks: &[(Uuid, &Kek)]) -> Result<Rotation> {
        self.rotate_master(keks, &[id])
    }

    /// Replace MK and re-wrap every slot. Slots in `drop` are removed
    /// instead; slots of unknown type are removed because they cannot be
    /// re-wrapped. Recovery slots are re-wrapped to their public key and
    /// need no KEK. Every other remaining slot needs its correct KEK in
    /// `keks`, each proven by unwrapping before anything changes: on any
    /// error the vault is untouched. At least one recovery slot must remain.
    pub fn rotate_master(&mut self, keks: &[(Uuid, &Kek)], drop: &[Uuid]) -> Result<Rotation> {
        for id in drop {
            let present = self.entries.iter().any(|e| match e {
                SlotEntry::Known(k) => k.id == *id,
                SlotEntry::Unknown(u) => u.id == Some(*id),
            });
            if !present {
                return Err(Error::NoSuchKeyslot(*id));
            }
        }
        let mut dropped: Vec<Uuid> = known(&self.entries)
            .filter(|s| drop.contains(&s.id))
            .map(|s| s.id)
            .collect();
        dropped.sort();
        dropped.dedup();
        let keep: Vec<&Keyslot> = known(&self.entries)
            .filter(|s| !drop.contains(&s.id))
            .collect();
        if !keep.iter().any(|s| matches!(s.kind, SlotKind::Recovery(_))) {
            return Err(Error::RecoveryRequired);
        }
        for slot in keep
            .iter()
            .filter(|s| !matches!(s.kind, SlotKind::Recovery(_)))
        {
            let (_, kek) = keks
                .iter()
                .find(|(id, _)| *id == slot.id)
                .ok_or(Error::MissingKek(slot.id))?;
            if !KeyHandle::unwraps_to(
                kek,
                &slot.wrapped(),
                &Keyslot::aad(self.vault_id, slot.id, &slot.kind),
                &self.key.id(),
            ) {
                return Err(Error::WrongKek(slot.id));
            }
        }

        let new_key = KeyHandle::generate()?;
        let mut rewrapped = Vec::with_capacity(keep.len());
        for slot in keep {
            let mut slot = slot.clone();
            let fresh_recovery_kek;
            let kek: &Kek = match &mut slot.kind {
                SlotKind::Recovery(r) => {
                    let (ct, ss) = xwing::encapsulate(&r.xwing_pk)?;
                    r.xwing_ct = ct;
                    fresh_recovery_kek = recovery_kek(&ss)?;
                    &fresh_recovery_kek
                }
                _ => keks
                    .iter()
                    .find(|(id, _)| *id == slot.id)
                    .map(|(_, k)| *k)
                    .expect("presence checked above"),
            };
            let w = new_key.wrap(kek, &Keyslot::aad(self.vault_id, slot.id, &slot.kind))?;
            slot.nonce = w.nonce;
            slot.wrapped_mk = w.ciphertext;
            rewrapped.push(SlotEntry::Known(slot));
        }

        let rotation = Rotation {
            dropped,
            dropped_unknown: unknown(&self.entries).cloned().collect(),
        };
        self.entries = rewrapped;
        self.key = new_key;
        self.rotated.store(true, Ordering::SeqCst);
        Ok(rotation)
    }

    /// Serialize the next generation, with a fresh body nonce and a
    /// recomputed header MAC, and advance the generation. Fails without a
    /// recovery slot. Use `write` to put a vault on disk: it returns the
    /// `Mark` of what it wrote.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let generation = self.next_generation()?;
        let bytes = self.serialize(&self.entries, generation)?;
        self.generation.fetch_max(generation, Ordering::SeqCst);
        Ok(bytes)
    }

    fn next_generation(&self) -> Result<u64> {
        if !known(&self.entries).any(|s| matches!(s.kind, SlotKind::Recovery(_))) {
            return Err(Error::RecoveryRequired);
        }
        self.generation
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or(Error::GenerationOverflow)
    }

    /// A copy for `aleph backup`: the current generation with only the
    /// recovery slot(s), so a leaked backup exposes no login-password
    /// slot to offline guessing.
    pub fn to_backup_bytes(&self) -> Result<Vec<u8>> {
        let recovery: Vec<SlotEntry> = self
            .entries
            .iter()
            .filter(|e| matches!(e, SlotEntry::Known(k) if matches!(k.kind, SlotKind::Recovery(_))))
            .cloned()
            .collect();
        if recovery.is_empty() {
            return Err(Error::RecoveryRequired);
        }
        // Generations start at 1, even for a never-written vault.
        self.serialize(&recovery, self.generation.load(Ordering::SeqCst).max(1))
    }

    fn serialize(&self, entries: &[SlotEntry], generation: u64) -> Result<Vec<u8>> {
        self.serialize_with_mk_id(entries, generation, self.key.id())
    }

    fn serialize_with_mk_id(
        &self,
        entries: &[SlotEntry],
        generation: u64,
        mk_id: [u8; 16],
    ) -> Result<Vec<u8>> {
        let keyslots = entries
            .iter()
            .map(|e| e.encode().map(serde_bytes::ByteBuf::from))
            .collect::<Result<Vec<_>>>()?;
        let mut header = Vec::new();
        encode(
            &Header {
                vault_id: self.vault_id,
                generation,
                mk_id,
                keyslots,
            },
            &mut header,
        )?;
        let header_mac = self
            .key
            .mac(HEADER_MAC_INFO, &mac_input(FORMAT_VERSION, &header));
        let pt = encode_body(&self.body)?;
        let (nonce, ct) = self.key.seal(
            BODY_KEY_INFO,
            &body_aad(self.vault_id, FORMAT_VERSION, &header_mac),
            &pt,
        )?;
        let mut out = MAGIC.to_vec();
        encode(
            &VaultFile(FORMAT_VERSION, header, header_mac, nonce, ct),
            &mut out,
        )?;
        Ok(out)
    }

    /// Atomically replace the vault at `path` with the next generation and
    /// return that generation's `Mark` (what the daemon records in the
    /// high-water store).
    ///
    /// - The previous version is kept as `<path>.bak`, except on the first
    ///   write after a rotation, when `.bak` is also the new file (the old
    ///   one still holds the old MK and any removed slot).
    /// - The generation is chosen and serialized while holding
    ///   `<path>.lock`, and committed only after the rename. Concurrent
    ///   writers therefore get distinct generations, the file on disk is the
    ///   highest, and a failed write does not advance the generation.
    /// - Creates the parent directory (0700), tightens an existing one that
    ///   is group- or world-accessible, and refuses to replace a symlink.
    pub fn write(&self, path: &Path) -> Result<Mark> {
        let rotated = self.rotated.load(Ordering::SeqCst);
        let mut written = 0;
        write_atomic(
            path,
            || {
                written = self.next_generation()?;
                self.serialize(&self.entries, written)
            },
            rotated,
        )?;
        self.generation.fetch_max(written, Ordering::SeqCst);
        if rotated {
            self.rotated.store(false, Ordering::SeqCst);
        }
        Ok(Mark {
            vault_id: self.vault_id,
            generation: written,
            mk_id: self.key.id(),
        })
    }
}

fn sibling(path: &Path, suffix: &str) -> Result<std::path::PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("vault path {} has no file name", path.display()),
            )
        })?
        .to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}

/// Write a fresh 0600 file. Any existing file at `path` (a temp file left
/// by a crash or another tool) is removed first, because `mode` only
/// applies when a file is created and would not tighten an existing one.
fn write_file_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Replace `path` atomically with the bytes `make` produces. `make` runs
/// while `<path>.lock` is held, so what it reads (e.g. the next generation)
/// cannot interleave with another writer. With `replace_backup`, `.bak`
/// becomes a copy of the new file instead of the previous one.
fn write_atomic(
    path: &Path,
    make: impl FnOnce() -> Result<Vec<u8>>,
    replace_backup: bool,
) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    } else if dir.metadata()?.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    // `rename` would silently replace a symlink (e.g. into a sync folder)
    // with a regular file.
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to replace symlink {}", path.display()),
        )));
    }
    // Serialize writers. Without this, one writer's `write_file_synced`
    // could unlink another's temp file mid-write, and the other's rename
    // would then put this half-written file in place. The lock is on a
    // sibling that is never renamed, so it guards every path below.
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(sibling(path, ".lock")?)?;
    lock.lock()?;
    let bytes = make()?;
    let bak_tmp = sibling(path, ".bak.tmp")?;
    let bak = sibling(path, ".bak")?;
    if path.exists() && !replace_backup {
        write_file_synced(&bak_tmp, &fs::read(path)?)?;
        fs::rename(&bak_tmp, &bak)?;
    }
    let tmp = sibling(path, ".tmp")?;
    write_file_synced(&tmp, &bytes)?;
    fs::rename(&tmp, path)?;
    if replace_backup {
        write_file_synced(&bak_tmp, &bytes)?;
        fs::rename(&bak_tmp, &bak)?;
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Atomically write a small private file (0600, in a 0700 directory it
/// creates if needed): temp file, fsync, rename. No backup, no lock.
pub(crate) fn write_small_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let tmp = sibling(path, ".tmp")?;
    write_file_synced(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Hooks for this crate's own tests, only with `insecure-test-params`.
#[cfg(feature = "insecure-test-params")]
#[doc(hidden)]
pub mod testing {
    use std::sync::atomic::Ordering;

    use super::{SlotEntry, UnlockedVault};
    use crate::error::Result;

    /// Add an encoded slot as if a newer aleph had written it.
    pub fn push_unknown(v: &mut UnlockedVault, raw: Vec<u8>) {
        v.entries
            .push(SlotEntry::decode(&raw).expect("decodable slot"));
    }

    /// Force the generation counter (to test overflow).
    pub fn set_generation(v: &UnlockedVault, generation: u64) {
        v.generation.store(generation, Ordering::SeqCst);
    }

    /// Serialize with a chosen `mk_id` but a valid MAC under the real key:
    /// what someone holding this (old) MK could forge.
    pub fn to_bytes_with_mk_id(v: &UnlockedVault, mk_id: [u8; 16]) -> Result<Vec<u8>> {
        v.serialize_with_mk_id(&v.entries, 1, mk_id)
    }
}
~~~

`crates/aleph-core/src/recovery.rs`:

```rust
//! Recovery keys: 256 random bits shown to the user once as Crockford
//! base32, `XXXX-XXXX-…`, 14 groups of 4 (52 data chars + 4 checksum).

use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{Error, Result};
use crate::key::try_init_secret;
use crate::xwing::Recipient;

const XWING_SEED_INFO: &[u8] = b"aleph recovery xwing seed v1";

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const KEY_BYTES: usize = 32;
const DATA_CHARS: usize = 52; // ceil(256 / 5); the final 4 bits are zero padding
const CHECK_CHARS: usize = 4; // 20 bits of SHA-256
const GROUP: usize = 4;

pub struct RecoveryKey(SecretBox<[u8; KEY_BYTES]>);

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        try_init_secret(|buf| crypto::fill_random(buf)).map(Self)
    }

    fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        self.0.expose_secret()
    }

    /// This key's X-Wing recipient: the key pair whose seed is
    /// `HKDF(recovery key, "aleph recovery xwing seed v1")`. No Argon2:
    /// the recovery key already has full entropy.
    pub fn recipient(&self) -> Recipient {
        Recipient::from_seed(&crypto::hkdf(self.as_bytes(), XWING_SEED_INFO))
    }

    /// Display form, e.g. `7K3M-…`. Show once; never log.
    pub fn format(&self) -> Zeroizing<String> {
        let mut chars = Zeroizing::new(encode(self.as_bytes()));
        chars.extend_from_slice(&checksum(self.as_bytes()));
        let mut out = Zeroizing::new(String::with_capacity(chars.len() + chars.len() / GROUP));
        for (i, c) in chars.iter().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(*c as char);
        }
        out
    }

    /// Parse user input. Case-insensitive; ignores `-` and whitespace;
    /// reads `O` as `0` and `I`/`L` as `1`.
    pub fn parse(input: &str) -> Result<Self> {
        let mut vals = Zeroizing::new(Vec::with_capacity(DATA_CHARS + CHECK_CHARS));
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            vals.push(decode_char(c).ok_or(Error::InvalidRecoveryKey(
                "contains a character that is not in the recovery alphabet",
            ))?);
        }
        if vals.len() != DATA_CHARS + CHECK_CHARS {
            return Err(Error::InvalidRecoveryKey(
                "wrong length (expected 56 characters)",
            ));
        }
        let bytes = decode(&vals[..DATA_CHARS])?;
        let expected: Vec<u8> = checksum(&bytes)
            .iter()
            .map(|&c| decode_char(c as char).expect("alphabet char"))
            .collect();
        if expected[..] != vals[DATA_CHARS..] {
            return Err(Error::InvalidRecoveryKey(
                "checksum mismatch (check for a typo)",
            ));
        }
        try_init_secret(|buf| {
            buf.copy_from_slice(&*bytes);
            Ok(())
        })
        .map(Self)
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

fn encode(bytes: &[u8; KEY_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_CHARS + CHECK_CHARS);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize]);
        }
    }
    // 256 = 51*5 + 1: one leftover bit, padded with four zero bits.
    out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize]);
    out
}

fn decode(vals: &[u8]) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let mut out = Zeroizing::new([0u8; KEY_BYTES]);
    let (mut acc, mut bits, mut i) = (0u32, 0u32, 0usize);
    for &v in vals {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if i < KEY_BYTES {
                out[i] = (acc >> bits) as u8;
                i += 1;
            }
        }
    }
    // The 4 padding bits must be zero, otherwise two inputs would decode
    // to the same key.
    if acc & ((1 << bits) - 1) != 0 {
        return Err(Error::InvalidRecoveryKey("non-canonical encoding"));
    }
    Ok(out)
}

fn checksum(bytes: &[u8; KEY_BYTES]) -> [u8; CHECK_CHARS] {
    let digest = Sha256::digest(bytes);
    let v =
        (u32::from(digest[0]) << 12) | (u32::from(digest[1]) << 4) | (u32::from(digest[2]) >> 4);
    let mut out = [0u8; CHECK_CHARS];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ALPHABET[((v >> (5 * (CHECK_CHARS - 1 - i))) & 31) as usize];
    }
    out
}

fn decode_char(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|p| p as u8)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_14_groups_of_4() {
        let s = RecoveryKey::generate().unwrap().format();
        let groups: Vec<&str> = s.split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups.iter().all(|g| g.len() == 4));
    }

    /// Cross-checked against an independent Python encoder of the same
    /// scheme (big-endian bits, 4 zero pad bits, SHA-256 top 20 bits).
    #[test]
    fn known_encoding_of_bytes_0_to_31() {
        let bytes: [u8; KEY_BYTES] = std::array::from_fn(|i| i as u8);
        let k = RecoveryKey(SecretBox::new(Box::new(bytes)));
        assert_eq!(
            k.format().as_str(),
            "000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-CC6W"
        );
    }

    #[test]
    fn recipient_is_determined_by_the_key() {
        let k = RecoveryKey::generate().unwrap();
        let same = RecoveryKey::parse(&k.format()).unwrap();
        let other = RecoveryKey::generate().unwrap();
        assert_eq!(k.recipient().public_key(), same.recipient().public_key());
        assert_ne!(k.recipient().public_key(), other.recipient().public_key());
        assert_eq!(
            k.recipient().public_key().len(),
            crate::xwing::PUBLIC_KEY_LEN
        );
    }

    #[test]
    fn parse_round_trips_format() {
        let k = RecoveryKey::generate().unwrap();
        let back = RecoveryKey::parse(&k.format()).unwrap();
        assert_eq!(k.as_bytes(), back.as_bytes());
    }

    #[test]
    fn parse_is_forgiving_about_case_separators_and_lookalikes() {
        let k = RecoveryKey(SecretBox::new(Box::new([0u8; KEY_BYTES])));
        let canonical = k.format().to_string();
        assert!(canonical.starts_with("0000-"));
        let sloppy = canonical
            .replacen('0', "o", 1)
            .replacen('0', "O", 1)
            .to_lowercase()
            .replace('-', " ");
        assert_eq!(
            RecoveryKey::parse(&sloppy).unwrap().as_bytes(),
            &[0u8; KEY_BYTES]
        );
        // I and L read as 1.
        assert_eq!(decode_char('i'), Some(1));
        assert_eq!(decode_char('L'), Some(1));
    }

    #[test]
    fn parse_rejects_typos_wrong_length_and_bad_chars() {
        let s = RecoveryKey::generate().unwrap().format().to_string();
        // Change one data character to a different valid one.
        let mut chars: Vec<char> = s.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(
            RecoveryKey::parse(&typo),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(&s[..s.len() - 1]),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(&s.replacen(|c: char| c.is_ascii_alphanumeric(), "U", 1)),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(""),
            Err(Error::InvalidRecoveryKey(_))
        ));
    }

    #[test]
    fn nonzero_padding_bits_are_rejected() {
        let k = RecoveryKey(SecretBox::new(Box::new([0u8; KEY_BYTES])));
        let mut chars: Vec<u8> = encode(k.as_bytes());
        chars[DATA_CHARS - 1] = b'1'; // sets a padding bit
        let vals: Vec<u8> = chars
            .iter()
            .map(|&c| decode_char(c as char).unwrap())
            .collect();
        assert!(decode(&vals).is_err());
    }
}
```

`crates/aleph-core/src/lib.rs`:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod highwater;
pub mod kdf;
pub mod key;
pub mod keyslot;
pub mod model;
pub mod recovery;
pub mod vault;
pub mod xwing;

pub use error::{Error, Result};
pub use highwater::{HighWater, Mark, Standing};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
pub use keyslot::{
    Argon2Slot, Fido2Slot, Keyslot, RecoverySlot, SlotEntry, SlotKind, TpmSlot, UnknownSlot,
};
pub use model::{Body, Collection, Item, SecretBytes};
pub use recovery::RecoveryKey;
pub use vault::{LockedVault, Rotation, UnlockedVault};
```

- [ ] **Step 4: Regenerate the golden file**

v1 has not been released, so the golden file is regenerated once for the new format. The old one no longer parses (`Malformed("…expected bytes")`).

```bash
rm crates/aleph-core/tests/golden/v1.aleph
cargo test -p aleph-core --test golden -- --ignored regenerate
```

Expected: `1 passed`. The new file is about 3.1 KB (the X-Wing public key and ciphertext account for most of it).

- [ ] **Step 5: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected:
- unit `56 passed`, `golden` `1 passed, 1 ignored`, `vault` `25 passed`, `write` `9 passed`, `zeroize` `1 passed`
- about 20 s in total, of which the exhaustive bit-flip test takes about 10 s

- [ ] **Step 6: Confirm the revocation test has teeth**

Temporarily change the last line of `remove_keyslot` from `self.rotate_master(keks, &[id])` to

```rust
        let _ = keks;
        self.entries.retain(|e| !matches!(e, SlotEntry::Known(k) if k.id == id));
        Ok(Rotation {
            dropped: vec![id],
            ..Rotation::default()
        })
```

(the slot is removed and reported as dropped, but MK is not rotated), then run `cargo test -p aleph-core --test vault removing_a_slot`.
Expected: FAIL at `assert_ne!(v.mark().mk_id, mk_before)`. Revert, then re-run to confirm it passes.

Also check the high-water fixes, one at a time, restoring after each:
- Remove ` || key.id() != self.mk_id` from `LockedVault::unlock`. `--test vault a_header_claiming_another_mk_id` must FAIL.
- In `highwater::compare`, change `(false, false) => Standing::Rekeyed,` to `(false, false) => Standing::Newer,`. `--test vault a_replayed_old_mk` must FAIL.
- In `UnlockedVault::write`, add `self.generation.fetch_max(written, Ordering::SeqCst);` right after `written = self.next_generation()?;`, which commits the generation before writing. `--test write a_failed_write_does_not_advance` must FAIL.

After restoring each file, re-run the test to confirm it passes. If cargo reports the old failure, `touch` the restored file first, since a restored older mtime can make cargo reuse the mutant build.

- [ ] **Step 7: Update the spec**

In `docs/superpowers/specs/2026-09-26-aleph-design.md` §4:

1. In the Layout header table row for `keyslots`, replace "Each element is one keyslot, below." with "Each element is a byte string holding one keyslot's CBOR, so that unknown slot types can be re-emitted byte-for-byte."
2. In "Generation and high-water mark":
   - replace the path `` `$XDG_STATE_HOME/aleph/highwater` `` with `` `$XDG_STATE_HOME/aleph/highwater-<vault_id>` `` (one file per vault)
   - after the "Same `generation` but a different `mk_id`" bullet, add: "- **Higher `generation` with a different `mk_id`:** MK changed somewhere other than this daemon, or someone holding an old MK is replaying it under a forged generation (`Rekeyed`). Same handling."
   - add the paragraph: "Only the daemon's own writes move the mark to a new MK: `write` returns the `Mark` it put on disk, and the daemon records exactly that. Marks of files it reads are only ever raised within the same MK."

- [ ] **Step 8: Commit**

```bash
git add crates/aleph-core docs/superpowers/specs/2026-09-26-aleph-design.md
git commit -m "feat(core): vault format v2 with X-Wing recovery, rotation on removal, generations" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
