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
use aleph_core::{Argon2Kind, Argon2Params, Item, LockedVault, SecretBytes, UnlockedVault};

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
    let slot = v
        .add_argon2_keyslot(
            "p",
            Argon2Kind::Passphrase,
            b"pw",
            Argon2Params::INSECURE_TEST,
        )
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
        .unlock_argon2(slot, b"pw")
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
