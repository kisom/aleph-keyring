//! Rate limiting of failed unseals (spec §5), in two layers.
//!
//! The TPM's dictionary-attack counter is shared by every user and by
//! `systemd-cryptenroll` disk unlock, and a lockout survives reboot. So:
//!
//! - **Global reserve:** the helper refuses any DA-counted unseal once
//!   the TPM's failure counter reaches [`reserve_threshold`]. aleph can
//!   therefore never drive the TPM into lockout, and `max(1, max/2)`
//!   tries stay available to disk unlock.
//! - **Per-uid budget:** each uid may have at most [`FAILURES_PER_UID`]
//!   failures within a [`window`] of `FAILURES_PER_UID` recovery times
//!   (a recovery time is how long the TPM takes to forget one failure).
//!   One uid guessing without pause therefore adds failures no faster
//!   than the TPM forgets them, and cannot hold the reserve at its limit
//!   alone. Several uids together can, for as long as they keep guessing:
//!   that denial of TPM unlock is accepted (spec §2); a lockout is not.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Failures a uid may have outstanding within one recovery window.
pub const FAILURES_PER_UID: usize = 2;
/// The shortest per-uid window, whatever the TPM's recovery time.
pub const MIN_WINDOW: Duration = Duration::from_secs(60);

/// The TPM failure count at which the helper stops attempting DA-counted
/// unseals: half of `max_tries`, keeping at least one try in reserve. A
/// TPM with `max_tries == 0` is always locked for DA-protected auth.
pub fn reserve_threshold(max_tries: u32) -> u32 {
    max_tries.saturating_sub((max_tries / 2).max(1))
}

/// The per-uid window for a TPM recovery time in seconds.
pub fn window(recovery_time_secs: u32) -> Duration {
    (Duration::from_secs(recovery_time_secs.into()) * FAILURES_PER_UID as u32).max(MIN_WINDOW)
}

#[derive(Default)]
pub struct RateLimiter {
    failures: HashMap<u32, VecDeque<Instant>>,
}

impl RateLimiter {
    /// Whether `uid` has used up its budget within `window`.
    pub fn blocked(&mut self, uid: u32, now: Instant, window: Duration) -> bool {
        self.prune(now, window);
        self.failures
            .get(&uid)
            .is_some_and(|f| f.len() >= FAILURES_PER_UID)
    }

    /// Record a failed unseal by `uid`.
    pub fn record_failure(&mut self, uid: u32, now: Instant, window: Duration) {
        self.prune(now, window);
        self.failures.entry(uid).or_default().push_back(now);
    }

    /// Forget failures older than `window`, for every uid (bounded memory
    /// however many uids have come and gone).
    fn prune(&mut self, now: Instant, window: Duration) {
        self.failures.retain(|_, f| {
            while f.front().is_some_and(|t| now.duration_since(*t) >= window) {
                f.pop_front();
            }
            !f.is_empty()
        });
    }

    /// How many uids have failures on record.
    pub fn tracked(&self) -> usize {
        self.failures.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(600);

    #[test]
    fn blocks_after_the_per_uid_budget_then_recovers_after_the_window() {
        let t0 = Instant::now();
        let mut l = RateLimiter::default();
        for i in 0..FAILURES_PER_UID {
            assert!(!l.blocked(1000, t0, W), "blocked after {i}");
            l.record_failure(1000, t0, W);
        }
        assert!(l.blocked(1000, t0, W));
        assert!(l.blocked(1000, t0 + W - Duration::from_secs(1), W));
        assert!(!l.blocked(1000, t0 + W, W));
    }

    #[test]
    fn uids_are_limited_independently() {
        let t0 = Instant::now();
        let mut l = RateLimiter::default();
        for _ in 0..FAILURES_PER_UID {
            l.record_failure(1000, t0, W);
        }
        assert!(l.blocked(1000, t0, W));
        assert!(!l.blocked(1001, t0, W));
    }

    #[test]
    fn stale_uids_are_forgotten() {
        let t0 = Instant::now();
        let mut l = RateLimiter::default();
        for uid in 0..1000 {
            l.record_failure(uid, t0, W);
        }
        l.record_failure(5000, t0 + W, W);
        assert_eq!(l.tracked(), 1);
    }

    #[test]
    fn the_reserve_keeps_half_the_tries_and_at_least_one() {
        assert_eq!(reserve_threshold(32), 16);
        assert_eq!(reserve_threshold(3), 2);
        assert_eq!(reserve_threshold(1), 0);
        assert_eq!(reserve_threshold(0), 0);
        // One uid's sustained rate equals the TPM's decay: 2 per 2 × 600 s.
        assert_eq!(window(600), Duration::from_secs(1200));
        assert_eq!(window(10), MIN_WINDOW);
        assert_eq!(window(0), MIN_WINDOW);
    }
}
