//! The reveal guard's clock (the manager spec, "What each action does"):
//! a confirmation holds for the `reveal_hold` setting (5 minutes unless
//! changed; 0 asks every time), and not past a lock. A guard against a
//! glance, not security: any program running as the user can read secrets.

use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct Reauth {
    confirmed: Option<Instant>,
}

impl Reauth {
    /// Whether showing or copying needs a confirmation first, when one
    /// holds for `hold` (read at each check: a shorter hold ends an older
    /// confirmation at once).
    pub fn needed(&self, now: Instant, hold: Duration) -> bool {
        hold.is_zero()
            || self
                .confirmed
                .is_none_or(|at| now.duration_since(at) >= hold)
    }

    pub fn confirmed(&mut self, now: Instant) {
        self.confirmed = Some(now);
    }

    /// The keyring locked (or the window closes): confirm again.
    pub fn forget(&mut self) {
        self.confirmed = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_confirmation_holds_for_the_setting_and_not_past_a_lock() {
        let t = Instant::now();
        let hold = Duration::from_secs(300);
        let mut r = Reauth::default();
        assert!(r.needed(t, hold));
        r.confirmed(t);
        assert!(!r.needed(t + Duration::from_secs(299), hold));
        assert!(r.needed(t + hold, hold));
        // A shorter hold applies at once, to a confirmation already given.
        assert!(r.needed(t + Duration::from_secs(120), Duration::from_secs(60)));
        // Zero: every time, even right after a confirmation.
        assert!(r.needed(t, Duration::ZERO));
        r.confirmed(t);
        r.forget();
        assert!(r.needed(t, hold));
    }
}
