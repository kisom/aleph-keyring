//! The reveal guard's clock (the manager spec, "What each action does"):
//! a confirmation holds for 5 minutes, and not past a lock. A guard
//! against a glance, not security: any program running as the user can
//! read secrets.

use std::time::{Duration, Instant};

/// How long a confirmation holds.
pub const HOLD: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Default)]
pub struct Reauth {
    confirmed: Option<Instant>,
}

impl Reauth {
    /// Whether showing or copying needs a confirmation first.
    pub fn needed(&self, now: Instant) -> bool {
        self.confirmed
            .is_none_or(|at| now.duration_since(at) >= HOLD)
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
    fn a_confirmation_holds_five_minutes_and_not_past_a_lock() {
        let t = Instant::now();
        let mut r = Reauth::default();
        assert!(r.needed(t));
        r.confirmed(t);
        assert!(!r.needed(t + Duration::from_secs(299)));
        assert!(r.needed(t + HOLD));
        r.confirmed(t);
        r.forget();
        assert!(r.needed(t));
    }
}
