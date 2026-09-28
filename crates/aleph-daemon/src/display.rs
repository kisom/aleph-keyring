//! Which display a prompter opens on (spec §6 "Prompter orchestration").
//!
//! alephd's own environment is fixed when it starts, and it often starts
//! before the compositor: `pam_aleph` activates it during login, before
//! Hyprland has run (and exported `WAYLAND_DISPLAY` to the user manager).
//! So at each launch the display is read from the user manager's current
//! environment, where the compositor puts it (`systemctl --user
//! import-environment`), and only if the manager cannot be asked from
//! alephd's own.

use std::time::Duration;

/// Where a prompter's display comes from.
pub trait Session: Send + Sync {
    /// The session's Wayland display (`WAYLAND_DISPLAY`), if it has one now.
    fn wayland_display(&self) -> Option<String>;
}

/// alephd's own environment.
pub struct OwnEnvironment;

impl Session for OwnEnvironment {
    fn wayland_display(&self) -> Option<String> {
        std::env::var("WAYLAND_DISPLAY").ok().filter(|v| usable(v))
    }
}

/// A display name the prompter may use: a bare socket name in the runtime
/// directory (`wayland-1`), never a path. Any process of the user can set
/// the manager's environment; a path could send the prompt, and what is
/// typed into it, through a proxy of its choosing.
fn usable(name: &str) -> bool {
    !name.is_empty() && !name.contains('/')
}

/// The systemd user manager's environment (its `Environment` property,
/// read fresh at each launch), falling back to alephd's own when the
/// manager cannot be asked.
pub struct UserManager {
    pub conn: zbus::Connection,
    pub runtime: tokio::runtime::Handle,
}

/// How long the manager may take to answer.
const ASK: Duration = Duration::from_secs(2);

impl Session for UserManager {
    /// Blocks: called from blocking threads (prompts run on them), never
    /// from async code.
    fn wayland_display(&self) -> Option<String> {
        let manager = self.runtime.block_on(async {
            tokio::time::timeout(ASK, manager_environment(&self.conn))
                .await
                .ok()?
                .map_err(|e| tracing::debug!("the user manager's environment: {e}"))
                .ok()
        });
        choose(manager.as_deref(), OwnEnvironment.wayland_display())
    }
}

async fn manager_environment(conn: &zbus::Connection) -> zbus::Result<Vec<String>> {
    // Not cached: systemd does not signal changes to it.
    let proxy: zbus::Proxy = zbus::proxy::Builder::new(conn)
        .destination("org.freedesktop.systemd1")?
        .path("/org/freedesktop/systemd1")?
        .interface("org.freedesktop.systemd1.Manager")?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    proxy.get_property("Environment").await
}

/// The manager's word when it answered (no display there means none now,
/// whatever alephd started with); alephd's own otherwise.
fn choose(manager: Option<&[String]>, own: Option<String>) -> Option<String> {
    match manager {
        Some(env) => env
            .iter()
            .find_map(|kv| kv.strip_prefix("WAYLAND_DISPLAY="))
            .filter(|v| usable(v))
            .map(str::to_string),
        None => own,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_managers_environment_wins_over_alephds_own() {
        let env = vec![
            "PATH=/usr/bin".to_string(),
            "WAYLAND_DISPLAY=wayland-1".into(),
        ];
        assert_eq!(
            choose(Some(&env), Some("wayland-0".into())),
            Some("wayland-1".into())
        );
        // No display in the session now (logged out): none, even if alephd
        // started with one.
        assert_eq!(choose(Some(&env[..1]), Some("wayland-0".into())), None);
        // The manager could not be asked: alephd's own.
        assert_eq!(
            choose(None, Some("wayland-0".into())),
            Some("wayland-0".into())
        );
        assert_eq!(choose(Some(&["WAYLAND_DISPLAY=".to_string()]), None), None);
        // A path (a proxy socket anywhere) is refused.
        assert_eq!(
            choose(Some(&["WAYLAND_DISPLAY=/tmp/proxy".to_string()]), None),
            None
        );
    }
}
