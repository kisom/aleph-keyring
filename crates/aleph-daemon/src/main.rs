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
    let (config, warning) = Config::load_or_default(&paths.config_file);
    if let Some(warning) = warning {
        tracing::warn!("{warning}");
    }
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
        .and_then(|b| b.name(BUS_NAME))
        .map_err(|e| e.to_string())?
        .build()
        .await
        .map_err(|e| format!("cannot own {BUS_NAME} on the session bus: {e}"))?;
    let pam_socket = paths.pam_socket();
    let activation = paths
        .data_dir
        .parent()
        .map(|data| data.join("dbus-1/services/org.freedesktop.secrets.service"));
    let secrets =
        aleph_daemon::daemon::serve(&conn, keyring.clone(), launcher, config.clone(), paths)
            .await
            .map_err(|e| e.to_string())?;
    // Queued behind gnome-keyring until it lets go (DECISIONS.md E1), and
    // only while setup's activation file is in place: before setup (which
    // claims it through the admin interface) and after a revert, the
    // Secret Service is gnome-keyring's.
    let claim = aleph_daemon::daemon::claims_at_start(activation.as_deref());
    if !claim {
        tracing::info!(
            "serving {BUS_NAME}; not claiming {SECRETS_NAME} (alephctl setup has not switched over)"
        );
    }
    match if claim {
        aleph_daemon::daemon::request_secrets_name(&conn).await
    } else {
        Ok(true)
    } {
        Ok(true) if !claim => {}
        Ok(true) => tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}"),
        // After setup switched over, nothing else should hold it.
        Ok(false) if activation.as_ref().is_some_and(|a| a.exists()) => {
            tracing::warn!(
                "another program owns {SECRETS_NAME} although alephctl setup switched over (gnome-keyring started outside systemd?); alephd waits in the queue"
            )
        }
        Ok(false) => tracing::info!(
            "serving {BUS_NAME}; queued for {SECRETS_NAME}, which another program owns"
        ),
        Err(e) => return Err(format!("cannot request {SECRETS_NAME}: {e}")),
    }
    // The lock policy: logind (sleep, screen lock) on the system bus, and
    // the idle timer. Without logind the rest still works.
    match zbus::Connection::system().await {
        Ok(system) => {
            let (secrets, config) = (secrets.clone(), config.clone());
            tokio::spawn(async move {
                if let Err(e) =
                    aleph_daemon::lockpolicy::watch_logind(system, secrets, config).await
                {
                    tracing::warn!("not following logind (no lock on sleep or screen lock): {e}");
                }
            });
        }
        Err(e) => tracing::warn!("no system bus (no lock on sleep or screen lock): {e}"),
    }
    tokio::spawn(aleph_daemon::lockpolicy::lock_when_idle(
        keyring.clone(),
        secrets.clone(),
        config,
    ));
    // Login unlock needs pam.sock; without it the rest still works.
    match aleph_daemon::pamsock::listener(&pam_socket) {
        Ok(listener) => {
            tokio::spawn(async move {
                if let Err(e) = aleph_daemon::pamsock::serve(listener, keyring, secrets).await {
                    tracing::error!("pam.sock stopped: {e}");
                }
            });
        }
        Err(e) => tracing::warn!(
            "no pam.sock ({}): login unlock is unavailable: {e}",
            pam_socket.display()
        ),
    }
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
