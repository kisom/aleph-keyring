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
    let config = Config::load(&paths.config_file).map_err(|e| e.to_string())?;
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
        .and_then(|b| b.name(SECRETS_NAME))
        .and_then(|b| b.name(BUS_NAME))
        .map_err(|e| e.to_string())?
        .build()
        .await
        .map_err(|e| {
            format!("cannot own {SECRETS_NAME} on the session bus (is gnome-keyring still running?): {e}")
        })?;
    aleph_daemon::daemon::serve(&conn, keyring, launcher, config, paths)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}");
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
