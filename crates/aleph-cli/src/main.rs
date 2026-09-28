//! `aleph`, the command-line client (spec §7 "CLI").
//!
//! Everything goes through the running `alephd`: `io.aleph.Admin1` for the
//! keyring, the Secret Service for items. Prompts the daemon needs are
//! answered in this terminal. Secrets are read from standard input, never
//! from the command line.

mod client;
mod prompter;
mod switchover;
mod system;
mod wizard;

use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

use client::{Args, Client, Result};

#[derive(Parser)]
#[command(name = "alephctl", version, about = "The aleph keyring")]
struct Cli {
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum SystemCmd {
    /// Add aleph to the login, lock-screen, and passwd PAM services, then
    /// check the login and lock screen with a real login (undone at once
    /// if that fails).
    Apply {
        /// Whose login password checks the edited services.
        #[arg(long)]
        user: String,
    },
    /// Check the login and lock-screen services with a real login.
    Verify {
        #[arg(long)]
        user: String,
    },
    /// Undo what `apply` did (only what it did).
    Revert,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ImportSource {
    /// gnome-keyring, while it still runs (its items stay there).
    GnomeKeyring,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up aleph: create the keyring, import from gnome-keyring, and take
    /// over the Secret Service from it.
    Setup {
        /// Hand everything back to gnome-keyring (copying the keyring there
        /// first); the aleph vault is left in place.
        #[arg(long)]
        revert: bool,
    },
    /// Show the keyring's state and keyslots.
    Status,
    /// The root side of setup (run with sudo): login and screen unlock.
    #[command(subcommand)]
    System(SystemCmd),
    /// Import items from another keyring (alephd reads them itself).
    Import {
        #[arg(value_enum)]
        source: ImportSource,
    },
    Lock,
    Unlock,
    #[command(subcommand)]
    Keyslot(KeyslotCmd),
    #[command(subcommand)]
    Recovery(RecoveryCmd),
    /// Write a backup (only the recovery slot: it opens with the recovery key).
    Backup {
        path: std::path::PathBuf,
        /// Replace an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Recover with the recovery key: this vault, or a backup file.
    Restore {
        path: Option<std::path::PathBuf>,
        /// Replace an unreadable vault file with its backup copy.
        #[arg(long, conflicts_with_all = ["path", "accept_rollback"])]
        from_bak: bool,
        /// Accept a rolled-back, replaced, or different vault file as current.
        #[arg(long, conflicts_with = "path")]
        accept_rollback: bool,
    },
    /// Print the secret of the item matching attr=value pairs.
    Get {
        attributes: Vec<String>,
    },
    /// List items matching attr=value pairs.
    Search {
        attributes: Vec<String>,
    },
    /// Store a secret (read from standard input) with a label and attributes.
    Store {
        #[arg(long)]
        label: String,
        attributes: Vec<String>,
    },
    /// Delete the items matching attr=value pairs.
    Delete {
        attributes: Vec<String>,
    },
    /// List collections, or the items of one.
    Ls {
        collection: Option<String>,
    },
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Print shell completions.
    Completions {
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum KeyslotCmd {
    List,
    #[command(subcommand)]
    Add(AddCmd),
    /// Remove a keyslot (rotates the master key).
    Remove {
        id: String,
    },
    RotateMaster,
    /// Try a stale keyslot again.
    Retry {
        id: String,
    },
}

#[derive(Subcommand)]
enum AddCmd {
    /// The TPM, unlocked with your login password.
    Tpm,
    /// A FIDO2 security key.
    Fido2 {
        /// Unlock with a touch alone (anyone holding the key can unlock).
        #[arg(long)]
        touch_only: bool,
    },
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Issue a new recovery key; the old one stops working.
    Reissue,
}

#[derive(Subcommand)]
enum ConfigCmd {
    Get { key: String },
    Set { key: String, value: String },
}

/// Parse `attr=value` pairs.
fn attributes(pairs: &[String]) -> Result<HashMap<String, String>> {
    pairs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("expected attr=value, not {p:?}"))
        })
        .collect()
}

fn print_json(v: &impl serde::Serialize) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(v).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// Report a conversation's outcome; failure is an error.
fn outcome(o: prompter::Outcome) -> Result<()> {
    match (o.ok, o.message) {
        (true, Some(m)) => {
            eprintln!("alephctl: {m}");
            Ok(())
        }
        (true, None) => Ok(()),
        (false, m) => Err(m.unwrap_or_else(|| "failed".into())),
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    if let Cmd::Completions { shell } = cli.cmd {
        clap_complete::generate(
            shell,
            &mut Cli::command(),
            "alephctl",
            &mut std::io::stdout(),
        );
        return Ok(ExitCode::SUCCESS);
    }
    // The root side: no session bus, no user configuration.
    if let Cmd::System(action) = cli.cmd {
        return run_system(action).map(|()| ExitCode::SUCCESS);
    }
    let c = Client::connect().await?;
    match cli.cmd {
        Cmd::Completions { .. } | Cmd::System(_) => unreachable!(),
        Cmd::Setup { revert: true } => revert(&c).await?,
        Cmd::Setup { revert: false } => {
            let status = c.status().await?;
            let tpm = status.tpm.unwrap_or(false);
            eprintln!(
                "alephctl: TPM: {}",
                match status.tpm {
                    Some(true) => "usable",
                    Some(false) => "not usable (a login-password keyslot is used instead)",
                    None => "busy (could not check now)",
                }
            );
            let autologin = wizard::autologin_user(&wizard::SddmConfig::system());
            if let Some(user) = &autologin {
                eprintln!(
                    "alephctl: SDDM logs {user} in automatically: there is no password at login, so the keyring stays locked until first use, then asks for a security key or your login password"
                );
            }
            if status.vault {
                eprintln!("alephctl: a keyring already exists; checking the rest of setup");
            } else {
                create_keyring(&c, tpm, autologin.is_some()).await?;
            }
            // Import while gnome-keyring still serves the Secret Service
            // (E1), then take over from it (E9).
            if c.status().await?.locked {
                outcome(c.converse("Unlock", Args::None).await?)?;
            }
            let summary = c.import_gnome_keyring().await?;
            eprintln!("alephctl: {summary}");
            if summary.contains("Not imported:") {
                let mut term = prompter::Terminal::new();
                let answer = ask(
                    &mut term,
                    "Those collections stay in gnome-keyring, out of reach once aleph takes over (until `alephctl setup --revert`). Take over anyway? [y/N] ",
                )?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    eprintln!(
                        "alephctl: stopped before taking over: unlock them in gnome-keyring (Seahorse), then run `alephctl setup` again"
                    );
                    return Ok(ExitCode::SUCCESS);
                }
            }
            let dirs = switchover::Dirs::from_env()?;
            let mut record = switchover::Record::load(&dirs)?;
            for step in
                switchover::switch_over(c.bus(), &switchover::Systemctl, &dirs, &mut record).await?
            {
                eprintln!("alephctl: {step}");
            }
            if let Some(hook) = wizard::install_omarchy_hook(&dirs.config_home)? {
                eprintln!(
                    "alephctl: installed {}: the keyring locks with the screen once Omarchy's lock runs `omarchy-hook lock`",
                    hook.display()
                );
            }
            let mut term = prompter::Terminal::new();
            if let Some(config) = wizard::hyprland_config(&dirs.config_home)
                && !wizard::hyprland_rule_included(&config)
            {
                let answer = ask(
                    &mut term,
                    "Float the unlock prompt in the middle of the screen in Hyprland (adds two lines to hyprland.lua)? [Y/n] ",
                )?;
                if matches!(answer.trim(), "" | "y" | "Y" | "yes") {
                    wizard::include_hyprland_rule(&config)?;
                    eprintln!(
                        "alephctl: {} now includes {}",
                        config.display(),
                        wizard::HYPRLAND_RULE_FILE
                    );
                    if !std::path::Path::new(wizard::HYPRLAND_RULE_FILE).exists() {
                        eprintln!(
                            "alephctl: {} is not installed yet (`make install` puts it there); until then the rule does nothing",
                            wizard::HYPRLAND_RULE_FILE
                        );
                    }
                }
            }
            if tpm {
                offer_lockout_auth(&mut term)?;
            }
            // The root side comes last, and is optional (E10).
            let user = std::env::var("USER").map_err(|_| "USER is not set")?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let exe = exe.to_string_lossy();
            let apply = [exe.as_ref(), "system", "apply", "--user", user.as_str()];
            // (A re-run skips it once done: no sudo, no password.)
            if system::applied(&system::Root::as_seen_by_setup()).unwrap_or(false) {
                eprintln!(
                    "alephctl: login and screen unlock already reach aleph (`sudo alephctl system verify --user {user}` checks them)"
                );
            } else {
                let answer = ask(
                    &mut term,
                    "Set up login and screen unlock now (runs sudo)? [Y/n] ",
                )?;
                if matches!(answer.trim(), "" | "y" | "Y" | "yes") {
                    if let Err(e) = wizard::run_as_root(&apply) {
                        eprintln!(
                            "alephctl: {e}; run `sudo alephctl system apply --user {user}` later"
                        );
                        eprintln!("alephctl: {ROOT_STEP_PENDING}");
                    }
                } else {
                    eprintln!("alephctl: later: `sudo alephctl system apply --user {user}`");
                    eprintln!("alephctl: {ROOT_STEP_PENDING}");
                }
            }
            eprintln!("alephctl: setup is done (`alephctl status` shows the keyring)");
        }

        Cmd::Status => {
            let s = c.status().await?;
            if cli.json {
                print_json(&s)?;
            } else {
                let state = match (s.vault, s.locked) {
                    (false, _) => "none (run `alephctl setup`)",
                    (true, true) => "locked",
                    (true, false) => "unlocked",
                };
                println!("keyring: {state}");
                if let Some(owner) = &s.secret_service {
                    println!("secret service: served by {owner}");
                }
                if let Some(why) = &s.untrusted {
                    println!("warning: the vault file was {why}; writes are refused");
                }
                if s.memory_locked == Some(false) {
                    println!(
                        "warning: the master key could not be locked in RAM (mlock); it may be swapped"
                    );
                }
                if s.rotation_pending {
                    println!(
                        "warning: after a password change the master key still needs rotating: run `alephctl keyslot rotate-master`"
                    );
                }
                print_slots(&s.keyslots);
            }
        }
        Cmd::Import {
            source: ImportSource::GnomeKeyring,
        } => println!("{}", c.import_gnome_keyring().await?),
        Cmd::Lock => c.lock().await?,
        Cmd::Unlock => outcome(c.converse("Unlock", Args::None).await?)?,
        Cmd::Keyslot(k) => match k {
            KeyslotCmd::List => {
                let s = c.status().await?;
                if cli.json {
                    print_json(&s.keyslots)?;
                } else {
                    print_slots(&s.keyslots);
                }
            }
            KeyslotCmd::Add(AddCmd::Tpm) => outcome(c.converse("EnrollTpm", Args::None).await?)?,
            KeyslotCmd::Add(AddCmd::Fido2 { touch_only }) => {
                if touch_only {
                    eprintln!(
                        "alephctl: warning: anyone holding a touch-only key can unlock the keyring"
                    );
                }
                outcome(c.converse("EnrollFido2", Args::Bool(touch_only)).await?)?;
            }
            KeyslotCmd::Remove { id } => outcome(
                c.converse("RemoveKeyslot", Args::Str(&full_id(&c, &id).await?))
                    .await?,
            )?,
            KeyslotCmd::RotateMaster => outcome(c.converse("RotateMaster", Args::None).await?)?,
            KeyslotCmd::Retry { id } => c.retry_keyslot(&full_id(&c, &id).await?).await?,
        },
        Cmd::Recovery(RecoveryCmd::Reissue) => {
            outcome(c.converse("ReissueRecoveryKey", Args::None).await?)?
        }
        Cmd::Backup { path, force } => backup(&c, &path, force).await?,
        Cmd::Restore {
            path,
            from_bak,
            accept_rollback,
        } => {
            let result = match (path, from_bak, accept_rollback) {
                (Some(p), _, _) => {
                    // Not a FIFO or device: opening one could wait forever.
                    let meta =
                        std::fs::metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                    if !meta.is_file() {
                        return Err(format!("{}: not a regular file", p.display()));
                    }
                    let file =
                        std::fs::File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                    c.converse("RestoreBackup", Args::File(file)).await?
                }
                (None, true, _) => c.converse("RestoreFromBak", Args::None).await?,
                (None, _, true) => c.converse("AcceptRollback", Args::None).await?,
                (None, false, false) => c.converse("Recover", Args::None).await?,
            };
            outcome(result)?
        }
        Cmd::Get { attributes: pairs } => {
            let attrs = attributes(&pairs)?;
            if attrs.is_empty() {
                return Err("get needs at least one attr=value pair".into());
            }
            let items = c.search(&attrs).await?;
            let Some(item) = items.first() else {
                return Ok(ExitCode::FAILURE);
            };
            let secret = c.secret(&item.path).await?;
            let mut out = std::io::stdout().lock();
            out.write_all(&secret).map_err(|e| e.to_string())?;
            if std::io::stdout().is_terminal() {
                writeln!(out).map_err(|e| e.to_string())?;
            }
        }
        Cmd::Search { attributes: pairs } => {
            let items = c.search(&attributes(&pairs)?).await?;
            if cli.json {
                print_json(&items)?;
            } else {
                for item in &items {
                    print_item(item);
                }
            }
            if items.is_empty() {
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Store {
            label,
            attributes: pairs,
        } => {
            let attrs = attributes(&pairs)?;
            if attrs.is_empty() {
                return Err("store needs at least one attr=value pair".into());
            }
            let secret = read_secret()?;
            c.store(&label, &attrs, &secret).await?;
        }
        Cmd::Delete { attributes: pairs } => {
            let attrs = attributes(&pairs)?;
            if attrs.is_empty() {
                return Err(
                    "delete needs at least one attr=value pair (refusing to delete everything)"
                        .into(),
                );
            }
            let items = c.search(&attrs).await?;
            for item in &items {
                c.delete(&item.path).await?;
            }
            if items.is_empty() {
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Ls { collection } => {
            let collections = c.collections().await?;
            if cli.json {
                let v: Vec<_> = collections
                    .iter()
                    .filter(|(l, _)| collection.as_ref().is_none_or(|c| c == l))
                    .map(|(l, items)| serde_json::json!({ "label": l, "items": items }))
                    .collect();
                print_json(&v)?;
            } else {
                match collection {
                    None => {
                        for (label, items) in &collections {
                            println!("{label}\t{} items", items.len());
                        }
                    }
                    Some(want) => {
                        let (_, items) = collections
                            .iter()
                            .find(|(l, _)| *l == want)
                            .ok_or_else(|| format!("no collection {want:?}"))?;
                        for item in items {
                            print_item(item);
                        }
                    }
                }
            }
        }
        Cmd::Config(ConfigCmd::Get { key }) => println!("{}", c.get_config(&key).await?),
        Cmd::Config(ConfigCmd::Set { key, value }) => {
            if key == "lock.on_suspend" && value == "false" {
                eprintln!(
                    "alephctl: warning: the keyring will stay unlocked through suspend and hibernation; \
                     the master key can then be written to a hibernation image (keep swap encrypted)"
                );
            }
            outcome(c.converse("SetConfig", Args::Str2(&key, &value)).await?)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `alephctl backup`: the CLI creates the file (never following a symlink,
/// never replacing one without `--force`, which writes a temporary file and
/// renames it over the target once the daemon is done) and passes it.
async fn backup(c: &Client, path: &std::path::Path, force: bool) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let target = if force {
        let name = path
            .file_name()
            .ok_or("the backup path has no file name")?
            .to_string_lossy();
        path.with_file_name(format!(".{name}.aleph-tmp"))
    } else {
        path.to_path_buf()
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&target)
        .map_err(|e| {
            if force && e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{}: left by an interrupted `alephctl backup --force`; remove it and try again",
                    target.display()
                )
            } else {
                format!("{}: {e}", target.display())
            }
        })?;
    let result = c.converse("Backup", Args::File(file)).await;
    let ok = matches!(&result, Ok(o) if o.ok);
    if force && ok {
        std::fs::rename(&target, path).map_err(|e| format!("{}: {e}", path.display()))?;
    } else if !ok {
        let _ = std::fs::remove_file(&target);
    }
    outcome(result?)?;
    eprintln!(
        "alephctl: note: copies of ~/.local/share/aleph made any other way hold every keyslot \
         (including a login-password slot on machines without a TPM); `alephctl backup` holds only the recovery slot"
    );
    Ok(())
}

/// What stays until the root step runs.
const ROOT_STEP_PENDING: &str = "until then, logging in does not unlock the keyring, and the login's PAM service can still start gnome-keyring behind aleph";

/// `alephctl system ...`, as root (DECISIONS.md E4–E6).
fn run_system(action: SystemCmd) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("run it as root: sudo alephctl system ...".into());
    }
    if let Some(w) = system::writable_binary_warning() {
        eprintln!("alephctl: {w}");
    }
    let root = system::Root::system();
    match action {
        SystemCmd::Apply { user } => {
            if std::path::Path::new("/etc/NIXOS").exists() {
                eprintln!(
                    "alephctl: NixOS manages /etc/pam.d: add to your configuration, for each of the login and lock-screen services,
  security.pam.services.<name>.text lines: `{}` (and for the login `{}`; for passwd `{}`)",
                    system::AUTH,
                    system::SESSION,
                    system::PASSWORD
                );
                return Ok(());
            }
            // Asked before anything changes: nothing is ever left edited
            // and unchecked.
            let password = zeroize::Zeroizing::new(
                rpassword::prompt_password(format!(
                    "Login password for {user} (checks the login and lock screen once): "
                ))
                .map_err(|e| e.to_string())?,
            );
            let report = system::apply_checked(&root, &user, &password, system::verify)?;
            for m in &report.manual {
                eprintln!("alephctl: by hand: {m}");
            }
            eprintln!("alephctl: login and screen unlock now reach aleph");
        }
        SystemCmd::Verify { user } => {
            let password = zeroize::Zeroizing::new(
                rpassword::prompt_password(format!("Login password for {user}: "))
                    .map_err(|e| e.to_string())?,
            );
            system::verify(&root, &user, &password)?;
            eprintln!("alephctl: the login and lock-screen services accept the password");
        }
        SystemCmd::Revert => {
            for line in system::revert(&root)? {
                eprintln!("alephctl: {line}");
            }
        }
    }
    Ok(())
}

/// `alephctl setup --revert` (DECISIONS.md E3): copy the keyring back to
/// gnome-keyring and verify it, then switch back and let go of the name.
async fn revert(c: &Client) -> Result<()> {
    let installed = std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|d| d.join("gnome-keyring-daemon").is_file())
    });
    if !installed {
        return Err(
            "gnome-keyring is not installed: reverting would leave no Secret Service (Arch: pacman -S gnome-keyring)"
                .into(),
        );
    }
    if c.status().await?.locked {
        outcome(c.converse("Unlock", Args::None).await?)?;
    }
    let dirs = switchover::Dirs::from_env()?;
    let mut record = switchover::Record::load(&dirs)?;
    // A revert that stopped after switching back resumes at the release
    // (gnome-keyring runs by then, and a second export would be refused).
    if record.revert_phase.as_deref() != Some(switchover::SWITCHED_BACK) {
        let removed = c.removed_since_import().await?;
        let mut delete = false;
        if !removed.is_empty() {
            eprintln!(
                "alephctl: imported from gnome-keyring and deleted in aleph since: {}",
                removed.join(", ")
            );
            let mut term = prompter::Terminal::new();
            let answer = ask(&mut term, "Delete them from gnome-keyring too? [y/N] ")?;
            delete = matches!(answer.trim(), "y" | "Y" | "yes");
        }
        outcome(
            c.converse("ExportToGnomeKeyring", Args::Bool(delete))
                .await?,
        )?;
        let steps = match switchover::switch_back(
            c.bus(),
            &switchover::Systemctl,
            &dirs,
            &mut record,
        )
        .await
        {
            Ok(steps) => steps,
            Err(e) => {
                let _ = c.thaw_writes().await;
                return Err(e);
            }
        };
        for step in steps {
            eprintln!("alephctl: {step}");
        }
    }
    match wizard::remove_omarchy_hook(&dirs.config_home) {
        Ok(Some(hook)) => eprintln!("alephctl: removed {}", hook.display()),
        Ok(None) => {}
        Err(e) => eprintln!("alephctl: {e}"),
    }
    if let Err(e) = c.release_secret_service().await {
        let _ = c.thaw_writes().await;
        return Err(e);
    }
    // (Only once gnome-keyring has everything back: a failed release keeps
    // aleph serving, and its prompt keeps its window rule.)
    match wizard::remove_hyprland_rule(&dirs.config_home) {
        Ok(Some(config)) => eprintln!(
            "alephctl: took the prompt's window rule out of {}",
            config.display()
        ),
        Ok(None) => {}
        Err(e) => eprintln!("alephctl: {e}"),
    }
    record.revert_phase = None;
    record.save(&dirs)?;
    eprintln!(
        "alephctl: gnome-keyring serves the Secret Service again; the aleph vault is left in place"
    );
    // The root side last (E3).
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.to_string_lossy();
    if let Err(e) = wizard::run_as_root(&[exe.as_ref(), "system", "revert"]) {
        eprintln!("alephctl: {e}; run `sudo alephctl system revert` to undo the PAM changes");
    }
    Ok(())
}

/// Offer to set the TPM's lockoutAuth (D9): shown once, typed back, then
/// set through sudo from standard input; declined, the command is printed.
fn offer_lockout_auth(term: &mut prompter::Terminal) -> Result<()> {
    let command = format!(
        "sudo {} (the value on standard input)",
        wizard::LOCKOUT_COMMAND.join(" ")
    );
    let answer = ask(
        term,
        "Protect the TPM's dictionary-attack lockout with a password of its own (recommended if nobody set one)? [y/N] ",
    )?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        eprintln!("alephctl: later: {command}");
        return Ok(());
    }
    let value = zeroize::Zeroizing::new(wizard::lockout_value()?);
    eprintln!(
        "\nThe TPM lockout password. Keep it with your recovery key; it is needed only to clear a dictionary-attack lockout:\n\n    {}\n",
        value.as_str()
    );
    let typed = zeroize::Zeroizing::new(term_line(term, "Type it back to confirm: ")?);
    if !wizard::lockout_matches(&value, &typed) {
        eprintln!(
            "alephctl: that does not match; the lockout password was not set (later: {command})"
        );
        return Ok(());
    }
    if let Err(e) = wizard::set_lockout_auth(&value) {
        eprintln!("alephctl: {e}");
    }
    Ok(())
}

/// Create the keyring, asking which unlock method to use (a security key
/// by default with autologin, where no login password unlocks it).
async fn create_keyring(c: &Client, tpm: bool, autologin: bool) -> Result<()> {
    let first = if tpm {
        "the TPM and your login password"
    } else {
        "your login password"
    };
    let (default, first, second) = if autologin {
        (
            "2",
            first.to_string(),
            "a FIDO2 security key (recommended with autologin)",
        )
    } else {
        (
            "1",
            format!("{first} (recommended)"),
            "a FIDO2 security key",
        )
    };
    eprintln!("How should the keyring unlock?\n  1) {first}\n  2) {second}");
    let mut term = prompter::Terminal::new();
    let choice = term_line(&mut term, &format!("Choice [{default}]: "))?;
    let choice = match choice.trim() {
        "" => default,
        other => other,
    };
    let method = if choice == "2" { "fido2" } else { "password" };
    outcome(c.converse("Create", Args::Str(method)).await?)?;
    Ok(())
}

fn term_line(term: &mut prompter::Terminal, prompt: &str) -> Result<String> {
    term.line(prompt).map_err(|e| e.to_string())
}

/// A question with a default: no more input (end of file) takes it.
fn ask(term: &mut prompter::Terminal, prompt: &str) -> Result<String> {
    match term.line(prompt) {
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(String::new()),
        other => other.map_err(|e| e.to_string()),
    }
}

/// A keyslot id from its full form or a unique prefix (as `status` shows).
async fn full_id(c: &Client, prefix: &str) -> Result<String> {
    let slots = c.status().await?.keyslots;
    // Unknown slots without an id report the nil UUID; never match those.
    let nil = "00000000-0000-0000-0000-000000000000";
    let matches: Vec<&client::SlotInfo> = slots
        .iter()
        .filter(|s| s.id != nil && s.id.starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => Err(format!("no keyslot {prefix:?}")),
        _ => Err(format!(
            "{prefix:?} matches several keyslots; give more of the id"
        )),
    }
}

fn print_slots(slots: &[client::SlotInfo]) {
    for s in slots {
        let stale = if s.stale { "  (stale)" } else { "" };
        println!(
            "  {}  {:<15} {}{stale}",
            &s.id[..8.min(s.id.len())],
            s.kind,
            s.label
        );
    }
}

fn print_item(item: &client::ItemInfo) {
    println!("{}", item.label);
    let mut attrs: Vec<_> = item.attributes.iter().collect();
    attrs.sort();
    for (k, v) in attrs {
        println!("  {k} = {v}");
    }
}

/// The secret to store: typed with echo off at a terminal, else all of
/// standard input (a single trailing newline is dropped, as `secret-tool`
/// does).
fn read_secret() -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if std::io::stdin().is_terminal() {
        let s = rpassword::prompt_password("Secret: ").map_err(|e| e.to_string())?;
        return Ok(zeroize::Zeroizing::new(s.into_bytes()));
    }
    // Reserved up front so ordinary secrets never reallocate (a
    // reallocation would leave an unzeroized copy behind).
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(64 * 1024));
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    Ok(buf)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("alephctl: {e}");
            ExitCode::FAILURE
        }
    }
}
