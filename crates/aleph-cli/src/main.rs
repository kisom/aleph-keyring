//! `aleph`, the command-line client (spec §7 "CLI").
//!
//! Everything goes through the running `alephd`: `io.aleph.Admin1` for the
//! keyring, the Secret Service for items. Prompts the daemon needs are
//! answered in this terminal. Secrets are read from standard input, never
//! from the command line.

mod client;
mod prompter;

use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

use client::{Args, Client, Result};

#[derive(Parser)]
#[command(name = "aleph", version, about = "The aleph keyring")]
struct Cli {
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the keyring (system integration comes in a later release).
    Setup,
    /// Show the keyring's state and keyslots.
    Status,
    Lock,
    Unlock,
    #[command(subcommand)]
    Keyslot(KeyslotCmd),
    #[command(subcommand)]
    Recovery(RecoveryCmd),
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
            eprintln!("aleph: {m}");
            Ok(())
        }
        (true, None) => Ok(()),
        (false, m) => Err(m.unwrap_or_else(|| "failed".into())),
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    if let Cmd::Completions { shell } = cli.cmd {
        clap_complete::generate(shell, &mut Cli::command(), "aleph", &mut std::io::stdout());
        return Ok(ExitCode::SUCCESS);
    }
    let c = Client::connect().await?;
    match cli.cmd {
        Cmd::Completions { .. } => unreachable!(),
        Cmd::Setup => {
            let status = c.status().await?;
            if status.vault {
                eprintln!("aleph: a keyring already exists (see `aleph status`)");
                return Ok(ExitCode::SUCCESS);
            }
            let tpm = status.tpm.unwrap_or(false);
            let first = if tpm {
                "the TPM and your login password (recommended)"
            } else {
                "your login password"
            };
            eprintln!("How should the keyring unlock?\n  1) {first}\n  2) a FIDO2 security key");
            let mut term = prompter::Terminal::new();
            let choice = term_line(&mut term, "Choice [1]: ")?;
            let method = if choice.trim() == "2" {
                "fido2"
            } else {
                "password"
            };
            outcome(c.converse("Create", Args::Str(method)).await?)?;
            eprintln!(
                "aleph: note: setup does not yet set up login unlock (PAM), take over from gnome-keyring, or import its items: these are not available yet (see docs/testing.md for the PAM lines)"
            );
        }
        Cmd::Status => {
            let s = c.status().await?;
            if cli.json {
                print_json(&s)?;
            } else {
                let state = match (s.vault, s.locked) {
                    (false, _) => "none (run `aleph setup`)",
                    (true, true) => "locked",
                    (true, false) => "unlocked",
                };
                println!("keyring: {state}");
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
                        "warning: after a password change the master key still needs rotating: run `aleph keyslot rotate-master`"
                    );
                }
                print_slots(&s.keyslots);
            }
        }
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
                        "aleph: warning: anyone holding a touch-only key can unlock the keyring"
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
                    "aleph: warning: the keyring will stay unlocked through suspend and hibernation; \
                     the master key can then be written to a hibernation image (keep swap encrypted)"
                );
            }
            outcome(c.converse("SetConfig", Args::Str2(&key, &value)).await?)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn term_line(term: &mut prompter::Terminal, prompt: &str) -> Result<String> {
    term.line(prompt).map_err(|e| e.to_string())
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
            eprintln!("aleph: {e}");
            ExitCode::FAILURE
        }
    }
}
