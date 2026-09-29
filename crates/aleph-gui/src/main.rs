//! `aleph-gui`: the manager window (the manager spec); `aleph-gui prompt`:
//! the prompter alephd starts, with its end of a socketpair as
//! `ALEPH_PROMPT_FD` (spec §6 "Prompter orchestration").

use std::process::ExitCode;

use aleph_gui::{app, clipboard, link, manager, screens, settings, store};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [] => manage(),
        ["prompt"] => prompt(),
        _ => {
            eprintln!("usage: aleph-gui            the keyring manager");
            eprintln!("       aleph-gui prompt     (alephd starts it)");
            ExitCode::from(2)
        }
    }
}

fn manage() -> ExitCode {
    // It shows and copies secrets: no core dumps, no ptrace by other
    // processes of the user.
    // SAFETY: prctl with these arguments only sets a process flag.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let file = settings::config_home().map(|dir| settings::path(&dir));
    let (settings, broken) = match &file {
        Some(f) => settings::Settings::load(f),
        None => (settings::Settings::default(), None),
    };
    if let Some(w) = &broken {
        eprintln!("aleph-gui: {w}");
    }
    let (still, home) = (settings::reduced_motion(), settings::home());
    let viewport = egui::ViewportBuilder::default()
        .with_app_id("aleph")
        .with_title("aleph")
        .with_inner_size(manager::SIZE);
    let options = aleph_gui::native_options(viewport);
    let result = eframe::run_native(
        "aleph",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let store = store::DbusStore::start(None, move || ctx.request_repaint());
            let mut app =
                manager::Manager::new(store, clipboard::Wayland::default(), settings, home, still)
                    .with_settings_file(file, broken);
            aleph_gui::theme::apply(&cc.egui_ctx, &app.palette);
            if still {
                cc.egui_ctx.all_styles_mut(|s| s.animation_time = 0.0);
            }
            app.watch_theme(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aleph-gui: cannot open the window: {e}");
            ExitCode::FAILURE
        }
    }
}

fn prompt() -> ExitCode {
    // What is typed here is a password: no core dumps, no ptrace by
    // other processes of the user.
    // SAFETY: prctl with these arguments only sets a process flag.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    // First, while single-threaded: the variable is removed.
    let stream = match link::take_from_env() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aleph-gui: {e}");
            return ExitCode::from(2);
        }
    };
    let config_home = settings::config_home();
    let (settings, warning) = match &config_home {
        Some(dir) => settings::Settings::load(&settings::path(dir)),
        None => (settings::Settings::default(), None),
    };
    if let Some(w) = warning {
        eprintln!("aleph-gui: {w}");
    }
    let still = settings::reduced_motion();
    let home = settings::home();
    let viewport = egui::ViewportBuilder::default()
        .with_app_id("aleph-prompt")
        .with_title("aleph")
        .with_inner_size(screens::SIZE)
        .with_min_inner_size(screens::SIZE)
        .with_max_inner_size(screens::SIZE)
        .with_resizable(false)
        .with_active(true);
    let options = aleph_gui::native_options(viewport);
    let result = eframe::run_native(
        "aleph-prompt",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let events = link::spawn_reader(stream.try_clone()?, move || ctx.request_repaint())?;
            let mut app = app::PromptApp::new(stream, events, settings, home, still);
            aleph_gui::theme::apply(&cc.egui_ctx, &app.ui.palette);
            if still {
                cc.egui_ctx.all_styles_mut(|s| s.animation_time = 0.0);
            }
            app.watch_theme(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Without an answer: alephd reads the closed socket as "no
            // prompter", and the prompt waits for an unlock from elsewhere
            // (a Cancel would dismiss it).
            eprintln!("aleph-gui: cannot open the prompt window: {e}");
            ExitCode::FAILURE
        }
    }
}
