//! The launcher entry agrees with the program: it runs the manager, its
//! window class is the manager's app id, and every icon install.sh
//! copies exists.

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

#[test]
fn the_launcher_entry_opens_the_manager_with_its_icon() {
    let entry = std::fs::read_to_string(format!("{ROOT}/packaging/aleph-gui.desktop")).unwrap();
    let value = |key: &str| {
        entry
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key}"))
            .to_string()
    };
    assert_eq!(value("Exec"), "aleph-gui");
    assert_eq!(value("Icon"), "aleph");
    // (The manager's viewport app id, main.rs.)
    assert_eq!(value("StartupWMClass"), "aleph");
    let main = std::fs::read_to_string(format!("{ROOT}/crates/aleph-gui/src/main.rs")).unwrap();
    assert!(main.contains(".with_app_id(\"aleph\")"));

    let install = std::fs::read_to_string(format!("{ROOT}/packaging/install.sh")).unwrap();
    let icons: Vec<&str> = install
        .split_whitespace()
        .filter(|w| w.starts_with("assets/icons/"))
        .collect();
    assert_eq!(icons.len(), 4, "{icons:?}");
    for icon in icons {
        assert!(
            std::path::Path::new(&format!("{ROOT}/{icon}")).is_file(),
            "{icon}"
        );
    }
    // (The desktop entry is installed to its path — in a line that carries
    // both, whatever target prefix the installer supports.)
    assert!(install.lines().any(|l| {
        l.contains("packaging/aleph-gui.desktop")
            && l.contains("/usr/share/applications/aleph-gui.desktop")
    }));
    // Both install and uninstall refresh the icon and desktop caches.
    assert_eq!(
        install.matches("gtk-update-icon-cache").count(),
        2,
        "{install}"
    );
    assert_eq!(
        install.matches("update-desktop-database").count(),
        2,
        "{install}"
    );
}
