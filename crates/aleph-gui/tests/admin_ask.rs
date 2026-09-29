//! The admin page's Yes/No step: No starts focused, and Tab can move to Yes.

use aleph_gui::admin_page::{Ask, ask_section};
use egui::Key;
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};

#[test]
fn no_starts_focused_and_tab_reaches_yes() {
    let p = aleph_gui::theme::neon();
    let mut h = Harness::new_ui(move |ui| {
        ask_section(ui, &p, &Ask::NewRecoveryKey);
    });
    h.run();
    assert!(h.get_by_label("No").accesskit_node().is_focused());
    h.key_press(Key::Tab);
    h.run();
    h.run();
    assert!(h.get_by_label("Yes").accesskit_node().is_focused());
    assert!(!h.get_by_label("No").accesskit_node().is_focused());
}
