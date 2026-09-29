//! The file picker: whether the portal is there is decided by its bus
//! name's owner (`rfd` cannot tell "no portal" from "cancelled"), and the
//! fake the window tests use.

use std::path::PathBuf;

use aleph_gui::filepicker::{Fake, FilePicker, Pick, portal_present};

#[tokio::test(flavor = "multi_thread")]
async fn the_portal_is_present_only_when_its_name_has_an_owner() {
    let bus = aleph_daemon::testing::bus();
    assert!(!portal_present(Some(&bus.address)).await);
    let _owner = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.portal.Desktop")
        .unwrap()
        .build()
        .await
        .unwrap();
    assert!(portal_present(Some(&bus.address)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_bus_at_all_is_no_portal() {
    assert!(!portal_present(Some("unix:path=/nonexistent/aleph-test-bus")).await);
}

#[test]
fn the_fake_answers_in_order_and_remembers_what_was_asked() {
    let fake = Fake::new(vec![
        Pick::Chosen(PathBuf::from("/tmp/x.aleph")),
        Pick::Cancelled,
    ]);
    let rx = fake.start("a.aleph".into(), Some(PathBuf::from("/home/u")));
    assert_eq!(
        rx.recv().unwrap(),
        Pick::Chosen(PathBuf::from("/tmp/x.aleph"))
    );
    assert_eq!(
        fake.start("b.aleph".into(), None).recv().unwrap(),
        Pick::Cancelled
    );
    // (Nothing left: a cancel.)
    assert_eq!(
        fake.start("c.aleph".into(), None).recv().unwrap(),
        Pick::Cancelled
    );
    assert_eq!(
        fake.asked.lock().unwrap().clone(),
        vec![
            ("a.aleph".to_string(), Some(PathBuf::from("/home/u"))),
            ("b.aleph".to_string(), None),
            ("c.aleph".to_string(), None),
        ]
    );
}
