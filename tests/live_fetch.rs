//! Hits the real crates.io registry via a scratch `cargo add`/`cargo fetch`.
//! Excluded from normal `cargo test` runs; run explicitly with:
//!   cargo test --test live_fetch -- --ignored

use std::fs;

use capscan::{diff_lockfiles, diff_reports, locate_or_fetch, scan_dir};

#[test]
#[ignore = "requires network access to crates.io"]
fn diffing_two_real_anyhow_versions_finds_a_new_unsafe_fn() {
    let old_path = locate_or_fetch("anyhow", "1.0.70").unwrap();
    let new_path = locate_or_fetch("anyhow", "1.0.104").unwrap();
    let old = scan_dir("anyhow", "1.0.70", &old_path).unwrap();
    let new = scan_dir("anyhow", "1.0.104", &new_path).unwrap();
    let diff = diff_reports(&old, &new);
    assert!(diff
        .added
        .iter()
        .any(|s| s.detail == "object_reallocate_boxed"));
}

fn minimal_lockfile(packages: &[(&str, &str)]) -> String {
    let mut out = String::from("version = 4\n\n");
    for (name, version) in packages {
        out.push_str(&format!(
            "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n"
        ));
    }
    out
}

#[test]
#[ignore = "requires network access to crates.io"]
fn diff_lockfiles_handles_updated_added_and_removed_crates_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let old_path = dir.path().join("old.lock");
    let new_path = dir.path().join("new.lock");

    // anyhow: updated (a version bump we've already verified adds a real
    // unsafe fn, above). backtrace: removed. serde: added.
    fs::write(
        &old_path,
        minimal_lockfile(&[("anyhow", "1.0.70"), ("backtrace", "0.3.67")]),
    )
    .unwrap();
    fs::write(
        &new_path,
        minimal_lockfile(&[("anyhow", "1.0.104"), ("serde", "1.0.200")]),
    )
    .unwrap();

    let results = diff_lockfiles(&old_path, &new_path).unwrap();
    assert_eq!(results.len(), 3);

    let anyhow = results.iter().find(|r| r.name == "anyhow").unwrap();
    assert_eq!(anyhow.old_version.as_deref(), Some("1.0.70"));
    assert_eq!(anyhow.new_version.as_deref(), Some("1.0.104"));
    assert!(anyhow.error.is_none());
    assert!(anyhow
        .diff
        .as_ref()
        .unwrap()
        .added
        .iter()
        .any(|s| s.detail == "object_reallocate_boxed"));

    let backtrace = results.iter().find(|r| r.name == "backtrace").unwrap();
    assert_eq!(backtrace.old_version.as_deref(), Some("0.3.67"));
    assert_eq!(backtrace.new_version, None);
    assert!(backtrace.diff.is_none());
    assert!(backtrace.error.is_none());

    let serde = results.iter().find(|r| r.name == "serde").unwrap();
    assert_eq!(serde.old_version, None);
    assert_eq!(serde.new_version.as_deref(), Some("1.0.200"));
    assert!(serde.error.is_none());
    // "added" crate is represented as a diff from nothing: its whole
    // capability surface shows up as `added` signals.
    let serde_diff = serde.diff.as_ref().unwrap();
    assert!(serde_diff.removed.is_empty());
}
