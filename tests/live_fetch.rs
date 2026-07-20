//! Hits the real crates.io registry via a scratch `cargo add`/`cargo fetch`.
//! Excluded from normal `cargo test` runs; run explicitly with:
//!   cargo test --test live_fetch -- --ignored

use capscan::{diff_reports, locate_or_fetch, scan_dir};

#[test]
#[ignore = "requires network access to crates.io"]
fn diffing_two_real_anyhow_versions_finds_a_new_unsafe_fn() {
    let old_path = locate_or_fetch("anyhow", "1.0.70").unwrap();
    let new_path = locate_or_fetch("anyhow", "1.0.104").unwrap();
    let old = scan_dir("anyhow", "1.0.70", &old_path).unwrap();
    let new = scan_dir("anyhow", "1.0.104", &new_path).unwrap();
    let diff = diff_reports(&old, &new);
    assert!(diff.added.iter().any(|s| s.detail == "object_reallocate_boxed"));
}
