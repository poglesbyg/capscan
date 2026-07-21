use std::fs;

use std::str::FromStr;

use capscan::{
    diff_reports, filter_by_min_severity, lockfile_version_changes, parse_lockfile, scan_dir,
    AuditEntry, CrateReport, Diff, LockedDependency, Severity, Signal, SignalKind,
};
use tempfile::TempDir;

fn make_crate(files: &[(&str, &str)]) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (rel, content) in files {
        let path = dir.path().join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
    }
    dir
}

const MINIMAL_MANIFEST: &str = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n";

#[test]
fn detects_unsafe_block() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "pub fn f() { unsafe { std::hint::unreachable_unchecked(); } }\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::UnsafeBlock));
}

#[test]
fn detects_unsafe_fn() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        ("src/lib.rs", "pub unsafe fn dangerous() {}\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::UnsafeFn && s.detail == "dangerous"));
}

#[test]
fn detects_unsafe_impl() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        ("src/lib.rs", "pub struct S;\nunsafe impl Send for S {}\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::UnsafeImpl));
}

#[test]
fn detects_ffi_block() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        ("src/lib.rs", "extern \"C\" {\n    fn foo();\n}\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::Ffi));
}

#[test]
fn detects_process_spawn() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "pub fn f() { let _ = std::process::Command::new(\"ls\"); }\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::ProcessSpawn));
}

#[test]
fn detects_network_access() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "pub fn f() { let _ = std::net::TcpStream::connect(\"a:1\"); }\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::NetworkAccess));
}

#[test]
fn detects_filesystem_write() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "pub fn f() { let _ = std::fs::write(\"a\", \"b\"); }\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::FilesystemWrite));
}

#[test]
fn detects_env_read_and_write() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "pub fn f() { std::env::set_var(\"A\", \"B\"); let _ = std::env::var(\"A\"); }\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::EnvWrite));
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::EnvRead));
}

#[test]
fn detects_transmute() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "pub fn f(x: u32) -> f32 { unsafe { std::mem::transmute(x) } }\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::Transmute));
}

#[test]
fn detects_symbol_export_attrs() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "#[no_mangle]\npub extern \"C\" fn exported() {}\n\n#[export_name = \"other_name\"]\npub fn also_exported() {}\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    let exports: Vec<_> = report
        .signals
        .iter()
        .filter(|s| s.kind == SignalKind::SymbolExport)
        .collect();
    assert_eq!(exports.len(), 2);
    assert!(exports.iter().any(|s| s.detail == "exported"));
    assert!(exports.iter().any(|s| s.detail == "also_exported"));
}

#[test]
fn detects_network_access_via_common_http_crates() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "pub fn f() { let _ = reqwest::blocking::get(\"http://x\"); }\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::NetworkAccess));
}

#[test]
fn detects_build_time_macro() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        (
            "src/lib.rs",
            "pub fn f() { let _ = env!(\"CARGO_PKG_NAME\"); }\n",
        ),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::BuildTimeMacro));
}

#[test]
fn detects_build_script_presence() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        ("build.rs", "fn main() {}\n"),
        ("src/lib.rs", "\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::BuildScript && s.file == "build.rs"));
}

#[test]
fn detects_proc_macro_crate() {
    let manifest = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[lib]\nproc-macro = true\n";
    let dir = make_crate(&[("Cargo.toml", manifest), ("src/lib.rs", "\n")]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::ProcMacroCrate));
}

#[test]
fn detects_native_linkage() {
    let manifest = "[package]\nname = \"x\"\nversion = \"0.1.0\"\nlinks = \"foo\"\n";
    let dir = make_crate(&[("Cargo.toml", manifest), ("src/lib.rs", "\n")]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::NativeLinkage && s.detail.contains("foo")));
}

#[test]
fn parses_dependencies_from_manifest() {
    let manifest =
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nlibc = \"0.2\"\n";
    let dir = make_crate(&[("Cargo.toml", manifest), ("src/lib.rs", "\n")]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert_eq!(
        report.dependencies,
        vec!["libc".to_string(), "serde".to_string()]
    );
}

#[test]
fn skips_target_dir_and_unparseable_fragments() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        ("src/lib.rs", "pub fn f() {}\n"),
        ("README.md", "# not rust\n"),
        ("src/fragment.rs", "this is not valid rust {{{\n"),
        ("target/debug/build/ghost.rs", "pub unsafe fn ghost() {}\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(!report.signals.iter().any(|s| s.detail == "ghost"));
    assert_eq!(report.files_scanned, 1); // only lib.rs parses; fragment.rs is skipped, not counted
}

fn synthetic_report(name: &str, version: &str, signals: Vec<Signal>, deps: &[&str]) -> CrateReport {
    CrateReport {
        name: name.to_string(),
        version: version.to_string(),
        files_scanned: 1,
        lines_scanned: 1,
        dependencies: deps.iter().map(|s| s.to_string()).collect(),
        signals,
    }
}

fn signal(kind: SignalKind, line: usize, detail: &str) -> Signal {
    Signal {
        kind,
        file: "src/lib.rs".to_string(),
        line,
        detail: detail.to_string(),
    }
}

#[test]
fn diff_flags_new_signal_and_dependency() {
    let old = synthetic_report("x", "1.0.0", vec![], &["serde"]);
    let new = synthetic_report(
        "x",
        "1.1.0",
        vec![signal(SignalKind::UnsafeFn, 3, "danger")],
        &["serde", "libc"],
    );
    let diff = diff_reports(&old, &new);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added_dependencies, vec!["libc".to_string()]);
    assert_eq!(diff.worst_severity(), Some(Severity::High));
}

#[test]
fn diff_ignores_line_number_shifts() {
    let old = synthetic_report(
        "x",
        "1.0.0",
        vec![signal(SignalKind::UnsafeBlock, 10, "unsafe { .. }")],
        &[],
    );
    let new = synthetic_report(
        "x",
        "1.0.1",
        vec![signal(SignalKind::UnsafeBlock, 20, "unsafe { .. }")],
        &[],
    );
    let diff = diff_reports(&old, &new);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.worst_severity(), None);
}

#[test]
fn diff_flags_removed_signal_but_not_as_new_risk() {
    let old = synthetic_report(
        "x",
        "1.0.0",
        vec![signal(SignalKind::Ffi, 1, "extern \"C\" { 1 item(s) }")],
        &[],
    );
    let new = synthetic_report("x", "1.1.0", vec![], &[]);
    let diff = diff_reports(&old, &new);
    assert_eq!(diff.removed.len(), 1);
    assert!(diff.added.is_empty());
    assert_eq!(diff.worst_severity(), None);
}

#[test]
fn parse_lockfile_keeps_only_registry_dependencies() {
    let lockfile = r#"
# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "root-crate"
version = "0.1.0"
dependencies = ["anyhow", "local-path-dep"]

[[package]]
name = "anyhow"
version = "1.0.104"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"

[[package]]
name = "local-path-dep"
version = "0.1.0"
"#;
    let dir = make_crate(&[("Cargo.lock", lockfile)]);
    let deps = parse_lockfile(&dir.path().join("Cargo.lock")).unwrap();

    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "anyhow");
    assert_eq!(deps[0].version, "1.0.104");
}

#[test]
fn severity_orders_low_lt_medium_lt_high() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
}

#[test]
fn severity_from_str_accepts_any_case() {
    assert_eq!(Severity::from_str("low").unwrap(), Severity::Low);
    assert_eq!(Severity::from_str("Medium").unwrap(), Severity::Medium);
    assert_eq!(Severity::from_str("HIGH").unwrap(), Severity::High);
}

#[test]
fn severity_from_str_rejects_unknown_values() {
    let err = Severity::from_str("critical").unwrap_err();
    assert!(err.contains("critical"));
}

fn audit_entry_with_severity(name: &str, worst: Option<Severity>) -> AuditEntry {
    let diff = worst.map(|sev| {
        let kind = match sev {
            Severity::Low => SignalKind::EnvRead,
            Severity::Medium => SignalKind::UnsafeBlock,
            Severity::High => SignalKind::UnsafeFn,
        };
        Diff {
            old: (name.to_string(), "1.0.0".to_string()),
            new: (name.to_string(), "2.0.0".to_string()),
            added: vec![Signal {
                kind,
                file: "src/lib.rs".to_string(),
                line: 1,
                detail: "x".to_string(),
            }],
            removed: vec![],
            added_dependencies: vec![],
            removed_dependencies: vec![],
        }
    });
    AuditEntry {
        name: name.to_string(),
        locked_version: "1.0.0".to_string(),
        latest_version: if worst.is_some() { "2.0.0" } else { "1.0.0" }.to_string(),
        diff,
    }
}

#[test]
fn filter_by_min_severity_keeps_only_at_or_above_threshold() {
    let entries = vec![
        audit_entry_with_severity("up-to-date", None),
        audit_entry_with_severity("low-only", Some(Severity::Low)),
        audit_entry_with_severity("medium-hit", Some(Severity::Medium)),
        audit_entry_with_severity("high-hit", Some(Severity::High)),
    ];

    let filtered = filter_by_min_severity(entries, Severity::Medium);
    let names: Vec<&str> = filtered.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["medium-hit", "high-hit"]);
}

fn locked(name: &str, version: &str) -> LockedDependency {
    LockedDependency {
        name: name.to_string(),
        version: version.to_string(),
    }
}

#[test]
fn lockfile_version_changes_detects_updated_crate() {
    let old = vec![locked("anyhow", "1.0.70"), locked("serde", "1.0.200")];
    let new = vec![locked("anyhow", "1.0.104"), locked("serde", "1.0.200")];

    let changes = lockfile_version_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].name, "anyhow");
    assert_eq!(changes[0].old_version.as_deref(), Some("1.0.70"));
    assert_eq!(changes[0].new_version.as_deref(), Some("1.0.104"));
}

#[test]
fn lockfile_version_changes_detects_added_and_removed_crates() {
    let old = vec![locked("removed-dep", "1.0.0")];
    let new = vec![locked("added-dep", "2.0.0")];

    let changes = lockfile_version_changes(&old, &new);
    assert_eq!(changes.len(), 2);

    let added = changes.iter().find(|c| c.name == "added-dep").unwrap();
    assert_eq!(added.old_version, None);
    assert_eq!(added.new_version.as_deref(), Some("2.0.0"));

    let removed = changes.iter().find(|c| c.name == "removed-dep").unwrap();
    assert_eq!(removed.old_version.as_deref(), Some("1.0.0"));
    assert_eq!(removed.new_version, None);
}

#[test]
fn lockfile_version_changes_ignores_unchanged_crates() {
    let deps = vec![locked("anyhow", "1.0.104"), locked("serde", "1.0.200")];
    let changes = lockfile_version_changes(&deps, &deps.clone());
    assert!(changes.is_empty());
}

#[test]
fn lockfile_version_changes_is_sorted_by_name() {
    let old = vec![locked("zzz", "1.0.0"), locked("aaa", "1.0.0")];
    let new = vec![locked("zzz", "2.0.0"), locked("aaa", "2.0.0")];

    let changes = lockfile_version_changes(&old, &new);
    let names: Vec<&str> = changes.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["aaa", "zzz"]);
}
