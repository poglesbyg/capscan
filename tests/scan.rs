use std::fs;

use capscan::{diff_reports, scan_dir, CrateReport, Severity, Signal, SignalKind};
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
        ("src/lib.rs", "pub fn f() { unsafe { std::hint::unreachable_unchecked(); } }\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::UnsafeBlock));
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
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::UnsafeImpl));
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
        ("src/lib.rs", "pub fn f() { let _ = std::process::Command::new(\"ls\"); }\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::ProcessSpawn));
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
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::NetworkAccess));
}

#[test]
fn detects_filesystem_write() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        ("src/lib.rs", "pub fn f() { let _ = std::fs::write(\"a\", \"b\"); }\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::FilesystemWrite));
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
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::EnvWrite));
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::EnvRead));
}

#[test]
fn detects_build_time_macro() {
    let dir = make_crate(&[
        ("Cargo.toml", MINIMAL_MANIFEST),
        ("src/lib.rs", "pub fn f() { let _ = env!(\"CARGO_PKG_NAME\"); }\n"),
    ]);
    let report = scan_dir("x", "0.1.0", dir.path()).unwrap();
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::BuildTimeMacro));
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
    assert!(report.signals.iter().any(|s| s.kind == SignalKind::ProcMacroCrate));
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
    assert_eq!(report.dependencies, vec!["libc".to_string(), "serde".to_string()]);
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
    let old = synthetic_report("x", "1.0.0", vec![signal(SignalKind::UnsafeBlock, 10, "unsafe { .. }")], &[]);
    let new = synthetic_report("x", "1.0.1", vec![signal(SignalKind::UnsafeBlock, 20, "unsafe { .. }")], &[]);
    let diff = diff_reports(&old, &new);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.worst_severity(), None);
}

#[test]
fn diff_flags_removed_signal_but_not_as_new_risk() {
    let old = synthetic_report("x", "1.0.0", vec![signal(SignalKind::Ffi, 1, "extern \"C\" { 1 item(s) }")], &[]);
    let new = synthetic_report("x", "1.1.0", vec![], &[]);
    let diff = diff_reports(&old, &new);
    assert_eq!(diff.removed.len(), 1);
    assert!(diff.added.is_empty());
    assert_eq!(diff.worst_severity(), None);
}

#[test]
fn severity_orders_low_lt_medium_lt_high() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
}
