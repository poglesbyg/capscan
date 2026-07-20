//! Core scanning/diffing logic for `capscan`.
//!
//! Walks a crate's source tree with `syn`, records a coarse but structural
//! "capability surface" (unsafe, FFI, process/network/fs access, macros that
//! read the environment at build time, build scripts, proc-macro crates,
//! native linkage), and can diff that surface between two versions of the
//! same crate so a `cargo update` risk is visible before it lands.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::thread;

use anyhow::{bail, Context, Result};
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalKind {
    UnsafeBlock,
    UnsafeFn,
    UnsafeImpl,
    Ffi,
    ProcessSpawn,
    NetworkAccess,
    FilesystemWrite,
    EnvRead,
    EnvWrite,
    BuildTimeMacro,
    BuildScript,
    ProcMacroCrate,
    NativeLinkage,
    Transmute,
    SymbolExport,
}

impl SignalKind {
    /// How much attention a *newly added* instance of this signal deserves.
    pub fn severity(&self) -> Severity {
        use SignalKind::*;
        match self {
            UnsafeFn | UnsafeImpl | Ffi | ProcessSpawn | BuildScript | NativeLinkage
            | ProcMacroCrate | Transmute | SymbolExport => Severity::High,
            UnsafeBlock | NetworkAccess | FilesystemWrite | EnvWrite => Severity::Medium,
            EnvRead | BuildTimeMacro => Severity::Low,
        }
    }
}

impl fmt::Display for SignalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SignalKind::UnsafeBlock => "unsafe block",
            SignalKind::UnsafeFn => "unsafe fn",
            SignalKind::UnsafeImpl => "unsafe impl",
            SignalKind::Ffi => "extern FFI block",
            SignalKind::ProcessSpawn => "process spawn",
            SignalKind::NetworkAccess => "network access",
            SignalKind::FilesystemWrite => "filesystem write",
            SignalKind::EnvRead => "env read",
            SignalKind::EnvWrite => "env write",
            SignalKind::BuildTimeMacro => "build-time macro",
            SignalKind::BuildScript => "build.rs script",
            SignalKind::ProcMacroCrate => "proc-macro crate",
            SignalKind::NativeLinkage => "native library linkage",
            SignalKind::Transmute => "mem::transmute",
            SignalKind::SymbolExport => "exported symbol",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub kind: SignalKind,
    pub file: String,
    pub line: usize,
    pub detail: String,
}

impl Signal {
    /// Identity used when diffing across versions: line numbers shift
    /// constantly and shouldn't cause noise, so we key on kind + what was
    /// detected, not where.
    fn dedup_key(&self) -> (SignalKind, String) {
        (self.kind, self.detail.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateReport {
    pub name: String,
    pub version: String,
    pub files_scanned: usize,
    pub lines_scanned: usize,
    pub dependencies: Vec<String>,
    pub signals: Vec<Signal>,
}

impl CrateReport {
    pub fn counts(&self) -> HashMap<SignalKind, usize> {
        let mut m = HashMap::new();
        for s in &self.signals {
            *m.entry(s.kind).or_insert(0) += 1;
        }
        m
    }
}

fn path_str(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Heuristic classification of a free function call's path. This can't do
/// real name resolution (that would require a full compile), so it matches
/// on recognizable `std`/common-crate path shapes. False negatives (e.g. a
/// call through a re-exported alias) are expected; the goal is signal, not
/// completeness.
fn classify_call(v: &mut Visitor, path: &str, span: proc_macro2::Span) {
    if path.ends_with("mem::transmute") || path.ends_with("mem::transmute_copy") {
        v.push(SignalKind::Transmute, span, path.to_string());
    } else if path.ends_with("Command::new") {
        v.push(SignalKind::ProcessSpawn, span, path.to_string());
    } else if path.contains("TcpStream")
        || path.contains("TcpListener")
        || path.contains("TcpSocket")
        || path.contains("UdpSocket")
        || path.contains("UnixStream")
        || path.contains("UnixListener")
        || path.starts_with("reqwest::")
        || path.starts_with("hyper::")
        || path.starts_with("ureq::")
    {
        v.push(SignalKind::NetworkAccess, span, path.to_string());
    } else if path.ends_with("fs::write")
        || path.ends_with("File::create")
        || path.ends_with("remove_file")
        || path.ends_with("remove_dir_all")
        || path.ends_with("remove_dir")
        || path.ends_with("OpenOptions::new")
        || path.ends_with("fs::rename")
        || path.ends_with("set_permissions")
    {
        v.push(SignalKind::FilesystemWrite, span, path.to_string());
    } else if path.ends_with("env::set_var") || path.ends_with("env::remove_var") {
        v.push(SignalKind::EnvWrite, span, path.to_string());
    } else if path.ends_with("env::var")
        || path.ends_with("env::vars")
        || path.ends_with("env::var_os")
    {
        v.push(SignalKind::EnvRead, span, path.to_string());
    }
}

/// `#[no_mangle]` / `#[export_name = "..."]` pin a function's symbol name so
/// it can be called from outside the crate (cdylib/staticlib consumers, or
/// linked C code) -- a distinct FFI surface from an `extern "C" { .. }` block.
fn has_symbol_export_attr(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().is_ident("no_mangle") || a.path().is_ident("export_name"))
}

struct Visitor<'a> {
    file: &'a str,
    signals: Vec<Signal>,
}

impl<'a> Visitor<'a> {
    fn push(&mut self, kind: SignalKind, span: proc_macro2::Span, detail: impl Into<String>) {
        self.signals.push(Signal {
            kind,
            file: self.file.to_string(),
            line: span.start().line,
            detail: detail.into(),
        });
    }
}

impl<'a, 'ast> Visit<'ast> for Visitor<'a> {
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.push(SignalKind::UnsafeBlock, node.span(), "unsafe { .. }");
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.unsafety.is_some() {
            self.push(
                SignalKind::UnsafeFn,
                node.span(),
                node.sig.ident.to_string(),
            );
        }
        if has_symbol_export_attr(&node.attrs) {
            self.push(
                SignalKind::SymbolExport,
                node.span(),
                node.sig.ident.to_string(),
            );
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if node.unsafety.is_some() {
            let detail = node.self_ty.to_token_stream().to_string();
            self.push(SignalKind::UnsafeImpl, node.span(), detail);
        }
        visit::visit_item_impl(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let abi = node
            .abi
            .name
            .as_ref()
            .map(|l| l.value())
            .unwrap_or_default();
        self.push(
            SignalKind::Ffi,
            node.span(),
            format!("extern \"{}\" {{ {} item(s) }}", abi, node.items.len()),
        );
        visit::visit_item_foreign_mod(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            let path = path_str(&p.path);
            classify_call(self, &path, node.span());
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = path_str(&node.path);
        if matches!(
            name.as_str(),
            "env" | "option_env" | "include" | "include_str" | "include_bytes"
        ) {
            self.push(SignalKind::BuildTimeMacro, node.span(), name);
        }
        visit::visit_macro(self, node);
    }
}

/// Walk every `.rs` file under `root` and build a capability report for it.
pub fn scan_dir(name: &str, version: &str, root: &Path) -> Result<CrateReport> {
    let mut signals = Vec::new();
    let mut files_scanned = 0usize;
    let mut lines_scanned = 0usize;

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| e.file_name() != "target" && e.file_name() != ".git")
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        lines_scanned += content.lines().count();

        let file_rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();

        let parsed = match syn::parse_file(&content) {
            Ok(f) => f,
            Err(_) => continue, // not every .rs file parses standalone (e.g. included fragments)
        };
        files_scanned += 1;

        let mut visitor = Visitor {
            file: &file_rel,
            signals: Vec::new(),
        };
        visitor.visit_file(&parsed);
        signals.extend(visitor.signals);
    }

    if root.join("build.rs").is_file() {
        signals.push(Signal {
            kind: SignalKind::BuildScript,
            file: "build.rs".into(),
            line: 0,
            detail: "build script present".into(),
        });
    }

    let mut dependencies = Vec::new();
    let manifest_path = root.join("Cargo.toml");
    if let Ok(manifest) = std::fs::read_to_string(&manifest_path) {
        if let Ok(value) = manifest.parse::<toml::Value>() {
            let is_proc_macro = value
                .get("lib")
                .and_then(|l| l.get("proc-macro"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_proc_macro {
                signals.push(Signal {
                    kind: SignalKind::ProcMacroCrate,
                    file: "Cargo.toml".into(),
                    line: 0,
                    detail: "lib.proc-macro = true".into(),
                });
            }

            if let Some(links) = value
                .get("package")
                .and_then(|p| p.get("links"))
                .and_then(|v| v.as_str())
            {
                signals.push(Signal {
                    kind: SignalKind::NativeLinkage,
                    file: "Cargo.toml".into(),
                    line: 0,
                    detail: format!("links = \"{links}\""),
                });
            }

            for key in ["dependencies", "build-dependencies"] {
                if let Some(table) = value.get(key).and_then(|d| d.as_table()) {
                    dependencies.extend(table.keys().cloned());
                }
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();

    Ok(CrateReport {
        name: name.to_string(),
        version: version.to_string(),
        files_scanned,
        lines_scanned,
        dependencies,
        signals,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedDependency {
    pub name: String,
    pub version: String,
}

/// Parse a `Cargo.lock` and return every dependency sourced from crates.io.
/// Path and git dependencies (and the workspace's own root package, which
/// has no `source` field) are skipped -- there's no "latest version" to
/// compare a path dependency against.
pub fn parse_lockfile(path: &Path) -> Result<Vec<LockedDependency>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: toml::Value = content.parse().context("parsing Cargo.lock as TOML")?;
    let packages = value
        .get("package")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    let mut deps = Vec::new();
    for pkg in packages {
        let is_registry_dep = pkg
            .get("source")
            .and_then(|s| s.as_str())
            .map(|s| s.starts_with("registry+"))
            .unwrap_or(false);
        if !is_registry_dep {
            continue;
        }
        if let (Some(name), Some(version)) = (
            pkg.get("name").and_then(|v| v.as_str()),
            pkg.get("version").and_then(|v| v.as_str()),
        ) {
            deps.push(LockedDependency {
                name: name.to_string(),
                version: version.to_string(),
            });
        }
    }
    Ok(deps)
}

/// Ask cargo what the latest published version of `name` is, by running
/// `cargo add --dry-run` in a throwaway scratch project and reading the
/// version back out of the scratch project's `Cargo.lock` -- not by parsing
/// `cargo add`'s human-readable "Adding NAME vVERSION" summary, which
/// truncates semver build metadata (`1.1.3+spec-1.1.0` prints as `1.1.3`,
/// which then doesn't match any directory in the registry source cache).
/// Reuses the same trusted cargo-shells-out path as [`locate_or_fetch`]
/// rather than talking to the registry API directly. Returns `Ok(None)`
/// (not an error) if the crate can't be resolved, e.g. it was pulled from
/// crates.io since the lockfile was written.
pub fn latest_version(name: &str) -> Result<Option<String>> {
    let tmp = tempfile::tempdir().context("creating scratch dir")?;
    let status = ProcCommand::new("cargo")
        .args(["init", "--name", "capscan_probe", "--quiet"])
        .current_dir(tmp.path())
        .status()
        .context("running `cargo init`")?;
    if !status.success() {
        bail!("`cargo init` failed while resolving the latest version of {name}");
    }

    let status = ProcCommand::new("cargo")
        .args(["add", name, "--quiet"])
        .current_dir(tmp.path())
        .status()
        .context("running `cargo add`")?;
    if !status.success() {
        return Ok(None); // crate not found / couldn't be resolved -- not a hard error
    }

    let deps = parse_lockfile(&tmp.path().join("Cargo.lock"))?;
    Ok(deps.into_iter().find(|d| d.name == name).map(|d| d.version))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub name: String,
    pub locked_version: String,
    pub latest_version: String,
    /// `None` means locked and latest are the same version -- nothing to diff.
    pub diff: Option<Diff>,
}

impl AuditEntry {
    pub fn worst_severity(&self) -> Option<Severity> {
        self.diff.as_ref().and_then(Diff::worst_severity)
    }
}

/// Each lookup is dominated by `cargo` subprocess startup + registry-index
/// I/O, not CPU, so it's worth running many at once even on a small number
/// of cores. Capped rather than one-thread-per-name so a huge lockfile
/// doesn't spawn hundreds of concurrent `cargo` processes fighting over the
/// registry cache lock.
const MAX_VERSION_LOOKUP_WORKERS: usize = 16;

/// Resolve the latest published version of every name in `names`, in
/// parallel. Each name is independent (its own scratch tempdir, no shared
/// mutable state) so this is a plain worker pool over `std::thread::scope`
/// rather than anything needing synchronization beyond collecting results.
fn resolve_latest_versions(names: &[String]) -> HashMap<String, String> {
    let worker_count = names.len().clamp(1, MAX_VERSION_LOOKUP_WORKERS);
    let mut chunks: Vec<Vec<&str>> = vec![Vec::new(); worker_count];
    for (i, name) in names.iter().enumerate() {
        chunks[i % worker_count].push(name.as_str());
    }

    let mut latest_by_name = HashMap::new();
    thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .into_iter()
                        .map(|name| (name, latest_version(name)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        for handle in handles {
            for (name, resolved) in handle.join().expect("version-lookup worker panicked") {
                match resolved {
                    Ok(Some(v)) => {
                        latest_by_name.insert(name.to_string(), v);
                    }
                    Ok(None) => {
                        eprintln!(
                            "warning: couldn't resolve a latest version for {name}, skipping"
                        );
                    }
                    Err(e) => {
                        eprintln!("warning: failed to resolve latest version for {name}: {e}");
                    }
                }
            }
        }
    });
    latest_by_name
}

/// The end-to-end real-world workflow: read a project's `Cargo.lock`, find
/// out which dependencies have a newer version published, and diff the
/// capability surface for each one that does.
pub fn audit_project(lockfile_path: &Path) -> Result<Vec<AuditEntry>> {
    let deps = parse_lockfile(lockfile_path)?;

    let mut unique_names: Vec<String> = deps.iter().map(|d| d.name.clone()).collect();
    unique_names.sort_unstable();
    unique_names.dedup();

    let latest_by_name = resolve_latest_versions(&unique_names);

    let mut entries = Vec::new();
    for dep in deps {
        let Some(latest) = latest_by_name.get(&dep.name) else {
            continue;
        };

        if *latest == dep.version {
            entries.push(AuditEntry {
                name: dep.name,
                locked_version: dep.version,
                latest_version: latest.clone(),
                diff: None,
            });
            continue;
        }

        let old_path = locate_or_fetch(&dep.name, &dep.version)?;
        let new_path = locate_or_fetch(&dep.name, latest)?;
        let old_report = scan_dir(&dep.name, &dep.version, &old_path)?;
        let new_report = scan_dir(&dep.name, latest, &new_path)?;
        let diff = diff_reports(&old_report, &new_report);

        entries.push(AuditEntry {
            name: dep.name,
            locked_version: dep.version,
            latest_version: latest.clone(),
            diff: Some(diff),
        });
    }

    Ok(entries)
}

/// Find `name-version` in the local cargo registry source cache, fetching it
/// into the cache first (via a scratch `cargo add && cargo fetch`) if it
/// isn't there yet.
pub fn locate_or_fetch(name: &str, version: &str) -> Result<PathBuf> {
    if let Some(p) = locate_cached(name, version)? {
        return Ok(p);
    }
    fetch_via_cargo(name, version)?;
    locate_cached(name, version)?.with_context(|| {
        format!("still couldn't find {name}-{version} in the registry cache after fetching")
    })
}

fn locate_cached(name: &str, version: &str) -> Result<Option<PathBuf>> {
    let cargo_home = home::cargo_home().context("resolving CARGO_HOME")?;
    let src_root = cargo_home.join("registry").join("src");
    if !src_root.is_dir() {
        return Ok(None);
    }
    let want = format!("{name}-{version}");
    for entry in std::fs::read_dir(&src_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let candidate = entry.path().join(&want);
        if candidate.is_dir() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn fetch_via_cargo(name: &str, version: &str) -> Result<()> {
    let tmp = tempfile::tempdir().context("creating scratch dir")?;

    let status = ProcCommand::new("cargo")
        .args(["init", "--name", "capscan_probe", "--quiet"])
        .current_dir(tmp.path())
        .status()
        .context("running `cargo init`")?;
    if !status.success() {
        bail!("`cargo init` failed while preparing a scratch project to fetch {name}-{version}");
    }

    let dep_spec = format!("{name}@={version}");
    let status = ProcCommand::new("cargo")
        .args(["add", &dep_spec, "--quiet"])
        .current_dir(tmp.path())
        .status()
        .context("running `cargo add`")?;
    if !status.success() {
        bail!("`cargo add {dep_spec}` failed -- does that name/version exist on crates.io?");
    }

    let status = ProcCommand::new("cargo")
        .args(["fetch", "--quiet"])
        .current_dir(tmp.path())
        .status()
        .context("running `cargo fetch`")?;
    if !status.success() {
        bail!("`cargo fetch` failed for {name}-{version}");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    pub old: (String, String),
    pub new: (String, String),
    pub added: Vec<Signal>,
    pub removed: Vec<Signal>,
    pub added_dependencies: Vec<String>,
    pub removed_dependencies: Vec<String>,
}

impl Diff {
    /// Worst severity among everything *newly gained* -- the number a CI
    /// gate should key off. `None` means the update looks safe by this
    /// tool's heuristics.
    pub fn worst_severity(&self) -> Option<Severity> {
        let sig_sev = self.added.iter().map(|s| s.kind.severity());
        let dep_sev = self.added_dependencies.iter().map(|_| Severity::Medium);
        sig_sev.chain(dep_sev).max()
    }
}

pub fn diff_reports(old: &CrateReport, new: &CrateReport) -> Diff {
    let old_keys: HashSet<_> = old.signals.iter().map(Signal::dedup_key).collect();
    let new_keys: HashSet<_> = new.signals.iter().map(Signal::dedup_key).collect();

    let mut added = Vec::new();
    let mut seen = HashSet::new();
    for s in &new.signals {
        let k = s.dedup_key();
        if !old_keys.contains(&k) && seen.insert(k) {
            added.push(s.clone());
        }
    }

    let mut removed = Vec::new();
    let mut seen = HashSet::new();
    for s in &old.signals {
        let k = s.dedup_key();
        if !new_keys.contains(&k) && seen.insert(k) {
            removed.push(s.clone());
        }
    }

    let old_deps: HashSet<_> = old.dependencies.iter().cloned().collect();
    let new_deps: HashSet<_> = new.dependencies.iter().cloned().collect();
    let mut added_dependencies: Vec<_> = new_deps.difference(&old_deps).cloned().collect();
    let mut removed_dependencies: Vec<_> = old_deps.difference(&new_deps).cloned().collect();
    added_dependencies.sort();
    removed_dependencies.sort();

    added.sort_by(|a, b| {
        b.kind
            .severity()
            .cmp(&a.kind.severity())
            .then_with(|| a.file.cmp(&b.file))
    });
    removed.sort_by(|a, b| a.file.cmp(&b.file));

    Diff {
        old: (old.name.clone(), old.version.clone()),
        new: (new.name.clone(), new.version.clone()),
        added,
        removed,
        added_dependencies,
        removed_dependencies,
    }
}
