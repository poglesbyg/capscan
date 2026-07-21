use std::path::PathBuf;

use anyhow::Result;
use capscan::{
    audit_project, diff_lockfiles, diff_reports, filter_by_min_severity, locate_or_fetch, scan_dir,
    AuditEntry, CrateReport, Diff, LockfileDiffResult, Severity,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cargo-capscan",
    bin_name = "cargo capscan",
    version,
    about = "Diff a crate's capability surface (unsafe, FFI, process/network/fs access, build scripts) between two versions before you update it."
)]
struct Cli {
    #[command(subcommand)]
    command: CmdKind,
}

#[derive(Subcommand)]
enum CmdKind {
    /// Scan a single crate version and print its capability signals.
    Scan {
        name: String,
        version: String,
        #[arg(long)]
        json: bool,
    },
    /// Diff two versions of the same crate; exit non-zero if new high/medium
    /// severity capabilities were gained (handy as a CI gate on `cargo update`).
    Diff {
        name: String,
        old_version: String,
        new_version: String,
        #[arg(long)]
        json: bool,
    },
    /// Scan every crates.io dependency in a Cargo.lock and flag which ones
    /// would gain new capabilities if updated to their latest published
    /// version. Exit code mirrors `diff`: worst severity found across all
    /// dependencies (computed from every dependency regardless of
    /// --min-severity, which only affects what's displayed/returned).
    Audit {
        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,
        #[arg(long)]
        json: bool,
        /// Only show/return dependencies whose worst new capability is at
        /// least this severity ("low", "medium", or "high"). Omit to see
        /// every dependency, including ones already at latest.
        #[arg(long)]
        min_severity: Option<Severity>,
    },
    /// Compare two Cargo.lock files -- typically a PR's base branch against
    /// its head -- and diff the capability surface of every crate whose
    /// version changed between them. This answers "what did *this PR*
    /// change" rather than `audit`'s "what's out of date relative to
    /// crates.io in general". Exit code mirrors `diff`/`audit`: worst
    /// severity found across every changed crate, regardless of
    /// --min-severity (which only affects what's displayed/returned).
    DiffLockfiles {
        old_lockfile: PathBuf,
        new_lockfile: PathBuf,
        #[arg(long)]
        json: bool,
        /// Render as GitHub-flavored markdown, suitable for posting
        /// directly as a PR comment (see the `pr-comment` GitHub Action).
        #[arg(long)]
        markdown: bool,
        #[arg(long)]
        min_severity: Option<Severity>,
    },
}

fn main() -> Result<()> {
    // `cargo capscan <args>` invokes us as `cargo-capscan capscan <args>` --
    // cargo re-injects the subcommand name as argv[1]. Drop it so clap sees
    // a normal argv regardless of whether we were run directly or via cargo.
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "capscan" {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);

    match cli.command {
        CmdKind::Scan {
            name,
            version,
            json,
        } => {
            let path = locate_or_fetch(&name, &version)?;
            let report = scan_dir(&name, &version, &path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }
            Ok(())
        }
        CmdKind::Diff {
            name,
            old_version,
            new_version,
            json,
        } => {
            let old_path = locate_or_fetch(&name, &old_version)?;
            let new_path = locate_or_fetch(&name, &new_version)?;
            let old_report = scan_dir(&name, &old_version, &old_path)?;
            let new_report = scan_dir(&name, &new_version, &new_path)?;
            let diff = diff_reports(&old_report, &new_report);

            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                print_diff(&diff);
            }

            let code = match diff.worst_severity() {
                Some(Severity::High) => 2,
                Some(Severity::Medium) => 1,
                Some(Severity::Low) | None => 0,
            };
            std::process::exit(code);
        }
        CmdKind::Audit {
            lockfile,
            json,
            min_severity,
        } => {
            let entries = audit_project(&lockfile)?;

            if json {
                let output_entries = match min_severity {
                    Some(threshold) => filter_by_min_severity(entries.clone(), threshold),
                    None => entries.clone(),
                };
                println!("{}", serde_json::to_string_pretty(&output_entries)?);
            } else {
                print_audit(&entries, min_severity);
            }

            let worst = entries.iter().filter_map(AuditEntry::worst_severity).max();
            let code = match worst {
                Some(Severity::High) => 2,
                Some(Severity::Medium) => 1,
                Some(Severity::Low) | None => 0,
            };
            std::process::exit(code);
        }
        CmdKind::DiffLockfiles {
            old_lockfile,
            new_lockfile,
            json,
            markdown,
            min_severity,
        } => {
            let results = diff_lockfiles(&old_lockfile, &new_lockfile)?;

            if json {
                let output_results = match min_severity {
                    Some(threshold) => results
                        .iter()
                        .filter(|r| r.worst_severity().is_some_and(|sev| sev >= threshold))
                        .cloned()
                        .collect::<Vec<_>>(),
                    None => results.clone(),
                };
                println!("{}", serde_json::to_string_pretty(&output_results)?);
            } else if markdown {
                println!("{}", render_markdown(&results, min_severity));
            } else {
                print_lockfile_diff(&results, min_severity);
            }

            let worst = results
                .iter()
                .filter_map(LockfileDiffResult::worst_severity)
                .max();
            let code = match worst {
                Some(Severity::High) => 2,
                Some(Severity::Medium) => 1,
                Some(Severity::Low) | None => 0,
            };
            std::process::exit(code);
        }
    }
}

fn print_report(r: &CrateReport) {
    println!(
        "{} {}  ({} files scanned, {} lines)",
        r.name, r.version, r.files_scanned, r.lines_scanned
    );
    println!("dependencies: {}", r.dependencies.join(", "));
    if r.signals.is_empty() {
        println!("no capability signals found.");
        return;
    }
    for s in &r.signals {
        println!(
            "  [{}] {}:{}  {} -- {}",
            s.kind.severity(),
            s.file,
            s.line,
            s.kind,
            s.detail
        );
    }
}

fn print_diff(d: &Diff) {
    println!("{} {}  ->  {} {}", d.old.0, d.old.1, d.new.0, d.new.1);

    if d.added.is_empty() && d.added_dependencies.is_empty() {
        println!("no new capability signals.");
    } else {
        if !d.added.is_empty() {
            println!("+ {} new signal(s):", d.added.len());
            for s in &d.added {
                println!(
                    "    [{}] {}:{}  {} -- {}",
                    s.kind.severity(),
                    s.file,
                    s.line,
                    s.kind,
                    s.detail
                );
            }
        }
        if !d.added_dependencies.is_empty() {
            println!("+ new dependencies: {}", d.added_dependencies.join(", "));
        }
    }

    if !d.removed.is_empty() {
        println!("- {} signal(s) no longer present:", d.removed.len());
        for s in &d.removed {
            println!(
                "    [{}] {}:{}  {} -- {}",
                s.kind.severity(),
                s.file,
                s.line,
                s.kind,
                s.detail
            );
        }
    }
    if !d.removed_dependencies.is_empty() {
        println!(
            "- removed dependencies: {}",
            d.removed_dependencies.join(", ")
        );
    }

    match d.worst_severity() {
        Some(sev) => println!("\nworst new severity: {sev}"),
        None => println!("\nno new risk detected"),
    }
}

fn print_audit(entries: &[AuditEntry], min_severity: Option<Severity>) {
    let total = entries.len();
    let up_to_date = entries.iter().filter(|e| e.diff.is_none()).count();
    let updated: Vec<&AuditEntry> = entries.iter().filter(|e| e.diff.is_some()).collect();

    let mut shown: Vec<&AuditEntry> = updated
        .iter()
        .copied()
        .filter(|e| match min_severity {
            Some(threshold) => e.worst_severity().is_some_and(|sev| sev >= threshold),
            None => true,
        })
        .collect();
    shown.sort_by(|a, b| {
        b.worst_severity()
            .cmp(&a.worst_severity())
            .then_with(|| a.name.cmp(&b.name))
    });

    println!("audited {total} registry dependencies ({up_to_date} already at latest)");

    if updated.is_empty() {
        println!("no pending updates.");
        return;
    }

    if shown.is_empty() {
        let threshold = min_severity.expect("shown can only differ from updated when filtering");
        println!(
            "{} update(s) available, but none at or above '{threshold}' severity.",
            updated.len()
        );
        return;
    }

    println!("{} have updates available:", shown.len());
    for e in &shown {
        let diff = e.diff.as_ref().expect("filtered to Some above");
        let sev = e
            .worst_severity()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".to_string());
        let extra_deps = if diff.added_dependencies.is_empty() {
            String::new()
        } else {
            format!(", +{} new dep(s)", diff.added_dependencies.len())
        };
        println!(
            "  [{sev:6}] {:<24} {} -> {}  (+{} signal(s), -{} signal(s){extra_deps})",
            e.name,
            e.locked_version,
            e.latest_version,
            diff.added.len(),
            diff.removed.len(),
        );
    }

    println!("\nrun `cargo capscan diff <name> <old> <new>` for details on any of the above.");
}

fn version_change_label(r: &LockfileDiffResult) -> Option<String> {
    match (&r.old_version, &r.new_version) {
        (Some(old), Some(new)) => Some(format!("{old} -> {new}")),
        (None, Some(new)) => Some(format!("added at {new}")),
        (Some(old), None) => Some(format!("removed (was {old})")),
        (None, None) => None,
    }
}

fn print_lockfile_diff(results: &[LockfileDiffResult], min_severity: Option<Severity>) {
    if results.is_empty() {
        println!("no dependency version changes between the two lockfiles.");
        return;
    }

    let mut shown: Vec<&LockfileDiffResult> = results
        .iter()
        .filter(|r| match min_severity {
            Some(threshold) => r.worst_severity().is_some_and(|sev| sev >= threshold),
            None => true,
        })
        .collect();
    shown.sort_by(|a, b| {
        b.worst_severity()
            .cmp(&a.worst_severity())
            .then_with(|| a.name.cmp(&b.name))
    });

    if shown.is_empty() {
        let threshold = min_severity.expect("shown can only differ from results when filtering");
        println!(
            "{} crate(s) changed, but none at or above '{threshold}' severity.",
            results.len()
        );
        return;
    }

    println!("{} crate(s) changed:", shown.len());
    for r in &shown {
        let Some(version_change) = version_change_label(r) else {
            continue;
        };

        if let Some(err) = &r.error {
            println!("  [error]  {:<24} {version_change}  -- {err}", r.name);
            continue;
        }

        match &r.diff {
            Some(diff) => {
                let sev = r
                    .worst_severity()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let extra_deps = if diff.added_dependencies.is_empty() {
                    String::new()
                } else {
                    format!(", +{} new dep(s)", diff.added_dependencies.len())
                };
                println!(
                    "  [{sev:6}] {:<24} {version_change}  (+{} signal(s), -{} signal(s){extra_deps})",
                    r.name,
                    diff.added.len(),
                    diff.removed.len(),
                );
            }
            None => println!("  [none  ] {:<24} {version_change}", r.name),
        }
    }

    println!("\nrun `cargo capscan diff <name> <old> <new>` for full detail on any of the above.");
}

fn severity_emoji(severity: Option<Severity>) -> &'static str {
    match severity {
        Some(Severity::High) => "🔴 high",
        Some(Severity::Medium) => "🟡 medium",
        Some(Severity::Low) => "🟢 low",
        None => "-",
    }
}

/// Escapes a value that might contain a literal `|` or newline (currently
/// only error messages can -- crate names and versions can't) so it can't
/// break a markdown table's structure.
fn markdown_table_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn render_markdown(results: &[LockfileDiffResult], min_severity: Option<Severity>) -> String {
    let mut out = String::from("## 📦 capscan: dependency capability changes\n\n");

    if results.is_empty() {
        out.push_str("No dependency version changes detected between these two lockfiles.\n");
        return out;
    }

    let mut sorted: Vec<&LockfileDiffResult> = results
        .iter()
        .filter(|r| match min_severity {
            Some(threshold) => r.worst_severity().is_some_and(|sev| sev >= threshold),
            None => true,
        })
        .collect();
    sorted.sort_by(|a, b| {
        b.worst_severity()
            .cmp(&a.worst_severity())
            .then_with(|| a.name.cmp(&b.name))
    });

    if sorted.is_empty() {
        let threshold = min_severity.expect("sorted can only differ from results when filtering");
        out.push_str(&format!(
            "{} crate(s) changed, but none at or above '{threshold}' severity.\n",
            results.len()
        ));
        return out;
    }

    out.push_str("| Crate | Change | Worst severity | Signals | New deps |\n");
    out.push_str("|---|---|---|---|---|\n");

    for r in &sorted {
        let Some(change) = version_change_label(r) else {
            continue;
        };

        if let Some(err) = &r.error {
            out.push_str(&format!(
                "| `{}` | {change} | ⚠️ error | {} | |\n",
                r.name,
                markdown_table_cell(err)
            ));
            continue;
        }

        match &r.diff {
            Some(diff) => {
                let new_deps = if diff.added_dependencies.is_empty() {
                    "-".to_string()
                } else {
                    format!("+{}", diff.added_dependencies.len())
                };
                out.push_str(&format!(
                    "| `{}` | {change} | {} | +{} / -{} | {new_deps} |\n",
                    r.name,
                    severity_emoji(r.worst_severity()),
                    diff.added.len(),
                    diff.removed.len(),
                ));
            }
            None => out.push_str(&format!("| `{}` | {change} | - | - | - |\n", r.name)),
        }
    }

    // Collapsible per-crate detail for anything with an actual signal to show.
    for r in &sorted {
        let Some(diff) = &r.diff else { continue };
        if diff.added.is_empty()
            && diff.removed.is_empty()
            && diff.added_dependencies.is_empty()
            && diff.removed_dependencies.is_empty()
        {
            continue;
        }
        let Some(change) = version_change_label(r) else {
            continue;
        };

        out.push_str(&format!(
            "\n<details>\n<summary><code>{}</code> {change}</summary>\n\n",
            r.name
        ));

        if !diff.added.is_empty() {
            out.push_str("**Added:**\n");
            for s in &diff.added {
                out.push_str(&format!(
                    "- `[{}]` {}:{} {} -- {}\n",
                    s.kind.severity(),
                    s.file,
                    s.line,
                    s.kind,
                    s.detail
                ));
            }
        }
        if !diff.removed.is_empty() {
            out.push_str("\n**Removed:**\n");
            for s in &diff.removed {
                out.push_str(&format!(
                    "- `[{}]` {}:{} {} -- {}\n",
                    s.kind.severity(),
                    s.file,
                    s.line,
                    s.kind,
                    s.detail
                ));
            }
        }
        if !diff.added_dependencies.is_empty() {
            out.push_str(&format!(
                "\n**New dependencies:** {}\n",
                diff.added_dependencies.join(", ")
            ));
        }
        if !diff.removed_dependencies.is_empty() {
            out.push_str(&format!(
                "\n**Removed dependencies:** {}\n",
                diff.removed_dependencies.join(", ")
            ));
        }

        out.push_str("\n</details>\n");
    }

    out.push_str(
        "\n---\n*Generated by [capscan](https://github.com/poglesbyg/capscan). \
         Signal classification is heuristic AST matching, not real type resolution.*\n",
    );
    out
}
