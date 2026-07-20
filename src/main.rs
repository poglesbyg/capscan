use anyhow::Result;
use capscan::{diff_reports, locate_or_fetch, scan_dir, CrateReport, Diff, Severity};
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
        CmdKind::Scan { name, version, json } => {
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
        println!("  [{}] {}:{}  {} -- {}", s.kind.severity(), s.file, s.line, s.kind, s.detail);
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
                println!("    [{}] {}:{}  {} -- {}", s.kind.severity(), s.file, s.line, s.kind, s.detail);
            }
        }
        if !d.added_dependencies.is_empty() {
            println!("+ new dependencies: {}", d.added_dependencies.join(", "));
        }
    }

    if !d.removed.is_empty() {
        println!("- {} signal(s) no longer present:", d.removed.len());
        for s in &d.removed {
            println!("    [{}] {}:{}  {} -- {}", s.kind.severity(), s.file, s.line, s.kind, s.detail);
        }
    }
    if !d.removed_dependencies.is_empty() {
        println!("- removed dependencies: {}", d.removed_dependencies.join(", "));
    }

    match d.worst_severity() {
        Some(sev) => println!("\nworst new severity: {sev}"),
        None => println!("\nno new risk detected"),
    }
}
