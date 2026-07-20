# capscan

`cargo update` can silently hand a dependency new abilities: a `build.rs` that
didn't exist before, a new `unsafe fn`, a `Command::new` call, a socket. None
of that shows up in a normal diff review because nobody reviews vendored
dependency source on every update. capscan does a structural pass over a
crate's source with [`syn`](https://docs.rs/syn) and tells you what changed,
capability-wise, between two versions.

It is not a replacement for [`cargo-audit`](https://github.com/rustsec/rustsec)
(known-vulnerability scanning) or [`cackle`](https://github.com/davidlattimore/cackle)
(configured, enforced capability policy for CI). It's the zero-config check
you run before an update: no policy file, no crate list to maintain — just
"what capabilities did this gain."

## Install

```
cargo install capscan
```

or, from a checkout of this repo:

```
cargo install --path .
```

Either way this installs `cargo-capscan` so `cargo capscan ...` works as a
normal cargo subcommand. It also runs fine unbuilt-installed, straight from
the repo:

```
cargo run --release --bin cargo-capscan -- scan anyhow 1.0.104
```

## Usage

Scan a single version:

```
$ cargo capscan scan anyhow 1.0.104
anyhow 1.0.104  (36 files scanned, 5854 lines)
dependencies:
  [high] build.rs:117  process spawn -- Command::new
  [medium] build.rs:156  filesystem write -- fs::remove_dir_all
  [medium] src/error.rs:163  unsafe block -- unsafe { .. }
  [high] src/error.rs:736  unsafe fn -- object_drop
  ...
```

Diff two versions — the workflow this is built for:

```
$ cargo capscan diff anyhow 1.0.70 1.0.104
anyhow 1.0.70  ->  anyhow 1.0.104
+ 3 new signal(s):
    [high] src/error.rs:777  unsafe fn -- object_reallocate_boxed
    [medium] build.rs:156  filesystem write -- fs::remove_dir_all
    [low] src/nightly.rs:39  build-time macro -- option_env
- 6 signal(s) no longer present:
    [medium] build.rs:85  filesystem write -- fs::write
    [high] src/backtrace.rs:332  unsafe impl -- LazilyResolvedCapture
    ...
- removed dependencies: backtrace

worst new severity: high
$ echo $?
2
```

Exit code is `2` if the update adds a `high` severity signal, `1` for
`medium`, `0` otherwise — wire it into CI right before you'd otherwise run
`cargo update && cargo build`:

```
cargo capscan diff "$CRATE" "$OLD_VERSION" "$NEW_VERSION" || fail_the_build
```

Audit an entire project at once — reads `Cargo.lock`, checks every crates.io
dependency against its latest published version, and diffs the ones that are
behind:

```
$ cargo capscan audit
audited 54 registry dependencies (47 already at latest)
7 have updates available:
  [medium] serde_spanned            0.6.9 -> 1.1.1  (+0 signal(s), -0 signal(s), +1 new dep(s))
  [medium] toml                     0.8.23 -> 1.1.3+spec-1.1.0  (+0 signal(s), -0 signal(s), +7 new dep(s))
  [medium] toml_edit                0.22.27 -> 0.25.13+spec-1.1.0  (+0 signal(s), -2 signal(s), +5 new dep(s))
  [none  ] syn                      2.0.119 -> 3.0.2  (+0 signal(s), -0 signal(s))
  ...

run `cargo capscan diff <name> <old> <new>` for details on any of the above.
```

(That's real output from running capscan on its own `Cargo.lock` — the
`toml` 0.8 → 1.1 line is genuine: that major bump quietly pulls in 7 new
transitive dependencies.) Point it at another lockfile with `--lockfile
path/to/Cargo.lock`. Exit code is the worst severity found across every
dependency, same scale as `diff` -- computed from *every* dependency
regardless of `--min-severity` below, so filtering what's displayed never
silently changes what a CI gate would catch.

Add `--min-severity low`/`medium`/`high` to only show dependencies whose
worst new capability is at least that severity, skipping the ones already
at latest (or below the threshold) instead of scrolling past them:

```
$ cargo capscan audit --min-severity medium
audited 54 registry dependencies (47 already at latest)
4 have updates available:
  [medium] serde_spanned            0.6.9 -> 1.1.1  (+0 signal(s), -0 signal(s), +1 new dep(s))
  [medium] toml                     0.8.23 -> 1.1.3+spec-1.1.0  (+0 signal(s), -0 signal(s), +7 new dep(s))
  ...
```

The header always reflects the true total either way; only the listed
entries (and, with `--json`, the returned array) are filtered.

Add `--json` to any subcommand for machine-readable output.

If the requested version isn't already in your local cargo registry cache,
capscan fetches it: it spins up a scratch project, runs
`cargo add name@=version && cargo fetch` in it, and reads the result out of
`~/.cargo/registry/src/`. No custom download/untar code — it reuses cargo's
own already-trusted path to the registry.

## What it detects

| Signal | Severity | Notes |
|---|---|---|
| `unsafe fn` / `unsafe impl` | high | |
| FFI (`extern "C" { .. }`) | high | |
| exported symbol (`#[no_mangle]` / `#[export_name]`) | high | pins a symbol name so it's callable from outside the crate |
| `mem::transmute` / `transmute_copy` | high | reinterprets bytes across types; a common UB source even among "safe" unsafe usage |
| process spawn (`Command::new`, incl. `tokio::process::Command`) | high | |
| `build.rs` present | high | runs arbitrary code with full FS/network access on every build |
| proc-macro crate (`lib.proc-macro = true`) | high | runs arbitrary code at compile time |
| native linkage (`package.links`) | high | |
| `unsafe { .. }` block | medium | |
| network access (`TcpStream`/`TcpListener`/`UdpSocket`/`UnixStream`, or a `reqwest::`/`hyper::`/`ureq::` call) | medium | |
| filesystem write (`fs::write`, `remove_dir_all`, ...) | medium | |
| `env::set_var` / `env::remove_var` | medium | |
| `env::var` / `env::var_os` | low | read-only |
| `env!` / `include!` / `include_str!` / `include_bytes!` | low | build-time macros |

New dependencies pulled in by the update are also reported and count as
`medium` severity toward the diff's worst-severity exit code.

Diffing keys signals on `(kind, detail)`, not file/line — a function moving
50 lines down the file isn't a "new" signal, so updates with heavy internal
refactors don't drown you in noise.

## Use as a GitHub Action

`action.yml` at the root of this repo wraps `cargo capscan audit` as a
composite action, so any repo can gate CI on it without installing anything
by hand:

```yaml
name: Dependency capability audit
on:
  pull_request:
    paths: ['**/Cargo.lock']
  schedule:
    - cron: '0 6 * * 1'  # catch updates published on their own, not just yours

jobs:
  capscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: poglesbyg/capscan@v0.1.0
        with:
          fail-on: medium   # 'high' | 'medium' | 'none' (report only)
          # lockfile: path/to/Cargo.lock
          # version: pin a specific capscan release; empty = latest
```

The action installs capscan via `cargo install`, runs `cargo capscan audit`,
and fails the job if the worst severity found is at or above `fail-on`
(default `medium`) — same severity scale as everywhere else in this README.
It exposes the raw exit code as the `audit-exit-code` output if you want
custom logic instead. This repo dogfoods it in its own
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) via `uses: ./`.

## Limitations

Path classification is textual AST matching, not real name resolution — that
would require compiling the crate. Consequences:

- A call through a re-exported alias (`use std::fs::write as w; w(...)`)
  won't be recognized.
- A user-defined type also named `Command` with a `::new()` method would
  false-positive as a process spawn.
- Anything generated by a proc-macro *before* your crate expands it is
  invisible — capscan reads the macro's own source, not what it expands to
  at your call sites.

Treat this as a fast heuristic triage step, not a proof of safety. It tells
you where to look, not that everything else is fine.

## Tests

```
cargo test              # pure in-memory fixtures, no network
cargo test -- --ignored # also exercises the real crates.io fetch path
```
