# Cross-platform caveats

The kit's **harnesses** are Python + POSIX `sh` on purpose, so `make check-kit`
runs anywhere. But two things around them are NOT host-agnostic: the **safety
tooling** (Miri, the sanitizers) assumes a Linux nightly toolchain, and the
**ported binary's runtime** inherits the target OS's quirks. This is the field
guide — distilled from winlsof, a *Windows* port — so a non-Linux port isn't
surprised. The kit's default guidance (PLAYBOOK Phase 3/4, the CI template) is
written for Linux; the deltas below are where you adjust.

## Sanitizers & Miri — availability by toolchain

The `sanitizers` gate (`harnesses/sanitizers/run_sanitizers.sh`) and the CI
template's sanitizer/miri jobs assume `x86_64-unknown-linux-gnu` + nightly, where
Miri/ASan/UBSan/TSan all work. Elsewhere:

- **Miri** interprets MIR, so it is host-agnostic for **pure logic** (`core`) — but
  it **cannot execute FFI / raw syscalls**, so it does not cover the `sys` layer
  (the OS seam) on any platform. Needs `+nightly` and `-Zbuild-std` (component
  `rust-src`). Use it for `core` regardless of OS.
- **ASan/UBSan** ship for the LLVM targets. On **`windows-msvc`** ASan is usable
  (MSVC/clang ASan); **UBSan/TSan are limited or absent**. On **`windows-gnu`**
  sanitizer support is weaker still. Don't expect the Linux sanitizer matrix to
  run on a Windows runner.
- **TSan** is **Linux/macOS only** (not Windows). Threaded `sys` code you'd
  normally TSan must be covered another way — winlsof's worker-thread hang was
  caught by *design review + the spike-and-gate ritual* (LESSONS #1), not TSan.

**What to do on Windows/macOS:** run the sanitizer gate in a **Linux CI job** (or
WSL) against the platform-independent logic, and cover the OS-specific `sys` code
with the **differential + fuzzing** gates (which don't need a sanitizer runtime)
plus Miri on any pure-logic helpers. Keep a small native-Windows job for
`build + test + clippy + unsafe-audit` so the real target still builds and the
hard gate still runs.

## "Exit hard after output" — the liveness pattern

A worker thread or async task that outlives `main`'s useful work can wedge process
**teardown**: winlsof's blocking `NtQueryObject` worker never returned and hung the
whole process at exit (LESSONS #1). A hang is not UB, so Miri and the sanitizers
never see it — only the differential harness's per-case **timeout** backstops it.

Pattern: once the program has produced its output, **exit hard**
(`std::process::exit(code)`) instead of waiting to join every worker — an
abandoned or blocked worker must never hold the process open. Better still, design
the blocking call *out* (winlsof's fix was to avoid the blocking query, not wrap
it); where you can't, cap it with a timeout and exit past it. This is a runtime
property of the *ported binary*, independent of OS, but it bites hardest on
platforms with blocking, cancellation-hostile syscalls (Windows object queries,
some `ioctl`s).

## ASCII-default output for legacy shells

Windows consoles — **PowerShell 5.1**, `cmd` — default to a legacy code page
(Windows-1252 / OEM), not UTF-8. Emitting UTF-8 or box-drawing/Unicode **by
default** produces mojibake and can corrupt downstream parsing (winlsof burned six
commits on PowerShell-5.1 / Windows-1252 breakage *in the test harness itself*).

Pattern: default the tool's output to **ASCII** — the lowest common denominator of
the target's default shell — and make UTF-8/Unicode **opt-in** (a flag or env var).
The kit's own harnesses are ASCII-safe for exactly this reason; keep the ported
binary the same.

## `target/` file locks on synced / scanned folders

Cloud-sync clients (OneDrive, Dropbox, Google Drive) and real-time AV/EDR lock
files while they index or upload them. A build churns thousands of files under
`target/`; a sync client holding a lock on one produces intermittent "Access is
denied" / "file in use" failures that masquerade as compiler bugs.

Keep the workspace (and `target/`) **out of a synced folder** — use a local path,
or exclude `target/` from sync **and** from AV scanning. On Windows, excluding
`target/` from Defender real-time scanning also removes a large, silent build-time
tax. (`LESSONS`: "pin + vendor deps so a clean-machine build never becomes a
re-debug session" — the same spirit: make the build environment boring.)

## Fork-based harnesses on Windows

`harnesses/library-differential/lib_diff.py` isolates each C-ABI call in a
**forked child** so a segfault/abort is a finding, not a harness death — a
Linux/macOS mechanism. Windows has no `fork()`; a `.dll` differential there needs a
**spawn-based** worker (a fresh process that `LoadLibrary`s the DLL and reports
back over a pipe) or running the harness under WSL. This is a documented to-do in
`lib_diff.py`'s own docstring.

---

*Referenced from `README.md` and `PLAYBOOK.md` Phase 3. When a port on a new
platform teaches another delta, add it here and log the lesson in `LESSONS.md` —
this doc compounds like the rest of the kit.*
