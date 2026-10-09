# Telamon Archive: security

Archive replaces Ark on Telamon OS. It opens archives people download and are
sent, so every byte of every archive is hostile until proven otherwise; and it
serves a D-Bus API (`Archive1`) to every program of the user, including
sandboxed ones with a bus grant. This file is the threat model, what the code
does about it, where the tests are and what is left. `docs/DESIGN.md` ("The
sandbox", "Extraction rules", "Bomb limits", "Names") has the rules in the form
the code is held to; a change to a defence here changes this file in the same
commit.

## Assets

- The user's files: nothing an archive does may write, change, read or
  delete outside the folder the user chose, and nothing may be created that
  the user did not ask for (devices, setuid files, links out, files that run
  at the next login).
- The user's session and credentials: the archive reader must not become a
  foothold (a parser bug is the realistic attack: Fedora's libarchive has had
  memory-corruption bugs in its RAR5 and 7z readers), and a password the user
  types must not leak (argv, environment, files, logs, bus, core dumps).
- Availability of the desktop: bombs (ratio, entry count, depth, path length,
  windows, jobs) end with a question or a refusal, not a full disk or a frozen
  session.

## Who is trusted

| | Trust |
|---|---|
| The person at the keyboard | Trusted; asked before anything risky (limits, replacing files). |
| `telamon-archive-core`, `-engine`, `-service`, the GUI, the CLI | Trusted code. |
| `telamon-archive-worker` (libarchive, the codecs) | **Untrusted after it starts reading**: it is sandboxed, and everything it says and leaves in staging is audited as if a hostile archive wrote it. |
| Archive bytes, entry names, sizes, link targets, comments, modes, times | Untrusted. |
| Other programs of the user on the session bus | Untrusted beyond the interface: they may be sandboxed apps with a bus grant. |
| File names and paths from callers (`Archive1`, the CLI, `--`-less arguments) | Untrusted: validated, never passed through a shell. |

## Attacker-controlled inputs, and what stands between them and the user

| Input | Defence | Tests |
|---|---|---|
| Archive bytes (every format) | Parsed only in the worker: `PR_SET_NO_NEW_PRIVS`, not dumpable, `RLIMIT_AS/CORE/NOFILE`, Landlock (read `/usr` and the archive fds; write only below staging; no devices, FIFOs, sockets, exec; TCP, signals and abstract sockets out), then a seccomp filter (no sockets, processes, namespaces, ptrace, io_uring, BPF, perf, keyrings, mounts, IPC, **no change of mode, owner, times or extended attributes of anything by path**). The worker refuses to run without Landlock ABI 6 | `sandbox.rs` (child process that tries each call), `seccomp.rs`, worker tests |
| Entry paths (zip slip, absolute, `..`, backslash, drive letters, NUL, long, deep, Shift_JIS trail bytes, case/normalisation collisions) | `core::path::parse`: decoded before split, relative components only, every disk name safe (no `/`, controls, `.`/`..`, ≤ 255 bytes), depth 256, 4096 bytes; the writer uses `openat2(RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS)` with `O_EXCL\|O_NOFOLLOW` below the staging descriptor; the client audits staging again before moving anything | `path.rs`, `audit.rs`, engine tests with crafted archives, `fuzz/entry_path` |
| Symlinks and hard links in archives | `core::link`: relative only, never above the top, never through another link; written in the shortest normalised form, created last; hard links only to a file really written; the audit removes anything else | `link.rs`, `audit.rs` tests, `fuzz/symlink`, `fuzz/audit_staging` |
| Special files, setuid/setgid/sticky, odd modes | Devices, FIFOs, sockets are never created (Landlock) and removed by the audit; setuid, setgid, sticky stripped; mode 0 folders unlocked for cleanup; group ownership reset to staging's; launcher files lose the execute bit | `audit.rs` tests, `fuzz/audit_staging` |
| Bombs (ratio, huge declared sizes, many entries, deep nesting, nested archives) | `core::limits`: asked at 16 GiB, 200,000 entries, 256 MiB with ratio over the limit, nesting; the client watches the free space of staging every 250 ms and kills the worker; frames are capped | `limits.rs`, engine and worker tests |
| Names shown | Controls, bidi, invisible characters made visible (`name::display`); every `TelamonLabel` sets `Text.PlainText`; names from the worker are re-checked by the client | `name.rs`, `fuzz/names` |
| The worker's replies | Treated as untrusted: capped frames and counts, unknown tags refused, no allocation before validation, progress that goes backwards is an error, every path re-checked | `proto.rs`, `fuzz/proto` |
| Passwords | Never argv, environment, file, log line or D-Bus argument; `Zeroizing` buffers, redacting `Debug`, pipes; the CLI sets `RLIMIT_CORE 0` and is not dumpable; the GUI process (since this phase) sets `RLIMIT_CORE 0` | `dbus.rs` (`a_password_is_never_a_bus_argument`, core limit), CLI tests |
| D-Bus callers of `Archive1` | URIs: `file://`, absolute, no `..`/`.`, no NUL, ≤ 8 KiB, regular files for archives, writable folders; counts capped (64 archives, 10,000 items, 100,000 entries); 2 running + 16 waiting jobs; **only the program that started a job may pause, resume, cancel or answer it** (`AccessDenied` for others); activation token and window handle cleaned like the options; at most 8 finished-job windows stay open | `validate.rs`, `uri.rs`, `dbus.rs` (`only_the_program_that_started_…`) |
| `/MainApplication` (KDBusService exports the Qt application object) | Not exported: `quit()`, `closeAllWindows()` and the properties are not reachable from the bus | `dbus.rs` (`the_application_object_is_not_on_the_bus`) |
| The dialogs (`ExtractAll`, `CompressDialog`) | The answer must be an absolute folder; an archive replaced while the dialog waited (up to 10 minutes) is refused | `validate.rs`, `service.rs` tests |
| CLI arguments | `--` handling, names and paths made safe before printing (escape sequences cannot reach the terminal), password only from a tty with echo off or an inherited fd | CLI tests |
| Launchers | `.desktop` and service-menu `Exec=` put `--` before `%F`/`%U`; the legacy `Open` accepts local `file:` URLs and absolute paths only (no working-folder relative names; KDBusService's own `Open` is the framework's) | spec `%check` checks the D-Bus `Exec=` lines |

## Trust boundaries

1. **Archive bytes ↔ worker.** The only parser boundary. A compromised worker
   can write anything inside staging and say anything on its pipe; it cannot
   read the user's files (Landlock), reach the network, start a process, or
   (since this phase) change the metadata of a file it did not create.
2. **Worker ↔ client.** The client kills the worker before it audits staging,
   and moves files out only by descriptor and `renameat2(RENAME_NOREPLACE)`.
3. **Client ↔ the session bus.** Callers are known only by their bus name.
4. **GUI process ↔ the user.** Holds typed passwords for a short time; no
   core file.

## What Archive does not defend against

- A malicious process of the user that is not sandboxed: it can run `7z`
  itself. The bus limits what a sandboxed or confused caller gets.
- A kernel without Landlock ABI 6: the worker refuses to run.
- Bugs in the kernel's Landlock/seccomp implementation.
- `7z`/`unrar` drivers: they will get their own sandbox profile when they land
  (a PID namespace and a different seccomp filter); not part of this phase.

## Build hardening

- RPM builds use Fedora's flags (stack protector strong, `_FORTIFY_SOURCE=3`,
  stack-clash protection, `-fcf-protection`, PIE, `-z relro -z now` for the C++
  program; PIE and full RELRO for the Rust ones). `%check` runs
  `packaging/check-hardening.sh` on the GUI, CLI and worker, and refuses a
  worker built with the test-only `unsandboxed` feature.
- Rust release profile: `overflow-checks = true`; `panic` stays `unwind`
  (the service contains a panicking job; the worker ends and the job fails).
- `cargo-deny` (`deny.toml`) and the fuzz targets run in
  `.github/workflows/security.yml`, on changes and weekly.

## Testing

- `cargo test --workspace --locked` plus the CLI's `dev-worker` tests: crafted
  archives for each attack through the real worker.
- The D-Bus tests (`apps/telamon-archive/tests/dbus.rs`) run the real app on a
  private session bus (CMake with `-DTELAMON_ARCHIVE_FEATURES=dev-worker`).
- `fuzz/` (cargo-fuzz, `--sanitizer none`, `RUSTC_BOOTSTRAP=1`): `entry_path`,
  `names`, `proto`, `symlink`, `service_text`, `audit_staging`.

## Findings of the Secure phase

See the pull request for the table (severity, fix, test). In short:

| | Severity | Finding | Fix |
|---|---|---|---|
| A1 | medium | Landlock does not rule chmod/chown/utimes/removexattr by path; a compromised worker could change the mode or group of any file of the user's (home folder, `~/.ssh`), or lock the destination | seccomp denies them by path (and `utimensat` with a path); test child tries each |
| A2 | medium | any bus peer could answer another caller's "replace"/"unpack anyway" question and pause or cancel its jobs | owner check on every job method |
| A3 | medium | a caller in a loop could open unlimited finished-job windows | the oldest of more than 8 is closed |
| A4 | low | seccomp deny list lacked the newest siblings of denied calls, `lsm_*`, `fanotify` | added; the test child tries a selection by number |
| A5 | low | the audit kept the group a compromised worker gave to staged files | reset to staging's group |
| A6 | low | `ExtractAll` dialog forgot the archive's identity and took relative folders | identity kept; absolute folders only |
| A7 | low | `/MainApplication` exposed `quit()` to the bus | not exported |
| A8 | low | `Open()` passed an unvalidated activation token/window handle; legacy `Open` read bare names against the working folder | cleaned; strict URLs |
| A9 | low | the GUI could write a core file with a typed password in it | `RLIMIT_CORE 0` (not made undumpable: the desktop portals read `/proc/<pid>/root`; a native crash of the window is therefore not collected by the framework's crash reporter) |
| A10 | low | CLI echoed an unknown command with terminal escapes | made safe |

## What is left

- The worker keeps the descriptors the client gives it; `fchmod`/`futimens` on a read-only descriptor of the archive (or, in a Create job, of the source folder's files) remain possible.
- The worker's seccomp filter is still a deny list (an allow list derived with
  `strace` is the stronger form); `clone` with `CLONE_THREAD` is allowed (no
  thread cap).
- The audit accepts any lexically valid relative symlink a compromised worker
  wrote (it does not insist on the canonical form the honest writer uses); on
  case-folding destinations this could resolve one level higher.
- Drag-out with Keep Both/Skip can leave a link pointing at an item that kept
  its name.
- Declared totals are checked as data is written, not before (`check_declared`
  has no caller); bounded by the space watch.
- Paused jobs and unanswered questions have no timeout.
- Callers are identified by bus name only; no Flatpak/portal awareness.
- Framework components `TelamonNavigationStack`, `TelamonViewSwitcher`,
  `TelamonHeaderBar` do not set `textFormat`; Archive does not feed them
  archive text.
