# Telamon Archive (Telamon OS)

Rust + Qt 6.11 + Kirigami (CXX-Qt) archive manager for Telamon OS, a Fedora
Kinoite 44 bootc image (repo `~/Documents/Projects/AtlasOS/AtlasOS`). It
replaces KDE Ark: browse archives as folders, extract, create, edit, test, with
a CLI and a D-Bus API that Explorer calls for its right-click actions.
Read `docs/DESIGN.md` first: it fixes the backends, the sandbox, the
extraction rules, the API, the threading rule and the budgets. Change it only
together with the code that implements the change. The plan and roadmap are
the Atlas Notes notes "AtlasOS/Archive/Plan" and "AtlasOS/Archive/Roadmap".

The stack, build and look are Atlas Store's
(`~/Documents/Projects/AtlasOS/AtlasOS Store`) and Atlas Monitor's. When in
doubt, do what they do.

## Hard rules

- **Security is the core of this app.** Every archive byte, entry path, name,
  size and link target is untrusted. The rules in DESIGN.md ("The sandbox",
  "Extraction rules", "Bomb limits", "Names") are not optional and not
  weakened for speed. The security-reviewer passes a feature before it ships.
- **Archive bytes are parsed only in `telamon-archive-worker`**, after it has
  applied no_new_privs and Landlock. Nothing in `telamon-archive-core`, the GUI
  or the CLI links libarchive or the zip crate. Replies from the worker are
  untrusted input to the client.
- **Extraction writes only through `openat2` below the staging folder's
  descriptor** (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`),
  files with `O_EXCL | O_NOFOLLOW`. Never a path string joined onto the
  destination, never `std::fs` on archive-derived paths.
- **Passwords:** never in argv, the environment, a file, a log line or a
  D-Bus argument. `Zeroizing` buffers, a redacting `Debug`, pipes and stdin or
  a pty only.
- **Build and test inside the `fedora:44` dev container**, never on the host:
  `scripts/dev.sh <command>`. The repo is at `/src`; all build output goes to
  `/work` (`~/.cache/claude-builds/telamon-archive` on the host), never into the
  repo or `/tmp`. Use a separate target dir per agent or task
  (`CARGO_TARGET_DIR=/work/target/<name> scripts/dev.sh ...`). Compiles go
  through `~/.claude/heavy/run.sh` (`-j 8` or less); full suites, the dev
  image, RPMs, UI runs and fuzzing campaigns go to the "AtlasOS" coordinator.
- **Test data only.** Test archives are generated under `/work` or committed
  as small fixtures in `crates/*/tests/fixtures`; never Zach's files. Runs
  set `XDG_*_HOME` under `/work`.
- **Never run the GUI on the user's display.** Smoke runs use
  `QT_QPA_PLATFORM=offscreen`, or `xvfb-run -a -s "-screen 0 1920x1080x24"`,
  inside `dbus-run-session`.
- **Every `Text` or `Label` that shows archive text sets
  `textFormat: Text.PlainText`.**
- **The GUI thread never blocks.** Workers are driven from job threads;
  results come back with `qt_thread().queue`.
- **Telamon.Ui is the installed `telamon-ui` package** from atlas-framework
  (`~/Documents/Atlas Framework`, read-only from here). Never fork Telamon.Ui
  components into this repo: ask the "AtlasOS Framework" session.
- **No privilege.** No setuid, polkit, system service or root step.
- Commits are authored as
  `EternalHell <77252745+EternalCoder454@users.noreply.github.com>`. Commit
  only the paths you own (`git commit -- <paths>`). Don't push unless the
  lead asked.
- Licence: MIT. App ID and D-Bus name `net.eterneon.telamon.archive`. Wording
  follows KDE: Title Case buttons and titles, US spelling.
- **Until the next release the old names still work** (Atlas Archive, 0.1.x):
  `atlas-archive` and `atlas-archive-cli` (links), `net.eterneon.atlas.archive`
  (hidden desktop file with the same MimeType list, empty service menu, and
  the D-Bus name and path, see `cpp/main.cpp`), `~/.local/state/atlas-archive`
  (moved on first use) and `.atlas-partial-` staging folders (still cleaned).
  The other apps and the image move to the new names one by one; do not
  remove these before they have (`apps/telamon-archive/data/legacy`).

## Commands

| Task | Command (from the repo root on the host) |
|---|---|
| Format | `scripts/dev.sh cargo fmt --all --check` |
| Lint | `scripts/dev.sh cargo clippy --workspace --all-targets --locked -- -D warnings` |
| Tests | `scripts/dev.sh bash -c 'cargo test --workspace --locked && cargo test -p telamon-archive-cli --locked --features dev-worker'` (the second runs the CLI's integration tests, which need the `dev-worker` feature) |
| App build | `scripts/dev.sh bash -c 'cmake -S apps/telamon-archive -B /work/cmake/dev -G Ninja && cmake --build /work/cmake/dev'` |
| Smoke run | `scripts/dev.sh dbus-run-session -- env QT_QPA_PLATFORM=offscreen /work/cmake/dev/telamon-archive` |
| RPM | `podman run --rm --security-opt label=disable -v "$PWD":/src -v <framework rpms>:/telamon-rpms:ro -e TELAMON_LOCAL_RPMS=/telamon-rpms -v telamon-cargo:/root/.cargo/registry -v telamon-cargo-git:/root/.cargo/git -e CARGO_HOME=/root/.cargo registry.fedoraproject.org/fedora:44 /src/packaging/build-rpm.sh /src/out` |
| Telamon checks | `git -C ~/Documents/Projects/AtlasOS/AtlasOS\ Framework archive v2.0.0 tools ui \| tar -x -C <dir>`, then `<dir>/tools/lint-app.sh apps/telamon-archive` and `<dir>/tools/check-app-names.sh apps/telamon-archive` |

`<framework rpms>` is the out dir of atlas-framework's `packaging/build-rpm.sh`
(a 2.0.0 build is in `~/.cache/atlas-test/rpms-2.0.0`).
`scripts/dev.sh` builds `localhost/telamon-archive-dev:44` on first use, which
needs `TELAMON_LOCAL_RPMS=<dir>` holding them.

## Moving the atlas-framework pin

1. Change `tag` in `Cargo.toml`, then
   `scripts/dev.sh cargo update -p telamon-framework-ui`.
2. Move the pin in `.github/workflows/ci.yml` (app-checks, its
   `framework-ref` and the framework RPM job): CI pins by the tag's commit
   SHA, with the tag in a comment (`gh api repos/EternalCoder454/atlas-framework/commits/vX.Y.Z --jq .sha`), and when the app uses something new in Telamon.Ui, `ui:`
   in `apps/telamon-archive/src/lib.rs` and `telamon-ui >=` in the spec (Requires
   and BuildRequires).
3. Rebuild the dev image against that release's RPMs.
4. Commit `Cargo.toml` and `Cargo.lock` together.
