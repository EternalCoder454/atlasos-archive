# Atlas Archive: design

What this file fixes: the layout, the backends, the sandbox, the extraction
rules, the API other apps call, the threading rule, the failure modes and the
budgets. Change it together with the code that changes them. The plan and its
reasons are the Atlas Notes note "AtlasOS/Archive/Plan"; the checklist is
"AtlasOS/Archive/Roadmap".

## Scope

Atlas Archive replaces KDE Ark on AtlasOS. It is as simple as Windows 11's
"Extract all" and macOS's double-click, with 7-Zip's power underneath.

| Who | Does what |
|---|---|
| Archive window | Opens an archive as a folder: browse, search, preview, drag out, open nested archives in place, add, rename, delete, test, Extract All |
| Archive job windows | Progress with Cancel for every extract, compress and test, including those Explorer starts |
| `atlas-archive-cli` | The same operations for scripts and the launcher, with JSON output |
| D-Bus `net.eterneon.atlas.Archive1` | What Explorer's right-click actions and drag-out call |
| Explorer | Shows the actions and calls the API; never links libarchive |
| The AtlasOS image (coordinator) | Removes Ark, sets the mimeapps defaults listed below |

### Formats

| Format | List and extract | Create | Edit (add, rename, delete) | Backend |
|---|---|---|---|---|
| zip (deflate, deflate64, bzip2, lzma, xz, zstd, store; ZipCrypto and WinZip AES-256 read; AES-256 write; non-UTF-8 names) | yes | yes | yes, unchanged entries raw-copied | `zip` crate |
| 7z (solid, LZMA/LZMA2/PPMd/BCJ) | yes | yes | yes | libarchive to read; `7z` to create and edit |
| 7z encrypted (AES-256, encrypted headers) | yes | yes | yes | `7z` |
| tar, tar.gz/.bz2/.xz/.zst/.lz4 | yes | yes | yes, by rewriting | libarchive |
| gz, xz, zst, bz2, lz4 (one file) | yes | yes | no (one file) | libarchive |
| rar 4 and 5, multi-volume | yes | no | no | libarchive |
| rar encrypted (data or names) | yes | no | no | `unrar` (RPM Fusion nonfree, shipped in the AtlasOS image) |
| iso9660 (Joliet, Rock Ridge), cab, cpio, ar | yes | cpio only | no | libarchive |
| deb, rpm | yes (read only) | no | no | libarchive |
| Split volumes `.001`, `.002`… of any of the above | yes | yes (zip, 7z) | no | a joined reader, or `7z -v` |
| Spanned zip (`.z01`…`.zip`) | yes | no | no | `7z` |

Backends, vetted 2026-10-05:

- **libarchive** (system, Fedora 44: 3.8.7, OpenSSL crypto). The widest
  reader, and what bsdtar and Windows 11 use. Its C parsers have a steady CVE
  stream (3.8.8 and 3.8.9 fix a RAR5 double free and a tar overflow that
  Fedora 44 stable still has; 3.8.8 is in updates-testing), which is why it
  only ever runs in the sandboxed worker. The AtlasOS image moves to the
  fixed version when it reaches stable (the coordinator tracks it). Hand-written FFI for the ~40 functions used, linked with
  pkg-config; the old `libarchive3-sys` (2016) is unmaintained.
- **`zip` crate** (zip2 8.6, MIT, actively maintained, fuzzed upstream). Pure
  Rust, random access by index (parallel extraction, a central-directory
  listing for the 50k-entry budget), AES-256 read and write, raw copy for
  edits, raw name bytes for encoding detection. Its one advisory
  (RUSTSEC-2025-0168, symlink traversal in its own `extract()`) is in code we
  never call: extraction is ours.
- **`7z`** (Fedora `7zip` 26.03, LGPL; Fedora strips the RAR code). The
  reference 7z encoder, multi-threaded. It reads the password from stdin when
  `-p` is left out (verified), so a password never goes on a command line. It
  runs inside the worker's sandbox and writes only into staging.
- **Not used:** `unar` (takes passwords only as `-p` on the command line, and
  leaves partial files on failure); `sevenz-rust` (two 2026 advisories);
  `compress-tools` (a thin wrapper that extracts by itself).
- **unrar** (RPM Fusion nonfree, 7.2.7) is freeware, not free software: its
  licence allows free redistribution with the licence text, and Zach chose to
  ship it in the AtlasOS image (2026-10-05) for encrypted RAR. It runs inside
  the sandbox as `unrar x -p -y -- <archive>` with no tty: it then reads the
  password from stdin (verified, RAR4 and RAR5, encrypted names too), so it
  never goes on argv. On a system without it, encrypted RAR says "Encrypted
  RAR archives need the unrar tool, which isn't installed"; everything else
  works.

## Layout

- `crates/atlas-archive-core`: no Qt, no C parser. Entry paths and their
  checks, names (encoding detection, display and on-disk sanitising), limits,
  the worker protocol (both ends), the archive tree (an arena of entries, the
  model behind every view), the job model, the format table.
- `crates/atlas-archive-engine`: runs only in the worker. libarchive FFI, the
  zip and 7z/unrar drivers, the joined split-volume reader, and the
  extraction writer (`openat2` below the staging folder).
- `apps/atlas-archive-worker`: the sandboxed process (`/usr/libexec`).
- `apps/atlas-archive-cli`: `atlas-archive-cli`, no Qt.
- `apps/atlas-archive`: the GUI. CXX-Qt backend in `src/`, `cpp/main.cpp`
  (Qt start, single instance, the D-Bus adaptor), `qml/`.
- `fuzz/`: cargo-fuzz targets (below).

## The sandbox

The GUI and CLI never parse archive bytes. Each operation (list, extract,
test, preview, create, edit) runs in a fresh `atlas-archive-worker` process:

1. The client opens the archive (and each volume) read-only and creates the
   staging folder, then starts the worker with those descriptors, a pipe for
   requests and one for replies, an empty environment (plus `LANG`), and
   nothing else open.
2. Before it reads a byte, the worker sets `PR_SET_NO_NEW_PRIVS` and
   `PR_SET_DUMPABLE 0` and applies a Landlock ruleset: it may read its
   archive descriptors and `/usr` (never execute), and write only below the
   staging folder (files, folders and symlinks; never devices, FIFOs or
   sockets). TCP is denied (ABI 4), as are signals and abstract sockets
   outside it (ABI 6); the worker refuses to run on a kernel short of ABI 6,
   and newer rights (unix socket paths, ABI 9) are best effort. Then a
   seccomp filter denies what Landlock doesn't rule: `socket` and
   `socketpair` of every family (so no UDP, netlink or unix sockets at all),
   starting processes (`fork`, `vfork`, `clone` without `CLONE_THREAD`,
   `clone3`, `execve`, `execveat`; threads still work), namespaces,
   `ptrace` and `process_vm_*`, extended attributes and ACLs (`*setxattr*`),
   io_uring and the older `io_*` calls, BPF, perf, keyrings, `userfaultfd`,
   mounts, modules and the other administrative calls, System V and POSIX
   message queues, shared memory and semaphores, `kcmp`, `setpriority`, and
   the terminal and btrfs `ioctl` commands that reach outside the worker
   (`TIOCSTI`, `TIOCLINUX`, `TIOCCONS`, `TIOCSCTTY`, `TIOCSETD`, subvolume
   and snapshot creation); `prlimit64` and the `sched_set*` calls work only
   on the worker itself (pid 0). A call from another architecture's table
   kills it. The worker refuses to start with a terminal on descriptor 0, 1
   or 2: the client gives it pipes. So nothing a compromised parser starts can outlive the worker
   and keep writing to staging while the client audits it. Limits:
   `RLIMIT_AS` 4 GiB (the largest 7z dictionary is 1.5 GiB),
   `RLIMIT_CORE` 0, `RLIMIT_NOFILE` 256. On a kernel without Landlock the
   worker refuses to run unless the build was made for tests. The client
   starts it in its own process group with `PR_SET_PDEATHSIG(SIGKILL)` and
   kills the group. The `7z` and `unrar` jobs, which must start a program,
   get their own profile when those drivers land: the tool runs in a new
   PID namespace (inside a user namespace) whose init is the worker, so
   killing the worker kills every process the tool started, and the worker
   reaps them all before it audits.
3. Requests and replies are length-prefixed binary frames (`core::proto`),
   capped at 1 MiB each, 64 MiB per listing. The client treats every reply as
   untrusted: it re-checks paths, names, counts and sizes. A compromised
   worker can put anything inside staging (Landlock stops it only from
   writing elsewhere), so the client also audits staging before moving
   anything out (see "Extraction rules").
4. Cancel is `SIGKILL` to the worker, then the client deletes staging. A
   crash, a frame error or a limit overrun is an error with a plain message,
   never a hang: every read from the worker has a timeout that resets with
   progress (30 s without a byte).

Passwords reach the worker over its request pipe, never through argv, the
environment or a file, and `7z`/`unrar` get them on stdin. In Rust
they live in `Zeroizing` buffers with a redacting `Debug`; nothing logs a
request frame. On the Qt side the text field's buffer is overwritten through
the shared `QString` and the field cleared as soon as Rust has its copy (best
effort: Qt may have made copies we cannot reach). The worker exits after
each job, so libarchive's own copy dies with it.

## Extraction rules

Every entry path is untrusted. In `core::path`:

- Names are decoded first, then split on `/` (and `\` for archives made on
  DOS or Windows). Empty and `.` components are dropped. An absolute path,
  `..` anywhere, NUL, a drive prefix (`C:`, DOS archives only), more than 256
  components or more than 4,096 bytes on disk rejects the entry; it is listed
  in the report as skipped, with the reason.
- The tree holds at most 1,000,000 nodes and reports at most 10,000 skipped
  entries individually; past either, the rest are counted, not kept.
- Each component is sanitised for disk (below); two entries that sanitise to
  the same path get `name (2)`, never a silent overwrite.

The writer (`engine::extract`) works below one descriptor, the staging folder:

- Staging is `.<archive name>.atlas-partial-<random>`, created 0700 with
  `mkdirat` inside the destination, and opened `O_DIRECTORY|O_NOFOLLOW`.
- Every open is `openat2(staging, path, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
  | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`; files with `O_CREAT|O_EXCL|
  O_NOFOLLOW|O_CLOEXEC`. A symlink made earlier in the same archive can
  therefore never be followed by a later entry (symlink-then-file), and no
  path can leave staging (zip-slip).
- Symlinks are created last, after every file and folder, and only when
  their target is relative, stays inside the extracted tree when resolved
  from the link's own folder, and passes through no other symlink of the
  archive on the way (a link to `.` would otherwise let `x/..` climb out),
  and does not name the top of the extracted tree itself (a link to the top
  would point into the user's folder once the result moves out).
  Lexical resolution then matches what the kernel will do. Others are skipped
  and reported ("2 links that point outside the folder were not extracted").
  Hardlinks are made with `linkat` only to a regular file this run already
  wrote (looked up by its sanitised path); others become skipped entries.
- Device nodes, FIFOs and sockets are never created. setuid, setgid and
  sticky bits are dropped; permissions are `mode & 0777 & ~umask`, with the
  owner's read and write kept (and search, for folders), so nothing extracted
  is locked away from its owner. A file reached by a launcher name
  (`*.desktop`, `*.directory`, `*.kdelnk`, any case), whether directly,
  through a hard link or at the end of symlinks, loses its execute bits, so a
  click opens it as text instead of running it. Owners, ACLs and xattrs are not
  restored. Files are written 0600 and get their final mode and times
  (`futimens`) when complete; folders get theirs last, deepest first.
- Each entry's bytes are counted as they are written. More than its declared
  size is a corrupt archive.

Then the result moves out of staging with `renameat2(RENAME_NOREPLACE)`:

- **Extract to `<name>/`** (and Extract All): staging itself becomes the
  folder. If the archive holds one top-level folder with that same name,
  that folder is moved out instead, so `photos.zip` holding `photos/` never
  gives `photos/photos/` (a lone folder with another name stays inside, so
  the result is always `<name>`), under the same `Tree::lone_top` rule as
  Extract here
  (a folder holding `l -> ../.ssh/x` stays inside the new folder). A name in
  use becomes `name (2)`.
- **Extract here** (smart, as Explorer, macOS and PeaZip do): an archive
  holding one top-level item extracts as that item; anything else goes into a
  `<archive name>` folder. The lone item is moved out only when the tree
  says it is safe (`Tree::lone_top`): a folder whose symlinks all stay inside
  it, or a file whose name doesn't start with `.` (so `.bashrc` or `.config/`
  never land loose in the user's folder). On a name clash the job asks, with Explorer's
  choices: Replace, Skip, Keep Both (default), "Do this for all conflicts".
  Replace moves the old item to the trash (XDG trash spec, same file system),
  never deletes it.
- A cancel deletes staging (by descriptor, never following links). A crash
  leaves only the hidden staging folder: each job records its staging path
  in `~/.local/state/atlas-archive/jobs/`, and the next start removes the
  ones whose job is dead. The user's files never mix with half a tree.
- Before writing, the free space below the destination is checked against
  the declared total; a full disk mid-way stops with "There isn't enough
  space on <device> for <archive>", and staging is removed.
- **The staging audit** (`core::audit`, one walker used in two places):
  walks staging by descriptor (`openat2` as above, never following links,
  breadth first, one descriptor open at a time, with the node, depth and
  path-length caps of the tree; past one, the audit fails and staging is
  deleted). Staging itself is set to 0700 first (the move out gives the
  folder its final mode). The audit describes what is there as archive
  entries and builds a `Tree` from them, so the same rules decide: anything but regular files, folders
  and symlinks is removed; a file with more links than names in staging (a
  hard link to a file outside) is removed by every name, before any mode is
  touched; the others become hard link entries of their first name; every
  symlink is checked as an archive's would be and removed when it fails;
  a name that isn't its own disk form is renamed to it
  (`renameat2(RENAME_NOREPLACE)`, through a temporary name first so no
  order of clashing names can fail; paths already in disk form keep their
  names, clashes get `name (2)`); setuid, setgid and sticky bits go, the
  umask applies, every extended attribute but the SELinux label goes
  (ACLs included), and a file loses its execute bits when any of its names
  is a launcher or a launcher-named link resolves to it (resolved by the
  kernel below staging, after the renames). Modes and attributes are fixed
  through an `O_PATH` handle checked (device, inode, type) to be what the
  walk found. The tree it returns is built again from what is left, and
  each item's name in it must be its name on disk, or the audit fails. Two
  folders whose names have the same disk form are never merged: the audit
  fails. Paths of 4096 bytes or more fail it too. Removals are reported as
  skipped entries: the first 1000 by name (each shown in at most 1024
  bytes), the rest as a count.
- **After a libarchive extraction** the client runs the audit itself, once
  the worker has exited: it kills (`SIGKILL`) and reaps (`waitpid`) the
  worker before the first look at staging, so nothing can change between
  the check and the move.
- **After `7z` or `unrar`** the worker runs the audit too, once the tool and
  all its children have exited, also when the tool failed; then the client
  runs it again as above. Neither tool is given link options (`-snl` for
  7z, `-ol` for unrar), so they make no links; the audit removes any that
  appear anyway.
- **Moving out.** The worker's `Done` names what it wrote at the top of
  staging; the client uses it only as a cross-check. What moves is the top
  level of its own audited walk: each name a single component
  (`components.len() == 1`, no `dir_hint`, the raw bytes equal to the disk
  form, no duplicates), moved with `renameat2(staging_fd, name, dest_fd,
  name, RENAME_NOREPLACE)`. Never a path string joined from what the worker
  said. A `Done` that names something the walk didn't find, or misses
  something it did, is logged as a worker fault.

### Bomb limits

Checked from the listing before extraction, and again against bytes actually
written (declared sizes can lie, and tar.gz streams have none):

| Limit | Default | Past it |
|---|---|---|
| Total expanded size | 16 GiB | ask |
| Free space (`fstatvfs` of staging, in the worker) | what is free, less 1 GiB (a tenth of it on a smaller drive) | stop; no answer goes past it |
| Ratio, expanded to archive size | 100:1, once past 256 MiB | ask |
| Entries | 200,000 | ask |
| One entry's ratio | 1,000:1, once past 64 MiB | ask |
| Nested archive depth (opened in place) | 8 | refuse: "extract it first" |

Every folder, file and link the extraction creates costs 4 KiB against the
size limits on top of its data, and counts as an entry, so an archive of a
million empty folders asks (and stops at the free space) like one of a
million bytes. The free-space reserve is 1 GiB, or a tenth of what is free
on a smaller drive. `Reply::Limit` for the free space or the nesting depth
is a failure, never a question: the client offers no "go on" and never
sends `GoOn(true)` for them (the worker would not ask).

The worker measures the archive's ratio against bytes read from the file
(`archive_filter_bytes(-1)`). libarchive gives no per-entry packed size, so
the one-entry ratio applies only where a backend knows it (the zip crate,
7z's listing); the whole-archive ratio covers the rest.

The question is in plain words, with Cancel the default: "This archive would
expand to 48 GB, 4,800 times its own size. Archives built to fill a disk look
like this. Extract it anyway?" During extraction the worker pauses at the
limit and the job waits for the answer. The CLI fails past a limit unless
given `--allow-large`.

## Names

Zip names without the UTF-8 flag are decoded with one encoding per archive:
UTF-8 if every name is valid UTF-8, else the best of `chardetng`'s guess and
CP437 (the default for archives made by MS-DOS or Windows' own zip), with
Shift_JIS, GBK, Big5, EUC-KR, CP866, Windows-1251 and Windows-1252 among the
candidates. The window offers Name Encoding to override it. RAR and tar use
libarchive's `hdrcharset` with the same guess.

- **Shown:** control characters (C0, C1, DEL) as `\xNN` in a dimmed style
  (a literal `\` as `\\`, so an escape can't be faked), bidi controls
  (U+202A–202E, U+2066–2069, U+200E/F, U+061C) and invisible characters
  (zero-width spaces, word joiners, Hangul fillers, variation selectors and
  tags out of place, U+FEFF, U+2800 and the like) as `<U+202E>` (after a
  flag, only the England, Scotland and Wales tag sequences are in place),
  whitespace other than a single space as `<U+3000>`, undecodable bytes as `\xNN`. The
  row is marked "Unusual name" for any of these, and for leading, trailing
  or doubled spaces. Joiners in emoji and scripts that need them are kept.
  All text from an archive is set with `textFormat: Text.PlainText`.
- Free text from the worker (failure reasons, archive comments) goes through
  `name::display_text` before it is shown.
- **On disk:** control characters become `_`, bidi controls are removed,
  undecodable bytes are decoded by the chosen encoding or become `_`, a
  component over 255 bytes is shortened (keeping its extension, plus a short
  hash so it stays unique). The report lists every renamed entry.

## Archives as folders, drag-out, preview, nesting

- Double-click opens the archive in the Archive window, listed by a worker
  into an in-memory tree (paths split once, names interned). Views are
  folder models over it, so navigating is instant.
- **Preview** (images, text, PDF via Explorer's previewer later): the entry
  is extracted by a worker into `~/.cache/atlas-archive/<window>/` (0700),
  capped at 256 MiB, and shown from there; images are read with a
  `QImageReader` allocation limit, text as plain text.
- **Drag-out:** the drag carries `text/uri-list` of files extracted to that
  cache when the selection is under 512 MiB, and always
  `application/x-atlas-archive-entries` (the archive path and the entry
  IDs). Explorer, on a drop of the latter, calls `ExtractEntries` so large
  selections extract straight into the drop folder, with progress.
- **Nested archives** open in place: extracted to the cache, listed by a new
  worker, and shown as another breadcrumb level ("backup.zip › 2024.tar.gz ›
  photos"). Editing a nested archive is not offered.
- The cache is removed when the window closes, and at start for windows that
  are gone.

## Editing

Archives are never changed in place. A new archive is written beside the
original (`.<name>.atlas-edit-<random>`, same folder, same permissions),
`fsync`ed, then renamed over it; the original stays intact until that rename.
zip copies unchanged entries raw; 7z edits run `7z a|d|rn` on a reflink
(`FICLONE`, instant on btrfs) or a copy in staging; tar rewrites through
libarchive. Read-only formats show the actions disabled with the reason:
"RAR archives can't be changed. Extract it and compress the files as ZIP
or 7z."

## The API other apps call

App ID, D-Bus name and desktop file: `net.eterneon.atlas.archive`
(`DBusActivatable=true`, `KDBusService::Unique`, so
`org.freedesktop.Application` works too).

### D-Bus: `net.eterneon.atlas.Archive1` at `/net/eterneon/atlas/archive`

Every method takes `file://` URIs (absolute, local, no NUL; others are
refused with `net.eterneon.atlas.Archive1.Error.InvalidArgs`) and an
`a{sv}` of options. Known options: `activation_token` (s, for focus),
`parent_window` (s, `wayland:<xdg-foreign handle>` or `x11:<hex id>`, so our
dialogs stack on the caller's window), `show_progress` (b, default true;
Explorer passes false and shows the job in its own queue). Unknown keys are
ignored. A call returns as soon as the job is queued; at most 16 jobs wait at
once.

| Method | Does |
|---|---|
| `ExtractHere(as archives, a{sv}) → o job` | Extract here, as above |
| `ExtractTo(as archives, s folder, a{sv}) → o job` | Extract each to `<folder>/<name>/`; `folder` empty means next to the archive ("Extract to <name>/") |
| `ExtractAll(as archives, a{sv})` | The Extract All dialog: asks once where, defaults to `<name>/` next to it |
| `ExtractEntries(s archive, as entries, s folder, a{sv}) → o job` | The drop half of drag-out |
| `Compress(as files, s format, s destination, a{sv}) → o job` | `format`: `zip`, `7z`, `tar.gz`, `tar.xz`, `tar.zst`, at Normal level, no password. `destination` empty: `<name>.<ext>` next to the first item, `Archive.<ext>` for several, ` (2)` on a clash |
| `CompressDialog(as files, a{sv})` | The Compress… dialog: name, place, format, level, password, split size |
| `Test(as archives, a{sv}) → o job` | Integrity test with a result window |
| `Open(s archive, a{sv})` | The Archive window |

A password is never a D-Bus argument: when one is needed, the job's own
window asks for it.

Job objects, `/net/eterneon/atlas/archive/job/<n>`, interface
`net.eterneon.atlas.Archive1.Job`:

- properties (with `PropertiesChanged`, at most 10 a second): `Title` (s),
  `State` (s: `queued`, `running`, `paused`, `waiting-for-user`, `done`,
  `failed`, `cancelled`), `ProcessedBytes` (t), `TotalBytes` (t, 0 unknown),
  `ProcessedItems` (u), `TotalItems` (u, 0 unknown), `Error` (s, plain words)
- methods: `Pause()`, `Resume()` (`SIGSTOP`/`SIGCONT` to the worker),
  `Cancel()`
- signal: `Finished(s state, as results)`, `results` being the URIs of what
  was made (for Explorer to select)

Job objects disappear 60 s after they finish.

### CLI: `atlas-archive-cli`

`list`, `extract`, `test`, `create`, `info`, each with `--json` (one JSON
object per line, names as given plus a `display` form). Passwords come from
the terminal or `--password-fd N`, never an argument. Limits are enforced
unless `--allow-large`. Exit codes: 0 done, 1 failed, 2 bad usage, 3 needs
a password, 4 a limit refused, 130 cancelled.

The GUI takes `atlas-archive [--extract-here|--extract-to DIR|--extract-all|
--compress-zip|--compress|--test] FILES…` (the Explorer actions without
D-Bus), and `atlas-archive FILE` opens it.

### Browsing inside Explorer

Version 1: double-click opens the Archive window (the default handler), which
is the browse, preview and drag-out view. No KIO worker and no FUSE mount: a
stock KIO worker (kio-extras' `zip:`/`tar:`) parses archives in-process
outside this sandbox and caches passwords in kpasswdserver, and FUSE exposes
the contents to every process of the user for the mount's lifetime.

After parity, an `atlas-archive:` KIO worker may follow, for Explorer and file
dialogs: a thin read-only shim (list, stat, get) with no parser of its own,
which runs every request through the same sandboxed worker and asks for
passwords through this app's dialog, never kpasswdserver. It ships only after
its own S review.

### Mime types and defaults (for the coordinator)

Archive is the default for: `application/zip`, `application/x-7z-compressed`,
`application/x-tar`, `application/x-compressed-tar`,
`application/x-bzip2-compressed-tar`, `application/x-bzip-compressed-tar`,
`application/x-xz-compressed-tar`, `application/x-zstd-compressed-tar`,
`application/x-lz4-compressed-tar`, `application/gzip`, `application/x-xz`,
`application/zstd`, `application/x-bzip2`, `application/x-bzip`,
`application/x-lz4`, `application/vnd.rar`, `application/x-rar`,
`application/vnd.ms-cab-compressed`, `application/x-cpio`,
`application/x-archive`, `application/vnd.debian.binary-package`.
It handles, without being the default: `application/x-cd-image` and
`application/x-iso9660-image` (Disks mounts ISOs), `application/x-rpm` (the
Store explains RPMs), `application/java-archive`.

## Threads

The GUI thread never blocks. Each job has one thread that drives its worker
over the pipes; listing results are folded into the tree on that thread and
handed to the GUI with `qt_thread().queue` in batches (every 50 ms or 5,000
entries). Questions (password, limits, name clashes) park the job thread on a
channel until the GUI answers. Two jobs at once by default (queue beyond
that), since extraction is disk-bound.

## Look

Atlas.Ui throughout (`AtlasWindow`, `AtlasHeaderBar`, `AtlasBreadcrumb`,
`DataTable`, `StatusHero`, `Section`/`SectionRow`, `AtlasDialog`,
`AtlasProgressBar`, `AtlasPasswordField`, `AtlasSegmentedControl`,
`AtlasDropZone`, `ContextMenu`).

- **No archive open:** a centred hero ("Open an archive, or drop files here
  to compress them"), Open Archive… as the one accent button, Create
  Archive… secondary.
- **Archive open:** header with Back, Up, the breadcrumb (nested levels
  included) and search; Extract All… is the accent button; a menu for Add
  Files…, Test, Name Encoding, Properties. The list is a grouped rounded
  table (Name, Size, Packed, Modified); an info and preview pane on the right
  toggles.
- **Password needed:** the hero with a lock, the password field and Open.
- **Job window** (Windows' copy dialog, drawn with Atlas.Ui): title ("Extracting
  photos.zip"), progress, "1.2 GB of 3.4 GB · about 2 minutes left", Cancel;
  when done "Extracted to Photos" with Show Files (accent) and Close, and a
  details list of anything skipped or renamed.
- **Compress dialog:** Name, Location, Format (ZIP, 7z, TAR.GZ, TAR.XZ,
  TAR.ZST), Level (Store, Fast, Normal, Best), Password (with "Encrypt file
  names" for 7z, and a note that ZIP encryption hides contents but not
  names), Split (Off, 100 MB, 700 MB, 4 GB, Custom; a note that split zips
  need Atlas Archive or 7-Zip to join).

## Failure modes

| Failure | Behaviour |
|---|---|
| Wrong password | Asked again in place with "That password didn't work"; never a crash or a stuck "Loading" |
| Corrupt or truncated archive | Listing shows what was readable and says where it broke; extraction keeps complete entries only if the user chooses "Keep What Was Extracted" |
| Missing volume | "Part 3 of 5 (photos.7z.003) is missing", with Locate… |
| Disk full, read-only destination, permission denied | Stops, removes staging, says which and where |
| Worker crash, kill, timeout, garbage | Job failed with a plain message; logged with the format and offset, never the password |
| Archive changed or removed while open | Detected by size and mtime before each job; asks to reload |
| Name clash | Asked (Extract here) or `name (2)` (Extract to) |
| Cancel at any point | Worker killed, staging removed, nothing left in the destination |
| Crash or power loss | Hidden staging only, cleaned at next start; edited archives are either old or new, never half |
| Huge archive (1M entries) | Listing streams in, the window stays responsive, the limit question comes first |
| No Landlock | Refuses to open archives, saying why (AtlasOS kernels have it) |
| `7z` missing | 7z creation and encrypted 7z say "7-Zip is missing"; other formats work |

## Privilege

None. No setuid, no polkit, no system service, no root step. D-Bus
activation starts it in the user's session only. The sandbox only removes
rights.

## Budgets

| What | Budget |
|---|---|
| Open a 50k-entry zip to the listing painted | ≤ 300 ms (worker listing ≤ 120 ms) |
| Cold start to the empty window | ≤ 350 ms |
| Extraction throughput | ≥ `7z x` and `bsdtar -x` on the same archive (zip: parallel; tar.*: same libarchive) |
| zip and 7z creation | ≥ 0.9× `7z a` at the same level and threads |
| Folder navigation, search keystroke on 50k entries | ≤ 16 ms, ≤ 50 ms |
| Worker start (spawn + sandbox) | ≤ 10 ms |
| RSS | GUI ≤ 120 MB with a 50k-entry archive open; worker ≤ 64 MB plus codec dictionaries |
| Idle CPU, window open | 0 % |
| RPM | ≤ 8 MB |

## Fuzzing and malicious archives

cargo-fuzz targets: `entry_path` (path checks), `names` (decode, display and
disk forms), `proto` (the client's reply parser), `list` (libarchive and zip
listing of arbitrary bytes, every format) and `extract` (arbitrary bytes
extracted into a temporary folder, asserting nothing appears outside it, no
symlink escapes, no device node, no setuid bit). The test suite holds crafted
archives for each attack: `../` and absolute paths, zip-slip through
backslashes, symlink-then-file, hardlink escapes, a symlink chain, a
42.zip-style bomb, an overlapping-entries zip bomb, a 300k-entry archive,
device and FIFO entries, setuid files, names with control and bidi
characters, invalid encodings, and entries lying about their size.
