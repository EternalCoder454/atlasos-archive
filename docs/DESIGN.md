# Telamon Archive: design

What this file fixes: the layout, the backends, the sandbox, the extraction
rules, the API other apps call, the threading rule, the failure modes and the
budgets. Change it together with the code that changes them. The plan and its
reasons are the Atlas Notes note "AtlasOS/Archive/Plan"; the checklist is
"AtlasOS/Archive/Roadmap".

## Scope

Telamon Archive replaces KDE Ark on Telamon OS. It is as simple as Windows 11's
"Extract all" and macOS's double-click, with 7-Zip's power underneath.

| Who | Does what |
|---|---|
| Archive window | Opens an archive as a folder: browse, search, preview, drag out, open nested archives in place, add, rename, delete, test, Extract All |
| Archive job windows | Progress with Cancel for every extract, compress and test, including those Explorer starts |
| `telamon-archive-cli` | The same operations for scripts and the launcher, with JSON output |
| D-Bus `net.eterneon.telamon.Archive1` | What Explorer's right-click actions and drag-out call |
| Explorer | Shows the actions and calls the API; never links libarchive |
| The Telamon OS image (coordinator) | Removes Ark, sets the mimeapps defaults listed below |

### Formats

| Format | List and extract | Create | Edit (add, rename, delete) | Backend |
|---|---|---|---|---|
| zip (deflate, deflate64, bzip2, lzma, xz, zstd, store; ZipCrypto and WinZip AES-256 read; AES-256 write; non-UTF-8 names) | yes | yes (deflate or store since 0.3.0; AES-256 later) | yes, unchanged entries raw-copied | `zip` crate; libarchive writes (0.3.0) |
| 7z (solid, LZMA/LZMA2/PPMd/BCJ) | yes | yes (LZMA2 or copy since 0.3.0, no passwords yet) | yes | libarchive to read and (0.3.0) to create; `7z` to edit |
| 7z encrypted (AES-256, encrypted headers) | yes | yes | yes | `7z` |
| tar, tar.gz/.bz2/.xz/.zst/.lz4 | yes | yes (tar.gz, tar.xz, tar.zst since 0.3.0) | yes, by rewriting | libarchive |
| gz, xz, zst, bz2, lz4 (one file) | yes | yes | no (one file) | libarchive |
| rar 4 and 5, multi-volume | yes | no | no | libarchive |
| rar encrypted (data or names) | yes | no | no | `unrar` (RPM Fusion nonfree, shipped in the Telamon OS image) |
| iso9660 (Joliet, Rock Ridge), cab, cpio, ar | yes | cpio only | no | libarchive |
| deb, rpm | yes (read only) | no | no | libarchive |
| Split volumes `.001`, `.002`… of any of the above | yes | yes (zip, 7z) | no | a joined reader, or `7z -v` |
| Spanned zip (`.z01`…`.zip`) | yes | no | no | `7z` |

Backends, vetted 2026-10-05:

- **libarchive** (system, Fedora 44: 3.8.7, OpenSSL crypto). The widest
  reader, and what bsdtar and Windows 11 use. Its C parsers have a steady CVE
  stream (3.8.8 and 3.8.9 fix a RAR5 double free and a tar overflow that
  Fedora 44 stable still has; 3.8.8 is in updates-testing), which is why it
  only ever runs in the sandboxed worker. The Telamon OS image moves to the
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
  ship it in the Telamon OS image (2026-10-05) for encrypted RAR. It runs inside
  the sandbox as `unrar x -p -y -- <archive>` with no tty: it then reads the
  password from stdin (verified, RAR4 and RAR5, encrypted names too), so it
  never goes on argv. On a system without it, encrypted RAR says "Encrypted
  RAR archives need the unrar tool, which isn't installed"; everything else
  works.

## Layout

- `crates/telamon-archive-core`: no Qt, no C parser. Entry paths and their
  checks, names (encoding detection, display and on-disk sanitising), limits,
  the worker protocol (both ends), the archive tree (an arena of entries, the
  model behind every view), the job model, the format table.
- `crates/telamon-archive-engine`: runs only in the worker. libarchive FFI, the
  zip and 7z/unrar drivers, the joined split-volume reader, the
  extraction writer (`openat2` below the staging folder) and the archive
  writer (`create.rs`).
- `crates/telamon-archive-service`: no Qt. The Archive1 API's logic: argument
  checks, the job queue, each job's state and questions, driven through the
  client.
- `apps/telamon-archive-worker`: the sandboxed process (`/usr/libexec/telamon-archive/telamon-archive-worker`, `client::SYSTEM_WORKER`).
- `apps/telamon-archive-cli`: `telamon-archive-cli`, no Qt.
- `apps/telamon-archive`: the GUI. CXX-Qt backend in `src/`, `cpp/main.cpp`
  (Qt start, single instance, the D-Bus adaptor), `qml/`.
- `fuzz/`: cargo-fuzz targets (below).

## The sandbox

The GUI and CLI never parse archive bytes. Each operation (list, extract,
test, preview, create, edit) runs in a fresh `telamon-archive-worker` process:

1. The client opens the archive (and each volume) read-only and creates the
   staging folder, then starts the worker with those descriptors, a pipe for
   requests and one for replies, an empty environment (plus `LANG`, and the
   user's `TZ` when it is set, UTF-8 and at most 256 bytes, for the local
   times DOS-era entries store), and nothing else open.
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
   message queues, shared memory and semaphores, `kcmp`, `setpriority`,
   `ioprio_set`, `migrate_pages`, `move_pages`, `pidfd_send_signal`,
   `process_mrelease`, `setpgid` and `setsid` (the group stays the one the
   client made), and
   the calls that change the mode, owner, times or extended attributes of a
   file *by path* (`chmod`, `fchmodat`, `fchmodat2`, `chown`, `lchown`,
   `fchownat`, `fchown`, `utime`, `utimes`, `futimesat`, `removexattr` and
   its kin; `utimensat` only without a path, which is `futimens`) because
   Landlock does not rule them and the worker needs them only on the
   descriptors it opened below staging, the newer siblings of calls denied
   here (`open_tree_attr`, `file_getattr`/`file_setattr`, `listns`,
   `quotactl_fd`), the security-module calls (`lsm_*`), `fanotify`, and
   the terminal and btrfs `ioctl` commands that reach outside the worker
   (`TIOCSTI`, `TIOCLINUX`, `TIOCCONS`, `TIOCSCTTY`, `TIOCSETD`, subvolume
   and snapshot creation); `prlimit64` and the `sched_set*` calls work only
   on the worker itself (pid 0). A call from another architecture's table
   kills it. The worker refuses to start with a terminal on descriptor 0, 1
   or 2: the client gives it pipes. So nothing a compromised parser starts can outlive the worker
   and keep writing to staging while the client audits it. Limits:
   `RLIMIT_AS` 4 GiB (the largest 7z dictionary is 1.5 GiB),
   `RLIMIT_CORE` 0, `RLIMIT_NOFILE` 256. `tzset()` runs before Landlock, so
   local-time conversions (zip DOS times, iso9660, cab) can read
   `/etc/localtime`. On a kernel without Landlock, or with one older than ABI
   6, the worker refuses to run unless the build was made for tests, and
   says so in plain words ("This system's kernel doesn't offer the sandbox
   Telamon Archive needs"); the library's own error goes to the log. The client
   starts it in its own process group with `PR_SET_PDEATHSIG(SIGKILL)` and
   signals the worker itself through its pidfd (flags 0, which can't be
   redirected) and its group with `kill(-pid)`, both every time and only while
   the child is unreaped, so the number is still its own; never the pidfd's
   process-group flag, which follows the worker into whatever group it joined.
   Its working folder is
   `/`, its signal dispositions and mask are reset, and every descriptor
   above 4 is closed at exec. The archive is opened `O_PATH` first, checked
   to be a regular file, then reopened read-only (`O_NOCTTY`) and checked to
   be the same file. `PR_SET_PDEATHSIG` is bound to the thread that starts
   the worker, so that thread lives until the job returns. After the kill,
   the client waits at most 10 s for the worker to go; a worker stuck on a
   dead drive gets "The archive's drive isn't responding.", is left to a
   reaper thread, and its staging is kept for the next start's cleanup. The
   `7z` and `unrar` jobs, which must start a program,
   get their own profile when those drivers land: the tool runs in a new
   PID namespace (inside a user namespace) whose init is the worker, so
   killing the worker kills every process the tool started, and the worker
   reaps them all before it audits.
3. Requests and replies are length-prefixed binary frames (`core::proto`),
   capped at 1 MiB each, 256 MiB and 1,000,000 entries per listing. An Extract
   request names its entries as sorted `[start, len]` runs (at most 1,000,000
   indices); a selection too scattered for one frame is refused before
   anything starts ("Too many items are selected to extract at once…"), never
   blamed on the reader. A listing that asks for a password (encrypted
   headers) is asked like any job, before any entry. The client treats every reply as
   untrusted: it re-checks paths, names, counts and sizes. A compromised
   worker can put anything inside staging (Landlock stops it only from
   writing elsewhere), so the client also audits staging before moving
   anything out (see "Extraction rules").
4. Cancel is `SIGKILL` to the worker, then the client deletes staging. A
   crash, a frame error or a limit overrun is an error with a plain message,
   never a hang: every read from the worker has a timeout that resets only
   when the job advances (30 s without more Progress bytes or items, a
   listing batch or the answer to a question; Progress that goes backwards
   is a protocol error). A job may send at most 4,000,000 frames and
   1,000,000 skipped-entry frames; each kind of limit is asked once; after a
   declined limit only `Failed` is accepted; a password is asked 5 times at
   most, and each one asked is tried. A listing batch with no entries
   doesn't count as the job advancing. Progress of one byte at a time does,
   so a hostile worker can creep along slowly; the user's Cancel ends it.
   The worker therefore sends `Progress` on a 100 ms clock from every loop
   that can take long: every entry (data or not), each read of data it
   throws away (entries skipped behind a compression filter are read and
   discarded in steps, never skipped in one blocking call; where skipping is
   a seek it stays one), and each link or folder made when the extraction
   finishes. Progress's items advance with every one of those. `Progress`
   means: `bytes`, the entry data handled so far, written to files or read and
   thrown away (so it can pass the size of the entries selected, and the
   client clamps it); `items`, the entries handled so far, each counted once:
   files when read, folders and links as the end of the pass makes them,
   all of them by the final `Progress`. Both only grow. libarchive isn't
   thread-safe, so there is no heartbeat thread. The worker reads no request
   except the answer to an open limit question: any other request, before
   or during one, fails the job as out of turn.
   The worker logs to descriptor 2, one line per failure and per entry that
   couldn't be written (the first 50): format, bytes read, entry number and
   an error code; never a path, a name or a password.
   While a limit question is open, the client stops the worker and its
   group (`SIGSTOP`) and continues them (`SIGCONT`) before sending the
   answer; Cancel kills them as usual. If the stop can't be sent, the client
   doesn't ask: it kills the worker and the job fails ("Telamon Archive
   couldn't pause the archive reader to ask, so it stopped."). The space
   check runs right after the stop, before the question. A worker's end that
   can't be waited for (the host set `SIGCHLD` to be ignored after the
   spawn) is confirmed through the pidfd, within the same bounded wait; if it
   can't be, the worker counts as hung. At most 8 workers stuck on drives that
   don't respond (waited for by reaper threads) exist at once; past that,
   new jobs are refused ("Too many archive jobs are stuck…"). The client
   enforces the size limits too: it checks staging's file system every
   250 ms and kills the worker when the free space
   falls below the reserve, or the space used passes the approved size plus
   an eighth (at least 16 MiB). The watch fails closed: where the drive gives
   no usable figure (an error, or zeros for block size and count: some FUSE
   and network file systems), an extraction is refused before the worker is
   asked ("This drive doesn't report its free space, so Telamon Archive can't
   extract here safely."), and the worker itself reports no figure there
   too. A read that fails during a job is logged and tolerated; the third in
   a row, at least 2 s after the first, stops the job. The "approved size" is
   measured on the whole drive, so another program's writes during the job
   count as used: that is what the margin is for, and a busy drive can stop
   a job early. Every stop is logged with the figures (free at start, free
   now, reserve, used, approved). A pause (`SIGSTOP`)
   is confirmed through the pidfd (`waitid`, which reports a stop only once
   every thread has stopped; else the leader's state in `/proc` while the
   child is unreaped), up to 3 s, before the space check, or the job fails.
   Once the pidfd says the worker is gone (`ESRCH`), nothing more is
   signalled by number, since the kernel may have reaped it and reused the
   number. The xdg-document-portal's FUSE mount reports no figures, so a
   folder passed through it is refused. Writes to the worker never raise `SIGPIPE`
   (blocked on the writing thread), so a host that doesn't ignore it can't
   be killed by a worker that closed its end.

**Creating an archive (0.3.0)** is a job of the same worker, with `Create`
as its one request. It has no archive on descriptor 3, the staging folder on
4 (the archive is written there, as `archive.part`), and the folders its items
are in on 5 and up (`proto::ROOT_FD`, at most 64 and 10,000 items). The client
opens each parent folder and checks each item is there; the worker reads the
request before the sandbox goes up (the client wrote it; it holds no archive
byte) so that Landlock gets one read rule for each item given, a file or a
folder beneath it, and nothing else: it can't read the item's neighbours, run
anything, or write outside staging. Items are read through those descriptors
with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`,
a link is stored as a link and never followed, devices, FIFOs and sockets are
left out and reported, and the staging folder itself is skipped if an item
contains it. A first pass counts the bytes and items (`Reply::Scanned`, so
the client has a total; its clock sees it grow) and a second writes through
libarchive's writer (zip, 7z, pax tar with a gzip, xz or zstd filter) with the
levels Store, Fast, Normal and Best; names must be UTF-8 (others are
reported and left out), owners are not stored, modes are `0777` and times are
kept. libarchive's 7z writer keeps its data in a temporary file: the worker
points `TMPDIR` into staging (`/proc/self/fd/4`), the only place it may write. The
client watches the free space of staging's drive as for extraction, kills the worker
on a cancel, checks that staging holds one plain file, gives it the user's
mode, and moves it out with `renameat2(RENAME_NOREPLACE)`: a taken name is
numbered (`name (2).zip`) when the caller didn't choose it, and asked about
(Replace through the Trash, Skip, Keep Both) when it did. Pause and Resume
are `SIGSTOP` and `SIGCONT` to the worker and its group, taken at the
client's next look (100 ms).

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

- A file is closed explicitly and the close's error counts (network and FUSE
  drives report a full disk there); a file shorter than the size the archive
  states is a failed entry (removed, reported, never a hard link target).
  `ENOSPC`, `EDQUOT`, `EROFS` and `EIO` from any step, including folders,
  links and the close, fail the whole job; a drive that can't keep modes or
  times (`EPERM`, `ENOTSUP`, `EINVAL` from `fchmod` or `futimens`) doesn't:
  the item stays without them.
- In cpio (newc) the data of a set of hard links comes with the last name,
  which libarchive reports as a link to the first: the data is written into
  the first name's file (found as the tree will resolve the link), so every
  name has the contents. The first name keeps its mode and time until that
  data is in (writing would change the time); if none comes, they are given
  at the end. If the file can't be opened again for the data, it is removed
  and reported, and the last name isn't linked to it. Only a first name
  still waiting for data is opened again (never one that is complete: a
  hostile archive with data on both names keeps the first's); and if the
  name that carries the data is refused, the first name is removed and
  reported ("its data wasn't found in the archive").
- Staging is `.<archive name>.telamon-partial-<random>`, created 0700 with
  `mkdirat` inside the destination, opened `O_DIRECTORY|O_NOFOLLOW`, and
  used only if it is ours and empty. On a drive that rejects the archive's
  name in it (FAT, exFAT and NTFS refuse `: ? * " < > |`, answering
  `EINVAL`), the name is `.archive.telamon-partial-<random>` instead, tried
  once. The sweep takes an `flock` on `jobs/sweep.lock` (0600) and holds it
  while it runs, so two starts never sweep at once.
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
  never land loose in the user's folder). With several top-level items, the
  `<archive name>` folder is ours: if one of that name is there it is
  numbered `name (2)` without asking, since nothing of the user's is replaced.
  On a name clash the job asks, with Explorer's
  choices: Replace, Skip, Keep Both (default), "Do this for all conflicts".
  Replace moves the old item to the trash (XDG trash spec, same file system),
  never deletes it; if the move out then fails, the old item is put back
  from the trash, and if that fails too, staging is kept and the message
  says where both are. Before and after the move out, the name in the
  destination is checked (device, inode, type) to be staging's descriptor.
  A mismatch after the move deletes nothing and the job still succeeds, with
  the placed path and a sentence (`Extracted::unconfirmed`) naming the hidden
  folder to look in. This is the case where some FUSE and network file
  systems change inode numbers.
  A destination folder others can write to is refused unless it is sticky
  ("Choose a folder of your own"); so is one a group other than the
  user's own can write to, and one whose access list lets another user or
  a group write (an access list that can't be read counts as shared), and
  one another user (not root) owns and can write, sticky or not. A user's
  primary group is taken as private, as on Fedora. Staging stays exactly 0700 until it is in place,
  and gets its final mode by descriptor after the move. What remains is a race with the user's
  own processes, which have the user's rights anyway. On file systems
  without `RENAME_NOREPLACE` (FAT, exFAT, some FUSE, NFS and SMB mounts) the
  move falls back to a check then `renameat`, and modes that can't be set
  there are left as the file system gives them.
- A cancel deletes staging (by descriptor, never following links,
  iteratively with a bounded number of descriptors: subtrees deeper than a
  bound are renamed up to the top and deleted from there; names are read in
  batches, with up to 256 non-empty subfolders pending per level so a wide
  tree is read once; every delete is bounded in time, and one that runs out
  is left for the next start, never retried at once). A crash leaves only the
  hidden staging folder: each job records its staging path, the boot id and
  the destination folder's device and inode in
  `~/.local/state/telamon-archive/jobs/` (0700, records ours and not group or
  other writable), and the next start removes the ones whose job is dead
  (another boot, or the pid gone or reused). A record proves nothing by
  itself: the target's name must match `.<name>.telamon-partial-<16 hex>`,
  and only a folder of ours with mode 0700 (setgid aside) is deleted, or of
  ours by name alone where the record says the file system keeps no modes
  (FAT, exFAT). When the device
  number differs (btrfs changes it across boots) but the folder's inode and
  that proof hold, it is deleted. A record whose destination is gone, not
  a folder, unreachable, or holds a folder that can't be proven waits, and
  is dropped after 30 days (by the record's age) with a log line naming the
  hidden folder, which then stays to be deleted by hand (a renamed or moved
  destination ends this way); a record whose delete keeps failing is
  dropped the same way. The whole cleanup has a 20 s budget per start; a
  delete that doesn't finish keeps its record for the next one. It runs on
  a background thread nobody waits for, at most once per 10 minutes (the
  stamp `jobs/sweep.stamp`, 0600, replaced by rename), since a dead mount
  can block it; the CLI may exit with it unfinished, so a huge leftover
  found only by short CLI runs goes a slice at a time (the GUI, which stays
  open, finishes it). Residual: a thread
  stuck in a hard-mounted dead NFS share can still hold up process exit. The user's files
  never mix with half a tree.
- Before writing, the free space below the destination is checked against
  the declared total; a full disk mid-way stops with "There isn't enough
  space on <device> for <archive>", and staging is removed.
- **The staging audit** (`core::audit`, one walker used in two places):
  walks staging by descriptor (`openat2` as above, never following links,
  breadth first, one descriptor open at a time, with the node, depth and
  path-length caps of the tree; past one, the audit fails and staging is
  deleted). When it fails with one of its own fixed sentences (two folders
  with one name, too many items, nested too deep, a name too long), the
  user sees that sentence; an OS error keeps the generic text. Staging itself is set to 0700 first (the move out gives the
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
  fails. Paths of 4096 bytes or more fail it too, as do more than 64 MiB of
  link targets in all (symlink targets as they are read, and hard links'
  target paths), and (should one ever arise) a name too long once it is in disk form. Removals are reported as
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

Entries that aren't wanted (not selected, links, anything not written) are
skipped with a seek (`archive_read_data_skip`) where the format stores its data
as it is (tar, cpio, ar, iso9660, zip, with no compression filter) and the
entry's size is stated (a zip with no central directory streams, and skipping
would inflate), and for any entry whose declared size is known and at most
32 MiB: one skip call then decodes about that much, well inside the client's
30 s deadline. The encrypted flag is the archive's word and changes nothing:
without the password a read fails fast and the entry is damaged (below). A
skip that isn't a plain seek is metered: the bytes the decoder produced
(`archive_filter_bytes(a, 0)` before and after) or the declared size, if more,
count as discarded. Every other entry (declared larger, or no size) has
its data read and thrown away, because one call to skip it could decode
without end and can't be counted or interrupted. Those bytes count: total
size and ratio are over written plus discarded bytes (not the free space,
nothing is written), so a bomb in entries nobody chose asks like any other,
and the same `Reply::Limit` answer applies. A listing has nobody to ask, so it
has a hard bound instead: it stops with a plain `Failed` once it has read and
thrown away more than 1 TiB, or more than 5,000 times the archive's size past
4 GiB; the entries already sent stay (`Entries*` then `Failed`).

Once the user approves a total size or ratio question, discarded bytes are bounded
only by Cancel.

A read error while throwing away an entry's data doesn't stop the job when
libarchive can go on (`ARCHIVE_WARN` or `ARCHIVE_FAILED`, not
`ARCHIVE_FATAL`): the listing carries on, an extraction or test reports the
entry as skipped only if it was selected (else it is only logged), and the
next header fails if the stream is broken.

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
  is extracted by a worker into `~/.cache/telamon-archive/<window>/` (0700),
  capped at 256 MiB, and shown from there; images are read with a
  `QImageReader` allocation limit, text as plain text.
- **Drag-out:** the drag carries `text/uri-list` of files extracted to that
  cache when the selection is under 512 MiB, and always
  `application/x-telamon-archive-entries` (the archive path and the entry
  IDs). Explorer, on a drop of the latter, calls `ExtractEntries` so large
  selections extract straight into the drop folder, with progress.
- **Nested archives** open in place: extracted to the cache, listed by a new
  worker, and shown as another breadcrumb level ("backup.zip › 2024.tar.gz ›
  photos"). Editing a nested archive is not offered.
- The cache is removed when the window closes, and at start for windows that
  are gone.

## Editing

Archives are never changed in place. A new archive is written beside the
original (`.<name>.telamon-edit-<random>`, same folder, same permissions),
`fsync`ed, then renamed over it; the original stays intact until that rename.
zip copies unchanged entries raw; 7z edits run `7z a|d|rn` on a reflink
(`FICLONE`, instant on btrfs) or a copy in staging; tar rewrites through
libarchive. Read-only formats show the actions disabled with the reason:
"RAR archives can't be changed. Extract it and compress the files as ZIP
or 7z."

## The API other apps call

App ID, D-Bus name and desktop file: `net.eterneon.telamon.archive`
(`DBusActivatable=true`, `KDBusService::Unique`, so
`org.freedesktop.Application` works too).

### The names until 0.2.0 (Atlas Archive)

Telamon Archive was Atlas Archive up to 0.1.x, and the apps that call it
(Explorer, the launcher) and the image change names one by one. For one
release the old names work as well as the new ones, and an app may use
either:

| Old name | Now | What keeps the old one working |
|---|---|---|
| `atlas-archive`, `atlas-archive-cli` | `telamon-archive`, `telamon-archive-cli` | symbolic links in `/usr/bin` |
| package `atlas-archive` | `telamon-archive` | `Obsoletes:` and `Provides: atlas-archive` |
| `net.eterneon.atlas.archive.desktop` | `net.eterneon.telamon.archive.desktop` | the old file stays, hidden (`NoDisplay=true`), with the same `MimeType=` list (Explorer reads it) and `Exec=telamon-archive`, so mimeapps defaults that name it still open the app |
| `kio/servicemenus/net.eterneon.atlas.archive.desktop` | `.../net.eterneon.telamon.archive.desktop` | the old file stays with no actions, so the right-click actions are not shown twice |
| D-Bus `net.eterneon.atlas.archive` at `/net/eterneon/atlas/archive` | `net.eterneon.telamon.archive` at `/net/eterneon/telamon/archive` | the running instance owns both names; `org.freedesktop.Application` answers on both (`cpp/main.cpp`). The `Archive1` interface below is served as `net.eterneon.atlas.Archive1` too (since 0.3.0), with the same jobs as objects of their own (`.../atlas/archive/job/<n>`, `net.eterneon.atlas.Archive1.Job`) and the error names under `net.eterneon.atlas.Archive1.Error.`; `net.eterneon.atlas.archive` also has its own bus activation file |
| drag type `application/x-atlas-archive-entries` | `application/x-telamon-archive-entries` | a drop carrying either is accepted, and a drag carries both |
| `atlas-archive:` KIO worker (not built yet) | `telamon-archive:` | the old scheme is registered with it |
| `~/.config/atlas-archiverc` | `telamon-archiverc` | copied once by the framework (`[Atlas]` becomes `[Telamon]`) |
| `~/.local/state/atlas-archive/jobs` | `~/.local/state/telamon-archive/jobs` | the folder moves in one rename the first time; the records in it name staging folders that are still removed |
| staging folders `.<name>.atlas-partial-<hex>` | `.<name>.telamon-partial-<hex>` | the leftovers of 0.1.x are recognised and removed like ours |
| `~/.cache/atlas-archive/<window>/` | `~/.cache/telamon-archive/<window>/` | a cache that 0.1.x never wrote; nothing to move |

The old names go in the release after the image and the other apps use the
new ones.

### D-Bus: `net.eterneon.telamon.Archive1` at `/net/eterneon/telamon/archive`

Served by the app itself (0.3.0): the methods hang off the object that
`KDBusService` exports, so `org.freedesktop.Application` and `Archive1` share
a path; the old names have theirs (`/net/eterneon/atlas/archive`). The logic
is `crates/telamon-archive-service` (no Qt: arguments, queue, jobs, state), the
bus is `cpp/archive1.cpp`, the windows are `qml/JobWindow.qml`.

**Activation.** The RPM installs `dbus-1/services/net.eterneon.telamon.archive.service`
(and one for `net.eterneon.atlas.archive`) with `Exec=/usr/bin/telamon-archive --service`.
`--service` starts the program with no window: the archive window is made
only when something asks for it (`Open`, `org.freedesktop.Application`, a
launch with files), and job windows only when a job has something to show.
The program exits when it has no visible window and no job (a finished job
is kept for 60 s for its caller) for 5 s. It owns its names before it reads
a call, so a caller's call waits on the bus until it can be answered.

Every method takes `file://` URIs (absolute, local, no NUL, no `.` or `..`
parts, at most 8 KiB; others are refused with
`net.eterneon.telamon.Archive1.Error.InvalidArgs`) and an `a{sv}` of options.
Known options: `activation_token` (s, for focus: `xdg-activation` on Wayland),
`parent_window` (s, `wayland:<xdg-foreign handle>` or `x11:<hex id>`, so our
windows stack on the caller's window; anything else is dropped),
`show_progress` (b, default true; Explorer passes false for jobs and shows
them in its own queue; our window still comes up for a question). Unknown
keys are ignored, and so is a value of the wrong type or a token that isn't
printable ASCII. Arguments are checked before a job exists: archives must be
regular files that can be read (a link to one is the archive; the file's
device and inode are remembered, and a job that finds another file under the
name when its turn comes stops), folders must be folders that can be written,
items to compress must exist (a link counts as itself), `Compress` refuses two
items of one name, an unknown format, a destination that is a folder or one
of the items. At most 64 archives or 10,000 items in a call. A call returns
as soon as the job exists; **at most 2 jobs run and 16 wait** (queued, or a
dialog waiting for its answer), and past that a call fails with
`net.eterneon.telamon.Archive1.Error.TooManyJobs` ("Archive is busy. Try
again when a job finishes."; Explorer doesn't retry by itself).

| Method | Does |
|---|---|
| `ExtractHere(as archives, a{sv}) → o job` | Extract here, as above, one archive after another in one job |
| `ExtractTo(as archives, s folder, a{sv}) → o job` | Extract each to `<folder>/<name>/`; `folder` empty means next to the archive ("Extract to <name>/") |
| `ExtractAll(as archives, a{sv}) → o job` | The Extract All dialog: asks once where, defaults to the archive's own folder (`<name>/` goes in it). The job exists at once in `waiting-for-user` with `Question` "dialog"; OK in the dialog starts it, Cancel in the dialog (or `Cancel()`) ends it as `cancelled` |
| `ExtractEntries(s archive, as entries, s folder, a{sv}) → o job` | The drop half of drag-out (below) |
| `Compress(as files, s format, s destination, a{sv}) → o job` | `format`: `zip`, `7z`, `tar.gz`, `tar.xz`, `tar.zst`, at Normal level, no password. `destination` empty: `<name>.<ext>` next to the first item, where `<name>` is a folder's name or a file's name without its extension (`report.pdf` becomes `report.zip`), `Archive.<ext>` for several, ` (2)` on a clash. A destination is used as given (the format's extension is added if it lacks it) and a clash asks |
| `CompressDialog(as files, a{sv}) → o job` | The Compress… dialog: name, place, format, level; like `ExtractAll`, the job waits in `waiting-for-user` (`Question` "dialog") until the dialog is answered. (Password and split size are not offered yet.) |
| `Test(as archives, a{sv}) → o job` | Integrity test; the job window is the result window |
| `Open(s archive, a{sv})` | The Archive window |

Before 0.3.0 `ExtractAll` and `CompressDialog` returned nothing; a caller that
ignores their return still works, and one that follows the job gets
progress, Pause/Resume/Cancel and the `results` to select, as for every
other method.

A password is never a D-Bus argument: when one is needed, the job's own
window asks for it (the job is `waiting-for-user`, `Question` "password");
there is no method on the job that takes one. A dialog nobody answers is
cancelled after 10 minutes; a finished job's window stays until it is closed,
longer than its D-Bus object.

Job objects, `/net/eterneon/telamon/archive/job/<n>`, interface
`net.eterneon.telamon.Archive1.Job` (the same jobs are objects under
`/net/eterneon/atlas/archive/job/<n>` with `net.eterneon.atlas.Archive1.Job`):

- properties (with `PropertiesChanged`, at most 10 a second per job, the last
  change always sent before `Finished`): `Title` (s), `State` (s: `queued`,
  `running`, `paused`, `waiting-for-user`, `done`, `failed`, `cancelled`),
  `ProcessedBytes` (t), `TotalBytes` (t, 0 unknown), `ProcessedItems` (u),
  `TotalItems` (u, 0 unknown), `Error` (s, plain words; it can hold archive
  names, so it is plain text and every front end shows it with
  `Text.PlainText`), and, new in 0.3.0, `Kind` (s: `extract`,
  `extract-entries`, `compress`, `test`), `Question` (s: "" for none,
  `password`, `limit`, `conflict`, `dialog`), `QuestionText` (s) and
  `Results` (as, the URIs made so far)
- methods: `Pause()`, `Resume()` (`SIGSTOP`/`SIGCONT` to the worker's group;
  a queued job is held back; progress doesn't move while paused), `Cancel()`
  (the worker is killed and nothing is left in the destination), and, new,
  `AnswerConflict(s action, b all) → b` (`replace`, `skip` or `keep-both`;
  Replace moves the old item to the Trash) and `AnswerLimit(b go_on) → b` for
  a caller that can answer a question without our window (`true` when the
  job took the answer; the window can answer too, whoever is first). A
  question always brings our window up as well, so a caller that can't
  answer loses nothing. **Only the program that started a job** (its unique
  bus name, remembered when the job is made) may `Pause`, `Resume`, `Cancel`
  or answer it; anyone else gets `net.eterneon.telamon.Archive1.Error.AccessDenied`.
  Without that, any process of the user could say "replace" or "unpack
  anyway" to a question put to someone else. Properties and `Finished` stay
  readable by everyone. The program does not know *who* a caller is beyond
  its bus name (a Flatpak app with a bus grant is a caller like any other:
  the portal is the supported way for those).
- signal: `Finished(s state, as results)`, `results` being the URIs of what
  was made (for Explorer to select): an extraction's folders or items, the
  archive. Sent once, after the last property change. Programs that listen
  for it from before the call don't miss a job that ends quickly.

Job objects disappear 60 s after they finish. The app only exits after that.

**Drag-out and `ExtractEntries`.** Archive's window starts a drag with
`application/x-telamon-archive-entries` (and the same bytes as
`application/x-atlas-archive-entries`) holding JSON:
`{"version":1,"archive":"file:///path/photos.zip","entries":["12-1a2b3c4d","15-0d9e8f7a"]}`.
Each entry is an opaque token naming one item shown in the window (a node of
the archive's tree and a hash of its path, so a token from another listing,
or after the archive changed, names nothing). A receiver that understands the
type calls `ExtractEntries(archive, entries, folder, {})` with the `archive`
URI and the tokens unchanged and `folder` the `file://` URI of the folder
dropped on. The items must be in one folder of the archive (as a window shows
them); each lands directly in `folder` (a folder with what is inside it), a
taken name asks like Extract here (every question is asked before the first
item moves, so a Cancel there places nothing), and the job's `results` are
the placed items. A link inside the items that names something not dragged
along would point outside its new place, so it is left out; that and what the
safety rules take out are listed in the job window.
`text/uri-list` is not carried yet (nothing is extracted until the drop), so
other targets get nothing from this drag.

Where a call is waiting on the user: Explorer saw `waiting-for-user` and says
once "Telamon Archive needs an answer from you".

How Explorer uses it (agreed with the Explorer session, 2026-10-05): it
always passes `activation_token` and `parent_window` and `show_progress`
false for jobs, and drives Pause, Resume and Cancel through the Job
interface; "Extract To…" is `ExtractAll` (our dialog, no picker of its own;
the returned job is followed for progress and the result is selected);
drops of `application/x-telamon-archive-entries` on a local folder, tab,
breadcrumb segment or sidebar place call `ExtractEntries(archive, ids,
folder, {})` with the entry tokens kept opaque, `text/uri-list` being the
fallback for other targets. A later `List(s archive, s inner_path)` for Quick
Look on an archive (a top-level listing capped at 200 entries plus a total
count) is wanted but low priority; changing a signature here means telling
Explorer first.

### CLI: `telamon-archive-cli`

`telamon-archive-cli COMMAND [OPTIONS] [--] ARCHIVE [ENTRY…]`, with the
commands `list`, `extract`, `test`, `create` and `info`, each with `--json`
(one JSON object per line, names as given plus a `display` form; consumers
use `display` or the index, never join `path` onto a folder). Options come
before the archive, git-style: the first word that isn't an option, or
`--`, ends them, so a file named `--allow-large` is never an option.
Explorer and the launcher pass `--` before paths. Passwords come from the
terminal or `--password-fd N` (at most 30 s of waiting, then exit 3; a
descriptor that ends with no line is exit 3 too, "No password was sent on
descriptor N."), never an argument. Limits are enforced unless `--allow-large`. `extract`
takes `--to DIR`, `--here`, `--name N` (one name, checked before any work)
and `--on-clash replace|skip|keep-both`; ENTRY is matched component by
component against the shown names (then the disk names; a name matching two
entries is an error), and a folder ENTRY brings what is inside it. `list`,
`info` and `extract` take `--encoding` for names without the UTF-8 flag.
Notes on skipped and removed entries go to stderr, and every error, reason
and log line is one line (only `info`'s archive comment keeps its line
breaks). `test` fails (exit 1) when any item couldn't be read. A first
Ctrl-C, Ctrl-\, SIGTERM or SIGHUP cancels; a second, or one with no job
running, restores the terminal and exits at once; Ctrl-Z is blocked while
the CLI runs. Once an extraction has put the files in place, its job counts
as running until the result line is written: a first signal then is ignored
and the run exits 0 (a second still exits at once). A Ctrl-C at a name-clash
or limit question cancels the job (exit 130, nothing placed). Writing to
stderr is best effort everywhere, so a closed or full stderr never changes
the exit code; after a successful extraction a failed write to stdout is a
warning on stderr naming the folder, and still exit 0. A panic in the main
thread ends the run with exit 1 and one fixed sentence; one in the signal
thread ends it with 130 (nothing could cancel it otherwise); one in any
other thread (such as the stale-staging sweep) only ends that thread. A listing that breaks part way (`list`, `info`) prints every
entry read, then the reason on stderr, and exits 1; `--json` carries it as
`"broken"` in the summary (null when whole), and `extract` of such an archive
fails before writing anything. An extraction whose move couldn't be proven
(`unconfirmed`) prints a warning on stderr after the result line, keeps exit
0, and adds `"unconfirmed"` to the JSON summary. `-v`
logs each phase: the command and options, opening, the format and entry
count, the destination, how the password was supplied (never the value), and
the elapsed time. It sets its core limit to 0 and is not dumpable (it may hold
a password). Stale staging is cleaned only by `extract`. The hidden
`--worker PATH` exists only in builds with the `dev-worker` feature (the
tests). Exit codes: 0 done, 1 failed, 2 bad usage, 3 needs a password (or
`--password-fd` gave a wrong one), 4 a limit refused, 130 cancelled.
`create` exits 2 until the CLI is wired to the writers (the worker has them since 0.3.0).

The GUI takes `telamon-archive [--extract-here|--extract-to DIR|--extract-all|
--compress-zip|--compress|--test] FILES…` (the Explorer actions without
D-Bus), and `telamon-archive FILE` opens it.

### Browsing inside Explorer

Version 1: double-click opens the Archive window (the default handler), which
is the browse, preview and drag-out view. No KIO worker and no FUSE mount: a
stock KIO worker (kio-extras' `zip:`/`tar:`) parses archives in-process
outside this sandbox and caches passwords in kpasswdserver, and FUSE exposes
the contents to every process of the user for the mount's lifetime.

After parity, an `telamon-archive:` KIO worker may follow, for Explorer and file
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
channel until the GUI answers. Two jobs at once (the rest wait, at most 16 of them), since
extraction is disk-bound. API jobs run in the job service
(`crates/telamon-archive-service`) on threads of their own and tell the GUI
thread through events; the window's own extraction (`src/job.rs`) is the
same client with the same worker.

## Look

Telamon.Ui throughout (`TelamonWindow`, `TelamonHeaderBar`, `TelamonBreadcrumb`,
`DataTable`, `StatusHero`, `Section`/`SectionRow`, `TelamonDialog`,
`TelamonProgressBar`, `TelamonPasswordField`, `TelamonSegmentedControl`,
`TelamonDropZone`, `ContextMenu`).

- **No archive open:** a centred hero ("Open an archive, or drop files here
  to compress them"), Open Archive… as the one accent button, Create
  Archive… secondary.
- **Archive open:** header with Back, Up, the breadcrumb (nested levels
  included) and search; Extract All… is the accent button; a menu for Add
  Files…, Test, Name Encoding, Properties. The list is a grouped rounded
  table (Name, Size, Packed, Modified); an info and preview pane on the right
  toggles.
- **Password needed:** the hero with a lock, the password field and Open.
- **Job window** (Windows' copy dialog, drawn with Telamon.Ui): title ("Extracting
  photos.zip"), progress, "1.2 GB of 3.4 GB · about 2 minutes left", Cancel;
  when done "Extracted to Photos" with Show Files (accent) and Close, and a
  details list of anything skipped or renamed.
- **Compress dialog:** Name, Location, Format (ZIP, 7z, TAR.GZ, TAR.XZ,
  TAR.ZST), Level (Store, Fast, Normal, Best), Password (with "Encrypt file
  names" for 7z, and a note that ZIP encryption hides contents but not
  names), Split (Off, 100 MB, 700 MB, 4 GB, Custom; a note that split zips
  need Telamon Archive or 7-Zip to join).

## Failure modes

| Failure | Behaviour |
|---|---|
| Wrong password | Asked again in place with "That password didn't work"; never a crash or a stuck "Loading" |
| Corrupt or truncated archive | Listing shows what was readable and says where it broke (the worker sends the entries read, then `Failed`); extraction keeps complete entries only if the user chooses "Keep What Was Extracted" |
| Missing volume | "Part 3 of 5 (photos.7z.003) is missing", with Locate… |
| Disk full, read-only destination, permission denied | Stops, removes staging, says which and where |
| Worker crash, kill, timeout, garbage | Job failed with a plain message; logged with the format and offset, never the password |
| Archive changed or removed while open | Detected by size and mtime before each job; asks to reload |
| Name clash | Asked (Extract here) or `name (2)` (Extract to) |
| Cancel at any point | Worker killed, staging removed, nothing left in the destination |
| Crash or power loss | Hidden staging only, cleaned at next start; edited archives are either old or new, never half |
| Huge archive (1M entries) | Listing streams in, the window stays responsive, the limit question comes first |
| No Landlock | Refuses to open archives, saying why (Telamon OS kernels have it) |
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

cargo-fuzz targets (`fuzz/`, built with `cargo fuzz run --sanitizer none <target>`
and `RUSTC_BOOTSTRAP=1` on the stable toolchain; CI runs each for 20 s,
`.github/workflows/security.yml`): `entry_path` (path checks, all encodings),
`names` (decode, display and disk forms), `proto` (the client's reply
parser, and the frame reader), `symlink` (link targets), `service_text`
(URIs the bus callers send, and the JSON strings) and `audit_staging`
(staging built from random operations, as a compromised reader could leave it,
then audited: afterwards only plain files, folders and relative links that
stay inside it, no setuid bit, no name with controls, hard links with all their
names inside, and the file outside untouched). `list` and `extract`
(libarchive on arbitrary bytes) are for the worker's own harness and are not
here: libarchive is C, so they need the sandbox. The test suite holds crafted
archives for each attack: `../` and absolute paths, zip-slip through
backslashes, symlink-then-file, hardlink escapes, a symlink chain, a
42.zip-style bomb, an overlapping-entries zip bomb, a 300k-entry archive,
device and FIFO entries, setuid files, names with control and bidi
characters, invalid encodings, and entries lying about their size.
