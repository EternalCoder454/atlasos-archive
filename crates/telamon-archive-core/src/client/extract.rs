//! Moving the audited result out of staging (docs/DESIGN.md, "Extraction
//! rules"): where it goes, what it is called, what happens on a clash.

use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use super::staging::Staging;
use super::sys;
use super::trash::Trash;
use super::{Callbacks, Cancel, Clash, Error, Mode, cause, fail, io_words};
use crate::audit::Audit;
use crate::name::{self, MAX_COMPONENT_BYTES};
use crate::proto::Kind;

/// What the destination folder is for, in the words of its errors.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Extract,
    Compress,
}

/// Opens the folder a job writes into and checks it is the user's own: not
/// writable by others (unless sticky), no access list that lets others write.
/// Returns the descriptor and the folder's absolute path.
pub fn open_destination(dest_dir: &Path, purpose: Purpose) -> Result<(OwnedFd, PathBuf), Error> {
    let into = match purpose {
        Purpose::Extract => "extract into",
        Purpose::Compress => "make the archive in",
    };
    let dest = sys::open_dir(dest_dir).map_err(|e| {
        let words = match e.raw_os_error() {
            Some(libc::ENOENT) => format!("The folder to {into} isn't there."),
            Some(libc::EACCES | libc::EPERM) => {
                format!("Telamon Archive isn't allowed to open the folder to {into}.")
            }
            Some(libc::ENOTDIR) => format!("The place to {into} isn't a folder."),
            _ => format!("The folder to {into} couldn't be opened."),
        };
        fail(words, format!("{}: {e}", sys::log_path(dest_dir)))
    })?;
    let dest_st = sys::fstat(sys::bfd(&dest)).map_err(|e| io_words("look at the folder", &e))?;
    // An access list that can't be read counts as shared, like a malformed one.
    if super::staging::dest_is_shared(&dest_st)
        || super::staging::acl_is_shared(sys::bfd(&dest)).unwrap_or(true)
    {
        let doing = match purpose {
            Purpose::Extract => "extracting into it",
            Purpose::Compress => "making an archive in it",
        };
        return Err(fail(
            format!(
                "Other users can change this folder, so {doing} isn't safe. Pick a folder of your own."
            ),
            format!("{} is writable by others", sys::log_path(dest_dir)),
        ));
    }
    let dest_abs = std::path::absolute(dest_dir).map_err(|e| io_words("find the folder", &e))?;
    Ok((dest, dest_abs))
}

/// How many numbered names (`name (2)`...) are tried before giving up.
const MAX_TRIES: u32 = 1000;

/// What the archive's file name loses to make the default folder name.
const ARCHIVE_EXTENSIONS: &[&str] = &[
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz4", ".tgz", ".tbz2", ".txz", ".tzst",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".xz", ".zst", ".bz2", ".lz4", ".iso", ".cab", ".cpio",
    ".deb", ".rpm",
];

/// The folder name for an archive file name: without its archive extension
/// (any case), in disk form, never empty and never hidden.
pub fn default_name(file_name: &[u8]) -> String {
    if matches!(file_name, b"" | b"." | b"..") {
        return "Archive".into();
    }
    let mut pieces = Vec::new();
    name::decode(file_name, name::NameEncoding::Utf8, |p| pieces.push(p));
    let (disk, _) = name::disk(&pieces);
    let lower = disk.to_ascii_lowercase();
    // The longest match: ".tar.gz" before ".gz".
    let cut = ARCHIVE_EXTENSIONS
        .iter()
        .filter(|e| lower.ends_with(**e) && disk.len() > e.len())
        .map(|e| e.len())
        .max()
        .unwrap_or(0);
    // The extensions are ASCII, so the cut is on a character boundary.
    let stem = &disk[..disk.len() - cut];
    if stem.is_empty() || stem.starts_with('.') {
        "Archive".into()
    } else {
        stem.into()
    }
}

/// `name` with a number, for a name that is taken: `name (2)` for a folder,
/// `a (2).txt` for a file. Cut to fit `NAME_MAX`. `n` is at least 2.
pub fn numbered_name(name: &str, n: u32, is_dir: bool) -> String {
    if !is_dir {
        return name::numbered(name, n);
    }
    let suffix = format!(" ({n})");
    let mut cut = name.len().min(MAX_COMPONENT_BYTES - suffix.len());
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{suffix}", &name[..cut])
}

/// A name that is one component and nothing else.
fn single_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_COMPONENT_BYTES
        && name != "."
        && name != ".."
        && !name.contains(['/', '\0'])
}

/// Where the result went.
pub struct Placed {
    pub path: PathBuf,
    /// Every item that was moved into the destination (one for most modes;
    /// the selected items for `Mode::Items`).
    pub paths: Vec<PathBuf>,
    /// Nothing was moved: the user chose Skip.
    pub left_out: bool,
    /// The answer given with "do this for all conflicts".
    pub clash_all: Option<Clash>,
    /// The move went through but couldn't be confirmed (see `unconfirmed`).
    pub unconfirmed: Option<String>,
}

/// What `move_out` needs besides the audit.
#[derive(Clone, Copy)]
pub struct MoveOut<'a> {
    pub dest_path: &'a Path,
    pub mode: &'a Mode,
    /// The folder name when the mode gives none.
    pub default_name: &'a str,
    pub umask: u32,
    pub trash: Option<&'a Trash>,
    /// A standing answer for clashes from earlier archives.
    pub clash_all: Option<Clash>,
    /// Checked after a clash question: a Ctrl-C at the prompt ends the job.
    pub cancel: &'a Cancel,
}

/// Moves what is at the top of the audited `staging` out into the
/// destination, by `renameat2(RENAME_NOREPLACE)` on single audited names.
pub fn move_out(
    staging: &mut Staging,
    audit: &Audit,
    job: &MoveOut<'_>,
    cb: &mut dyn Callbacks,
) -> Result<Placed, Error> {
    for n in audit.top_level() {
        if !single_component(&n) {
            return Err(fail(
                "The extracted files couldn't be checked, so nothing was kept.",
                format!("an audited top-level name is not one component: {n:?}"),
            ));
        }
    }
    let lone = audit.tree.lone_top.map(|id| &audit.tree.nodes[id as usize]);
    let (name, here) = match job.mode {
        Mode::ExtractTo { name } => (clean_name(name)?, false),
        Mode::ExtractHere => (job.default_name.to_string(), true),
        Mode::Items { dir, names } => return move_items(staging, dir, names, job, cb),
    };
    let placed = |final_name: &str| Placed {
        path: job.dest_path.join(final_name),
        paths: vec![job.dest_path.join(final_name)],
        left_out: false,
        clash_all: job.clash_all,
        unconfirmed: None,
    };

    match lone {
        // A folder with the folder's own name: it is the result.
        Some(n) if !here && n.kind == Kind::Dir && n.name.disk == name => {
            let got = move_item(staging, &n.name.disk, &name, true)?;
            finish_staging(staging);
            Ok(placed(&got.unwrap_or_default()))
        }
        // Extract here: the one item moves out as it is.
        Some(n) if here => {
            let (item, is_dir) = (n.name.disk.as_str(), n.kind == Kind::Dir);
            match move_item(staging, item, item, false)? {
                Some(got) => {
                    finish_staging(staging);
                    Ok(placed(&got))
                }
                None => resolve_clash(staging, item, is_dir, job, cb),
            }
        }
        // Everything else: staging itself becomes the folder.
        _ => {
            let (got, note) = place_staging(staging, &name, job.umask)?;
            Ok(Placed {
                unconfirmed: note,
                ..placed(&got)
            })
        }
    }
}

/// The user's folder name, as a disk name.
fn clean_name(name: &str) -> Result<String, Error> {
    let pieces: Vec<_> = name.chars().map(name::Piece::Char).collect();
    let (disk, _) = name::disk(&pieces);
    if single_component(&disk) {
        Ok(disk)
    } else {
        Err(Error::Failed("That isn't a name a folder can have.".into()))
    }
}

/// Removes what is left of staging after its content moved out.
fn finish_staging(staging: &mut Staging) {
    if let Err(e) = staging.remove() {
        log::warn!("The staging folder couldn't be removed after the move: {e}");
    }
}

/// Moves the folder `item` from staging to the destination as `want`, or
/// `want (2)`, `(3)`... if that is taken. With `numbered` false, a taken name
/// gives `None` instead.
fn move_item(
    staging: &Staging,
    item: &str,
    want: &str,
    numbered: bool,
) -> Result<Option<String>, Error> {
    for n in 1..=MAX_TRIES {
        let cand = if n == 1 {
            want.to_string()
        } else {
            numbered_name(want, n, true)
        };
        match sys::rename_noreplace(
            staging.fd(),
            item.as_bytes(),
            staging.dest(),
            cand.as_bytes(),
        ) {
            Ok(()) => return Ok(Some(cand)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if !numbered {
                    return Ok(None);
                }
            }
            Err(e) => return Err(move_failed(&e)),
        }
    }
    Err(Error::Failed(
        "Too many items with this name are already in the folder.".into(),
    ))
}

/// Renames staging itself to `name` (numbered when taken) and then opens it up
/// for its owner's umask, by descriptor: it was made 0700 so nobody else saw
/// it half done, and stays exactly 0700 until it is in place (so a crash
/// leaves a folder the next start's record proof still accepts).
/// The destination's setgid bit is kept. The folder is checked by identity
/// (device, inode, type) under its old name before the rename and under the
/// new one after. A mismatch before the rename places nothing and empties
/// staging by descriptor; one after it deletes nothing (`unconfirmed`). What this can't close: a process allowed to write the
/// destination can still swap a name between the check and the rename.
fn place_staging(
    staging: &mut Staging,
    name: &str,
    umask: u32,
) -> Result<(String, Option<String>), Error> {
    let ours = sys::fstat(staging.fd()).map_err(|e| move_failed(&e))?;
    if !super::staging::is_our_dir(&ours) {
        return Err(fail(
            "The extracted files couldn't be moved into place safely, so nothing was kept.",
            "the staging descriptor isn't a folder of ours".to_string(),
        ));
    }
    let dest = sys::fstat(staging.dest()).map_err(|e| move_failed(&e))?;
    let mode = ((0o777 & !umask) | 0o700) | (dest.st_mode & libc::S_ISGID);
    for n in 1..=MAX_TRIES {
        let cand = if n == 1 {
            name.to_string()
        } else {
            numbered_name(name, n, true)
        };
        match staging.name_is_ours() {
            Ok(true) => {}
            Ok(false) => {
                // Gone, or another folder: only the first has a plain cause.
                let gone = matches!(
                    sys::lstatat(staging.dest(), staging.name().as_bytes()),
                    Err(ref e) if e.kind() == io::ErrorKind::NotFound
                );
                return Err(swapped(staging, "before the move", None, gone));
            }
            Err(e) => return Err(move_failed(&e)),
        }
        match sys::rename_noreplace(
            staging.dest(),
            staging.name().as_bytes(),
            staging.dest(),
            cand.as_bytes(),
        ) {
            Ok(()) => {
                match sys::lstatat(staging.dest(), cand.as_bytes()) {
                    Ok(now) if sys::same_file(&now, &ours) => {}
                    // The files are in place by the rename; only the proof is
                    // missing. The result names where, with the caveat.
                    other => {
                        let note = unconfirmed(staging, &cand, other.err());
                        // Still ours by descriptor: not left at 0700 either.
                        if let Err(e) = sys::fchmod_soft(staging.fd(), mode) {
                            log::warn!("The extracted folder couldn't be given its mode: {e}");
                        }
                        return Ok((cand, Some(note)));
                    }
                }
                staging.forget();
                // In place: now it takes the user's mode, by descriptor. A
                // file system that keeps no modes is fine; any other failure
                // leaves the folder placed but private, which is only strict.
                if let Err(e) = sys::fchmod_soft(staging.fd(), mode) {
                    log::warn!("The extracted folder couldn't be given its mode: {e}");
                }
                return Ok((cand, None));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(move_failed(&e)),
        }
    }
    Err(Error::Failed(
        "Too many items with this name are already in the folder.".into(),
    ))
}

/// The rename went through but the name doesn't provably lead to our folder
/// (a different one is there, or a file system with unstable inode numbers
/// answered differently). Nothing is deleted: what we can't prove is ours stays,
/// and the user is told both places (the sentence returned, for the result's
/// `unconfirmed`). The job's record goes, so no later start looks at either.
fn unconfirmed(staging: &mut Staging, placed: &str, why: Option<io::Error>) -> String {
    let hidden = staging.name().to_string();
    staging.forget();
    let (placed_text, hidden_text) = (name::display_text(placed), name::display_text(&hidden));
    let words = format!(
        "The extracted files were moved to “{placed_text}”, but that couldn't be confirmed, so nothing was deleted. They should be in “{placed_text}”; if not, look for the hidden folder “{hidden_text}”, both in the destination folder."
    );
    log::warn!(
        "{words} (after the move, {placed:?} wasn't proven to be the staging folder {hidden:?}: {})",
        why.map_or_else(
            || "a different file is there".to_string(),
            |e| e.to_string()
        )
    );
    words
}

/// The staging folder's name led somewhere else: refuse, and empty what is
/// ours by descriptor (the folder itself then goes when `staging` drops).
/// `placed` is the name the move gave it when the swap showed up after the
/// move: something else is at that name then, and it is left alone.
fn swapped(staging: &Staging, when: &str, placed: Option<&str>, gone: bool) -> Error {
    if let Err(e) = staging.clear() {
        log::warn!("The staging folder couldn't be emptied: {e}");
    }
    let shown = match placed {
        None if gone => "The extracted files couldn't be moved into place because the folder they were in isn't there any more, so nothing was kept."
            .to_string(),
        None => "The extracted files couldn't be moved into place safely, so nothing was kept."
            .to_string(),
        Some(p) => format!(
            "The extracted files couldn't be moved into place safely and were removed. Something else is now at “{}” in the folder; it was not touched.",
            name::display_text(p)
        ),
    };
    fail(shown, format!("the staging folder was replaced {when}"))
}

/// Extract here met an item of the same name: ask, then do as told.
fn resolve_clash(
    staging: &mut Staging,
    item: &str,
    is_dir: bool,
    job: &MoveOut<'_>,
    cb: &mut dyn Callbacks,
) -> Result<Placed, Error> {
    let from = staging
        .fd_owned()
        .try_clone()
        .map_err(|e| move_failed(&e))?;
    let (outcome, clash_all) = match clash_item(&from, staging, item, is_dir, job, cb) {
        Ok(r) => r,
        Err(Error::Cancelled) => {
            finish_staging(staging);
            return Err(Error::Cancelled);
        }
        Err(e) => return Err(e),
    };
    finish_staging(staging);
    Ok(match outcome {
        Clashed::At(got) => Placed {
            path: job.dest_path.join(&got),
            paths: vec![job.dest_path.join(&got)],
            left_out: false,
            clash_all,
            unconfirmed: None,
        },
        Clashed::Skipped => Placed {
            path: job.dest_path.to_path_buf(),
            paths: Vec::new(),
            left_out: true,
            clash_all,
            unconfirmed: None,
        },
    })
}

/// What came of one item whose name was taken.
enum Clashed {
    /// Placed in the destination under this name.
    At(String),
    /// The user chose Skip.
    Skipped,
}

/// Asks what to do about `item` (in the folder `from`, which is staging or a
/// folder below it) when its name is taken in the destination, and does it.
/// The second value is the standing answer ("do this for all conflicts").
fn clash_item(
    from: &OwnedFd,
    staging: &mut Staging,
    item: &str,
    is_dir: bool,
    job: &MoveOut<'_>,
    cb: &mut dyn Callbacks,
) -> Result<(Clashed, Option<Clash>), Error> {
    let mut clash_all = job.clash_all;
    let action = match clash_all {
        Some(a) => a,
        None => {
            let answer = cb.clash(&name::display_text(item));
            if job.cancel.is_cancelled() {
                // The answer is a guess made because the question was cut
                // short: nothing is placed, and staging goes.
                return Err(Error::Cancelled);
            }
            if answer.all {
                clash_all = Some(answer.action);
            }
            answer.action
        }
    };
    let src = sys::bfd(from);
    match action {
        Clash::Skip => Ok((Clashed::Skipped, clash_all)),
        Clash::KeepBoth => {
            for n in 2..=MAX_TRIES {
                let cand = numbered_name(item, n, is_dir);
                match sys::rename_noreplace(src, item.as_bytes(), staging.dest(), cand.as_bytes()) {
                    Ok(()) => return Ok((Clashed::At(cand), clash_all)),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(move_failed(&e)),
                }
            }
            Err(Error::Failed(
                "Too many items with this name are already in the folder.".into(),
            ))
        }
        Clash::Replace => {
            let shown = name::display_text(item);
            let Some(trash) = job.trash else {
                return Err(not_replaced(&shown, "there is no Trash to use", None));
            };
            let trashed = trash
                .trash_item(staging.dest(), job.dest_path, item)
                .map_err(|e| not_replaced(&shown, &e.to_string(), cause(&e)))?;
            match sys::rename_noreplace(src, item.as_bytes(), staging.dest(), item.as_bytes()) {
                Ok(()) => Ok((Clashed::At(item.to_string()), clash_all)),
                Err(e) => {
                    // The old item is in the Trash and the new one didn't
                    // get its place: put the old one back.
                    match trashed.undo(staging.dest(), item.as_bytes()) {
                        Ok(()) => Err(move_failed(&e)),
                        Err(undo) => {
                            // Both are kept, and the user is told where.
                            let old = sys::log_path(&trashed.files_path);
                            let new = sys::log_path(&job.dest_path.join(staging.name()).join(item));
                            staging.forget();
                            Err(fail(
                                format!(
                                    "“{shown}” couldn't be replaced. The old one is in the Trash at {old} and the new one is at {new}."
                                ),
                                format!("replace failed: {e}; undo failed: {undo}"),
                            ))
                        }
                    }
                }
            }
        }
    }
}

/// `Mode::Items`: the selected items, which sit in the folder `dir` below
/// staging (disk names from the archive's top), move into the destination
/// one by one, each asking on a clash. What the audit took out is not there
/// to move: the audit reported it.
fn move_items(
    staging: &mut Staging,
    dir: &[String],
    names: &[String],
    job: &MoveOut<'_>,
    cb: &mut dyn Callbacks,
) -> Result<Placed, Error> {
    let bad = |what: &str| {
        fail(
            "The extracted files couldn't be checked, so nothing was kept.",
            format!("a selected item's name is not one component: {what}"),
        )
    };
    if names.is_empty() {
        return Err(Error::Failed("No items were selected.".into()));
    }
    let mut from = staging
        .fd_owned()
        .try_clone()
        .map_err(|e| move_failed(&e))?;
    for c in dir {
        if !single_component(c) {
            return Err(bad(c));
        }
        from = match sys::open_subdir(sys::bfd(&from), c.as_bytes()) {
            Ok(fd) => fd,
            // The audit removed the folder (or the worker never made it):
            // nothing of the selection is there.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                finish_staging(staging);
                return Ok(Placed {
                    path: job.dest_path.to_path_buf(),
                    paths: Vec::new(),
                    left_out: true,
                    clash_all: job.clash_all,
                    unconfirmed: None,
                });
            }
            Err(e) => return Err(move_failed(&e)),
        };
    }
    let mut clash_all = job.clash_all;
    let mut paths = Vec::new();
    let mut skipped_any = false;
    for item in names {
        if !single_component(item) {
            return Err(bad(item));
        }
        let st = match sys::lstatat(sys::bfd(&from), item.as_bytes()) {
            Ok(st) => st,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(move_failed(&e)),
        };
        let is_dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
        match sys::rename_noreplace(
            sys::bfd(&from),
            item.as_bytes(),
            staging.dest(),
            item.as_bytes(),
        ) {
            Ok(()) => paths.push(job.dest_path.join(item)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let one = MoveOut { clash_all, ..*job };
                let (outcome, all) = match clash_item(&from, staging, item, is_dir, &one, cb) {
                    Ok(r) => r,
                    Err(Error::Cancelled) => {
                        finish_staging(staging);
                        return Err(Error::Cancelled);
                    }
                    Err(e) => return Err(e),
                };
                clash_all = all;
                match outcome {
                    Clashed::At(got) => paths.push(job.dest_path.join(got)),
                    Clashed::Skipped => skipped_any = true,
                }
            }
            Err(e) => return Err(move_failed(&e)),
        }
    }
    finish_staging(staging);
    Ok(Placed {
        path: paths
            .first()
            .cloned()
            .unwrap_or_else(|| job.dest_path.to_path_buf()),
        left_out: paths.is_empty() && skipped_any,
        paths,
        clash_all,
        unconfirmed: None,
    })
}

fn not_replaced(shown: &str, why: &str, cause: Option<&str>) -> Error {
    let because = cause.map_or(String::new(), |c| format!(" because {c}"));
    fail(
        format!("“{shown}” couldn't be moved to the Trash{because}, so it was not replaced."),
        format!("trash failed: {why}"),
    )
}

fn move_failed(e: &io::Error) -> Error {
    io_words("move the extracted files into place", e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_names_lose_archive_extensions() {
        let d = |s: &str| default_name(s.as_bytes());
        assert_eq!(d("photos.zip"), "photos");
        assert_eq!(d("photos.tar.gz"), "photos");
        assert_eq!(d("photos.TAR.GZ"), "photos");
        assert_eq!(d("photos.tgz"), "photos");
        assert_eq!(d("photos.tar.zst"), "photos");
        assert_eq!(d("notes.txt.gz"), "notes.txt");
        assert_eq!(d("a.b.c.7z"), "a.b.c");
        assert_eq!(d("pkg.x86_64.rpm"), "pkg.x86_64");
        assert_eq!(d("noextension"), "noextension");
        assert_eq!(d("photos.tar"), "photos");
        // Only the last archive extension goes.
        assert_eq!(d("a.zip.zip"), "a.zip");
        // Never empty, never hidden.
        assert_eq!(d(".zip"), "Archive");
        assert_eq!(d(".hidden.zip"), "Archive");
        assert_eq!(d(".tar.gz"), "Archive");
        assert_eq!(d(""), "Archive");
        // Disk form: no slash, no control character.
        assert_eq!(d("a\u{1}b.zip"), "a_b");
        assert_eq!(default_name(b"x\xffy.zip"), "x_y");
    }

    #[test]
    fn numbered_names_fit_and_keep_extensions() {
        assert_eq!(numbered_name("docs", 2, true), "docs (2)");
        assert_eq!(numbered_name("v1.2", 3, true), "v1.2 (3)");
        assert_eq!(numbered_name("a.txt", 2, false), "a (2).txt");
        assert_eq!(numbered_name(".bashrc", 2, false), ".bashrc (2)");
        let long = "x".repeat(255);
        let n = numbered_name(&long, 12, true);
        assert_eq!(n.len(), 255);
        assert!(n.ends_with(" (12)"));
        let n = numbered_name(&"é".repeat(127), 10, true);
        assert!(n.len() <= 255 && n.ends_with(" (10)"));
    }

    #[test]
    fn only_one_component_names_pass() {
        assert!(single_component("a b"));
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            assert!(!single_component(bad), "{bad:?}");
        }
        assert!(!single_component(&"x".repeat(256)));
    }
}
