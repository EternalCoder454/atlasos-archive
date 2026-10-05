//! Moving the audited result out of staging (docs/DESIGN.md, "Extraction
//! rules"): where it goes, what it is called, what happens on a clash.

use std::io;
use std::path::{Path, PathBuf};

use super::staging::Staging;
use super::sys;
use super::trash::Trash;
use super::{Callbacks, Clash, Error, Mode, fail, io_words};
use crate::audit::Audit;
use crate::name::{self, MAX_COMPONENT_BYTES};
use crate::proto::Kind;

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
    /// Nothing was moved: the user chose Skip.
    pub left_out: bool,
    /// The answer given with "do this for all conflicts".
    pub clash_all: Option<Clash>,
}

/// What `move_out` needs besides the audit.
pub struct MoveOut<'a> {
    pub dest_path: &'a Path,
    pub mode: &'a Mode,
    /// The folder name when the mode gives none.
    pub default_name: &'a str,
    pub umask: u32,
    pub trash: Option<&'a Trash>,
    /// A standing answer for clashes from earlier archives.
    pub clash_all: Option<Clash>,
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
    };
    let placed = |final_name: &str| Placed {
        path: job.dest_path.join(final_name),
        left_out: false,
        clash_all: job.clash_all,
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
            let got = place_staging(staging, &name, job.umask)?;
            Ok(placed(&got))
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

/// Renames staging itself to `name` (numbered when taken) and opens it up
/// for its owner's umask: it was made 0700 so nobody else saw it half done.
fn place_staging(staging: &mut Staging, name: &str, umask: u32) -> Result<String, Error> {
    sys::fchmod(staging.fd(), (0o777 & !umask) | 0o700).map_err(|e| move_failed(&e))?;
    for n in 1..=MAX_TRIES {
        let cand = if n == 1 {
            name.to_string()
        } else {
            numbered_name(name, n, true)
        };
        match sys::rename_noreplace(
            staging.dest(),
            staging.name().as_bytes(),
            staging.dest(),
            cand.as_bytes(),
        ) {
            Ok(()) => {
                staging.forget();
                return Ok(cand);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(move_failed(&e)),
        }
    }
    Err(Error::Failed(
        "Too many items with this name are already in the folder.".into(),
    ))
}

/// Extract here met an item of the same name: ask, then do as told.
fn resolve_clash(
    staging: &mut Staging,
    item: &str,
    is_dir: bool,
    job: &MoveOut<'_>,
    cb: &mut dyn Callbacks,
) -> Result<Placed, Error> {
    let mut clash_all = job.clash_all;
    let action = match clash_all {
        Some(a) => a,
        None => {
            let answer = cb.clash(&name::display_text(item));
            if answer.all {
                clash_all = Some(answer.action);
            }
            answer.action
        }
    };
    let at = |got: &str| Placed {
        path: job.dest_path.join(got),
        left_out: false,
        clash_all,
    };
    match action {
        Clash::Skip => {
            finish_staging(staging);
            Ok(Placed {
                path: job.dest_path.to_path_buf(),
                left_out: true,
                clash_all,
            })
        }
        Clash::KeepBoth => {
            for n in 2..=MAX_TRIES {
                let cand = numbered_name(item, n, is_dir);
                match sys::rename_noreplace(
                    staging.fd(),
                    item.as_bytes(),
                    staging.dest(),
                    cand.as_bytes(),
                ) {
                    Ok(()) => {
                        finish_staging(staging);
                        return Ok(at(&cand));
                    }
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
                return Err(not_replaced(&shown, "there is no Trash to use"));
            };
            trash
                .trash(staging.dest(), job.dest_path, item)
                .map_err(|e| not_replaced(&shown, &e.to_string()))?;
            match sys::rename_noreplace(
                staging.fd(),
                item.as_bytes(),
                staging.dest(),
                item.as_bytes(),
            ) {
                Ok(()) => {
                    finish_staging(staging);
                    Ok(at(item))
                }
                Err(e) => Err(move_failed(&e)),
            }
        }
    }
}

fn not_replaced(shown: &str, why: &str) -> Error {
    fail(
        format!("“{shown}” couldn't be moved to the Trash, so it was not replaced."),
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
