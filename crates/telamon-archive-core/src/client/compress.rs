//! Making an archive through the sandboxed worker (docs/DESIGN.md, "The API
//! other apps call"): the sources are opened here and passed as folder
//! descriptors, the worker writes the archive into the staging folder, and
//! the finished file is moved out with `renameat2(RENAME_NOREPLACE)`, so a
//! cancel or a failure leaves nothing in the destination.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::staging::Staging;
use super::{
    Callbacks, Cancel, Clash, Collected, Error, Op, SkippedEntry, Worker, cause, extract, fail,
    io_words, sys,
};
use crate::compress::{CompressFormat, Level};
use crate::name;
use crate::proto::{MAX_FRAME, MAX_ROOTS, MAX_SOURCES, Request, Source};

/// What happens when the file name is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClashPolicy {
    /// The name was not chosen by the user: take `name (2)`, `name (3)`...
    Number,
    /// The user named the file: ask (Replace, Skip, Keep Both).
    Ask,
}

/// One compression.
#[derive(Clone, Debug)]
pub struct CompressRequest<'a> {
    /// Absolute paths of the items. Each goes in at the top of the archive
    /// under its own name; folders bring what is inside them. A link is stored
    /// as a link.
    pub sources: &'a [PathBuf],
    pub dest_dir: &'a Path,
    /// The archive's file name in `dest_dir`.
    pub file_name: &'a str,
    pub format: CompressFormat,
    pub level: Level,
    pub clash: ClashPolicy,
    /// A standing answer from "do this for all conflicts" on an earlier job.
    pub clash_all: Option<Clash>,
}

/// What a compression produced.
#[derive(Clone, Debug)]
pub struct Compressed {
    /// The archive, or the destination folder when the user chose Skip.
    pub path: PathBuf,
    /// The user chose Skip: nothing was made.
    pub left_out: bool,
    pub clash_all: Option<Clash>,
    /// Items that were not put in, with the reason.
    pub skipped: Vec<SkippedEntry>,
    pub skipped_more: u64,
}

/// The temporary name of the archive inside staging.
const OUT_NAME: &str = "archive.part";
/// How many numbered names are tried before giving up.
const MAX_TRIES: u32 = 1000;

fn is_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= name::MAX_COMPONENT_BYTES
        && name != "."
        && name != ".."
        && !name.contains(['/', '\0'])
}

/// `photos.zip` with a number: `photos (2).zip`.
fn numbered(file_name: &str, ext: &str, n: u32) -> String {
    let stem = file_name
        .strip_suffix(ext)
        .filter(|s| !s.is_empty())
        .unwrap_or(file_name);
    let ext = if stem.len() == file_name.len() {
        ""
    } else {
        ext
    };
    let suffix = format!(" ({n})");
    let mut cut = stem
        .len()
        .min(name::MAX_COMPONENT_BYTES.saturating_sub(suffix.len() + ext.len()));
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{suffix}{ext}", &stem[..cut])
}

impl Worker {
    /// Makes an archive of `req.sources` in `req.dest_dir`. Same thread rules
    /// as `list`. On any failure or cancel the destination is as it was.
    pub fn compress(
        &self,
        req: &CompressRequest<'_>,
        cb: &mut dyn Callbacks,
        cancel: &Cancel,
    ) -> Result<Compressed, Error> {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if !is_component(req.file_name) {
            return Err(Error::Failed("That isn't a name a file can have.".into()));
        }
        if req.sources.is_empty() {
            return Err(Error::Failed("There is nothing to compress.".into()));
        }
        if req.sources.len() > MAX_SOURCES {
            return Err(Error::Failed(
                "Too many items are selected to compress at once. Put them in a folder and compress the folder."
                    .into(),
            ));
        }
        let (dest, dest_abs) = extract::open_destination(req.dest_dir, extract::Purpose::Compress)?;

        // The folders the sources are in, one descriptor each, and the names.
        let mut roots: Vec<(PathBuf, OwnedFd)> = Vec::new();
        let mut sources = Vec::with_capacity(req.sources.len());
        let mut seen = std::collections::HashSet::new();
        for path in req.sources {
            let (Some(parent), Some(leaf)) = (path.parent(), path.file_name()) else {
                return Err(Error::Failed(
                    "One of the items has no name Telamon Archive can use.".into(),
                ));
            };
            let leaf_bytes = leaf.as_bytes().to_vec();
            if !path.is_absolute()
                || leaf_bytes.len() > name::MAX_COMPONENT_BYTES
                || !seen.insert(leaf_bytes.clone())
            {
                let shown = name::display_text(&leaf.to_string_lossy());
                return Err(Error::Failed(if path.is_absolute() {
                    format!(
                        "Two of the items are named “{shown}”, so they can't go in one archive."
                    )
                } else {
                    "The items must be given with their full paths.".into()
                }));
            }
            let at = match roots.iter().position(|(p, _)| p == parent) {
                Some(i) => i,
                None => {
                    if roots.len() >= MAX_ROOTS {
                        return Err(Error::Failed(
                            "These items are in too many different folders. Compress them from one folder."
                                .into(),
                        ));
                    }
                    let fd = sys::open_dir(parent).map_err(|e| {
                        let words = match e.kind() {
                            io::ErrorKind::NotFound => {
                                "A folder with items to compress isn't there."
                            }
                            io::ErrorKind::PermissionDenied => {
                                "A folder with items to compress can't be opened."
                            }
                            _ => "A folder with items to compress couldn't be opened.",
                        };
                        fail(words, format!("{}: {e}", sys::log_path(parent)))
                    })?;
                    roots.push((parent.to_path_buf(), fd));
                    roots.len() - 1
                }
            };
            // The item must be there now; the worker looks again as it reads.
            match sys::lstatat(sys::bfd(&roots[at].1), &leaf_bytes) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let shown = name::display_text(&leaf.to_string_lossy());
                    return Err(Error::Failed(format!("“{shown}” isn't there.")));
                }
                Err(e) => return Err(io_words("look at an item to compress", &e)),
            }
            sources.push(Source {
                root: at as u32,
                name: leaf_bytes,
            });
        }
        let request = Request::Create {
            format: req.format.label().to_string(),
            level: req.level.tag(),
            out_name: OUT_NAME.to_string(),
            sources,
        };
        if request.encode().len() > MAX_FRAME {
            return Err(Error::Failed(
                "Too many items are selected to compress at once. Put them in a folder and compress the folder."
                    .into(),
            ));
        }

        let mut staging = Staging::create(
            dest,
            &dest_abs,
            req.file_name.as_bytes(),
            self.state_dir.as_deref(),
        )
        .map_err(|e| io_words("make a folder to make the archive in", &e))?;
        let mut col = Collected::default();
        let root_fds: Vec<OwnedFd> = roots.into_iter().map(|(_, fd)| fd).collect();
        if let Err(e) = self.run_job(
            Op::Create,
            Path::new(""),
            Some(&staging),
            &root_fds,
            &request,
            cancel,
            cb,
            &mut col,
        ) {
            if col.hung {
                staging.leave_for_cleanup();
            }
            return Err(e);
        }
        // The worker is dead and reaped: staging can't change under us.
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if col.written.len() != 1 || col.written[0] != OUT_NAME.as_bytes() {
            log::warn!("The worker named {} files it wrote.", col.written.len());
        }
        let umask = sys::read_umask();
        check_output(&staging, umask)?;

        let placed = move_archive(
            &mut staging,
            req,
            cb,
            cancel,
            &dest_abs,
            self.trash.as_ref(),
        )?;
        if let Err(e) = staging.remove() {
            log::warn!("The staging folder couldn't be removed after the move: {e}");
        }
        Ok(Compressed {
            path: placed.0,
            left_out: placed.1,
            clash_all: placed.2,
            skipped: col.skipped,
            skipped_more: col.skipped_more,
        })
    }
}

/// The worker's output must be one plain file. It gets the user's mode.
fn check_output(staging: &Staging, umask: u32) -> Result<(), Error> {
    let bad = |detail: String| {
        fail(
            "The archive couldn't be checked, so nothing was kept.",
            detail,
        )
    };
    let st = sys::lstatat(staging.fd(), OUT_NAME.as_bytes())
        .map_err(|e| bad(format!("the archive isn't in staging: {e}")))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_nlink != 1 {
        return Err(bad("the archive isn't a plain file".into()));
    }
    let fd = sys::open_path_nofollow(staging.fd(), OUT_NAME.as_bytes())
        .map_err(|e| bad(format!("the archive can't be opened: {e}")))?;
    let now = sys::fstat(fd.as_fd()).map_err(|e| bad(e.to_string()))?;
    if !sys::same_file(&st, &now) {
        return Err(bad("the archive changed".into()));
    }
    // Written 0600: it takes the mode other new files get.
    if let Err(e) = sys::fchmod_path(fd.as_fd(), (0o666 & !umask) | 0o600) {
        log::warn!("The archive couldn't be given its mode: {e}");
    }
    Ok(())
}

/// Moves the archive out of staging as its file name, or a numbered one, or
/// what the user answers. `(path, left_out, standing answer)`.
fn move_archive(
    staging: &mut Staging,
    req: &CompressRequest<'_>,
    cb: &mut dyn Callbacks,
    cancel: &Cancel,
    dest_path: &Path,
    trash: Option<&super::Trash>,
) -> Result<(PathBuf, bool, Option<Clash>), Error> {
    let ext = req.format.extension();
    let place = |staging: &Staging, to: &str| {
        sys::rename_noreplace(
            staging.fd(),
            OUT_NAME.as_bytes(),
            staging.dest(),
            to.as_bytes(),
        )
    };
    let moved = |e: &io::Error| io_words("move the archive into place", e);
    match place(staging, req.file_name) {
        Ok(()) => return Ok((dest_path.join(req.file_name), false, req.clash_all)),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(moved(&e)),
    }
    // The name is taken.
    let mut clash_all = req.clash_all;
    let action = match req.clash {
        ClashPolicy::Number => Clash::KeepBoth,
        ClashPolicy::Ask => match clash_all {
            Some(a) => a,
            None => {
                let answer = cb.clash(&name::display_text(req.file_name));
                if cancel.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                if answer.all {
                    clash_all = Some(answer.action);
                }
                answer.action
            }
        },
    };
    match action {
        Clash::Skip => Ok((dest_path.to_path_buf(), true, clash_all)),
        Clash::KeepBoth => {
            for n in 2..=MAX_TRIES {
                let cand = numbered(req.file_name, ext, n);
                match place(staging, &cand) {
                    Ok(()) => return Ok((dest_path.join(cand), false, clash_all)),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(moved(&e)),
                }
            }
            Err(Error::Failed(
                "Too many files with this name are already in the folder.".into(),
            ))
        }
        Clash::Replace => {
            let shown = name::display_text(req.file_name);
            let Some(trash) = trash else {
                return Err(fail(
                    format!("“{shown}” couldn't be moved to the Trash, so it was not replaced."),
                    "there is no Trash to use".to_string(),
                ));
            };
            let trashed = trash
                .trash_item(staging.dest(), dest_path, req.file_name)
                .map_err(|e| {
                    let because = cause(&e).map_or(String::new(), |c| format!(" because {c}"));
                    fail(
                        format!("“{shown}” couldn't be moved to the Trash{because}, so it was not replaced."),
                        format!("trash failed: {e}"),
                    )
                })?;
            match place(staging, req.file_name) {
                Ok(()) => Ok((dest_path.join(req.file_name), false, clash_all)),
                Err(e) => match trashed.undo(staging.dest(), req.file_name.as_bytes()) {
                    Ok(()) => Err(moved(&e)),
                    Err(undo) => {
                        let old = sys::log_path(&trashed.files_path);
                        let new = sys::log_path(&dest_path.join(staging.name()).join(OUT_NAME));
                        staging.forget();
                        Err(fail(
                            format!(
                                "“{shown}” couldn't be replaced. The old one is in the Trash at {old} and the new archive is at {new}."
                            ),
                            format!("replace failed: {e}; undo failed: {undo}"),
                        ))
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbered_names_keep_the_extension() {
        assert_eq!(numbered("photos.zip", ".zip", 2), "photos (2).zip");
        assert_eq!(numbered("a.tar.gz", ".tar.gz", 3), "a (3).tar.gz");
        assert_eq!(numbered("noext", ".zip", 2), "noext (2)");
        assert_eq!(numbered(".zip", ".zip", 2), ".zip (2)");
        let long = format!("{}.7z", "x".repeat(300));
        assert!(numbered(&long, ".7z", 12).len() <= 255);
        assert!(numbered(&long, ".7z", 12).ends_with(" (12).7z"));
    }

    #[test]
    fn component_names() {
        assert!(is_component("a b.zip"));
        for bad in ["", ".", "..", "a/b", "a\0"] {
            assert!(!is_component(bad));
        }
        assert!(!is_component(&"x".repeat(256)));
    }
}
