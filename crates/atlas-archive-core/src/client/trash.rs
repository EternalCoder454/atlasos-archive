//! The XDG Trash (freedesktop.org Trash specification), for Extract here's
//! Replace: the old item is moved to the Trash, never deleted.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use super::sys::{self, bfd};
use crate::name::{self, MAX_COMPONENT_BYTES};

/// The longest name in `files/`: its `.trashinfo` must fit too.
const MAX_TRASHED_NAME: usize = MAX_COMPONENT_BYTES - ".trashinfo".len();
/// How many numbered names are tried before giving up.
const MAX_TRIES: u32 = 1000;

/// Where trashed items go. Built for the real Trash by `from_environment`,
/// or for any folder (`at`) in tests.
#[derive(Clone, Debug)]
pub struct Trash {
    /// The home Trash, `$XDG_DATA_HOME/Trash`.
    home: PathBuf,
    uid: u32,
}

impl Trash {
    /// `$XDG_DATA_HOME/Trash`, or `~/.local/share/Trash`. `None` when the
    /// environment names no usable home.
    pub fn from_environment() -> Option<Trash> {
        let absolute = |v: std::ffi::OsString| {
            let p = PathBuf::from(v);
            p.is_absolute().then_some(p)
        };
        let data = std::env::var_os("XDG_DATA_HOME")
            .and_then(absolute)
            .or_else(|| {
                std::env::var_os("HOME")
                    .and_then(absolute)
                    .map(|h| h.join(".local/share"))
            })?;
        Some(Trash::at(data.join("Trash")))
    }

    /// A Trash whose home folder is `home` (made when needed).
    pub fn at(home: impl Into<PathBuf>) -> Trash {
        // SAFETY: getuid has no failure.
        let uid = unsafe { libc::getuid() };
        Trash {
            home: home.into(),
            uid,
        }
    }

    /// Moves `name` in the folder `dir` (at `dir_path`, for the record) to the
    /// Trash. Returns where it is now. Nothing is deleted on failure.
    pub fn trash(&self, dir: BorrowedFd<'_>, dir_path: &Path, name: &str) -> io::Result<PathBuf> {
        self.trash_item(dir, dir_path, name).map(|t| t.files_path)
    }

    /// Like `trash`, and keeps what is needed to undo it.
    pub(super) fn trash_item(
        &self,
        dir: BorrowedFd<'_>,
        dir_path: &Path,
        name: &str,
    ) -> io::Result<Trashed> {
        let item = sys::lstatat(dir, name.as_bytes())?;
        // Where the folder is now, from the descriptor: the string may lead
        // elsewhere by the time it is used. The string is the fallback when
        // /proc can't say.
        let real = sys::fd_path(dir).unwrap_or_else(|| {
            std::path::absolute(dir_path).unwrap_or_else(|_| dir_path.to_path_buf())
        });
        let abs = real.join(name);
        let mut errors = Vec::new();

        match self.home_trash(item.st_dev) {
            Ok(Some((t, fd))) => match self.put(dir, name, &t, &fd, &abs, None) {
                Ok(done) => return Ok(done),
                // The home Trash is on a bind mount of this drive (the same
                // device number, a different mount): the drive's own Trash
                // is next.
                Err(e) if e.raw_os_error() == Some(libc::EXDEV) => errors.push(e),
                Err(e) => return Err(e),
            },
            Ok(None) => {}
            Err(e) => errors.push(e),
        }
        match self.top_trash(&real, item.st_dev) {
            Ok((t, top, fd)) => return self.put(dir, name, &t, &fd, &abs, Some(&top)),
            Err(e) => errors.push(e),
        }
        let why = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        log::warn!("No Trash works for {}: {why}", sys::log_path(&abs));
        // The last one's own error, so its cause (a full drive) can be told.
        Err(errors
            .pop()
            .unwrap_or_else(|| io::Error::other("no Trash works")))
    }

    /// The home Trash, when it exists (or can be made) on the device `dev`.
    /// It may be a link to a folder of the user's (a common setup).
    fn home_trash(&self, dev: libc::dev_t) -> io::Result<Option<(PathBuf, OwnedFd)>> {
        let fd = make_trash_dir(&self.home, true, true)?;
        let st = sys::fstat(bfd(&fd))?;
        Ok((st.st_dev == dev).then(|| (self.home.clone(), fd)))
    }

    /// `$topdir/.Trash/$uid` when `$topdir/.Trash` is a sticky folder that
    /// isn't a link, else `$topdir/.Trash-$uid`, with the mount's top folder.
    /// `real` is the item's folder as the kernel names it.
    fn top_trash(&self, real: &Path, dev: libc::dev_t) -> io::Result<(PathBuf, PathBuf, OwnedFd)> {
        use std::os::unix::fs::MetadataExt;
        let mut top = real;
        while let Some(parent) = top.parent() {
            if std::fs::metadata(parent)?.dev() != dev {
                break;
            }
            top = parent;
        }
        let shared = top.join(".Trash");
        if let Ok(m) = std::fs::symlink_metadata(&shared)
            && m.is_dir()
            && m.mode() & libc::S_ISVTX != 0
        {
            let mine = shared.join(self.uid.to_string());
            match make_trash_dir(&mine, false, false) {
                Ok(fd) => return Ok((mine, top.to_path_buf(), fd)),
                Err(e) => log::debug!("{} isn't usable: {e}", sys::log_path(&mine)),
            }
        }
        let own = top.join(format!(".Trash-{}", self.uid));
        let fd = make_trash_dir(&own, false, false)?;
        Ok((own, top.to_path_buf(), fd))
    }

    /// Writes the `.trashinfo` (O_EXCL, so a name is never shared), then
    /// moves the item in. Removes the info again if the move fails. A topdir
    /// Trash records the path relative to the mount's top, as the spec says.
    fn put(
        &self,
        dir: BorrowedFd<'_>,
        name: &str,
        trash: &Path,
        trash_fd: &OwnedFd,
        abs: &Path,
        top: Option<&Path>,
    ) -> io::Result<Trashed> {
        let info_dir = open_trash_sub(trash_fd, "info")?;
        let files_dir = open_trash_sub(trash_fd, "files")?;
        let recorded = match top {
            Some(t) => abs.strip_prefix(t).unwrap_or(abs),
            None => abs,
        };
        let text = format!(
            "[Trash Info]\nPath={}\nDeletionDate={}\n",
            sys::pct_encode(recorded.as_os_str().as_bytes()),
            local_date()?
        );
        let base = trimmed(name);
        for n in 1..=MAX_TRIES {
            let cand = if n == 1 {
                base.clone()
            } else {
                name::numbered(&base, n)
            };
            let cand = trimmed(&cand);
            let info_name = format!("{cand}.trashinfo");
            match create_info(&info_dir, &info_name, &text) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
            match sys::rename_noreplace(dir, name.as_bytes(), bfd(&files_dir), cand.as_bytes()) {
                Ok(()) => {
                    return Ok(Trashed {
                        files_path: trash.join("files").join(&cand),
                        files_dir,
                        info_dir,
                        cand,
                        info_name,
                    });
                }
                Err(e) => {
                    let _ = sys::unlinkat(bfd(&info_dir), info_name.as_bytes(), 0);
                    // A leftover in files/ without an info: try the next name.
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        return Err(e);
                    }
                }
            }
        }
        Err(io::Error::other(
            "too many items with this name are in the Trash",
        ))
    }
}

/// An item that was moved to the Trash, and the way back.
pub(super) struct Trashed {
    /// Where the item is now.
    pub files_path: PathBuf,
    files_dir: OwnedFd,
    info_dir: OwnedFd,
    cand: String,
    info_name: String,
}

impl Trashed {
    /// Moves the item back as `name` in `dir` (never over anything there) and
    /// removes its `.trashinfo`.
    pub fn undo(&self, dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<()> {
        sys::rename_noreplace(bfd(&self.files_dir), self.cand.as_bytes(), dir, name)?;
        if let Err(e) = sys::unlinkat(bfd(&self.info_dir), self.info_name.as_bytes(), 0) {
            log::warn!("The Trash's info for a restored item couldn't be removed: {e}");
        }
        Ok(())
    }
}

/// `name` cut to what `files/` takes, on a character boundary.
fn trimmed(name: &str) -> String {
    let mut cut = name.len().min(MAX_TRASHED_NAME);
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    name[..cut].to_string()
}

fn create_info(info_dir: &OwnedFd, file: &str, text: &str) -> io::Result<()> {
    let c = sys::cstr(file.as_bytes())?;
    // SAFETY: a valid descriptor and C string; O_EXCL and O_NOFOLLOW make the
    // create atomic and link-proof, and the result is a new descriptor.
    let fd = unsafe {
        libc::openat(
            info_dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor we own.
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    if let Err(e) = f.write_all(text.as_bytes()) {
        // No half-written info is left to be mistaken for a record.
        drop(f);
        let _ = sys::unlinkat(bfd(info_dir), file.as_bytes(), 0);
        return Err(e);
    }
    Ok(())
}

/// Makes `path` (and its `files` and `info`) a Trash folder owned by us and
/// returns it open. `parents`: make the missing parents too. `follow_final`:
/// the home Trash may be a link to a folder of ours; any other must be a real
/// folder. `files` and `info` are never followed.
fn make_trash_dir(path: &Path, parents: bool, follow_final: bool) -> io::Result<OwnedFd> {
    let mut b = std::fs::DirBuilder::new();
    b.mode(0o700).recursive(parents);
    match b.create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let fd = if follow_final {
        sys::open_dir(path)?
    } else {
        sys::open_dir_nofollow(path)?
    };
    let st = sys::fstat(bfd(&fd))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR || st.st_uid != sys::getuid() {
        return Err(io::Error::other(format!(
            "{} isn't a folder of yours",
            sys::log_path(path)
        )));
    }
    for sub in ["files", "info"] {
        match sys::mkdirat(bfd(&fd), sub.as_bytes(), 0o700) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(fd)
}

/// Opens `trash/<sub>` without following a link; it must be ours.
fn open_trash_sub(trash: &OwnedFd, sub: &str) -> io::Result<OwnedFd> {
    let fd = sys::open_subdir(bfd(trash), sub.as_bytes())?;
    let st = sys::fstat(bfd(&fd))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR || st.st_uid != sys::getuid() {
        return Err(io::Error::other(format!(
            "the Trash's {sub} folder isn't yours"
        )));
    }
    Ok(fd)
}

/// Now, in local time, as the spec writes it: `YYYY-MM-DDThh:mm:ss`.
fn local_date() -> io::Result<String> {
    // SAFETY: time(NULL) has no failure; `tm` is plain data, filled by
    // localtime_r, which is reentrant.
    let tm = unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return Err(io::Error::last_os_error());
        }
        tm
    };
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_has_the_spec_shape() {
        let d = local_date().unwrap();
        let b = d.as_bytes();
        assert_eq!(b.len(), 19, "{d}");
        assert!(b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':');
    }

    #[test]
    fn long_names_are_cut_for_the_info_file() {
        let n = trimmed(&"é".repeat(200));
        assert!(n.len() <= MAX_TRASHED_NAME);
        assert_eq!(trimmed("a.txt"), "a.txt");
    }
}
