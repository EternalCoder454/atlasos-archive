//! Checking what a caller sent, before a job exists: every path is absolute
//! and normal (`uri`), exists, is the right kind and can be used. Errors are
//! sentences for the caller (`InvalidArgs`).

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use telamon_archive_core::name;

use crate::{ApiError, uri};

/// Which file a path named when it was checked. A job opens the file later;
/// if it is another file by then (the name was swapped), the job stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

impl FileId {
    pub fn of(meta: &std::fs::Metadata) -> FileId {
        FileId {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

/// The name of a file for a sentence: its last part, made safe to show.
pub fn shown(path: &Path) -> String {
    let leaf = path
        .file_name()
        .map_or_else(|| path.to_string_lossy(), |n| n.to_string_lossy());
    name::display_text(&leaf)
}

fn invalid(words: String) -> ApiError {
    ApiError::InvalidArgs(words)
}

fn access(path: &Path, mode: libc::c_int) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a valid C string.
    unsafe { libc::access(c.as_ptr(), mode) == 0 }
}

/// An archive: a regular file (after the links in its path) that can be read.
pub fn archive(text: &str) -> Result<(PathBuf, FileId), ApiError> {
    let path = uri::to_path(text).map_err(invalid)?;
    let meta = std::fs::metadata(&path).map_err(|e| {
        invalid(match e.kind() {
            std::io::ErrorKind::NotFound => format!("“{}” isn't there.", shown(&path)),
            std::io::ErrorKind::PermissionDenied => {
                format!(
                    "Telamon Archive isn't allowed to look at “{}”.",
                    shown(&path)
                )
            }
            _ => format!("“{}” couldn't be looked at.", shown(&path)),
        })
    })?;
    if !meta.is_file() {
        return Err(invalid(format!(
            "“{}” is not an archive file.",
            shown(&path)
        )));
    }
    if !access(&path, libc::R_OK) {
        return Err(invalid(format!("“{}” can't be read.", shown(&path))));
    }
    Ok((path, FileId::of(&meta)))
}

/// A folder to write into: it exists, is a folder, and can be written.
pub fn folder(text: &str) -> Result<PathBuf, ApiError> {
    let path = uri::to_path(text).map_err(invalid)?;
    check_folder(&path)?;
    Ok(path)
}

pub fn check_folder(path: &Path) -> Result<(), ApiError> {
    // A dialog's answer comes as plain text: a relative folder would be read
    // against this program's working folder.
    if !path.is_absolute() {
        return Err(invalid(format!(
            "The folder “{}” isn't a full path.",
            shown(path)
        )));
    }
    let meta = std::fs::metadata(path).map_err(|e| {
        invalid(match e.kind() {
            std::io::ErrorKind::NotFound => format!("The folder “{}” isn't there.", shown(path)),
            _ => format!("The folder “{}” couldn't be looked at.", shown(path)),
        })
    })?;
    if !meta.is_dir() {
        return Err(invalid(format!("“{}” is not a folder.", shown(path))));
    }
    if !access(path, libc::W_OK | libc::X_OK) {
        return Err(invalid(format!(
            "Telamon Archive can't save files in “{}”.",
            shown(path)
        )));
    }
    Ok(())
}

/// An item to compress: it exists (a link counts as itself, not its target)
/// and its top can be read.
pub fn source(text: &str) -> Result<PathBuf, ApiError> {
    let path = uri::to_path(text).map_err(invalid)?;
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(invalid(
            "A whole drive or the root folder can't be compressed.".into(),
        ));
    }
    let meta = std::fs::symlink_metadata(&path).map_err(|e| {
        invalid(match e.kind() {
            std::io::ErrorKind::NotFound => format!("“{}” isn't there.", shown(&path)),
            std::io::ErrorKind::PermissionDenied => {
                format!(
                    "Telamon Archive isn't allowed to look at “{}”.",
                    shown(&path)
                )
            }
            _ => format!("“{}” couldn't be looked at.", shown(&path)),
        })
    })?;
    let readable = if meta.is_symlink() {
        true
    } else if meta.is_dir() {
        access(&path, libc::R_OK | libc::X_OK)
    } else {
        access(&path, libc::R_OK)
    };
    if !readable {
        return Err(invalid(format!("“{}” can't be read.", shown(&path))));
    }
    Ok(path)
}

/// A file name the user may give an archive: one part, not too long, no NUL.
pub fn file_name(text: &str) -> Result<String, ApiError> {
    let t = text.trim();
    if t.is_empty() || t == "." || t == ".." || t.contains(['/', '\0']) || t.len() > 250 {
        return Err(invalid("That isn't a name a file can have.".into()));
    }
    Ok(t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("telamon-validate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn a_relative_folder_is_not_a_folder() {
        let d = dir("relative");
        std::fs::create_dir(d.join("sub")).unwrap();
        // "." exists (it is the working folder) and can be written, and is
        // still refused: it is not a full path.
        assert!(check_folder(Path::new(".")).is_err());
        assert!(check_folder(&d.join("sub")).is_ok());
    }

    #[test]
    fn archives_folders_and_sources() {
        let d = dir("kinds");
        std::fs::write(d.join("a.zip"), b"x").unwrap();
        std::os::unix::fs::symlink("a.zip", d.join("link.zip")).unwrap();
        std::os::unix::fs::symlink("/nonexistent", d.join("dangling")).unwrap();
        std::fs::create_dir(d.join("sub")).unwrap();
        let u = |p: &str| uri::from_path(&d.join(p));

        let (p, id) = archive(&u("a.zip")).unwrap();
        assert_eq!(p, d.join("a.zip"));
        // A link to an archive is the archive: the same file.
        assert_eq!(archive(&u("link.zip")).unwrap().1, id);
        assert!(
            archive(&u("sub"))
                .unwrap_err()
                .message()
                .contains("not an archive file")
        );
        assert!(
            archive(&u("nope.zip"))
                .unwrap_err()
                .message()
                .contains("isn't there")
        );
        assert!(
            archive(&u("dangling"))
                .unwrap_err()
                .message()
                .contains("isn't there")
        );
        assert!(archive("a.zip").is_err());
        assert!(
            archive("file:///dev/null")
                .unwrap_err()
                .message()
                .contains("not an archive")
        );

        assert_eq!(folder(&u("sub")).unwrap(), d.join("sub"));
        assert!(
            folder(&u("a.zip"))
                .unwrap_err()
                .message()
                .contains("not a folder")
        );
        assert!(
            folder(&u("nope"))
                .unwrap_err()
                .message()
                .contains("isn't there")
        );
        if unsafe { libc::geteuid() } != 0 {
            std::fs::set_permissions(
                d.join("sub"),
                std::os::unix::fs::PermissionsExt::from_mode(0o500),
            )
            .unwrap();
            assert!(
                folder(&u("sub"))
                    .unwrap_err()
                    .message()
                    .contains("can't save")
            );
            std::fs::set_permissions(
                d.join("sub"),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
        }

        assert_eq!(source(&u("a.zip")).unwrap(), d.join("a.zip"));
        // A link is itself, even a dangling one.
        assert!(source(&u("dangling")).is_ok());
        assert!(source(&u("nope")).is_err());
        assert!(source("file:///").unwrap_err().message().contains("root"));

        assert_eq!(file_name(" a b.zip ").unwrap(), "a b.zip");
        for bad in ["", " ", ".", "..", "a/b", "a\0b", &"x".repeat(251)] {
            assert!(file_name(bad).is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
