//! The link policy (docs/DESIGN.md, "Extraction rules").
//!
//! A symbolic link is written only when its target is relative, stays inside
//! the destination when resolved by name, and passes through no other
//! symbolic link of the archive on the way. That last rule is what makes the
//! name check true on disk: with no link in between, `x/..` means the same
//! folder lexically and physically, so a link to `.` plus a path through it
//! cannot climb out. Links are created after every file and folder (the
//! writer's job), so no entry is ever written through one.
//!
//! A hard link's target is an archive path, checked like an entry path; the
//! writer links only to a regular file it wrote in this run.

use std::fmt;

use crate::name::{self, NameEncoding, Piece};
use crate::path::{self, EntryPath, MAX_DEPTH, MAX_PATH_BYTES};

/// Why a link was refused. Each is shown in plain words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    Empty,
    Absolute,
    /// Resolving the target climbs above the destination folder.
    Escapes,
    /// The target passes through another symbolic link of the archive.
    ThroughLink,
    Nul,
    TooLong,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LinkError::Empty => "The link has no target.",
            LinkError::Absolute => {
                "The link points outside the destination folder (its target starts at the root)."
            }
            LinkError::Escapes => "The link points outside the destination folder.",
            LinkError::ThroughLink => "The link's target goes through another link in the archive.",
            LinkError::Nul => "The link's target holds a NUL byte.",
            LinkError::TooLong => "The link's target is too long.",
        })
    }
}

impl std::error::Error for LinkError {}

/// A symbolic link target that passed the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymlinkTarget {
    /// The target to write: relative, built from disk forms, the shortest
    /// `../`-path from the link's folder to what it names (`.` for the
    /// link's own folder).
    pub disk: String,
    /// The target as the archive stores it, in display form.
    pub display: String,
    /// The disk forms of what the target names, from the destination folder.
    /// Empty when it names the destination folder itself.
    pub resolved: Vec<String>,
}

/// Checks a symbolic link at `link` whose stored target is `raw`.
/// `is_symlink` answers whether the archive holds a symbolic link at the
/// given disk path (components from the destination folder).
pub fn check_symlink(
    link: &EntryPath,
    raw: &[u8],
    encoding: NameEncoding,
    dos_separators: bool,
    is_symlink: impl Fn(&[String]) -> bool,
) -> Result<SymlinkTarget, LinkError> {
    if raw.len() > MAX_PATH_BYTES {
        return Err(LinkError::TooLong);
    }
    if raw.contains(&0) {
        return Err(LinkError::Nul);
    }
    if raw.is_empty() {
        return Err(LinkError::Empty);
    }
    let mut pieces = Vec::with_capacity(raw.len());
    name::decode(raw, encoding, |p| pieces.push(p));
    let is_sep = |p: &Piece| {
        matches!(p, Piece::Char('/')) || (dos_separators && matches!(p, Piece::Char('\\')))
    };
    if pieces.first().is_some_and(is_sep) {
        return Err(LinkError::Absolute);
    }
    if matches!(pieces.as_slice(), [Piece::Char(d), Piece::Char(':'), ..] if d.is_ascii_alphabetic())
    {
        return Err(LinkError::Absolute);
    }

    // Start in the link's folder. Its own folders must not be links either.
    let parent: Vec<String> = link.components[..link.components.len() - 1]
        .iter()
        .map(|c| c.disk.clone())
        .collect();
    for i in 1..=parent.len() {
        if is_symlink(&parent[..i]) {
            return Err(LinkError::ThroughLink);
        }
    }

    let mut at = parent.clone();
    let parts: Vec<&[Piece]> = pieces.split(is_sep).collect();
    let mut display_parts = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        let (shown, _) = name::display(part);
        display_parts.push(shown);
        match part {
            [] | [Piece::Char('.')] => {}
            [Piece::Char('.'), Piece::Char('.')] => {
                // Leaving a folder: `at` was checked when it was entered.
                if at.pop().is_none() {
                    return Err(LinkError::Escapes);
                }
            }
            _ => {
                if at.len() == MAX_DEPTH {
                    return Err(LinkError::TooLong);
                }
                at.push(name::disk(part).0);
                // The target may itself be a link (its own target is checked
                // on its own); only links passed through are refused.
                let more = parts[i + 1..].iter().any(|p| !p.is_empty());
                if more && is_symlink(&at) {
                    return Err(LinkError::ThroughLink);
                }
            }
        }
    }

    let common = parent.iter().zip(&at).take_while(|(a, b)| a == b).count();
    let mut disk: Vec<&str> = vec![".."; parent.len() - common];
    disk.extend(at[common..].iter().map(String::as_str));
    let disk = if disk.is_empty() {
        ".".to_string()
    } else {
        disk.join("/")
    };
    Ok(SymlinkTarget {
        disk,
        display: display_parts.join("/"),
        resolved: at,
    })
}

/// Checks a hard link's target, an archive path like an entry's own.
pub fn check_hardlink(
    raw: &[u8],
    encoding: NameEncoding,
    dos_separators: bool,
) -> Result<EntryPath, path::PathError> {
    path::parse(raw, encoding, dos_separators)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(p: &str) -> EntryPath {
        path::parse(p.as_bytes(), NameEncoding::Utf8, false).unwrap()
    }

    fn check(link: &str, target: &str, links: &[&str]) -> Result<String, LinkError> {
        check_symlink(
            &entry(link),
            target.as_bytes(),
            NameEncoding::Utf8,
            false,
            |p| links.contains(&p.join("/").as_str()),
        )
        .map(|t| t.disk)
    }

    #[test]
    fn inside_targets() {
        assert_eq!(check("a/l", "b", &[]).unwrap(), "b");
        assert_eq!(check("a/l", "../b", &[]).unwrap(), "../b");
        assert_eq!(check("a/b/l", "../../c/d", &[]).unwrap(), "../../c/d");
        assert_eq!(check("a/b/l", "x/../y", &[]).unwrap(), "y");
        assert_eq!(check("l", ".", &[]).unwrap(), ".");
        assert_eq!(check("a/l", "..", &[]).unwrap(), "..");
        assert_eq!(check("a/l", "./b/", &[]).unwrap(), "b");
    }

    #[test]
    fn escaping_targets() {
        assert_eq!(check("l", "..", &[]), Err(LinkError::Escapes));
        assert_eq!(check("a/l", "../../x", &[]), Err(LinkError::Escapes));
        assert_eq!(check("a/l", "b/../../../x", &[]), Err(LinkError::Escapes));
        assert_eq!(check("l", "/etc/passwd", &[]), Err(LinkError::Absolute));
        assert_eq!(check("l", "C:/x", &[]), Err(LinkError::Absolute));
        assert_eq!(check("l", "", &[]), Err(LinkError::Empty));
        assert_eq!(check("l", "a\0b", &[]), Err(LinkError::Nul));
    }

    #[test]
    fn link_to_dot_cannot_be_climbed_through() {
        // "d" -> "." and then "e" -> "d/d/d/../../.." would be lexically
        // inside, but physically climbs out through "d".
        assert_eq!(check("d", ".", &[]).unwrap(), ".");
        assert_eq!(check("e", "d/d/../..", &["d"]), Err(LinkError::ThroughLink));
        assert_eq!(check("e", "d/x", &["d"]), Err(LinkError::ThroughLink));
        // Naming the link itself is fine: its own target was checked.
        assert_eq!(check("e", "d", &["d"]).unwrap(), "d");
        assert_eq!(check("e", "d/", &["d"]).unwrap(), "d");
    }

    #[test]
    fn link_inside_a_linked_folder_is_refused() {
        assert_eq!(check("d/l", "x", &["d"]), Err(LinkError::ThroughLink));
    }

    #[test]
    fn targets_use_disk_forms() {
        let t = check_symlink(
            &entry("l"),
            "a\u{202E}b/c\x01".as_bytes(),
            NameEncoding::Utf8,
            false,
            |_| false,
        )
        .unwrap();
        assert_eq!(t.disk, "ab/c_");
        assert_eq!(t.display, "a<U+202E>b/c\\x01");
        assert_eq!(t.resolved, ["ab", "c_"]);
        // A ".." hidden behind a bidi character is a name, not a climb.
        assert_eq!(check("l", ".\u{202E}.", &[]).unwrap(), "_..");
    }

    #[test]
    fn hardlink_targets_are_entry_paths() {
        assert!(check_hardlink(b"a/b", NameEncoding::Utf8, false).is_ok());
        assert!(check_hardlink(b"../b", NameEncoding::Utf8, false).is_err());
        assert!(check_hardlink(b"/etc/shadow", NameEncoding::Utf8, false).is_err());
    }
}
