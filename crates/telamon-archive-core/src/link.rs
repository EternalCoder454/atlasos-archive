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
    /// The target is the folder everything is extracted into.
    ToTop,
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
            LinkError::ToTop => "The link points at the folder everything is extracted into.",
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

/// The archive's folders, as `check_symlink` walks them.
pub trait Lookup {
    /// The child named `disk` of the folder `parent` (`tree::ROOT` for the
    /// top).
    fn child(&self, parent: u32, disk: &str) -> Option<u32>;
    fn is_symlink(&self, node: u32) -> bool;
}

/// Checks a symbolic link whose stored target is `raw`. `folder`: the
/// link's folders from the top, as disk name and node; they are real
/// folders (in a tree, a node with something inside is always one).
///
/// Refused: absolute targets, targets that climb above the top or name the
/// top itself (after `Extract here` moves a lone folder out, the top is the
/// user's own folder), and targets that pass through another link. Every
/// step is one lookup, so a long target costs no more than its length.
pub fn check_symlink(
    folder: &[(String, u32)],
    raw: &[u8],
    encoding: NameEncoding,
    dos_separators: bool,
    lookup: &impl Lookup,
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
    if dos_separators
        && matches!(pieces.as_slice(), [Piece::Char(d), Piece::Char(':'), ..] if d.is_ascii_alphabetic())
    {
        return Err(LinkError::Absolute);
    }

    // Where the walk is: disk names, and the node of each when the archive
    // has one there (a target may name something that isn't in it).
    let mut at: Vec<(String, Option<u32>)> = folder
        .iter()
        .map(|(n, id)| (n.clone(), Some(*id)))
        .collect();
    let parts: Vec<&[Piece]> = pieces.split(is_sep).collect();
    let last_named = parts
        .iter()
        .rposition(|p| !p.is_empty() && !matches!(p, [Piece::Char('.')]));
    let mut display_parts = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        display_parts.push(name::display(part).0);
        match part {
            [] | [Piece::Char('.')] => {}
            [Piece::Char('.'), Piece::Char('.')] => {
                // Leaving a folder: it was checked when it was entered.
                if at.pop().is_none() {
                    return Err(LinkError::Escapes);
                }
            }
            _ => {
                if at.len() == MAX_DEPTH {
                    return Err(LinkError::TooLong);
                }
                let disk = name::disk(part).0;
                let parent = match at.last() {
                    Some((_, id)) => *id,
                    None => Some(crate::tree::ROOT),
                };
                let node = parent.and_then(|p| lookup.child(p, &disk));
                // The target may itself be a link (its own target is checked
                // on its own); only links passed through are refused.
                if last_named.is_some_and(|l| i < l) && node.is_some_and(|n| lookup.is_symlink(n)) {
                    return Err(LinkError::ThroughLink);
                }
                at.push((disk, node));
            }
        }
    }
    if at.is_empty() {
        return Err(LinkError::ToTop);
    }

    let common = folder
        .iter()
        .zip(&at)
        .take_while(|(a, b)| a.0 == b.0)
        .count();
    let mut disk: Vec<&str> = vec![".."; folder.len() - common];
    disk.extend(at[common..].iter().map(|(n, _)| n.as_str()));
    let disk = if disk.is_empty() {
        ".".to_string()
    } else {
        disk.join("/")
    };
    if disk.len() >= MAX_PATH_BYTES {
        return Err(LinkError::TooLong);
    }
    Ok(SymlinkTarget {
        disk,
        display: display_parts.join("/"),
        resolved: at.into_iter().map(|(n, _)| n).collect(),
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

    /// Paths of an archive; node ids are positions plus one.
    struct Paths {
        paths: Vec<String>,
        links: Vec<String>,
    }

    impl Lookup for Paths {
        fn child(&self, parent: u32, disk: &str) -> Option<u32> {
            let full = if parent == 0 {
                disk.to_string()
            } else {
                format!("{}/{disk}", self.paths[parent as usize - 1])
            };
            self.paths
                .iter()
                .position(|p| *p == full)
                .map(|i| i as u32 + 1)
        }
        fn is_symlink(&self, node: u32) -> bool {
            self.links.contains(&self.paths[node as usize - 1])
        }
    }

    fn check(link: &str, target: &str, links: &[&str]) -> Result<String, LinkError> {
        let mut paths: Vec<String> = Vec::new();
        for p in links.iter().copied().chain([link]) {
            let parts: Vec<&str> = p.split('/').collect();
            for i in 1..=parts.len() {
                let prefix = parts[..i].join("/");
                if !paths.contains(&prefix) {
                    paths.push(prefix);
                }
            }
        }
        let lookup = Paths {
            paths,
            links: links.iter().map(|s| s.to_string()).collect(),
        };
        let parts: Vec<&str> = link.split('/').collect();
        let mut folder = Vec::new();
        let mut at = 0;
        for p in &parts[..parts.len() - 1] {
            at = lookup.child(at, p).unwrap();
            folder.push((p.to_string(), at));
        }
        check_symlink(
            &folder,
            target.as_bytes(),
            NameEncoding::Utf8,
            false,
            &lookup,
        )
        .map(|t| t.disk)
    }

    #[test]
    fn inside_targets() {
        assert_eq!(check("a/l", "b", &[]).unwrap(), "b");
        assert_eq!(check("a/l", "../b", &[]).unwrap(), "../b");
        assert_eq!(check("a/b/l", "../../c/d", &[]).unwrap(), "../../c/d");
        assert_eq!(check("a/b/l", "x/../y", &[]).unwrap(), "y");
        assert_eq!(check("a/l", ".", &[]).unwrap(), ".");
        assert_eq!(check("a/b/l", "..", &[]).unwrap(), "..");
        assert_eq!(check("a/l", "./b/", &[]).unwrap(), "b");
        // A colon is a name character unless the archive was made on Windows.
        assert_eq!(check("l", "C:/x", &[]).unwrap(), "C:/x");
    }

    #[test]
    fn escaping_targets() {
        assert_eq!(check("l", "..", &[]), Err(LinkError::Escapes));
        assert_eq!(check("a/l", "../../x", &[]), Err(LinkError::Escapes));
        assert_eq!(check("a/l", "b/../../../x", &[]), Err(LinkError::Escapes));
        assert_eq!(check("l", "/etc/passwd", &[]), Err(LinkError::Absolute));
        let none = Paths {
            paths: vec![],
            links: vec![],
        };
        assert_eq!(
            check_symlink(&[], b"C:\\x", NameEncoding::Utf8, true, &none),
            Err(LinkError::Absolute)
        );
        assert_eq!(
            check_symlink(&[], b"\\x", NameEncoding::Utf8, true, &none),
            Err(LinkError::Absolute)
        );
        // The top itself: after a lone folder is moved out of staging, the
        // top is the user's own folder.
        assert_eq!(check("l", ".", &[]), Err(LinkError::ToTop));
        assert_eq!(check("a/l", "..", &[]), Err(LinkError::ToTop));
        assert_eq!(check("a/l", "../a/..", &[]), Err(LinkError::ToTop));
        assert_eq!(check("l", "", &[]), Err(LinkError::Empty));
        assert_eq!(check("l", "a\0b", &[]), Err(LinkError::Nul));
    }

    #[test]
    fn link_to_dot_cannot_be_climbed_through() {
        // "d" -> "." and then "e" -> "d/d/d/../../.." would be lexically
        // inside, but physically climbs out through "d".
        assert_eq!(check("e", "d/d/../..", &["d"]), Err(LinkError::ThroughLink));
        assert_eq!(check("e", "d/x", &["d"]), Err(LinkError::ThroughLink));
        // Naming the link itself is fine: its own target was checked.
        assert_eq!(check("e", "d", &["d"]).unwrap(), "d");
        assert_eq!(check("e", "d/", &["d"]).unwrap(), "d");
    }

    #[test]
    fn long_targets_cost_their_length() {
        // 2,000 steps of "x/.." through a folder: linear, and inside.
        let target = format!("{}y", "x/../".repeat(800));
        assert_eq!(check("a/l", &target, &["a/x"]), Err(LinkError::ThroughLink));
        assert_eq!(check("a/l", &target, &[]).unwrap(), "y");
    }

    #[test]
    fn targets_use_disk_forms() {
        let none = Paths {
            paths: vec![],
            links: vec![],
        };
        let t = check_symlink(
            &[],
            "a\u{202E}b/c\x01".as_bytes(),
            NameEncoding::Utf8,
            false,
            &none,
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
