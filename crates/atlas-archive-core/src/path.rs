//! Entry paths: the untrusted path an archive stores for each entry, checked
//! and split into components (docs/DESIGN.md, "Extraction rules").
//!
//! A path is refused when it is absolute, climbs with `..`, names a Windows
//! drive, holds a NUL byte, or is too deep or too long. What passes is a list
//! of components, each with the display and disk forms from `name`. The disk
//! forms never hold `/` and are never empty, `.` or `..`, so joining them
//! gives a path that stays below the folder it is opened from; the writer
//! still opens it with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`.
//!
//! The path is decoded before it is split: in Shift_JIS, GBK and Big5 the
//! byte `\` (0x5C) can be the second half of a character, so splitting the
//! bytes would cut names in two.

use std::fmt;

use crate::name::{self, NameEncoding, Piece};

/// The most components one entry path may have.
pub const MAX_DEPTH: usize = 256;
/// The longest entry path taken, in bytes as stored (Linux's PATH_MAX).
pub const MAX_PATH_BYTES: usize = 4096;

/// Why an entry path was refused. Each is shown in plain words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The path is empty, or only `.` and separators.
    Empty,
    /// The path starts at the root (`/etc/passwd`, or `\\server\share` from
    /// a Windows archive).
    Absolute,
    /// A component is `..`.
    Parent,
    /// The path starts with a Windows drive (`C:`).
    Drive,
    /// The path holds a NUL byte.
    Nul,
    /// More than `MAX_DEPTH` components.
    TooDeep,
    /// Longer than `MAX_PATH_BYTES`.
    TooLong,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathError::Empty => "The item has no name.",
            PathError::Absolute => "The item would be written outside the destination folder (its path starts at the root).",
            PathError::Parent => "The item would be written outside the destination folder (its path uses \"..\").",
            PathError::Drive => "The item would be written outside the destination folder (its path starts with a drive letter).",
            PathError::Nul => "The item's name holds a NUL byte.",
            PathError::TooDeep => "The item is nested in too many folders.",
            PathError::TooLong => "The item's path is too long.",
        })
    }
}

impl std::error::Error for PathError {}

/// One checked component of an entry path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    /// The name shown to the user (`name::display`).
    pub display: String,
    /// The file name written (`name::disk`). Two different names can give
    /// the same disk form ("a\x01" and "a\x02" both give "a_"); the tree and
    /// the writer treat that as a conflict.
    pub disk: String,
    /// The name held controls, bidi characters or undecodable bytes.
    pub unusual: bool,
    /// The disk form differs from the decoded name.
    pub renamed: bool,
}

/// A checked entry path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryPath {
    /// At least one, at most `MAX_DEPTH`.
    pub components: Vec<Component>,
    /// The path ended with a separator, which archives use to mark folders.
    pub dir_hint: bool,
}

impl EntryPath {
    /// The components' disk forms joined with `/`: relative, no `.` or `..`.
    pub fn disk_path(&self) -> String {
        join(self.components.iter().map(|c| c.disk.as_str()))
    }

    /// The components' display forms joined with `/`.
    pub fn display_path(&self) -> String {
        join(self.components.iter().map(|c| c.display.as_str()))
    }

    /// The last component: the entry's own name.
    pub fn name(&self) -> &Component {
        self.components
            .last()
            .expect("an EntryPath has at least one component")
    }
}

fn join<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    let mut out = String::new();
    for (i, p) in parts.enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(p);
    }
    out
}

/// Checks and splits the path an archive stores for an entry.
/// `dos_separators`: the archive was made on DOS or Windows, so `\` separates
/// folders too.
pub fn parse(
    raw: &[u8],
    encoding: NameEncoding,
    dos_separators: bool,
) -> Result<EntryPath, PathError> {
    if raw.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    if raw.contains(&0) {
        return Err(PathError::Nul);
    }
    let mut pieces = Vec::with_capacity(raw.len());
    name::decode(raw, encoding, |p| pieces.push(p));
    let is_sep = |p: &Piece| {
        matches!(p, Piece::Char('/')) || (dos_separators && matches!(p, Piece::Char('\\')))
    };

    if pieces.first().is_some_and(is_sep) {
        return Err(PathError::Absolute);
    }
    let dir_hint = pieces.last().is_some_and(is_sep);

    let mut components = Vec::new();
    for (index, part) in pieces.split(is_sep).enumerate() {
        match part {
            [] | [Piece::Char('.')] => continue,
            [Piece::Char('.'), Piece::Char('.')] => return Err(PathError::Parent),
            _ => {}
        }
        // "C:", "C:foo" and "C:\foo" are drive paths on Windows. Only the
        // first component: a colon is an ordinary character on Linux.
        if index == 0
            && matches!(part, [Piece::Char(d), Piece::Char(':'), ..] if d.is_ascii_alphabetic())
        {
            return Err(PathError::Drive);
        }
        if components.len() == MAX_DEPTH {
            return Err(PathError::TooDeep);
        }
        let (display, unusual) = name::display(part);
        let (disk, renamed) = name::disk(part);
        components.push(Component {
            display,
            disk,
            unusual,
            renamed,
        });
    }
    if components.is_empty() {
        return Err(PathError::Empty);
    }
    Ok(EntryPath {
        components,
        dir_hint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(raw: &[u8]) -> Result<String, PathError> {
        parse(raw, NameEncoding::Utf8, false).map(|p| p.disk_path())
    }

    fn dos(raw: &[u8]) -> Result<String, PathError> {
        parse(raw, NameEncoding::Utf8, true).map(|p| p.disk_path())
    }

    #[test]
    fn plain_paths() {
        assert_eq!(disk(b"a/b/c.txt").unwrap(), "a/b/c.txt");
        assert_eq!(disk(b"./a//b/./c").unwrap(), "a/b/c");
        let p = parse(b"docs/", NameEncoding::Utf8, false).unwrap();
        assert!(p.dir_hint);
        assert_eq!(p.name().disk, "docs");
        assert!(!parse(b"docs", NameEncoding::Utf8, false).unwrap().dir_hint);
    }

    #[test]
    fn escapes_are_refused() {
        assert_eq!(disk(b"/etc/passwd"), Err(PathError::Absolute));
        assert_eq!(disk(b"//x"), Err(PathError::Absolute));
        assert_eq!(disk(b"../x"), Err(PathError::Parent));
        assert_eq!(disk(b"a/../../x"), Err(PathError::Parent));
        assert_eq!(disk(b"a/.."), Err(PathError::Parent));
        assert_eq!(disk(b"a/b/../c"), Err(PathError::Parent));
        assert_eq!(dos(b"\\Windows\\x"), Err(PathError::Absolute));
        assert_eq!(dos(b"\\\\server\\share\\x"), Err(PathError::Absolute));
        assert_eq!(dos(b"a\\..\\..\\x"), Err(PathError::Parent));
        assert_eq!(dos(b"C:\\x"), Err(PathError::Drive));
        assert_eq!(dos(b"c:x"), Err(PathError::Drive));
        assert_eq!(disk(b"C:/x"), Err(PathError::Drive));
        assert_eq!(disk(b"a\0b"), Err(PathError::Nul));
    }

    #[test]
    fn empty_paths() {
        assert_eq!(disk(b""), Err(PathError::Empty));
        assert_eq!(disk(b"."), Err(PathError::Empty));
        assert_eq!(disk(b"./"), Err(PathError::Empty));
        assert_eq!(disk(b".//./"), Err(PathError::Empty));
        assert_eq!(disk(b"/"), Err(PathError::Absolute));
    }

    #[test]
    fn backslash_is_a_name_character_off_dos() {
        assert_eq!(disk(b"a\\b").unwrap(), "a\\b");
        assert_eq!(disk(b"..\\x").unwrap(), "..\\x");
        assert_eq!(dos(b"a\\b").unwrap(), "a/b");
        // A colon later on is an ordinary character.
        assert_eq!(disk(b"a/C:x").unwrap(), "a/C:x");
        assert_eq!(disk(b"1:x").unwrap(), "1:x");
    }

    #[test]
    fn hidden_dotdot_cannot_survive_sanitising() {
        // ".\u{202E}." loses its bidi character on disk, which would leave "..".
        let p = parse(".\u{202E}./x".as_bytes(), NameEncoding::Utf8, false).unwrap();
        assert_eq!(p.disk_path(), "_../x");
        assert_eq!(p.display_path(), ".<U+202E>./x");
        assert!(p.components[0].unusual && p.components[0].renamed);
        // A control character in "..": shown, and written as "._.".
        let p = parse(b"a/.\x01./b", NameEncoding::Utf8, false).unwrap();
        assert_eq!(p.disk_path(), "a/._./b");
    }

    #[test]
    fn decoded_before_splitting() {
        // Shift_JIS "ソ" is 0x83 0x5C: its second byte is "\" and must not
        // split the name, even in a DOS-made archive.
        let sjis = NameEncoding::from_label("Shift_JIS").unwrap();
        let p = parse(b"\x83\x5C/x", sjis, true).unwrap();
        assert_eq!(p.disk_path(), "ソ/x");
        let p = parse(b"\x83\x5C\\x", sjis, true).unwrap();
        assert_eq!(p.disk_path(), "ソ/x");
    }

    #[test]
    fn invalid_utf8_is_kept_visible() {
        let p = parse(b"a/b\xFFc", NameEncoding::Utf8, false).unwrap();
        assert_eq!(p.disk_path(), "a/b_c");
        assert_eq!(p.display_path(), "a/b\\xFFc");
    }

    #[test]
    fn limits() {
        let deep = "a/".repeat(MAX_DEPTH);
        assert_eq!(disk(deep.as_bytes()).unwrap().split('/').count(), MAX_DEPTH);
        let deeper = "a/".repeat(MAX_DEPTH + 1);
        assert_eq!(disk(deeper.as_bytes()), Err(PathError::TooDeep));
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(disk(long.as_bytes()), Err(PathError::TooLong));
        // A 300-byte component is shortened on disk, not refused.
        let p = parse("b".repeat(300).as_bytes(), NameEncoding::Utf8, false).unwrap();
        assert!(p.name().disk.len() <= name::MAX_COMPONENT_BYTES);
        assert!(p.name().renamed);
    }

    #[test]
    fn errors_read_as_sentences() {
        for e in [
            PathError::Empty,
            PathError::Absolute,
            PathError::Parent,
            PathError::Drive,
            PathError::Nul,
            PathError::TooDeep,
            PathError::TooLong,
        ] {
            let s = e.to_string();
            assert!(s.ends_with('.') && s.starts_with("The item"), "{s}");
        }
    }
}
