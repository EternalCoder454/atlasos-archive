//! `file://` URIs, the only way the API names a file (docs/DESIGN.md): absolute,
//! local, no NUL, and normal (no `.` or `..`, no empty parts).

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// The longest URI the API reads.
pub const MAX_URI: usize = 8192;

/// The path a `file://` URI names. `Err` is a sentence for the caller.
pub fn to_path(uri: &str) -> Result<PathBuf, String> {
    let bad = || "Only files on this computer can be used, named as file:// links.".to_string();
    if uri.len() > MAX_URI || uri.contains('\0') {
        return Err(bad());
    }
    let rest = uri.strip_prefix("file://").ok_or_else(bad)?;
    // `file:///x` and `file://localhost/x`; any other host is not this computer.
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') || rest.contains(['?', '#']) {
        return Err(bad());
    }
    let bytes = decode(rest).ok_or_else(bad)?;
    if bytes.contains(&0) {
        return Err(bad());
    }
    let path = PathBuf::from(OsString::from_vec(bytes));
    normal(&path).then_some(path).ok_or_else(|| {
        "The path has parts like “.” or “..” that Telamon Archive won't follow. Give the full path.".into()
    })
}

/// No `.` or `..` and no empty part (one trailing slash is allowed).
fn normal(path: &Path) -> bool {
    let b = path.as_os_str().as_bytes();
    if b.len() > 4096 || b.first() != Some(&b'/') {
        return false;
    }
    let body = b[1..].strip_suffix(b"/").unwrap_or(&b[1..]);
    body.is_empty()
        || body
            .split(|&c| c == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}

fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// The `file://` URI of a path, as KDE writes it: everything but letters,
/// digits and `-_.~/` encoded.
pub fn from_path(path: &Path) -> String {
    let mut out = String::from("file://");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn good_uris() {
        assert_eq!(
            to_path("file:///home/a%20b/c.zip").unwrap(),
            Path::new("/home/a b/c.zip")
        );
        assert_eq!(to_path("file://localhost/x").unwrap(), Path::new("/x"));
        assert_eq!(to_path("file:///x/").unwrap(), Path::new("/x/"));
        assert_eq!(to_path("file:///").unwrap(), Path::new("/"));
        assert_eq!(to_path("file:///caf%C3%A9").unwrap(), Path::new("/café"));
        // Not UTF-8 is allowed: file names are bytes.
        assert_eq!(
            to_path("file:///a%FFb").unwrap().as_os_str().as_bytes(),
            b"/a\xffb"
        );
    }

    #[test]
    fn bad_uris() {
        for bad in [
            "",
            "/home/a",
            "home/a",
            "https://x/y",
            "file:/x",
            "file://host/x",
            "file://",
            "file://x",
            "file:///a%00b",
            "file:///a%0",
            "file:///a%zz",
            "file:///a?b",
            "file:///a#b",
            "file:///a\0b",
            "file:///../etc",
            "file:///a/../b",
            "file:///a/./b",
            "file:///a//b",
            "file:///a%2F..%2Fb/../c",
        ] {
            assert!(to_path(bad).is_err(), "{bad:?}");
        }
        assert!(to_path(&format!("file:///{}", "a".repeat(MAX_URI))).is_err());
        assert!(to_path(&format!("file:///{}", "a/".repeat(2100))).is_err());
    }

    #[test]
    fn round_trip() {
        for p in ["/a b/c#d?e%f", "/héllo/日本語.zip", "/plain/path"] {
            assert_eq!(to_path(&from_path(Path::new(p))).unwrap(), Path::new(p));
        }
        assert_eq!(from_path(Path::new("/a b/é")), "file:///a%20b/%C3%A9");
    }
}
