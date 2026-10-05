//! What the commands print. Every name goes out in display form (or, in JSON,
//! escaped), never as the raw bytes an archive held.

use std::io::{self, Write};
use std::path::Path;

use atlas_archive_core::limits::format_size;
use atlas_archive_core::name::{self, NameEncoding, Piece};
use atlas_archive_core::proto::Kind;
use atlas_archive_core::tree::Node;
use std::os::unix::ffi::OsStrExt;

use crate::job::{Extraction, Loaded, Raw, Tested};
use crate::json::{self, Obj};
use crate::term;

/// "1 file", "2 files".
fn count(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// A time as `YYYY-MM-DD HH:MM` in UTC.
pub fn utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn marker(kind: Kind) -> char {
    match kind {
        Kind::File => '-',
        Kind::Dir => 'd',
        Kind::Symlink => 'l',
        Kind::Hardlink => 'h',
        Kind::Special => 's',
    }
}

fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::File => "file",
        Kind::Dir => "dir",
        Kind::Symlink => "symlink",
        Kind::Hardlink => "hardlink",
        Kind::Special => "special",
    }
}

/// The name as the archive stored it, decoded: undecodable bytes become
/// U+FFFD. Not safe to print as is; JSON escapes it.
fn decoded(raw: &[u8], encoding: NameEncoding) -> String {
    let mut s = String::with_capacity(raw.len());
    name::decode(raw, encoding, |p| match p {
        Piece::Char(c) => s.push(c),
        Piece::Bad(_) => s.push(char::REPLACEMENT_CHARACTER),
    });
    s
}

/// A name or link target in display form.
fn displayed(raw: &[u8], encoding: NameEncoding) -> String {
    let mut pieces = Vec::with_capacity(raw.len());
    name::decode(raw, encoding, |p| pieces.push(p));
    name::display(&pieces).0
}

fn encoding_of(raw: &Raw, tree_encoding: NameEncoding) -> NameEncoding {
    if raw.utf8 {
        NameEncoding::Utf8
    } else {
        tree_encoding
    }
}

/// What a link points at, in display form.
fn link_of(l: &Loaded, node: &Node) -> Option<String> {
    if let Some(s) = &node.symlink {
        return Some(s.display.clone());
    }
    if let Some(h) = node.hardlink {
        return Some(l.tree.display_path(h));
    }
    let raw = l.raw.get(&node.entry?)?;
    let target = raw.link.as_ref()?;
    Some(displayed(target, encoding_of(raw, l.tree.encoding)))
}

/// Everything that is not a folder or a hard link (whose size is its
/// target's), added up.
pub fn total_size(l: &Loaded) -> u64 {
    l.tree
        .nodes
        .iter()
        .skip(1)
        .filter(|n| !matches!(n.kind, Kind::Dir | Kind::Hardlink))
        .fold(0u64, |a, n| a.saturating_add(n.size))
}

fn refused_count(l: &Loaded) -> u64 {
    let nodes = l.tree.nodes.iter().filter(|n| n.refused.is_some()).count() as u64;
    nodes + l.tree.skipped.len() as u64 + l.tree.skipped_more
}

pub fn list_text(out: &mut impl Write, l: &Loaded) -> io::Result<()> {
    writeln!(out, "T  {:>10}  {:<16}  Name", "Size", "Modified")?;
    for id in 1..l.tree.nodes.len() as u32 {
        let node = &l.tree.nodes[id as usize];
        let mut name = l.tree.display_path(id);
        if node.kind == Kind::Dir {
            name.push('/');
        }
        if let Some(to) = link_of(l, node) {
            name.push_str(" -> ");
            name.push_str(&to);
        }
        let flag = if node.refused.is_some() {
            '!'
        } else if node.encrypted {
            '*'
        } else {
            ' '
        };
        let size = if node.kind == Kind::Dir {
            "-".to_string()
        } else {
            format_size(node.size)
        };
        let time = node.mtime.map_or("-".to_string(), utc);
        writeln!(
            out,
            "{}{flag} {size:>10}  {time:<16}  {name}",
            marker(node.kind)
        )?;
        if let Some(r) = &node.refused {
            writeln!(out, "     ! {}", term::safe(&r.reason()))?;
        }
    }
    for s in &l.tree.skipped {
        writeln!(out, "?! {:>10}  {:<16}  {}", "-", "-", s.path)?;
        writeln!(out, "     ! {}", term::safe(&s.reason))?;
    }
    if l.tree.skipped_more > 0 {
        writeln!(
            out,
            "   ({} more refused)",
            count(l.tree.skipped_more, "entry", "entries")
        )?;
    }
    if l.tree.overflow {
        writeln!(out, "   (The archive holds more items than can be shown.)")?;
    }
    writeln!(
        out,
        "{}, {}, {} unpacked{}",
        count(l.tree.files, "file", "files"),
        count(l.tree.folders, "folder", "folders"),
        format_size(total_size(l)),
        match refused_count(l) {
            0 => String::new(),
            n => format!(", {n} refused"),
        }
    )
}

pub fn list_json(out: &mut impl Write, l: &Loaded) -> io::Result<()> {
    let tree_encoding = l.tree.encoding;
    for id in 1..l.tree.nodes.len() as u32 {
        let node = &l.tree.nodes[id as usize];
        let display = l.tree.display_path(id);
        let raw = node.entry.and_then(|i| l.raw.get(&i));
        let path = match raw {
            Some(r) => {
                let p = decoded(&r.path, encoding_of(r, tree_encoding));
                // A folder is stored as "docs/"; its path is "docs".
                match node.kind == Kind::Dir {
                    true => p.trim_end_matches('/').to_string(),
                    false => p,
                }
            }
            None => display.clone(),
        };
        let mut o = Obj::new().str("path", &path).str("display", &display);
        if let Some(r) = raw
            && std::str::from_utf8(&r.path).is_err()
        {
            o = o.str("raw_hex", &json::hex(&r.path));
        }
        let refused = node.refused.as_ref().map(|r| term::safe(&r.reason()));
        let o = o
            .str("kind", kind_word(node.kind))
            .num("size", node.size)
            .opt_num("packed", node.packed)
            .opt_int("mtime", node.mtime)
            .num("mode", u64::from(node.mode))
            .bool("encrypted", node.encrypted)
            .opt_str("link", link_of(l, node).as_deref())
            .opt_str("refused", refused.as_deref());
        writeln!(out, "{}", o.finish())?;
    }
    for s in &l.tree.skipped {
        let raw = l.raw.get(&s.index);
        let path = match raw {
            Some(r) => decoded(&r.path, encoding_of(r, tree_encoding)),
            None => s.path.clone(),
        };
        let mut o = Obj::new().str("path", &path).str("display", &s.path);
        if let Some(r) = raw
            && std::str::from_utf8(&r.path).is_err()
        {
            o = o.str("raw_hex", &json::hex(&r.path));
        }
        let o = o
            .raw("kind", "null")
            .raw("size", "null")
            .raw("packed", "null")
            .raw("mtime", "null")
            .raw("mode", "null")
            .bool("encrypted", false)
            .raw("link", "null")
            .str("refused", &term::safe(&s.reason));
        writeln!(out, "{}", o.finish())?;
    }
    let summary = Obj::new()
        .str("format", &term::safe(&l.format.name))
        .num("entries", l.entries)
        .num("files", l.tree.files)
        .num("folders", l.tree.folders)
        .num("size", total_size(l))
        .num("refused", refused_count(l))
        .bool("overflow", l.tree.overflow)
        .finish();
    writeln!(out, "{}", Obj::new().raw("summary", &summary).finish())
}

pub fn info_text(out: &mut impl Write, l: &Loaded) -> io::Result<()> {
    let f = &l.format;
    writeln!(out, "Format:     {}", term::safe(&f.name))?;
    writeln!(
        out,
        "Items:      {}, {} ({} listed)",
        count(l.tree.files, "file", "files"),
        count(l.tree.folders, "folder", "folders"),
        l.entries
    )?;
    let total = total_size(l);
    writeln!(out, "Unpacked:   {} ({total} bytes)", format_size(total))?;
    writeln!(
        out,
        "Encrypted:  {}",
        match (f.encrypted, f.encrypted_names) {
            (_, true) => "yes, file names too",
            (true, false) => "yes",
            (false, false) => "no",
        }
    )?;
    writeln!(out, "Volumes:    {}", f.volumes)?;
    writeln!(out, "Names:      {}", l.tree.encoding.label())?;
    if let Some(c) = &f.comment {
        let safe = term::safe_multiline(c);
        let mut lines = safe.lines();
        writeln!(out, "Comment:    {}", lines.next().unwrap_or(""))?;
        for line in lines {
            writeln!(out, "            {line}")?;
        }
    }
    Ok(())
}

pub fn info_json(out: &mut impl Write, l: &Loaded) -> io::Result<()> {
    let f = &l.format;
    let comment = f.comment.as_deref().map(term::safe_multiline);
    let o = Obj::new()
        .str("format", &term::safe(&f.name))
        .num("entries", l.entries)
        .num("files", l.tree.files)
        .num("folders", l.tree.folders)
        .num("size", total_size(l))
        .bool("encrypted", f.encrypted || f.encrypted_names)
        .bool("encrypted_names", f.encrypted_names)
        .bool("solid", f.solid)
        .num("volumes", u64::from(f.volumes))
        .str("encoding", l.tree.encoding.label())
        .opt_str("comment", comment.as_deref());
    writeln!(out, "{}", o.finish())
}

pub fn test_text(out: &mut impl Write, err: &mut impl Write, t: &Tested) -> io::Result<()> {
    for (i, reason) in &t.skipped {
        writeln!(err, "atlas-archive-cli: Left out item {i}: {reason}")?;
    }
    if t.skipped_more > 0 {
        writeln!(
            err,
            "atlas-archive-cli: {} more were left out.",
            count(t.skipped_more, "item", "items")
        )?;
    }
    if t.ok() {
        writeln!(out, "No errors found.")?;
    }
    Ok(())
}

pub fn test_json(out: &mut impl Write, t: &Tested) -> io::Result<()> {
    for (i, reason) in &t.skipped {
        let o = Obj::new().num("index", u64::from(*i)).str("reason", reason);
        writeln!(out, "{}", Obj::new().raw("skipped", &o.finish()).finish())?;
    }
    let summary = Obj::new()
        .bool("ok", t.ok())
        .num("skipped", t.skipped.len() as u64 + t.skipped_more)
        .finish();
    writeln!(out, "{}", Obj::new().raw("summary", &summary).finish())
}

pub fn extract_text(out: &mut impl Write, err: &mut impl Write, x: &Extraction) -> io::Result<()> {
    for (name, reason) in &x.skipped {
        writeln!(err, "atlas-archive-cli: Skipped {name}: {reason}")?;
    }
    if x.skipped_more > 0 {
        writeln!(
            err,
            "atlas-archive-cli: {} more were skipped.",
            count(x.skipped_more, "item", "items")
        )?;
    }
    for (path, reason) in &x.removed {
        writeln!(err, "atlas-archive-cli: Removed {path}: {reason}")?;
    }
    if x.left_out {
        writeln!(
            err,
            "atlas-archive-cli: An item with that name is already in {}, and Skip was chosen, so nothing was extracted.",
            term::safe_os(x.path.as_os_str())
        )
    } else {
        writeln!(out, "Extracted to {}", term::safe_os(x.path.as_os_str()))
    }
}

fn path_fields(o: Obj, path: &Path) -> Obj {
    let bytes = path.as_os_str().as_bytes();
    let o = o.str("path", &String::from_utf8_lossy(bytes));
    if std::str::from_utf8(bytes).is_err() {
        o.str("path_hex", &json::hex(bytes))
    } else {
        o
    }
}

pub fn extract_json(out: &mut impl Write, x: &Extraction) -> io::Result<()> {
    for (name, reason) in &x.skipped {
        let o = Obj::new().str("path", name).str("reason", reason);
        writeln!(out, "{}", Obj::new().raw("skipped", &o.finish()).finish())?;
    }
    for (path, reason) in &x.removed {
        let o = Obj::new().str("path", path).str("reason", reason);
        writeln!(out, "{}", Obj::new().raw("removed", &o.finish()).finish())?;
    }
    let summary = path_fields(Obj::new(), &x.path)
        .bool("left_out", x.left_out)
        .num("skipped", x.skipped.len() as u64 + x.skipped_more)
        .num("removed", x.removed.len() as u64)
        .finish();
    writeln!(out, "{}", Obj::new().raw("summary", &summary).finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_utc_civil_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00");
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13");
        assert_eq!(utc(-86_400), "1969-12-31 00:00");
        assert_eq!(utc(4_102_444_799), "2099-12-31 23:59");
    }

    #[test]
    fn counts_are_plural_only_when_needed() {
        assert_eq!(count(1, "file", "files"), "1 file");
        assert_eq!(count(0, "file", "files"), "0 files");
        assert_eq!(count(2, "entry", "entries"), "2 entries");
    }

    #[test]
    fn decoding_keeps_text_and_replaces_bad_bytes() {
        assert_eq!(decoded(b"a\xffb", NameEncoding::Utf8), "a\u{fffd}b");
        assert_eq!(decoded(b"caf\x82", NameEncoding::Cp437), "café");
        assert_eq!(displayed(b"a\x1bb", NameEncoding::Utf8), "a\\x1Bb");
    }
}
