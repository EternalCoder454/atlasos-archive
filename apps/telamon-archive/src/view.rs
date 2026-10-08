//! What the window shows, as plain data: the launch arguments, the rows of a
//! folder of the listing tree and the breadcrumb, as JSON for QML. No Qt here,
//! so it is tested without a display. Everything that comes from an archive
//! (names, reasons) is untrusted: QML shows it with `Text.PlainText`, and it is
//! cleaned of control and bidi characters here as well.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use telamon_archive_core::limits::format_size;
use telamon_archive_core::name::{is_bidi_control, is_control, is_invisible};
use telamon_archive_core::proto::Kind;
use telamon_archive_core::tree::{ROOT, Tree};

/// The most arguments one launch is read from; the rest are counted.
pub const MAX_ARGS: usize = 64;
/// The most rows one folder shows. A bigger folder says how many are left out.
pub const MAX_ROWS: usize = 20_000;
/// Past this many entries a folder is not sorted by name (the sort would hold
/// the window), only folders first.
const SORT_LIMIT: usize = 100_000;
/// The longest text kept from an archive or the worker, in characters.
const MAX_TEXT: usize = 500;

/// What a launch asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Open the (first) archive in the window.
    Open,
    /// `--extract-here`: into the archive's folder, each archive after another.
    ExtractHere,
    /// `--extract-to-folder`: into `<name>/` next to the archive.
    ExtractToFolder,
}

/// A launch, read from its arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct Launch {
    pub action: Action,
    pub files: Vec<PathBuf>,
    /// A plain sentence when something in the arguments was refused.
    pub problem: Option<String>,
}

/// Reads a launch's arguments (without the program name). Relative paths are
/// read against `cwd`; `file:` URLs are decoded; any other URL is refused.
pub fn parse_launch(args: &[String], cwd: &str) -> Launch {
    let mut action = Action::Open;
    let mut files = Vec::new();
    let mut problem = None;
    let mut options = true;
    for (n, arg) in args.iter().enumerate() {
        if n >= MAX_ARGS {
            problem = Some(format!(
                "Only the first {MAX_ARGS} files were read; the others were left out."
            ));
            break;
        }
        if options && arg == "--" {
            options = false;
        } else if options && arg == "--extract-here" {
            action = Action::ExtractHere;
        } else if options && arg == "--extract-to-folder" {
            action = Action::ExtractToFolder;
        } else if options && arg.starts_with('-') && arg.len() > 1 {
            problem =
                Some("Telamon Archive doesn't know one of the options it was started with.".into());
        } else {
            match local_path(arg, cwd) {
                Some(p) => files.push(p),
                None => {
                    problem =
                        Some("Only files on this computer can be opened, with a full path.".into())
                }
            }
        }
    }
    Launch {
        action,
        files,
        problem,
    }
}

/// The file a path or `file:` URL names; `None` for any other URL, a bad
/// escape, a NUL, or a relative path with no `cwd` to read it against.
pub fn local_path(text: &str, cwd: &str) -> Option<PathBuf> {
    if text.is_empty() || text.contains('\0') {
        return None;
    }
    let path = if let Some(rest) = text.strip_prefix("file://") {
        // `file:///x`, or `file://localhost/x`.
        let rest = rest.strip_prefix("localhost").unwrap_or(rest);
        if !rest.starts_with('/') {
            return None;
        }
        PathBuf::from(OsString::from_vec(percent_decode(rest)?))
    } else if text.contains("://") {
        return None;
    } else {
        PathBuf::from(text)
    };
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return None;
    }
    if path.is_absolute() {
        Some(path)
    } else if cwd.starts_with('/') {
        Some(PathBuf::from(cwd).join(path))
    } else {
        None
    }
}

fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Text from an archive or the worker, made safe to show: no controls, no
/// bidi or invisible characters, and not longer than `MAX_TEXT`.
pub fn clean(text: &str) -> String {
    let mut out = String::new();
    for (n, c) in text.chars().enumerate() {
        if n >= MAX_TEXT {
            out.push('…');
            break;
        }
        if is_control(c) || is_bidi_control(c) || is_invisible(c) {
            out.push('\u{FFFD}');
        } else {
            out.push(c);
        }
    }
    out
}

/// A JSON string literal.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn count_words(n: usize) -> String {
    if n == 1 {
        "1 item".into()
    } else {
        format!("{n} items")
    }
}

/// The rows of folder `id`: folders first, then by name. `{"rows": [...],
/// "total": n}`; `total` is more than the rows when the folder was cut.
pub fn folder_json(tree: &Tree, id: u32) -> String {
    let Some(node) = tree.nodes.get(id as usize) else {
        return r#"{"rows":[],"total":0}"#.into();
    };
    let mut kids: Vec<u32> = node
        .children
        .iter()
        .copied()
        .filter(|c| (*c as usize) < tree.nodes.len())
        .collect();
    let total = kids.len();
    let is_dir = |c: &u32| tree.nodes[*c as usize].kind == Kind::Dir;
    if total <= SORT_LIMIT {
        kids.sort_by(|a, b| {
            let (x, y) = (&tree.nodes[*a as usize], &tree.nodes[*b as usize]);
            (y.kind == Kind::Dir)
                .cmp(&(x.kind == Kind::Dir))
                .then_with(|| {
                    let lx = x.name.display.chars().flat_map(char::to_lowercase);
                    lx.cmp(y.name.display.chars().flat_map(char::to_lowercase))
                })
        });
    } else {
        kids.sort_by_key(|c| !is_dir(c));
    }
    kids.truncate(MAX_ROWS);
    let mut out = String::from("{\"rows\":[");
    for (n, c) in kids.iter().enumerate() {
        let k = &tree.nodes[*c as usize];
        if n > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"id\":{c},\"token\":\"{}\",\"name\":",
            tree.token(*c)
        ));
        json_str(&mut out, &clean(&k.name.display));
        let (icon, size) = match k.kind {
            Kind::Dir => ("folder", count_words(k.children.len())),
            Kind::Symlink | Kind::Hardlink => ("emblem-symbolic-link", String::new()),
            Kind::Special => ("text-x-generic", String::new()),
            Kind::File => ("text-x-generic", format_size(k.size)),
        };
        out.push_str(&format!(
            ",\"dir\":{},\"icon\":\"{icon}\",\"size\":",
            k.kind == Kind::Dir
        ));
        json_str(&mut out, &size);
        let ms = k.mtime.and_then(|s| s.checked_mul(1000)).unwrap_or(-1);
        out.push_str(&format!(",\"mtime\":{ms}}}"));
    }
    out.push_str(&format!("],\"total\":{total}}}"));
    out
}

/// The breadcrumb to folder `id`: the archive's name, then each folder.
pub fn crumbs_json(tree: &Tree, id: u32, archive_name: &str) -> String {
    let mut chain = Vec::new();
    let mut at = id;
    // The walk is bounded: a tree that loops would otherwise never end.
    while at != ROOT && chain.len() <= tree.nodes.len() {
        let Some(n) = tree.nodes.get(at as usize) else {
            break;
        };
        chain.push(at);
        at = n.parent;
    }
    chain.reverse();
    let mut out = String::from("[{\"id\":0,\"title\":");
    json_str(&mut out, archive_name);
    out.push('}');
    for c in chain {
        out.push_str(&format!(",{{\"id\":{c},\"title\":"));
        json_str(&mut out, &clean(&tree.nodes[c as usize].name.display));
        out.push('}');
    }
    out.push(']');
    out
}

/// The details list of a finished extraction: `{"rows": [{"name", "reason"}],
/// "more": n}`, `more` being what was left out of the list.
pub fn details_json(rows: &[(String, String)], more: u64) -> String {
    let mut out = String::from("{\"rows\":[");
    for (n, (name, reason)) in rows.iter().take(MAX_ROWS).enumerate() {
        if n > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        json_str(&mut out, name);
        out.push_str(",\"reason\":");
        json_str(&mut out, reason);
        out.push('}');
    }
    let cut = rows.len().saturating_sub(MAX_ROWS) as u64;
    out.push_str(&format!("],\"more\":{}}}", more.saturating_add(cut)));
    out
}

/// The folder above `id` (the root's is itself).
pub fn parent_of(tree: &Tree, id: u32) -> u32 {
    tree.nodes.get(id as usize).map_or(ROOT, |n| n.parent)
}

/// True when `id` is a folder of the tree.
pub fn is_folder(tree: &Tree, id: u32) -> bool {
    tree.nodes
        .get(id as usize)
        .is_some_and(|n| n.kind == Kind::Dir)
}

/// The listing names of the entries with these indices: for a skipped entry
/// the worker names only an index. One pass over the tree.
pub fn names_for(tree: &Tree, wanted: &[u32]) -> std::collections::HashMap<u32, String> {
    let mut out = std::collections::HashMap::new();
    if wanted.is_empty() {
        return out;
    }
    let want: std::collections::HashSet<u32> = wanted.iter().copied().collect();
    for (i, n) in tree.nodes.iter().enumerate() {
        if let Some(e) = n.entry
            && want.contains(&e)
        {
            out.insert(e, clean(&tree.display_path(i as u32)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn launch_reads_modes_and_files() {
        let l = parse_launch(&s(&["--extract-here", "a.zip", "/x/b.zip"]), "/home/u");
        assert_eq!(l.action, Action::ExtractHere);
        assert_eq!(
            l.files,
            vec![PathBuf::from("/home/u/a.zip"), PathBuf::from("/x/b.zip")]
        );
        assert!(l.problem.is_none());
    }

    #[test]
    fn after_dashes_nothing_is_an_option() {
        let l = parse_launch(&s(&["--", "--extract-here"]), "/h");
        assert_eq!(l.action, Action::Open);
        assert_eq!(l.files, vec![PathBuf::from("/h/--extract-here")]);
    }

    #[test]
    fn urls_are_decoded_or_refused() {
        assert_eq!(
            local_path("file:///a%20b/c.zip", ""),
            Some(PathBuf::from("/a b/c.zip"))
        );
        assert_eq!(local_path("https://x/y.zip", "/"), None);
        assert_eq!(local_path("file:///a%zz", ""), None);
        assert_eq!(local_path("file:///a%00", ""), None);
        assert_eq!(local_path("rel.zip", ""), None);
        assert_eq!(local_path("file://host/x", ""), None);
    }

    #[test]
    fn too_many_arguments_are_counted_out() {
        let many: Vec<String> = (0..70).map(|i| format!("/f{i}.zip")).collect();
        let l = parse_launch(&many, "/");
        assert_eq!(l.files.len(), MAX_ARGS);
        assert!(l.problem.is_some());
    }

    #[test]
    fn clean_replaces_controls_and_bidi() {
        assert_eq!(clean("a\u{202e}b\nc"), "a\u{FFFD}b\u{FFFD}c");
        assert!(clean(&"x".repeat(2000)).chars().count() <= MAX_TEXT + 1);
    }

    #[test]
    fn json_escapes() {
        let mut o = String::new();
        json_str(&mut o, "a\"b\\c\n");
        assert_eq!(o, "\"a\\\"b\\\\c\\u000a\"");
    }
}
