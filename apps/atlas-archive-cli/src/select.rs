//! Which entries `extract ARCHIVE ENTRY...` means, by the listing's paths.

use std::collections::HashMap;
use std::ffi::OsString;

use atlas_archive_core::tree::Tree;

use crate::term;

/// The archive indices of the named items. A name matches a path as listed
/// (display form) or as it would be written (disk form); a folder brings
/// everything inside it. An error is a sentence naming what wasn't found.
pub fn resolve(tree: &Tree, wanted: &[OsString]) -> Result<Vec<u32>, String> {
    let mut by_path: HashMap<String, Vec<u32>> = HashMap::new();
    for id in 1..tree.nodes.len() as u32 {
        for path in [tree.display_path(id), tree.disk_path(id)] {
            let ids = by_path.entry(path).or_default();
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    let mut out = Vec::new();
    for w in wanted {
        let text = w.to_string_lossy();
        let key = text.trim_start_matches("./").trim_end_matches('/');
        let Some(ids) = by_path.get(key) else {
            return Err(format!(
                "There is no item called \"{}\" in this archive.",
                term::safe_os(w)
            ));
        };
        let mut stack: Vec<u32> = ids.clone();
        while let Some(id) = stack.pop() {
            let node = &tree.nodes[id as usize];
            if let Some(i) = node.entry {
                out.push(i);
            }
            stack.extend(&node.children);
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err("Nothing in this archive matches what was asked for.".into());
    }
    Ok(out)
}

/// Each entry's path in display form, by archive index, for messages.
pub fn names_by_index(tree: &Tree) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    for id in 1..tree.nodes.len() as u32 {
        if let Some(i) = tree.nodes[id as usize].entry {
            out.insert(i, tree.display_path(id));
        }
    }
    for s in &tree.skipped {
        out.entry(s.index).or_insert_with(|| s.path.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_archive_core::proto::{Entry, Format, Kind};

    fn format() -> Format {
        Format {
            name: "zip".into(),
            encrypted: false,
            encrypted_names: false,
            solid: false,
            compressed_file: false,
            volumes: 1,
            made_on_dos: false,
            comment: None,
        }
    }

    fn entry(index: u32, path: &str, kind: Kind) -> Entry {
        Entry {
            index,
            path: path.as_bytes().to_vec(),
            kind,
            size: Some(1),
            packed: None,
            mtime: None,
            mode: 0o644,
            encrypted: false,
            utf8: true,
            link: None,
        }
    }

    fn tree() -> Tree {
        let entries = [
            entry(0, "docs/", Kind::Dir),
            entry(1, "docs/a.txt", Kind::File),
            entry(2, "docs/sub/b.txt", Kind::File),
            entry(3, "top.txt", Kind::File),
            entry(4, "../escape", Kind::File),
        ];
        Tree::build(format(), &entries, None)
    }

    fn pick(names: &[&str]) -> Result<Vec<u32>, String> {
        let w: Vec<OsString> = names.iter().map(OsString::from).collect();
        resolve(&tree(), &w)
    }

    #[test]
    fn a_file_is_found_by_its_path() {
        assert_eq!(pick(&["top.txt"]).unwrap(), [3]);
        assert_eq!(pick(&["docs/a.txt", "top.txt"]).unwrap(), [1, 3]);
    }

    #[test]
    fn a_folder_brings_what_is_inside() {
        assert_eq!(pick(&["docs"]).unwrap(), [0, 1, 2]);
        assert_eq!(pick(&["docs/"]).unwrap(), [0, 1, 2]);
        assert_eq!(pick(&["./docs/sub"]).unwrap(), [2]);
    }

    #[test]
    fn repeats_are_merged() {
        assert_eq!(
            pick(&["docs/a.txt", "docs", "docs/a.txt"]).unwrap(),
            [0, 1, 2]
        );
    }

    #[test]
    fn a_missing_item_is_named_safely() {
        let e = pick(&["nope\x1b[2J"]).unwrap_err();
        assert!(e.contains("nope"), "{e}");
        assert!(!e.contains('\x1b'), "{e}");
        assert!(pick(&["docs/a.txt", "gone"]).is_err());
    }

    #[test]
    fn names_by_index_include_refused_entries() {
        let n = names_by_index(&tree());
        assert_eq!(n[&1], "docs/a.txt");
        assert!(n.contains_key(&4), "{n:?}");
    }
}
