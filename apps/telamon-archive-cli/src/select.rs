//! Which entries `extract ARCHIVE ENTRY...` means, by the listing's paths.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;

use telamon_archive_core::tree::Tree;

use crate::term;

/// One folder's children by name: the id, or `None` when two share the name.
type ByName<'a> = HashMap<&'a str, Option<u32>>;

/// Name maps for the folders looked into, built on first use so a wide
/// folder costs one pass, not one per path component.
struct Lookup<'a> {
    tree: &'a Tree,
    maps: HashMap<u32, (ByName<'a>, ByName<'a>)>,
}

impl<'a> Lookup<'a> {
    fn new(tree: &'a Tree) -> Self {
        Lookup {
            tree,
            maps: HashMap::new(),
        }
    }

    /// The child of `parent` that `part` names: by display name first, by
    /// disk name only when no display name matches. `Ok(None)`: nothing
    /// matches; `Err`: more than one item does.
    fn child(&mut self, parent: u32, part: &str) -> Result<Option<u32>, ()> {
        let tree = self.tree;
        let (display, disk) = self.maps.entry(parent).or_insert_with(|| {
            let mut display = ByName::new();
            let mut disk = ByName::new();
            for &k in &tree.nodes[parent as usize].children {
                let n = &tree.nodes[k as usize].name;
                for (map, name) in [(&mut display, &n.display), (&mut disk, &n.disk)] {
                    map.entry(name.as_str())
                        .and_modify(|e| *e = None)
                        .or_insert(Some(k));
                }
            }
            (display, disk)
        });
        for map in [display, disk] {
            match map.get(part) {
                Some(Some(k)) => return Ok(Some(*k)),
                Some(None) => return Err(()),
                None => {}
            }
        }
        Ok(None)
    }
}

/// The archive indices of the named items. A name matches a path as listed
/// (display form) or as it would be written (disk form), one component at a
/// time down the tree; a folder brings everything inside it. An error is a
/// sentence naming what wasn't found, or what named more than one item.
pub fn resolve(tree: &Tree, wanted: &[OsString]) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    let mut lookup = Lookup::new(tree);
    for w in wanted {
        let text = w.to_string_lossy();
        let key = text.trim_start_matches("./").trim_end_matches('/');
        let mut at = Some(0u32);
        for part in key.split('/') {
            let Some(from) = at else { break };
            at = lookup.child(from, part).map_err(|()| {
                format!(
                    "\"{}\" names more than one item in this archive.",
                    term::safe_os(w)
                )
            })?;
        }
        let Some(start) = at.filter(|&id| id != 0) else {
            return Err(format!(
                "There is no item called \"{}\" in this archive.",
                term::safe_os(w)
            ));
        };
        let mut stack = vec![start];
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

/// The display path of each of the entries `wanted` (archive indices), for
/// messages. Paths are built for these only, not for every node.
pub fn names_for(tree: &Tree, wanted: HashSet<u32>) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    if wanted.is_empty() {
        return out;
    }
    for id in 1..tree.nodes.len() as u32 {
        if let Some(i) = tree.nodes[id as usize].entry
            && wanted.contains(&i)
        {
            out.insert(i, tree.display_path(id));
        }
    }
    for s in &tree.skipped {
        if wanted.contains(&s.index) {
            out.entry(s.index).or_insert_with(|| s.path.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use telamon_archive_core::proto::{Entry, Format, Kind};

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
    fn names_for_covers_refused_entries() {
        let n = names_for(&tree(), HashSet::from([1, 4]));
        assert_eq!(n.len(), 2);
        assert_eq!(n[&1], "docs/a.txt");
        assert!(n.contains_key(&4), "{n:?}");
    }

    #[test]
    fn components_match_one_level_at_a_time() {
        // Not a path as a whole: a part that is missing stops the search.
        assert!(pick(&["docs/nope/b.txt"]).is_err());
        assert!(pick(&["docs/a.txt/x"]).is_err());
        assert!(pick(&["docs//a.txt"]).is_err());
        assert!(pick(&[""]).is_err());
        assert!(pick(&["../escape"]).is_err());
        assert_eq!(pick(&["docs/sub/b.txt"]).unwrap(), [2]);
    }

    #[test]
    fn the_disk_form_is_the_way_in_when_no_display_name_matches() {
        let entries = [
            entry(0, "we\u{1}ird.txt", Kind::File),
            entry(1, "we_ird.txt", Kind::File),
            entry(2, "d\u{1}/in.txt", Kind::File),
        ];
        let t = Tree::build(format(), &entries, None);
        let one = |n: &str| resolve(&t, &[OsString::from(n)]);
        // As the listing shows each, and by the disk name of the first.
        assert_eq!(one("we\\x01ird.txt").unwrap(), [0]);
        assert_eq!(one("we_ird (2).txt").unwrap(), [1]);
        assert_eq!(one("we_ird.txt").unwrap(), [0]);
        // A folder reached by its disk name, with a display name below it.
        assert_eq!(one("d_/in.txt").unwrap(), [2]);
    }

    #[test]
    fn a_wide_folder_is_looked_up_fast() {
        let entries: Vec<Entry> = (0..50_000)
            .map(|i| entry(i, &format!("wide/file{i}.txt"), Kind::File))
            .collect();
        let t = Tree::build(format(), &entries, None);
        let wanted: Vec<OsString> = (0..5_000)
            .map(|i| OsString::from(format!("wide/file{}.txt", i * 10)))
            .collect();
        let start = std::time::Instant::now();
        let got = resolve(&t, &wanted).unwrap();
        assert_eq!(got.len(), 5_000);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }
}
