//! The archive tree: every entry placed in its folder, with the name it is
//! shown as and the name it is written as (docs/DESIGN.md, "Archives as
//! folders").
//!
//! Both sides build it from the same listing with the same code: the window
//! and the CLI to show the archive, the worker to decide what it writes. So
//! what the user saw is what lands on disk, including every rename:
//!
//! - Entries whose paths are refused (`path`) are skipped, with the reason.
//! - Folders the archive doesn't list but its paths imply are made up.
//! - A folder wins its name: a file, link or device with a folder's name is
//!   kept as `name (2)`. Two entries whose names differ in the archive but
//!   are the same on disk (after sanitising) are kept as `name (2)` too.
//! - The same path stored twice: the later entry wins, as tar does, and the
//!   earlier one is skipped.
//! - Symbolic links are checked with `link::check_symlink` against the whole
//!   tree; hard links must name a regular file stored before them. Devices,
//!   FIFOs and sockets are listed and never created.

use std::collections::HashMap;

use crate::link::{self, LinkError, SymlinkTarget};
use crate::name::{self, NameEncoding};
use crate::path::{self, Component};
use crate::proto::{Entry, Format, Kind};

/// The root folder's id.
pub const ROOT: u32 = 0;

/// Why an entry is listed but not written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    Path(path::PathError),
    Link(LinkError),
    /// A hard link to something that isn't a regular file stored before it.
    HardlinkTarget,
    /// A device, FIFO or socket.
    Special,
}

impl Refused {
    /// The reason, in plain words.
    pub fn reason(&self) -> String {
        match self {
            Refused::Path(e) => e.to_string(),
            Refused::Link(e) => e.to_string(),
            Refused::HardlinkTarget => "The link points to something that isn't a file stored earlier in the archive.".into(),
            Refused::Special => "Devices, pipes and sockets are never created.".into(),
        }
    }
}

/// An entry that isn't in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skip {
    /// The archive index.
    pub index: u32,
    /// The path in display form.
    pub path: String,
    pub reason: String,
}

/// One file, folder or link.
#[derive(Clone, Debug)]
pub struct Node {
    /// The folder it is in (the root's is itself).
    pub parent: u32,
    pub name: Component,
    pub kind: Kind,
    /// The archive index; `None` for folders the archive doesn't list.
    pub entry: Option<u32>,
    /// Unpacked size; for folders, everything inside.
    pub size: u64,
    pub packed: Option<u64>,
    pub mtime: Option<i64>,
    pub mode: u32,
    pub encrypted: bool,
    /// A symbolic link's target, checked.
    pub symlink: Option<SymlinkTarget>,
    /// A hard link's target node.
    pub hardlink: Option<u32>,
    /// Shown but not written, and why.
    pub refused: Option<Refused>,
    pub children: Vec<u32>,
}

/// The tree of one archive.
#[derive(Clone, Debug)]
pub struct Tree {
    pub format: Format,
    /// The encoding names not marked UTF-8 were read with.
    pub encoding: NameEncoding,
    pub nodes: Vec<Node>,
    /// Entries not in the tree (refused paths, earlier duplicates).
    pub skipped: Vec<Skip>,
    /// Files, links and devices (not folders).
    pub files: u64,
    pub folders: u64,
    /// Some name holds controls, bidi characters or undecodable bytes.
    pub unusual_names: bool,
    by_name: HashMap<(u32, Box<str>), u32>,
    /// Raw path of each non-folder node, to tell a duplicate from a clash.
    raw_of: HashMap<u32, Box<[u8]>>,
    links: Vec<PendingLink>,
}

/// What `Tree::add` did with an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Added {
    /// Its path was refused; it is in `skipped`.
    Skipped,
    Node {
        id: u32,
        /// A node already placed had to give up its name to a folder: it is
        /// now `name (2)`. `from` is its old disk path, for a writer that has
        /// written it already.
        moved: Option<Moved>,
        /// The same path was stored before (this archive index); this entry
        /// replaces it. A writer removes what it wrote for the earlier one.
        replaced: Option<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Moved {
    pub node: u32,
    pub from: String,
}

/// A link entry's target, resolved once every path is known.
#[derive(Clone, Debug)]
struct PendingLink {
    node: u32,
    index: u32,
    target: Vec<u8>,
    encoding: NameEncoding,
}

impl Tree {
    /// Builds the tree from a whole listing. `encoding`: the user's choice,
    /// or `None` to detect it from the names not marked UTF-8.
    pub fn build(format: Format, entries: &[Entry], encoding: Option<NameEncoding>) -> Tree {
        let encoding = encoding.unwrap_or_else(|| {
            name::detect(entries.iter().filter(|e| !e.utf8).map(|e| e.path.as_slice()), format.made_on_dos)
        });
        let mut t = Tree::new(format, encoding);
        t.by_name.reserve(entries.len());
        for e in entries {
            t.add(e);
        }
        t.finish();
        t
    }

    /// An empty tree, for building one entry at a time as a streamed archive
    /// is read (`add`, then `finish`). The encoding can't be detected then:
    /// it is the one chosen when the archive was listed, or UTF-8.
    pub fn new(format: Format, encoding: NameEncoding) -> Tree {
        let root = Node {
            parent: ROOT,
            name: Component { display: String::new(), disk: String::new(), unusual: false, renamed: false },
            kind: Kind::Dir,
            entry: None,
            size: 0,
            packed: None,
            mtime: None,
            mode: 0o755,
            encrypted: false,
            symlink: None,
            hardlink: None,
            refused: None,
            children: Vec::new(),
        };
        Tree {
            format,
            encoding,
            nodes: vec![root],
            skipped: Vec::new(),
            files: 0,
            folders: 0,
            unusual_names: false,
            by_name: HashMap::new(),
            raw_of: HashMap::new(),
            links: Vec::new(),
        }
    }

    /// Places one entry. Links are placed but checked only by `finish`.
    pub fn add(&mut self, e: &Entry) -> Added {
        let enc = if e.utf8 { NameEncoding::Utf8 } else { self.encoding };
        let p = match path::parse(&e.path, enc, self.format.made_on_dos) {
            Ok(p) => p,
            Err(err) => {
                self.skip(e, enc, err.to_string());
                return Added::Skipped;
            }
        };
        let (last, dirs) = p.components.split_last().expect("at least one component");
        let mut at = ROOT;
        let mut moved = None;
        for c in dirs {
            let (id, m) = self.folder(at, c, None);
            at = id;
            moved = moved.or(m);
        }
        if e.kind == Kind::Dir {
            let (id, m) = self.folder(at, last, Some(e));
            return Added::Node { id, moved: moved.or(m), replaced: None };
        }
        if let Some(&old) = self.by_name.get(&(at, last.disk.as_str().into()))
            && self.nodes[old as usize].kind != Kind::Dir
            && self.raw_of.get(&old).is_some_and(|r| **r == *e.path)
        {
            // Stored twice: the later one wins.
            let old_index = self.nodes[old as usize].entry.expect("listed");
            self.skipped.push(Skip {
                index: old_index,
                path: p.display_path(),
                reason: "A later item in the archive has the same name.".into(),
            });
            self.links.retain(|l| l.node != old);
            self.set_entry(old, e);
            self.pend_link(old, e, enc);
            return Added::Node { id: old, moved, replaced: Some(old_index) };
        }
        let mut name = last.clone();
        self.free_name(at, &mut name);
        let id = self.push(at, name, e.kind);
        self.set_entry(id, e);
        self.raw_of.insert(id, e.path.clone().into_boxed_slice());
        self.pend_link(id, e, enc);
        Added::Node { id, moved, replaced: None }
    }

    fn pend_link(&mut self, node: u32, e: &Entry, encoding: NameEncoding) {
        if matches!(e.kind, Kind::Symlink | Kind::Hardlink) {
            let target = e.link.clone().unwrap_or_default();
            self.links.push(PendingLink { node, index: e.index, target, encoding });
        }
    }

    /// Checks links against the whole tree, refuses devices, and adds up
    /// folder sizes and counts. Call once, after the last `add`.
    pub fn finish(&mut self) {
        let links = std::mem::take(&mut self.links);
        for l in &links {
            let id = l.node;
            let refused = match self.nodes[id as usize].kind {
                Kind::Symlink => {
                    let at = self.entry_path(id);
                    match link::check_symlink(&at, &l.target, l.encoding, self.format.made_on_dos, |p| {
                        self.is_symlink(p)
                    }) {
                        Ok(s) => {
                            self.nodes[id as usize].symlink = Some(s);
                            None
                        }
                        Err(err) => Some(Refused::Link(err)),
                    }
                }
                _ => {
                    let target = link::check_hardlink(&l.target, l.encoding, self.format.made_on_dos)
                        .ok()
                        .and_then(|p| self.find(p.components.iter().map(|c| c.disk.as_str())));
                    match target {
                        Some(to)
                            if self.nodes[to as usize].kind == Kind::File
                                && self.nodes[to as usize].entry.is_some_and(|i| i < l.index) =>
                        {
                            self.nodes[id as usize].hardlink = Some(to);
                            self.nodes[id as usize].size = self.nodes[to as usize].size;
                            None
                        }
                        _ => Some(Refused::HardlinkTarget),
                    }
                }
            };
            self.nodes[id as usize].refused = refused;
        }
        for n in &mut self.nodes[1..] {
            if n.kind == Kind::Special {
                n.refused = Some(Refused::Special);
            }
        }

        // Folder sizes: a child's id is always above its folder's.
        for id in (1..self.nodes.len()).rev() {
            let (size, parent) = (self.nodes[id].size, self.nodes[id].parent as usize);
            self.nodes[parent].size = self.nodes[parent].size.saturating_add(size);
        }
        for n in &self.nodes[1..] {
            if n.kind == Kind::Dir {
                self.folders += 1;
            } else {
                self.files += 1;
            }
            self.unusual_names |= n.name.unusual;
        }
        self.raw_of = HashMap::new();
    }

    fn skip(&mut self, e: &Entry, enc: NameEncoding, reason: String) {
        let mut pieces = Vec::new();
        name::decode(&e.path, enc, |p| pieces.push(p));
        self.unusual_names = true;
        self.skipped.push(Skip { index: e.index, path: name::display(&pieces).0, reason });
    }

    fn push(&mut self, parent: u32, name: Component, kind: Kind) -> u32 {
        let id = self.nodes.len() as u32;
        self.by_name.insert((parent, name.disk.as_str().into()), id);
        self.nodes.push(Node {
            parent,
            name,
            kind,
            entry: None,
            size: 0,
            packed: None,
            mtime: None,
            mode: if kind == Kind::Dir { 0o755 } else { 0o644 },
            encrypted: false,
            symlink: None,
            hardlink: None,
            refused: None,
            children: Vec::new(),
        });
        self.nodes[parent as usize].children.push(id);
        id
    }

    fn set_entry(&mut self, id: u32, e: &Entry) {
        let n = &mut self.nodes[id as usize];
        n.entry = Some(e.index);
        n.kind = e.kind;
        n.size = if e.kind == Kind::Dir { 0 } else { e.size.unwrap_or(0) };
        n.packed = e.packed;
        n.mtime = e.mtime;
        n.mode = e.mode;
        n.encrypted = e.encrypted;
    }

    /// The folder `c` in `parent`, made if missing. A non-folder holding the
    /// name moves to `name (2)`, and is returned as moved.
    fn folder(&mut self, parent: u32, c: &Component, entry: Option<&Entry>) -> (u32, Option<Moved>) {
        let key = (parent, Box::<str>::from(c.disk.as_str()));
        let mut moved = None;
        let id = match self.by_name.get(&key) {
            Some(&id) if self.nodes[id as usize].kind == Kind::Dir => id,
            Some(&other) => {
                let from = self.disk_path(other);
                // Numbered while the name is still taken, then moved.
                let mut name = self.nodes[other as usize].name.clone();
                self.free_name(parent, &mut name);
                self.by_name.remove(&key);
                self.by_name.insert((parent, name.disk.as_str().into()), other);
                self.nodes[other as usize].name = name;
                moved = Some(Moved { node: other, from });
                self.push(parent, c.clone(), Kind::Dir)
            }
            None => self.push(parent, c.clone(), Kind::Dir),
        };
        if let Some(e) = entry {
            self.set_entry(id, e);
        }
        (id, moved)
    }

    /// Numbers `name` until no sibling holds its disk form.
    fn free_name(&self, parent: u32, name: &mut Component) {
        if !self.by_name.contains_key(&(parent, name.disk.as_str().into())) {
            return;
        }
        for n in 2.. {
            let disk = name::numbered(&name.disk, n);
            if !self.by_name.contains_key(&(parent, disk.as_str().into())) {
                name.display = name::numbered(&name.display, n);
                name.disk = disk;
                name.renamed = true;
                return;
            }
        }
    }

    fn is_symlink(&self, disk: &[String]) -> bool {
        self.find(disk.iter().map(String::as_str))
            .is_some_and(|id| self.nodes[id as usize].kind == Kind::Symlink)
    }

    /// The node at a path of disk names from the root.
    pub fn find<'a>(&self, disk: impl IntoIterator<Item = &'a str>) -> Option<u32> {
        let mut at = ROOT;
        for part in disk {
            at = *self.by_name.get(&(at, part.into()))?;
        }
        Some(at)
    }

    /// The child of `parent` with this disk name.
    pub fn child(&self, parent: u32, disk: &str) -> Option<u32> {
        self.by_name.get(&(parent, disk.into())).copied()
    }

    fn ancestry(&self, mut id: u32) -> Vec<u32> {
        let mut out = Vec::new();
        while id != ROOT {
            out.push(id);
            id = self.nodes[id as usize].parent;
        }
        out.reverse();
        out
    }

    fn entry_path(&self, id: u32) -> path::EntryPath {
        path::EntryPath {
            components: self.ancestry(id).into_iter().map(|i| self.nodes[i as usize].name.clone()).collect(),
            dir_hint: false,
        }
    }

    /// A node's path from the root, in disk form.
    pub fn disk_path(&self, id: u32) -> String {
        let parts: Vec<&str> = self.ancestry(id).into_iter().map(|i| self.nodes[i as usize].name.disk.as_str()).collect();
        parts.join("/")
    }

    /// A node's path from the root, in display form.
    pub fn display_path(&self, id: u32) -> String {
        let parts: Vec<&str> =
            self.ancestry(id).into_iter().map(|i| self.nodes[i as usize].name.display.as_str()).collect();
        parts.join("/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt() -> Format {
        Format {
            name: "zip".into(),
            encrypted: false,
            encrypted_names: false,
            solid: false,
            volumes: 1,
            made_on_dos: false,
            comment: None,
        }
    }

    fn e(index: u32, path: &str, kind: Kind) -> Entry {
        Entry {
            index,
            path: path.as_bytes().to_vec(),
            kind,
            size: Some(10),
            packed: Some(5),
            mtime: None,
            mode: 0o644,
            encrypted: false,
            utf8: true,
            link: None,
        }
    }

    fn link(index: u32, path: &str, kind: Kind, to: &str) -> Entry {
        Entry { link: Some(to.as_bytes().to_vec()), ..e(index, path, kind) }
    }

    fn paths(t: &Tree) -> Vec<String> {
        let mut v: Vec<String> = (1..t.nodes.len() as u32).map(|i| t.disk_path(i)).collect();
        v.sort();
        v
    }

    #[test]
    fn implied_folders_and_sizes() {
        let t = Tree::build(fmt(), &[e(0, "a/b/c.txt", Kind::File), e(1, "a/d.txt", Kind::File), e(2, "a/", Kind::Dir)], None);
        assert_eq!(paths(&t), ["a", "a/b", "a/b/c.txt", "a/d.txt"]);
        assert_eq!(t.nodes[ROOT as usize].size, 20);
        let a = t.find(["a"]).unwrap();
        assert_eq!(t.nodes[a as usize].entry, Some(2));
        assert_eq!(t.nodes[t.find(["a", "b"]).unwrap() as usize].entry, None);
        assert_eq!((t.files, t.folders), (2, 2));
    }

    #[test]
    fn refused_paths_are_skipped() {
        let t = Tree::build(fmt(), &[e(0, "../evil", Kind::File), e(1, "/etc/x", Kind::File), e(2, "ok", Kind::File)], None);
        assert_eq!(paths(&t), ["ok"]);
        assert_eq!(t.skipped.len(), 2);
        assert_eq!(t.skipped[0].path, "../evil");
        assert!(t.skipped[0].reason.contains(".."));
    }

    #[test]
    fn folders_win_their_name() {
        // A file "x", then a file inside a folder "x".
        let t = Tree::build(fmt(), &[e(0, "x", Kind::File), e(1, "x/y", Kind::File)], None);
        assert_eq!(paths(&t), ["x", "x (2)", "x/y"]);
        assert_eq!(t.nodes[t.find(["x (2)"]).unwrap() as usize].entry, Some(0));
        // The other order.
        let t = Tree::build(fmt(), &[e(0, "x/y", Kind::File), e(1, "x", Kind::File)], None);
        assert_eq!(paths(&t), ["x", "x (2)", "x/y"]);
        assert_eq!(t.nodes[t.find(["x (2)"]).unwrap() as usize].entry, Some(1));
    }

    #[test]
    fn same_disk_name_is_numbered_same_path_is_replaced() {
        let t = Tree::build(fmt(), &[e(0, "a\x01", Kind::File), e(1, "a\x02", Kind::File)], None);
        assert_eq!(paths(&t), ["a_", "a_ (2)"]);
        assert!(t.unusual_names);
        let t = Tree::build(fmt(), &[e(0, "f", Kind::File), e(1, "f", Kind::File)], None);
        assert_eq!(paths(&t), ["f"]);
        assert_eq!(t.nodes[t.find(["f"]).unwrap() as usize].entry, Some(1));
        assert_eq!(t.skipped.len(), 1);
        assert_eq!(t.skipped[0].index, 0);
    }

    #[test]
    fn symlink_then_file_cannot_escape() {
        // The classic: a link "l" -> "/", then "l/etc/passwd".
        let t = Tree::build(fmt(), &[link(0, "l", Kind::Symlink, "/"), e(1, "l/etc/passwd", Kind::File)], None);
        // "l" is a real folder; the link is kept as "l (2)", refused.
        let l = t.find(["l"]).unwrap();
        assert_eq!(t.nodes[l as usize].kind, Kind::Dir);
        let l2 = t.find(["l (2)"]).unwrap();
        assert_eq!(t.nodes[l2 as usize].refused, Some(Refused::Link(LinkError::Absolute)));
        // A link to "." then a link through it.
        let t = Tree::build(
            fmt(),
            &[link(0, "d", Kind::Symlink, "."), link(1, "e", Kind::Symlink, "d/d/../..")],
            None,
        );
        assert!(t.nodes[t.find(["d"]).unwrap() as usize].refused.is_none());
        assert_eq!(
            t.nodes[t.find(["e"]).unwrap() as usize].refused,
            Some(Refused::Link(LinkError::ThroughLink))
        );
    }

    #[test]
    fn hardlinks_need_an_earlier_file() {
        let t = Tree::build(
            fmt(),
            &[
                e(0, "f", Kind::File),
                link(1, "ok", Kind::Hardlink, "f"),
                link(2, "early", Kind::Hardlink, "g"),
                e(3, "g", Kind::File),
                link(4, "out", Kind::Hardlink, "../../etc/shadow"),
                link(5, "dir", Kind::Hardlink, "sub"),
                e(6, "sub/", Kind::Dir),
            ],
            None,
        );
        let get = |p: &str| t.nodes[t.find([p]).unwrap() as usize].clone();
        assert_eq!(get("ok").hardlink, t.find(["f"]));
        assert_eq!(get("ok").refused, None);
        for p in ["early", "out", "dir"] {
            assert_eq!(get(p).refused, Some(Refused::HardlinkTarget), "{p}");
        }
    }

    #[test]
    fn devices_are_listed_not_made() {
        let t = Tree::build(fmt(), &[e(0, "dev/sda", Kind::Special)], None);
        assert_eq!(t.nodes[t.find(["dev", "sda"]).unwrap() as usize].refused, Some(Refused::Special));
    }

    #[test]
    fn legacy_names_are_detected() {
        let mut f = fmt();
        f.made_on_dos = true;
        // CP437, as Windows' own zip writes names in a German locale.
        let raw: [&[u8]; 3] = [b"Gr\x81\xE1e an M\x81ller.txt", b"\x9Abersicht der Kosten.doc", b"\x8Enderungen f\x81r M\x84rz.txt"];
        let entries: Vec<Entry> = raw
            .iter()
            .enumerate()
            .map(|(i, r)| Entry { path: r.to_vec(), utf8: false, ..e(i as u32, "", Kind::File) })
            .collect();
        let t = Tree::build(f, &entries, None);
        assert_eq!(t.encoding, NameEncoding::Cp437);
        assert_eq!(paths(&t), ["Grüße an Müller.txt", "Änderungen für März.txt", "Übersicht der Kosten.doc"]);
    }

    #[test]
    fn dos_separators() {
        let mut f = fmt();
        f.made_on_dos = true;
        let t = Tree::build(f, &[e(0, "a\\b.txt", Kind::File)], None);
        assert_eq!(paths(&t), ["a", "a/b.txt"]);
    }

    #[test]
    fn one_pass_reports_moves_and_replacements() {
        let mut t = Tree::new(fmt(), NameEncoding::Utf8);
        let Added::Node { id: x, .. } = t.add(&e(0, "x", Kind::File)) else { panic!() };
        // A folder needs "x": the file moves, and the writer is told.
        let Added::Node { moved, .. } = t.add(&e(1, "x/y", Kind::File)) else { panic!() };
        assert_eq!(moved, Some(Moved { node: x, from: "x".into() }));
        assert_eq!(t.disk_path(x), "x (2)");
        // The same path again replaces it.
        let Added::Node { id, replaced, .. } = t.add(&e(2, "x/y", Kind::File)) else { panic!() };
        assert_eq!(replaced, Some(1));
        assert_eq!(t.disk_path(id), "x/y");
        assert_eq!(t.add(&e(3, "../z", Kind::File)), Added::Skipped);
        t.finish();
        assert_eq!((t.files, t.folders), (2, 1));
        assert_eq!(t.skipped.len(), 2);
    }

    #[test]
    fn a_replaced_link_is_checked_as_its_last_version() {
        let t = Tree::build(
            fmt(),
            &[link(0, "l", Kind::Symlink, "ok"), link(1, "l", Kind::Symlink, "../../escape")],
            None,
        );
        assert_eq!(t.nodes[t.find(["l"]).unwrap() as usize].refused, Some(Refused::Link(LinkError::Escapes)));
        let t = Tree::build(
            fmt(),
            &[link(0, "l", Kind::Symlink, "/abs"), link(1, "l", Kind::Symlink, "ok")],
            None,
        );
        let n = &t.nodes[t.find(["l"]).unwrap() as usize];
        assert_eq!(n.refused, None);
        assert_eq!(n.symlink.as_ref().unwrap().disk, "ok");
    }

    #[test]
    fn fifty_thousand_entries() {
        let entries: Vec<Entry> =
            (0..50_000).map(|i| e(i, &format!("d{}/s{}/file{i}.txt", i % 100, i % 7), Kind::File)).collect();
        let start = std::time::Instant::now();
        let t = Tree::build(fmt(), &entries, None);
        let took = start.elapsed();
        assert_eq!(t.files, 50_000);
        assert!(took.as_millis() < 2000, "{took:?}");
    }
}
