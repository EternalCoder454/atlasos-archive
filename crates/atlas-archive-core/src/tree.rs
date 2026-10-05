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

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher, RandomState};

use crate::link::{self, LinkError, SymlinkTarget};
use crate::name::{self, NameEncoding};
use crate::path::{self, Component};
use crate::proto::{Entry, Format, Kind};

/// The root folder's id.
pub const ROOT: u32 = 0;

/// The most nodes a tree holds (each path can imply up to 255 folders, so
/// this, not the entry count, bounds memory). Past it, entries are skipped
/// and `overflow` is set.
pub const MAX_NODES: usize = 1_000_000;
/// The most skipped entries kept with their reasons; the rest are counted.
pub const MAX_SKIPPED: usize = 10_000;

/// A child's key: its folder and disk name. Looked up as `(u32, &str)`
/// through `KeyRef`, so a lookup never allocates.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key(u32, Box<str>);

trait KeyRef {
    fn key(&self) -> (u32, &str);
}

impl KeyRef for Key {
    fn key(&self) -> (u32, &str) {
        (self.0, &self.1)
    }
}

impl KeyRef for (u32, &str) {
    fn key(&self) -> (u32, &str) {
        *self
    }
}

impl<'a> Borrow<dyn KeyRef + 'a> for Key {
    fn borrow(&self) -> &(dyn KeyRef + 'a) {
        self
    }
}

impl Hash for dyn KeyRef + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Must match the derived Hash of Key: the u32, then the str.
        let (p, n) = self.key();
        p.hash(state);
        n.hash(state);
    }
}

impl PartialEq for dyn KeyRef + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for dyn KeyRef + '_ {}

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
            Refused::HardlinkTarget => {
                "The link points to something that isn't a file stored earlier in the archive."
                    .into()
            }
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
    /// Skipped entries past `MAX_SKIPPED`, counted only.
    pub skipped_more: u64,
    /// The archive implies more than `MAX_NODES` items; the rest were
    /// skipped. A client says so instead of showing part of the archive.
    pub overflow: bool,
    /// The one item at the top, when `Extract here` may move it out of
    /// staging as it is: a folder whose links all point inside it, or a
    /// regular file; never a link or a hidden (dot) item. Set by `finish`.
    pub lone_top: Option<u32>,
    by_name: HashMap<Key, u32>,
    /// Where numbering resumes for a name that is taken (`name (n)`), so a
    /// thousand entries with one disk name cost a thousand probes, not a
    /// million.
    next_number: HashMap<Key, u32>,
    /// Keyed hash of each non-folder node's raw path, to tell a duplicate
    /// from a clash without keeping the path (an archive can hold a million
    /// long ones). The key is random per tree, so no entry can be built to
    /// collide.
    raw_of: HashMap<u32, u64>,
    hasher: RandomState,
    /// Link entries by node: a later duplicate replaces the earlier one.
    links: HashMap<u32, PendingLink>,
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

impl link::Lookup for Tree {
    fn child(&self, parent: u32, disk: &str) -> Option<u32> {
        Tree::child(self, parent, disk)
    }
    fn is_symlink(&self, node: u32) -> bool {
        self.nodes[node as usize].kind == Kind::Symlink
    }
}

impl Tree {
    /// Builds the tree from a whole listing. `encoding`: the user's choice,
    /// or `None` to detect it from the names not marked UTF-8.
    pub fn build(format: Format, entries: &[Entry], encoding: Option<NameEncoding>) -> Tree {
        let encoding = encoding.unwrap_or_else(|| {
            name::detect(
                entries
                    .iter()
                    .filter(|e| !e.utf8)
                    .map(|e| e.path.as_slice()),
                format.made_on_dos,
            )
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
            name: Component {
                display: String::new(),
                disk: String::new(),
                unusual: false,
                renamed: false,
            },
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
            skipped_more: 0,
            overflow: false,
            lone_top: None,
            by_name: HashMap::new(),
            next_number: HashMap::new(),
            raw_of: HashMap::new(),
            hasher: RandomState::new(),
            links: HashMap::new(),
        }
    }

    /// Places one entry. Links are placed but checked only by `finish`.
    pub fn add(&mut self, e: &Entry) -> Added {
        let enc = if e.utf8 {
            NameEncoding::Utf8
        } else {
            self.encoding
        };
        let p = match path::parse(&e.path, enc, self.format.made_on_dos) {
            Ok(p) => p,
            Err(err) => {
                self.skip(e, enc, err.to_string());
                return Added::Skipped;
            }
        };
        if self.nodes.len() + p.components.len() > MAX_NODES {
            self.overflow = true;
            self.skip(
                e,
                enc,
                "The archive holds more items than Atlas Archive can open.".into(),
            );
            return Added::Skipped;
        }
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
            return Added::Node {
                id,
                moved: moved.or(m),
                replaced: None,
            };
        }
        if let Some(old) = self.child(at, &last.disk)
            && self.nodes[old as usize].kind != Kind::Dir
            && self.raw_of.get(&old) == Some(&self.hasher.hash_one(&e.path[..]))
        {
            // Stored twice: the later one wins.
            let old_index = self.nodes[old as usize].entry.expect("listed");
            self.push_skip(Skip {
                index: old_index,
                path: p.display_path(),
                reason: "A later item in the archive has the same name.".into(),
            });
            self.links.remove(&old);
            self.set_entry(old, e);
            self.pend_link(old, e, enc);
            return Added::Node {
                id: old,
                moved,
                replaced: Some(old_index),
            };
        }
        let mut name = last.clone();
        self.free_name(at, &mut name);
        let id = self.push(at, name, e.kind);
        self.set_entry(id, e);
        let h = self.hasher.hash_one(&e.path[..]);
        self.raw_of.insert(id, h);
        self.pend_link(id, e, enc);
        Added::Node {
            id,
            moved,
            replaced: None,
        }
    }

    fn pend_link(&mut self, node: u32, e: &Entry, encoding: NameEncoding) {
        if matches!(e.kind, Kind::Symlink | Kind::Hardlink) {
            let target = e.link.clone().unwrap_or_default();
            self.links.insert(
                node,
                PendingLink {
                    node,
                    index: e.index,
                    target,
                    encoding,
                },
            );
        }
    }

    /// Checks links against the whole tree, refuses devices, and adds up
    /// folder sizes and counts. Call once, after the last `add`.
    pub fn finish(&mut self) {
        let mut links: Vec<PendingLink> = std::mem::take(&mut self.links).into_values().collect();
        links.sort_unstable_by_key(|l| l.node);
        for l in &links {
            let id = l.node;
            let refused = match self.nodes[id as usize].kind {
                Kind::Symlink => {
                    let folder: Vec<(String, u32)> = self
                        .ancestry(self.nodes[id as usize].parent)
                        .into_iter()
                        .map(|f| (self.nodes[f as usize].name.disk.clone(), f))
                        .collect();
                    match link::check_symlink(
                        &folder,
                        &l.target,
                        l.encoding,
                        self.format.made_on_dos,
                        &*self,
                    ) {
                        Ok(s) => {
                            self.nodes[id as usize].symlink = Some(s);
                            None
                        }
                        Err(err) => Some(Refused::Link(err)),
                    }
                }
                _ => {
                    let target =
                        link::check_hardlink(&l.target, l.encoding, self.format.made_on_dos)
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
        self.next_number = HashMap::new();
        self.lone_top = self.find_lone_top();
    }

    /// Points the hard link `node` at `to`, a node the caller knows is its
    /// target, as `finish` would have if the link's path had named it (the
    /// staging audit, whose raw names can clash with another name's disk
    /// form). The same rules apply: a file stored earlier. Folder sizes are
    /// left as `finish` made them.
    pub(crate) fn set_hardlink(&mut self, node: u32, to: u32) {
        let ok = self.nodes[node as usize].kind == Kind::Hardlink
            && self.nodes[to as usize].kind == Kind::File
            && self.nodes[to as usize]
                .entry
                .is_some_and(|t| self.nodes[node as usize].entry.is_some_and(|n| t < n));
        let n = &mut self.nodes[node as usize];
        if ok {
            n.hardlink = Some(to);
            n.refused = None;
        } else {
            n.hardlink = None;
            n.refused = Some(Refused::HardlinkTarget);
        }
    }

    fn find_lone_top(&self) -> Option<u32> {
        let [top] = self.nodes[ROOT as usize].children[..] else {
            return None;
        };
        let n = &self.nodes[top as usize];
        if n.name.disk.starts_with('.') || n.refused.is_some() {
            return None;
        }
        match n.kind {
            Kind::File => Some(top),
            Kind::Dir => {
                // Every link must point inside the folder, not beside it: once
                // moved out, beside it is the user's own folder.
                let inside = self.nodes.iter().all(|m| match (&m.symlink, &m.refused) {
                    (Some(t), None) => t.resolved.first() == Some(&n.name.disk),
                    _ => true,
                });
                inside.then_some(top)
            }
            _ => None,
        }
    }

    fn push_skip(&mut self, s: Skip) {
        if self.skipped.len() < MAX_SKIPPED {
            self.skipped.push(s);
        } else {
            self.skipped_more += 1;
        }
    }

    fn skip(&mut self, e: &Entry, enc: NameEncoding, reason: String) {
        let mut pieces = Vec::new();
        name::decode(&e.path, enc, |p| pieces.push(p));
        self.unusual_names = true;
        self.push_skip(Skip {
            index: e.index,
            path: name::display(&pieces).0,
            reason,
        });
    }

    fn push(&mut self, parent: u32, name: Component, kind: Kind) -> u32 {
        let id = self.nodes.len() as u32;
        self.by_name
            .insert(Key(parent, name.disk.as_str().into()), id);
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
        n.size = if e.kind == Kind::Dir {
            0
        } else {
            e.size.unwrap_or(0)
        };
        n.packed = e.packed;
        n.mtime = e.mtime;
        n.mode = e.mode;
        n.encrypted = e.encrypted;
    }

    /// The folder `c` in `parent`, made if missing. A non-folder holding the
    /// name moves to `name (2)`, and is returned as moved.
    fn folder(
        &mut self,
        parent: u32,
        c: &Component,
        entry: Option<&Entry>,
    ) -> (u32, Option<Moved>) {
        let mut moved = None;
        let id = match self.child(parent, &c.disk) {
            Some(id) if self.nodes[id as usize].kind == Kind::Dir => id,
            Some(other) => {
                let from = self.disk_path(other);
                // Numbered while the name is still taken, then moved.
                let mut name = self.nodes[other as usize].name.clone();
                self.free_name(parent, &mut name);
                self.by_name
                    .remove(&(parent, c.disk.as_str()) as &dyn KeyRef);
                self.by_name
                    .insert(Key(parent, name.disk.as_str().into()), other);
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

    /// Numbers `name` until no sibling holds its disk form, resuming where
    /// the last clash on the same name stopped.
    fn free_name(&mut self, parent: u32, name: &mut Component) {
        if self.child(parent, &name.disk).is_none() {
            return;
        }
        let key = Key(parent, name.disk.as_str().into());
        let mut n = self.next_number.get(&key).copied().unwrap_or(2);
        let disk = loop {
            let disk = name::numbered(&name.disk, n);
            n += 1;
            if self.child(parent, &disk).is_none() {
                break disk;
            }
        };
        self.next_number.insert(key, n);
        name.display = name::numbered(&name.display, n - 1);
        name.disk = disk;
        name.renamed = true;
    }

    /// The files whose execute bits must go because a launcher name
    /// (`name::is_launcher`) reaches them: the file itself, through a hard
    /// link, or at the end of a chain of symbolic links.
    pub fn launcher_files(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for (id, n) in self.nodes.iter().enumerate() {
            if n.kind == Kind::Dir || !crate::name::is_launcher(&n.name.disk) {
                continue;
            }
            let mut at = id as u32;
            // Symbolic links chain only at their last component; the bound
            // ends link loops.
            for _ in 0..40 {
                let node = &self.nodes[at as usize];
                if node.refused.is_some() {
                    break;
                }
                let next = match node.kind {
                    Kind::File => {
                        out.push(at);
                        break;
                    }
                    Kind::Hardlink => node.hardlink,
                    Kind::Symlink => node
                        .symlink
                        .as_ref()
                        .and_then(|t| self.find(t.resolved.iter().map(String::as_str))),
                    _ => None,
                };
                let Some(next) = next else { break };
                at = next;
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The node at a path of disk names from the root.
    pub fn find<'a>(&self, disk: impl IntoIterator<Item = &'a str>) -> Option<u32> {
        let mut at = ROOT;
        for part in disk {
            at = self.child(at, part)?;
        }
        Some(at)
    }

    /// The child of `parent` with this disk name.
    pub fn child(&self, parent: u32, disk: &str) -> Option<u32> {
        self.by_name.get(&(parent, disk) as &dyn KeyRef).copied()
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

    /// A node's path from the root, in disk form.
    pub fn disk_path(&self, id: u32) -> String {
        let parts: Vec<&str> = self
            .ancestry(id)
            .into_iter()
            .map(|i| self.nodes[i as usize].name.disk.as_str())
            .collect();
        parts.join("/")
    }

    /// A node's path from the root, in display form.
    pub fn display_path(&self, id: u32) -> String {
        let parts: Vec<&str> = self
            .ancestry(id)
            .into_iter()
            .map(|i| self.nodes[i as usize].name.display.as_str())
            .collect();
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
            compressed_file: false,
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
        Entry {
            link: Some(to.as_bytes().to_vec()),
            ..e(index, path, kind)
        }
    }

    fn paths(t: &Tree) -> Vec<String> {
        let mut v: Vec<String> = (1..t.nodes.len() as u32).map(|i| t.disk_path(i)).collect();
        v.sort();
        v
    }

    #[test]
    fn implied_folders_and_sizes() {
        let t = Tree::build(
            fmt(),
            &[
                e(0, "a/b/c.txt", Kind::File),
                e(1, "a/d.txt", Kind::File),
                e(2, "a/", Kind::Dir),
            ],
            None,
        );
        assert_eq!(paths(&t), ["a", "a/b", "a/b/c.txt", "a/d.txt"]);
        assert_eq!(t.nodes[ROOT as usize].size, 20);
        let a = t.find(["a"]).unwrap();
        assert_eq!(t.nodes[a as usize].entry, Some(2));
        assert_eq!(t.nodes[t.find(["a", "b"]).unwrap() as usize].entry, None);
        assert_eq!((t.files, t.folders), (2, 2));
    }

    #[test]
    fn refused_paths_are_skipped() {
        let t = Tree::build(
            fmt(),
            &[
                e(0, "../evil", Kind::File),
                e(1, "/etc/x", Kind::File),
                e(2, "ok", Kind::File),
            ],
            None,
        );
        assert_eq!(paths(&t), ["ok"]);
        assert_eq!(t.skipped.len(), 2);
        assert_eq!(t.skipped[0].path, "../evil");
        assert!(t.skipped[0].reason.contains(".."));
    }

    #[test]
    fn folders_win_their_name() {
        // A file "x", then a file inside a folder "x".
        let t = Tree::build(
            fmt(),
            &[e(0, "x", Kind::File), e(1, "x/y", Kind::File)],
            None,
        );
        assert_eq!(paths(&t), ["x", "x (2)", "x/y"]);
        assert_eq!(t.nodes[t.find(["x (2)"]).unwrap() as usize].entry, Some(0));
        // The other order.
        let t = Tree::build(
            fmt(),
            &[e(0, "x/y", Kind::File), e(1, "x", Kind::File)],
            None,
        );
        assert_eq!(paths(&t), ["x", "x (2)", "x/y"]);
        assert_eq!(t.nodes[t.find(["x (2)"]).unwrap() as usize].entry, Some(1));
    }

    #[test]
    fn same_disk_name_is_numbered_same_path_is_replaced() {
        let t = Tree::build(
            fmt(),
            &[e(0, "a\x01", Kind::File), e(1, "a\x02", Kind::File)],
            None,
        );
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
        let t = Tree::build(
            fmt(),
            &[
                link(0, "l", Kind::Symlink, "/"),
                e(1, "l/etc/passwd", Kind::File),
            ],
            None,
        );
        // "l" is a real folder; the link is kept as "l (2)", refused.
        let l = t.find(["l"]).unwrap();
        assert_eq!(t.nodes[l as usize].kind, Kind::Dir);
        let l2 = t.find(["l (2)"]).unwrap();
        assert_eq!(
            t.nodes[l2 as usize].refused,
            Some(Refused::Link(LinkError::Absolute))
        );
        // A link to "." is refused, and a link through any link too.
        let t = Tree::build(
            fmt(),
            &[
                link(0, "d", Kind::Symlink, "."),
                link(1, "e", Kind::Symlink, "d/d/../.."),
            ],
            None,
        );
        assert_eq!(
            t.nodes[t.find(["d"]).unwrap() as usize].refused,
            Some(Refused::Link(LinkError::ToTop))
        );
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
        assert_eq!(
            t.nodes[t.find(["dev", "sda"]).unwrap() as usize].refused,
            Some(Refused::Special)
        );
    }

    #[test]
    fn legacy_names_are_detected() {
        let mut f = fmt();
        f.made_on_dos = true;
        // CP437, as Windows' own zip writes names in a German locale.
        let raw: [&[u8]; 3] = [
            b"Gr\x81\xE1e an M\x81ller.txt",
            b"\x9Abersicht der Kosten.doc",
            b"\x8Enderungen f\x81r M\x84rz.txt",
        ];
        let entries: Vec<Entry> = raw
            .iter()
            .enumerate()
            .map(|(i, r)| Entry {
                path: r.to_vec(),
                utf8: false,
                ..e(i as u32, "", Kind::File)
            })
            .collect();
        let t = Tree::build(f, &entries, None);
        assert_eq!(t.encoding, NameEncoding::Cp437);
        assert_eq!(
            paths(&t),
            [
                "Grüße an Müller.txt",
                "Änderungen für März.txt",
                "Übersicht der Kosten.doc"
            ]
        );
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
        let Added::Node { id: x, .. } = t.add(&e(0, "x", Kind::File)) else {
            panic!()
        };
        // A folder needs "x": the file moves, and the writer is told.
        let Added::Node { moved, .. } = t.add(&e(1, "x/y", Kind::File)) else {
            panic!()
        };
        assert_eq!(
            moved,
            Some(Moved {
                node: x,
                from: "x".into()
            })
        );
        assert_eq!(t.disk_path(x), "x (2)");
        // The same path again replaces it.
        let Added::Node { id, replaced, .. } = t.add(&e(2, "x/y", Kind::File)) else {
            panic!()
        };
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
            &[
                link(0, "l", Kind::Symlink, "ok"),
                link(1, "l", Kind::Symlink, "../../escape"),
            ],
            None,
        );
        assert_eq!(
            t.nodes[t.find(["l"]).unwrap() as usize].refused,
            Some(Refused::Link(LinkError::Escapes))
        );
        let t = Tree::build(
            fmt(),
            &[
                link(0, "l", Kind::Symlink, "/abs"),
                link(1, "l", Kind::Symlink, "ok"),
            ],
            None,
        );
        let n = &t.nodes[t.find(["l"]).unwrap() as usize];
        assert_eq!(n.refused, None);
        assert_eq!(n.symlink.as_ref().unwrap().disk, "ok");
    }

    #[test]
    fn many_names_for_one_disk_name_stay_linear() {
        // "a", "./a", ".//a", ... all write "a": numbering resumes.
        let entries: Vec<Entry> = (0..20_000)
            .map(|i| {
                e(
                    i,
                    &format!("{}a", "./".repeat(i as usize % 2000)),
                    Kind::File,
                )
            })
            .collect();
        let start = std::time::Instant::now();
        let t = Tree::build(fmt(), &entries, None);
        assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
        assert_eq!(t.files, 20_000 - t.skipped.len() as u64);
        assert!(t.find(["a (1000)"]).is_some());
    }

    #[test]
    fn deep_paths_hit_the_node_cap() {
        let deep = "d/".repeat(250);
        let entries: Vec<Entry> = (0..5000)
            .map(|i| e(i, &format!("{i}/{deep}f"), Kind::File))
            .collect();
        let t = Tree::build(fmt(), &entries, None);
        assert!(t.overflow);
        assert!(t.nodes.len() <= MAX_NODES);
    }

    #[test]
    fn lone_top_is_moved_out_only_when_safe() {
        let t = Tree::build(
            fmt(),
            &[
                e(0, "proj/a.txt", Kind::File),
                link(1, "proj/l", Kind::Symlink, "a.txt"),
            ],
            None,
        );
        assert_eq!(t.lone_top, t.find(["proj"]));
        // A link to beside the folder would point into the user's folder.
        let t = Tree::build(
            fmt(),
            &[
                e(0, "proj/a.txt", Kind::File),
                link(1, "proj/l", Kind::Symlink, "../x"),
            ],
            None,
        );
        assert_eq!(t.lone_top, None);
        let t = Tree::build(fmt(), &[e(0, "notes.txt", Kind::File)], None);
        assert_eq!(t.lone_top, t.find(["notes.txt"]));
        for (path, kind) in [
            (".bashrc", Kind::File),
            (".config/x", Kind::File),
            ("l", Kind::Symlink),
        ] {
            let t = Tree::build(fmt(), &[link(0, path, kind, "x")], None);
            assert_eq!(t.lone_top, None, "{path}");
        }
        let t = Tree::build(fmt(), &[e(0, "a", Kind::File), e(1, "b", Kind::File)], None);
        assert_eq!(t.lone_top, None);
    }

    #[test]
    fn launchers_reached_by_any_name() {
        let t = Tree::build(
            fmt(),
            &[
                e(0, "a.desktop", Kind::File),
                e(1, "script", Kind::File),
                link(2, "Open me.desktop", Kind::Symlink, "hop"),
                link(3, "hop", Kind::Symlink, "script"),
                e(4, "plain", Kind::File),
                link(5, "hard.kdelnk", Kind::Hardlink, "plain"),
                link(6, "loop.desktop", Kind::Symlink, "loop.desktop"),
                e(7, "safe", Kind::File),
            ],
            None,
        );
        let mut want: Vec<u32> = ["a.desktop", "script", "plain"]
            .iter()
            .map(|p| t.find([*p]).unwrap())
            .collect();
        want.sort_unstable();
        assert_eq!(t.launcher_files(), want);
    }

    #[test]
    fn fifty_thousand_entries() {
        let entries: Vec<Entry> = (0..50_000)
            .map(|i| {
                e(
                    i,
                    &format!("d{}/s{}/file{i}.txt", i % 100, i % 7),
                    Kind::File,
                )
            })
            .collect();
        let start = std::time::Instant::now();
        let t = Tree::build(fmt(), &entries, None);
        let took = start.elapsed();
        assert_eq!(t.files, 50_000);
        assert!(took.as_millis() < 2000, "{took:?}");
    }
}
