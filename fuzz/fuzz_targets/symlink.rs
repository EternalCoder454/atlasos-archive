#![no_main]
//! A symlink entry's target: what passes names something inside the archive's
//! own folders, never above them and never through another link.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use telamon_archive_core::link::{self, Lookup};
use telamon_archive_core::name::NameEncoding;

/// An archive whose folders are `a` (1), `b` (2) and `c` under `a` (3), and
/// a link `l` (4) under the top.
struct Tree;
impl Lookup for Tree {
    fn child(&self, parent: u32, disk: &str) -> Option<u32> {
        match (parent, disk) {
            (0, "a") => Some(1),
            (0, "b") => Some(2),
            (1, "c") => Some(3),
            (0, "l") => Some(4),
            _ => None,
        }
    }
    fn is_symlink(&self, node: u32) -> bool {
        node == 4
    }
}

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    raw: &'a [u8],
    depth: u8,
    dos: bool,
}

fuzz_target!(|i: Input| {
    let folder: Vec<(String, u32)> = match i.depth % 3 {
        0 => vec![],
        1 => vec![("a".into(), 1)],
        _ => vec![("a".into(), 1), ("c".into(), 3)],
    };
    if let Ok(t) = link::check_symlink(&folder, i.raw, NameEncoding::Utf8, i.dos, &Tree) {
        assert!(!t.disk.starts_with('/') && !t.disk.contains('\0'), "{:?}", t.disk);
        // walking the written target from the link's folder never leaves the top
        let mut depth = folder.len() as i64;
        for part in t.disk.split('/') {
            match part {
                "" | "." => {}
                ".." => depth -= 1,
                _ => depth += 1,
            }
            assert!(depth >= 0, "{:?} climbs above the top from {:?}", t.disk, folder);
        }
    }
});
