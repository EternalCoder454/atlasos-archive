//! Limits that catch archives built to fill a disk (docs/DESIGN.md, "Bomb
//! limits").
//!
//! Sizes an archive declares can lie, so a `Meter` counts what is actually
//! written as it is written, against what was actually read from the archive.
//! The declared sizes are checked too, before anything is written, so an
//! honest large archive asks first instead of half way through.
//!
//! Most limits are a question, not a failure: the worker pauses and the job
//! asks in plain words, Cancel being the default. When the user goes on, that
//! limit is off for the rest of the job. Two never are: the free space on the
//! destination less a reserve (a tenth of it, at most 1 GiB), and the nesting
//! depth.

use std::fmt;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// The limits for one job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes written before asking.
    pub total_bytes: u64,
    /// The most bytes written, ever: the free space less the reserve.
    pub free_space: u64,
    /// The most bytes written per byte read from the archive...
    pub ratio: u64,
    /// ...once this many bytes have been written.
    pub ratio_after: u64,
    /// The most entries.
    pub entries: u64,
    /// The most bytes one entry may unpack to per compressed byte...
    pub entry_ratio: u64,
    /// ...once it has unpacked to this many bytes.
    pub entry_ratio_after: u64,
    /// The most archives inside archives opened in place.
    pub nest_depth: u32,
}

/// The most room kept free on the destination's file system. On a small drive
/// the reserve is a tenth of what is free, so a small drive isn't refused
/// outright.
pub const FREE_SPACE_RESERVE: u64 = GIB;

/// What an inode and its directory entry are counted to cost on disk, in
/// bytes, so an archive of millions of empty files meets the size limits.
pub const NODE_COST: u64 = 4096;

/// The room kept free of `free` bytes: a tenth, at most `FREE_SPACE_RESERVE`.
pub fn reserve_for(free: u64) -> u64 {
    FREE_SPACE_RESERVE.min(free / 10)
}

impl Limits {
    /// The default limits. `free_space`: the bytes free on the destination's
    /// file system, when known.
    pub fn new(free_space: Option<u64>) -> Limits {
        Limits {
            total_bytes: 16 * GIB,
            free_space: free_space.map_or(u64::MAX, |f| f.saturating_sub(reserve_for(f))),
            ratio: 100,
            ratio_after: 256 * MIB,
            entries: 200_000,
            entry_ratio: 1000,
            entry_ratio_after: 64 * MIB,
            nest_depth: 8,
        }
    }
}

/// Which limit was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    TotalSize,
    Ratio,
    Entries,
    EntryRatio,
    NestDepth,
    FreeSpace,
}

impl Kind {
    /// The user may choose to go past it.
    pub fn askable(self) -> bool {
        !matches!(self, Kind::NestDepth | Kind::FreeSpace)
    }
}

/// A limit was reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exceeded {
    pub kind: Kind,
    /// The limit's value, for the words. It may come from the worker: shown,
    /// never computed with.
    pub limit: u64,
}

impl Exceeded {
    /// What the job says, in plain words: a question when `kind.askable()`,
    /// otherwise why it stopped.
    pub fn question(&self) -> String {
        match self.kind {
            Kind::FreeSpace => format!(
                "There isn't enough space on this drive: the archive unpacks to more than the {} that can be used on this drive.",
                format_size(self.limit)
            ),
            Kind::TotalSize => format!(
                "This archive unpacks to more than {}. Unpack it anyway?",
                format_size(self.limit)
            ),
            Kind::Ratio => format!(
                "This archive unpacks to more than {} times its own size. Archives made to fill a disk look like this. Unpack it anyway?",
                group(self.limit)
            ),
            Kind::Entries => format!(
                "This archive holds more than {} items. Unpack it anyway?",
                group(self.limit)
            ),
            Kind::EntryRatio => format!(
                "A file in this archive unpacks to more than {} times its packed size. Archives made to fill a disk look like this. Unpack it anyway?",
                group(self.limit)
            ),
            Kind::NestDepth => format!(
                "This archive is inside more than {} other archives, so it can't be opened in place. Extract it first.",
                group(self.limit)
            ),
        }
    }
}

impl fmt::Display for Exceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.question())
    }
}

/// Counts a job's output against its limits.
#[derive(Clone, Debug)]
pub struct Meter {
    limits: Limits,
    off: Vec<Kind>,
    written: u64,
    entries: u64,
    entry_written: u64,
}

impl Meter {
    pub fn new(limits: Limits) -> Meter {
        Meter {
            limits,
            off: Vec::new(),
            written: 0,
            entries: 0,
            entry_written: 0,
        }
    }

    /// Turns a limit off for the rest of the job: the user chose to go on.
    /// Limits that aren't `askable` stay on.
    pub fn allow(&mut self, kind: Kind) {
        if kind.askable() && !self.off.contains(&kind) {
            self.off.push(kind);
        }
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    fn on(&self, kind: Kind) -> bool {
        !self.off.contains(&kind)
    }

    fn exceeded(&self, kind: Kind, limit: u64) -> Exceeded {
        Exceeded { kind, limit }
    }

    fn check_size(&self, size: u64) -> Result<(), Exceeded> {
        let l = &self.limits;
        if size > l.free_space {
            return Err(self.exceeded(Kind::FreeSpace, l.free_space));
        }
        if self.on(Kind::TotalSize) && size > l.total_bytes {
            return Err(self.exceeded(Kind::TotalSize, l.total_bytes));
        }
        Ok(())
    }

    /// Checks what the archive declares before anything is written: its
    /// entry count, the sum of its entries' sizes (add them with
    /// `saturating_add`) and its own size.
    pub fn check_declared(
        &self,
        entries: u64,
        unpacked: u64,
        archive_size: u64,
    ) -> Result<(), Exceeded> {
        let l = &self.limits;
        if self.on(Kind::Entries) && entries > l.entries {
            return Err(self.exceeded(Kind::Entries, l.entries));
        }
        self.check_size(unpacked)?;
        if self.on(Kind::Ratio)
            && unpacked > l.ratio_after
            && unpacked / archive_size.max(1) >= l.ratio
        {
            return Err(self.exceeded(Kind::Ratio, l.ratio));
        }
        Ok(())
    }

    /// Starts counting a new entry's bytes.
    pub fn start_entry(&mut self) {
        self.entry_written = 0;
    }

    /// Counts `n` new tree nodes (the entries and the folders made for them):
    /// each is an entry and costs `NODE_COST` bytes of disk.
    pub fn add_nodes(&mut self, n: u64) -> Result<(), Exceeded> {
        self.entries = self.entries.saturating_add(n);
        self.written = self.written.saturating_add(n.saturating_mul(NODE_COST));
        if self.on(Kind::Entries) && self.entries > self.limits.entries {
            return Err(self.exceeded(Kind::Entries, self.limits.entries));
        }
        self.check_size(self.written)
    }

    /// Counts `n` bytes written for the current entry. `archive_read`: the
    /// bytes read from the archive so far; `entry_packed`: the current
    /// entry's packed size, when the format stores one.
    pub fn add(
        &mut self,
        n: u64,
        archive_read: u64,
        entry_packed: Option<u64>,
    ) -> Result<(), Exceeded> {
        self.written = self.written.saturating_add(n);
        self.entry_written = self.entry_written.saturating_add(n);
        self.check_size(self.written)?;
        let l = &self.limits;
        if self.on(Kind::EntryRatio)
            && let Some(packed) = entry_packed
            && self.entry_written > l.entry_ratio_after
            && self.entry_written / packed.max(1) >= l.entry_ratio
        {
            return Err(self.exceeded(Kind::EntryRatio, l.entry_ratio));
        }
        if self.on(Kind::Ratio)
            && self.written > l.ratio_after
            && self.written / archive_read.max(1) >= l.ratio
        {
            return Err(self.exceeded(Kind::Ratio, l.ratio));
        }
        Ok(())
    }

    /// Checks opening an archive `depth` archives deep (1: inside one).
    pub fn check_nesting(&self, depth: u32) -> Result<(), Exceeded> {
        if depth > self.limits.nest_depth {
            return Err(self.exceeded(Kind::NestDepth, self.limits.nest_depth.into()));
        }
        Ok(())
    }
}

/// A size in plain words: "512 bytes", "1.5 KiB", "16 GiB".
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return if bytes == 1 {
            "1 byte".into()
        } else {
            format!("{bytes} bytes")
        };
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let shown = format!("{value:.1}");
    let shown = shown.strip_suffix(".0").unwrap_or(&shown);
    format!("{shown} {}", UNITS[unit])
}

/// A count with thousands separators: "200,000".
fn group(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_is_a_hard_stop() {
        assert_eq!(Limits::new(None).free_space, u64::MAX);
        assert_eq!(Limits::new(Some(20 * GIB)).free_space, 19 * GIB);
        assert_eq!(Limits::new(Some(5 * GIB)).free_space, 5 * GIB - GIB / 2);
        // A small drive keeps a tenth, not a whole GiB.
        assert_eq!(Limits::new(Some(GIB)).free_space, GIB - GIB / 10);
        assert_eq!(Limits::new(Some(10 * MIB)).free_space, 9 * MIB);
        assert_eq!(Limits::new(Some(0)).free_space, 0);
        let mut m = Meter::new(Limits::new(Some(20 * GIB)));
        let e = m.check_declared(1, 20 * GIB, 20 * GIB).unwrap_err();
        assert_eq!(e.kind, Kind::FreeSpace);
        assert!(!e.kind.askable());
        assert!(
            e.question()
                .contains("more than the 19 GiB that can be used"),
            "{}",
            e.question()
        );
        // Saying yes to everything still stops at the free space.
        for k in [Kind::TotalSize, Kind::Ratio, Kind::FreeSpace] {
            m.allow(k);
        }
        m.start_entry();
        assert!(m.add(19 * GIB, 19 * GIB, None).is_ok());
        assert_eq!(m.add(1, 19 * GIB, None).unwrap_err().kind, Kind::FreeSpace);
    }

    #[test]
    fn declared_sizes() {
        let m = Meter::new(Limits::new(None));
        assert!(m.check_declared(10, 100 * MIB, MIB).is_ok());
        assert_eq!(
            m.check_declared(200_001, 1, 1).unwrap_err().kind,
            Kind::Entries
        );
        assert_eq!(
            m.check_declared(1, 17 * GIB, 16 * GIB).unwrap_err().kind,
            Kind::TotalSize
        );
        assert_eq!(
            m.check_declared(1, GIB, 10 * MIB).unwrap_err().kind,
            Kind::Ratio
        );
        // Highly compressible but small: fine.
        assert!(m.check_declared(1, 200 * MIB, 1024).is_ok());
    }

    #[test]
    fn a_bomb_is_caught_while_writing() {
        // 42.zip-like: 1 MiB read, output keeps coming.
        let mut m = Meter::new(Limits::new(None));
        m.start_entry();
        let mut err = None;
        for _ in 0..1024 {
            if let Err(e) = m.add(MIB, MIB, None) {
                err = Some(e);
                break;
            }
        }
        let e = err.expect("caught");
        assert_eq!(e.kind, Kind::Ratio);
        assert!(m.written() <= 257 * MIB);
    }

    #[test]
    fn one_entry_ratio() {
        let mut m = Meter::new(Limits::new(None));
        m.start_entry();
        // 64 MiB from 64 KiB: under the threshold, fine.
        assert!(m.add(64 * MIB, 128 * MIB, Some(64 * 1024)).is_ok());
        let e = m.add(1, 128 * MIB, Some(64 * 1024)).unwrap_err();
        assert_eq!(e.kind, Kind::EntryRatio);
        // A new entry starts its own count.
        m.start_entry();
        assert!(m.add(MIB, 129 * MIB, Some(1)).is_ok());
    }

    #[test]
    fn allowing_turns_an_askable_limit_off() {
        let mut m = Meter::new(Limits {
            entries: 2,
            ..Limits::new(None)
        });
        m.add_nodes(2).unwrap();
        assert_eq!(m.add_nodes(1).unwrap_err().kind, Kind::Entries);
        m.allow(Kind::Entries);
        m.add_nodes(1).unwrap();
        assert!(m.check_nesting(8).is_ok());
        m.allow(Kind::NestDepth);
        assert_eq!(m.check_nesting(9).unwrap_err().kind, Kind::NestDepth);
    }

    #[test]
    fn nodes_cost_disk() {
        let mut m = Meter::new(Limits {
            total_bytes: 10 * NODE_COST,
            ..Limits::new(None)
        });
        m.add_nodes(10).unwrap();
        assert_eq!(m.written(), 10 * NODE_COST);
        assert_eq!(m.add_nodes(1).unwrap_err().kind, Kind::TotalSize);
        // Free space is a hard stop for nodes too.
        let mut m = Meter::new(Limits {
            free_space: 2 * NODE_COST,
            ..Limits::new(None)
        });
        m.allow(Kind::FreeSpace);
        m.add_nodes(2).unwrap();
        assert_eq!(m.add_nodes(1).unwrap_err().kind, Kind::FreeSpace);
        // Counts can't overflow.
        let mut m = Meter::new(Limits::new(None));
        assert!(m.add_nodes(u64::MAX).is_err());
    }

    #[test]
    fn total_is_counted_as_written() {
        let mut m = Meter::new(Limits {
            total_bytes: 10,
            ..Limits::new(None)
        });
        m.start_entry();
        assert!(m.add(10, 10, None).is_ok());
        assert_eq!(m.add(1, 11, None).unwrap_err().kind, Kind::TotalSize);
    }

    #[test]
    fn words() {
        assert_eq!(format_size(0), "0 bytes");
        assert_eq!(format_size(1), "1 byte");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(16 * GIB), "16 GiB");
        assert_eq!(group(200_000), "200,000");
        assert_eq!(group(1000), "1,000");
        assert_eq!(group(999), "999");
        for kind in [
            Kind::TotalSize,
            Kind::Ratio,
            Kind::Entries,
            Kind::EntryRatio,
            Kind::NestDepth,
            Kind::FreeSpace,
        ] {
            // A worker's u64::MAX can't overflow the words.
            let q = Exceeded {
                kind,
                limit: u64::MAX,
            }
            .question();
            assert_eq!(q.ends_with("anyway?"), kind.askable(), "{q}");
        }
    }
}
