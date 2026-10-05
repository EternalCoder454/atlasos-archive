//! Limits that catch archives built to fill a disk (docs/DESIGN.md, "Bomb
//! limits").
//!
//! Sizes an archive declares can lie, so a `Meter` counts what is actually
//! written as it is written, against what was actually read from the archive.
//! The declared sizes are checked too, before anything is written, so an
//! honest large archive asks first instead of half way through.
//!
//! Going past a limit is a question, not a failure: the worker pauses and the
//! job asks in plain words, Cancel being the default. When the user goes on,
//! that limit is off for the rest of the job. A full disk still stops the
//! writer (ENOSPC); these limits are what ask before it gets there.

use std::fmt;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// The limits for one job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes written in all.
    pub total_bytes: u64,
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
    /// The free space, not the 16 GiB default, set `total_bytes`.
    pub by_free_space: bool,
}

/// Room left free on the destination's file system.
pub const FREE_SPACE_RESERVE: u64 = GIB;

impl Limits {
    /// The default limits. `free_space`: the bytes free on the destination's
    /// file system, when known; the total is then at most that less 1 GiB.
    pub fn new(free_space: Option<u64>) -> Limits {
        let default = 16 * GIB;
        let total_bytes = free_space.map_or(default, |free| {
            default.min(free.saturating_sub(FREE_SPACE_RESERVE))
        });
        Limits {
            total_bytes,
            ratio: 100,
            ratio_after: 256 * MIB,
            entries: 200_000,
            entry_ratio: 1000,
            entry_ratio_after: 64 * MIB,
            nest_depth: 8,
            by_free_space: total_bytes < default,
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
}

/// A limit was reached: what to ask the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exceeded {
    pub kind: Kind,
    /// The limit's value, for the question.
    pub limit: u64,
    /// The free space was what set the total size limit.
    pub by_free_space: bool,
}

impl Exceeded {
    /// The question the job asks, in plain words.
    pub fn question(&self) -> String {
        match self.kind {
            Kind::TotalSize if self.by_free_space => format!(
                "This archive unpacks to more than the {} free on this drive (keeping 1 GiB spare). Unpack it anyway?",
                format_size(self.limit + FREE_SPACE_RESERVE)
            ),
            Kind::TotalSize => format!(
                "This archive unpacks to more than {}. Unpack it anyway?",
                format_size(self.limit)
            ),
            Kind::Ratio => format!(
                "This archive unpacks to more than {} times its own size. Archives made to fill a disk look like this. Unpack it anyway?",
                self.limit
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
                "This archive is inside more than {} other archives. Open it anyway?",
                self.limit
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
    pub fn allow(&mut self, kind: Kind) {
        if !self.off.contains(&kind) {
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
        Exceeded {
            kind,
            limit,
            by_free_space: kind == Kind::TotalSize && self.limits.by_free_space,
        }
    }

    /// Checks what the archive declares before anything is written: its
    /// entry count, the sum of its entries' sizes and its own size.
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
        if self.on(Kind::TotalSize) && unpacked > l.total_bytes {
            return Err(self.exceeded(Kind::TotalSize, l.total_bytes));
        }
        if self.on(Kind::Ratio)
            && unpacked > l.ratio_after
            && unpacked / archive_size.max(1) >= l.ratio
        {
            return Err(self.exceeded(Kind::Ratio, l.ratio));
        }
        Ok(())
    }

    /// Counts the start of an entry.
    pub fn start_entry(&mut self) -> Result<(), Exceeded> {
        self.entries += 1;
        self.entry_written = 0;
        if self.on(Kind::Entries) && self.entries > self.limits.entries {
            return Err(self.exceeded(Kind::Entries, self.limits.entries));
        }
        Ok(())
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
        let l = &self.limits;
        if self.on(Kind::TotalSize) && self.written > l.total_bytes {
            return Err(self.exceeded(Kind::TotalSize, l.total_bytes));
        }
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
        if self.on(Kind::NestDepth) && depth > self.limits.nest_depth {
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
        if i > 0 && (digits.len() - i) % 3 == 0 {
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
    fn free_space_caps_the_total() {
        assert_eq!(Limits::new(None).total_bytes, 16 * GIB);
        assert_eq!(Limits::new(Some(5 * GIB)).total_bytes, 4 * GIB);
        assert_eq!(Limits::new(Some(100 * GIB)).total_bytes, 16 * GIB);
        assert_eq!(Limits::new(Some(MIB)).total_bytes, 0);
        let m = Meter::new(Limits::new(Some(5 * GIB)));
        let e = m.check_declared(1, 5 * GIB, 5 * GIB).unwrap_err();
        assert!(e.by_free_space);
        assert!(e.question().contains("5 GiB free"), "{}", e.question());
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
        m.start_entry().unwrap();
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
        m.start_entry().unwrap();
        // 64 MiB from 64 KiB: under the threshold, fine.
        assert!(m.add(64 * MIB, 128 * MIB, Some(64 * 1024)).is_ok());
        let e = m.add(1, 128 * MIB, Some(64 * 1024)).unwrap_err();
        assert_eq!(e.kind, Kind::EntryRatio);
        // A new entry starts its own count.
        m.start_entry().unwrap();
        assert!(m.add(MIB, 129 * MIB, Some(1)).is_ok());
    }

    #[test]
    fn allowing_turns_a_limit_off() {
        let mut m = Meter::new(Limits {
            entries: 2,
            ..Limits::new(None)
        });
        m.start_entry().unwrap();
        m.start_entry().unwrap();
        assert_eq!(m.start_entry().unwrap_err().kind, Kind::Entries);
        m.allow(Kind::Entries);
        m.start_entry().unwrap();
        assert!(m.check_nesting(8).is_ok());
        assert_eq!(m.check_nesting(9).unwrap_err().kind, Kind::NestDepth);
    }

    #[test]
    fn total_is_counted_as_written() {
        let mut m = Meter::new(Limits {
            total_bytes: 10,
            ..Limits::new(None)
        });
        m.start_entry().unwrap();
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
        ] {
            let q = Exceeded {
                kind,
                limit: 8,
                by_free_space: false,
            }
            .question();
            assert!(q.ends_with("anyway?"), "{q}");
        }
    }
}
