//! The worker's jobs: list, extract and test one archive, talking to the
//! client through a `Conn` (frames on pipes in the worker, a queue in tests).
//!
//! Extraction is one pass: entries are placed in a `Tree` as they are read
//! and written at once, the way bsdtar does, so a tar.gz is decompressed
//! once. Bytes are counted against the limits as they are written; past one,
//! the job asks the client and waits for its answer.

use std::collections::HashSet;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use atlas_archive_core::limits::{Exceeded, Limits, Meter};
use atlas_archive_core::name::NameEncoding;
use atlas_archive_core::proto::{self, Entry, Format, Kind, Reply, Request};
use atlas_archive_core::tree::{Added, Tree};

use crate::extract::Writer;
use crate::libarchive::Reader;

/// How the job talks to its client.
pub trait Conn {
    fn send(&mut self, reply: &Reply) -> io::Result<()>;
    /// The next request; `None` when the client has gone.
    fn recv(&mut self) -> io::Result<Option<Request>>;
}

/// Frames on a pair of pipes.
pub struct Pipes<R, W> {
    pub input: R,
    pub output: W,
}

impl<R: io::Read, W: io::Write> Conn for Pipes<R, W> {
    fn send(&mut self, reply: &Reply) -> io::Result<()> {
        proto::write_frame(&mut self.output, &reply.encode())
    }

    fn recv(&mut self) -> io::Result<Option<Request>> {
        match proto::read_frame(&mut self.input)? {
            Some(frame) => Ok(Some(Request::decode(&frame)?)),
            None => Ok(None),
        }
    }
}

const PROGRESS_EVERY: Duration = Duration::from_millis(100);
/// Entries frames are sent once their entries pass this many bytes.
const BATCH_BYTES: usize = 256 * 1024;

fn format_of(reader: &Reader) -> Format {
    let name = reader.format_name();
    let solid = name.starts_with("tar.") || name == "7z";
    Format {
        encrypted: reader.has_encrypted_entries() == Some(true),
        encrypted_names: false,
        solid,
        compressed_file: reader.is_compressed_file(),
        volumes: 1,
        made_on_dos: false,
        comment: None,
        name,
    }
}

fn not_an_archive() -> Reply {
    Reply::Failed {
        reason: "The file isn't an archive Atlas Archive can read.".into(),
    }
}

/// Lists every entry: `Entries` batches, then `Format`, then `Listed`.
pub fn list(conn: &mut impl Conn, archive: BorrowedFd<'_>) -> io::Result<()> {
    let mut reader = match Reader::open(archive) {
        Ok(r) => r,
        Err(e) => return conn.send(&Reply::Failed { reason: e.0 }),
    };
    let mut batch = Vec::new();
    let mut batch_bytes = 0;
    let mut sent: u64 = 0;
    let mut count: u32 = 0;
    loop {
        let entry = match reader.next() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => return conn.send(&Reply::Failed { reason: e.0 }),
        };
        if count == 0 && reader.is_plain_file() {
            return conn.send(&not_an_archive());
        }
        if let Err(e) = reader.skip() {
            return conn.send(&Reply::Failed { reason: e.0 });
        }
        batch_bytes += 64 + entry.path.len() + entry.link.as_ref().map_or(0, Vec::len);
        batch.push(entry);
        count += 1;
        if batch_bytes >= BATCH_BYTES {
            sent += batch_bytes as u64;
            if sent > proto::MAX_LISTING {
                return conn.send(&Reply::Failed {
                    reason: "The archive lists more items than Atlas Archive can show.".into(),
                });
            }
            conn.send(&Reply::Entries(std::mem::take(&mut batch)))?;
            batch_bytes = 0;
        }
    }
    if !batch.is_empty() {
        conn.send(&Reply::Entries(batch))?;
    }
    conn.send(&Reply::Format(format_of(&reader)))?;
    conn.send(&Reply::Listed { entries: count })
}

/// What `extract` is asked to do.
pub struct ExtractJob<'a> {
    pub archive: BorrowedFd<'a>,
    pub staging: OwnedFd,
    pub umask: u32,
    pub encoding: NameEncoding,
    /// Archive indices to write, or every entry.
    pub entries: Option<HashSet<u32>>,
    /// The worker makes them with `Limits::new(free_space(staging))`.
    pub limits: Limits,
    pub raw_name: String,
}

/// The bytes free on the file system holding `dir`, if it can tell.
pub fn free_space(dir: BorrowedFd<'_>) -> Option<u64> {
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: fstatvfs fills `st` on success; `dir` is a live descriptor.
    if unsafe { libc::fstatvfs(dir.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: initialised by the successful call above.
    let st = unsafe { st.assume_init() };
    Some(u64::from(st.f_bavail).saturating_mul(u64::from(st.f_frsize)))
}

/// Asks the client about a limit. `Ok`: go on, with that limit off. A limit
/// that can't be gone past (the free space, the nesting) fails the job.
fn ask(conn: &mut impl Conn, meter: &mut Meter, e: Exceeded) -> Result<(), Stop> {
    if !e.kind.askable() {
        return Err(Stop::Failed(e.question()));
    }
    conn.send(&Reply::Limit(e.clone()))?;
    loop {
        match conn.recv()? {
            Some(Request::GoOn(true)) => {
                meter.allow(e.kind);
                return Ok(());
            }
            Some(Request::GoOn(false)) | None => return Err(Stop::Declined),
            // Anything else is out of turn; keep waiting for the answer.
            Some(_) => {}
        }
    }
}

/// Why a job stopped early.
enum Stop {
    /// The client said not to go past a limit, or went away.
    Declined,
    Failed(String),
}

impl From<io::Error> for Stop {
    fn from(e: io::Error) -> Stop {
        Stop::Failed(plain_io(&e))
    }
}

/// An I/O error in plain words.
pub fn plain_io(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ENOSPC) | Some(libc::EDQUOT) => "There isn't enough space on the drive.".into(),
        Some(libc::EROFS) => "The destination is read-only.".into(),
        Some(libc::EACCES) | Some(libc::EPERM) => {
            "Atlas Archive isn't allowed to write there.".into()
        }
        Some(libc::ENAMETOOLONG) => "A name is too long for this drive.".into(),
        Some(libc::EEXIST) => "An item with the same name is already there.".into(),
        Some(libc::EXDEV) => "A path would cross onto another drive.".into(),
        Some(libc::ELOOP) | Some(libc::EAGAIN) => "A path would go through a link.".into(),
        _ => {
            let s = e.to_string();
            let mut c = s.chars();
            match c.next() {
                Some(f) => format!("{}{}.", f.to_uppercase(), c.as_str().trim_end_matches('.')),
                None => "Something went wrong.".into(),
            }
        }
    }
}

/// Extracts into staging. Sends `Progress`, `Skipped` for each entry not
/// written, and `Done` (or `Failed`).
pub fn extract(conn: &mut impl Conn, job: ExtractJob<'_>) -> io::Result<()> {
    let mut written = Vec::new();
    match run_extract(conn, job, &mut written) {
        Ok(()) => conn.send(&Reply::Done {
            written: written.into_iter().map(String::into_bytes).collect(),
        }),
        Err(Stop::Declined) => conn.send(&Reply::Failed {
            reason: "Stopped before going past a limit.".into(),
        }),
        Err(Stop::Failed(reason)) => conn.send(&Reply::Failed { reason }),
    }
}

fn run_extract(
    conn: &mut impl Conn,
    job: ExtractJob<'_>,
    written: &mut Vec<String>,
) -> Result<(), Stop> {
    let mut reader = Reader::open(job.archive).map_err(|e| Stop::Failed(e.0))?;
    let mut writer = Writer::new(job.staging, job.umask);
    let mut meter = Meter::new(job.limits);
    let mut tree: Option<Tree> = None;
    let mut buf = vec![0u8; 256 * 1024];
    let mut last_progress = Instant::now();
    let mut items: u64 = 0;

    loop {
        let mut entry = match reader.next() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => return Err(Stop::Failed(e.0)),
        };
        let tree = tree.get_or_insert_with(|| Tree::new(format_of(&reader), job.encoding));
        if items == 0 && reader.is_plain_file() {
            return Err(Stop::Failed(
                "The file isn't an archive Atlas Archive can read.".into(),
            ));
        }
        if tree.format.compressed_file {
            entry.path = job.raw_name.clone().into_bytes();
            entry.utf8 = true;
        }
        items += 1;
        if let Err(e) = meter.start_entry() {
            ask(conn, &mut meter, e)?;
        }
        let (id, moved, replaced) = match tree.add(&entry) {
            Added::Skipped => {
                reader.skip().map_err(|e| Stop::Failed(e.0))?;
                continue;
            }
            Added::Node {
                id,
                moved,
                replaced,
            } => (id, moved, replaced),
        };
        if let Some(m) = moved {
            writer.moved(tree, &m)?;
        }
        let wanted = job
            .entries
            .as_ref()
            .is_none_or(|set| set.contains(&entry.index));
        if !wanted || entry.kind != Kind::File && entry.kind != Kind::Dir {
            // Links are made at the end; devices never.
            reader.skip().map_err(|e| Stop::Failed(e.0))?;
            continue;
        }
        if replaced.is_some() {
            writer.replace(tree, id)?;
        }
        if entry.kind == Kind::Dir {
            if let Err(e) = writer.dir(tree, id) {
                writer.failed(id, e);
            }
            reader.skip().map_err(|e| Stop::Failed(e.0))?;
            continue;
        }
        let mut out = match writer.file(tree, id, entry.size) {
            Ok(out) => out,
            Err(e) if is_fatal(&e) => return Err(e.into()),
            Err(e) => {
                writer.failed(id, e);
                reader.skip().map_err(|e| Stop::Failed(e.0))?;
                continue;
            }
        };
        let copied: Result<(), Stop> = loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) => break Err(Stop::Failed(e.0)),
            };
            if let Err(e) = out.write_all(&buf[..n]) {
                if is_fatal(&e) {
                    return Err(e.into());
                }
                break Err(Stop::Failed(plain_io(&e)));
            }
            if let Err(e) = meter.add(n as u64, reader.bytes_read(), entry.packed) {
                ask(conn, &mut meter, e)?;
            }
            if last_progress.elapsed() >= PROGRESS_EVERY {
                last_progress = Instant::now();
                conn.send(&Reply::Progress {
                    bytes: meter.written(),
                    items,
                })?;
            }
        };
        match copied {
            Ok(()) => writer.finish_file(tree, out)?,
            Err(Stop::Failed(reason)) => {
                // A damaged or undecryptable entry: drop what was written
                // and go on; a broken stream fails at the next header.
                drop(out);
                let _ = writer.replace(tree, id);
                conn.send(&Reply::Skipped {
                    index: entry.index,
                    reason,
                })?;
            }
            Err(stop) => return Err(stop),
        }
    }

    let Some(mut tree) = tree else {
        return Ok(()); // An empty archive.
    };
    tree.finish();
    let failed = writer.finish(&tree)?;
    for s in &tree.skipped {
        conn.send(&Reply::Skipped {
            index: s.index,
            reason: s.reason.clone(),
        })?;
    }
    for n in &tree.nodes {
        if let (Some(refused), Some(index)) = (&n.refused, n.entry)
            && job.entries.as_ref().is_none_or(|set| set.contains(&index))
        {
            conn.send(&Reply::Skipped {
                index,
                reason: refused.reason(),
            })?;
        }
    }
    for f in failed {
        if let Some(index) = tree.nodes[f.node as usize].entry {
            conn.send(&Reply::Skipped {
                index,
                reason: plain_io(&f.error),
            })?;
        }
    }
    conn.send(&Reply::Progress {
        bytes: meter.written(),
        items,
    })?;
    *written = writer.top_level(&tree);
    Ok(())
}

/// Errors that stop the whole job rather than one entry.
fn is_fatal(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOSPC | libc::EDQUOT | libc::EROFS | libc::EIO)
    )
}

/// Reads every entry's data and reports the damaged ones.
pub fn test(conn: &mut impl Conn, archive: BorrowedFd<'_>) -> io::Result<()> {
    let mut reader = match Reader::open(archive) {
        Ok(r) => r,
        Err(e) => return conn.send(&Reply::Failed { reason: e.0 }),
    };
    let mut buf = vec![0u8; 256 * 1024];
    let mut bytes: u64 = 0;
    let mut items: u64 = 0;
    let mut last_progress = Instant::now();
    loop {
        let entry: Entry = match reader.next() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => return conn.send(&Reply::Failed { reason: e.0 }),
        };
        if items == 0 && reader.is_plain_file() {
            return conn.send(&not_an_archive());
        }
        items += 1;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes += n as u64,
                Err(e) => {
                    conn.send(&Reply::Skipped {
                        index: entry.index,
                        reason: e.0,
                    })?;
                    break;
                }
            }
            if last_progress.elapsed() >= PROGRESS_EVERY {
                last_progress = Instant::now();
                conn.send(&Reply::Progress { bytes, items })?;
            }
        }
    }
    conn.send(&Reply::Progress { bytes, items })?;
    conn.send(&Reply::Done {
        written: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::os::fd::AsFd;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// A client that answers limits with `go_on` and records every reply.
    struct Fake {
        go_on: bool,
        replies: Vec<Reply>,
        pending: VecDeque<Request>,
    }

    impl Conn for Fake {
        fn send(&mut self, r: &Reply) -> io::Result<()> {
            if matches!(r, Reply::Limit(_)) {
                self.pending.push_back(Request::GoOn(self.go_on));
            }
            self.replies.push(r.clone());
            Ok(())
        }
        fn recv(&mut self) -> io::Result<Option<Request>> {
            Ok(self.pending.pop_front())
        }
    }

    fn fake(go_on: bool) -> Fake {
        Fake {
            go_on,
            replies: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let p = base.join(format!("atlas-job-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn tar(dir: &Path, name: &str, args: &[&str]) -> PathBuf {
        let out = dir.join(name);
        let ok = Command::new("tar")
            .arg("-cf")
            .arg(&out)
            .args(args)
            .current_dir(dir.join("src"))
            .status()
            .unwrap();
        assert!(ok.success());
        out
    }

    fn run_extract(archive: &Path, staging: &Path, limits: Limits, go_on: bool) -> Fake {
        let f = std::fs::File::open(archive).unwrap();
        let mut c = fake(go_on);
        extract(
            &mut c,
            ExtractJob {
                archive: f.as_fd(),
                staging: crate::extract::open_dir(staging).unwrap(),
                umask: 0o022,
                encoding: NameEncoding::Utf8,
                entries: None,
                limits,
                raw_name: "data".into(),
            },
        )
        .unwrap();
        c
    }

    #[test]
    fn lists_and_extracts_a_tar() {
        let d = scratch("tar");
        std::fs::create_dir_all(d.join("src/top/sub")).unwrap();
        std::fs::write(d.join("src/top/sub/f.txt"), b"content").unwrap();
        std::os::unix::fs::symlink("sub/f.txt", d.join("src/top/l")).unwrap();
        let a = tar(&d, "a.tar", &["top"]);

        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        list(&mut c, f.as_fd()).unwrap();
        assert!(
            matches!(c.replies.last(), Some(Reply::Listed { entries: 4 })),
            "{:?}",
            c.replies
        );
        assert!(
            c.replies
                .iter()
                .any(|r| matches!(r, Reply::Format(f) if f.name == "tar"))
        );

        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&a, &staging, Limits::new(None), false);
        assert_eq!(
            c.replies.last(),
            Some(&Reply::Done {
                written: vec![b"top".to_vec()]
            }),
            "{:?}",
            c.replies
        );
        assert_eq!(
            std::fs::read(staging.join("top/sub/f.txt")).unwrap(),
            b"content"
        );
        assert_eq!(std::fs::read(staging.join("top/l")).unwrap(), b"content");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_bomb_asks_and_stops() {
        let d = scratch("bomb");
        std::fs::create_dir_all(d.join("src")).unwrap();
        // 300 MiB of zeros compresses to about 300 KiB: past 256 MiB at
        // more than 100:1.
        let ok = Command::new("sh")
            .arg("-c")
            .arg("head -c 314572800 /dev/zero > src/zeros && tar -czf bomb.tar.gz -C src zeros && rm src/zeros")
            .current_dir(&d)
            .status()
            .unwrap();
        assert!(ok.success());
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&d.join("bomb.tar.gz"), &staging, Limits::new(None), false);
        assert!(c.replies.iter().any(
            |r| matches!(r, Reply::Limit(l) if l.kind == atlas_archive_core::limits::Kind::Ratio)
        ));
        assert!(
            matches!(c.replies.last(), Some(Reply::Failed { .. })),
            "{:?}",
            c.replies.last()
        );
        let size = std::fs::metadata(staging.join("zeros"))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(size <= 257 * 1024 * 1024 + 256 * 1024, "{size}");

        // Saying yes goes on to the end.
        std::fs::remove_dir_all(&staging).unwrap();
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&d.join("bomb.tar.gz"), &staging, Limits::new(None), true);
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies.last()
        );
        assert_eq!(
            std::fs::metadata(staging.join("zeros")).unwrap().len(),
            314572800
        );

        // Yes can't go past the free space.
        std::fs::remove_dir_all(&staging).unwrap();
        std::fs::create_dir(&staging).unwrap();
        let tight = Limits {
            free_space: 1024 * 1024,
            ..Limits::new(None)
        };
        let c = run_extract(&d.join("bomb.tar.gz"), &staging, tight, true);
        assert!(
            !c.replies.iter().any(|r| matches!(r, Reply::Limit(_))),
            "{:?}",
            c.replies
        );
        assert!(
            matches!(c.replies.last(), Some(Reply::Failed { reason }) if reason.contains("enough space")),
            "{:?}",
            c.replies.last()
        );
        assert!(
            free_space(crate::extract::open_dir(&staging).unwrap().as_fd()).is_some_and(|f| f > 0)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hostile_tar_entries_are_skipped() {
        let d = scratch("hostile");
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("src/ok"), b"ok").unwrap();
        // GNU tar keeps "../" only with -P; the transform makes the names.
        let a = d.join("evil.tar");
        let ok = Command::new("tar")
            .args(["-cf"])
            .arg(&a)
            .args(["-P", "--transform=s|^ok$|../escape|", "ok"])
            .current_dir(d.join("src"))
            .status()
            .unwrap();
        assert!(ok.success());
        let ok = Command::new("tar")
            .args(["-rf"])
            .arg(&a)
            .args(["-P", "--transform=s|^ok$|/tmp/absolute|", "ok"])
            .current_dir(d.join("src"))
            .status()
            .unwrap();
        assert!(ok.success());
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&a, &staging, Limits::new(None), false);
        let skipped = c
            .replies
            .iter()
            .filter(|r| matches!(r, Reply::Skipped { .. }))
            .count();
        assert_eq!(skipped, 2, "{:?}", c.replies);
        assert!(std::fs::read_dir(&staging).unwrap().next().is_none());
        assert!(!d.join("escape").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_plain_file_is_refused() {
        let d = scratch("plain");
        std::fs::write(d.join("x.txt"), b"just text, not an archive").unwrap();
        let f = std::fs::File::open(d.join("x.txt")).unwrap();
        let mut c = fake(false);
        list(&mut c, f.as_fd()).unwrap();
        assert!(
            matches!(c.replies.last(), Some(Reply::Failed { .. })),
            "{:?}",
            c.replies
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
