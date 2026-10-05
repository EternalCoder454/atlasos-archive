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
use atlas_archive_core::tree::{Added, MAX_SKIPPED, Tree};
use zeroize::Zeroizing;

use crate::extract::{Writer, is_fatal};
use crate::libarchive::Reader;

/// How the job talks to its client.
pub trait Conn {
    fn send(&mut self, reply: &Reply) -> io::Result<()>;
    /// The next request; `None` when the client has gone.
    fn recv(&mut self) -> io::Result<Option<Request>>;
    /// A request is waiting that nothing asked for (the only one a job waits
    /// for is the answer to a limit question, read in `ask`). Reads it.
    fn unexpected_request(&mut self) -> io::Result<bool> {
        Ok(false)
    }
}

/// Frames on a pair of pipes.
pub struct Pipes<R, W> {
    pub input: R,
    pub output: W,
}

impl<R: io::Read + AsRawFd, W: io::Write> Conn for Pipes<R, W> {
    fn send(&mut self, reply: &Reply) -> io::Result<()> {
        proto::write_frame(&mut self.output, &reply.encode())
    }

    fn recv(&mut self) -> io::Result<Option<Request>> {
        match proto::read_frame(&mut self.input)? {
            Some(frame) => Ok(Some(Request::decode(&frame)?)),
            None => Ok(None),
        }
    }

    fn unexpected_request(&mut self) -> io::Result<bool> {
        let mut p = libc::pollfd {
            fd: self.input.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd; a zero timeout never blocks.
        let n = unsafe { libc::poll(&mut p, 1, 0) };
        // A failed poll or a hang-up with nothing to read is no request.
        if n <= 0 || p.revents & libc::POLLIN == 0 {
            return Ok(false);
        }
        Ok(self.recv()?.is_some())
    }
}

const PROGRESS_EVERY: Duration = Duration::from_millis(100);
/// Entries frames are sent once their entries pass this many bytes.
const BATCH_BYTES: usize = 256 * 1024;
/// The most entries one listing holds: what the client's tree holds.
const MAX_LISTED: usize = atlas_archive_core::tree::MAX_NODES;
const OUT_OF_TURN: &str = "The request came out of turn.";
/// Per-entry errors logged in one job; the rest are counted.
const MAX_LOGGED: u32 = 50;

/// The progress clock: `due` is true at most every `PROGRESS_EVERY`.
struct Clock(Instant);

impl Clock {
    fn new() -> Clock {
        Clock(Instant::now())
    }

    fn due(&mut self) -> bool {
        #[cfg(test)]
        let every = EVERY_FOR_TESTS.with(std::cell::Cell::get);
        #[cfg(not(test))]
        let every = PROGRESS_EVERY;
        if self.0.elapsed() >= every {
            self.0 = Instant::now();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Tests that need many ticks shorten the interval.
    static EVERY_FOR_TESTS: std::cell::Cell<Duration> = const { std::cell::Cell::new(PROGRESS_EVERY) };
}

/// Sends `Progress`; a request nobody asked for fails the job.
fn progress(conn: &mut impl Conn, bytes: u64, items: u64) -> io::Result<()> {
    if conn.unexpected_request()? {
        return Err(io::Error::new(io::ErrorKind::InvalidData, OUT_OF_TURN));
    }
    conn.send(&Reply::Progress { bytes, items })
}

/// One log line about a failure: the format, how far the archive was read,
/// the entry and an error code (a libarchive errno or an OS one), never text
/// from the archive.
fn note(what: &str, reader: Option<&Reader>, entry: Option<u32>, code: i32) {
    match reader {
        Some(r) => crate::log_line!(
            "{what}: format={} bytes={} entry={} code={code}",
            r.format_name(),
            r.bytes_read(),
            entry.map_or(-1, i64::from),
        ),
        None => crate::log_line!("{what}: code={code}"),
    }
}

/// `note` for per-entry errors, at most `MAX_LOGGED` of them per job.
#[derive(Default)]
struct Trace {
    logged: u32,
    more: u64,
}

impl Trace {
    fn entry(&mut self, what: &str, reader: &Reader, entry: u32, code: i32) {
        if self.logged < MAX_LOGGED {
            self.logged += 1;
            note(what, Some(reader), Some(entry), code);
        } else {
            self.more += 1;
        }
    }

    fn end(&self) {
        if self.more > 0 {
            crate::log_line!("{} more entry errors not logged", self.more);
        }
    }
}

fn os_code(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// The most data one `skip()` call may decode, by an entry's declared size:
/// one call can't report progress or be interrupted, so it must stay well
/// inside the client's 30 s deadline.
const SKIP_MAX: u64 = 32 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    /// Tests that need entries to be read and thrown away make this small.
    static SKIP_MAX_FOR_TESTS: std::cell::Cell<u64> = const { std::cell::Cell::new(SKIP_MAX) };
}

fn skip_max() -> u64 {
    #[cfg(test)]
    return SKIP_MAX_FOR_TESTS.with(std::cell::Cell::get);
    #[cfg(not(test))]
    SKIP_MAX
}

/// How skipping an entry's data went.
enum Skipped {
    Done,
    /// The entry's data is damaged but the archive can go on: the reason, in
    /// words.
    Damaged(String),
}

/// Skips the current entry's data. A seek (`skip()`) where the archive stores
/// its entries as they are and states the entry's size (an unfiltered zip with
/// no central directory streams, and its skip would inflate the entry), and
/// for any entry declared at most `SKIP_MAX`. Otherwise the data is read and
/// thrown away, so it is counted, reported and can be stopped. The encrypted
/// flag is the archive's word and earns nothing: without the password a read
/// fails fast, and that is `Damaged`. A `skip()` on a path that isn't a plain
/// seek is metered: the bytes the decoder produced (`decoded_bytes`), or the
/// declared size if more, are fed to `on_data` after the call. `on_data` is
/// called with every chunk thrown away: it counts them, reports progress and
/// can stop the job. A read error that libarchive can go on after is
/// `Damaged`, not a failure of the job: the next header says if the stream is
/// broken. Errors are logged through `trace`.
fn skip_entry(
    reader: &mut Reader,
    buf: &mut [u8],
    size: Option<u64>,
    index: u32,
    trace: &mut Trace,
    on_data: &mut dyn FnMut(&Reader, u64) -> Result<(), Stop>,
) -> Result<Skipped, Stop> {
    let plain = reader.skip_is_cheap() && size.is_some();
    let seek = plain || size.is_some_and(|s| s <= skip_max());
    let mut failed = |reader: &Reader, e: crate::libarchive::Error| {
        trace.entry("skipping failed", reader, index, reader.errno());
        if reader.can_go_on() {
            Ok(Skipped::Damaged(e.0))
        } else {
            Err(Stop::Failed(e.0))
        }
    };
    if seek {
        let before = reader.decoded_bytes();
        let r = reader.skip();
        if !plain {
            let delta = reader.decoded_bytes().saturating_sub(before);
            on_data(reader, delta.max(size.unwrap_or(0)))?;
        }
        return match r {
            Ok(()) => Ok(Skipped::Done),
            Err(e) => failed(reader, e),
        };
    }
    loop {
        match reader.read(buf) {
            Ok(0) => return Ok(Skipped::Done),
            Ok(n) => on_data(reader, n as u64)?,
            Err(e) => return failed(reader, e),
        }
    }
}

/// What a listing may read and throw away before it is given up on. A listing
/// has nobody to ask (the client refuses a limit question while listing), so
/// these are hard: far past the sizes an extraction asks about, for an
/// archive that is only listed.
#[derive(Clone, Copy)]
struct ListBound {
    /// The most bytes thrown away.
    bytes: u64,
    /// The most thrown away per byte read from the file...
    ratio: u64,
    /// ...once this many have been.
    ratio_after: u64,
}

impl ListBound {
    const DEFAULT: ListBound = ListBound {
        bytes: 1024 * 1024 * 1024 * 1024,
        ratio: 5000,
        ratio_after: 4 * 1024 * 1024 * 1024,
    };

    fn passed(&self, discarded: u64, archive_read: u64) -> bool {
        discarded > self.bytes
            || (discarded > self.ratio_after && discarded / archive_read.max(1) >= self.ratio)
    }
}

/// The node a cpio hard link's name points at, resolved as the tree will when
/// it is finished: the regular file stored earlier at the path it names.
fn hardlink_target(tree: &Tree, entry: &Entry, encoding: NameEncoding) -> Option<u32> {
    let enc = if entry.utf8 {
        NameEncoding::Utf8
    } else {
        encoding
    };
    let path = atlas_archive_core::link::check_hardlink(
        entry.link.as_deref()?,
        enc,
        tree.format.made_on_dos,
    )
    .ok()?;
    let to = tree.find(path.components.iter().map(|c| c.disk.as_str()))?;
    let node = &tree.nodes[to as usize];
    (node.kind == Kind::File && node.entry.is_some_and(|i| i < entry.index)).then_some(to)
}

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

/// Lists every entry: `Entries` batches, then `Format`, then `Listed`. If the
/// archive breaks part-way, the entries read so far are sent first, then
/// `Failed` (no `Format`, no `Listed`).
pub fn list(conn: &mut impl Conn, archive: BorrowedFd<'_>) -> io::Result<()> {
    list_with(conn, archive, None)
}

/// `list` with a password, for archives whose headers are encrypted: without
/// the right one the reply is `NeedPassword`.
pub fn list_with(
    conn: &mut impl Conn,
    archive: BorrowedFd<'_>,
    password: Option<&[u8]>,
) -> io::Result<()> {
    list_bounded(conn, archive, password, ListBound::DEFAULT)
}

fn list_bounded(
    conn: &mut impl Conn,
    archive: BorrowedFd<'_>,
    password: Option<&[u8]>,
    bound: ListBound,
) -> io::Result<()> {
    let mut reader = match Reader::open_with(archive, password) {
        Ok(r) => r,
        Err(e) => {
            note("list: open failed", None, None, 0);
            return conn.send(&Reply::Failed { reason: e.0 });
        }
    };
    let mut batch = Vec::new();
    let mut batch_bytes = 0;
    let mut sent: u64 = 0;
    let mut count: u32 = 0;
    let mut clock = Clock::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut discarded = 0u64;
    let mut trace = Trace::default();
    // How the listing ended, if not at its end: the reply to send once the
    // entries read so far are on their way.
    let end: Option<Reply> = 'read: {
        loop {
            let entry = match reader.next_header() {
                Ok(Some(e)) => e,
                Ok(None) => break 'read None,
                Err(_) if count == 0 && reader.wants_password() => {
                    batch.clear();
                    break 'read Some(Reply::NeedPassword {
                        wrong: password.is_some(),
                    });
                }
                Err(e) => {
                    note(
                        "list: header failed",
                        Some(&reader),
                        Some(count),
                        reader.errno(),
                    );
                    break 'read Some(Reply::Failed { reason: e.0 });
                }
            };
            if count == 0 && reader.is_plain_file() {
                break 'read Some(not_an_archive());
            }
            if count as usize >= MAX_LISTED || sent + batch_bytes as u64 > proto::MAX_LISTING {
                note("list: too many entries", Some(&reader), Some(count), 0);
                break 'read Some(Reply::Failed {
                    reason: "The archive lists more items than Atlas Archive can show.".into(),
                });
            }
            let mut on_data = |r: &Reader, n: u64| {
                discarded += n;
                if bound.passed(discarded, r.bytes_read()) {
                    note("list: too much data to read", Some(r), Some(count), 0);
                    return Err(Stop::Failed(
                        "The archive holds far more data than its size, so it can't be listed."
                            .into(),
                    ));
                }
                if clock.due() {
                    progress(&mut *conn, r.bytes_read(), u64::from(count))?;
                }
                Ok(())
            };
            match skip_entry(
                &mut reader,
                &mut buf,
                entry.size,
                count,
                &mut trace,
                &mut on_data,
            ) {
                Ok(Skipped::Done) => {}
                // The entry is listed all the same (logged by `skip_entry`); a
                // broken stream fails at the next header.
                Ok(Skipped::Damaged(_)) => {}
                Err(stop) => break 'read Some(stop_reply(stop)),
            }
            batch_bytes += 64 + entry.path.len() + entry.link.as_ref().map_or(0, Vec::len);
            batch.push(entry);
            count += 1;
            if clock.due() {
                progress(conn, reader.bytes_read(), u64::from(count))?;
            }
            if batch_bytes >= BATCH_BYTES {
                sent += batch_bytes as u64;
                conn.send(&Reply::Entries(std::mem::take(&mut batch)))?;
                batch_bytes = 0;
            }
        }
    };
    trace.end();
    if !batch.is_empty() {
        conn.send(&Reply::Entries(batch))?;
    }
    if let Some(reply) = end {
        return conn.send(&reply);
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
    /// For encrypted entries.
    pub password: Option<Zeroizing<Vec<u8>>>,
    pub raw_name: String,
}

/// The bytes free on the file system holding `dir`, if it can tell. A drive
/// that answers with zeros for its block size or count (some FUSE and network
/// file systems) gives no figure: `None`, never `Some(0)`.
pub fn free_space(dir: BorrowedFd<'_>) -> Option<u64> {
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: fstatvfs fills `st` on success; `dir` is a live descriptor.
    if unsafe { libc::fstatvfs(dir.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: initialised by the successful call above.
    let st = unsafe { st.assume_init() };
    free_from(st.f_bavail, st.f_frsize, st.f_blocks)
}

/// The figure, or `None` when block size or count is zero.
fn free_from(bavail: u64, frsize: u64, blocks: u64) -> Option<u64> {
    (frsize != 0 && blocks != 0).then(|| bavail.saturating_mul(frsize))
}

/// Asks the client about a limit. `Ok`: go on, with that limit off. A limit
/// that can't be gone past (the free space, the nesting) fails the job. The
/// answer is the only request a job expects, and only while a question is
/// open: any other request, before or during it, is out of turn.
fn ask(conn: &mut impl Conn, meter: &mut Meter, e: Exceeded) -> Result<(), Stop> {
    if !e.kind.askable() {
        return Err(Stop::Failed(e.question()));
    }
    if conn.unexpected_request()? {
        return Err(Stop::Failed(OUT_OF_TURN.into()));
    }
    conn.send(&Reply::Limit(e.clone()))?;
    match conn.recv()? {
        Some(Request::GoOn(true)) => {
            meter.allow(e.kind);
            Ok(())
        }
        Some(Request::GoOn(false)) | None => Err(Stop::Declined),
        Some(_) => Err(Stop::Failed(OUT_OF_TURN.into())),
    }
}

/// Why a job stopped early.
enum Stop {
    /// The client said not to go past a limit, or went away.
    Declined,
    Failed(String),
    /// An encrypted entry needs a password; `true`: the one given is wrong.
    NeedPassword(bool),
}

impl Stop {
    /// For the log: what happened, never why in the archive's words.
    fn kind(&self) -> &'static str {
        match self {
            Stop::Declined => "declined at a limit",
            Stop::Failed(_) => "failed",
            Stop::NeedPassword(_) => "needs a password",
        }
    }
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
            // "No such file or directory (os error 2)": the code is for logs.
            let s = match s.rfind(" (os error ") {
                Some(i) if s.ends_with(')') => &s[..i],
                _ => &s[..],
            };
            let mut c = s.chars();
            match c.next() {
                Some(f) => format!("{}{}.", f.to_uppercase(), c.as_str().trim_end_matches('.')),
                None => "Something went wrong.".into(),
            }
        }
    }
}

/// The final reply for a job that stopped early.
fn stop_reply(stop: Stop) -> Reply {
    match stop {
        Stop::Declined => Reply::Failed {
            reason: "Stopped before going past a limit.".into(),
        },
        Stop::Failed(reason) => Reply::Failed { reason },
        Stop::NeedPassword(wrong) => Reply::NeedPassword { wrong },
    }
}

/// Sends `Skipped` frames, at most `MAX_SKIPPED` per job: a hostile archive
/// can't make the worker (or the client) handle a million of them. The rest
/// are counted and sent as one `SkippedMore`.
#[derive(Default)]
struct SkipOut {
    sent: usize,
    more: u64,
}

impl SkipOut {
    fn send(&mut self, conn: &mut impl Conn, index: u32, reason: String) -> io::Result<()> {
        if self.sent < MAX_SKIPPED {
            self.sent += 1;
            conn.send(&Reply::Skipped { index, reason })
        } else {
            self.more += 1;
            Ok(())
        }
    }

    fn finish(self, conn: &mut impl Conn, more: u64) -> io::Result<()> {
        let count = self.more.saturating_add(more);
        if count > 0 {
            conn.send(&Reply::SkippedMore { count })?;
        }
        Ok(())
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
        Err(stop) => {
            crate::log_line!("extract stopped: {}", stop.kind());
            conn.send(&stop_reply(stop))
        }
    }
}

fn run_extract(
    conn: &mut impl Conn,
    job: ExtractJob<'_>,
    written: &mut Vec<String>,
) -> Result<(), Stop> {
    let mut reader = Reader::open_with(job.archive, job.password.as_deref().map(Vec::as_slice))
        .map_err(|e| {
            note("extract: open failed", None, None, 0);
            Stop::Failed(e.0)
        })?;
    let had_password = job.password.is_some();
    let mut writer = Writer::new(job.staging, job.umask);
    let mut meter = Meter::new(job.limits);
    let mut tree: Option<Tree> = None;
    let mut buf = vec![0u8; 256 * 1024];
    let mut clock = Clock::new();
    // Entries read so far, each counted once whatever it is.
    let mut items: u64 = 0;
    // Of those, the folders and links, which are made when the pass ends:
    // they show as done then, one step each, so the figure advances through
    // the end without counting anything twice.
    let mut deferred: u64 = 0;
    // Bytes of entry data handled: written to files, or read and thrown away
    // (entries not wanted). Never goes back.
    let mut done: u64 = 0;
    let mut skips = SkipOut::default();
    let mut trace = Trace::default();

    // Skips the current entry's data. Whatever is read and thrown away
    // counts as progress, and against the limits like what is written: a
    // bomb in entries nobody chose is a bomb all the same.
    macro_rules! skip {
        ($index:expr, $size:expr, $report:expr) => {
            // Damaged data in an entry nobody wanted isn't the job's
            // problem: it is counted in the log, and reported only if the
            // entry was selected.
            match skip_entry(
                &mut reader,
                &mut buf,
                $size,
                $index,
                &mut trace,
                &mut |r, n| {
                    done += n;
                    if let Err(e) = meter.add_discarded(n, r.bytes_read()) {
                        ask(conn, &mut meter, e)?;
                    }
                    if clock.due() {
                        progress(conn, done, items - deferred)?;
                    }
                    Ok(())
                },
            )? {
                Skipped::Done => {}
                Skipped::Damaged(reason) => {
                    if $report {
                        skips.send(conn, $index, reason)?;
                    }
                }
            }
        };
    }

    loop {
        let mut entry = match reader.next_header() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) if reader.wants_password() => return Err(Stop::NeedPassword(had_password)),
            Err(e) => {
                note(
                    "extract: header failed",
                    Some(&reader),
                    Some(items as u32),
                    reader.errno(),
                );
                return Err(Stop::Failed(e.0));
            }
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
        deferred += u64::from(matches!(
            entry.kind,
            Kind::Dir | Kind::Symlink | Kind::Hardlink
        ));
        // Every entry, data or not, keeps the client's clock going.
        if clock.due() {
            progress(conn, done, items - deferred)?;
        }
        meter.start_entry();
        // cpio (newc) keeps the data of a set of hard links with the last
        // name, which libarchive reports as a link to the first: the data
        // belongs in the first name's file.
        let carries_link_data =
            entry.kind == Kind::Hardlink && entry.size.is_some_and(|s| s > 0) && reader.is_cpio();
        // A first name of such a set: empty now, its data comes later.
        let first_of_set =
            entry.kind == Kind::File && entry.size == Some(0) && reader.cpio_linked();
        let nodes_before = tree.nodes.len();
        let added = tree.add(&entry);
        // Every node costs an entry and some disk, written or not.
        let new_nodes = (tree.nodes.len() - nodes_before) as u64;
        if new_nodes > 0
            && let Err(e) = meter.add_nodes(new_nodes)
        {
            ask(conn, &mut meter, e)?;
        }
        let wanted = job
            .entries
            .as_ref()
            .is_none_or(|set| set.contains(&entry.index));
        let (id, moved, replaced) = match added {
            Added::Skipped => {
                // The name that carries the data of a cpio set was refused:
                // the first name, still empty, would read as a success.
                if carries_link_data
                    && let Some(to) = hardlink_target(tree, &entry, job.encoding)
                    && writer.is_pending(to)
                {
                    if let Err(r) = writer.replace(tree, to) {
                        trace.entry("leftover not removed", &reader, entry.index, os_code(&r));
                    }
                    writer.failed(to, io::Error::other("its data wasn't found in the archive"));
                }
                // Reported with the tree's skipped entries at the end.
                skip!(entry.index, entry.size, false);
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
        // Whatever this entry is, it takes the place of the earlier one with
        // its path: remove what that one left (a file that would otherwise
        // stay behind with its mode when this entry is a link, a FIFO or
        // not selected).
        if replaced.is_some() {
            writer.replace(tree, id)?;
        }
        // Written even when this name isn't selected, if the file it
        // completes is.
        let data_target = carries_link_data
            .then(|| hardlink_target(tree, &entry, job.encoding))
            .flatten()
            // Only a first name still waiting for data: any other is a hard
            // link made at the end, and must not truncate good data.
            .filter(|&to| writer.is_pending(to));
        if data_target.is_none() && (!wanted || entry.kind != Kind::File && entry.kind != Kind::Dir)
        {
            // Links are made at the end; devices never.
            skip!(entry.index, entry.size, wanted);
            continue;
        }
        if entry.kind == Kind::Dir {
            if let Err(e) = writer.dir(tree, id) {
                if is_fatal(&e) {
                    note(
                        "extract: folder failed",
                        Some(&reader),
                        Some(entry.index),
                        os_code(&e),
                    );
                    return Err(e.into());
                }
                trace.entry("folder failed", &reader, entry.index, os_code(&e));
                writer.failed(id, e);
            }
            skip!(entry.index, entry.size, false);
            continue;
        }
        let data_node = data_target.unwrap_or(id);
        let opened = match data_target {
            Some(to) => writer.reopen(tree, to, entry.size),
            None => writer.file(tree, id, entry.size),
        };
        let mut out = match opened {
            Ok(out) => out,
            Err(e) if is_fatal(&e) => {
                note(
                    "extract: file failed",
                    Some(&reader),
                    Some(entry.index),
                    os_code(&e),
                );
                return Err(e.into());
            }
            Err(e) => {
                trace.entry("file not created", &reader, entry.index, os_code(&e));
                match data_target {
                    // The first name stays empty: take it back out, so it is
                    // reported and the last name isn't linked to it.
                    Some(to) => {
                        if let Err(r) = writer.replace(tree, to) {
                            trace.entry("leftover not removed", &reader, entry.index, os_code(&r));
                        }
                        writer.failed(to, e);
                    }
                    None => writer.failed(id, e),
                }
                // Already failed above: nothing more to say about its data.
                skip!(entry.index, entry.size, false);
                continue;
            }
        };
        let mut code = 0;
        let copied: Result<(), Stop> = loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(_) if entry.encrypted && reader.wants_password() => {
                    return Err(Stop::NeedPassword(had_password));
                }
                Err(e) => {
                    code = reader.errno();
                    break Err(Stop::Failed(e.0));
                }
            };
            if let Err(e) = out.write_all(&buf[..n]) {
                if is_fatal(&e) {
                    note(
                        "extract: write failed",
                        Some(&reader),
                        Some(entry.index),
                        os_code(&e),
                    );
                    return Err(e.into());
                }
                code = os_code(&e);
                break Err(Stop::Failed(plain_io(&e)));
            }
            if let Err(e) = meter.add(n as u64, reader.bytes_read(), entry.packed) {
                ask(conn, &mut meter, e)?;
            }
            done += n as u64;
            if clock.due() {
                progress(conn, done, items - deferred)?;
            }
        };
        match copied {
            Ok(()) => match if first_of_set {
                writer.finish_file_for_data_to_come(tree, out)
            } else {
                writer.finish_file(tree, out)
            } {
                Ok(()) => {}
                Err(e) if is_fatal(&e) => {
                    note(
                        "extract: close failed",
                        Some(&reader),
                        Some(entry.index),
                        os_code(&e),
                    );
                    return Err(e.into());
                }
                Err(e) => {
                    // Incomplete (or its mode couldn't be set): not a file
                    // to keep, not a hard link target.
                    trace.entry("file not completed", &reader, entry.index, os_code(&e));
                    if let Err(r) = writer.replace(tree, data_node) {
                        trace.entry("leftover not removed", &reader, entry.index, os_code(&r));
                    }
                    if data_node != id {
                        writer.failed(data_node, io::Error::other("its data was incomplete"));
                    }
                    skips.send(conn, entry.index, plain_io(&e))?;
                }
            },
            Err(Stop::Failed(reason)) => {
                // A damaged or undecryptable entry: drop what was written
                // and go on; a broken stream fails at the next header.
                drop(out);
                trace.entry("entry unreadable", &reader, entry.index, code);
                if let Err(r) = writer.replace(tree, data_node) {
                    trace.entry("leftover not removed", &reader, entry.index, os_code(&r));
                }
                if data_node != id {
                    writer.failed(
                        data_node,
                        io::Error::other("its data could not be read from the archive"),
                    );
                }
                skips.send(conn, entry.index, reason)?;
            }
            Err(stop) => return Err(stop),
        }
    }
    trace.end();

    let Some(mut tree) = tree else {
        return Ok(()); // An empty archive.
    };
    tree.finish();
    let selected = job.entries.as_ref();
    let is_selected = |index: u32| selected.is_none_or(|set| set.contains(&index));
    // Links and folder modes can be a million steps: the clock runs here
    // too, and each step shows one more of the deferred entries as done.
    let mut steps = 0u64;
    let failed = writer
        .finish(&tree, selected, &mut || {
            steps += 1;
            if clock.due() {
                progress(conn, done, items - deferred + steps.min(deferred))?;
            }
            Ok(())
        })
        .inspect_err(|e| note("extract: finishing failed", None, None, os_code(e)))?;
    for s in tree.skipped.iter().filter(|s| is_selected(s.index)) {
        skips.send(conn, s.index, s.reason.clone())?;
    }
    for n in &tree.nodes {
        if let (Some(refused), Some(index)) = (&n.refused, n.entry)
            && is_selected(index)
        {
            skips.send(conn, index, refused.reason())?;
        }
    }
    let mut finish_trace = Trace::default();
    for f in failed {
        if let Some(index) = tree.nodes[f.node as usize].entry
            && is_selected(index)
        {
            if finish_trace.logged < MAX_LOGGED {
                finish_trace.logged += 1;
                note(
                    "extract: link or folder failed",
                    Some(&reader),
                    Some(index),
                    os_code(&f.error),
                );
            }
            skips.send(conn, index, plain_io(&f.error))?;
        }
    }
    skips.finish(conn, tree.skipped_more)?;
    conn.send(&Reply::Progress { bytes: done, items })?;
    *written = writer.top_level(&tree);
    Ok(())
}

/// Reads every entry's data and reports the damaged ones.
pub fn test(
    conn: &mut impl Conn,
    archive: BorrowedFd<'_>,
    password: Option<&[u8]>,
) -> io::Result<()> {
    let mut reader = match Reader::open_with(archive, password) {
        Ok(r) => r,
        Err(e) => {
            note("test: open failed", None, None, 0);
            return conn.send(&Reply::Failed { reason: e.0 });
        }
    };
    let mut buf = vec![0u8; 256 * 1024];
    // Bytes are metered like an extraction's, so a bomb under test asks too
    // (the free space isn't a limit here: nothing is written).
    let mut meter = Meter::new(Limits::new(None));
    let mut items: u64 = 0;
    let mut skips = SkipOut::default();
    let mut trace = Trace::default();
    let mut clock = Clock::new();
    loop {
        let entry: Entry = match reader.next_header() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) if reader.wants_password() => {
                return conn.send(&Reply::NeedPassword {
                    wrong: password.is_some(),
                });
            }
            Err(e) => {
                note(
                    "test: header failed",
                    Some(&reader),
                    Some(items as u32),
                    reader.errno(),
                );
                return conn.send(&Reply::Failed { reason: e.0 });
            }
        };
        if items == 0 && reader.is_plain_file() {
            return conn.send(&not_an_archive());
        }
        items += 1;
        // Entries without data keep the client's clock going too.
        if clock.due()
            && let Err(e) = progress(conn, meter.written(), items)
        {
            return conn.send(&Reply::Failed {
                reason: plain_io(&e),
            });
        }
        meter.start_entry();
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = meter.add(n as u64, reader.bytes_read(), entry.packed)
                        && let Err(stop) = ask(conn, &mut meter, e)
                    {
                        return conn.send(&stop_reply(stop));
                    }
                }
                Err(_) if entry.encrypted && reader.wants_password() => {
                    return conn.send(&Reply::NeedPassword {
                        wrong: password.is_some(),
                    });
                }
                Err(e) => {
                    trace.entry("entry unreadable", &reader, entry.index, reader.errno());
                    skips.send(conn, entry.index, e.0)?;
                    break;
                }
            }
            if clock.due()
                && let Err(e) = progress(conn, meter.written(), items)
            {
                return conn.send(&Reply::Failed {
                    reason: plain_io(&e),
                });
            }
        }
    }
    trace.end();
    conn.send(&Reply::Progress {
        bytes: meter.written(),
        items,
    })?;
    skips.finish(conn, 0)?;
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
        fn unexpected_request(&mut self) -> io::Result<bool> {
            Ok(self.pending.pop_front().is_some())
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
        // On disk, in the cargo target dir, never in tmpfs.
        let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("../test-scratch")
            });
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
                password: None,
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

    fn extract_with(archive: &Path, staging: &Path, password: Option<&[u8]>) -> Fake {
        let f = std::fs::File::open(archive).unwrap();
        let mut c = fake(false);
        extract(
            &mut c,
            ExtractJob {
                archive: f.as_fd(),
                staging: crate::extract::open_dir(staging).unwrap(),
                umask: 0o022,
                encoding: NameEncoding::Utf8,
                entries: None,
                limits: Limits::new(None),
                raw_name: String::new(),
                password: password.map(|p| Zeroizing::new(p.to_vec())),
            },
        )
        .unwrap();
        c
    }

    #[test]
    fn encrypted_zips_ask_for_the_password() {
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
        for name in ["aes256-secret.zip", "zipcrypto-secret.zip"] {
            let d = scratch(name);
            let a = data.join(name);
            for (password, want) in [
                (None, Some(false)),
                (Some(&b"wrong"[..]), Some(true)),
                (Some(&b"secret"[..]), None),
            ] {
                let staging = d.join("staging");
                let _ = std::fs::remove_dir_all(&staging);
                std::fs::create_dir(&staging).unwrap();
                let c = extract_with(&a, &staging, password);
                match want {
                    Some(wrong) => assert_eq!(
                        c.replies.last(),
                        Some(&Reply::NeedPassword { wrong }),
                        "{name}"
                    ),
                    None => {
                        assert!(
                            matches!(c.replies.last(), Some(Reply::Done { .. })),
                            "{name}: {:?}",
                            c.replies
                        );
                        assert_eq!(
                            std::fs::read(staging.join("f.txt")).unwrap(),
                            b"secret text\n"
                        );
                    }
                }
                let f = std::fs::File::open(&a).unwrap();
                let mut c = fake(false);
                test(&mut c, f.as_fd(), password).unwrap();
                match want {
                    Some(wrong) => assert_eq!(
                        c.replies.last(),
                        Some(&Reply::NeedPassword { wrong }),
                        "{name}"
                    ),
                    None => assert!(
                        matches!(c.replies.last(), Some(Reply::Done { .. })),
                        "{name}"
                    ),
                }
            }
            let _ = std::fs::remove_dir_all(&d);
        }
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

        // Testing the archive meters it too.
        let f = std::fs::File::open(d.join("bomb.tar.gz")).unwrap();
        let mut c = fake(false);
        test(&mut c, f.as_fd(), None).unwrap();
        assert!(c.replies.iter().any(
            |r| matches!(r, Reply::Limit(l) if l.kind == atlas_archive_core::limits::Kind::Ratio)
        ));
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        let f = std::fs::File::open(d.join("bomb.tar.gz")).unwrap();
        let mut c = fake(true);
        test(&mut c, f.as_fd(), None).unwrap();
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies.last()
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
    fn a_drive_with_zero_figures_gives_no_free_space() {
        assert_eq!(free_from(10, 4096, 100), Some(40960));
        assert_eq!(free_from(0, 4096, 100), Some(0));
        assert_eq!(free_from(10, 0, 100), None);
        assert_eq!(free_from(10, 4096, 0), None);
        // /proc reports no blocks at all.
        let proc = std::fs::File::open("/proc").unwrap();
        assert_eq!(free_space(proc.as_fd()), None);
    }

    /// A tar made by a shell script run in `d/src`.
    fn tar_script(d: &Path, script: &str) -> PathBuf {
        let ok = Command::new("sh")
            .arg("-c")
            .arg(script)
            .current_dir(d.join("src"))
            .status()
            .unwrap();
        assert!(ok.success());
        d.join("a.tar")
    }

    fn no_executable_launcher(staging: &Path) {
        use std::os::unix::fs::PermissionsExt;
        for e in std::fs::read_dir(staging).unwrap() {
            let e = e.unwrap();
            let m = std::fs::symlink_metadata(e.path()).unwrap();
            if m.is_file() && e.file_name().to_string_lossy().ends_with(".desktop") {
                assert_eq!(m.permissions().mode() & 0o111, 0, "{:?}", e.path());
            }
        }
    }

    #[test]
    fn a_later_link_or_fifo_replaces_an_earlier_launcher() {
        for (tag, later) in [
            ("sym", "ln -s other x.desktop"),
            ("fifo", "mkfifo x.desktop"),
            ("hard", "ln other x.desktop"),
        ] {
            let d = scratch(&format!("replace-{tag}"));
            std::fs::create_dir_all(d.join("src")).unwrap();
            let a = tar_script(
                &d,
                &format!(
                    "echo run > x.desktop && chmod 755 x.desktop && echo o > other \
                     && tar -cf ../a.tar x.desktop other && rm x.desktop && {later} \
                     && tar -rf ../a.tar x.desktop"
                ),
            );
            let staging = d.join("staging");
            std::fs::create_dir(&staging).unwrap();
            let c = run_extract(&a, &staging, Limits::new(None), false);
            assert!(
                matches!(c.replies.last(), Some(Reply::Done { .. })),
                "{tag}: {:?}",
                c.replies
            );
            no_executable_launcher(&staging);
            let kind = std::fs::symlink_metadata(staging.join("x.desktop"));
            match tag {
                "sym" => assert!(kind.unwrap().file_type().is_symlink()),
                "fifo" => assert!(kind.is_err(), "no FIFO and no old file"),
                _ => assert_eq!(std::fs::read(staging.join("x.desktop")).unwrap(), b"o\n"),
            }
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn an_unselected_later_entry_removes_the_earlier_file() {
        let d = scratch("replace-unselected");
        std::fs::create_dir_all(d.join("src")).unwrap();
        let a = tar_script(
            &d,
            "echo run > x.desktop && chmod 755 x.desktop \
             && tar -cf ../a.tar x.desktop && tar -rf ../a.tar x.desktop",
        );
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        extract(
            &mut c,
            ExtractJob {
                archive: f.as_fd(),
                staging: crate::extract::open_dir(&staging).unwrap(),
                umask: 0o022,
                encoding: NameEncoding::Utf8,
                entries: Some([0].into()),
                limits: Limits::new(None),
                password: None,
                raw_name: String::new(),
            },
        )
        .unwrap();
        assert!(
            std::fs::symlink_metadata(staging.join("x.desktop")).is_err(),
            "{:?}",
            c.replies
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_selected_entries_are_reported_and_linked() {
        let d = scratch("selected");
        std::fs::create_dir_all(d.join("src")).unwrap();
        let a = tar_script(
            &d,
            "echo a > f && ln -s f s1 && ln -s f s2 && ln -s /etc/passwd bad \
             && tar -cf ../a.tar f s1 s2 bad",
        );
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        extract(
            &mut c,
            ExtractJob {
                archive: f.as_fd(),
                staging: crate::extract::open_dir(&staging).unwrap(),
                umask: 0o022,
                encoding: NameEncoding::Utf8,
                entries: Some([0, 1].into()),
                limits: Limits::new(None),
                password: None,
                raw_name: String::new(),
            },
        )
        .unwrap();
        assert!(staging.join("f").is_file());
        assert!(std::fs::symlink_metadata(staging.join("s1")).is_ok());
        assert!(std::fs::symlink_metadata(staging.join("s2")).is_err());
        assert!(
            !c.replies.iter().any(|r| matches!(r, Reply::Skipped { .. })),
            "the unselected refused link isn't reported: {:?}",
            c.replies
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nodes_count_against_the_limits() {
        let d = scratch("nodes");
        std::fs::create_dir_all(d.join("src")).unwrap();
        let a = tar_script(&d, "touch a b c d && tar -cf ../a.tar a b c d");
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let few = Limits {
            entries: 3,
            ..Limits::new(None)
        };
        let c = run_extract(&a, &staging, few, false);
        assert!(c.replies.iter().any(
            |r| matches!(r, Reply::Limit(l) if l.kind == atlas_archive_core::limits::Kind::Entries)
        ));
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        let c = run_extract(&a, &staging, few, true);
        assert!(matches!(c.replies.last(), Some(Reply::Done { .. })));
        // Empty files fill a drive too: four nodes cost 16 KiB.
        let tight = Limits {
            free_space: 3 * atlas_archive_core::limits::NODE_COST,
            ..Limits::new(None)
        };
        let c = run_extract(&a, &staging, tight, true);
        assert!(
            matches!(c.replies.last(), Some(Reply::Failed { reason }) if reason.contains("enough space")),
            "{:?}",
            c.replies.last()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn skipped_frames_are_capped() {
        let d = scratch("capped");
        std::fs::create_dir_all(d.join("src")).unwrap();
        let n = MAX_SKIPPED + 25;
        let a = tar_script(
            &d,
            &format!(
                "seq {n} | xargs touch && tar -cPf ../a.tar --transform='s|^|../|' $(seq {n})"
            ),
        );
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&a, &staging, Limits::new(None), false);
        let skipped = c
            .replies
            .iter()
            .filter(|r| matches!(r, Reply::Skipped { .. }))
            .count();
        assert_eq!(skipped, MAX_SKIPPED);
        assert!(c.replies.contains(&Reply::SkippedMore { count: 25 }));
        assert!(matches!(c.replies.last(), Some(Reply::Done { .. })));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn os_error_codes_are_dropped_from_the_words() {
        let e = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(plain_io(&e), "No such file or directory.");
        let e = io::Error::other("the item holds more data than the archive says it does");
        assert_eq!(
            plain_io(&e),
            "The item holds more data than the archive says it does."
        );
        assert_eq!(
            plain_io(&io::Error::from_raw_os_error(libc::ENOSPC)),
            "There isn't enough space on the drive."
        );
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

    #[test]
    fn a_go_on_out_of_turn_fails_the_job() {
        let d = scratch("outofturn");
        std::fs::create_dir_all(d.join("src")).unwrap();
        let a = tar_script(&d, "touch a b c d && tar -cf ../a.tar a b c d");
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let few = Limits {
            entries: 3,
            ..Limits::new(None)
        };
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(true);
        // A "yes" that nobody asked for is not the answer to the question.
        c.pending.push_back(Request::GoOn(true));
        extract(
            &mut c,
            ExtractJob {
                archive: f.as_fd(),
                staging: crate::extract::open_dir(&staging).unwrap(),
                umask: 0o022,
                encoding: NameEncoding::Utf8,
                entries: None,
                limits: few,
                password: None,
                raw_name: String::new(),
            },
        )
        .unwrap();
        assert!(!c.replies.iter().any(|r| matches!(r, Reply::Limit(_))));
        assert!(
            matches!(c.replies.last(), Some(Reply::Failed { reason }) if reason.contains("out of turn")),
            "{:?}",
            c.replies
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_broken_listing_sends_what_was_read_then_fails() {
        let d = scratch("brokenlist");
        std::fs::create_dir_all(d.join("src")).unwrap();
        let a = tar_script(
            &d,
            "echo 1 > a && echo 2 > b && echo 3 > c && tar -cf ../a.tar a b c",
        );
        // Break the third header (blocks are 512 bytes; each entry takes 2).
        let mut bytes = std::fs::read(&a).unwrap();
        for b in &mut bytes[2048..2048 + 100] {
            *b = 0xff;
        }
        std::fs::write(&a, &bytes).unwrap();
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        list(&mut c, f.as_fd()).unwrap();
        let entries: usize = c
            .replies
            .iter()
            .map(|r| match r {
                Reply::Entries(e) => e.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(entries, 2, "{:?}", c.replies);
        assert!(
            matches!(c.replies.last(), Some(Reply::Failed { .. })),
            "{:?}",
            c.replies
        );
        assert!(!c.replies.iter().any(|r| matches!(r, Reply::Listed { .. })));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn skipping_behind_a_filter_reports_progress() {
        EVERY_FOR_TESTS.with(|c| c.set(Duration::from_millis(1)));
        let d = scratch("skipprogress");
        std::fs::create_dir_all(d.join("src")).unwrap();
        // A big entry nobody selected, then a small one that is.
        let ok = Command::new("sh")
            .arg("-c")
            .arg("head -c 419430400 /dev/zero > src/big && echo small > src/small && tar -czf a.tar.gz -C src big small && rm src/big")
            .current_dir(&d)
            .status()
            .unwrap();
        assert!(ok.success());
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let f = std::fs::File::open(d.join("a.tar.gz")).unwrap();
        // The skipped zeros are a ratio question; yes goes on.
        let mut c = fake(true);
        extract(
            &mut c,
            ExtractJob {
                archive: f.as_fd(),
                staging: crate::extract::open_dir(&staging).unwrap(),
                umask: 0o022,
                encoding: NameEncoding::Utf8,
                entries: Some([1].into()),
                limits: Limits::new(None),
                password: None,
                raw_name: String::new(),
            },
        )
        .unwrap();
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies.last()
        );
        assert_eq!(std::fs::read(staging.join("small")).unwrap(), b"small\n");
        assert!(!staging.join("big").exists());
        let bytes: Vec<u64> = c
            .replies
            .iter()
            .filter_map(|r| match r {
                Reply::Progress { bytes, .. } => Some(*bytes),
                _ => None,
            })
            .collect();
        // The skipped data was read, in steps, and the figure never goes back.
        assert!(bytes.len() >= 2, "{bytes:?}");
        assert!(bytes.windows(2).all(|w| w[0] <= w[1]), "{bytes:?}");
        assert!(*bytes.last().unwrap() >= 419430400, "{bytes:?}");
        assert!(
            bytes[0] < 419430400,
            "progress came before the end: {bytes:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// One cpio newc member.
    fn newc(out: &mut Vec<u8>, ino: u32, name: &str, nlink: u32, data: &[u8]) {
        newc_mode(out, 0o644, ino, name, nlink, data);
    }

    fn newc_mode(out: &mut Vec<u8>, perm: u32, ino: u32, name: &str, nlink: u32, data: &[u8]) {
        let mode = if name == "TRAILER!!!" {
            0
        } else {
            0o100000 | perm
        };
        out.extend(
            format!(
                "070701{ino:08X}{mode:08X}{:08X}{:08X}{nlink:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
                0, 0, 1_000_000_000u32, data.len(), 0, 0, 0, 0, name.len() + 1, 0
            )
            .into_bytes(),
        );
        out.extend(name.bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    #[test]
    fn cpio_hard_links_all_have_the_contents() {
        let d = scratch("cpio");
        // newc stores the data of a set of links with the last one.
        let mut a = Vec::new();
        newc(&mut a, 7, "one", 3, b"");
        newc(&mut a, 7, "dir/two", 3, b"");
        newc(&mut a, 7, "three", 3, b"shared data\n");
        newc(&mut a, 0, "TRAILER!!!", 1, b"");
        std::fs::write(d.join("a.cpio"), &a).unwrap();
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&d.join("a.cpio"), &staging, Limits::new(None), false);
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies
        );
        for name in ["one", "dir/two", "three"] {
            let got = std::fs::read(staging.join(name));
            assert_eq!(
                got.as_ref().ok().map(Vec::as_slice),
                Some(&b"shared data\n"[..]),
                "{name}: {:?}",
                c.replies
            );
        }

        // Only the first name selected: its data is with a name that isn't,
        // and still lands in it.
        std::fs::remove_dir_all(&staging).unwrap();
        std::fs::create_dir(&staging).unwrap();
        let f = std::fs::File::open(d.join("a.cpio")).unwrap();
        let mut c = fake(false);
        extract(
            &mut c,
            ExtractJob {
                archive: f.as_fd(),
                staging: crate::extract::open_dir(&staging).unwrap(),
                umask: 0o022,
                encoding: NameEncoding::Utf8,
                entries: Some([0].into()),
                limits: Limits::new(None),
                password: None,
                raw_name: String::new(),
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(staging.join("one")).unwrap(),
            b"shared data\n",
            "{:?}",
            c.replies
        );
        assert!(!staging.join("three").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cpio_hard_links_keep_their_modes_and_times() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // 0444 and 0555 sets: the data comes after the first names were
        // complete, and must still land, with the final mode and time.
        for (perm, want) in [(0o444, 0o644), (0o555, 0o755), (0o400, 0o600)] {
            let d = scratch(&format!("cpio-mode-{perm:o}"));
            let mut a = Vec::new();
            newc_mode(&mut a, perm, 7, "one", 3, b"");
            newc_mode(&mut a, perm, 7, "dir/two", 3, b"");
            newc_mode(&mut a, perm, 7, "three", 3, b"shared data\n");
            // A set whose data never comes: still gets its mode.
            newc_mode(&mut a, perm, 9, "empty", 2, b"");
            newc_mode(&mut a, perm, 9, "empty2", 2, b"");
            newc(&mut a, 0, "TRAILER!!!", 1, b"");
            std::fs::write(d.join("a.cpio"), &a).unwrap();
            let staging = d.join("staging");
            std::fs::create_dir(&staging).unwrap();
            let c = run_extract(&d.join("a.cpio"), &staging, Limits::new(None), false);
            assert!(
                matches!(c.replies.last(), Some(Reply::Done { .. })),
                "{perm:o}: {:?}",
                c.replies
            );
            assert!(
                !c.replies.iter().any(|r| matches!(r, Reply::Skipped { .. })),
                "{perm:o}: {:?}",
                c.replies
            );
            for name in ["one", "dir/two", "three"] {
                let p = staging.join(name);
                assert_eq!(
                    std::fs::read(&p).ok().as_deref(),
                    Some(&b"shared data\n"[..]),
                    "{perm:o} {name}: {:?}",
                    c.replies
                );
                let m = std::fs::metadata(&p).unwrap();
                assert_eq!(m.permissions().mode() & 0o777, want, "{perm:o} {name}");
                assert_eq!(m.mtime(), 1_000_000_000, "{perm:o} {name}");
            }
            for name in ["empty", "empty2"] {
                let m = std::fs::metadata(staging.join(name)).unwrap();
                assert_eq!(m.len(), 0);
                assert_eq!(m.permissions().mode() & 0o777, want, "{perm:o} {name}");
                assert_eq!(m.mtime(), 1_000_000_000, "{perm:o} {name}");
            }
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// A tar.gz of `zeros` MiB of zeros (named "big") and a small file.
    /// Entries over 1 MiB are read and thrown away here, as ones over 256 MiB
    /// are in a real job.
    fn zeros_tar_gz(d: &Path, mib: u32) -> PathBuf {
        SKIP_MAX_FOR_TESTS.with(|c| c.set(1024 * 1024));
        std::fs::create_dir_all(d.join("src")).unwrap();
        let ok = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "echo small > src/small && head -c {} /dev/zero > src/big && \
                 tar -czf a.tar.gz -C src small big && rm src/big",
                u64::from(mib) * 1024 * 1024
            ))
            .current_dir(d)
            .status()
            .unwrap();
        assert!(ok.success());
        d.join("a.tar.gz")
    }

    fn extract_selected(
        archive: &Path,
        staging: &Path,
        entries: HashSet<u32>,
        limits: Limits,
        go_on: bool,
    ) -> Fake {
        let f = std::fs::File::open(archive).unwrap();
        let mut c = fake(go_on);
        extract(
            &mut c,
            ExtractJob {
                archive: f.as_fd(),
                staging: crate::extract::open_dir(staging).unwrap(),
                umask: 0o022,
                encoding: NameEncoding::Utf8,
                entries: Some(entries),
                limits,
                password: None,
                raw_name: String::new(),
            },
        )
        .unwrap();
        c
    }

    #[test]
    fn discarded_bytes_trigger_the_limit_questions() {
        let d = scratch("discard-limits");
        let a = zeros_tar_gz(&d, 8);
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        // Only "small" is wanted; the 8 MiB of zeros nobody chose count.
        let small = Limits {
            total_bytes: 4 * 1024 * 1024,
            ..Limits::new(None)
        };
        let c = extract_selected(&a, &staging, [0].into(), small, false);
        assert!(
            c.replies.iter().any(|r| matches!(r, Reply::Limit(l)
                if l.kind == atlas_archive_core::limits::Kind::TotalSize)),
            "{:?}",
            c.replies
        );
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        let c = extract_selected(&a, &staging, [0].into(), small, true);
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies
        );
        // The ratio: 8 MiB of zeros is past 100:1, once past its threshold.
        std::fs::remove_dir_all(&staging).unwrap();
        std::fs::create_dir(&staging).unwrap();
        let ratio = Limits {
            ratio_after: 1024 * 1024,
            ..Limits::new(None)
        };
        let c = extract_selected(&a, &staging, [0].into(), ratio, false);
        assert!(
            c.replies.iter().any(|r| matches!(r, Reply::Limit(l)
                if l.kind == atlas_archive_core::limits::Kind::Ratio)),
            "{:?}",
            c.replies
        );
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        // Progress counts each entry once and never goes back.
        let c = extract_selected(&a, &staging, [0].into(), Limits::new(None), true);
        let items: Vec<u64> = c
            .replies
            .iter()
            .filter_map(|r| match r {
                Reply::Progress { items, .. } => Some(*items),
                _ => None,
            })
            .collect();
        assert!(items.windows(2).all(|w| w[0] <= w[1]), "{items:?}");
        assert!(items.iter().all(|&i| i <= 2), "{items:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_listing_gives_up_past_its_bound_with_what_it_read() {
        let d = scratch("list-bound");
        let a = zeros_tar_gz(&d, 8);
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        let bound = ListBound {
            bytes: 1024 * 1024,
            ratio: 5000,
            ratio_after: u64::MAX,
        };
        list_bounded(&mut c, f.as_fd(), None, bound).unwrap();
        let entries: usize = c
            .replies
            .iter()
            .map(|r| match r {
                Reply::Entries(e) => e.len(),
                _ => 0,
            })
            .sum();
        // "small" was listed; "big" went past the bound while being skipped.
        assert_eq!(entries, 1, "{:?}", c.replies);
        assert!(
            matches!(c.replies.last(), Some(Reply::Failed { reason }) if reason.contains("can't be listed")),
            "{:?}",
            c.replies
        );
        assert!(!c.replies.iter().any(|r| matches!(r, Reply::Limit(_))));
        // The ratio bound works too, and a bound not reached lists it all.
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        let bound = ListBound {
            bytes: u64::MAX,
            ratio: 100,
            ratio_after: 1024 * 1024,
        };
        list_bounded(&mut c, f.as_fd(), None, bound).unwrap();
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        list(&mut c, f.as_fd()).unwrap();
        assert!(matches!(
            c.replies.last(),
            Some(Reply::Listed { entries: 2 })
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn names_that_say_password_never_ask_for_one() {
        let d = scratch("password-name");
        std::fs::create_dir_all(d.join("src")).unwrap();
        let a = tar_script(
            &d,
            "echo 1 > 'password.txt' && echo 2 > 'Passphrase required' && echo 3 > c \
             && tar -cf ../a.tar 'password.txt' 'Passphrase required' c",
        );
        // Break the third header: the archive fails, in words, not by asking.
        let mut bytes = std::fs::read(&a).unwrap();
        bytes[2048..2148].fill(0xff);
        std::fs::write(&a, &bytes).unwrap();
        let none = |replies: &[Reply]| {
            !replies
                .iter()
                .any(|r| matches!(r, Reply::NeedPassword { .. }))
        };
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        list(&mut c, f.as_fd()).unwrap();
        assert!(none(&c.replies), "{:?}", c.replies);
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        test(&mut c, f.as_fd(), None).unwrap();
        assert!(none(&c.replies), "{:?}", c.replies);
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&a, &staging, Limits::new(None), false);
        assert!(none(&c.replies), "{:?}", c.replies);
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn data(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name)
    }

    fn listed(c: &Fake) -> Vec<Entry> {
        c.replies
            .iter()
            .flat_map(|r| match r {
                Reply::Entries(e) => e.clone(),
                _ => Vec::new(),
            })
            .collect()
    }

    #[test]
    fn small_entries_are_skipped_and_metered() {
        let d = scratch("skip-small");
        // The default skip size: 8 MiB of zeros is one skip() call, but the
        // bytes the decoder made behind a filter still count.
        let a = zeros_tar_gz(&d, 8);
        SKIP_MAX_FOR_TESTS.with(|c| c.set(SKIP_MAX));
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let small = Limits {
            total_bytes: 4 * 1024 * 1024,
            ..Limits::new(None)
        };
        let c = extract_selected(&a, &staging, [0].into(), small, false);
        assert!(
            c.replies.iter().any(|r| matches!(r, Reply::Limit(l)
                if l.kind == atlas_archive_core::limits::Kind::TotalSize)),
            "{:?}",
            c.replies
        );
        // So does a listing's bound.
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        let bound = ListBound {
            bytes: 1024 * 1024,
            ratio: 5000,
            ratio_after: u64::MAX,
        };
        list_bounded(&mut c, f.as_fd(), None, bound).unwrap();
        assert!(
            matches!(c.replies.last(), Some(Reply::Failed { .. })),
            "{:?}",
            c.replies
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn damaged_data_in_an_entry_nobody_wanted_is_not_fatal() {
        // 7z, copy method, not solid: a.txt's data is changed, so its CRC
        // fails when it is read. Entries are read, not skipped, with the
        // skip size at zero.
        SKIP_MAX_FOR_TESTS.with(|c| c.set(0));
        let a = data("bad-crc.7z");
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        list(&mut c, f.as_fd()).unwrap();
        let entries = listed(&c);
        assert!(
            matches!(c.replies.last(), Some(Reply::Listed { entries: 2 })),
            "{:?}",
            c.replies
        );
        let find = |n: &str| entries.iter().find(|e| e.path.ends_with(n.as_bytes()));
        let bad = find("a.txt").unwrap().index;
        let good = find("b.txt").unwrap().index;
        let d = scratch("damaged-unwanted");
        // Only the good one selected: the damaged one isn't reported.
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = extract_selected(&a, &staging, [good].into(), Limits::new(None), false);
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies
        );
        assert!(
            !c.replies.iter().any(|r| matches!(r, Reply::Skipped { .. })),
            "{:?}",
            c.replies
        );
        assert_eq!(
            std::fs::read(staging.join("s/b.txt")).unwrap(),
            b"second file\n"
        );
        // Both selected: the damaged one is reported, the other written.
        let staging = d.join("staging2");
        std::fs::create_dir(&staging).unwrap();
        let c = extract_selected(&a, &staging, [bad, good].into(), Limits::new(None), false);
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies
        );
        assert_eq!(
            std::fs::read(staging.join("s/b.txt")).unwrap(),
            b"second file\n"
        );
        assert!(!staging.join("s/a.txt").exists(), "{:?}", c.replies);
        assert!(
            c.replies
                .iter()
                .any(|r| matches!(r, Reply::Skipped { index, .. } if *index == bad)),
            "{:?}",
            c.replies
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn encrypted_7z_is_refused_in_words_never_asked_for_a_password() {
        // libarchive 3.8.7 can't read encrypted 7z at all ("...is encrypted,
        // but currently not supported": it has no passphrase phrase for 7z),
        // so a password can't help and none is asked for. Made with
        // `7z a -mhe=on -psecret` (headers too) and `-mhe=off` (data only).
        // The rar and rar5 phrases of `is_password_message` are untested:
        // those archives need the proprietary tool.
        let no_ask = |c: &Fake| {
            !c.replies
                .iter()
                .any(|r| matches!(r, Reply::NeedPassword { .. }))
        };
        let a = data("enc-headers.7z");
        for password in [None, Some(&b"nope"[..]), Some(&b"secret"[..])] {
            let f = std::fs::File::open(&a).unwrap();
            let mut c = fake(false);
            list_with(&mut c, f.as_fd(), password).unwrap();
            assert!(no_ask(&c), "{:?}", c.replies);
            assert!(
                matches!(c.replies.last(), Some(Reply::Failed { reason })
                    if reason.contains("encrypted")),
                "{:?}",
                c.replies
            );
            let d = scratch("7z-headers");
            let c = extract_with(&a, &d, password);
            assert!(no_ask(&c), "{:?}", c.replies);
            assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
            let _ = std::fs::remove_dir_all(&d);
        }
        // Data only: the listing works, each entry is reported unreadable.
        let a = data("enc-data.7z");
        let f = std::fs::File::open(&a).unwrap();
        let mut c = fake(false);
        list(&mut c, f.as_fd()).unwrap();
        assert!(
            matches!(c.replies.last(), Some(Reply::Listed { entries: 2 })),
            "{:?}",
            c.replies
        );
        for password in [None, Some(&b"nope"[..]), Some(&b"secret"[..])] {
            let d = scratch("7z-data");
            let c = extract_with(&a, &d, password);
            assert!(no_ask(&c), "{:?}", c.replies);
            assert!(
                matches!(c.replies.last(), Some(Reply::Done { .. })),
                "{:?}",
                c.replies
            );
            let skipped = c
                .replies
                .iter()
                .filter(|r| matches!(r, Reply::Skipped { .. }))
                .count();
            assert_eq!(skipped, 2, "{:?}", c.replies);
            assert!(!d.join("s/a.txt").exists());
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn a_hostile_cpio_with_data_on_both_names_keeps_the_first() {
        let d = scratch("cpio-both");
        let mut a = Vec::new();
        newc(&mut a, 7, "a", 2, b"AAAA");
        newc(&mut a, 7, "b", 2, b"BBBB");
        newc(&mut a, 0, "TRAILER!!!", 1, b"");
        std::fs::write(d.join("a.cpio"), &a).unwrap();
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&d.join("a.cpio"), &staging, Limits::new(None), false);
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies
        );
        // The first name's data isn't overwritten by the second's.
        assert_eq!(std::fs::read(staging.join("a")).unwrap(), b"AAAA");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_cpio_first_name_whose_data_was_refused_is_reported_and_removed() {
        let d = scratch("cpio-refused");
        let mut a = Vec::new();
        newc(&mut a, 7, "one", 2, b"");
        // The name that carries the data is refused (it climbs out).
        newc(&mut a, 7, "../two", 2, b"shared data\n");
        newc(&mut a, 0, "TRAILER!!!", 1, b"");
        std::fs::write(d.join("a.cpio"), &a).unwrap();
        let staging = d.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let c = run_extract(&d.join("a.cpio"), &staging, Limits::new(None), false);
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies
        );
        assert!(!staging.join("one").exists(), "{:?}", c.replies);
        assert!(
            c.replies
                .iter()
                .any(|r| matches!(r, Reply::Skipped { index: 0, .. })),
            "{:?}",
            c.replies
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
