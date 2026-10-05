//! The worker protocol (docs/DESIGN.md, "The sandbox").
//!
//! Frames are a little-endian `u32` length then that many bytes, at most
//! `MAX_FRAME`. Each frame is one message: a tag byte, then its fields.
//! Integers are little-endian, byte strings a `u32` length then the bytes,
//! text the same and valid UTF-8, options a 0/1 byte then the value.
//!
//! The client decodes replies from a worker that parsed a hostile archive, so
//! `Reply::decode` is a fuzzed boundary: it never panics, never allocates
//! more than the frame holds, and refuses trailing bytes. Values that make it
//! through are still untrusted: paths go through `path`, names through `name`,
//! counts and sizes through `limits`.
//!
//! Passwords travel in `Request::Password`. Their buffers are `Zeroizing`,
//! and `Debug` never shows them.

use std::fmt;
use std::io::{self, Read, Write};

use crate::limits::Exceeded;
use zeroize::Zeroizing;

/// The largest frame, in bytes (length prefix not counted).
pub const MAX_FRAME: usize = 1024 * 1024;
/// The most bytes of `Reply::Entries` frames one listing may send.
pub const MAX_LISTING: u64 = 64 * 1024 * 1024;
/// The longest text or byte string in a message.
pub const MAX_STRING: usize = 64 * 1024;

/// Why a frame was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// The frame ended inside a field.
    Truncated,
    /// A frame, string or list is over its limit.
    TooLarge,
    /// An unknown message or value tag.
    BadTag(u8),
    /// Text that isn't UTF-8.
    BadText,
    /// Bytes left after the message.
    Trailing,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            ProtoError::Truncated => "a message was cut short",
            ProtoError::TooLarge => "a message was too large",
            ProtoError::BadTag(_) => "a message had an unknown type",
            ProtoError::BadText => "a message held invalid text",
            ProtoError::Trailing => "a message had extra bytes",
        };
        write!(f, "The archive reader sent something unexpected ({what}).")
    }
}

impl std::error::Error for ProtoError {}

impl From<ProtoError> for io::Error {
    fn from(e: ProtoError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

// ---- frames ----

/// Writes one frame. Give it the pipe itself, never a `BufWriter`: a
/// buffer would keep a copy of a password frame that nothing zeroes.
pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(ProtoError::TooLarge.into());
    }
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Reads one frame into a buffer sized to it. `Ok(None)` at a clean end of
/// stream (before a length); a stream that ends inside a frame is an error.
/// The buffer is `Zeroizing` because request frames can hold a password.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(ProtoError::Truncated.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(ProtoError::TooLarge.into());
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            ProtoError::Truncated.into()
        } else {
            e
        }
    })?;
    Ok(Some(buf))
}

// ---- encoding ----

#[derive(Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    /// Strings over `MAX_STRING` are cut: the decoder would refuse them, and
    /// a cut name is checked like any other.
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        let v = &v[..v.len().min(MAX_STRING)];
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
        self
    }
    fn text(&mut self, v: &str) -> &mut Self {
        let mut end = v.len().min(MAX_STRING);
        while !v.is_char_boundary(end) {
            end -= 1;
        }
        self.bytes(&v.as_bytes()[..end])
    }
    fn opt_u64(&mut self, v: Option<u64>) -> &mut Self {
        match v {
            Some(v) => self.u8(1).u64(v),
            None => self.u8(0),
        }
    }
    fn opt_i64(&mut self, v: Option<i64>) -> &mut Self {
        match v {
            Some(v) => self.u8(1).i64(v),
            None => self.u8(0),
        }
    }
    fn opt_bytes(&mut self, v: Option<&[u8]>) -> &mut Self {
        match v {
            Some(v) => self.u8(1).bytes(v),
            None => self.u8(0),
        }
    }
    fn opt_text(&mut self, v: Option<&str>) -> &mut Self {
        match v {
            Some(v) => self.u8(1).text(v),
            None => self.u8(0),
        }
    }
}

struct Dec<'a>(&'a [u8]);

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.0.len() < n {
            return Err(ProtoError::Truncated);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> Result<bool, ProtoError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(ProtoError::BadTag(t)),
        }
    }
    fn u32(&mut self) -> Result<u32, ProtoError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ProtoError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, ProtoError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let len = self.u32()? as usize;
        if len > MAX_STRING {
            return Err(ProtoError::TooLarge);
        }
        self.take(len)
    }
    fn text(&mut self) -> Result<String, ProtoError> {
        std::str::from_utf8(self.bytes()?)
            .map(str::to_owned)
            .map_err(|_| ProtoError::BadText)
    }
    fn opt<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, ProtoError>,
    ) -> Result<Option<T>, ProtoError> {
        if self.bool()? {
            f(self).map(Some)
        } else {
            Ok(None)
        }
    }
    /// A list count, refused when even one byte per item would not fit.
    fn count(&mut self, min_item: usize) -> Result<usize, ProtoError> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min_item) > self.0.len() {
            return Err(ProtoError::Truncated);
        }
        Ok(n)
    }
    fn end(&self) -> Result<(), ProtoError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::Trailing)
        }
    }
}

// ---- requests: client to worker ----

/// What the client asks of the worker. The archive and staging descriptors
/// were passed when it started.
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    /// List every entry.
    List,
    /// Extract into the staging folder: every entry, or these indices.
    Extract {
        /// The encoding of names not marked UTF-8, by label: the one the
        /// client detected or the user chose (`NameEncoding::from_label`).
        encoding: String,
        entries: Option<Vec<u32>>,
        /// The name for the one file in a compressed file that is no archive
        /// (`notes.txt` for `notes.txt.gz`), which stores none.
        raw_name: String,
    },
    /// Read every entry and check it, writing nothing.
    Test,
    /// The password the worker asked for.
    Password(Zeroizing<Vec<u8>>),
    /// The answer to `Reply::Limit`: go on past it, or stop.
    GoOn(bool),
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Request::List => f.write_str("List"),
            Request::Extract {
                encoding,
                entries,
                raw_name,
            } => f
                .debug_struct("Extract")
                .field("encoding", encoding)
                .field("entries", &entries.as_ref().map(Vec::len))
                .field("raw_name", raw_name)
                .finish(),
            Request::Test => f.write_str("Test"),
            Request::Password(_) => f.write_str("Password(<redacted>)"),
            Request::GoOn(v) => f.debug_tuple("GoOn").field(v).finish(),
        }
    }
}

impl Request {
    /// The frame payload. `Zeroizing` because a password request holds one.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Enc::default();
        match self {
            Request::List => {
                e.u8(1);
            }
            Request::Extract {
                encoding,
                entries,
                raw_name,
            } => {
                e.u8(2).text(encoding);
                match entries {
                    Some(list) => {
                        e.u8(1).u32(list.len() as u32);
                        list.iter().for_each(|&i| {
                            e.u32(i);
                        });
                    }
                    None => {
                        e.u8(0);
                    }
                }
                e.text(raw_name);
            }
            Request::Test => {
                e.u8(3);
            }
            Request::Password(p) => {
                // Sized up front so the password is never copied by a
                // growing Vec into memory that isn't wiped.
                let mut out = Zeroizing::new(Vec::with_capacity(1 + 4 + p.len()));
                out.push(4);
                out.extend_from_slice(&(p.len() as u32).to_le_bytes());
                out.extend_from_slice(p);
                return out;
            }
            Request::GoOn(v) => {
                e.u8(5).bool(*v);
            }
        }
        Zeroizing::new(e.0)
    }

    pub fn decode(frame: &[u8]) -> Result<Request, ProtoError> {
        let mut d = Dec(frame);
        let r = match d.u8()? {
            1 => Request::List,
            2 => {
                let encoding = d.text()?;
                let entries = d.opt(|d| {
                    let n = d.count(4)?;
                    (0..n).map(|_| d.u32()).collect::<Result<Vec<_>, _>>()
                })?;
                Request::Extract {
                    encoding,
                    entries,
                    raw_name: d.text()?,
                }
            }
            3 => Request::Test,
            4 => {
                // No length cap but the frame's: a password is not a name.
                let len = d.u32()? as usize;
                let mut p = Zeroizing::new(Vec::with_capacity(len.min(d.0.len())));
                p.extend_from_slice(d.take(len)?);
                Request::Password(p)
            }
            5 => Request::GoOn(d.bool()?),
            t => return Err(ProtoError::BadTag(t)),
        };
        d.end()?;
        Ok(r)
    }
}

// ---- replies: worker to client ----

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Hardlink,
    /// Devices, FIFOs, sockets: listed, never created.
    Special,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::File => 0,
            Kind::Dir => 1,
            Kind::Symlink => 2,
            Kind::Hardlink => 3,
            Kind::Special => 4,
        }
    }
    fn from_tag(t: u8) -> Result<Kind, ProtoError> {
        Ok(match t {
            0 => Kind::File,
            1 => Kind::Dir,
            2 => Kind::Symlink,
            3 => Kind::Hardlink,
            4 => Kind::Special,
            t => return Err(ProtoError::BadTag(t)),
        })
    }
}

/// One entry as the archive stores it. Everything here is untrusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its position in the archive; requests name entries by it.
    pub index: u32,
    /// The path bytes as stored.
    pub path: Vec<u8>,
    pub kind: Kind,
    /// Unpacked size, when the archive says.
    pub size: Option<u64>,
    /// Packed size, when the format stores one per entry.
    pub packed: Option<u64>,
    /// Modification time, seconds since 1970.
    pub mtime: Option<i64>,
    /// Permission bits as stored (the writer keeps only 0o777, less the umask).
    pub mode: u32,
    pub encrypted: bool,
    /// The archive marks this name as UTF-8 (zip's flag, or a format whose
    /// names always are); other names are in the archive's legacy encoding.
    pub utf8: bool,
    /// A link's target bytes as stored.
    pub link: Option<Vec<u8>>,
}

/// What the archive is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Format {
    /// "zip", "7z", "tar.gz"...
    pub name: String,
    /// Some entries (or the names) are encrypted.
    pub encrypted: bool,
    /// The names are encrypted too: nothing lists without the password.
    pub encrypted_names: bool,
    /// Entries are compressed together (7z, rar solid, tar.*).
    pub solid: bool,
    /// A compressed file that is no archive (`notes.txt.gz`): one entry,
    /// whose name the archive doesn't store.
    pub compressed_file: bool,
    pub volumes: u32,
    /// The archive was made on DOS or Windows: `\` separates folders and
    /// names without a UTF-8 flag are in an OEM code page.
    pub made_on_dos: bool,
    pub comment: Option<String>,
}

fn limit_tag(k: crate::limits::Kind) -> u8 {
    use crate::limits::Kind as K;
    match k {
        K::TotalSize => 0,
        K::Ratio => 1,
        K::Entries => 2,
        K::EntryRatio => 3,
        K::NestDepth => 4,
        K::FreeSpace => 5,
    }
}

fn limit_from_tag(t: u8) -> Result<crate::limits::Kind, ProtoError> {
    use crate::limits::Kind as K;
    Ok(match t {
        0 => K::TotalSize,
        1 => K::Ratio,
        2 => K::Entries,
        3 => K::EntryRatio,
        4 => K::NestDepth,
        5 => K::FreeSpace,
        t => return Err(ProtoError::BadTag(t)),
    })
}

/// What the worker says. Untrusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Format(Format),
    /// A batch of entries; as many as fit in a frame.
    Entries(Vec<Entry>),
    /// The listing is complete.
    Listed {
        entries: u32,
    },
    Progress {
        bytes: u64,
        items: u64,
    },
    /// A password is needed (`wrong`: the last one didn't work).
    NeedPassword {
        wrong: bool,
    },
    /// A limit was reached; the worker waits for `Request::GoOn`.
    Limit(Exceeded),
    /// An entry was skipped, with the reason in plain words.
    Skipped {
        index: u32,
        reason: String,
    },
    /// `count` more entries were skipped, past the `tree::MAX_SKIPPED`
    /// individually reported ones.
    SkippedMore {
        count: u64,
    },
    /// The job finished. `written`: the top-level names it wrote in staging.
    Done {
        written: Vec<Vec<u8>>,
    },
    /// The job failed, with the reason in plain words.
    Failed {
        reason: String,
    },
}

/// Bytes an entry takes at least (empty path, no options).
const MIN_ENTRY: usize = 4 + 4 + 1 + 1 + 1 + 1 + 4 + 1 + 1 + 1;

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::default();
        match self {
            Reply::Format(f) => {
                e.u8(1)
                    .text(&f.name)
                    .bool(f.encrypted)
                    .bool(f.encrypted_names)
                    .bool(f.solid)
                    .bool(f.compressed_file)
                    .u32(f.volumes)
                    .bool(f.made_on_dos)
                    .opt_text(f.comment.as_deref());
            }
            Reply::Entries(list) => {
                e.u8(2).u32(list.len() as u32);
                for x in list {
                    e.u32(x.index)
                        .bytes(&x.path)
                        .u8(x.kind.tag())
                        .opt_u64(x.size)
                        .opt_u64(x.packed)
                        .opt_i64(x.mtime)
                        .u32(x.mode)
                        .bool(x.encrypted)
                        .bool(x.utf8)
                        .opt_bytes(x.link.as_deref());
                }
            }
            Reply::Listed { entries } => {
                e.u8(3).u32(*entries);
            }
            Reply::Progress { bytes, items } => {
                e.u8(4).u64(*bytes).u64(*items);
            }
            Reply::NeedPassword { wrong } => {
                e.u8(5).bool(*wrong);
            }
            Reply::Limit(l) => {
                e.u8(6).u8(limit_tag(l.kind)).u64(l.limit);
            }
            Reply::Skipped { index, reason } => {
                e.u8(7).u32(*index).text(reason);
            }
            Reply::SkippedMore { count } => {
                e.u8(10).u64(*count);
            }
            Reply::Done { written } => {
                e.u8(8).u32(written.len() as u32);
                written.iter().for_each(|w| {
                    e.bytes(w);
                });
            }
            Reply::Failed { reason } => {
                e.u8(9).text(reason);
            }
        }
        e.0
    }

    pub fn decode(frame: &[u8]) -> Result<Reply, ProtoError> {
        let mut d = Dec(frame);
        let r = match d.u8()? {
            1 => Reply::Format(Format {
                name: d.text()?,
                encrypted: d.bool()?,
                encrypted_names: d.bool()?,
                solid: d.bool()?,
                compressed_file: d.bool()?,
                volumes: d.u32()?,
                made_on_dos: d.bool()?,
                comment: d.opt(Dec::text)?,
            }),
            2 => {
                let n = d.count(MIN_ENTRY)?;
                let mut list = Vec::with_capacity(n);
                for _ in 0..n {
                    list.push(Entry {
                        index: d.u32()?,
                        path: d.bytes()?.to_vec(),
                        kind: Kind::from_tag(d.u8()?)?,
                        size: d.opt(Dec::u64)?,
                        packed: d.opt(Dec::u64)?,
                        mtime: d.opt(Dec::i64)?,
                        mode: d.u32()?,
                        encrypted: d.bool()?,
                        utf8: d.bool()?,
                        link: d.opt(|d| d.bytes().map(<[u8]>::to_vec))?,
                    });
                }
                Reply::Entries(list)
            }
            3 => Reply::Listed { entries: d.u32()? },
            4 => Reply::Progress {
                bytes: d.u64()?,
                items: d.u64()?,
            },
            5 => Reply::NeedPassword { wrong: d.bool()? },
            6 => Reply::Limit(Exceeded {
                kind: limit_from_tag(d.u8()?)?,
                limit: d.u64()?,
            }),
            7 => Reply::Skipped {
                index: d.u32()?,
                reason: d.text()?,
            },
            8 => {
                let n = d.count(4)?;
                let written = (0..n)
                    .map(|_| d.bytes().map(<[u8]>::to_vec))
                    .collect::<Result<_, _>>()?;
                Reply::Done { written }
            }
            9 => Reply::Failed { reason: d.text()? },
            10 => Reply::SkippedMore { count: d.u64()? },
            t => return Err(ProtoError::BadTag(t)),
        };
        d.end()?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: u32) -> Entry {
        Entry {
            index: i,
            path: format!("dir/file{i}.txt").into_bytes(),
            kind: Kind::File,
            size: Some(1234),
            packed: None,
            mtime: Some(-5),
            mode: 0o644,
            encrypted: i.is_multiple_of(2),
            utf8: i != 1,
            link: (i == 3).then(|| b"../x".to_vec()),
        }
    }

    fn replies() -> Vec<Reply> {
        vec![
            Reply::Format(Format {
                name: "zip".into(),
                encrypted: true,
                encrypted_names: false,
                solid: false,
                compressed_file: false,
                volumes: 1,
                made_on_dos: true,
                comment: Some("hi".into()),
            }),
            Reply::Entries((0..5).map(entry).collect()),
            Reply::Entries(vec![]),
            Reply::Listed { entries: 5 },
            Reply::Progress {
                bytes: u64::MAX,
                items: 7,
            },
            Reply::NeedPassword { wrong: true },
            Reply::Limit(Exceeded {
                kind: crate::limits::Kind::Ratio,
                limit: 100,
            }),
            Reply::Limit(Exceeded {
                kind: crate::limits::Kind::FreeSpace,
                limit: u64::MAX,
            }),
            Reply::Skipped {
                index: 9,
                reason: "The item has no name.".into(),
            },
            Reply::Done {
                written: vec![b"a".to_vec(), b"\xFF".to_vec()],
            },
            Reply::Failed { reason: "x".into() },
            Reply::SkippedMore { count: u64::MAX },
        ]
    }

    #[test]
    fn replies_round_trip() {
        for r in replies() {
            assert_eq!(Reply::decode(&r.encode()).unwrap(), r);
        }
    }

    #[test]
    fn requests_round_trip() {
        for r in [
            Request::List,
            Request::Extract {
                encoding: "Shift_JIS".into(),
                entries: Some(vec![1, 2, 3]),
                raw_name: "notes.txt".into(),
            },
            Request::Extract {
                encoding: "UTF-8".into(),
                entries: None,
                raw_name: String::new(),
            },
            Request::Test,
            Request::Password(Zeroizing::new(b"hunter2".to_vec())),
            Request::Password(Zeroizing::new(vec![])),
            Request::GoOn(true),
        ] {
            assert_eq!(Request::decode(&r.encode()).unwrap(), r);
        }
    }

    #[test]
    fn passwords_are_never_shown() {
        let r = Request::Password(Zeroizing::new(b"hunter2".to_vec()));
        assert!(!format!("{r:?}").contains("hunter2"));
        assert!(!format!("{r:#?}").contains("hunter2"));
    }

    #[test]
    fn every_truncation_is_refused() {
        for r in replies() {
            let full = r.encode();
            for cut in 0..full.len() {
                assert!(Reply::decode(&full[..cut]).is_err(), "{r:?} cut at {cut}");
            }
            let mut long = full.clone();
            long.push(0);
            assert_eq!(Reply::decode(&long), Err(ProtoError::Trailing));
        }
    }

    #[test]
    fn hostile_frames() {
        assert_eq!(Reply::decode(&[]), Err(ProtoError::Truncated));
        assert_eq!(Reply::decode(&[0]), Err(ProtoError::BadTag(0)));
        assert_eq!(Reply::decode(&[200]), Err(ProtoError::BadTag(200)));
        // A count of 4 billion entries in a tiny frame: refused before any
        // allocation.
        assert_eq!(
            Reply::decode(&[2, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(ProtoError::Truncated)
        );
        // A string longer than MAX_STRING.
        let mut f = vec![9];
        f.extend_from_slice(&((MAX_STRING as u32) + 1).to_le_bytes());
        f.resize(f.len() + MAX_STRING + 1, b'a');
        assert_eq!(Reply::decode(&f), Err(ProtoError::TooLarge));
        // Invalid UTF-8 in text.
        assert_eq!(
            Reply::decode(&[9, 1, 0, 0, 0, 0xFF]),
            Err(ProtoError::BadText)
        );
        // A bool that is neither 0 nor 1.
        assert_eq!(Reply::decode(&[5, 2]), Err(ProtoError::BadTag(2)));
        // An unknown entry kind.
        let mut e = Reply::Entries(vec![entry(0)]).encode();
        let kind_at = 1 + 4 + 4 + 4 + entry(0).path.len();
        e[kind_at] = 9;
        assert_eq!(Reply::decode(&e), Err(ProtoError::BadTag(9)));
    }

    #[test]
    fn frames() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"abc").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut r = buf.as_slice();
        assert_eq!(read_frame(&mut r).unwrap().unwrap().as_slice(), b"abc");
        assert_eq!(read_frame(&mut r).unwrap().unwrap().as_slice(), b"");
        assert!(read_frame(&mut r).unwrap().is_none());

        // Cut inside the length, and inside the payload.
        assert!(read_frame(&mut &buf[..2]).is_err());
        assert!(read_frame(&mut &buf[..5]).is_err());
        // A length over MAX_FRAME is refused without allocating it.
        let big = ((MAX_FRAME as u32) + 1).to_le_bytes();
        assert!(read_frame(&mut big.as_slice()).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![0; MAX_FRAME + 1]).is_err());
    }

    #[test]
    fn long_strings_are_cut_when_sent() {
        let r = Reply::Failed {
            reason: "é".repeat(MAX_STRING),
        };
        match Reply::decode(&r.encode()).unwrap() {
            Reply::Failed { reason } => {
                assert!(reason.len() <= MAX_STRING && reason.chars().all(|c| c == 'é'))
            }
            _ => unreachable!(),
        }
    }
}
