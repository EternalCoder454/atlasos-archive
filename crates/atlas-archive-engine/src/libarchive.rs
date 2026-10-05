//! libarchive, through a small hand-written binding (the calls below are all
//! Atlas Archive uses). It reads tar with every filter, 7z without
//! encryption, rar, iso, cab, cpio, deb (ar) and rpm, and plain compressed
//! files as one entry.
//!
//! Names: the worker runs in the C.UTF-8 locale, so libarchive turns names a
//! format stores as UTF-16 or marks as UTF-8 into UTF-8, and passes names in
//! an unknown encoding through as their bytes. An entry's name is `utf8` when
//! its bytes are valid UTF-8; the rest go through `core::name` detection.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::fmt;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, BorrowedFd};

use atlas_archive_core::proto::{Entry, Kind};
use zeroize::Zeroizing;

#[allow(non_camel_case_types)]
type archive = c_void;
#[allow(non_camel_case_types)]
type archive_entry = c_void;

const ARCHIVE_EOF: c_int = 1;
const ARCHIVE_OK: c_int = 0;
const ARCHIVE_WARN: c_int = -20;

const AE_IFMT: u32 = 0o170000;
const AE_IFREG: u32 = 0o100000;
const AE_IFLNK: u32 = 0o120000;
const AE_IFDIR: u32 = 0o040000;

/// `ARCHIVE_FORMAT_RAW`: the raw "format" (a compressed file, not an archive).
const ARCHIVE_FORMAT_RAW: c_int = 0x90000;
/// `ARCHIVE_FORMAT_BASE_MASK`.
const ARCHIVE_FORMAT_BASE_MASK: c_int = 0xff0000;
/// `ARCHIVE_FILTER_NONE`.
const ARCHIVE_FILTER_NONE: c_int = 0;

#[link(name = "archive")]
unsafe extern "C" {
    fn archive_read_new() -> *mut archive;
    fn archive_read_support_filter_gzip(a: *mut archive) -> c_int;
    fn archive_read_support_filter_bzip2(a: *mut archive) -> c_int;
    fn archive_read_support_filter_xz(a: *mut archive) -> c_int;
    fn archive_read_support_filter_lzma(a: *mut archive) -> c_int;
    fn archive_read_support_filter_lzip(a: *mut archive) -> c_int;
    fn archive_read_support_filter_zstd(a: *mut archive) -> c_int;
    fn archive_read_support_filter_lz4(a: *mut archive) -> c_int;
    fn archive_read_support_filter_compress(a: *mut archive) -> c_int;
    fn archive_read_support_filter_rpm(a: *mut archive) -> c_int;
    fn archive_read_support_format_7zip(a: *mut archive) -> c_int;
    fn archive_read_support_format_ar(a: *mut archive) -> c_int;
    fn archive_read_support_format_cab(a: *mut archive) -> c_int;
    fn archive_read_support_format_cpio(a: *mut archive) -> c_int;
    fn archive_read_support_format_iso9660(a: *mut archive) -> c_int;
    fn archive_read_support_format_rar(a: *mut archive) -> c_int;
    fn archive_read_support_format_rar5(a: *mut archive) -> c_int;
    fn archive_read_support_format_tar(a: *mut archive) -> c_int;
    fn archive_read_support_format_zip(a: *mut archive) -> c_int;
    fn archive_read_support_format_raw(a: *mut archive) -> c_int;
    fn archive_read_support_format_empty(a: *mut archive) -> c_int;
    fn archive_read_add_passphrase(a: *mut archive, passphrase: *const c_char) -> c_int;
    fn archive_read_set_options(a: *mut archive, opts: *const c_char) -> c_int;
    fn archive_read_open_fd(a: *mut archive, fd: c_int, block_size: usize) -> c_int;
    fn archive_read_next_header(a: *mut archive, entry: *mut *mut archive_entry) -> c_int;
    fn archive_read_data(a: *mut archive, buf: *mut c_void, size: usize) -> isize;
    fn archive_read_data_skip(a: *mut archive) -> c_int;
    fn archive_read_free(a: *mut archive) -> c_int;
    fn archive_error_string(a: *mut archive) -> *const c_char;
    fn archive_format(a: *mut archive) -> c_int;
    fn archive_format_name(a: *mut archive) -> *const c_char;
    fn archive_filter_count(a: *mut archive) -> c_int;
    fn archive_filter_code(a: *mut archive, n: c_int) -> c_int;
    fn archive_filter_name(a: *mut archive, n: c_int) -> *const c_char;
    fn archive_filter_bytes(a: *mut archive, n: c_int) -> i64;
    fn archive_read_has_encrypted_entries(a: *mut archive) -> c_int;

    fn archive_entry_pathname(e: *mut archive_entry) -> *const c_char;
    fn archive_entry_filetype(e: *mut archive_entry) -> u32;
    fn archive_entry_hardlink(e: *mut archive_entry) -> *const c_char;
    fn archive_entry_symlink(e: *mut archive_entry) -> *const c_char;
    fn archive_entry_size_is_set(e: *mut archive_entry) -> c_int;
    fn archive_entry_size(e: *mut archive_entry) -> i64;
    fn archive_entry_mtime_is_set(e: *mut archive_entry) -> c_int;
    fn archive_entry_mtime(e: *mut archive_entry) -> libc::time_t;
    fn archive_entry_perm(e: *mut archive_entry) -> u32;
    fn archive_entry_is_encrypted(e: *mut archive_entry) -> c_int;
}

/// A libarchive failure, with its message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// libarchive wants a password, or a different one ("Passphrase
    /// required for this entry", "Incorrect passphrase").
    pub fn is_password(&self) -> bool {
        self.0.contains("assphrase")
    }
}

/// One archive being read, front to back.
///
/// libarchive reads the descriptor as it goes, so the reader borrows it: the
/// fd can't be closed first.
pub struct Reader<'fd> {
    a: *mut archive,
    entry: *mut archive_entry,
    index: u32,
    _fd: PhantomData<BorrowedFd<'fd>>,
}

// The handle is used from one thread at a time.
unsafe impl Send for Reader<'_> {}

fn cstr_bytes(p: *const c_char) -> Option<Vec<u8>> {
    // SAFETY: libarchive returns NUL-terminated strings valid until the next
    // call on the same object; they are copied at once.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

impl<'fd> Reader<'fd> {
    /// Opens the archive at `fd` (read from its current offset). The fd must
    /// stay open while the reader lives.
    pub fn open(fd: BorrowedFd<'fd>) -> Result<Reader<'fd>, Error> {
        Reader::open_with(fd, None)
    }

    /// As `open`, with the password for encrypted entries. libarchive keeps
    /// its own copy, which lives until the worker exits after this job.
    pub fn open_with(fd: BorrowedFd<'fd>, password: Option<&[u8]>) -> Result<Reader<'fd>, Error> {
        let password = match password {
            Some(p) if p.contains(&0) => {
                return Err(Error("The password can't contain a NUL character.".into()));
            }
            Some(p) => {
                let mut c = Zeroizing::new(Vec::with_capacity(p.len() + 1));
                c.extend_from_slice(p);
                c.push(0);
                Some(c)
            }
            None => None,
        };
        // SAFETY: plain libarchive calls on a handle we own; it is freed in
        // Drop, also on the error paths (the Reader exists from here on).
        unsafe {
            let a = archive_read_new();
            if a.is_null() {
                return Err(Error("Out of memory.".into()));
            }
            let r = Reader {
                a,
                entry: std::ptr::null_mut(),
                index: 0,
                _fd: PhantomData,
            };
            // Only filters libarchive decodes itself: one built without its
            // library falls back to running an outside program (and lrzip,
            // lzop and grzip only ever do), which a parser must never do.
            for f in builtin_filters() {
                f(a);
            }
            // Not "all": mtree reads the files its entries name from the
            // disk, and warc, lha and xar aren't formats Atlas Archive offers.
            for f in [
                archive_read_support_format_7zip,
                archive_read_support_format_ar,
                archive_read_support_format_cab,
                archive_read_support_format_cpio,
                archive_read_support_format_iso9660,
                archive_read_support_format_rar,
                archive_read_support_format_rar5,
                archive_read_support_format_tar,
                archive_read_support_format_zip,
                archive_read_support_format_empty,
                // Lowest bid: only a compressed file that is no archive.
                archive_read_support_format_raw,
            ] {
                f(a);
            }
            // tar files joined by `cat`, as GNU tar -i reads them.
            let opts = c"read_concatenated_archives";
            archive_read_set_options(a, opts.as_ptr());
            if let Some(p) = &password
                && archive_read_add_passphrase(a, p.as_ptr().cast()) != ARCHIVE_OK
            {
                return Err(r.error("The password couldn't be used"));
            }
            if archive_read_open_fd(a, fd.as_raw_fd(), 256 * 1024) != ARCHIVE_OK {
                return Err(r.error("The file isn't an archive Atlas Archive can read"));
            }
            Ok(r)
        }
    }

    fn error(&self, fallback: &str) -> Error {
        // SAFETY: valid handle.
        let msg = cstr_bytes(unsafe { archive_error_string(self.a) })
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .filter(|s| !s.is_empty());
        Error(match msg {
            Some(m) => format!("{fallback}: {m}."),
            None => format!("{fallback}."),
        })
    }

    /// The next entry's header, or `None` at the end.
    pub fn next_header(&mut self) -> Result<Option<Entry>, Error> {
        let mut e = std::ptr::null_mut();
        // SAFETY: valid handle; `e` is owned by libarchive until the next call.
        let r = unsafe { archive_read_next_header(self.a, &mut e) };
        match r {
            ARCHIVE_EOF => return Ok(None),
            ARCHIVE_OK | ARCHIVE_WARN => {}
            _ => return Err(self.error("The archive is damaged")),
        }
        self.entry = e;
        // SAFETY: `e` is valid until the next header is read.
        let entry = unsafe {
            let path = cstr_bytes(archive_entry_pathname(e)).unwrap_or_default();
            let hardlink = cstr_bytes(archive_entry_hardlink(e));
            let kind = if hardlink.is_some() {
                Kind::Hardlink
            } else {
                match archive_entry_filetype(e) & AE_IFMT {
                    AE_IFREG => Kind::File,
                    AE_IFDIR => Kind::Dir,
                    AE_IFLNK => Kind::Symlink,
                    // A raw entry has no type: it is the one file inside.
                    0 if self.is_raw() => Kind::File,
                    _ => Kind::Special,
                }
            };
            let link = match kind {
                Kind::Hardlink => hardlink,
                Kind::Symlink => cstr_bytes(archive_entry_symlink(e)),
                _ => None,
            };
            let size =
                (archive_entry_size_is_set(e) != 0).then(|| archive_entry_size(e).max(0) as u64);
            let mtime = (archive_entry_mtime_is_set(e) != 0).then(|| archive_entry_mtime(e) as i64);
            Entry {
                index: self.index,
                utf8: std::str::from_utf8(&path).is_ok(),
                path,
                kind,
                size,
                packed: None,
                mtime,
                mode: archive_entry_perm(e) & 0o7777,
                encrypted: archive_entry_is_encrypted(e) != 0,
                link,
            }
        };
        self.index += 1;
        Ok(Some(entry))
    }

    /// Reads the current entry's data. 0 at its end.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        // SAFETY: valid handle and buffer.
        let n = unsafe { archive_read_data(self.a, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(self.error("An item couldn't be read"));
        }
        Ok(n as usize)
    }

    /// Skips the current entry's data.
    pub fn skip(&mut self) -> Result<(), Error> {
        // SAFETY: valid handle.
        if unsafe { archive_read_data_skip(self.a) } < ARCHIVE_WARN {
            return Err(self.error("The archive is damaged"));
        }
        Ok(())
    }

    /// Bytes read from the archive file so far (for the ratio limits).
    pub fn bytes_read(&self) -> u64 {
        // SAFETY: valid handle; -1 is the last filter, the file itself.
        unsafe { archive_filter_bytes(self.a, -1) }.max(0) as u64
    }

    fn is_raw(&self) -> bool {
        // SAFETY: valid handle.
        unsafe { archive_format(self.a) & ARCHIVE_FORMAT_BASE_MASK == ARCHIVE_FORMAT_RAW }
    }

    /// The file is a plain compressed file (`notes.txt.gz`), not an archive.
    pub fn is_compressed_file(&self) -> bool {
        self.is_raw()
    }

    /// A raw read with no compression filter is just some file, not an
    /// archive: refused.
    pub fn is_plain_file(&self) -> bool {
        // SAFETY: valid handle.
        self.is_raw()
            && unsafe {
                archive_filter_count(self.a) <= 1
                    || archive_filter_code(self.a, 0) == ARCHIVE_FILTER_NONE
            }
    }

    /// "tar.gz", "zip", "7z", "gz"... after the first header.
    pub fn format_name(&self) -> String {
        // SAFETY: valid handle; strings copied at once.
        unsafe {
            let format = cstr_bytes(archive_format_name(self.a))
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            let filters: Vec<String> = (0..archive_filter_count(self.a))
                .filter(|&i| archive_filter_code(self.a, i) != ARCHIVE_FILTER_NONE)
                .filter_map(|i| cstr_bytes(archive_filter_name(self.a, i)))
                .map(|b| short_filter(&String::from_utf8_lossy(&b)))
                .collect();
            let base = short_format(&format);
            match (self.is_raw(), filters.first()) {
                (true, Some(f)) => f.clone(),
                (_, Some(f)) => format!("{base}.{f}"),
                (_, None) => base,
            }
        }
    }

    /// Some entries are encrypted (known after the first header; `None`: the
    /// format can't tell).
    pub fn has_encrypted_entries(&self) -> Option<bool> {
        // SAFETY: valid handle.
        match unsafe { archive_read_has_encrypted_entries(self.a) } {
            0 => Some(false),
            n if n > 0 => Some(true),
            _ => None,
        }
    }
}

type Support = unsafe extern "C" fn(*mut archive) -> c_int;

/// The filters this libarchive decodes with its own code, found once by
/// registering each on a throwaway handle: `ARCHIVE_WARN` means it would run
/// an outside program instead.
fn builtin_filters() -> &'static [Support] {
    static FILTERS: std::sync::OnceLock<Vec<Support>> = std::sync::OnceLock::new();
    FILTERS.get_or_init(|| {
        let all: [Support; 9] = [
            archive_read_support_filter_gzip,
            archive_read_support_filter_bzip2,
            archive_read_support_filter_xz,
            archive_read_support_filter_lzma,
            archive_read_support_filter_lzip,
            archive_read_support_filter_zstd,
            archive_read_support_filter_lz4,
            archive_read_support_filter_compress,
            archive_read_support_filter_rpm,
        ];
        all.into_iter()
            .filter(|f| {
                // SAFETY: a fresh handle, freed at once.
                unsafe {
                    let probe = archive_read_new();
                    if probe.is_null() {
                        return false;
                    }
                    let ok = f(probe) == ARCHIVE_OK;
                    archive_read_free(probe);
                    ok
                }
            })
            .collect()
    })
}

/// libarchive's filter names to file extensions.
fn short_filter(name: &str) -> String {
    match name {
        "gzip" => "gz",
        "bzip2" => "bz2",
        "zstd" => "zst",
        "lzip" => "lz",
        "compress (.Z)" => "Z",
        other => other,
    }
    .into()
}

/// libarchive's format names to the short ones Atlas Archive shows.
fn short_format(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    let short =
        if n.contains("tar") || n.contains("ustar") || n.contains("pax") || n.contains("gnu") {
            "tar"
        } else if n.contains("7-zip") {
            "7z"
        } else if n.contains("rar") {
            "rar"
        } else if n.contains("iso9660") {
            "iso"
        } else if n.contains("cab") {
            "cab"
        } else if n.contains("cpio") || n.contains("rpm") {
            if n.contains("rpm") { "rpm" } else { "cpio" }
        } else if n.contains("ar") {
            "ar"
        } else if n.contains("zip") {
            "zip"
        } else {
            return n;
        };
    short.into()
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        // SAFETY: the handle is ours and freed once.
        unsafe { archive_read_free(self.a) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::path::PathBuf;
    use std::process::Command;

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
        let p = base.join(format!("atlas-la-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn list(path: &std::path::Path) -> (String, Vec<Entry>) {
        let f = std::fs::File::open(path).unwrap();
        let mut r = Reader::open(f.as_fd()).unwrap();
        let mut out = Vec::new();
        while let Some(e) = r.next_header().unwrap() {
            r.skip().unwrap();
            out.push(e);
        }
        (r.format_name(), out)
    }

    #[test]
    fn tar_gz_lists_with_kinds_and_links() {
        let d = scratch("targz");
        let src = d.join("src");
        std::fs::create_dir_all(src.join("dir")).unwrap();
        std::fs::write(src.join("dir/a.txt"), b"hello").unwrap();
        std::os::unix::fs::symlink("a.txt", src.join("dir/link")).unwrap();
        std::fs::hard_link(src.join("dir/a.txt"), src.join("hard")).unwrap();
        let out = d.join("t.tar.gz");
        let ok = Command::new("tar")
            .arg("-czf")
            .arg(&out)
            .arg("-C")
            .arg(&src)
            .arg(".")
            .status()
            .unwrap();
        assert!(ok.success());
        let (format, entries) = list(&out);
        assert_eq!(format, "tar.gz");
        let find = |p: &str| {
            entries
                .iter()
                .find(|e| e.path == p.as_bytes())
                .unwrap_or_else(|| panic!("{p}"))
        };
        assert_eq!(find("./dir/a.txt").kind, Kind::File);
        assert_eq!(find("./dir/a.txt").size, Some(5));
        assert_eq!(find("./dir/").kind, Kind::Dir);
        assert_eq!(find("./dir/link").link.as_deref(), Some(&b"a.txt"[..]));
        let hard = entries.iter().find(|e| e.kind == Kind::Hardlink).unwrap();
        assert!(hard.link.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn plain_gz_is_one_file_and_plain_files_are_refused() {
        let d = scratch("gz");
        let mut f = std::fs::File::create(d.join("notes.txt")).unwrap();
        f.write_all(b"some notes").unwrap();
        assert!(
            Command::new("gzip")
                .arg("-k")
                .arg(d.join("notes.txt"))
                .status()
                .unwrap()
                .success()
        );
        let file = std::fs::File::open(d.join("notes.txt.gz")).unwrap();
        let mut r = Reader::open(file.as_fd()).unwrap();
        let e = r.next_header().unwrap().unwrap();
        assert_eq!(e.kind, Kind::File);
        assert!(r.is_compressed_file() && !r.is_plain_file());
        let mut buf = [0u8; 64];
        let n = r.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"some notes");

        let file = std::fs::File::open(d.join("notes.txt")).unwrap();
        match Reader::open(file.as_fd()) {
            Err(_) => {}
            Ok(mut r) => {
                let _ = r.next_header();
                assert!(r.is_plain_file());
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn every_filter_is_built_in() {
        // Fedora's libarchive has them all; a missing one would mean an
        // outside program, so it is left out and this says so.
        assert_eq!(builtin_filters().len(), 9);
    }

    #[test]
    fn garbage_is_an_error_not_a_crash() {
        let d = scratch("garbage");
        let mut bytes = b"7z\xBC\xAF\x27\x1C".to_vec();
        bytes.extend((0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8));
        std::fs::write(d.join("bad.7z"), &bytes).unwrap();
        let file = std::fs::File::open(d.join("bad.7z")).unwrap();
        if let Ok(mut r) = Reader::open(file.as_fd()) {
            let mut n = 0;
            while let Ok(Some(_)) = r.next_header() {
                n += 1;
                if n > 1000 {
                    break;
                }
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
