#![no_main]
//! The audit of staging, which runs on whatever a compromised reader left
//! there: links, special files, setuid files, hard links, odd modes and
//! names. After it, what is in staging may only be plain files, folders and
//! links that stay inside it.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use telamon_archive_core::audit;

#[derive(Arbitrary, Debug)]
enum Op {
    Dir(Vec<u8>),
    File(Vec<u8>, u16),
    Link(Vec<u8>, Vec<u8>),
    Hard(Vec<u8>, Vec<u8>),
    Fifo(Vec<u8>),
    Chmod(Vec<u8>, u16),
}

/// A relative path from a few parts, so that operations meet each other.
/// `dots`: `..` and `.` may be among the parts (only for what a link points
/// to, never for where the fuzzer itself creates or changes things: a `..`
/// there would leave the scratch folder).
fn parts(raw: &[u8], dots: bool) -> PathBuf {
    const NAMES: [&str; 7] = ["a", "b", "c", "d.desktop", "x\u{202E}y", "n\u{1}m", "e"];
    let mut p = PathBuf::new();
    for &b in raw.iter().take(4) {
        let i = usize::from(b) % (NAMES.len() + 2);
        p.push(match i {
            7 if dots => "..",
            8 if dots => ".",
            i => NAMES[i % NAMES.len()],
        });
    }
    p
}

/// Where the fuzzer makes or changes something: below staging, no dots.
fn rel(raw: &[u8]) -> PathBuf {
    parts(raw, false)
}

/// What a link points to: dots allowed, and sometimes an absolute path. The
/// fuzzer never writes through a link it made (see `through_link`).
fn target(raw: &[u8]) -> PathBuf {
    if raw.first().is_some_and(|b| b % 7 == 0) {
        PathBuf::from("/etc/passwd")
    } else {
        parts(raw, true)
    }
}

/// Whether something on the way to `p` below `staging` is a link: the fuzzer
/// changes nothing through one (a link to `/etc/passwd` followed by a chmod of
/// it would change a real file).
fn through_link(staging: &Path, p: &Path) -> bool {
    let mut at = staging.to_path_buf();
    for c in p.strip_prefix(staging).unwrap_or(p).components() {
        at.push(c);
        if std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink()) {
            return true;
        }
    }
    false
}

/// Never blocks on a FIFO an earlier operation made at the same name.
fn write_file(f: &Path) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // Not through a hard link: the sandbox does not let the reader link a
    // file from outside staging, so a write through one is not a case.
    if std::fs::symlink_metadata(f).is_ok_and(|m| m.nlink() > 1) {
        return Err(std::io::Error::other("a hard link"));
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(f)?
        .write_all(b"x")
}

fn make_parent(f: &Path) {
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let root = base.join(format!("telamon-fuzz-audit-{}", std::process::id()));
    let _ = std::process::Command::new("chmod").args(["-R", "u+rwx"]).arg(&root).status();
    let _ = std::fs::remove_dir_all(&root);
    let staging = root.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::set_permissions(&staging, PermissionsExt::from_mode(0o700)).unwrap();
    std::fs::write(root.join("outside"), b"secret").unwrap();
    for op in ops.iter().take(24) {
        match op {
            Op::Dir(p) => {
                let d = staging.join(rel(p));
                if !through_link(&staging, &d) {
                    let _ = std::fs::create_dir_all(d);
                }
            }
            Op::File(p, m) => {
                let f = staging.join(rel(p));
                if through_link(&staging, &f) {
                    continue;
                }
                make_parent(&f);
                if write_file(&f).is_ok() {
                    let _ = std::fs::set_permissions(&f, PermissionsExt::from_mode(u32::from(*m) & 0o7777));
                }
            }
            Op::Link(p, t) => {
                let f = staging.join(rel(p));
                if through_link(&staging, &f) {
                    continue;
                }
                make_parent(&f);
                let _ = symlink(target(t), f);
            }
            Op::Hard(p, t) => {
                let f = staging.join(rel(p));
                if through_link(&staging, &f) {
                    continue;
                }
                make_parent(&f);
                // sometimes a hard link to a file outside, as a hostile reader could try
                let to = if t.first().is_some_and(|b| b % 5 == 0) {
                    root.join("outside")
                } else {
                    staging.join(rel(t))
                };
                let _ = std::fs::hard_link(to, f);
            }
            Op::Fifo(p) => {
                let f = staging.join(rel(p));
                if through_link(&staging, &f) {
                    continue;
                }
                make_parent(&f);
                if let Ok(c) = CString::new(f.as_os_str().as_bytes()) {
                    // SAFETY: a C string.
                    unsafe { libc::mkfifo(c.as_ptr(), 0o666) };
                }
            }
            Op::Chmod(p, m) => {
                let f = staging.join(rel(p));
                if !through_link(&staging, &f) {
                    let _ = std::fs::set_permissions(f, PermissionsExt::from_mode(u32::from(*m) & 0o7777));
                }
            }
        }
    }
    let outside_mode = std::fs::metadata(root.join("outside")).unwrap().mode();
    if audit::audit_path(&staging, 0o022).is_ok() {
        check(&staging, &staging);
    }
    // whatever the audit decided, the file outside is as it was
    let md = std::fs::metadata(root.join("outside")).unwrap();
    assert_eq!(md.mode(), outside_mode);
    assert_eq!(std::fs::read(root.join("outside")).unwrap(), b"secret");
});

fn check(root: &Path, dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let root_real = std::fs::canonicalize(root).unwrap();
    for e in rd.flatten() {
        let p = e.path();
        let md = std::fs::symlink_metadata(&p).unwrap();
        let ft = md.file_type();
        assert!(ft.is_file() || ft.is_dir() || ft.is_symlink(), "special file left: {p:?}");
        if !ft.is_symlink() {
            assert_eq!(md.mode() & 0o7000, 0, "setuid, setgid or sticky left: {p:?}");
        }
        if ft.is_file() && md.nlink() > 1 {
            // every name of the file is inside staging
            assert_eq!(count_names(root, md.dev(), md.ino()), md.nlink(), "hard link to the outside: {p:?}");
        }
        if ft.is_symlink() {
            let t = std::fs::read_link(&p).unwrap();
            assert!(t.is_relative(), "absolute link left: {p:?} -> {t:?}");
            if let Ok(real) = std::fs::canonicalize(&p) {
                assert!(real.starts_with(&root_real), "link leaves staging: {p:?} -> {real:?}");
            }
        }
        let name = e.file_name();
        let s = name.to_string_lossy();
        assert!(!s.chars().any(|c| c.is_control() || ('\u{202A}'..='\u{202E}').contains(&c)), "unsafe name left: {s:?}");
        if ft.is_dir() {
            check(root, &p);
        }
    }
}

fn count_names(dir: &Path, dev: u64, ino: u64) -> u64 {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let Ok(md) = std::fs::symlink_metadata(e.path()) else { continue };
            if md.is_dir() {
                n += count_names(&e.path(), dev, ino);
            } else if md.dev() == dev && md.ino() == ino {
                n += 1;
            }
        }
    }
    n
}
