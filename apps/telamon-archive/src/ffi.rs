//! The C interface `cpp/service.cpp` uses to reach the job service
//! (`telamon-archive-service`): the D-Bus methods and the job windows call
//! these, and events come back through one callback. Plain C types only; text
//! is UTF-8 and NUL-terminated; text handed out is freed with
//! `telamon_string_free`. Every pointer is checked, every panic stopped.

use std::ffi::{CStr, CString, c_char, c_int};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use telamon_archive_core::client::Worker;
use telamon_archive_core::compress::{CompressFormat, Level};
use telamon_archive_service::{
    Answer, ApiError, CompressChoice, Config, Notifier, Options, Service, State,
};
use zeroize::Zeroizing;

/// What `Event` reports. `arg` is JSON for finished (`{"state","results"}`).
const ADDED: c_int = 0;
const CHANGED: c_int = 1;
const FINISHED: c_int = 2;
const NEEDS_USER: c_int = 3;
const REMOVED: c_int = 4;

pub type Event = extern "C" fn(kind: c_int, id: u32, arg: *const c_char);

/// The options of a call: `show_progress` 0 or 1; the others may be null.
#[repr(C)]
pub struct CallOptions {
    pub show_progress: c_int,
    pub activation_token: *const c_char,
    pub parent_window: *const c_char,
}

struct Events(Event);

impl Notifier for Events {
    fn added(&self, id: u32) {
        (self.0)(ADDED, id, std::ptr::null());
    }
    fn changed(&self, id: u32) {
        (self.0)(CHANGED, id, std::ptr::null());
    }
    fn finished(&self, id: u32, state: State, results: &[String]) {
        let mut j = String::from("{\"state\":");
        j.push('"');
        j.push_str(state.as_str());
        j.push_str("\",\"results\":[");
        for (n, r) in results.iter().enumerate() {
            if n > 0 {
                j.push(',');
            }
            telamon_archive_service::json_string(&mut j, r);
        }
        j.push_str("]}");
        if let Ok(c) = CString::new(j) {
            (self.0)(FINISHED, id, c.as_ptr());
        }
    }
    fn needs_user(&self, id: u32) {
        (self.0)(NEEDS_USER, id, std::ptr::null());
    }
    fn removed(&self, id: u32) {
        (self.0)(REMOVED, id, std::ptr::null());
    }
}

static SERVICE: OnceLock<Service> = OnceLock::new();

/// The worker to use: the installed one. Only the `dev-worker` feature (tests,
/// never a shipped build) lets `TELAMON_ARCHIVE_WORKER` name another.
fn worker() -> Worker {
    #[cfg(feature = "dev-worker")]
    if let Some(p) = std::env::var_os("TELAMON_ARCHIVE_WORKER") {
        return Worker::at(p);
    }
    Worker::system()
}

/// Runs `f`, turning a panic into the fallback.
fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        log::error!("a service call panicked");
        fallback
    })
}

fn svc() -> Option<&'static Service> {
    SERVICE.get()
}

fn text(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string from the caller, valid for this call.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn list(items: *const *const c_char, n: usize) -> Option<Vec<String>> {
    if n == 0 {
        return Some(Vec::new());
    }
    if items.is_null() || n > 1_000_000 {
        return None;
    }
    // SAFETY: `n` pointers, valid for this call.
    let all = unsafe { std::slice::from_raw_parts(items, n) };
    all.iter().map(|&p| text(p)).collect()
}

fn options(o: *const CallOptions) -> Options {
    if o.is_null() {
        return Options::default();
    }
    // SAFETY: a CallOptions valid for this call.
    let o = unsafe { &*o };
    Options {
        show_progress: o.show_progress != 0,
        activation_token: text(o.activation_token),
        parent_window: text(o.parent_window),
    }
}

fn give(s: String) -> *mut c_char {
    CString::new(s.replace('\0', "")).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Writes an error's kind (1 InvalidArgs, 2 TooManyJobs) and words.
fn fail(e: ApiError, kind: *mut c_int, msg: *mut *mut c_char) {
    let k = match e {
        ApiError::InvalidArgs(_) => 1,
        ApiError::TooManyJobs(_) => 2,
    };
    // SAFETY: out-pointers valid for this call, or null.
    unsafe {
        if !kind.is_null() {
            *kind = k;
        }
        if !msg.is_null() {
            *msg = give(e.message().to_string());
        }
    }
}

/// An id, or 0 with the error written.
fn id_or(r: Result<u32, ApiError>, kind: *mut c_int, msg: *mut *mut c_char) -> u32 {
    match r {
        Ok(id) => id,
        Err(e) => {
            fail(e, kind, msg);
            0
        }
    }
}

fn bad_input(kind: *mut c_int, msg: *mut *mut c_char) -> u32 {
    fail(
        ApiError::InvalidArgs("The request wasn't valid text.".into()),
        kind,
        msg,
    );
    0
}

/// Starts the service; `event` is called on any thread. Once.
#[unsafe(no_mangle)]
pub extern "C" fn telamon_service_start(event: Event) -> c_int {
    guard(0, || {
        #[allow(unused_mut)]
        let mut cfg = Config::new(worker());
        // Tests only: how long a finished job's object stays.
        #[cfg(feature = "dev-worker")]
        if let Some(ms) = std::env::var("TELAMON_ARCHIVE_LINGER_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            cfg.linger = Duration::from_millis(ms);
        }
        let svc = Service::new(cfg, Arc::new(Events(event)));
        c_int::from(SERVICE.set(svc).is_ok())
    })
}

/// # Safety
/// `items` is `n` valid strings; the out-pointers are valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_extract_here(
    items: *const *const c_char,
    n: usize,
    o: *const CallOptions,
    kind: *mut c_int,
    msg: *mut *mut c_char,
) -> u32 {
    guard(0, || match (svc(), list(items, n)) {
        (Some(s), Some(a)) => id_or(s.extract_here(&a, options(o)), kind, msg),
        _ => bad_input(kind, msg),
    })
}

/// # Safety
/// As `telamon_service_extract_here`; `folder` is a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_extract_to(
    items: *const *const c_char,
    n: usize,
    folder: *const c_char,
    o: *const CallOptions,
    kind: *mut c_int,
    msg: *mut *mut c_char,
) -> u32 {
    guard(0, || match (svc(), list(items, n), text(folder)) {
        (Some(s), Some(a), Some(f)) => id_or(s.extract_to(&a, &f, options(o)), kind, msg),
        _ => bad_input(kind, msg),
    })
}

/// # Safety
/// As `telamon_service_extract_here`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_extract_all(
    items: *const *const c_char,
    n: usize,
    o: *const CallOptions,
    kind: *mut c_int,
    msg: *mut *mut c_char,
) -> u32 {
    guard(0, || match (svc(), list(items, n)) {
        (Some(s), Some(a)) => id_or(s.extract_all(&a, options(o)), kind, msg),
        _ => bad_input(kind, msg),
    })
}

/// # Safety
/// As `telamon_service_extract_here`; `archive` and `folder` are valid strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_extract_entries(
    archive: *const c_char,
    items: *const *const c_char,
    n: usize,
    folder: *const c_char,
    o: *const CallOptions,
    kind: *mut c_int,
    msg: *mut *mut c_char,
) -> u32 {
    guard(0, || {
        match (svc(), text(archive), list(items, n), text(folder)) {
            (Some(s), Some(a), Some(e), Some(f)) => {
                id_or(s.extract_entries(&a, &e, &f, options(o)), kind, msg)
            }
            _ => bad_input(kind, msg),
        }
    })
}

/// # Safety
/// As `telamon_service_extract_here`; `format` and `dest` are valid strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_compress(
    items: *const *const c_char,
    n: usize,
    format: *const c_char,
    dest: *const c_char,
    o: *const CallOptions,
    kind: *mut c_int,
    msg: *mut *mut c_char,
) -> u32 {
    guard(0, || {
        match (svc(), list(items, n), text(format), text(dest)) {
            (Some(s), Some(a), Some(f), Some(d)) => {
                id_or(s.compress(&a, &f, &d, options(o)), kind, msg)
            }
            _ => bad_input(kind, msg),
        }
    })
}

/// # Safety
/// As `telamon_service_extract_here`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_compress_dialog(
    items: *const *const c_char,
    n: usize,
    o: *const CallOptions,
    kind: *mut c_int,
    msg: *mut *mut c_char,
) -> u32 {
    guard(0, || match (svc(), list(items, n)) {
        (Some(s), Some(a)) => id_or(s.compress_dialog(&a, options(o)), kind, msg),
        _ => bad_input(kind, msg),
    })
}

/// # Safety
/// As `telamon_service_extract_here`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_test(
    items: *const *const c_char,
    n: usize,
    o: *const CallOptions,
    kind: *mut c_int,
    msg: *mut *mut c_char,
) -> u32 {
    guard(0, || match (svc(), list(items, n)) {
        (Some(s), Some(a)) => id_or(s.test(&a, options(o)), kind, msg),
        _ => bad_input(kind, msg),
    })
}

/// Checks an archive for `Open`; writes its path (free it) or the error.
/// Returns 1 on success.
///
/// # Safety
/// `archive` is a valid string; the out-pointers are valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_open(
    archive: *const c_char,
    path: *mut *mut c_char,
    kind: *mut c_int,
    msg: *mut *mut c_char,
) -> c_int {
    guard(0, || match (svc(), text(archive)) {
        (Some(s), Some(a)) => match s.open(&a) {
            Ok(p) => {
                // SAFETY: an out-pointer valid for this call, or null.
                unsafe {
                    if !path.is_null() {
                        *path = give(p.to_string_lossy().into_owned());
                    }
                }
                1
            }
            Err(e) => {
                fail(e, kind, msg);
                0
            }
        },
        _ => {
            bad_input(kind, msg);
            0
        }
    })
}

/// The job as JSON (free it), or null when it is gone.
#[unsafe(no_mangle)]
pub extern "C" fn telamon_service_snapshot(id: u32) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        svc()
            .and_then(|s| s.snapshot(id))
            .map_or(std::ptr::null_mut(), |s| give(s.to_json()))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn telamon_service_pause(id: u32) -> c_int {
    guard(0, || c_int::from(svc().is_some_and(|s| s.pause(id))))
}

#[unsafe(no_mangle)]
pub extern "C" fn telamon_service_resume(id: u32) -> c_int {
    guard(0, || c_int::from(svc().is_some_and(|s| s.resume(id))))
}

#[unsafe(no_mangle)]
pub extern "C" fn telamon_service_cancel(id: u32) -> c_int {
    guard(0, || c_int::from(svc().is_some_and(|s| s.cancel(id))))
}

/// `action`: "replace", "skip" or "keep-both". 1 if the job took the answer.
///
/// # Safety
/// `action` is a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_answer_conflict(
    id: u32,
    action: *const c_char,
    all: c_int,
) -> c_int {
    guard(0, || match (svc(), text(action)) {
        (Some(s), Some(a)) => c_int::from(s.answer_conflict(id, &a, all != 0).unwrap_or(false)),
        _ => 0,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn telamon_service_answer_limit(id: u32, go_on: c_int) -> c_int {
    guard(0, || {
        c_int::from(svc().is_some_and(|s| s.answer(id, Answer::Limit(go_on != 0))))
    })
}

/// The window's answer to a password question. `len` bytes at `bytes`, or
/// none to give up. The caller wipes its copy.
///
/// # Safety
/// `bytes` is `len` valid bytes (or null when `len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_answer_password(
    id: u32,
    bytes: *const u8,
    len: usize,
) -> c_int {
    guard(0, || {
        let too_long = len > telamon_archive_core::proto::MAX_PASSWORD;
        let pw = if len == 0 || bytes.is_null() || too_long {
            None
        } else {
            // SAFETY: `len` readable bytes, per the contract.
            Some(Zeroizing::new(
                unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec(),
            ))
        };
        c_int::from(svc().is_some_and(|s| s.answer(id, Answer::Password(pw))))
    })
}

/// The Extract All dialog's answer. Returns 1, or 0 with the words written.
///
/// # Safety
/// `folder` is a valid string; `msg` is valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_confirm_extract(
    id: u32,
    folder: *const c_char,
    msg: *mut *mut c_char,
) -> c_int {
    guard(0, || match (svc(), text(folder)) {
        (Some(s), Some(f)) => match s.confirm_extract_all(id, PathBuf::from(f)) {
            Ok(()) => 1,
            Err(e) => {
                fail(e, std::ptr::null_mut(), msg);
                0
            }
        },
        _ => 0,
    })
}

/// The Compress dialog's answer. `level`: "store", "fast", "normal" or "best".
///
/// # Safety
/// The strings are valid; `msg` is valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_service_confirm_compress(
    id: u32,
    folder: *const c_char,
    name: *const c_char,
    format: *const c_char,
    level: *const c_char,
    msg: *mut *mut c_char,
) -> c_int {
    guard(0, || {
        let (Some(s), Some(folder), Some(name), Some(format), Some(level)) =
            (svc(), text(folder), text(name), text(format), text(level))
        else {
            return 0;
        };
        let (Some(format), Some(level)) = (
            CompressFormat::from_label(&format),
            Level::from_label(&level),
        ) else {
            fail(
                ApiError::InvalidArgs("Choose a format and a level from the lists.".into()),
                std::ptr::null_mut(),
                msg,
            );
            return 0;
        };
        match s.confirm_compress(
            id,
            CompressChoice {
                folder: PathBuf::from(folder),
                name,
                format,
                level,
            },
        ) {
            Ok(()) => 1,
            Err(e) => {
                fail(e, std::ptr::null_mut(), msg);
                0
            }
        }
    })
}

/// No job exists (finished ones are kept for a minute).
#[unsafe(no_mangle)]
pub extern "C" fn telamon_service_is_idle() -> c_int {
    guard(1, || c_int::from(svc().is_none_or(Service::is_idle)))
}

/// Cancels every job and waits up to `ms` for them to clean up.
#[unsafe(no_mangle)]
pub extern "C" fn telamon_service_shutdown(ms: u32) {
    guard((), || {
        if let Some(s) = svc() {
            s.shutdown(Duration::from_millis(u64::from(ms)));
        }
    });
}

/// Frees text handed out by this interface.
///
/// # Safety
/// `s` came from this interface and is freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telamon_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: made by `CString::into_raw` in `give`.
        drop(unsafe { CString::from_raw(s) });
    }
}
