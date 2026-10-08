//! Turning a call into work, and doing it: the argument rules shared by the
//! API's methods, and the job thread that drives the client for each kind of
//! job.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use telamon_archive_core::client::{
    self, Callbacks, Clash, ClashAnswer, ClashPolicy, CompressRequest, Error, ExtractRequest, Mode,
};
use telamon_archive_core::compress::CompressFormat;
use telamon_archive_core::limits::Exceeded;
use telamon_archive_core::name;
use telamon_archive_core::tree::{ROOT, Tree};
use zeroize::Zeroizing;

use crate::validate::{self, FileId, shown};
use crate::{
    Answer, ApiError, Ask, Inner, Job, MAX_ARCHIVES, MAX_ITEMS, State, Work, answer_channel, uri,
};

/// How long a waiting job sleeps between looks at Cancel.
const PARK_SLICE: Duration = Duration::from_millis(100);
/// The most rows of skipped items a job keeps.
const MAX_DETAILS: usize = 200;
/// The most nodes of listings held at once across a job's archives.
const KEEP_NODES: usize = 1_000_000;
/// The longest error kept, in characters.
const MAX_ERROR: usize = 600;

/// One archive to extract, checked when the call was made.
#[derive(Clone, Debug)]
pub(crate) struct ExtractItem {
    pub archive: PathBuf,
    pub id: FileId,
    pub dest_dir: PathBuf,
}

fn invalid(words: impl Into<String>) -> ApiError {
    ApiError::InvalidArgs(words.into())
}

/// The archives of a call: at least one, not too many, each checked. Their
/// destination is `folder` or the archive's own folder.
pub(crate) fn archives(
    uris: &[String],
    folder: Option<&Path>,
) -> Result<Vec<ExtractItem>, ApiError> {
    if uris.is_empty() {
        return Err(invalid("Choose at least one archive."));
    }
    if uris.len() > MAX_ARCHIVES {
        return Err(invalid(format!(
            "Telamon Archive takes at most {MAX_ARCHIVES} archives at a time."
        )));
    }
    uris.iter()
        .map(|u| {
            let (archive, id) = validate::archive(u)?;
            let dest_dir = match folder {
                Some(f) => f.to_path_buf(),
                None => archive
                    .parent()
                    .map(Path::to_path_buf)
                    .ok_or_else(|| invalid("That archive has no folder to extract into."))?,
            };
            if folder.is_none() {
                validate::check_folder(&dest_dir)?;
            }
            Ok(ExtractItem {
                archive,
                id,
                dest_dir,
            })
        })
        .collect()
}

pub(crate) fn extract_title(items: &[ExtractItem]) -> String {
    match items {
        [one] => format!("Extracting {}", shown(&one.archive)),
        many => format!("Extracting {} archives", many.len()),
    }
}

pub(crate) fn format(label: &str) -> Result<CompressFormat, ApiError> {
    CompressFormat::from_label(label).ok_or_else(|| {
        invalid(format!(
            "“{}” isn't a format Telamon Archive makes. Use zip, 7z, tar.gz, tar.xz or tar.zst.",
            name::display_text(&label.chars().take(40).collect::<String>())
        ))
    })
}

/// The items of a Compress call, each checked, with no two of one name.
pub(crate) fn sources(uris: &[String]) -> Result<Vec<PathBuf>, ApiError> {
    if uris.is_empty() {
        return Err(invalid("Choose at least one file or folder to compress."));
    }
    if uris.len() > MAX_ITEMS {
        return Err(invalid(
            "Too many items are chosen to compress at once. Put them in a folder and compress the folder.",
        ));
    }
    let mut out = Vec::with_capacity(uris.len());
    let mut leaves = std::collections::HashSet::new();
    for u in uris {
        let p = validate::source(u)?;
        let leaf = p
            .file_name()
            .map(|n| n.as_bytes().to_vec())
            .unwrap_or_default();
        if !leaves.insert(leaf) {
            return Err(invalid(format!(
                "Two of the items are named “{}”, so they can't go in one archive.",
                shown(&p)
            )));
        }
        out.push(p);
    }
    Ok(out)
}

/// Where a compression goes: the folder, the file name, and whether the
/// name was the caller's (so a clash asks instead of numbering).
pub(crate) fn target(
    sources: &[PathBuf],
    format: CompressFormat,
    destination: &str,
) -> Result<(PathBuf, String, bool), ApiError> {
    let ext = format.extension();
    if destination.is_empty() {
        let first = &sources[0];
        let folder = first
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| invalid("That item has no folder to save the archive in."))?;
        validate::check_folder(&folder)?;
        let base = if sources.len() > 1 {
            "Archive".to_string()
        } else {
            let leaf = first.file_name().map(|n| n.to_string_lossy().into_owned());
            let meta = std::fs::symlink_metadata(first).ok();
            match leaf {
                // A file loses its extension (`report.pdf` becomes `report.zip`),
                // a folder keeps its whole name.
                Some(l) if meta.is_some_and(|m| m.is_file()) => Path::new(&l)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(l),
                Some(l) => l,
                None => "Archive".to_string(),
            }
        };
        let file_name = format!("{base}{ext}");
        validate::file_name(&file_name)?;
        return Ok((folder, file_name, false));
    }
    let path = uri::to_path(destination).map_err(invalid)?;
    let (Some(folder), Some(leaf)) = (path.parent(), path.file_name()) else {
        return Err(invalid("The archive's place needs a file name."));
    };
    validate::check_folder(folder)?;
    let mut file_name = validate::file_name(&leaf.to_string_lossy())?;
    if !file_name.to_ascii_lowercase().ends_with(ext) {
        file_name.push_str(ext);
        validate::file_name(&file_name)?;
    }
    let made = folder.join(&file_name);
    if made.is_dir() {
        return Err(invalid(format!("“{}” is a folder.", shown(&made))));
    }
    if sources.iter().any(|s| s == &made) {
        return Err(invalid(
            "The archive can't replace one of the items going into it.",
        ));
    }
    Ok((folder.to_path_buf(), file_name, true))
}

pub(crate) fn compress_title(sources: &[PathBuf], format: CompressFormat) -> String {
    match sources {
        [one] => format!("Compressing {} to {}", shown(one), format.shown()),
        many => format!("Compressing {} items to {}", many.len(), format.shown()),
    }
}

/// The shape of an entry token (`Tree::token`): checked when a call is made.
pub(crate) fn token_shape(t: &str) -> bool {
    t.len() <= 20
        && t.split_once('-').is_some_and(|(id, hash)| {
            !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_digit())
                && hash.len() == 8
                && hash.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

/// A failure in words for the `Error` property: safe to show, one piece of text.
pub(crate) fn words(e: &Error) -> String {
    let text = match e {
        Error::Cancelled => "The job was cancelled.".to_string(),
        Error::PasswordRequired => "This archive needs a password, and none was given.".to_string(),
        other => other.to_string(),
    };
    let clean = name::display_text(&text);
    let mut out: String = clean.chars().take(MAX_ERROR).collect();
    if out.is_empty() {
        out = "Telamon Archive did not say why.".into();
    }
    out
}

// ---- the job thread ----

/// The front end the client calls on the job thread: progress goes into the
/// job's state, questions park the thread until the window answers.
struct Front<'a> {
    inner: &'a Arc<Inner>,
    job: &'a Arc<Job>,
    answers: Receiver<Answer>,
    /// What the archives before this one already counted.
    base_bytes: u64,
    base_items: u64,
    /// This archive's own size and items, the most its progress may count.
    cap_bytes: u64,
    cap_items: u64,
    archive: String,
    saved: Option<Zeroizing<Vec<u8>>>,
}

impl Front<'_> {
    fn ask(&mut self, q: Ask) -> Option<Answer> {
        while self.answers.try_recv().is_ok() {}
        {
            let mut d = self.job.lock();
            d.ask = Some(q);
            d.state = State::WaitingForUser;
        }
        self.inner.changed(self.job);
        self.inner.notifier.needs_user(self.job.id);
        let got = loop {
            match self.answers.recv_timeout(PARK_SLICE) {
                Ok(a) => break Some(a),
                Err(RecvTimeoutError::Timeout) if self.job.cancel.is_cancelled() => break None,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break None,
            }
        };
        {
            let mut d = self.job.lock();
            d.ask = None;
            if !d.state.is_over() {
                d.state = if d.user_paused {
                    State::Paused
                } else {
                    State::Running
                };
            }
        }
        self.inner.changed(self.job);
        got
    }

    fn set_totals(&mut self, bytes: u64, items: u64) {
        self.cap_bytes = bytes;
        self.cap_items = items;
    }
}

impl Callbacks for Front<'_> {
    fn progress(&mut self, bytes: u64, items: u64) {
        {
            let mut d = self.job.lock();
            let (b, i) = (
                if self.cap_bytes > 0 {
                    bytes.min(self.cap_bytes)
                } else {
                    bytes
                },
                if self.cap_items > 0 {
                    items.min(self.cap_items)
                } else {
                    items
                },
            );
            d.processed_bytes = self.base_bytes.saturating_add(b);
            d.processed_items = self.base_items.saturating_add(i);
            if d.total_bytes > 0 {
                d.processed_bytes = d.processed_bytes.min(d.total_bytes);
            }
        }
        self.inner.changed(self.job);
    }

    fn total(&mut self, bytes: u64, items: u64) {
        {
            let mut d = self.job.lock();
            d.total_bytes = bytes;
            d.total_items = items;
        }
        self.set_totals(bytes, items);
        self.inner.changed(self.job);
    }

    fn limit(&mut self, exceeded: &Exceeded) -> bool {
        if !exceeded.kind.askable() {
            return false;
        }
        matches!(
            self.ask(Ask::Limit(name::display_text(&exceeded.question()))),
            Some(Answer::Limit(true))
        )
    }

    fn password(&mut self, wrong: bool) -> Option<Zeroizing<Vec<u8>>> {
        if !wrong && let Some(p) = &self.saved {
            return Some(p.clone());
        }
        let archive = self.archive.clone();
        match self.ask(Ask::Password { archive, wrong }) {
            Some(Answer::Password(Some(p))) if !p.is_empty() => {
                self.saved = Some(p.clone());
                Some(p)
            }
            _ => None,
        }
    }

    fn clash(&mut self, item: &str) -> ClashAnswer {
        match self.ask(Ask::Conflict(name::display_text(item))) {
            Some(Answer::Conflict(a)) => a,
            // Cancelled: whatever is chosen, the job stops next.
            _ => ClashAnswer {
                action: Clash::Skip,
                all: false,
            },
        }
    }
}

/// What a listing leaves for the extraction after it.
struct Listed {
    tree: Option<Arc<Tree>>,
    size: u64,
    items: u64,
    encoding: name::NameEncoding,
}

pub(crate) fn execute(inner: &Arc<Inner>, job: &Arc<Job>, work: Work) -> Result<(), Error> {
    let mut front = Front {
        inner,
        job,
        answers: answer_channel(job),
        base_bytes: 0,
        base_items: 0,
        cap_bytes: 0,
        cap_items: 0,
        archive: String::new(),
        saved: None,
    };
    match work {
        Work::Extract { items, here } => extract(inner, job, &mut front, &items, here),
        Work::Entries {
            archive,
            id,
            tokens,
            folder,
        } => entries(inner, job, &mut front, &archive, id, &tokens, &folder),
        Work::Compress {
            sources,
            folder,
            file_name,
            format,
            level,
            ask_on_clash,
        } => {
            let req = CompressRequest {
                sources: &sources,
                dest_dir: &folder,
                file_name: &file_name,
                format,
                level,
                clash: if ask_on_clash {
                    ClashPolicy::Ask
                } else {
                    ClashPolicy::Number
                },
                clash_all: None,
            };
            let got = inner.cfg.worker.compress(&req, &mut front, &job.cancel)?;
            let mut d = job.lock();
            if !got.left_out {
                d.results.push(uri::from_path(&got.path));
                d.result_path = got.path.to_string_lossy().into_owned();
            }
            let rows: Vec<(String, String)> = got
                .skipped
                .iter()
                .map(|s| split_reason(&name::display_text(&s.reason)))
                .collect();
            keep_rows(&mut d, rows, got.skipped_more);
            if got.left_out {
                d.error =
                    "Nothing was made, because you chose to skip the file that was already there."
                        .into();
            }
            Ok(())
        }
        Work::Test { archives } => test(inner, job, &mut front, &archives),
        Work::Dialog => Err(Error::Failed(
            "The job was started before it was set up.".into(),
        )),
    }
}

/// `“name” isn't included because why.` as (name, why).
fn split_reason(reason: &str) -> (String, String) {
    if let Some(rest) = reason.strip_prefix('“')
        && let Some((name, why)) = rest.split_once("” ")
    {
        return (name.to_string(), why.to_string());
    }
    (String::new(), reason.to_string())
}

fn keep_rows(d: &mut crate::Data, rows: Vec<(String, String)>, more: u64) {
    let room = MAX_DETAILS.saturating_sub(d.details.len());
    let left = rows.len().saturating_sub(room) as u64;
    d.details.extend(rows.into_iter().take(room));
    d.details_more = d.details_more.saturating_add(more).saturating_add(left);
}

fn still_the_same(item: &Path, id: FileId) -> Result<(), Error> {
    match std::fs::metadata(item) {
        Ok(m) if FileId::of(&m) == id => Ok(()),
        Ok(_) => Err(Error::Failed(format!(
            "“{}” was replaced by another file after it was chosen, so it wasn't opened.",
            shown(item)
        ))),
        Err(_) => Err(Error::Failed(format!(
            "“{}” isn't there any more.",
            shown(item)
        ))),
    }
}

/// Lists one archive for a job; a broken or oversize one stops the job.
fn list(
    inner: &Arc<Inner>,
    job: &Arc<Job>,
    front: &mut Front<'_>,
    archive: &Path,
    id: FileId,
    keep: bool,
) -> Result<Listed, Error> {
    still_the_same(archive, id)?;
    front.archive = shown(archive);
    front.saved = None;
    let l = inner.cfg.worker.list(archive, None, front, &job.cancel)?;
    if let Some(why) = l.broken {
        return Err(Error::Failed(format!(
            "“{}” is damaged: {}",
            shown(archive),
            name::display_text(&why)
        )));
    }
    if l.tree.overflow {
        return Err(Error::Failed(
            "This archive holds too many items to extract safely.".into(),
        ));
    }
    Ok(Listed {
        size: l.tree.nodes.get(ROOT as usize).map_or(0, |n| n.size),
        items: l.tree.files + l.tree.folders,
        encoding: l.tree.encoding,
        tree: keep.then(|| Arc::new(l.tree)),
    })
}

fn extract(
    inner: &Arc<Inner>,
    job: &Arc<Job>,
    front: &mut Front<'_>,
    items: &[crate::run::ExtractItem],
    here: bool,
) -> Result<(), Error> {
    let worker = &inner.cfg.worker;
    // Every archive is looked at first, so the job knows its total size.
    let mut listed: Vec<Listed> = Vec::with_capacity(items.len());
    let mut nodes = 0usize;
    for (n, it) in items.iter().enumerate() {
        if items.len() > 1 {
            job.lock().queue_note = format!("Reading archive {} of {}", n + 1, items.len());
            inner.changed(job);
        }
        let mut l = list(inner, job, front, &it.archive, it.id, true)?;
        // Only so many listings are kept; the rest are made again.
        let held = l.tree.as_ref().map_or(0, |t| t.nodes.len());
        if nodes + held > KEEP_NODES {
            l.tree = None;
        } else {
            nodes += held;
        }
        listed.push(l);
    }
    {
        let mut d = job.lock();
        d.total_bytes = listed.iter().map(|l| l.size).sum();
        d.total_items = listed.iter().map(|l| l.items).sum();
    }
    let mut clash_all = None;
    for (n, (it, l)) in items.iter().zip(listed).enumerate() {
        if items.len() > 1 {
            job.lock().queue_note = format!("Archive {} of {}", n + 1, items.len());
        }
        front.archive = shown(&it.archive);
        front.set_totals(l.size, l.items);
        front.saved = None;
        inner.changed(job);
        still_the_same(&it.archive, it.id)?;
        let file_name = it
            .archive
            .file_name()
            .map(|n| n.as_bytes().to_vec())
            .unwrap_or_default();
        let default = client::default_name(&file_name);
        let req = ExtractRequest {
            archive: &it.archive,
            dest_dir: &it.dest_dir,
            mode: if here {
                Mode::ExtractHere
            } else {
                Mode::ExtractTo {
                    name: default.clone(),
                }
            },
            selection: None,
            encoding: l.encoding,
            raw_name: default,
            clash_all,
        };
        let got = match worker.extract(&req, front, &job.cancel) {
            Ok(g) => g,
            Err(Error::Failed(why)) if items.len() > n + 1 => {
                let rest = items.len() - n - 1;
                return Err(Error::Failed(format!(
                    "{why} The {} wasn't extracted.",
                    if rest == 1 {
                        "next archive".to_string()
                    } else {
                        format!("other {rest} archives")
                    }
                )));
            }
            Err(e) => return Err(e),
        };
        clash_all = got.clash_all;
        front.base_bytes = front.base_bytes.saturating_add(l.size);
        front.base_items = front.base_items.saturating_add(l.items);
        let tree = l.tree;
        let names = names_for(tree.as_deref(), got.skipped.iter().map(|s| s.index));
        let mut rows: Vec<(String, String)> = got
            .skipped
            .iter()
            .map(|s| {
                (
                    names
                        .get(&s.index)
                        .cloned()
                        .unwrap_or_else(|| format!("Item {}", s.index)),
                    name::display_text(&s.reason),
                )
            })
            .collect();
        rows.extend(
            got.removed
                .iter()
                .map(|r| (name::display_text(&r.path), name::display_text(&r.reason))),
        );
        let more = got.skipped_more.saturating_add(got.removed_more as u64);
        let mut d = job.lock();
        if !got.left_out {
            for p in &got.paths {
                d.results.push(uri::from_path(p));
            }
            d.result_path = got.path.to_string_lossy().into_owned();
        } else if items.len() == 1 {
            d.error = "Nothing was extracted, because you chose to skip the one item that was already there.".into();
        }
        if let Some(w) = got.unconfirmed {
            d.warning = name::display_text(&w);
        }
        keep_rows(&mut d, rows, more);
    }
    Ok(())
}

/// Names for the skipped entries, from the listing when it was kept.
fn names_for(
    tree: Option<&Tree>,
    wanted: impl Iterator<Item = u32>,
) -> std::collections::HashMap<u32, String> {
    let wanted: std::collections::HashSet<u32> = wanted.collect();
    let mut out = std::collections::HashMap::new();
    let Some(tree) = tree else { return out };
    if wanted.is_empty() {
        return out;
    }
    for (id, n) in tree.nodes.iter().enumerate() {
        if let Some(e) = n.entry
            && wanted.contains(&e)
        {
            out.insert(e, name::display_text(&tree.display_path(id as u32)));
        }
    }
    out
}

fn entries(
    inner: &Arc<Inner>,
    job: &Arc<Job>,
    front: &mut Front<'_>,
    archive: &Path,
    id: FileId,
    tokens: &[String],
    folder: &Path,
) -> Result<(), Error> {
    let l = list(inner, job, front, archive, id, true)?;
    let Some(tree) = l.tree else {
        return Err(Error::Failed("The archive couldn't be read.".into()));
    };
    let changed = || {
        Error::Failed(
            "The archive has changed since its contents were shown, so those items can't be found. Open it again."
                .into(),
        )
    };
    let mut ids = Vec::with_capacity(tokens.len());
    for t in tokens {
        ids.push(tree.resolve_token(t).ok_or_else(changed)?);
    }
    let picked = tree.pick(&ids).ok_or_else(|| {
        Error::Failed("The items are not all in one folder of the archive.".into())
    })?;
    let size: u64 = if tree.format.solid {
        l.size
    } else {
        picked
            .names
            .iter()
            .filter_map(|n| tree.find(picked.dir.iter().map(String::as_str).chain([n.as_str()])))
            .map(|i| tree.nodes[i as usize].size)
            .sum()
    };
    {
        let mut d = job.lock();
        d.total_bytes = size;
        d.total_items = picked.entries.len() as u64;
    }
    front.set_totals(size, picked.entries.len() as u64);
    inner.changed(job);
    still_the_same(archive, id)?;
    let req = ExtractRequest {
        archive,
        dest_dir: folder,
        mode: Mode::Items {
            dir: picked.dir,
            names: picked.names,
        },
        selection: Some(picked.entries),
        encoding: l.encoding,
        raw_name: client::default_name(archive.file_name().map_or(&[][..], |n| n.as_bytes())),
        clash_all: None,
    };
    let got = inner.cfg.worker.extract(&req, front, &job.cancel)?;
    let names = names_for(Some(&tree), got.skipped.iter().map(|s| s.index));
    let mut rows: Vec<(String, String)> = got
        .skipped
        .iter()
        .map(|s| {
            (
                names
                    .get(&s.index)
                    .cloned()
                    .unwrap_or_else(|| format!("Item {}", s.index)),
                name::display_text(&s.reason),
            )
        })
        .collect();
    rows.extend(
        got.removed
            .iter()
            .map(|r| (name::display_text(&r.path), name::display_text(&r.reason))),
    );
    let more = got.skipped_more.saturating_add(got.removed_more as u64);
    let mut d = job.lock();
    for p in &got.paths {
        d.results.push(uri::from_path(p));
    }
    d.result_path = got.path.to_string_lossy().into_owned();
    if let Some(w) = got.unconfirmed {
        d.warning = name::display_text(&w);
    }
    keep_rows(&mut d, rows, more);
    Ok(())
}

fn test(
    inner: &Arc<Inner>,
    job: &Arc<Job>,
    front: &mut Front<'_>,
    archives: &[(PathBuf, FileId)],
) -> Result<(), Error> {
    for (n, (archive, id)) in archives.iter().enumerate() {
        if archives.len() > 1 {
            job.lock().queue_note = format!("Archive {} of {}", n + 1, archives.len());
            inner.changed(job);
        }
        still_the_same(archive, *id)?;
        front.archive = shown(archive);
        front.saved = None;
        inner
            .cfg
            .worker
            .test(archive, front, &job.cancel)
            .map_err(|e| match e {
                Error::Failed(why) => {
                    Error::Failed(format!("“{}” didn't pass: {why}", shown(archive)))
                }
                other => other,
            })?;
    }
    job.lock().processed_items = archives.len() as u64;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shapes() {
        assert!(token_shape("12-0a1b2c3d"));
        assert!(token_shape("0-ffffffff"));
        for bad in [
            "",
            "12",
            "12-",
            "-0a1b2c3d",
            "12-0a1b2c3",
            "12-0a1b2c3dd",
            "1x-0a1b2c3d",
            "12-0a1b2c3g",
            "123456789012345678901-0a1b2c3d",
        ] {
            assert!(!token_shape(bad), "{bad}");
        }
    }

    #[test]
    fn reasons_split_into_name_and_why() {
        assert_eq!(
            split_reason("“a.txt” isn't included because it was removed."),
            (
                "a.txt".into(),
                "isn't included because it was removed.".into()
            )
        );
        assert_eq!(split_reason("plain"), (String::new(), "plain".into()));
    }

    #[test]
    fn error_words_are_short_and_plain() {
        let long = Error::Failed("x\u{202e}y".repeat(1000));
        let w = words(&long);
        assert!(w.chars().count() <= MAX_ERROR);
        assert!(!w.contains('\u{202e}'));
        assert_eq!(
            words(&Error::Failed(String::new())),
            "Telamon Archive did not say why."
        );
    }
}
