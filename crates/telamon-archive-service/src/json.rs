//! A job's state as JSON, for the C++ side of the app (D-Bus objects and
//! windows), which has no other way to read a `Snapshot`.

use std::fmt::Write;

use crate::{Ask, Dialog, Snapshot};

/// A JSON string literal.
pub fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn list(out: &mut String, items: impl IntoIterator<Item = String>) {
    out.push('[');
    for (n, i) in items.into_iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        string(out, &i);
    }
    out.push(']');
}

fn opt(out: &mut String, s: &Option<String>) {
    match s {
        Some(s) => string(out, s),
        None => out.push_str("null"),
    }
}

impl Snapshot {
    /// "1.2 MiB of 3.4 GiB" for the job view; "" before anything is known.
    pub fn progress_text(&self) -> String {
        use telamon_archive_core::limits::format_size;
        match (self.processed_bytes, self.total_bytes) {
            (0, 0) => String::new(),
            (done, 0) => format_size(done),
            (done, total) => format!("{} of {}", format_size(done.min(total)), format_size(total)),
        }
    }

    pub fn to_json(&self) -> String {
        let mut o = String::with_capacity(512);
        let _ = write!(o, "{{\"id\":{},\"kind\":", self.id);
        string(&mut o, self.kind.as_str());
        o.push_str(",\"title\":");
        string(&mut o, &self.title);
        o.push_str(",\"state\":");
        string(&mut o, self.state.as_str());
        let _ = write!(
            o,
            ",\"processedBytes\":{},\"totalBytes\":{},\"processedItems\":{},\"totalItems\":{}",
            self.processed_bytes, self.total_bytes, self.processed_items, self.total_items
        );
        o.push_str(",\"text\":");
        string(&mut o, &self.progress_text());
        o.push_str(",\"error\":");
        string(&mut o, &self.error);
        o.push_str(",\"results\":");
        list(&mut o, self.results.iter().cloned());
        o.push_str(",\"ask\":");
        match &self.ask {
            None => o.push_str("null"),
            Some(a) => {
                o.push_str("{\"kind\":");
                string(&mut o, a.kind());
                o.push_str(",\"text\":");
                string(&mut o, &a.text());
                if let Ask::Password { wrong, .. } = a {
                    let _ = write!(o, ",\"wrong\":{wrong}");
                }
                if let Ask::Conflict(item) = a {
                    o.push_str(",\"item\":");
                    string(&mut o, item);
                }
                o.push('}');
            }
        }
        o.push_str(",\"dialog\":");
        match &self.dialog {
            None => o.push_str("null"),
            Some(Dialog::Extract { archives, folder }) => {
                o.push_str("{\"type\":\"extract\",\"archives\":");
                list(
                    &mut o,
                    archives.iter().map(|p| p.to_string_lossy().into_owned()),
                );
                o.push_str(",\"folder\":");
                string(&mut o, &folder.to_string_lossy());
                o.push('}');
            }
            Some(Dialog::Compress {
                sources,
                folder,
                name,
                format,
            }) => {
                o.push_str("{\"type\":\"compress\",\"sources\":");
                list(
                    &mut o,
                    sources.iter().map(|p| p.to_string_lossy().into_owned()),
                );
                o.push_str(",\"folder\":");
                string(&mut o, &folder.to_string_lossy());
                o.push_str(",\"name\":");
                string(&mut o, name);
                o.push_str(",\"format\":");
                string(&mut o, format.label());
                o.push('}');
            }
        }
        o.push_str(",\"details\":[");
        for (n, (name, why)) in self.details.iter().enumerate() {
            if n > 0 {
                o.push(',');
            }
            o.push_str("{\"name\":");
            string(&mut o, name);
            o.push_str(",\"reason\":");
            string(&mut o, why);
            o.push('}');
        }
        let _ = write!(o, "],\"detailsMore\":{}", self.details_more);
        o.push_str(",\"warning\":");
        string(&mut o, &self.warning);
        o.push_str(",\"queueNote\":");
        string(&mut o, &self.queue_note);
        o.push_str(",\"resultPath\":");
        string(&mut o, &self.result_path);
        let _ = write!(o, ",\"showProgress\":{}", self.show_progress);
        o.push_str(",\"token\":");
        opt(&mut o, &self.activation_token);
        o.push_str(",\"parent\":");
        opt(&mut o, &self.parent_window);
        o.push('}');
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kind, State};

    #[test]
    fn a_snapshot_is_valid_json_with_hostile_text() {
        let s = Snapshot {
            id: 7,
            kind: Kind::Extract,
            title: "a\"b\\c\n\u{2028}".into(),
            state: State::WaitingForUser,
            processed_bytes: 1,
            total_bytes: 2,
            processed_items: 3,
            total_items: 4,
            error: "e".into(),
            results: vec!["file:///a%20b".into()],
            ask: Some(Ask::Password {
                archive: "x".into(),
                wrong: true,
            }),
            dialog: None,
            details: vec![("n\u{1}".into(), "w".into())],
            details_more: 5,
            warning: String::new(),
            queue_note: String::new(),
            result_path: "/p".into(),
            show_progress: false,
            activation_token: None,
            parent_window: Some("x11:1".into()),
        };
        let j = s.to_json();
        assert!(!j.contains('\n') && !j.contains('\u{2028}') && !j.contains('\u{1}'));
        assert!(j.starts_with("{\"id\":7,\"kind\":\"extract\""));
        assert!(j.contains("\"ask\":{\"kind\":\"password\""));
        assert!(j.contains("\"wrong\":true"));
        assert!(j.contains("\"token\":null,\"parent\":\"x11:1\"}"));
        assert!(j.contains("\\u000a\\u2028"));
    }
}
