//! A small JSON writer: just enough for one object per line, with strings
//! escaped so nothing in an archive can break the line or fool a viewer.

use std::fmt::Write as _;

use telamon_archive_core::name;

/// Whether `c` is written as `\uXXXX`: the controls (C0, DEL, C1, U+2028 and
/// U+2029) and the bidi controls (U+202A to U+202E, U+2066 to U+2069, U+200E,
/// U+200F, U+061C). The quote and backslash get their usual short escapes.
fn must_escape(c: char) -> bool {
    name::is_control(c) || name::is_bidi_control(c)
}

/// `text` as a JSON string, quotes included.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
            out.push(c);
        } else if must_escape(c) {
            // Every escaped character is in the BMP: one `\uXXXX` each.
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out.push('"');
    out
}

/// Bytes as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// One JSON object, built key by key.
pub struct Obj {
    buf: String,
}

impl Obj {
    pub fn new() -> Obj {
        Obj { buf: "{".into() }
    }

    fn key(&mut self, key: &str) {
        if self.buf.len() > 1 {
            self.buf.push(',');
        }
        self.buf.push_str(&quote(key));
        self.buf.push(':');
    }

    pub fn str(mut self, key: &str, value: &str) -> Obj {
        self.key(key);
        self.buf.push_str(&quote(value));
        self
    }

    pub fn opt_str(self, key: &str, value: Option<&str>) -> Obj {
        match value {
            Some(v) => self.str(key, v),
            None => self.raw(key, "null"),
        }
    }

    pub fn num(self, key: &str, value: u64) -> Obj {
        self.raw(key, &value.to_string())
    }

    pub fn opt_num(self, key: &str, value: Option<u64>) -> Obj {
        match value {
            Some(v) => self.num(key, v),
            None => self.raw(key, "null"),
        }
    }

    pub fn opt_int(self, key: &str, value: Option<i64>) -> Obj {
        match value {
            Some(v) => self.raw(key, &v.to_string()),
            None => self.raw(key, "null"),
        }
    }

    pub fn bool(self, key: &str, value: bool) -> Obj {
        self.raw(key, if value { "true" } else { "false" })
    }

    /// A value that is JSON already (a nested object, `null`).
    pub fn raw(mut self, key: &str, json: &str) -> Obj {
        self.key(key);
        self.buf.push_str(json);
        self
    }

    pub fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_quoted() {
        assert_eq!(quote("a b/c.txt"), "\"a b/c.txt\"");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("héllo 日本"), "\"héllo 日本\"");
    }

    #[test]
    fn quote_and_backslash_are_escaped() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn controls_are_escaped() {
        assert_eq!(quote("a\nb\tc\0"), "\"a\\u000ab\\u0009c\\u0000\"");
        assert_eq!(quote("\x1b[31m"), "\"\\u001b[31m\"");
        assert_eq!(quote("\x7f\u{85}"), "\"\\u007f\\u0085\"");
        assert_eq!(quote("\u{2028}\u{2029}"), "\"\\u2028\\u2029\"");
    }

    #[test]
    fn bidi_controls_are_escaped() {
        for c in ('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}')
            .chain(['\u{200e}', '\u{200f}', '\u{061c}'])
        {
            let q = quote(&format!("a{c}b"));
            assert_eq!(q, format!("\"a\\u{:04x}b\"", c as u32), "{:x}", c as u32);
            assert!(q.is_ascii());
        }
    }

    #[test]
    fn nothing_escaped_is_left_raw() {
        let all: String = (0..0x3000u32).filter_map(char::from_u32).collect();
        let q = quote(&all);
        assert!(
            !q.chars()
                .any(|c| name::is_control(c) || name::is_bidi_control(c))
        );
    }

    #[test]
    fn objects_have_commas_and_nulls() {
        let o = Obj::new()
            .str("a", "x\"")
            .num("b", 5)
            .opt_str("c", None)
            .opt_num("d", Some(7))
            .opt_int("e", Some(-3))
            .bool("f", true)
            .raw("g", "{}")
            .finish();
        assert_eq!(
            o,
            r#"{"a":"x\"","b":5,"c":null,"d":7,"e":-3,"f":true,"g":{}}"#
        );
        assert_eq!(Obj::new().finish(), "{}");
    }

    #[test]
    fn keys_are_escaped_too() {
        assert_eq!(Obj::new().num("a\nb", 1).finish(), "{\"a\\u000ab\":1}");
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0, 0xff, 0x1a]), "00ff1a");
    }
}
