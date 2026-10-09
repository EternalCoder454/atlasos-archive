#![no_main]
//! Text the D-Bus callers send: URIs of archives and folders, and the strings
//! the service puts in its JSON.
use libfuzzer_sys::fuzz_target;
use telamon_archive_service::{json, uri};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();
    if let Ok(path) = uri::to_path(&text) {
        assert!(path.is_absolute());
        let s = path.to_string_lossy();
        assert!(!s.contains('\0'));
        assert!(!s.split('/').any(|c| c == ".." || c == "."), "{s:?}");
        // a path it accepted survives being written as a URI and read back
        let back = uri::to_path(&uri::from_path(&path)).expect("its own URI reads back");
        assert_eq!(back, path);
    }
    let mut out = String::new();
    json::string(&mut out, &text);
    assert!(out.starts_with('"') && out.ends_with('"') && out.len() >= 2);
    let inner = &out[1..out.len() - 1];
    assert!(!inner.chars().any(|c| (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}'), "{out:?}");
    // an unescaped quote or backslash would end the string early
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                it.next().expect("an escape has a character");
            }
            '"' => panic!("a raw quote inside a JSON string: {out:?}"),
            _ => {}
        }
    }
});
