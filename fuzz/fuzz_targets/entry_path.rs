#![no_main]
//! The path an archive stores for an entry: whatever it holds, what passes may
//! only name something below the folder it is written into.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use telamon_archive_core::name::{MAX_COMPONENT_BYTES, NameEncoding};
use telamon_archive_core::path::{self, MAX_DEPTH, MAX_PATH_BYTES};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    raw: &'a [u8],
    encoding: u8,
    dos: bool,
}

const LABELS: [&str; 6] = ["UTF-8", "IBM437", "Shift_JIS", "GBK", "Big5", "windows-1251"];

fuzz_target!(|i: Input| {
    let enc = NameEncoding::from_label(LABELS[usize::from(i.encoding) % LABELS.len()]).unwrap();
    if let Ok(p) = path::parse(i.raw, enc, i.dos) {
        assert!(!p.components.is_empty() && p.components.len() <= MAX_DEPTH);
        for c in &p.components {
            let d = c.disk.as_str();
            assert!(!d.is_empty() && d != "." && d != "..", "{d:?}");
            assert!(!d.contains(['/', '\0']), "{d:?}");
            assert!(!d.chars().any(|c| c.is_control()), "{d:?}");
            assert!(d.len() <= MAX_COMPONENT_BYTES, "{}", d.len());
        }
        let joined = p.disk_path();
        assert!(joined.len() <= MAX_PATH_BYTES);
        assert!(!joined.starts_with('/'));
        assert!(!joined.split('/').any(|c| c == ".." || c == "." || c.is_empty()));
        // and nothing in the raw path was an absolute one
        assert!(!i.raw.starts_with(b"/"));
        assert!(!i.raw.contains(&0));
    }
});
