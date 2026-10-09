#![no_main]
//! Names as an archive stores them: decoded, shown, written to disk.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use telamon_archive_core::name::{self, MAX_COMPONENT_BYTES, NameEncoding, Piece};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    raw: &'a [u8],
    encoding: u8,
    n: u32,
}

const LABELS: [&str; 6] = ["UTF-8", "IBM437", "Shift_JIS", "GBK", "Big5", "EUC-KR"];

fuzz_target!(|i: Input| {
    let enc = NameEncoding::from_label(LABELS[usize::from(i.encoding) % LABELS.len()]).unwrap();
    let mut pieces: Vec<Piece> = Vec::new();
    name::decode(i.raw, enc, |p| pieces.push(p));
    let (shown, _unusual) = name::display(&pieces);
    assert!(!shown.chars().any(|c| c.is_control()), "{shown:?}");
    assert!(!shown.chars().any(name::is_bidi_control), "{shown:?}");
    let (disk, _renamed) = name::disk(&pieces);
    assert!(!disk.contains(['/', '\0']) && !disk.chars().any(|c| c.is_control()), "{disk:?}");
    assert!(disk.len() <= MAX_COMPONENT_BYTES);
    let numbered = name::numbered(&disk, i.n);
    assert!(numbered.len() <= MAX_COMPONENT_BYTES, "{}", numbered.len());
    let _ = name::is_launcher(&disk);
    let _ = name::display_text(&String::from_utf8_lossy(i.raw));
    let _ = name::detect([i.raw], i.n % 2 == 0);
});
