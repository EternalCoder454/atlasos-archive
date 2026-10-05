//! Entry names: decoding the bytes an archive stores, and the two forms a
//! name is used in (docs/DESIGN.md, "Names"):
//!
//! - the **display** form, shown in the window and the CLI: nothing hidden,
//!   nothing that reorders text, every undecodable byte visible;
//! - the **disk** form, the file name written: no control or bidi characters,
//!   never empty, `.` or `..`, at most 255 bytes.
//!
//! Names are one path component here; `path` splits paths into them.

use encoding_rs::Encoding;
use std::fmt::Write as _;

/// The longest file name Linux file systems take, in bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// The encoding of an archive's names. One per archive: names in one archive
/// were written by one program on one system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameEncoding {
    Utf8,
    /// IBM PC code page 437, the zip format's default and what MS-DOS and
    /// Windows' own zip tools write on US systems. Not in encoding_rs.
    Cp437,
    /// Any encoding encoding_rs has (Shift_JIS, GBK, IBM866, Windows-125x...).
    Legacy(&'static Encoding),
}

/// The encodings the window offers under Name Encoding, by label.
pub const CHOICES: &[&str] = &[
    "UTF-8",
    "IBM437",
    "IBM866",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "windows-1253",
    "windows-1254",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-874",
    "KOI8-R",
    "Shift_JIS",
    "EUC-JP",
    "GBK",
    "Big5",
    "EUC-KR",
];

impl NameEncoding {
    /// The label shown and stored (WHATWG names; "IBM437" for CP437).
    pub fn label(self) -> &'static str {
        match self {
            NameEncoding::Utf8 => "UTF-8",
            NameEncoding::Cp437 => "IBM437",
            NameEncoding::Legacy(e) => e.name(),
        }
    }

    /// The encoding with this label, or `None`. Takes any WHATWG label and
    /// "IBM437", "cp437" or "437".
    pub fn from_label(label: &str) -> Option<NameEncoding> {
        let l = label.trim();
        if l.eq_ignore_ascii_case("ibm437") || l.eq_ignore_ascii_case("cp437") || l == "437" {
            return Some(NameEncoding::Cp437);
        }
        let e = Encoding::for_label(l.as_bytes())?;
        // A name is never decoded as a replacement or UTF-16 "encoding".
        if e == encoding_rs::REPLACEMENT || e == encoding_rs::UTF_16LE || e == encoding_rs::UTF_16BE
        {
            return None;
        }
        Some(if e == encoding_rs::UTF_8 {
            NameEncoding::Utf8
        } else {
            NameEncoding::Legacy(e)
        })
    }
}

/// Guesses the encoding of the names an archive stores without a UTF-8 flag.
/// `made_on_dos`: the archive says it was made on MS-DOS, Windows (NTFS or
/// VFAT) or OS/2, whose tools write the OEM code page, not the ANSI one.
///
/// UTF-8 when every name is valid UTF-8; otherwise chardetng's guess, mapped
/// to the OEM code page of the same script for DOS-made archives.
pub fn detect<'a>(names: impl IntoIterator<Item = &'a [u8]>, made_on_dos: bool) -> NameEncoding {
    // chardetng needs no more than this to decide, and a listing of a
    // million names stays cheap.
    const SAMPLE: usize = 1 << 20;
    let mut detector = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Deny);
    let mut all_utf8 = true;
    let mut any_non_ascii = false;
    let mut fed = 0usize;
    for name in names {
        if name.is_ascii() {
            continue;
        }
        any_non_ascii = true;
        if all_utf8 && std::str::from_utf8(name).is_err() {
            all_utf8 = false;
        }
        if fed < SAMPLE {
            let take = name.len().min(SAMPLE - fed);
            detector.feed(&name[..take], false);
            // Names are separate strings: a space keeps one's last bytes
            // from pairing with the next one's first.
            detector.feed(b" ", false);
            fed += take + 1;
        }
    }
    if !any_non_ascii || all_utf8 {
        return NameEncoding::Utf8;
    }
    detector.feed(b"", true);
    let guess = detector.guess(None, chardetng::Utf8Detection::Deny);
    if made_on_dos {
        if guess == encoding_rs::WINDOWS_1252 || guess == encoding_rs::ISO_8859_15 {
            return NameEncoding::Cp437;
        }
        if guess == encoding_rs::WINDOWS_1251
            || guess == encoding_rs::KOI8_R
            || guess == encoding_rs::KOI8_U
            || guess == encoding_rs::ISO_8859_5
            || guess == encoding_rs::IBM866
        {
            return NameEncoding::Legacy(encoding_rs::IBM866);
        }
    }
    NameEncoding::Legacy(guess)
}

/// One decoded piece of a name: a character, or bytes that don't decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Piece {
    Char(char),
    /// An undecodable byte. Its value is known for UTF-8 names; legacy
    /// decoders only say that something didn't decode (`None`).
    Bad(Option<u8>),
}

/// Decodes `raw` with `encoding`, calling `out` for each piece in order.
pub fn decode(raw: &[u8], encoding: NameEncoding, mut out: impl FnMut(Piece)) {
    match encoding {
        NameEncoding::Utf8 => {
            for chunk in raw.utf8_chunks() {
                chunk.valid().chars().for_each(|c| out(Piece::Char(c)));
                chunk
                    .invalid()
                    .iter()
                    .for_each(|&b| out(Piece::Bad(Some(b))));
            }
        }
        NameEncoding::Cp437 => {
            for &b in raw {
                out(Piece::Char(if b < 0x80 {
                    b as char
                } else {
                    CP437_HIGH[(b - 0x80) as usize]
                }));
            }
        }
        NameEncoding::Legacy(e) => {
            let (text, _) = e.decode_without_bom_handling(raw);
            for c in text.chars() {
                out(if c == char::REPLACEMENT_CHARACTER {
                    Piece::Bad(None)
                } else {
                    Piece::Char(c)
                });
            }
        }
    }
}

/// C0 and C1 controls, DEL, and the line and paragraph separators: anything
/// that breaks a line of text or does something instead of showing.
pub fn is_control(c: char) -> bool {
    matches!(c, '\0'..='\x1f' | '\x7f'..='\u{9f}' | '\u{2028}' | '\u{2029}')
}

/// The characters that change the order text is shown in: the bidi
/// embeddings, overrides, isolates and marks. A name holding U+202E can
/// show "photo\u{202E}gpj.exe" as "photoexe.jpg".
pub fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Characters that show as nothing, or as blank: zero-width spaces and
/// joiners, the soft hyphen, Hangul and Braille blanks, variation selectors,
/// tag characters, the BOM, interlinear annotations, invisible operators.
/// `invoice.pdf` and `invoice.pdf\u{200B}` would look the same.
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'..='\u{2065}'
            | '\u{206A}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Is `p` a character outside ASCII (where joiners and selectors do work)?
fn non_ascii(p: Option<&Piece>) -> bool {
    matches!(p, Some(&Piece::Char(c)) if !c.is_ascii())
}

/// The subdivision flags that exist (England, Scotland, Wales): the only
/// tag sequences kept, so no other text can hide in tag characters.
const SUBDIVISION_FLAGS: [&str; 3] = ["gbeng", "gbsct", "gbwls"];

/// The length of a well-formed tag flag starting at `i` (U+1F3F4, the tag
/// letters of one of `SUBDIVISION_FLAGS`, U+E007F), or 0.
fn tag_flag(pieces: &[Piece], i: usize) -> usize {
    if pieces.get(i) != Some(&Piece::Char('\u{1F3F4}')) {
        return 0;
    }
    let tags: String = pieces[i + 1..]
        .iter()
        .map_while(|p| match p {
            // A tag letter or digit is its ASCII character plus 0xE0000.
            Piece::Char(c @ ('\u{E0030}'..='\u{E0039}' | '\u{E0061}'..='\u{E007A}')) => {
                char::from_u32(*c as u32 - 0xE0000)
            }
            _ => None,
        })
        .take(8)
        .collect();
    let ends = pieces.get(i + 1 + tags.len()) == Some(&Piece::Char('\u{E007F}'));
    if ends && SUBDIVISION_FLAGS.contains(&tags.as_str()) {
        tags.len() + 2
    } else {
        0
    }
}

/// Is `p` a character that shows as something (not a space, control, bidi
/// or invisible character, nor an undecodable byte)?
fn visible(p: Option<&Piece>) -> bool {
    matches!(p, Some(&Piece::Char(c)) if !c.is_whitespace() && !is_control(c) && !is_bidi_control(c) && !is_invisible(c))
}

/// The display form of one name, and whether it held anything unusual,
/// which the window marks. Nothing can hide or reorder text:
///
/// - controls and undecodable bytes become `\xNN` (`\x??` for a byte a
///   legacy decoder rejected), and a literal `\` becomes `\\`, so the
///   escapes can't be faked;
/// - bidi characters and invisible ones become `<U+202E>`; joiners are kept
///   between two visible characters when one is outside ASCII (emoji,
///   Persian), variation selectors after a character outside ASCII, and tag
///   characters only inside a well-formed tag flag;
/// - spaces other than U+0020 become `<U+XXXX>` unless alone between two
///   visible characters;
/// - a name that starts or ends with a space, holds two in a row, or holds
///   `<U+` is marked unusual.
pub fn display(pieces: &[Piece]) -> (String, bool) {
    let mut s = String::with_capacity(pieces.len());
    let mut unusual = false;
    let mut flag_until = 0;
    for (i, &p) in pieces.iter().enumerate() {
        if i >= flag_until {
            flag_until = i + tag_flag(pieces, i);
        }
        let before = i.checked_sub(1).and_then(|j| pieces.get(j));
        let after = pieces.get(i + 1);
        match p {
            Piece::Char(c) if is_control(c) && (c as u32) <= 0xff => {
                unusual = true;
                let _ = write!(s, "\\x{:02X}", c as u32);
            }
            Piece::Char('\\') => s.push_str("\\\\"),
            Piece::Char(c @ ('\u{200C}' | '\u{200D}'))
                if visible(before) && visible(after) && (non_ascii(before) || non_ascii(after)) =>
            {
                s.push(c)
            }
            Piece::Char(c @ '\u{FE00}'..='\u{FE0F}') if visible(before) && non_ascii(before) => {
                s.push(c)
            }
            Piece::Char(c @ '\u{E0020}'..='\u{E007F}') if i < flag_until => s.push(c),
            Piece::Char(c) if is_control(c) || is_bidi_control(c) || is_invisible(c) => {
                unusual = true;
                let _ = write!(s, "<U+{:04X}>", c as u32);
            }
            Piece::Char(c)
                if c.is_whitespace() && c != ' ' && !(visible(before) && visible(after)) =>
            {
                unusual = true;
                let _ = write!(s, "<U+{:04X}>", c as u32);
            }
            Piece::Char(c) => s.push(c),
            Piece::Bad(Some(b)) => {
                unusual = true;
                let _ = write!(s, "\\x{b:02X}");
            }
            Piece::Bad(None) => {
                unusual = true;
                s.push_str("\\x??");
            }
        }
    }
    let spaces = |p: Option<&Piece>| matches!(p, Some(Piece::Char(c)) if c.is_whitespace());
    if spaces(pieces.first())
        || spaces(pieces.last())
        || pieces
            .windows(2)
            .any(|w| spaces(w.first()) && spaces(w.get(1)))
        || s.contains("<U+") && !unusual
    {
        unusual = true;
    }
    (s, unusual)
}

/// Free text from an archive or the worker (a comment, an error message)
/// made safe to show, as `display` does for names. Line breaks are kept.
pub fn display_text(text: &str) -> String {
    text.split('\n')
        .map(|line| display(&line.chars().map(Piece::Char).collect::<Vec<_>>()).0)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The disk form of one name (never `/`: `path` split on it already), and
/// whether it differs from what the archive holds. Controls and undecodable
/// bytes become `_`, bidi characters are removed; an empty result, `.` or
/// `..` gets a `_` in front; a name over 255 bytes is shortened, keeping its
/// extension, with a hash of the whole name so two long names stay apart.
pub fn disk(pieces: &[Piece]) -> (String, bool) {
    let mut s = String::with_capacity(pieces.len());
    let mut changed = false;
    for &p in pieces {
        match p {
            Piece::Char(c) if is_bidi_control(c) => changed = true,
            Piece::Char(c) if is_control(c) || c == '/' => {
                changed = true;
                s.push('_');
            }
            Piece::Char(c) => s.push(c),
            Piece::Bad(_) => {
                changed = true;
                s.push('_');
            }
        }
    }
    if s.is_empty() || s == "." || s == ".." {
        s.insert(0, '_');
        changed = true;
    }
    if s.len() > MAX_COMPONENT_BYTES {
        s = shorten(&s);
        changed = true;
    }
    (s, changed)
}

/// A name the desktop treats as a launcher when it is executable
/// (`.desktop`, `.directory`, `.kdelnk`, in any case). Extracted launchers
/// never keep their execute bits, so a click opens them as text instead of
/// running what they name.
pub fn is_launcher(name: &str) -> bool {
    let lower = name
        .as_bytes()
        .rsplit(|&b| b == b'.')
        .next()
        .map(<[u8]>::to_ascii_lowercase);
    name.contains('.')
        && matches!(
            lower.as_deref(),
            Some(b"desktop" | b"directory" | b"kdelnk")
        )
}

/// `name` with a number added before its extension, the way Keep Both
/// names a copy: "photo.jpg", 2 gives "photo (2).jpg". Shortened again if
/// that passes 255 bytes. Works on display and disk forms alike.
pub fn numbered(name: &str, n: u32) -> String {
    let ext = match name.rfind('.') {
        Some(i) if i > 0 => &name[i..],
        _ => "",
    };
    let out = format!("{} ({n}){ext}", &name[..name.len() - ext.len()]);
    if out.len() > MAX_COMPONENT_BYTES {
        shorten(&out)
    } else {
        out
    }
}

/// Shortens a name to at most 255 bytes: `<start>~<hash><extension>`, the
/// extension (the last `.` and what follows, up to 32 bytes) kept, the start
/// cut on a character boundary, the hash (FNV-1a, 64 bits) over the whole
/// name.
fn shorten(name: &str) -> String {
    let ext = match name.rfind('.') {
        Some(i) if i > 0 && name.len() - i <= 32 => &name[i..],
        _ => "",
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name.as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let tag = format!("~{hash:016x}");
    let room = MAX_COMPONENT_BYTES - ext.len() - tag.len();
    let stem = &name[..name.len() - ext.len()];
    let mut cut = room.min(stem.len());
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{tag}{ext}", &stem[..cut])
}

/// Code page 437, bytes 0x80 to 0xFF (from Python's cp437 codec).
const CP437_HIGH: [char; 128] = [
    '\u{00c7}', '\u{00fc}', '\u{00e9}', '\u{00e2}', '\u{00e4}', '\u{00e0}', '\u{00e5}', '\u{00e7}',
    '\u{00ea}', '\u{00eb}', '\u{00e8}', '\u{00ef}', '\u{00ee}', '\u{00ec}', '\u{00c4}', '\u{00c5}',
    '\u{00c9}', '\u{00e6}', '\u{00c6}', '\u{00f4}', '\u{00f6}', '\u{00f2}', '\u{00fb}', '\u{00f9}',
    '\u{00ff}', '\u{00d6}', '\u{00dc}', '\u{00a2}', '\u{00a3}', '\u{00a5}', '\u{20a7}', '\u{0192}',
    '\u{00e1}', '\u{00ed}', '\u{00f3}', '\u{00fa}', '\u{00f1}', '\u{00d1}', '\u{00aa}', '\u{00ba}',
    '\u{00bf}', '\u{2310}', '\u{00ac}', '\u{00bd}', '\u{00bc}', '\u{00a1}', '\u{00ab}', '\u{00bb}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255d}', '\u{255c}', '\u{255b}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252c}', '\u{251c}', '\u{2500}', '\u{253c}', '\u{255e}', '\u{255f}',
    '\u{255a}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256c}', '\u{2567}',
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256b}',
    '\u{256a}', '\u{2518}', '\u{250c}', '\u{2588}', '\u{2584}', '\u{258c}', '\u{2590}', '\u{2580}',
    '\u{03b1}', '\u{00df}', '\u{0393}', '\u{03c0}', '\u{03a3}', '\u{03c3}', '\u{00b5}', '\u{03c4}',
    '\u{03a6}', '\u{0398}', '\u{03a9}', '\u{03b4}', '\u{221e}', '\u{03c6}', '\u{03b5}', '\u{2229}',
    '\u{2261}', '\u{00b1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00f7}', '\u{2248}',
    '\u{00b0}', '\u{2219}', '\u{00b7}', '\u{221a}', '\u{207f}', '\u{00b2}', '\u{25a0}', '\u{00a0}',
];

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(raw: &[u8], e: NameEncoding) -> Vec<Piece> {
        let mut v = Vec::new();
        decode(raw, e, |p| v.push(p));
        v
    }

    fn both(raw: &[u8], e: NameEncoding) -> ((String, bool), (String, bool)) {
        let p = pieces(raw, e);
        (display(&p), disk(&p))
    }

    fn show(name: &str) -> (String, bool) {
        display(&name.chars().map(Piece::Char).collect::<Vec<_>>())
    }

    #[test]
    fn invisible_characters_are_shown() {
        assert_eq!(
            show("invoice.pdf\u{200B}"),
            ("invoice.pdf<U+200B>".into(), true)
        );
        assert_eq!(
            show("\u{3164}\u{3164}.exe"),
            ("<U+3164><U+3164>.exe".into(), true)
        );
        assert_eq!(show("a\u{FEFF}b").0, "a<U+FEFF>b");
        assert_eq!(show("\u{200D}x").0, "<U+200D>x");
        // Joiners and variation selectors that join something stay.
        assert_eq!(show("👩\u{200D}💻.png"), ("👩\u{200D}💻.png".into(), false));
        assert_eq!(show("❤\u{FE0F}.txt"), ("❤\u{FE0F}.txt".into(), false));
        assert_eq!(show("می\u{200C}خواهم.txt").1, false);
        // ...but not between ASCII, where they only hide.
        assert_eq!(
            show("invoice\u{200D}.pdf"),
            ("invoice<U+200D>.pdf".into(), true)
        );
        assert_eq!(
            show("invoice.pdf\u{FE0F}"),
            ("invoice.pdf<U+FE0F>".into(), true)
        );
        assert_eq!(show("a\u{206A}b"), ("a<U+206A>b".into(), true));
        // Tags only as a flag: England stays, a hidden message doesn't.
        let england = "🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}.png";
        assert_eq!(show(england), (england.into(), false));
        let hidden = format!("🏴{}.png", "\u{E0068}".repeat(40));
        assert!(show(&hidden).1);
        assert!(show(&hidden).0.contains("<U+E0068>"));
        let wales = "🏴\u{E0067}\u{E0062}\u{E0077}\u{E006C}\u{E0073}\u{E007F}";
        assert_eq!(show(wales), (wales.into(), false));
        let scotland = "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        assert_eq!(show(scotland), (scotland.into(), false));
        // Well-formed tags that spell no real subdivision hide text too.
        let word = "🏴\u{E0068}\u{E0069}\u{E0064}\u{E0065}\u{E007F}";
        assert!(show(word).1 && show(word).0.contains("<U+E0068>"), "hide");
        assert!(show("🏴\u{E0067}\u{E0062}.png").1, "no cancel tag");
        assert!(show("x\u{E0067}\u{E0062}\u{E007F}").1, "no flag");
        assert!(
            show("🏴\u{E0048}\u{E0049}\u{E0021}\u{E007F}").1,
            "tags outside a-z and 0-9 hide text"
        );
    }

    #[test]
    fn spaces_are_shown_or_marked() {
        assert_eq!(show("a\u{00A0}b"), ("a\u{00A0}b".into(), false));
        assert_eq!(
            show("\u{2003}\u{2003}.exe"),
            ("<U+2003><U+2003>.exe".into(), true)
        );
        assert!(show("invoice.pdf ").1);
        assert!(show(" invoice.pdf").1);
        assert!(show(&format!("{}.exe", " ".repeat(200))).1);
        assert!(!show("two words.txt").1);
    }

    #[test]
    fn escapes_cannot_be_faked() {
        assert_eq!(show(r"a\x41").0, r"a\\x41");
        assert!(show("a<U+202E>b").1);
        assert_eq!(
            display_text("line one\nbad\u{202E}line"),
            "line one\nbad<U+202E>line"
        );
    }

    #[test]
    fn launchers() {
        for n in [
            "a.desktop",
            "A.DESKTOP",
            ".directory",
            "x.kdelnk",
            "a.b.Desktop",
        ] {
            assert!(is_launcher(n), "{n}");
        }
        for n in ["desktop", "a.desktop.txt", "a.desk", "adesktop"] {
            assert!(!is_launcher(n), "{n}");
        }
    }

    #[test]
    fn numbered_copies() {
        assert_eq!(numbered("photo.jpg", 2), "photo (2).jpg");
        assert_eq!(numbered("notes", 3), "notes (3)");
        assert_eq!(numbered(".bashrc", 2), ".bashrc (2)");
        assert_eq!(numbered("a.tar.gz", 2), "a.tar (2).gz");
        let long = format!("{}.txt", "x".repeat(251));
        let n = numbered(&long, 2);
        assert!(n.len() <= MAX_COMPONENT_BYTES && n.ends_with(".txt") && n != long);
    }

    #[test]
    fn plain_names_pass_unchanged() {
        for name in [
            "report.pdf",
            "Ünïcødé ✓.txt",
            "日本語.txt",
            "👨‍👩‍👧 family.jpg",
            "a b",
        ] {
            let ((shown, unusual), (on_disk, changed)) = both(name.as_bytes(), NameEncoding::Utf8);
            assert_eq!(shown, name);
            assert_eq!(on_disk, name);
            assert!(!unusual && !changed, "{name}");
        }
    }

    #[test]
    fn controls_are_escaped_and_replaced() {
        let ((shown, unusual), (on_disk, changed)) = both(b"a\nb\x1b[31m\x7f", NameEncoding::Utf8);
        assert_eq!(shown, "a\\x0Ab\\x1B[31m\\x7F");
        assert_eq!(on_disk, "a_b_[31m_");
        assert!(unusual && changed);
        let ((shown, _), (on_disk, _)) = both("x\u{85}y\u{2028}z".as_bytes(), NameEncoding::Utf8);
        assert_eq!(shown, "x\\x85y<U+2028>z");
        assert_eq!(on_disk, "x_y_z");
    }

    #[test]
    fn bidi_overrides_are_shown_and_removed() {
        let raw = "photo\u{202e}gpj.exe".as_bytes();
        let ((shown, unusual), (on_disk, changed)) = both(raw, NameEncoding::Utf8);
        assert_eq!(shown, "photo<U+202E>gpj.exe");
        assert_eq!(on_disk, "photogpj.exe");
        assert!(unusual && changed);
        for c in [
            '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{2066}', '\u{2069}',
        ] {
            let (on_disk, _) = disk(&[Piece::Char('a'), Piece::Char(c), Piece::Char('b')]);
            assert_eq!(on_disk, "ab");
        }
    }

    #[test]
    fn removing_bidi_never_leaves_dot_or_dotdot() {
        for raw in ["\u{202e}..", ".\u{202e}.", "\u{2066}.", "\u{200f}"] {
            let (on_disk, changed) = disk(&pieces(raw.as_bytes(), NameEncoding::Utf8));
            assert!(changed);
            assert!(
                on_disk != "." && on_disk != ".." && !on_disk.is_empty(),
                "{raw:?} -> {on_disk:?}"
            );
        }
    }

    #[test]
    fn invalid_utf8_is_visible_and_replaced() {
        let ((shown, unusual), (on_disk, changed)) = both(b"caf\xe9\xff.txt", NameEncoding::Utf8);
        assert_eq!(shown, "caf\\xE9\\xFF.txt");
        assert_eq!(on_disk, "caf__.txt");
        assert!(unusual && changed);
    }

    #[test]
    fn cp437_and_legacy_decode() {
        let ((shown, unusual), _) = both(b"R\x82sum\x82.txt", NameEncoding::Cp437);
        assert_eq!(shown, "Résumé.txt");
        assert!(!unusual);
        // Every byte decodes in CP437, and the table matches Python's.
        assert_eq!(
            pieces(&[0xff], NameEncoding::Cp437),
            [Piece::Char('\u{a0}')]
        );
        let sjis = NameEncoding::from_label("Shift_JIS").unwrap();
        let ((shown, _), _) = both(b"\x83\x5c\x83\x74\x83\x67.txt", sjis);
        assert_eq!(shown, "ソフト.txt");
        // A truncated double-byte character.
        let ((shown, unusual), (on_disk, _)) = both(b"a\x83", sjis);
        assert_eq!(shown, "a\\x??");
        assert_eq!(on_disk, "a_");
        assert!(unusual);
    }

    #[test]
    fn labels_round_trip() {
        for &label in CHOICES {
            let e = NameEncoding::from_label(label).unwrap_or_else(|| panic!("{label}"));
            assert_eq!(NameEncoding::from_label(e.label()), Some(e), "{label}");
        }
        assert_eq!(NameEncoding::from_label("cp437"), Some(NameEncoding::Cp437));
        assert_eq!(NameEncoding::from_label("utf-16le"), None);
        assert_eq!(NameEncoding::from_label("replacement"), None);
        assert_eq!(NameEncoding::from_label("nonsense"), None);
    }

    #[test]
    fn long_names_are_shortened_uniquely() {
        let long_a = format!("{}.tar.gz", "a".repeat(300));
        let long_b = format!("{}b.tar.gz", "a".repeat(299));
        let (a, changed) = disk(&pieces(long_a.as_bytes(), NameEncoding::Utf8));
        let (b, _) = disk(&pieces(long_b.as_bytes(), NameEncoding::Utf8));
        assert!(changed);
        assert!(a.len() <= MAX_COMPONENT_BYTES && b.len() <= MAX_COMPONENT_BYTES);
        assert!(a.ends_with(".gz") && b.ends_with(".gz"));
        assert_ne!(a, b);
        // Multi-byte characters are cut on a boundary.
        let wide = "日".repeat(120);
        let (w, _) = disk(&pieces(wide.as_bytes(), NameEncoding::Utf8));
        assert!(w.len() <= MAX_COMPONENT_BYTES);
        // A name of exactly 255 bytes is kept.
        let exact = "x".repeat(255);
        assert_eq!(
            disk(&pieces(exact.as_bytes(), NameEncoding::Utf8)),
            (exact, false)
        );
    }

    #[test]
    fn detection() {
        let utf8: Vec<&[u8]> = vec![b"plain.txt", "café.txt".as_bytes()];
        assert_eq!(detect(utf8, true), NameEncoding::Utf8);
        let ascii: Vec<&[u8]> = vec![b"a.txt", b"b/c.txt"];
        assert_eq!(detect(ascii, false), NameEncoding::Utf8);
        // Western names from Windows' zip: CP437.
        let dos: Vec<&[u8]> = vec![b"R\x82sum\x82.doc", b"Pr\x82sentation.ppt", b"Caf\x82.txt"];
        assert_eq!(detect(dos, true), NameEncoding::Cp437);
        // Japanese names in Shift_JIS.
        let sjis: Vec<&[u8]> = vec![
            b"\x83\x5c\x83\x74\x83\x67\x83\x45\x83\x46\x83\x41.txt",
            b"\x93\xfa\x96\x7b\x8c\xea\x82\xcc\x83\x74\x83\x40\x83\x43\x83\x8b.doc",
        ];
        assert_eq!(
            detect(sjis, true),
            NameEncoding::Legacy(encoding_rs::SHIFT_JIS)
        );
    }
}
