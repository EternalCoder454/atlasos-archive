//! What the worker can create (docs/DESIGN.md, "The API other apps call"):
//! the formats, the levels and the names a new archive gets.

/// The formats `Compress` makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressFormat {
    Zip,
    SevenZip,
    TarGz,
    TarXz,
    TarZst,
}

impl CompressFormat {
    pub const ALL: [CompressFormat; 5] = [
        CompressFormat::Zip,
        CompressFormat::SevenZip,
        CompressFormat::TarGz,
        CompressFormat::TarXz,
        CompressFormat::TarZst,
    ];

    /// The name the D-Bus API and the protocol use.
    pub fn label(self) -> &'static str {
        match self {
            CompressFormat::Zip => "zip",
            CompressFormat::SevenZip => "7z",
            CompressFormat::TarGz => "tar.gz",
            CompressFormat::TarXz => "tar.xz",
            CompressFormat::TarZst => "tar.zst",
        }
    }

    pub fn from_label(label: &str) -> Option<CompressFormat> {
        CompressFormat::ALL.into_iter().find(|f| f.label() == label)
    }

    /// The file name extension, with its dot.
    pub fn extension(self) -> &'static str {
        match self {
            CompressFormat::Zip => ".zip",
            CompressFormat::SevenZip => ".7z",
            CompressFormat::TarGz => ".tar.gz",
            CompressFormat::TarXz => ".tar.xz",
            CompressFormat::TarZst => ".tar.zst",
        }
    }

    /// For the job's title: "ZIP", "7z", "TAR.GZ"...
    pub fn shown(self) -> &'static str {
        match self {
            CompressFormat::Zip => "ZIP",
            CompressFormat::SevenZip => "7z",
            CompressFormat::TarGz => "TAR.GZ",
            CompressFormat::TarXz => "TAR.XZ",
            CompressFormat::TarZst => "TAR.ZST",
        }
    }
}

/// How hard to compress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// No compression (not for the tar formats' filters: the lowest level).
    Store,
    Fast,
    Normal,
    Best,
}

impl Level {
    pub fn tag(self) -> u8 {
        match self {
            Level::Store => 0,
            Level::Fast => 1,
            Level::Normal => 2,
            Level::Best => 3,
        }
    }

    pub fn from_tag(t: u8) -> Option<Level> {
        Some(match t {
            0 => Level::Store,
            1 => Level::Fast,
            2 => Level::Normal,
            3 => Level::Best,
            _ => return None,
        })
    }

    pub fn from_label(label: &str) -> Option<Level> {
        Some(match label {
            "store" => Level::Store,
            "fast" => Level::Fast,
            "normal" => Level::Normal,
            "best" => Level::Best,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_round_trip() {
        for f in CompressFormat::ALL {
            assert_eq!(CompressFormat::from_label(f.label()), Some(f));
            assert!(f.extension().starts_with('.'));
        }
        assert_eq!(CompressFormat::from_label("rar"), None);
        assert_eq!(CompressFormat::from_label("ZIP"), None);
        for t in 0..4 {
            assert_eq!(Level::from_tag(t).map(Level::tag), Some(t));
        }
        assert_eq!(Level::from_tag(4), None);
    }
}
