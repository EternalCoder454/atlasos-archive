# Telamon Archive

The archive manager of [Telamon OS](https://github.com/EternalCoder454/AtlasOS).
It replaces KDE Ark.

- Double-click an archive to browse it like a folder, preview what's inside
  and drag files out.
- **Extract All** asks once where to put the files. By default they go into a
  folder named after the archive, next to it.
- Explorer gets **Extract Here**, **Extract to name/**, **Compress to ZIP** and
  **Compress…**, which offers format, level, password and split size.
- Reads and writes ZIP (with AES-256), 7z and tar (gz, bz2, xz, zstd, lz4).
  Reads RAR, ISO, cab, cpio, deb and rpm. Handles split volumes and nested
  archives.

Every archive is parsed in a sandboxed worker process (Landlock, no new
privileges) that can only write into the folder being extracted to. Entry
paths, links and names are checked before anything reaches the disk, and
archives built to fill a disk are caught first.

How it is built: [docs/DESIGN.md](docs/DESIGN.md). Licence: MIT.
