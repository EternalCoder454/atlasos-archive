# Telamon Archive for Telamon OS.

# No debuginfo subpackage: the Rust flags below keep symbols (debuginfo=2,
# strip=none) and the binary is shipped as built.
%global debug_package %{nil}

# --define "_telamon_build_cache <dir>" (packaging/build-rpm.sh passes it when
# TELAMON_BUILD_CACHE is set) keeps the CMake build, Corrosion's cargo target
# with it, in <dir>, so a rebuild only compiles what changed.
%if 0%{?_telamon_build_cache:1}
%global _vpath_builddir %{_telamon_build_cache}/cmake
%endif

Name:           telamon-archive
Version:        0.2.0
Release:        1%{?dist}
Summary:        Telamon Archive, the archive manager of Telamon OS
License:        MIT
URL:            https://github.com/EternalCoder454/atlasos-archive
# Atlas Archive until 0.2.0: an upgrade replaces it, and what asks for the
# old package name is still met.
Obsoletes:      atlas-archive < 0.2.0
Provides:       atlas-archive = %{version}-%{release}
Source0:        telamon-archive-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
# %%build_rustflags
BuildRequires:  rust-srpm-macros
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  cmake
BuildRequires:  ninja-build
BuildRequires:  corrosion
# Cargo fetches the atlas-framework crates from GitHub.
BuildRequires:  git-core
BuildRequires:  desktop-file-utils
BuildRequires:  libappstream-glib
BuildRequires:  cmake(Qt6Core)
BuildRequires:  cmake(Qt6Gui)
BuildRequires:  cmake(Qt6Qml)
BuildRequires:  cmake(Qt6Quick)
BuildRequires:  cmake(Qt6QuickControls2)
BuildRequires:  cmake(Qt6Widgets)
BuildRequires:  cmake(Qt6QmlTools)
BuildRequires:  qt6-qtbase-devel
# The worker's engine links libarchive (pkg-config).
BuildRequires:  pkgconfig(libarchive)
BuildRequires:  cmake(KF6CoreAddons)
BuildRequires:  cmake(KF6DBusAddons)
BuildRequires:  cmake(KF6WindowSystem)
# QML modules qmlcachegen resolves at build time (not linked). telamon-ui comes
# from atlas-framework, which is in no repository: install its RPMs first
# (build-rpm.sh does, given TELAMON_LOCAL_RPMS).
BuildRequires:  kf6-kirigami-devel
BuildRequires:  telamon-ui >= 2.0.0

Requires:       kf6-kirigami
# Telamon.Ui, the shared look (atlas-framework)
Requires:       telamon-ui >= 2.0.0
Requires:       kf6-qqc2-desktop-style
Requires:       qt6-qtdeclarative
# the app icon and Breeze's icons are SVG
Requires:       qt6-qtsvg
# 7z creation, encrypted 7z, 7z edits and spanned zips (docs/DESIGN.md)
Requires:       7zip

%description
Telamon Archive opens archives as folders you can browse, preview and drag
files out of, extracts them with one click and creates ZIP (with AES-256), 7z
and tar archives. It reads RAR, ISO, cab, cpio, deb and rpm files too. Every
archive is parsed in a sandboxed worker that can only write into the folder
being extracted to.

%prep
%autosetup -n telamon-archive-%{version}

%build
# NETWORK: cargo (Corrosion runs it with --locked) fetches crates.io and the
# pinned atlas-framework crates during %%build. That works in podman and with `rpmbuild`
# on a networked machine, not in an offline mock/Koji build.
# CARGO_HOME from the environment keeps a crate cache between builds
# (CLAUDE.md mounts one); otherwise a fresh one in the build dir.
export CARGO_HOME=${CARGO_HOME:-%{_builddir}/cargo-home}
# Fedora's Rust flags (hardening, build-id, ...), also used by Corrosion's cargo.
# The remaps keep build paths (panic locations, assert file names) out of the
# package, as atlas-framework's DESIGN.md asks of apps using its crates.
# HOST_CXXFLAGS reaches only the C++ that cargo's build scripts compile
# (cc-rs reads HOST_ when not cross-compiling; CMake ignores it), which
# otherwise gets no flags from here. (cc-rs then ignores a plain CXXFLAGS,
# which is only for CMake.)
# CFLAGS and CXXFLAGS are Fedora's plus the same remap for the C++ CMake
# builds (%%cmake keeps them when set). Without it the build dir, a random
# mktemp one, goes into the debug info and so into the linker's build ID,
# and two builds of one commit differ. These flags split on spaces, so
# _topdir must have none (build-rpm.sh's hasn't).
# A build cache (above) holds $PWD and the CMake build: its path is remapped too.
cache_rs="%{?_telamon_build_cache:--remap-path-prefix=%{_telamon_build_cache}=cache}"
cache_cc="%{?_telamon_build_cache:-ffile-prefix-map=%{_telamon_build_cache}=cache}"
# The last matching remap wins, and $PWD is inside the cache: the cache's
# comes first.
export RUSTFLAGS="%{build_rustflags} $cache_rs --remap-path-prefix=$PWD=. --remap-path-prefix=$CARGO_HOME=cargo"
export HOST_CXXFLAGS="$cache_cc -ffile-prefix-map=$PWD=. -ffile-prefix-map=$CARGO_HOME=cargo"
export CFLAGS="%{build_cflags} $cache_cc -ffile-prefix-map=$PWD=."
export CXXFLAGS="%{build_cxxflags} $cache_cc -ffile-prefix-map=$PWD=."
export CARGO_PROFILE_RELEASE_STRIP=none
# (checked with rpmspec --eval: %%cmake honours _vpath_srcdir, not __cmake_source_dir)
%global _vpath_srcdir apps/telamon-archive
%cmake -G Ninja -DCMAKE_BUILD_TYPE=Release
%cmake_build

%install
%cmake_install

%check
# No path into the build tree (checked as well as set: see %%build).
# grep: 0 = found, 1 = not found, anything else (no binary) fails too.
for bin in %{buildroot}%{_bindir}/telamon-archive %{buildroot}%{_bindir}/telamon-archive-cli \
    %{buildroot}%{_libexecdir}/telamon-archive/telamon-archive-worker; do
    for path in "%{_builddir}" %{?_telamon_build_cache:"%{_telamon_build_cache}"}; do
        rc=0
        grep -qF "$path" "$bin" || rc=$?
        if [ "$rc" != 1 ]; then
            echo "$bin holds the build path $path (grep status $rc)" >&2
            exit 1
        fi
    done
done
# The GUI and the CLI start the worker from this path (client::SYSTEM_WORKER).
for bin in %{buildroot}%{_bindir}/telamon-archive %{buildroot}%{_bindir}/telamon-archive-cli; do
    grep -qF "%{_libexecdir}/telamon-archive/telamon-archive-worker" "$bin" ||
        { echo "$bin doesn't start the installed worker" >&2; exit 1; }
done
# No test-only worker override in a shipped build (the dev-worker features).
for check in "%{buildroot}%{_bindir}/telamon-archive:TELAMON_ARCHIVE_WORKER" \
    "%{buildroot}%{_bindir}/telamon-archive-cli:TELAMON_ARCHIVE_TEST_FD_WAIT_MS"; do
    rc=0
    grep -qF "${check##*:}" "${check%%:*}" || rc=$?
    if [ "$rc" != 1 ]; then
        echo "${check%%:*} was built with the dev-worker feature (grep status $rc)" >&2
        exit 1
    fi
done
desktop-file-validate %{buildroot}%{_datadir}/applications/net.eterneon.telamon.archive.desktop
# What it was called until 0.2.0, kept for one release (data/legacy): the old
# names reach the same programs and the same MimeType list, and the old
# service menu adds no second set of actions.
desktop-file-validate %{buildroot}%{_datadir}/applications/net.eterneon.atlas.archive.desktop
[ "$(readlink %{buildroot}%{_bindir}/atlas-archive)" = telamon-archive ]
[ "$(readlink %{buildroot}%{_bindir}/atlas-archive-cli)" = telamon-archive-cli ]
[ "$(grep '^MimeType=' %{buildroot}%{_datadir}/applications/net.eterneon.atlas.archive.desktop)" = \
  "$(grep '^MimeType=' %{buildroot}%{_datadir}/applications/net.eterneon.telamon.archive.desktop)" ]
! grep -q '^Actions=' %{buildroot}%{_datadir}/kio/servicemenus/net.eterneon.atlas.archive.desktop
appstream-util validate-relax --nonet \
    %{buildroot}%{_datadir}/metainfo/net.eterneon.telamon.archive.metainfo.xml

%files
%license LICENSE
%{_bindir}/telamon-archive
%{_bindir}/telamon-archive-cli
%dir %{_libexecdir}/telamon-archive
%{_libexecdir}/telamon-archive/telamon-archive-worker
%{_datadir}/applications/net.eterneon.telamon.archive.desktop
%{_datadir}/kio/servicemenus/net.eterneon.telamon.archive.desktop
%{_datadir}/metainfo/net.eterneon.telamon.archive.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/net.eterneon.telamon.archive.svg
# Until 0.2.0's names, for one release (data/legacy)
%{_bindir}/atlas-archive
%{_bindir}/atlas-archive-cli
%{_datadir}/applications/net.eterneon.atlas.archive.desktop
%{_datadir}/kio/servicemenus/net.eterneon.atlas.archive.desktop

%changelog
* Wed Oct 07 2026 EternalHell <77252745+EternalCoder454@users.noreply.github.com> - 0.2.0-1
- Renamed to Telamon Archive (telamon-archive, net.eterneon.telamon.archive),
  on Telamon.Ui 2.0.0; replaces atlas-archive
- Settings and the job records of unfinished extractions move over by
  themselves; the old program, desktop file and D-Bus names keep working for
  this release

* Mon Oct 05 2026 Atlas <atlas@eterneon.net> - 0.1.0-1
- First package
