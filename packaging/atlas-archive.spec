# Atlas Archive for AtlasOS.

# No debuginfo subpackage: the Rust flags below keep symbols (debuginfo=2,
# strip=none) and the binary is shipped as built.
%global debug_package %{nil}

# --define "_atlas_build_cache <dir>" (packaging/build-rpm.sh passes it when
# ATLAS_BUILD_CACHE is set) keeps the CMake build, Corrosion's cargo target
# with it, in <dir>, so a rebuild only compiles what changed.
%if 0%{?_atlas_build_cache:1}
%global _vpath_builddir %{_atlas_build_cache}/cmake
%endif

Name:           atlas-archive
Version:        0.1.0
Release:        1%{?dist}
Summary:        Atlas Archive, the archive manager of AtlasOS
License:        MIT
URL:            https://github.com/EternalCoder454/atlasos-archive
Source0:        atlas-archive-%{version}.tar.gz

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
# (build-rpm.sh does, given ATLAS_LOCAL_RPMS).
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
Atlas Archive opens archives as folders you can browse, preview and drag
files out of, extracts them with one click and creates ZIP (with AES-256), 7z
and tar archives. It reads RAR, ISO, cab, cpio, deb and rpm files too. Every
archive is parsed in a sandboxed worker that can only write into the folder
being extracted to.

%prep
%autosetup -n atlas-archive-%{version}

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
cache_rs="%{?_atlas_build_cache:--remap-path-prefix=%{_atlas_build_cache}=cache}"
cache_cc="%{?_atlas_build_cache:-ffile-prefix-map=%{_atlas_build_cache}=cache}"
# The last matching remap wins, and $PWD is inside the cache: the cache's
# comes first.
export RUSTFLAGS="%{build_rustflags} $cache_rs --remap-path-prefix=$PWD=. --remap-path-prefix=$CARGO_HOME=cargo"
export HOST_CXXFLAGS="$cache_cc -ffile-prefix-map=$PWD=. -ffile-prefix-map=$CARGO_HOME=cargo"
export CFLAGS="%{build_cflags} $cache_cc -ffile-prefix-map=$PWD=."
export CXXFLAGS="%{build_cxxflags} $cache_cc -ffile-prefix-map=$PWD=."
export CARGO_PROFILE_RELEASE_STRIP=none
# (checked with rpmspec --eval: %%cmake honours _vpath_srcdir, not __cmake_source_dir)
%global _vpath_srcdir apps/atlas-archive
%cmake -G Ninja -DCMAKE_BUILD_TYPE=Release
%cmake_build

%install
%cmake_install

%check
# No path into the build tree (checked as well as set: see %%build).
# grep: 0 = found, 1 = not found, anything else (no binary) fails too.
for bin in %{buildroot}%{_bindir}/atlas-archive %{buildroot}%{_bindir}/atlas-archive-cli \
    %{buildroot}%{_libexecdir}/atlas-archive/atlas-archive-worker; do
    for path in "%{_builddir}" %{?_atlas_build_cache:"%{_atlas_build_cache}"}; do
        rc=0
        grep -qF "$path" "$bin" || rc=$?
        if [ "$rc" != 1 ]; then
            echo "$bin holds the build path $path (grep status $rc)" >&2
            exit 1
        fi
    done
done
# The GUI and the CLI start the worker from this path (client::SYSTEM_WORKER).
for bin in %{buildroot}%{_bindir}/atlas-archive %{buildroot}%{_bindir}/atlas-archive-cli; do
    grep -qF "%{_libexecdir}/atlas-archive/atlas-archive-worker" "$bin" ||
        { echo "$bin doesn't start the installed worker" >&2; exit 1; }
done
# No test-only worker override in a shipped build (the dev-worker features).
for check in "%{buildroot}%{_bindir}/atlas-archive:ATLAS_ARCHIVE_WORKER" \
    "%{buildroot}%{_bindir}/atlas-archive-cli:ATLAS_ARCHIVE_TEST_FD_WAIT_MS"; do
    rc=0
    grep -qF "${check##*:}" "${check%%:*}" || rc=$?
    if [ "$rc" != 1 ]; then
        echo "${check%%:*} was built with the dev-worker feature (grep status $rc)" >&2
        exit 1
    fi
done
desktop-file-validate %{buildroot}%{_datadir}/applications/net.eterneon.atlas.archive.desktop
appstream-util validate-relax --nonet \
    %{buildroot}%{_datadir}/metainfo/net.eterneon.atlas.archive.metainfo.xml

%files
%license LICENSE
%{_bindir}/atlas-archive
%{_bindir}/atlas-archive-cli
%dir %{_libexecdir}/atlas-archive
%{_libexecdir}/atlas-archive/atlas-archive-worker
%{_datadir}/applications/net.eterneon.atlas.archive.desktop
%{_datadir}/kio/servicemenus/net.eterneon.atlas.archive.desktop
%{_datadir}/metainfo/net.eterneon.atlas.archive.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/net.eterneon.atlas.archive.svg

%changelog
* Mon Oct 05 2026 Atlas <atlas@eterneon.net> - 0.1.0-1
- First package
