#!/bin/bash
# Build the Atlas Archive RPM inside a fedora:44 container, as root.
#   packaging/build-rpm.sh <out dir> [rpmbuild options]
# The binary RPM (no source, no debuginfo) is copied to <out dir>.
# Cargo needs network access.
# ATLAS_LOCAL_RPMS=<dir> installs the RPMs in <dir> first: atlas-framework's
# (telamon-ui), which the app builds against and no repository has.
set -euo pipefail

main() {
    out=${1:?usage: build-rpm.sh <out dir> [rpmbuild options]}
    shift

    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    src=$(dirname "$here")
    spec=$here/atlas-archive.spec
    version=$(awk '/^Version:/ {print $2; exit}' "$spec")

    # ATLAS_LOCAL_RPMS goes to it in the environment.
    bash "$here/install-builddeps.sh"

    # ATLAS_BUILD_CACHE=<dir> keeps the CMake build (Corrosion's cargo target
    # in it) in <dir>, at a fixed path, so a rebuild only compiles what
    # changed (CI caches it). It starts over when the version or the
    # toolchain changes. Without it, every build is a clean one in a temp dir.
    rpmopts=()
    cache=${ATLAS_BUILD_CACHE:-}
    if [ -n "$cache" ]; then
        mkdir -p "$cache"
        cache=$(cd "$cache" && pwd -P)
        case $cache/ in
            "$(cd "$src" && pwd -P)"/*) echo "ATLAS_BUILD_CACHE must be outside the source tree" >&2; exit 1 ;;
        esac
        # It goes into the build flags (split on spaces) and the spec's shell.
        if [[ ! $cache =~ ^[A-Za-z0-9_./-]+$ ]]; then
            echo "ATLAS_BUILD_CACHE may hold only letters, digits and _ . / -" >&2; exit 1
        fi
        # Only a directory this script made (or an empty one): it deletes
        # rpmbuild/ and cmake/ in it.
        if [ ! -e "$cache/.atlas-archive-build-cache" ] && [ -n "$(ls -A "$cache")" ]; then
            echo "ATLAS_BUILD_CACHE ($cache) is not empty and is not an Atlas Archive build cache" >&2; exit 1
        fi
        touch "$cache/.atlas-archive-build-cache"
        top=$cache/rpmbuild
        rm -rf "$top"
        toolchain=$(rpm -q rust cargo corrosion gcc-c++ cmake qt6-qtbase-devel qt6-qtdeclarative-devel \
            kf6-kirigami-devel telamon-ui || true)
        toolchain="atlas-archive-$version
$toolchain"
        if [ "$(cat "$cache/toolchain" 2>/dev/null)" != "$toolchain" ]; then
            rm -rf "$cache/cmake"
            printf '%s\n' "$toolchain" >"$cache/toolchain"
        fi
        rpmopts+=(--define "_atlas_build_cache $cache")
    else
        top=$(mktemp -d)
    fi
    trap 'rm -rf "$top"' EXIT
    mkdir -p "$top"/{SOURCES,BUILD,RPMS,SRPMS,SPECS}
    tar -C "$src" \
        --exclude=./.git --exclude=./target --exclude=./out --exclude=./build \
        --transform "s,^\./,atlas-archive-$version/," \
        -czf "$top/SOURCES/atlas-archive-$version.tar.gz" .

    rpmbuild -bb "${rpmopts[@]}" "$@" --define "_topdir $top" "$spec"

    mkdir -p "$out"
    find "$top/RPMS" -name '*.rpm' ! -name '*.src.rpm' ! -name '*debuginfo*' ! -name '*debugsource*' \
        -exec cp -v {} "$out"/ \;
}

main "$@"
exit $?
