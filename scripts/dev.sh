#!/bin/bash
# Run a command in the fedora:44 build container, with the repo at /src, the
# build output at /work and the cargo and dnf caches in named podman volumes
# (shared with the other Telamon apps).
#   scripts/dev.sh <command...>     e.g. scripts/dev.sh cargo test --workspace
#   scripts/dev.sh                  an interactive shell
# /work is $TELAMON_ARCHIVE_WORK, by default ~/.cache/claude-builds/telamon-archive:
# on disk, outside the repo (cargo's target dirs, CMake build dirs, generated
# test archives, fuzz corpora). ATLAS_ARCHIVE_WORK and ATLAS_LOCAL_RPMS still
# work when the TELAMON_ one is not set. Set CARGO_TARGET_DIR to /work/target/<name>
# to keep one target dir per task.
# The first run installs the build dependencies from the spec (cached after).
# They include telamon-ui, which no repository has: that run needs
# TELAMON_LOCAL_RPMS=<dir> holding atlas-framework's RPMs (telamon-ui and
# telamon-symbols-fonts), one version only. Delete the image after changing the
# spec's BuildRequires or to take a newer telamon-ui.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=localhost/telamon-archive-dev:44
work=${TELAMON_ARCHIVE_WORK:-${ATLAS_ARCHIVE_WORK:-$HOME/.cache/claude-builds/telamon-archive}}
mkdir -p "$work"

if ! podman image exists "$image"; then
    rpms=${TELAMON_LOCAL_RPMS:-${ATLAS_LOCAL_RPMS:?the dev image needs atlas-framework RPMs: set TELAMON_LOCAL_RPMS=<dir>}}
    rpms=$(cd "$rpms" && pwd)
    # Only a dir of atlas-framework's RPMs, so a wrong value fails here
    # instead of halfway through the image build.
    if [ -n "$(find "$rpms" -mindepth 1 ! -name '*.rpm' -print -quit)" ] ||
        ! compgen -G "$rpms/telamon-ui-[0-9]*.rpm" >/dev/null; then
        echo "TELAMON_LOCAL_RPMS=$rpms must hold only atlas-framework's RPMs (telamon-ui-*.rpm and telamon-symbols-fonts-*.rpm)" >&2
        exit 1
    fi
    # No SELinux relabelling (:z/:Z) of host folders: it would lock other
    # containers and tools out of them. Labels are off for the container.
    # --init: `sleep infinity` as PID 1 ignores SIGTERM.
    ctr=$(podman run -d --init --security-opt label=disable \
        -v "$repo/packaging":/packaging:ro \
        -v "$rpms":/telamon-rpms:ro \
        -v telamon-dnf:/var/cache/libdnf5 \
        registry.fedoraproject.org/fedora:44 sleep infinity)
    trap 'podman rm -f "$ctr" >/dev/null' EXIT
    # 7zip is a run-time backend (and the reference for tests and benchmarks);
    # bsdtar and zip/unzip make and check test archives; strace checks that no
    # password reaches argv or the environment. unrar (RPM Fusion nonfree,
    # shipped in the Telamon OS image) is the encrypted-RAR backend.
    podman exec "$ctr" bash -c '
        echo keepcache=True >>/etc/dnf/dnf.conf
        dnf -y install dnf5-plugins rpm-build clippy rustfmt xorg-x11-server-Xvfb \
            dbus-daemon qt6-qtbase-gui kf6-qqc2-desktop-style breeze-icon-theme \
            ImageMagick xdotool 7zip bsdtar zip unzip strace \
            /telamon-rpms/telamon-ui-[0-9]*.rpm /telamon-rpms/telamon-symbols-fonts-[0-9]*.rpm &&
        dnf -y builddep /packaging/telamon-archive.spec &&
        bash /packaging/rpmfusion-nonfree.sh unrar' >&2
    podman commit "$ctr" "$image" >/dev/null
    podman rm -f "$ctr" >/dev/null
    trap - EXIT
fi

tty=()
[ -t 0 ] && tty=(-it)
exec podman run --rm --init "${tty[@]}" --security-opt label=disable \
    -v "$repo":/src -w /src \
    -v "$work":/work \
    -v telamon-cargo:/root/.cargo/registry \
    -v telamon-cargo-git:/root/.cargo/git \
    -e CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/work/target/dev}" \
    "$image" "${@:-bash}"
