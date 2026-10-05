#!/bin/bash
# Install packages from RPM Fusion nonfree (unrar, which the AtlasOS image
# ships for encrypted RAR) in a Fedora container, as root.
#   packaging/rpmfusion-nonfree.sh <package...>
# Does nothing when they are all installed. Otherwise it adds the repo the
# way the AtlasOS image does (build_files/packages.sh there): dnf doesn't
# check the signature of a package given by URL, so the release package is
# checked against RPM Fusion's key from Fedora's distribution-gpg-keys, in a
# private rpm database holding only that key; the repo key it then adds is
# RPM Fusion's.
set -euo pipefail

main() {
    [ $# -gt 0 ] || { echo "usage: rpmfusion-nonfree.sh <package...>" >&2; exit 2; }
    if rpm -q -- "$@" >/dev/null 2>&1; then
        return 0
    fi
    if ! rpm -q rpmfusion-nonfree-release >/dev/null 2>&1; then
        fedora=$(rpm -E %fedora)
        rpm -q distribution-gpg-keys curl >/dev/null 2>&1 || dnf -y install distribution-gpg-keys curl >&2
        key=/usr/share/distribution-gpg-keys/rpmfusion/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$fedora
        tmp=$(mktemp -d)
        trap 'rm -rf "$tmp"' EXIT
        curl -fsSL --retry 5 --retry-all-errors --proto '=https' --tlsv1.2 -o "$tmp/nonfree.rpm" \
            "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$fedora.noarch.rpm"
        mkdir "$tmp/db"
        rpmkeys --define "_dbpath $tmp/db" --import "$key"
        if ! rpmkeys --define "_dbpath $tmp/db" --checksig "$tmp/nonfree.rpm" | grep -q ': digests signatures OK$'; then
            echo "rpmfusion-nonfree.sh: the release package is not signed by RPM Fusion's key" >&2
            rpmkeys --define "_dbpath $tmp/db" --checksig -v "$tmp/nonfree.rpm" >&2
            exit 1
        fi
        # This release's package, not an older one a mirror kept (also signed).
        if [ "$(rpm -qp --qf '%{NAME} %{VERSION}' "$tmp/nonfree.rpm")" != "rpmfusion-nonfree-release $fedora" ]; then
            echo "rpmfusion-nonfree.sh: the download is not rpmfusion-nonfree-release $fedora" >&2
            exit 1
        fi
        dnf -y install "$tmp/nonfree.rpm" >&2
    fi
    dnf -y install -- "$@" >&2
}

main "$@"
exit $?
