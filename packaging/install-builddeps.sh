#!/bin/bash
# Install what building Telamon Archive needs, as root in fedora:44: the spec's
# BuildRequires, rpm-build and the packages named. dnf (and its metadata
# download) runs only for what is missing, so the CI dev image, which has it
# all, skips it.
#   packaging/install-builddeps.sh [package ...]
# TELAMON_LOCAL_RPMS=<dir> (ATLAS_LOCAL_RPMS still works) installs the RPMs in <dir> first: atlas-framework's
# (telamon-ui), which the app builds against and no repository has.
set -euo pipefail

# Capabilities on stdin ("name [op version]"), one per line; prints those
# that nothing installed provides, or not in a version the line allows.
missing() {
    local cap op want
    while read -r cap op want; do
        [ -n "$cap" ] || continue
        satisfied "$cap" "$op" "$want" || printf '%s\n' "$cap${op:+ $op $want}"
    done
}

# satisfied <capability> [<op> <version>]: whether an installed package
# provides it, in a version the operator allows. Versions compare as rpm
# orders them ([epoch:]version[-release]); the release counts only when the
# wanted version has one, as in rpm's own dependency checks.
satisfied() {
    local cap=$1 op=${2:-} want=${3:-} name have c
    [ -n "$op" ] || { rpm -q --whatprovides -- "$cap" >/dev/null 2>&1; return; }
    [[ $want =~ ^[A-Za-z0-9._+~^:-]+$ ]] || return 1
    while IFS=$'\t' read -r name have; do
        [ "$name" = "$cap" ] || continue
        # An unversioned provide meets any version, as rpm has it.
        [ -n "$have" ] || return 0
        [[ $have =~ ^[A-Za-z0-9._+~^:-]+$ ]] || continue
        [[ $want == *-* ]] || have=${have%-*}
        c=$(rpm --eval "%{lua:local a, b = rpm.ver('$have'), rpm.ver('$want'); print(a < b and -1 or (a == b and 0 or 1))}")
        case $op in
            '>=') [ "$c" -ge 0 ] ;;
            '>') [ "$c" -gt 0 ] ;;
            '=' | '==') [ "$c" -eq 0 ] ;;
            '<=') [ "$c" -le 0 ] ;;
            '<') [ "$c" -lt 0 ] ;;
            *) false ;;
        esac && return 0
    done < <(rpm -q --qf '[%{PROVIDENAME}\t%{PROVIDEVERSION}\n]' --whatprovides -- "$cap" 2>/dev/null)
    return 1
}

main() {
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    spec=$here/telamon-archive.spec

    tools=(rpm-build dnf5-plugins tar gzip "$@")
    if [ -n "$(printf '%s\n' "${tools[@]}" | missing)" ]; then
        dnf -y install "${tools[@]}" >&2
    fi

    TELAMON_LOCAL_RPMS=${TELAMON_LOCAL_RPMS:-${ATLAS_LOCAL_RPMS:-}}
    if [ -n "$TELAMON_LOCAL_RPMS" ]; then
        # Telamon.Ui and its fonts, not the gallery. rpm puts these exact files
        # in place even when a build of the same (or a newer) version is
        # installed; dnf first brings their dependencies when rpm finds some
        # missing.
        local_rpms=("$TELAMON_LOCAL_RPMS"/telamon-ui-[0-9]*.rpm "$TELAMON_LOCAL_RPMS"/telamon-symbols-fonts-[0-9]*.rpm)
        if ! rpm -U --replacepkgs --replacefiles --oldpackage "${local_rpms[@]}" >&2; then
            echo "::warning::telamon-ui needs packages that are not installed (above); installing them with dnf" >&2
            dnf -y install "${local_rpms[@]}" >&2
            rpm -U --replacepkgs --replacefiles --oldpackage "${local_rpms[@]}" >&2
        fi
    fi

    reqs=$(rpmspec -q --buildrequires "$spec")
    if [ -n "$(missing <<<"$reqs")" ]; then
        dnf -y builddep "$spec" >&2
    fi
}

main "$@"
exit $?
