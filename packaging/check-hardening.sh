#!/bin/bash
# check-hardening.sh [--stack-protector] <elf>...
# Fails unless every program is built the way Telamon OS hardens its programs:
# position independent (ASLR), fully read-only after relocation (RELRO with
# BIND_NOW), a non-executable stack, no text relocations and no RPATH. With
# --stack-protector (for the C++ programs, which the distribution's compiler
# flags cover) it also wants the stack protector and fortified libc calls to be
# in use. Rust programs have no stack protector: rustc cannot emit one on a
# stable toolchain; they are covered by the checks above and by stack probes.
# Run by the spec's %check on the installed files, and by hand:
#   packaging/check-hardening.sh /usr/bin/telamon-explorer
set -u
stack=0
if [ "${1:-}" = "--stack-protector" ]; then
    stack=1
    shift
fi
[ $# -gt 0 ] || { echo "usage: check-hardening.sh [--stack-protector] <elf>..." >&2; exit 2; }
status=0
bad() { echo "check-hardening: $1: $2" >&2; status=1; }
for f in "$@"; do
    [ -f "$f" ] || { bad "$f" "no such file"; continue; }
    readelf -hW "$f" 2>/dev/null | grep -qE 'Type:[[:space:]]+DYN' || bad "$f" "not position independent (not ET_DYN)"
    readelf -dW "$f" 2>/dev/null | grep -qE '\(FLAGS_1\).*\bPIE\b' || bad "$f" "not marked PIE"
    readelf -lW "$f" 2>/dev/null | grep -q 'GNU_RELRO' || bad "$f" "no RELRO segment"
    readelf -dW "$f" 2>/dev/null | grep -qE 'BIND_NOW|\(FLAGS_1\).*\bNOW\b' || bad "$f" "lazy binding (no BIND_NOW), so RELRO is partial"
    readelf -lW "$f" 2>/dev/null | grep 'GNU_STACK' | grep -q 'RWE' && bad "$f" "executable stack"
    readelf -lW "$f" 2>/dev/null | grep -q 'GNU_STACK' || bad "$f" "no GNU_STACK header (stack would be executable)"
    readelf -dW "$f" 2>/dev/null | grep -q '(TEXTREL)' && bad "$f" "text relocations"
    readelf -dW "$f" 2>/dev/null | grep -qE '\((RPATH|RUNPATH)\)' && bad "$f" "has an RPATH or RUNPATH"
    if [ "$stack" = 1 ]; then
        syms=$(nm -D --undefined-only "$f" 2>/dev/null)
        grep -q '__stack_chk_fail' <<<"$syms" || bad "$f" "no stack protector (__stack_chk_fail is not used)"
        grep -E '__[a-z0-9]+_chk' <<<"$syms" | grep -qv '__stack_chk' || bad "$f" "no fortified libc calls (_FORTIFY_SOURCE not in effect)"
    fi
done
exit "$status"
