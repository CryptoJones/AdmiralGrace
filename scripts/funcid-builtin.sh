#!/usr/bin/env bash
# funcid-builtin.sh — regenerate the built-in whole-function signature databases.
#
# Usage:
#   scripts/funcid-builtin.sh
#
# The engine ships signatures for libc, libstdc++ and libgcc under
# crates/ag-engine/src/funcid/, compiled in with include_str!. They are taken
# from real libraries with `ag funcid create`, so this script reproduces them
# from the libraries on this host. A whole-function hash is exact: the files
# match the build they were taken from, so regenerating on a different host
# yields signatures for that host's libraries — which is the point. Each
# file's `source` records the build it came from; set the *_SOURCE variables
# to describe the libraries you are reading.
#
# Overridable:
#   AG            the ag binary (built with cargo when not set)
#   LIBC          path to libc.so.6
#   LIBSTDCXX     path to libstdc++.so.6
#   LIBGCC        path to libgcc_s.so.1
#   *_SOURCE      the provenance string recorded in each file
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/crates/ag-engine/src/funcid"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"

if [[ -z "${AG:-}" ]]; then
    cargo build --bin ag --offline --manifest-path "$REPO/Cargo.toml"
    AG="$CARGO_TARGET_DIR/debug/ag"
fi

LIBC="${LIBC:-/lib/x86_64-linux-gnu/libc.so.6}"
LIBSTDCXX="${LIBSTDCXX:-/lib/x86_64-linux-gnu/libstdc++.so.6}"
LIBGCC="${LIBGCC:-/lib/x86_64-linux-gnu/libgcc_s.so.1}"

LIBC_SOURCE="${LIBC_SOURCE:-GNU C Library, x86-64, from $LIBC}"
LIBSTDCXX_SOURCE="${LIBSTDCXX_SOURCE:-GNU libstdc++, x86-64, from $LIBSTDCXX}"
LIBGCC_SOURCE="${LIBGCC_SOURCE:-GNU libgcc_s, x86-64, from $LIBGCC}"

"$AG" funcid create "$LIBC"      -o "$OUT/libc.agsig"      --library libc      --source "$LIBC_SOURCE"
"$AG" funcid create "$LIBSTDCXX" -o "$OUT/libstdc++.agsig" --library libstdc++ --source "$LIBSTDCXX_SOURCE"
"$AG" funcid create "$LIBGCC"    -o "$OUT/libgcc.agsig"    --library libgcc    --source "$LIBGCC_SOURCE"

echo "wrote $OUT/{libc,libstdc++,libgcc}.agsig"
