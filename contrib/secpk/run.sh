#!/usr/bin/env bash
# Builds (if needed) and runs bridge_secp256k1_sign -- see bridge_secp256k1_sign.cpp for what it's
# for. Requires the main project to have already been built at least once (specifically
# external/secp256k1), since this links against that same build's libsecp256k1.a rather than
# building its own copy.
#
# Usage:
#   ./run.sh --generate
#   ./run.sh <32-byte-hex-secret-key> <32-byte-hex-hash>

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

# Same build directory convention used elsewhere in this repo/session (repo_root/build).
build_dir="${BELDEX_BUILD_DIR:-$repo_root/build/Darwin/GW-implementation/release}"
secp256k1_lib="$build_dir/external/secp256k1/lib/libsecp256k1.a"
secp256k1_include="$repo_root/external/secp256k1/include"
oxenc_include="$repo_root/external/oxen-encoding"

if [ ! -f "$secp256k1_lib" ]; then
  echo "error: $secp256k1_lib not found." >&2
  echo "Build the main project first (or set BELDEX_BUILD_DIR to point at an existing build dir)." >&2
  exit 1
fi

binary="$script_dir/bridge_secp256k1_sign"
source="$script_dir/bridge_secp256k1_sign.cpp"

if [ ! -x "$binary" ] || [ "$source" -nt "$binary" ]; then
  echo "building $binary ..." >&2
  g++ -O2 -std=c++17 -o "$binary" "$source" \
    -I"$secp256k1_include" \
    -I"$oxenc_include" \
    "$secp256k1_lib"
fi

exec "$binary" "$@"
