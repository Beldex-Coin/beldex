#!/usr/bin/env bash
# sign-pevm.sh — run one CGGMP21 `Pevm` threshold-signing session across the live devnet
# committee, over an arbitrary ABI-encoded preimage.
#
#   ./sign-pevm.sh <kind> <0x-preimage>
#
#     kind = mint    expects the 192-byte / 6-word mint tuple
#            rotate  expects the 160-byte / 5-word rotation tuple
#            raw     no length check (set FORCE_PREIMAGE=1 to mean the same thing)
#
# This is the generalised form of sign-mint.sh. The environment block, the signer-binary
# discovery, the per-node filter and the share glob are all copied from it verbatim —
# sign-mint.sh is the version that actually produced the H.2 mint signature, so it is the
# reference, not this file. Only three things differ here: the expected preimage shape,
# the log prefix (`<kind>-sign-*.log`, so a rotation run cannot clobber a mint run's logs,
# which 04-rotate.sh relies on), and a few extra guards on the way in and out.
#
# sign-mint.sh itself is deliberately left untouched so nothing that already works
# regresses. If you change the env surface in one, change it in both.
#
# WHY THE LENGTH CHECK MATTERS: the signer keccaks whatever bytes it is handed. Pass a
# 32-byte digest instead of the preimage and it will happily sign keccak(digest) — a
# perfectly valid signature over the wrong thing, which then fails as BadSigner on-chain
# with nothing pointing back to the real cause.
#
# Env:
#   SIGNER                             path to beldex-bridge-signer
#   BRIDGE_SIGNER_COMMITTEE_THRESHOLD  default 4 (devnet t+1)
#   BRIDGE_SIGNER_SIGN_TIMEOUT_SECS    default 600
#   SHARE_SUBDIR                       which per-node share tree to sign with
#                                      (default `shares`; `shares-next` = the
#                                      incoming committee, for the H.6 probe)
#   SHARE_GLOB                         override the per-node share discovery glob
#   LOG_PREFIX                         name the per-node logs <prefix>-sign-<node>.log
#                                      (default: the kind). Two runs of the SAME kind over
#                                      the same preimage with DIFFERENT share trees would
#                                      otherwise overwrite each other's logs — which is
#                                      exactly what the H.6 both-directions proof does.
#   FORCE_PREIMAGE=1                   skip the length check
#
# WHICH KEY SIGNS: the rotation signature must come from the key that is CURRENTLY
# in the contract, i.e. the default `shares`. SHARE_SUBDIR=shares-next is only for
# probing the INCOMING committee before you hand the bridge to it — signing the
# rotation with shares-next would be the new committee authorising itself, which
# proves nothing.

set -euo pipefail
cd "$(dirname "$0")"

KIND="${1:-}"
PREIMAGE="${2:-}"

case "$KIND" in
  mint)   WANT_HEX=384; WHAT="192-byte ABI-encoded mint tuple (6 words)" ;;
  rotate) WANT_HEX=320; WHAT="160-byte ABI-encoded rotation tuple (5 words)" ;;
  raw)    WANT_HEX=0;   WHAT="arbitrary preimage" ;;
  *)
    echo "usage: $0 <mint|rotate|raw> 0x<preimage>" >&2
    exit 1 ;;
esac

if [ -z "$PREIMAGE" ]; then
  echo "usage: $0 $KIND 0x<preimage>" >&2
  exit 1
fi

# The signer wants BARE hex — sign-mint.sh strips the 0x before exporting
# BRIDGE_SIGNER_SIGN_PREIMAGE, and that is the form known to work. Do the same.
PREIMAGE="${PREIMAGE#0x}"
PREIMAGE="${PREIMAGE#0X}"

case "$PREIMAGE" in
  *[!0-9a-fA-F]*) echo "!! the preimage contains non-hex characters" >&2; exit 1 ;;
esac
if [ $(( ${#PREIMAGE} % 2 )) -ne 0 ]; then
  echo "!! odd number of hex digits — not a whole number of bytes" >&2
  exit 1
fi

if [ "$WANT_HEX" -ne 0 ] && [ "${#PREIMAGE}" -ne "$WANT_HEX" ] && [ "${FORCE_PREIMAGE:-0}" != "1" ]; then
  echo "!! expected the $WHAT — $WANT_HEX hex chars, got ${#PREIMAGE} ($(( ${#PREIMAGE} / 2 )) bytes)"
  echo ""
  if [ "${#PREIMAGE}" -eq 64 ]; then
    echo "   That is 32 bytes, i.e. almost certainly the DIGEST rather than the preimage."
    echo "   The signer hashes what you give it, so signing a digest produces a signature"
    echo "   over keccak(digest) and the contract will reject it as BadSigner."
  fi
  echo "   Pass the ABI-encoded tuple (the 'preimage' line the prep script printed),"
  echo "   or set FORCE_PREIMAGE=1 if you really mean this."
  exit 1
fi

# --- where the per-node logs land ---------------------------------------------------------
# Defaults to the kind, which is what every caller before the H.6 hand-off proof relied on.
# That proof signs the SAME mint preimage twice — once with the retired committee's tree and
# once with the promoted one — and needs both sets of logs to survive, because the whole
# claim is the comparison between them. Keyed off the kind alone, the second run's `rm -f`
# would delete the first run's evidence before anyone read it.
PREFIX="${LOG_PREFIX:-$KIND}"
case "$PREFIX" in
  ""|*/*|*[*?[]*)
    echo "!! LOG_PREFIX must be a plain filename fragment, got '$PREFIX'" >&2
    exit 1 ;;
esac

cd testdata

# --- locate the signer binary -------------------------------------------------------------
# Resolved to an ABSOLUTE path, and resolved AFTER `cd testdata` — a relative path would
# be interpreted from the wrong directory once we are one level deeper. sign-mint.sh uses
# `git rev-parse --show-toplevel` for exactly this reason; mirror it.
if [ -z "${SIGNER:-}" ]; then
  ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
  if [ -n "$ROOT" ]; then
    # debug first: that is the build sign-mint.sh uses, so it is the one proven to work.
    for c in "$ROOT/bridge/signer/target/debug/beldex-bridge-signer" \
             "$ROOT/bridge/signer/target/release/beldex-bridge-signer"; do
      # NB: written as an `if` rather than `[ -x "$c" ] && SIGNER=... && break` —
      # under `set -e` a failing AND-list as the last command of a construct can take
      # the script down, and the terse form reads as if it cannot fail.
      if [ -x "$c" ]; then SIGNER="$c"; break; fi
    done
  fi
fi
if [ -z "${SIGNER:-}" ] || [ ! -x "$SIGNER" ]; then
  echo "!! beldex-bridge-signer not found" >&2
  echo "   build it:  cargo build --features live-dkg,live-pevm-dkg" >&2
  echo "   or set:    SIGNER=/path/to/beldex-bridge-signer" >&2
  exit 1
fi

# --- per-node share discovery ---------------------------------------------------------------
# The DKG persists each node's share under its OWN data dir, not a shared pool:
#   beldex-127.0.0.1-<port>/devnet/<subdir>/pevm-<i>.keyshare
# That is also the realistic arrangement — in production no host ever sees another's share.
SUBDIR="${SHARE_SUBDIR:-shares}"
GLOB="${SHARE_GLOB:-beldex-127.0.0.1-*/devnet/$SUBDIR/pevm-*.keyshare}"
# `|| true`: with `set -o pipefail`, a no-match glob makes `ls` exit non-zero, which fails
# the whole pipeline and — because this is a command substitution in an assignment — takes
# the script down under `set -e` with NO output at all. That would make the genuinely useful
# "no keyshares, run the DKG first" message below unreachable, replacing it with a silent
# exit 2. `wc -l` still prints 0 into the substitution, so the count stays correct.
N_SHARES="$(ls $GLOB 2>/dev/null | wc -l | tr -d ' ' || true)"
if [ "$N_SHARES" -eq 0 ]; then
  echo "!! no pevm keyshares matching $GLOB under $PWD" >&2
  echo "   Run the C.3 Pevm DKG first (BRIDGE_SIGNER_DKG_LEG=pevm)." >&2
  exit 1
fi

THRESHOLD="${BRIDGE_SIGNER_COMMITTEE_THRESHOLD:-4}"

echo "  kind      : $KIND"
echo "  signer    : $SIGNER"
echo "  preimage  : ${#PREIMAGE} hex chars ($(( ${#PREIMAGE} / 2 )) bytes)"
echo "  share dir : devnet/$SUBDIR$([ "$SUBDIR" = "shares" ] || echo '   <-- NOT the committee currently in the contract')"
echo "  shares    : $N_SHARES nodes hold a pevm keyshare"
echo "  threshold : $THRESHOLD"
echo ""

# --- fan the signing session out across the nodes ---------------------------------------------
# Kill stragglers from a previous run first: they still hold the mesh ports, and a stale
# signer joining this session would poison the transcript.
#
# The pattern is 'beldex-bridge-signer sign', not just the binary name: `pkill -f` matches
# the WHOLE command line of every process, so the bare name also matches any shell, editor
# or log tail that happens to mention it — including, in one test run here, the harness
# invoking this very script. Matching the `"$SIGNER" sign` invocation shape hits the real
# signers and essentially nothing else.
pkill -f 'beldex-bridge-signer sign' 2>/dev/null || true
sleep 1
rm -f "${PREFIX}-sign-"*.log

# 32 bytes of 0x11, standing in for the gateway id / self MN pubkey on devnet.
ANY32=$(printf '11%.0s' {1..32})

PIDS=""
for d in beldex-127.0.0.1-*/; do
  sock="$PWD/${d}devnet/beldexd.sock"
  key="$PWD/${d}devnet/key_ed25519"
  share="$PWD/${d}devnet/$SUBDIR"
  # Same filter as sign-mint.sh: a node without a live socket and an ed25519 identity
  # cannot join the authenticated mesh, so it is not a participant.
  [ -S "$sock" ] && [ -f "$key" ] || continue
  ls "$share"/pevm-*.keyshare >/dev/null 2>&1 || continue
  BRIDGE_SIGNER_BELDEXD_RPC_URL="http://127.0.0.1:19191" \
  BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$sock" \
  BRIDGE_SIGNER_GATEWAY_ID="$ANY32" BRIDGE_SIGNER_SELF_MN_PUBKEY="$ANY32" \
  BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=120 BRIDGE_SIGNER_COMMITTEE_THRESHOLD="$THRESHOLD" \
  BRIDGE_SIGNER_MN_KEY_FILE="$key" BRIDGE_SIGNER_MESH_PORT_BASE=6000 \
  BRIDGE_SIGNER_MESH_USE_CURVE=false BRIDGE_SIGNER_SHARE_DIR="$share" \
  BRIDGE_SIGNER_SIGN_LEG=pevm BRIDGE_SIGNER_SIGN_PREIMAGE="$PREIMAGE" \
  BRIDGE_SIGNER_SIGN_TIMEOUT_SECS="${BRIDGE_SIGNER_SIGN_TIMEOUT_SECS:-600}" \
    "$SIGNER" sign > "${PREFIX}-sign-${d%/}.log" 2>&1 &
  PIDS="$PIDS $!"
done

if [ -z "$PIDS" ]; then
  echo "!! no node had both a live beldexd.sock and a key_ed25519 — is the devnet up?" >&2
  exit 1
fi

# Wait per-pid rather than a bare `wait`: under `set -e` a bare `wait` that reports a
# non-zero child status would take the script down before the logs are read, and the
# logs are where the actual diagnosis lives.
for p in $PIDS; do wait "$p" || true; done

# --- results ------------------------------------------------------------------------------------
if grep -qh 'no BRIDGE_SIGNER_SIGN_PREIMAGE set' "${PREFIX}-sign-"*.log 2>/dev/null; then
  echo "!! the signer fell back to its built-in demo preimage — the env var did not reach it." >&2
  echo "   Nothing signed here is bound to the values you prepared. Stopping." >&2
  exit 1
fi

echo "── per-node results ──────────────────────────────────────────────────"
grep -h 'ecrecover\|wBDX signer\|over digest' "${PREFIX}-sign-"*.log 2>/dev/null | sort | uniq -c || true

# `|| true` inside the substitution: with pipefail, a grep that matches nothing fails the
# whole pipeline and `set -e` would take the script down on a legitimately-zero count.
NOK="$(grep -hc 'ecrecover.*VERIFIED' "${PREFIX}-sign-"*.log 2>/dev/null | awk '{s+=$1} END {print s+0}' || true)"
echo ""
echo "signers that ecrecover'd to the wBDX address: ${NOK:-0} (expect $THRESHOLD)"

SIGS="$(grep -h '^Pevm signature:' "${PREFIX}-sign-"*.log 2>/dev/null \
        | sed 's/^Pevm signature:[[:space:]]*//' | tr -d ' \r' | sort -u || true)"
NDISTINCT="$(printf '%s\n' "$SIGS" | grep -c . || true)"
if [ "$NDISTINCT" -eq 0 ]; then
  echo "!! no signature produced — check testdata/${PREFIX}-sign-*.log" >&2
  exit 1
fi
if [ "$NDISTINCT" -ne 1 ]; then
  echo "!! signers disagreed ($NDISTINCT distinct signatures) — they signed different preimages" >&2
  exit 1
fi

echo ""
echo "  Pevm signature: $SIGS"
echo "  logs: utils/local-devnet/testdata/${PREFIX}-sign-*.log"
