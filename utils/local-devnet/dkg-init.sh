#!/usr/bin/env bash
# dkg-init.sh — run the INITIAL dual DKG (Pgw + Pevm) across the live devnet committee,
# into each node's own `devnet/shares` tree. This is the C.2 step; it is what
# `dkg-next.sh` (rotation, writes `shares-next`, refuses generation 0) is NOT.
#
#     runlog ./dkg-init.sh
#
# Produces per node:
#   devnet/shares/pgw-<i>.{keypackage,pubkeypackage,groupvk}   Pgw  (ed25519 / FROST)
#   devnet/shares/pevm-<i>.{keyshare,groupkey}                 Pevm (secp256k1 / CGGMP21)
#
# The invocation mirrors bridge/docs/C2_DEVNET_VERIFICATION.md verbatim; if you change the
# env surface here, change it there (and in sign-mint.sh / dkg-next.sh, which copy it).
#
# Env:
#   SIGNER                            path to beldex-bridge-signer
#   BRIDGE_SIGNER_COMMITTEE_THRESHOLD default 4 (devnet t+1)
#   BRIDGE_SIGNER_DKG_TIMEOUT_SECS    default 600 — the Pevm aux-info phase generates
#                                     Paillier safe primes; with all 6 signers doing it on
#                                     ONE host they contend for cores, so 60s is far too
#                                     little (keygen finishes, aux-info then times out).
#   ALLOW_CLOBBER=1                   overwrite an existing `shares` tree

set -euo pipefail
cd "$(dirname "$0")"
cd testdata

# --- locate the signer binary ------------------------------------------------------------
if [ -z "${SIGNER:-}" ]; then
  ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
  if [ -n "$ROOT" ]; then
    for c in "$ROOT/bridge/signer/target/debug/beldex-bridge-signer" \
             "$ROOT/bridge/signer/target/release/beldex-bridge-signer"; do
      if [ -x "$c" ]; then SIGNER="$c"; break; fi
    done
  fi
fi
if [ -z "${SIGNER:-}" ] || [ ! -x "$SIGNER" ]; then
  echo "!! beldex-bridge-signer not found" >&2
  echo "   build it:  cargo build -p beldex-bridge-signer --features serve-live" >&2
  exit 1
fi
# The Pevm leg is feature-gated; a binary without it fails only after the mesh is up, which
# reads as a network fault. Check up front instead (same guard as dkg-next.sh).
if strings "$SIGNER" 2>/dev/null | grep -q 'the Pevm leg needs a build with'; then
  echo "!! this binary was built WITHOUT the Pevm DKG leg" >&2
  echo "   rebuild:  cargo build -p beldex-bridge-signer --features serve-live" >&2
  exit 1
fi

# --- refuse to clobber existing shares ----------------------------------------------------
# These are the keys the committee is USING: the contract's signer address and the gateway's
# owner key are derived from them. Overwriting means the deployed wBDX and the registered
# gateway now point at keys nobody holds — recoverable only by redeploying/re-registering.
EXISTING="$(ls beldex-127.0.0.1-*/devnet/shares/pgw-*.keypackage 2>/dev/null | wc -l | tr -d ' ' || true)"
if [ "$EXISTING" -ne 0 ] && [ "${ALLOW_CLOBBER:-0}" != "1" ]; then
  echo "!! devnet/shares already holds $EXISTING Pgw share(s)."
  echo "   Re-running the initial DKG replaces the committee's CURRENT keys — the deployed"
  echo "   wBDX signer and the registered gateway owner would both be orphaned."
  echo "   To rotate properly use ./dkg-next.sh <n>; to wipe anyway re-run with ALLOW_CLOBBER=1."
  exit 1
fi

THRESHOLD="${BRIDGE_SIGNER_COMMITTEE_THRESHOLD:-4}"
TIMEOUT="${BRIDGE_SIGNER_DKG_TIMEOUT_SECS:-600}"
ANY32=$(printf '11%.0s' {1..32})   # placeholder gateway_id / self pubkey (the DKG uses neither)

echo "  signer     : $SIGNER"
echo "  target     : <node>/devnet/shares  (both legs)"
echo "  threshold  : $THRESHOLD"
echo "  timeout    : ${TIMEOUT}s"
echo ""

pkill -f 'beldex-bridge-signer dkg' 2>/dev/null || true
sleep 1
rm -f dkg-*.log

PIDS=""
for d in beldex-127.0.0.1-*/; do
  sock="$PWD/${d}devnet/beldexd.sock"
  key="$PWD/${d}devnet/key_ed25519"
  # No live socket or no ed25519 identity ⇒ the node cannot join the authenticated mesh.
  [ -S "$sock" ] && [ -f "$key" ] || continue
  BRIDGE_SIGNER_BELDEXD_RPC_URL="http://127.0.0.1:19191" \
  BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$sock" \
  BRIDGE_SIGNER_GATEWAY_ID="$ANY32" BRIDGE_SIGNER_SELF_MN_PUBKEY="$ANY32" \
  BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=120 BRIDGE_SIGNER_COMMITTEE_THRESHOLD="$THRESHOLD" \
  BRIDGE_SIGNER_MN_KEY_FILE="$key" BRIDGE_SIGNER_MESH_PORT_BASE=6000 \
  BRIDGE_SIGNER_MESH_USE_CURVE=false \
  BRIDGE_SIGNER_DKG_TIMEOUT_SECS="$TIMEOUT" \
  BRIDGE_SIGNER_SHARE_DIR="$PWD/${d}devnet/shares" \
    "$SIGNER" dkg > "dkg-${d%/}.log" 2>&1 &
  PIDS="$PIDS $!"
done

if [ -z "$PIDS" ]; then
  echo "!! no node had both a live beldexd.sock and a key_ed25519 — is the devnet up?" >&2
  exit 1
fi
echo "  running the dual DKG (Pevm aux-info is slow — expect minutes)…"
# Per-pid, not a bare `wait`: under `set -e` a non-zero child would kill the script before
# the logs are read, and the logs are the diagnosis.
for p in $PIDS; do wait "$p" || true; done

echo ""
echo "── per-node results ─────────────────────────────────────────────────"
grep -h "Pgw DKG complete"          dkg-*.log 2>/dev/null | sort | uniq -c || true
grep -h "Pevm keygen complete"      dkg-*.log 2>/dev/null | sed 's/.*address //' | sort | uniq -c || true
grep -h "Pevm complete share ready" dkg-*.log 2>/dev/null | sort | uniq -c || true

NPGW="$(ls beldex-127.0.0.1-*/devnet/shares/pgw-*.groupvk 2>/dev/null | wc -l | tr -d ' ' || true)"
NPEVM="$(ls beldex-127.0.0.1-*/devnet/shares/pevm-*.keyshare 2>/dev/null | wc -l | tr -d ' ' || true)"
echo ""
echo "  Pgw  share sets : $NPGW"
echo "  Pevm share sets : $NPEVM"
if [ "$NPGW" -eq 0 ] || [ "$NPEVM" -eq 0 ]; then
  echo "!! the DKG did not complete both legs — check testdata/dkg-*.log" >&2
  exit 1
fi

# Every participant must agree on the Pgw group key, or they did not complete the SAME DKG
# and the gateway owner key would be meaningless. Compared with cmp (POSIX) rather than a
# hex tool, so a missing `xxd` cannot masquerade as a protocol failure.
FIRST=""; MISMATCH=0
for f in beldex-127.0.0.1-*/devnet/shares/pgw-*.groupvk; do
  [ -f "$f" ] || continue
  if [ -z "$FIRST" ]; then FIRST="$f"; continue; fi
  cmp -s "$FIRST" "$f" || MISMATCH=1
done
if [ "$MISMATCH" -ne 0 ]; then
  echo "!! participants disagree on the Pgw group key — the DKG did not converge." >&2
  echo "   Do NOT register a gateway to it. See testdata/dkg-*.log." >&2
  exit 1
fi

PGW_GROUP_VK="$(od -An -v -tx1 < "$FIRST" | tr -d ' \n')"
echo "  PGW_GROUP_VK    : $PGW_GROUP_VK"
echo "                    (all $NPGW participants agree — this is the gateway owner_key)"
echo ""
echo "Next:"
echo "  1) wBDX signer address (also proves the committee can sign):"
echo "       runlog ./sign-pevm.sh raw 0x$(printf 'ab%.0s' {1..32})"
echo "     read the 'wBDX signer : 0x…' line → INITIAL_SIGNER for the contract deploy."
echo "  2) register the bridge gateway with owner_type=eddsa and the PGW_GROUP_VK above"
echo "     (see bridge/test/e2e/DEVNET_SETUP.md §5)."
