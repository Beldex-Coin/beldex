#!/usr/bin/env bash
# dkg-next.sh — run a FRESH Pevm (secp256k1/CGGMP21) DKG across the live devnet
# committee, into a SEPARATE share tree, to produce the successor key for an H.6
# rotation.
#
#   runlog ./dkg-next.sh [keygen-number]
#
# cggmp21 0.6.3 has no threshold key refresh, so "rotate the committee key" means
# "run a whole new DKG". The new shares MUST land somewhere other than `shares`:
# the outgoing key has to survive long enough to sign the rotation that hands the
# bridge over. Losing it first leaves only the admin break-glass, which is exactly
# the trust assumption H.6 exists to remove.
#
#   devnet/shares       the committee currently in the contract   (DO NOT TOUCH)
#   devnet/shares-next  the incoming committee                    (written here)
#
# The env block below is copied from sign-pevm.sh, which is copied from sign-mint.sh
# — the invocation that actually works. Only the SIGN_* vars are dropped and the
# DKG_* vars added. If you change the env surface in one, change it in all three.
#
# Env:
#   SIGNER                            path to beldex-bridge-signer
#   SHARE_SUBDIR                      target tree (default shares-next)
#   BRIDGE_SIGNER_COMMITTEE_THRESHOLD default 4 (devnet t+1)
#   BRIDGE_SIGNER_DKG_TIMEOUT_SECS    default 900 (a Pevm DKG + aux-info is slow)
#   ALLOW_CLOBBER=1                   overwrite a non-empty target tree

set -euo pipefail
cd "$(dirname "$0")"

SUBDIR="${SHARE_SUBDIR:-shares-next}"

# --- the key generation number ------------------------------------------------------------
# Fed into the cggmp21 ExecutionId, which is the transcript's domain separator. Reusing the
# generation of an existing key would run a second, different protocol under an identity the
# first one already claimed — precisely the cross-protocol confusion the ExecutionId exists
# to prevent. So it must differ from every generation already used, and the default (0) is
# almost certainly taken by the key now in the contract.
KEYGEN="${1:-}"
if [ -z "$KEYGEN" ]; then
  echo "usage: $0 <keygen-number>" >&2
  echo "" >&2
  echo "  The number must not repeat one already used. The original devnet key is" >&2
  echo "  generation 0 (the default), so the first rotation is 1, the next 2, ..." >&2
  echo "  It is recorded in the run log, not on chain — check .debug/history." >&2
  exit 1
fi
case "$KEYGEN" in
  ''|*[!0-9]*) echo "!! keygen must be a non-negative integer, got '$KEYGEN'" >&2; exit 1 ;;
esac
if [ "$KEYGEN" = "0" ]; then
  echo "!! generation 0 is the default, i.e. what the ORIGINAL DKG almost certainly used." >&2
  echo "   Pick 1 or higher for a successor key." >&2
  exit 1
fi

if [ "$SUBDIR" = "shares" ]; then
  echo "!! refusing to DKG into 'shares' — that is the key currently in the contract." >&2
  echo "   Overwriting it destroys the ability to SIGN the rotation away from it," >&2
  echo "   leaving only the admin break-glass. Use shares-next (the default)." >&2
  exit 1
fi

cd testdata

# --- locate the signer binary ---------------------------------------------------------------
# Absolute, and resolved AFTER `cd testdata` — same reasoning as sign-pevm.sh.
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
  echo "   build it:  cargo build -p beldex-bridge-signer --features live-dkg,live-pevm-dkg" >&2
  exit 1
fi

# The Pevm leg is feature-gated; a binary built without it fails only after the mesh is up,
# which reads as a network problem. Check up front instead.
if strings "$SIGNER" 2>/dev/null | grep -q 'the Pevm leg needs a build with'; then
  echo "!! this binary was built WITHOUT --features live-pevm-dkg" >&2
  echo "   rebuild:  cargo build -p beldex-bridge-signer --features live-dkg,live-pevm-dkg" >&2
  exit 1
fi

# --- refuse to clobber an existing successor tree ----------------------------------------------
# `|| true`: a no-match glob makes `ls` exit non-zero; under pipefail+set -e that kills
# the script silently in this assignment. `wc -l` still prints 0, so the count is right.
EXISTING="$(ls beldex-127.0.0.1-*/devnet/"$SUBDIR"/pevm-*.keyshare 2>/dev/null | wc -l | tr -d ' ' || true)"
if [ "$EXISTING" -ne 0 ] && [ "${ALLOW_CLOBBER:-0}" != "1" ]; then
  echo "!! $SUBDIR already holds $EXISTING keyshare(s)."
  echo "   If a rotation is mid-flight, these are the shares it is rotating TO — replacing"
  echo "   them would strand the pending proposal against a key nobody holds any more."
  echo "   Re-run with ALLOW_CLOBBER=1 if you are sure."
  exit 1
fi

THRESHOLD="${BRIDGE_SIGNER_COMMITTEE_THRESHOLD:-4}"

echo "  signer     : $SIGNER"
echo "  target     : devnet/$SUBDIR  (the CURRENT key in devnet/shares is untouched)"
echo "  keygen     : $KEYGEN"
echo "  threshold  : $THRESHOLD"
echo ""

# --- fan the DKG out across the nodes ------------------------------------------------------------
# Match the invocation shape, not the bare binary name — `pkill -f` sees whole command lines,
# so the bare name also matches the shell that launched this script. Same trap as sign-pevm.sh.
pkill -f 'beldex-bridge-signer dkg' 2>/dev/null || true
sleep 1
rm -f dkg-next-*.log

ANY32=$(printf '11%.0s' {1..32})

PIDS=""
for d in beldex-127.0.0.1-*/; do
  sock="$PWD/${d}devnet/beldexd.sock"
  key="$PWD/${d}devnet/key_ed25519"
  share="$PWD/${d}devnet/$SUBDIR"
  # Same participant filter as sign-mint.sh: no live socket or no ed25519 identity means
  # the node cannot join the authenticated mesh.
  [ -S "$sock" ] && [ -f "$key" ] || continue
  mkdir -p "$share"
  BRIDGE_SIGNER_BELDEXD_RPC_URL="http://127.0.0.1:19191" \
  BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$sock" \
  BRIDGE_SIGNER_GATEWAY_ID="$ANY32" BRIDGE_SIGNER_SELF_MN_PUBKEY="$ANY32" \
  BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=120 BRIDGE_SIGNER_COMMITTEE_THRESHOLD="$THRESHOLD" \
  BRIDGE_SIGNER_MN_KEY_FILE="$key" BRIDGE_SIGNER_MESH_PORT_BASE=6000 \
  BRIDGE_SIGNER_MESH_USE_CURVE=false BRIDGE_SIGNER_SHARE_DIR="$share" \
  BRIDGE_SIGNER_DKG_LEG=pevm BRIDGE_SIGNER_DKG_KEYGEN="$KEYGEN" \
  BRIDGE_SIGNER_DKG_TIMEOUT_SECS="${BRIDGE_SIGNER_DKG_TIMEOUT_SECS:-900}" \
    "$SIGNER" dkg > "dkg-next-${d%/}.log" 2>&1 &
  PIDS="$PIDS $!"
done

if [ -z "$PIDS" ]; then
  echo "!! no node had both a live beldexd.sock and a key_ed25519 — is the devnet up?" >&2
  exit 1
fi

# Per-pid, not a bare `wait`: under `set -e` a non-zero child status would kill the script
# before the logs are read, and the logs are the diagnosis.
for p in $PIDS; do wait "$p" || true; done

# --- results --------------------------------------------------------------------------------------
echo "── per-node results ──────────────────────────────────────────────────"
grep -h 'Pevm share material written\|Pevm complete share ready' dkg-next-*.log 2>/dev/null \
  | sed 's/^/  /' | sort | uniq -c || true

# --- clean up after nodes that are not on the committee -------------------------------------------
# A node that isn't on the current bridge committee refuses the DKG immediately ("dkg: this node
# is not on the current bridge committee"), but BRIDGE_SIGNER_SHARE_DIR had to exist before the
# signer was started, so it leaves an EMPTY target dir behind. Left in place that dir is worse
# than useless: it looks like a participant that produced no shares, and it makes the promotion
# step (`shares-next` -> `shares`) try to archive a `shares` tree that node never had, failing
# with a bare "No such file or directory" that reads like the rotation went wrong.
# An empty dir only MEANS "not a member" when the log says so. Every other early refusal --
# a signer built without --features live-dkg, a config error, a dead mesh -- leaves exactly
# the same empty dir behind, and reporting those as "not on the committee" sends you to look
# at committee registration when the real cause is one line away in that node's log. Read it.
NONMEMBER=""
OTHERFAIL=""
for d in beldex-127.0.0.1-*/; do
  n="${d%/}"
  t="${d}devnet/$SUBDIR"
  [ -d "$t" ] || continue
  ls "$t"/pevm-*.keyshare >/dev/null 2>&1 && continue
  rmdir "$t" 2>/dev/null || true
  if grep -q 'not on the current bridge committee' "dkg-next-$n.log" 2>/dev/null; then
    NONMEMBER="$NONMEMBER $n"
  else
    OTHERFAIL="$OTHERFAIL $n"
  fi
done
if [ -n "$NONMEMBER" ]; then
  echo ""
  echo "  not on the committee, no shares written (empty dir removed):"
  for n in $NONMEMBER; do echo "    $n"; done
fi
if [ -n "$OTHERFAIL" ]; then
  echo ""
  echo "  wrote no shares, and NOT because they are off the committee:"
  for n in $OTHERFAIL; do
    printf '    %-30s %s\n' "$n" \
      "$(grep -v '^(no .env file' "dkg-next-$n.log" 2>/dev/null | tail -1)"
  done
fi

NEW="$(ls beldex-127.0.0.1-*/devnet/"$SUBDIR"/pevm-*.keyshare 2>/dev/null | wc -l | tr -d ' ' || true)"
echo ""
echo "  keyshares written : $NEW"
if [ "$NEW" -eq 0 ]; then
  echo "!! the DKG produced no shares — check testdata/dkg-next-*.log" >&2
  exit 1
fi

# Every participant must agree on the group key, or they did not complete the SAME DKG and
# the "new signer" address is meaningless. This is the one check worth failing loudly on.
#
# Compared with `cmp`, not by hexdumping: `xxd` is not POSIX and is missing from plenty of
# minimal environments (it ships with vim), and a missing hex tool here would silently turn
# into "0 distinct group keys — the DKG did not converge", which reads as a protocol failure
# rather than a tooling one. `cmp` and `od` are both in POSIX.
FIRST=""
NGROUP=0
MISMATCH=0
for f in beldex-127.0.0.1-*/devnet/"$SUBDIR"/pevm-*.groupkey; do
  [ -f "$f" ] || continue
  NGROUP=$(( NGROUP + 1 ))
  if [ -z "$FIRST" ]; then FIRST="$f"; continue; fi
  cmp -s "$FIRST" "$f" || MISMATCH=1
done
if [ "$NGROUP" -eq 0 ]; then
  echo "!! shares were written but no group key was — check testdata/dkg-next-*.log" >&2
  exit 1
fi
if [ "$MISMATCH" -ne 0 ]; then
  echo "!! participants disagree on the group key — the DKG did not converge on one key." >&2
  echo "   Do NOT rotate to it. Check testdata/dkg-next-*.log for who diverged." >&2
  exit 1
fi

GKS="$(od -An -v -tx1 < "$FIRST" | tr -d ' \n')"
echo "  group key         : 0x$GKS"
echo "                      (all $NGROUP participants agree)"
echo ""
echo "Next — get the new signer's ETH ADDRESS, and prove the new committee can actually"
echo "sign, in one step. A throwaway signature over 32 arbitrary bytes:"
echo ""
echo "    SHARE_SUBDIR=$SUBDIR runlog ./sign-pevm.sh raw \\"
echo "      0x$(printf 'ab%.0s' {1..32})"
echo ""
echo "Read the 'wBDX signer : 0x...' line out of that run — that is the newSigner to pass to"
echo "bridge-contract/devnet/03-rotate-prep.sh. If that probe cannot produce a signature, do"
echo "NOT rotate: you would be handing the bridge to a key the committee cannot use."
