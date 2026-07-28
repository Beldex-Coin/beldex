#!/usr/bin/env bash
# sign-mint.sh — threshold-sign a REAL WrappedBDX mint preimage on the live devnet
# committee (C.3 `Pevm` leg, bound to the deployed contract / chain / amount / txid).
#
#     runlog ./sign-mint.sh 0x<abi-encoded mint preimage>
#
# The preimage comes from bridge-contract/devnet/01-deploy.sh, which prints it and
# stores it in devnet/mint.env. It is:
#     abi.encode(MINT_TAG, block.chainid, address(this), to, amount, beldexTxid)
#
# Requires: the devnet up with an ACTIVE bridge committee, and a prior `dkg` run
# (leg pevm or both) that persisted pevm-<i>.keyshare into $SHARE_DIR.

set -euo pipefail
cd "$(dirname "$0")"

PREIMAGE="${1:-}"
[ -n "$PREIMAGE" ] || { echo "usage: ./sign-mint.sh 0x<preimage hex>"; exit 1; }
PREIMAGE="${PREIMAGE#0x}"
case "$PREIMAGE" in *[!0-9a-fA-F]*) echo "preimage must be hex"; exit 1 ;; esac
[ $(( ${#PREIMAGE} % 2 )) -eq 0 ] || { echo "preimage hex must be even-length"; exit 1; }
# The mint tuple abi.encodes to exactly 6 words = 192 bytes. A 32-byte argument is
# almost always the *digest* (or a tx hash) pasted by mistake — the signer keccaks
# whatever it gets, so signing a digest produces keccak(digest) and the mint fails.
if [ "${#PREIMAGE}" -ne 384 ] && [ "${FORCE_PREIMAGE:-0}" != "1" ]; then
  echo "!! expected the 192-byte ABI-encoded mint tuple (384 hex chars), got $(( ${#PREIMAGE} / 2 )) bytes"
  echo "   use the 'preimage :' line from bridge-contract/devnet/01-deploy.sh"
  echo "   (or PREIMAGE=... from bridge-contract/devnet/mint.env)"
  echo "   override with FORCE_PREIMAGE=1 if you really mean it"
  exit 1
fi

cd testdata

SIGNER="${SIGNER:-$(git rev-parse --show-toplevel)/bridge/signer/target/debug/beldex-bridge-signer}"
[ -x "$SIGNER" ] || { echo "build first: cargo build --features live-dkg,live-pevm-dkg"; exit 1; }
ANY32=$(printf '11%.0s' {1..32})
# The C.3 dkg run persisted each node's material under its OWN data dir
# (<node>/devnet/shares), not one pooled directory — mirror that here.
N_SHARES=$(ls beldex-127.0.0.1-*/devnet/shares/pevm-*.keyshare 2>/dev/null | wc -l | tr -d ' ')
[ "$N_SHARES" -gt 0 ] || {
  echo "no <node>/devnet/shares/pevm-*.keyshare under $PWD"
  echo "run the C.3 dkg step first (BRIDGE_SIGNER_DKG_LEG=pevm, BRIDGE_SIGNER_SHARE_DIR per node)"
  exit 1; }

echo "preimage : ${#PREIMAGE} hex chars ($(( ${#PREIMAGE} / 2 )) bytes)"
echo "shares   : $N_SHARES nodes hold a pevm keyshare"

pkill -f beldex-bridge-signer 2>/dev/null || true
sleep 1
rm -f sign-*.log

for d in beldex-127.0.0.1-*/; do
  sock="$PWD/${d}devnet/beldexd.sock"; key="$PWD/${d}devnet/key_ed25519"
  share="$PWD/${d}devnet/shares"
  [ -S "$sock" ] && [ -f "$key" ] || continue
  BRIDGE_SIGNER_BELDEXD_RPC_URL="http://127.0.0.1:19191" \
  BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$sock" \
  BRIDGE_SIGNER_GATEWAY_ID="$ANY32" BRIDGE_SIGNER_SELF_MN_PUBKEY="$ANY32" \
  BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=120 BRIDGE_SIGNER_COMMITTEE_THRESHOLD=4 \
  BRIDGE_SIGNER_MN_KEY_FILE="$key" BRIDGE_SIGNER_MESH_PORT_BASE=6000 \
  BRIDGE_SIGNER_MESH_USE_CURVE=false BRIDGE_SIGNER_SHARE_DIR="$share" \
  BRIDGE_SIGNER_SIGN_LEG=pevm BRIDGE_SIGNER_SIGN_PREIMAGE="$PREIMAGE" \
  BRIDGE_SIGNER_SIGN_TIMEOUT_SECS="${BRIDGE_SIGNER_SIGN_TIMEOUT_SECS:-600}" \
    "$SIGNER" sign > "sign-${d%/}.log" 2>&1 &
done
wait

echo
echo "== results =="
if grep -qh "no BRIDGE_SIGNER_SIGN_PREIMAGE set" sign-*.log 2>/dev/null; then
  echo "!! a signer fell back to the DEMO preimage — the env var did not reach it"; exit 1
fi
grep -h "ecrecover" sign-*.log | sort | uniq -c
grep -h "wBDX signer" sign-*.log | sort | uniq -c
echo
grep -h "over digest" sign-*.log | sort -u
grep -h "^Pevm signature:" sign-*.log | sort -u

N_OK=$(grep -hc "ecrecover   : VERIFIED" sign-*.log 2>/dev/null | paste -sd+ - | bc)
echo
echo "signers that ecrecover'd to the wBDX address: ${N_OK:-0} (expect 4)"
echo "next: cd ~/Niyas/projects/bridge-contract && runlog ./devnet/02-mint.sh"
