#!/usr/bin/env bash
# serve-live.sh — start the COORDINATED autonomous signer (`serve --live`) on exactly
# the signer-set nodes of the local devnet (bridge/test/e2e/AUTONOMOUS_ROUNDTRIP.md).
#
#     GATEWAY_ID=<gwB…|hex> VIEW_SECRET=<64hex> RELEASE_GATEWAY=<gwB…> \
#     WBDX=<0x…20-byte> EVM_RPC=http://127.0.0.1:8545 CHAIN_ID=31337 \
#     runlog ./serve-live.sh
#
# Which nodes run: by default EVERY node that holds dkg shares (each node dir's own
# devnet/shares/pgw-<i>.keypackage carries its committee index). Each duty's signing
# round runs among the session's canonical ACK set — the lowest t+1 committee indices
# that independently verified that duty — so more nodes serving just means more
# failover headroom. Set NODES=0,1,2 to start a subset (needs >= t+1 for liveness).
#
# Stop with:  pkill -f 'beldex-bridge-signer serve'
# Logs:       testdata/serve-<node>.log   (watch the `tick N: opened/acked/...` lines)

set -euo pipefail
cd "$(dirname "$0")"

: "${GATEWAY_ID:?set GATEWAY_ID (bridge gateway gwB… address or 64-char hex id)}"
: "${VIEW_SECRET:?set VIEW_SECRET (64-char hex gateway view secret — decrypts A.5 memos)}"
# Single-gateway model (the intended one): one account registered as
#   register_gateway_address <view_secret> eddsa <Pgw group vk>
# receives deposits (id = view pubkey) AND pays releases (owner = threshold key),
# so RELEASE_GATEWAY defaults to GATEWAY_ID. Override only for a split setup.
RELEASE_GATEWAY="${RELEASE_GATEWAY:-$GATEWAY_ID}"
: "${WBDX:?set WBDX (deployed WrappedBDX address, 0x…)}"
EVM_RPC="${EVM_RPC:-http://127.0.0.1:8545}"
CHAIN_ID="${CHAIN_ID:-31337}"
NODES="${NODES:-all}"          # which committee indices to start (default: all with shares)
THRESHOLD="${THRESHOLD:-4}"    # t+1, for the liveness warning below
RELEASE_FEE="${RELEASE_FEE:-100000000}"
START_HEIGHT="${START_HEIGHT:-0}"
POLL_SECS="${POLL_SECS:-5}"

# Chain registry for the EVM watcher (mirror the schema `watch-evm` uses; adjust
# caps to taste — they gate resolve_mint, not the contract).
EVM_CHAINS=$(cat <<EOF
[{"chain_id":${CHAIN_ID},"rpc_url":"${EVM_RPC}","contract":"${WBDX}","confirmations":1,
  "per_epoch_cap":"1000000000000000","per_tx_max":"1000000000000000","epoch_blocks":100}]
EOF
)

cd testdata

SIGNER="${SIGNER:-$(git rev-parse --show-toplevel)/bridge/signer/target/debug/beldex-bridge-signer}"
[ -x "$SIGNER" ] || { echo "build first: cargo build -p beldex-bridge-signer --features serve-live"; exit 1; }
ANY32=$(printf '11%.0s' {1..32})

pkill -f 'beldex-bridge-signer serve' 2>/dev/null || true
sleep 1
rm -f serve-*.log

started=0
for d in beldex-127.0.0.1-*/; do
  sock="$PWD/${d}devnet/beldexd.sock"; key="$PWD/${d}devnet/key_ed25519"
  share="$PWD/${d}devnet/shares"
  [ -S "$sock" ] && [ -f "$key" ] || continue

  # This node's committee index, from its own dkg share filename.
  idx=$(ls "$share"/pgw-*.keypackage 2>/dev/null | sed -E 's/.*pgw-([0-9]+)\.keypackage/\1/' | head -1)
  [ -n "$idx" ] || { echo "skip ${d%/}: no pgw share (did dkg run here?)"; continue; }
  if [ "$NODES" != "all" ]; then
    case ",$NODES," in
      *",$idx,"*) ;;
      *) echo "skip ${d%/}: committee index $idx not in NODES={$NODES}"; continue ;;
    esac
  fi

  echo "start ${d%/}: committee index $idx"
  BRIDGE_SIGNER_SERVE_LIVE=1 \
  BRIDGE_SIGNER_BELDEXD_RPC_URL="http://127.0.0.1:19191" \
  BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$sock" \
  BRIDGE_SIGNER_SELF_MN_PUBKEY="$ANY32" \
  BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=120 BRIDGE_SIGNER_COMMITTEE_THRESHOLD=4 \
  BRIDGE_SIGNER_MN_KEY_FILE="$key" BRIDGE_SIGNER_SHARE_DIR="$share" \
  BRIDGE_SIGNER_MESH_PORT_BASE=6000 BRIDGE_SIGNER_MESH_PEVM_OFFSET=100 \
  BRIDGE_SIGNER_MESH_COORD_OFFSET=200 BRIDGE_SIGNER_MESH_USE_CURVE=false \
  BRIDGE_SIGNER_SIGN_TIMEOUT_SECS="${BRIDGE_SIGNER_SIGN_TIMEOUT_SECS:-600}" \
  BRIDGE_SIGNER_STAGE_TIMEOUT_TICKS=4 \
  BRIDGE_SIGNER_GATEWAY_ID="$GATEWAY_ID" \
  BRIDGE_SIGNER_GATEWAY_VIEW_SECRET="$VIEW_SECRET" \
  BRIDGE_SIGNER_BELDEX_START_HEIGHT="$START_HEIGHT" \
  BRIDGE_SIGNER_EVM_CHAINS="$EVM_CHAINS" \
  BRIDGE_SIGNER_WATCH_POLL_SECS="$POLL_SECS" \
  BRIDGE_SIGNER_RELEASE_GATEWAY="$RELEASE_GATEWAY" \
  BRIDGE_SIGNER_RELEASE_FEE="$RELEASE_FEE" \
  BRIDGE_SIGNER_RELEASE_MAX_FEE="$RELEASE_FEE" \
    "$SIGNER" serve > "serve-${d%/}.log" 2>&1 &
  started=$((started + 1))
done

echo
echo "$started signer(s) serving (need >= $THRESHOLD observing the same event to sign)"
echo "watch:  tail -f testdata/serve-*.log"
echo "stop:   pkill -f 'beldex-bridge-signer serve'"
[ "$started" -ge "$THRESHOLD" ] || \
  echo "!! only $started started — below t+1=$THRESHOLD, duties will stay pending"
