#!/usr/bin/env bash
# serve-live.sh — start the COORDINATED autonomous signer (`serve --live`) on exactly
# the signer-set nodes of the local devnet (bridge/test/e2e/AUTONOMOUS_ROUNDTRIP.md).
#
#     GATEWAY_ID=<64-char hex id> VIEW_SECRET=<64hex> RELEASE_GATEWAY=<gwB…|hex> \
#     WBDX=<0x…20-byte> EVM_RPC=http://127.0.0.1:8545 CHAIN_ID=31337 \
#     runlog ./serve-live.sh
#
# Which nodes run: by default EVERY node that holds dkg shares (each node dir's own
# devnet/shares/pgw-<i>.keypackage carries its committee index). Each duty's signing
# round runs among the session's canonical ACK set — the lowest t+1 committee indices
# that independently verified that duty — so more nodes serving just means more
# failover headroom. Set NODES=0,1,2 to start a subset (needs >= t+1 for liveness).
#
# Two devnet-only knobs this script sets for you, both of which a local chain needs and
# a real network does not — see the block above each in the launch env below:
#   * BRIDGE_SIGNER_BELDEX_CONFIRMATIONS — deposit finality on a chain that never
#     checkpoints (every devnet). Without it NO deposit can ever mint, silently.
#   * BRIDGE_SIGNER_SIGN_SIGNERS — lets committee indices >= t+1 start at all.
#
# Stop with:  pkill -f 'beldex-bridge-signer serve'
# Logs:       testdata/serve-<node>.log   (watch the `tick N: opened/acked/...` lines)

set -euo pipefail
cd "$(dirname "$0")"

# GATEWAY_ID must be the 32-byte HEX id, not the gwB… address: the signer parses it
# with parse_hex32 (bridge/signer/src/config.rs:127) and a base58 address dies at
# startup with "config key gateway_id is not 32-byte hex". simplewallet prints the
# hex next to the address at registration, on the `Gateway id  :` line.
: "${GATEWAY_ID:?set GATEWAY_ID (64-char hex gateway id — the gwB… address is rejected)}"
: "${VIEW_SECRET:?set VIEW_SECRET (64-char hex gateway view secret — decrypts A.5 memos)}"
# Single-gateway model (the intended one): one account registered as
#   register_gateway_address <view_secret> eddsa <Pgw group vk>
# receives deposits (id = view pubkey) AND pays releases (owner = threshold key),
# so RELEASE_GATEWAY defaults to GATEWAY_ID. Override only for a split setup.
# Unlike GATEWAY_ID this one accepts EITHER form — it is passed through as the RPC
# `source` field, and core_rpc_server.cpp:3771 tries get_gateway_address_from_str
# first and falls back to hex_to_type.
RELEASE_GATEWAY="${RELEASE_GATEWAY:-$GATEWAY_ID}"
: "${WBDX:?set WBDX (deployed WrappedBDX address, 0x…)}"
EVM_RPC="${EVM_RPC:-http://127.0.0.1:8545}"
CHAIN_ID="${CHAIN_ID:-31337}"
NODES="${NODES:-all}"          # which committee indices to start (default: all with shares)
THRESHOLD="${THRESHOLD:-4}"    # t+1, for the liveness warning below
RELEASE_FEE="${RELEASE_FEE:-100000000}"
START_HEIGHT="${START_HEIGHT:-0}"
POLL_SECS="${POLL_SECS:-5}"

# Deposit finality. The signer's production rule is `get_info.immutable_height` — the
# master-node checkpoint below which the chain cannot reorg. beldexd emits that field
# only when `db.get_immutable_checkpoint` succeeds (core_rpc_server.cpp), and a
# checkpointing quorum is only generated once the network has CHECKPOINT_QUORUM_SIZE
# active masternodes — 20 in a normal build (master_node_rules.h; the value is 5 only
# under BELDEX_ENABLE_INTEGRATION_TEST_HOOKS, i.e. -DBUILD_INTEGRATION=ON). This devnet
# runs 6, so it never checkpoints, the field is absent from every get_info, and the
# watcher's finality gate never opens: deposits confirm on chain, gateway_get_history is
# never called, and no mint duty is ever created — with no error in the serve log,
# because service.rs treats a poll error as transient. See DEVNET_FINALITY_BLOCKER.md.
#
# BRIDGE_SIGNER_BELDEX_CONFIRMATIONS=N falls back to `top_height - N` in exactly that
# case. It is a strict either/or, not a max: a daemon that DOES report a checkpoint
# ignores this outright, so it can never widen finality on a real network. Unset it
# (BELDEX_CONFIRMATIONS= ) to restore strict behaviour and watch the gate stay shut.
BELDEX_CONFIRMATIONS="${BELDEX_CONFIRMATIONS-10}"

# Startup signer-set gate. `build_live_signers` (main.rs) refuses to start a node whose
# committee index is not in BRIDGE_SIGNER_SIGN_SIGNERS, and the default when the variable
# is unset is `0..threshold` — so on a 6-of-4 devnet indices 4 and 5 die instantly with
#   serve: this node (4) is not in the signer set [0, 1, 2, 3]
# and this script then exits 1 with two dead children. That default is a leftover from the
# one-shot `sign` subcommand: under coordinated autonomy the participants of each signing
# round are the session's canonical ACK set, passed per duty into pgw_sign/pevm_sign — the
# LiveSigners.signers field is never read again after this check. Listing the whole
# committee here therefore only widens the startup gate; it does not change who signs, and
# it is what AUTONOMOUS_ROUNDTRIP.md §1 describes.
SIGN_SIGNERS="${SIGN_SIGNERS:-0,1,2,3,4,5}"

# Chain registry for the EVM watcher. The keys are exactly the ones
# evm_watcher.rs::parse_evm_chains reads: chain_id, contract, confirmations, rpc,
# per_tx_max, per_epoch_cap, and the optional start_block. Two traps here, both of
# which cost a devnet run:
#   * the endpoint key is `rpc`, NOT `rpc_url` — the wrong spelling aborts every
#     signer at startup with "chain[0]: missing/invalid `rpc`";
#   * unrecognised keys are silently dropped, so a typo'd or invented key (this
#     block used to carry an `epoch_blocks` that nothing ever read) looks applied
#     and is not. `start_block` is the real name for "skip ahead".
# Caps gate resolve_mint, not the contract — adjust to taste.
EVM_START_BLOCK="${EVM_START_BLOCK:-0}"
EVM_CHAINS=$(cat <<EOF
[{"chain_id":${CHAIN_ID},"rpc":"${EVM_RPC}","contract":"${WBDX}","confirmations":1,
  "per_epoch_cap":"1000000000000000","per_tx_max":"1000000000000000",
  "start_block":${EVM_START_BLOCK}}]
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
PIDS=()
for d in beldex-127.0.0.1-*/; do
  sock="$PWD/${d}devnet/beldexd.sock"; key="$PWD/${d}devnet/key_ed25519"
  share="$PWD/${d}devnet/shares"
  [ -S "$sock" ] && [ -f "$key" ] || continue

  # This node's committee index, from its own dkg share filename.
  # `|| true` is load-bearing: under `set -euo pipefail` the failing `ls` in this
  # command substitution aborts the whole script, so a node dir with no pgw share
  # killed the loop before the guard below could skip it — and every node after it
  # in glob order never started.
  idx=$(ls "$share"/pgw-*.keypackage 2>/dev/null | sed -E 's/.*pgw-([0-9]+)\.keypackage/\1/' | head -1) || true
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
  BRIDGE_SIGNER_SIGN_SIGNERS="$SIGN_SIGNERS" \
  BRIDGE_SIGNER_GATEWAY_ID="$GATEWAY_ID" \
  BRIDGE_SIGNER_GATEWAY_VIEW_SECRET="$VIEW_SECRET" \
  BRIDGE_SIGNER_BELDEX_START_HEIGHT="$START_HEIGHT" \
  BRIDGE_SIGNER_BELDEX_CONFIRMATIONS="$BELDEX_CONFIRMATIONS" \
  BRIDGE_SIGNER_EVM_CHAINS="$EVM_CHAINS" \
  BRIDGE_SIGNER_WATCH_POLL_SECS="$POLL_SECS" \
  BRIDGE_SIGNER_RELEASE_GATEWAY="$RELEASE_GATEWAY" \
  BRIDGE_SIGNER_RELEASE_FEE="$RELEASE_FEE" \
  BRIDGE_SIGNER_RELEASE_MAX_FEE="$RELEASE_FEE" \
    "$SIGNER" serve > "serve-${d%/}.log" 2>&1 &
  PIDS+=("$!:${d%/}")
  started=$((started + 1))
done

# Launching is not running. A bad GATEWAY_ID or a malformed BRIDGE_SIGNER_EVM_CHAINS
# kills every child within a second, and without this check the script still exits 0
# and reports "6 signer(s) serving" over six dead processes. Give them a moment, then
# ask the kernel rather than guessing from log text.
sleep 2
alive=0; dead=()
# `${PIDS[@]+...}` guard: under `set -u`, bash 3.2 — which is what /bin/bash is on
# macOS — treats "${EMPTY[@]}" as an unbound variable and aborts.
for entry in ${PIDS[@]+"${PIDS[@]}"}; do
  pid="${entry%%:*}"; node="${entry#*:}"
  if kill -0 "$pid" 2>/dev/null; then alive=$((alive + 1)); else dead+=("$node"); fi
done

echo
if [ "${#dead[@]}" -gt 0 ]; then
  echo "!! $alive of $started still alive after 2s — these exited immediately:"
  for node in ${dead[@]+"${dead[@]}"}; do
    echo "   $node: $(grep -v '^(no .env file' "serve-${node}.log" | head -2 | tr '\n' ' ')"
  done
  echo "   full output: testdata/serve-<node>.log"
  exit 1
fi

echo "$alive signer(s) serving (need >= $THRESHOLD observing the same event to sign)"
echo "watch:  tail -f testdata/serve-*.log"
echo "stop:   pkill -f 'beldex-bridge-signer serve'"
[ "$alive" -ge "$THRESHOLD" ] || \
  echo "!! only $alive started — below t+1=$THRESHOLD, duties will stay pending"
