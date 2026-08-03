#!/usr/bin/env bash
# mine.sh — mine devnet blocks on demand, or keep mining in the background.
#
#     runlog ./mine.sh 20            # mine 20 blocks, wait for them, exit
#     ./mine.sh loop &               # keep the chain moving (Ctrl-C / kill to stop)
#
# WHY THIS EXISTS: the devnet harness (master_node_network.py) mines only when its `mine()`
# is called; after it prints "Use Ctrl-C to exit..." **nothing mines**. A submitted tx then
# sits in the mempool forever and balances never confirm. Worse for bridge testing, a gateway
# deposit only becomes a mint duty once it is past CHECKPOINT FINALITY (height <=
# get_info.immutable_height), which needs a steady supply of new blocks — so during a
# round-trip run you want `./mine.sh loop &` going the whole time.
#
# Env:
#   RPC          daemon RPC base (default http://127.0.0.1:19191)
#   MINER_ADDR   address to mine to (default: auto — the devnet wallet with a balance)
#   BATCH        blocks per burst in loop mode (default 2)
#   INTERVAL     seconds between bursts in loop mode (default 20)

set -euo pipefail
cd "$(dirname "$0")"

RPC="${RPC:-http://127.0.0.1:19191}"
BATCH="${BATCH:-2}"
INTERVAL="${INTERVAL:-20}"

height() { curl -s "$RPC/get_height" | sed -n 's/.*"height": *\([0-9]*\).*/\1/p'; }
pool_count() {
  curl -s "$RPC/get_transaction_pool" \
    | tr ',' '\n' | grep -c '"id_hash"' || true
}

# --- resolve a miner address ---------------------------------------------------------------
# Any valid devnet address works (the coinbase just has to go somewhere). Default to the
# first devnet wallet that reports a balance — that is Mike, the harness's mining wallet.
if [ -z "${MINER_ADDR:-}" ]; then
  for p in $(ls -d testdata/wallet-127.0.0.1-* 2>/dev/null | grep -v stderr | sed 's/.*-//' | sort -n); do
    addr=$(curl -s "http://127.0.0.1:$p/json_rpc" -H 'Content-Type: application/json' \
           -d '{"jsonrpc":"2.0","id":"0","method":"get_address","params":{"account_index":0}}' \
           | sed -n 's/.*"address": *"\([^"]*\)".*/\1/p' | head -1)
    bal=$(curl -s "http://127.0.0.1:$p/json_rpc" -H 'Content-Type: application/json' \
          -d '{"jsonrpc":"2.0","id":"0","method":"get_balance","params":{"account_index":0}}' \
          | sed -n 's/.*"balance": *\([0-9]*\).*/\1/p' | head -1)
    if [ -n "$addr" ] && [ -n "${bal:-}" ] && [ "$bal" -gt 0 ] 2>/dev/null; then
      MINER_ADDR="$addr"; break
    fi
    [ -n "$addr" ] && [ -z "${FALLBACK:-}" ] && FALLBACK="$addr"
  done
  MINER_ADDR="${MINER_ADDR:-${FALLBACK:-}}"
fi
if [ -z "${MINER_ADDR:-}" ]; then
  echo "!! could not resolve a miner address — is the devnet (and its wallet-rpc) up?" >&2
  echo "   pass one explicitly:  MINER_ADDR=<devnet address> $0 10" >&2
  exit 1
fi

mine_burst() {
  local n="$1" start end
  start="$(height)"
  curl -s "$RPC/start_mining" -H 'Content-Type: application/json' \
    -d "{\"miner_address\":\"$MINER_ADDR\",\"threads_count\":1,\"num_blocks\":$n,\"slow_mining\":true}" \
    > /dev/null
  # Wait for the burst to finish (the daemon stops itself after num_blocks).
  local waited=0
  while [ "$(curl -s "$RPC/mining_status" | sed -n 's/.*"active": *\([a-z]*\).*/\1/p')" = "true" ]; do
    sleep 1
    waited=$((waited + 1))
    # RandomX in the interpreter (MONERO_RANDOMX_UMASK=8 on Apple Silicon) is slow;
    # 120s per burst is generous but not infinite.
    if [ "$waited" -gt 120 ]; then
      echo "  (burst still running after ${waited}s — leaving it)" >&2
      break
    fi
  done
  end="$(height)"
  echo "  height $start → $end   (txpool: $(pool_count))"
}

case "${1:-10}" in
  loop)
    echo "mining to $MINER_ADDR — $BATCH block(s) every ${INTERVAL}s (Ctrl-C to stop)"
    while true; do
      mine_burst "$BATCH"
      sleep "$INTERVAL"
    done
    ;;
  ''|*[!0-9]*)
    echo "usage: $0 <blocks> | loop" >&2
    exit 1
    ;;
  *)
    echo "mining $1 block(s) to $MINER_ADDR"
    mine_burst "$1"
    ;;
esac
