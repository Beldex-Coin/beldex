#!/usr/bin/env bash
#
# Deploy the wBDX contract to a local anvil, with the committee's Pevm DKG address as the
# mint signer. Part of the Phase L end-to-end mint loop (see README.md).
#
#   INITIAL_SIGNER=0x<pevm dkg address> ./deploy_anvil.sh
#
# Env (all optional except INITIAL_SIGNER):
#   CONTRACTS_DIR  path to the standalone bridge-contract project (default: ../../../../bridge-contract)
#   RPC            anvil endpoint (default: http://127.0.0.1:8545)
#   DEPLOYER_KEY   gas key (default: anvil account #0's well-known dev key)
#   ADMIN          the contract admin (default: anvil account #0 address; a TimelockController in prod)
#   WINDOW_MINT_CAP / PER_TX_MAX / BOND_BACKING_CAP_LIMIT / EPOCH_SECONDS / ROTATE_TIMELOCK
set -euo pipefail

: "${INITIAL_SIGNER:?set INITIAL_SIGNER to the Pevm DKG address printed by the signer's \`dkg\` run}"

# anvil account #0 — a well-known, value-less local dev key/address. NEVER use on a real chain.
DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
export ADMIN="${ADMIN:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
RPC="${RPC:-http://127.0.0.1:8545}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="${CONTRACTS_DIR:-$SCRIPT_DIR/../../../../bridge-contract}"

# Caps in 9-decimal wBDX units (1 unit == 1 atomic BDX). WINDOW_MINT_CAP <= BOND_BACKING_CAP_LIMIT.
export INITIAL_SIGNER
export WINDOW_MINT_CAP="${WINDOW_MINT_CAP:-1000000000000000}"     # 1,000,000 wBDX
export PER_TX_MAX="${PER_TX_MAX:-100000000000000}"               # 100,000 wBDX
export BOND_BACKING_CAP_LIMIT="${BOND_BACKING_CAP_LIMIT:-1400000000000000}"
export EPOCH_SECONDS="${EPOCH_SECONDS:-86400}"
export ROTATE_TIMELOCK="${ROTATE_TIMELOCK:-172800}"

echo "Deploying wBDX to $RPC"
echo "  admin          : $ADMIN"
echo "  initial signer : $INITIAL_SIGNER   (Pevm committee address)"
echo "  contracts dir  : $CONTRACTS_DIR"
echo

cd "$CONTRACTS_DIR"
forge script script/Deploy.s.sol \
  --rpc-url "$RPC" \
  --private-key "$DEPLOYER_KEY" \
  --broadcast \
  --sig 'run()'

echo
echo "Note the 'WrappedBDX proxy' address above — that is your wBDX contract for the mint loop."
