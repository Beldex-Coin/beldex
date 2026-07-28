#!/usr/bin/env bash
# sign-rotate.sh — have the OUTGOING committee threshold-sign an H.6 rotation.
#
#   runlog ./sign-rotate.sh 0x<preimage-from-03-rotate-prep.sh>
#
# The preimage is abi.encode(ROTATE_TAG, chainid, wBDX, newKeyEpoch, newSigner) — 5 words,
# 160 bytes. Signed by the key that is CURRENTLY in the contract, over its existing
# shares; that is what makes the hand-off self-authorizing rather than an admin action.
#
# ─── getting a successor key first ───────────────────────────────────────────────────
# cggmp21 0.6.3 has no threshold key refresh, so the incoming committee's key comes from
# a whole fresh DKG, run into a SEPARATE share tree so the outgoing key survives to sign
# this rotation:
#
#   runlog ./dkg-next.sh 1        # 1 = key generation; must not repeat one already used
#
# The DKG writes devnet/shares-next and prints the 33-byte group key — but NOT an Ethereum
# address, which is what 03-rotate-prep.sh needs. Get the address by having the incoming
# committee sign something throwaway; the signer derives and prints the address itself:
#
#   SHARE_SUBDIR=shares-next runlog ./sign-pevm.sh raw 0x<any 32 bytes>
#
# and read the `wBDX signer : 0x...` line. That doubles as a liveness check: if the new
# committee cannot produce a signature, do not rotate to it.
#
#   bridge-contract/devnet/03-rotate-prep.sh <that-address>
#
# Losing the outgoing shares before this signature exists means the contract can only be
# repointed by the admin break-glass — which is precisely the trust assumption H.6 exists
# to avoid.

set -euo pipefail
exec "$(dirname "$0")/sign-pevm.sh" rotate "${1:-}"
