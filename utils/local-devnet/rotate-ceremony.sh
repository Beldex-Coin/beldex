#!/usr/bin/env bash
# rotate-ceremony.sh — run the whole H.6 committee rotation, end to end, across both repos.
#
#     runlog ./rotate-ceremony.sh              # the full ceremony, steps 1-8
#     runlog ./rotate-ceremony.sh --from 5     # resume after a failure, without re-DKG'ing
#
# Every one of the eight steps in ROTATION_RUNBOOK.md already has a script. What did not
# exist until now is the ceremony: the thing that runs them in order, carries the 320- and
# 384-character preimages between the two repos without a human retyping them, and leaves
# one transcript behind. Both defects this project has hit in the rotation path so far —
# the `mv` onto a non-existent shares dir, and the zsh no-match glob — happened at those
# hand-run seams, not inside the bridge.
#
# WHAT THIS DOES NOT DO. It does not decide anything. Every judgement call the runbook
# leaves to a human is still left to a human, behind a gate:
#
#     before step 1  the DKG        — 15 minutes of committee time, new key material
#     before step 5  the activation — an on-chain, irreversible hand-off of the bridge
#     before step 7  the promotion  — moves the live share trees on every node's disk
#
# The gates ask for a literal "yes". Everything between them is checks and plumbing.
#
# WHAT IT ADDS over running the eight scripts by hand. Three assertions that no existing
# script makes, each of which turns a confusing downstream failure into a local one:
#
#   * the successor probe (step 2) must NOT recover to the address already in the contract.
#     If it does, the DKG produced the key that is already live and there is nothing to
#     rotate to — caught here, rather than as a "successor equals current signer" much later.
#   * the rotation signature (step 4) must recover to the OUTGOING key. sign-rotate.sh
#     honours SHARE_SUBDIR if it is set in your environment, and 04-rotate.sh checks the
#     digest but not the signer, so signing with shares-next by accident produces a
#     perfectly valid signature by the wrong key and fails as an opaque BadSigner on chain.
#   * the retired share tree (step 8) is discovered by DIFFING the shares-gen* directories
#     across the promotion, not by assuming it is shares-gen0. Assuming that is right
#     exactly once, on the first rotation.
#
# Env:
#   BRIDGE_DIR      the bridge-contract checkout      (default: ../../../bridge-contract)
#   RPC             the EVM node                      (default: http://127.0.0.1:8545)
#   KEYGEN          DKG generation number             (default: derived, see step 1)
#   HANDOFF_TXID    32-byte txid for the step-8 mint  (default: fresh random)
#   PROBE_BYTES     throwaway 32 bytes for step 2     (default: 0xabab…ab)
#   CEREMONY_YES=1  answer every gate "yes" — for unattended runs ONLY
#   CEREMONY_WORK   transcript directory              (default: ./.ceremony)

set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"

LOCAL="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL"

# Gate answers come from FD 3, bound to the terminal if there is one. Binding it once, up
# front, is what lets a gate print its body via a heredoc without that heredoc becoming the
# thing `read` consumes — an easy way to build a confirmation prompt that always answers
# itself with an empty line.
if ( : </dev/tty ) 2>/dev/null; then exec 3</dev/tty; else exec 3<&0; fi

# ===========================================================================================
# plumbing
# ===========================================================================================
BOLD=''; DIM=''; RED=''; YEL=''; GRN=''; OFF=''
if [ -t 1 ]; then BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[1;31m'; YEL=$'\033[1;33m'; GRN=$'\033[32m'; OFF=$'\033[0m'; fi

STEP_TITLE=""
say()  { printf '\n%s== %s%s\n' "$BOLD" "$*" "$OFF"; }
ok()   { printf '  %sok%s   %s\n' "$GRN" "$OFF" "$*"; }
note() { printf '  %s·%s    %s\n' "$DIM" "$OFF" "$*"; }
fail() {
  printf '\n%s!! %s%s\n' "$RED" "$*" "$OFF" >&2
  if [ -n "$STEP_TITLE" ]; then
    printf '\n   Failed during: %s\n' "$STEP_TITLE" >&2
    printf '   Nothing after this point has run. Fix the cause, then resume with\n\n' >&2
    printf '       runlog ./rotate-ceremony.sh --from %s\n\n' "$FAILED_AT" >&2
    printf '   Transcripts for the steps that did run: %s\n' "$WORK" >&2
  fi
  exit 1
}

banner() {
  printf '\n%s┌───────────────────────────────────────────────────────────────────────%s\n' "$BOLD" "$OFF"
  printf '%s│ STEP %s%s\n' "$BOLD" "$*" "$OFF"
  printf '%s└───────────────────────────────────────────────────────────────────────%s\n' "$BOLD" "$OFF"
}

# A gate is a stop, not a prompt. It states what is about to happen, what about it cannot be
# undone, and what the way back looks like if there is one — then waits for a literal "yes".
gate() {
  local title="$1" ans=""
  printf '\n%s┌─ GATE — %s%s\n' "$YEL" "$title" "$OFF"
  while IFS= read -r line; do printf '%s│%s %s\n' "$YEL" "$OFF" "$line"; done
  printf '%s└─%s\n' "$YEL" "$OFF"
  if [ "${CEREMONY_YES:-0}" = "1" ]; then
    printf '  %sCEREMONY_YES=1 — proceeding without asking.%s\n' "$DIM" "$OFF"
    return 0
  fi
  printf '  type %syes%s to proceed, anything else to stop: ' "$BOLD" "$OFF"
  read -r ans <&3 || ans=""
  printf '\n'
  if [ "$ans" != "yes" ]; then
    printf '  Stopped at the gate. Nothing in this step has run.\n'
    printf '  Resume later with:  runlog ./rotate-ceremony.sh --from %s\n\n' "$CURRENT_STEP"
    exit 3
  fi
}

lc()  { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
num() { printf '%s' "$1" | sed -n 's/^[^0-9]*\([0-9][0-9]*\).*/\1/p'; }
# The generated env files are KEY=VALUE and nothing else, but reading a specific key with
# sed rather than sourcing them keeps a file that has grown a new variable from silently
# rebinding something in here.
envget() { sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1; }
onchain() { cast call "$PROXY" "$1" ${2:+"$2"} --rpc-url "$RPC" 2>/dev/null; }

# Run a sub-script, showing its output and keeping a copy. pipefail makes the `if` see the
# script's status rather than tee's.
run_logged() {
  local log="$1"; shift
  "$@" 2>&1 | tee "$WORK/$log"
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'
}

# ===========================================================================================
# arguments
# ===========================================================================================
FROM="${FROM:-1}"
while [ $# -gt 0 ]; do
  case "$1" in
    --from)    FROM="${2:-}"; shift 2 ;;
    --from=*)  FROM="${1#--from=}"; shift ;;
    --yes)     CEREMONY_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "!! unknown argument: $1" >&2; echo "   try --help" >&2; exit 1 ;;
  esac
done
case "$FROM" in
  1|2|3|4|5|6|7|8) ;;
  *) echo "!! --from takes a step number 1-8, got '$FROM'" >&2; exit 1 ;;
esac

CURRENT_STEP="$FROM"
FAILED_AT="$FROM"

RPC="${RPC:-http://127.0.0.1:8545}"
BRIDGE_DIR="${BRIDGE_DIR:-$LOCAL/../../../bridge-contract}"
WORK="${CEREMONY_WORK:-$LOCAL/.ceremony}"
TESTDATA="$LOCAL/testdata"
PROBE_BYTES="${PROBE_BYTES:-0x$(printf 'ab%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32)}"

mkdir -p "$WORK"
STATE="$WORK/state"
[ -f "$STATE" ] || : > "$STATE"
state_put() { sed -i.bak "/^$1=/d" "$STATE" 2>/dev/null || true; rm -f "$STATE.bak"; printf '%s=%s\n' "$1" "$2" >> "$STATE"; }
state_get() { envget "$STATE" "$1"; }

# ===========================================================================================
# step 0 — preflight
#
# Everything here is cheap and read-only, and every one of these is a condition that would
# otherwise surface fifteen minutes into a DKG or, worse, halfway through an on-chain
# rotation. The gates below are meaningless if the operator is being asked to approve a
# ceremony that was never going to work.
# ===========================================================================================
banner "0 — preflight"
STEP_TITLE="preflight"

[ -d "$BRIDGE_DIR" ] || fail "no bridge-contract checkout at $BRIDGE_DIR
   Set BRIDGE_DIR=/path/to/bridge-contract."
BRIDGE="$(cd "$BRIDGE_DIR" && pwd)"
note "beldex local-devnet : $LOCAL"
note "bridge-contract     : $BRIDGE"
note "transcripts         : $WORK"

for f in dkg-next.sh sign-pevm.sh sign-rotate.sh promote-shares.sh; do
  [ -x "$LOCAL/$f" ] || fail "$LOCAL/$f is missing or not executable"
done
for f in 03-rotate-prep.sh 04-rotate.sh 05-mint-prep.sh 06-handoff-proof.sh; do
  [ -x "$BRIDGE/devnet/$f" ] || fail "$BRIDGE/devnet/$f is missing or not executable"
done
ok "all eight steps' scripts are present and executable"

command -v cast    >/dev/null || fail "cast not on PATH — install foundry, or fix \$HOME/.foundry/bin"
command -v forge   >/dev/null || fail "forge not on PATH"
command -v python3 >/dev/null || fail "python3 is needed (06-handoff-proof.sh normalises low-S with it)"
ok "cast, forge and python3 are on PATH"

# The signer's `dkg` and `sign` subcommands are behind `--features live-dkg`; a default
# `cargo build` compiles them out and the binary refuses at run time. Checked HERE, before
# the DKG gate, because the failure otherwise lands after you have already agreed to burn a
# generation number — and dkg-next.sh's empty-share-dir cleanup reports it as "not on the
# committee", which sends you to look at committee registration instead of at the build.
# The probe is the compiled-out branch's own error string: with the feature on it is absent.
SIGNER_BIN="${SIGNER:-}"
if [ -z "$SIGNER_BIN" ]; then
  for c in "$LOCAL/../../bridge/signer/target/debug/beldex-bridge-signer" \
           "$LOCAL/../../bridge/signer/target/release/beldex-bridge-signer"; do
    if [ -x "$c" ]; then SIGNER_BIN="$c"; break; fi
  done
fi
if [ -n "$SIGNER_BIN" ] && [ -f "$SIGNER_BIN" ]; then
  if LC_ALL=C grep -qa 'subcommand requires a build with `--features live-dkg`' "$SIGNER_BIN"; then
    fail "the signer at
     $SIGNER_BIN
   was built WITHOUT the DKG features, so its \`dkg\` and \`sign\` subcommands are stubs that
   refuse immediately. Every node would write no shares. Rebuild:

       cd $(cd "$LOCAL/../.." && pwd)
       cargo build -p beldex-bridge-signer --features live-dkg,live-pevm-dkg

   Nothing has run. No generation number has been spent."
  fi
  ok "the signer binary has the live DKG features compiled in"
fi

[ -f "$BRIDGE/devnet/mint.env" ] || fail "no $BRIDGE/devnet/mint.env — there is no deployment to rotate.
   This ceremony rotates an EXISTING bridge. It never runs 01-deploy.sh: a fresh deploy
   would install the ORIGINAL committee as initialSigner and every check downstream would
   pass while answering a different question."
PROXY="$(envget "$BRIDGE/devnet/mint.env" PROXY)"
CHAIN_ID="$(envget "$BRIDGE/devnet/mint.env" CHAIN_ID)"
[ -n "$PROXY" ] || fail "mint.env has no PROXY"
note "proxy               : $PROXY  (chain id ${CHAIN_ID:-?})"

cast block latest --rpc-url "$RPC" >/dev/null 2>&1 \
  || fail "no EVM node answering at $RPC — start anvil, or set RPC=…"
ok "EVM node is answering at $RPC"

CUR_SIGNER="$(lc "$(onchain 'currentSigner()(address)')")"
CUR_EPOCH="$(num "$(onchain 'keyEpoch()(uint64)')")"
PENDING="$(lc "$(onchain 'pendingSigner()(address)')")"
PAUSED="$(lc "$(onchain 'paused()(bool)' || echo unknown)")"
[ -n "$CUR_SIGNER" ] || fail "currentSigner() returned nothing — is $PROXY really the bridge on $RPC?"
note "currentSigner       : $CUR_SIGNER  (keyEpoch $CUR_EPOCH)"

case "$PENDING" in
  0x0000000000000000000000000000000000000000|"") ok "no rotation is already in flight" ;;
  *) fail "a rotation to $PENDING is ALREADY pending on chain.
   Proposing a second one from here would either be rejected or would replace a proposal
   somebody is part-way through. Resolve that one first — activate it, let it be vetoed,
   or investigate who proposed it — then start this ceremony over." ;;
esac

[ "$PAUSED" != "true" ] || fail "the contract is paused — step 8's mint would revert before
   it reached the signature check, so the hand-off could not be proved either way."

# Node liveness, using exactly the participant filter the signing scripts use, so this
# preflight and the real runs agree on who is on the mesh.
NODES=0
for d in "$TESTDATA"/beldex-127.0.0.1-*/; do
  [ -S "${d}devnet/beldexd.sock" ] && [ -f "${d}devnet/key_ed25519" ] || continue
  NODES=$(( NODES + 1 ))
done
[ "$NODES" -gt 0 ] || fail "no node under $TESTDATA has both a live beldexd.sock and a key_ed25519.
   The devnet is not up, so no DKG and no signing session can run."
HOLDERS=0
for f in "$TESTDATA"/beldex-127.0.0.1-*/devnet/shares/pevm-*.keyshare; do
  [ -f "$f" ] && HOLDERS=$(( HOLDERS + 1 ))
done
THRESHOLD="${BRIDGE_SIGNER_COMMITTEE_THRESHOLD:-4}"
note "devnet              : $NODES node(s) on the mesh, $HOLDERS holding a live pevm keyshare"
[ "$HOLDERS" -ge "$THRESHOLD" ] || fail "only $HOLDERS node(s) hold a share of the CURRENT key, and the
   threshold is $THRESHOLD. The outgoing committee cannot sign its own replacement, which
   leaves only the admin break-glass — the exact trust assumption H.6 exists to remove."
ok "the outgoing committee can still reach threshold ($HOLDERS >= $THRESHOLD)"

# --- the DKG generation number ------------------------------------------------------------
# It is not recorded on chain, so derive it two independent ways and require them to agree.
# A generation is the cggmp21 ExecutionId's domain separator: reusing one runs a second,
# different protocol under an identity the first already claimed.
#
#   from the archives : promote-shares.sh names each retired tree after the generation it
#                       retired, so k archives means generations 0..k-1 are spent and the
#                       live tree is generation k.
#   from the chain    : the original DKG was generation 0 and shipped as keyEpoch 1, and
#                       every rotation bumps both, so the live generation is keyEpoch - 1.
#
# Both therefore say the next free generation is the current keyEpoch. If they disagree,
# something happened outside this ceremony and guessing is the wrong move.
# Counted by distinct generation NAME, not by directory: every node has its own copy of
# each archived tree, so counting directories would multiply the answer by the committee size.
ARCH_NAMES="$(ls -d "$TESTDATA"/beldex-127.0.0.1-*/devnet/shares-gen* 2>/dev/null \
              | sed 's#.*/##' | sort -u | tr '\n' ' ' || true)"
ARCH_N=0
for a in $ARCH_NAMES; do ARCH_N=$(( ARCH_N + 1 )); done

GEN_FROM_ARCHIVES=$(( ARCH_N + 1 ))
GEN_FROM_CHAIN="$CUR_EPOCH"

if [ -n "${KEYGEN:-}" ]; then
  note "DKG generation      : $KEYGEN  (from KEYGEN in the environment — derivation not used)"
elif [ "$GEN_FROM_ARCHIVES" = "$GEN_FROM_CHAIN" ]; then
  KEYGEN="$GEN_FROM_CHAIN"
  ok "next DKG generation is $KEYGEN (archives and keyEpoch agree)"
  note "archives: ${ARCH_NAMES:-none} -> live generation $(( GEN_FROM_ARCHIVES - 1 ))"
else
  fail "cannot derive the DKG generation number: the share archives say the next free one is
   $GEN_FROM_ARCHIVES (archives: ${ARCH_NAMES:-none}), the chain's keyEpoch $CUR_EPOCH says $GEN_FROM_CHAIN.
   Reusing a generation number runs a different protocol under an identity an earlier one
   already claimed, so this is not a number to guess at. Check .debug/history for what the
   previous DKGs actually used and re-run with KEYGEN=<n> set explicitly."
fi
[ "$KEYGEN" != "0" ] || fail "generation 0 is what the ORIGINAL DKG used — pick 1 or higher."

state_put KEYGEN "$KEYGEN"
state_put PROXY "$PROXY"
state_put OUTGOING_SIGNER "$CUR_SIGNER"
state_put OUTGOING_EPOCH "$CUR_EPOCH"

if [ "$FROM" -ne 1 ]; then
  printf '\n  %sresuming at step %s%s — steps 1..%s will be skipped, their results read off disk\n' \
    "$BOLD" "$FROM" "$OFF" "$(( FROM - 1 ))"
fi

# ===========================================================================================
# step 1 — the DKG
# ===========================================================================================
step1() {
  banner "1 — fresh Pevm DKG into devnet/shares-next"
  STEP_TITLE="step 1, the DKG"; FAILED_AT=1

  local existing
  existing="$(ls "$TESTDATA"/beldex-127.0.0.1-*/devnet/shares-next/pevm-*.keyshare 2>/dev/null | wc -l | tr -d ' ' || true)"
  if [ "$existing" -ne 0 ]; then
    gate "shares-next already holds $existing keyshare(s)" <<EOF
A previous DKG has already written a successor tree. It is either the one this ceremony
is resuming, or the target of a rotation that is still in flight somewhere.

Answering "yes" REUSES it and skips the DKG entirely — which is what you want when you
are resuming a ceremony whose later steps failed.

If you actually want a fresh key, stop, remove those trees by hand, and start again.
Nothing here will overwrite share material.
EOF
    ok "reusing the existing devnet/shares-next"
    return 0
  fi

  gate "run a fresh Pevm DKG, generation $KEYGEN" <<EOF
This runs a whole new CGGMP21 keygen across all $NODES devnet node(s), into
devnet/shares-next. cggmp21 0.6.3 has no threshold key refresh, so this is what
"rotate the committee key" means.

  cost        : slow — the timeout is ${BRIDGE_SIGNER_DKG_TIMEOUT_SECS:-900}s and a Pevm DKG plus aux-info uses it
  writes      : devnet/shares-next on each node  (devnet/shares is NOT touched)
  reversible  : yes, up to a point — nothing on chain moves, and the CURRENT key keeps
                signing. But generation $KEYGEN is spent either way: a second attempt must
                use $(( KEYGEN + 1 )), because an ExecutionId may not be reused.

The current committee stays live and in the contract throughout.
EOF

  if ! run_logged "01-dkg.log" "$LOCAL/dkg-next.sh" "$KEYGEN"; then
    # Whether the generation is spent depends on whether the protocol ever STARTED. A signer
    # that refused at the door -- wrong build, bad config, off the committee -- never derived
    # an ExecutionId, so $KEYGEN is still free, and telling you to skip it burns a generation
    # per attempt for no reason.
    #
    # The polarity matters: "spent" is the safe claim (it costs a number) and "not spent" is
    # the dangerous one (it invites reusing an ExecutionId). So default to spent, and only
    # say otherwise on positive evidence that EVERY node refused before the first round.
    local f total=0 refused=0
    for f in "$TESTDATA"/dkg-next-*.log; do
      [ -f "$f" ] || continue
      total=$(( total + 1 ))
      grep -qE 'requires a build with|configuration error|missing env|not on the current bridge committee' \
        "$f" 2>/dev/null && refused=$(( refused + 1 ))
    done
    if [ "$total" -gt 0 ] && [ "$refused" -eq "$total" ]; then
      fail "the DKG failed before the protocol started — see $WORK/01-dkg.log and the last line
   of each testdata/dkg-next-*.log, which names the refusal.
   Nothing has changed on chain and devnet/shares is untouched. No node got as far as
   deriving an ExecutionId, so generation $KEYGEN is NOT spent — fix the cause and re-run
   this same ceremony."
    fi
    fail "the DKG failed — see $WORK/01-dkg.log and testdata/dkg-next-*.log.
   Nothing has changed on chain and devnet/shares is untouched, so the bridge is exactly
   where it was. At least one node got past the door, so treat generation $KEYGEN as claimed
   and retry with $(( KEYGEN + 1 )): an ExecutionId may not be reused."
  fi

  local n
  n="$(ls "$TESTDATA"/beldex-127.0.0.1-*/devnet/shares-next/pevm-*.keyshare 2>/dev/null | wc -l | tr -d ' ' || true)"
  [ "$n" -ge "$THRESHOLD" ] || fail "the DKG wrote only $n keyshare(s), below the threshold of $THRESHOLD.
   The successor committee could never reach threshold, so rotating to it would brick
   the bridge. devnet/shares is untouched; nothing on chain has moved."
  ok "$n node(s) hold a share of the successor key"
  state_put DKG_DONE "$KEYGEN"
}
skip1() { note "step 1 skipped — using the devnet/shares-next already on disk"; }

# ===========================================================================================
# step 2 — the successor's Ethereum address
#
# The DKG prints a 33-byte group key; 03-rotate-prep.sh needs a 20-byte Ethereum address.
# The signer derives and prints the address itself, so the way to get one is to have the
# incoming committee sign something throwaway. That doubles as the liveness check: a
# committee that cannot produce a signature is not one to hand a bridge to.
# ===========================================================================================
scrape_signer() {  # prefix -> the single address every node's log recovered to
  local prefix="$1" v n
  ls "$TESTDATA/$prefix-sign-"*.log >/dev/null 2>&1 || { printf ''; return 0; }
  v="$(grep -h 'wBDX signer' "$TESTDATA/$prefix-sign-"*.log 2>/dev/null \
       | sed 's/.*: *//' | tr -d ' \r' | tr 'A-Z' 'a-z' | sort -u || true)"
  n="$(printf '%s\n' "$v" | grep -c . || true)"
  [ "$n" -le 1 ] || fail "$prefix-sign-*.log recovers to $n DIFFERENT addresses:
$(printf '     %s\n' $v)
   The nodes are not holding shares of one key."
  printf '%s' "$v"
}

step2() {
  banner "2 — successor address, and a liveness probe of the new committee"
  STEP_TITLE="step 2, the successor probe"; FAILED_AT=2

  ( export SHARE_SUBDIR=shares-next LOG_PREFIX=probe
    run_logged "02-probe.log" "$LOCAL/sign-pevm.sh" raw "$PROBE_BYTES" ) \
    || fail "the incoming committee could not produce a signature — see $WORK/02-probe.log.
   Do NOT rotate to this key. A committee that cannot sign now cannot sign later either,
   and once the contract points at it the only way back is the admin break-glass."

  SUCCESSOR="$(scrape_signer probe)"
  [ -n "$SUCCESSOR" ] || fail "the probe produced no 'wBDX signer' line — see $WORK/02-probe.log"
  finish_step2
}
skip2() {
  SUCCESSOR="$(scrape_signer probe)"
  if [ -z "$SUCCESSOR" ]; then
    SUCCESSOR="$(lc "$(envget "$BRIDGE/devnet/rotate.env" NEW_SIGNER)")"
    [ -n "$SUCCESSOR" ] || fail "step 2 was skipped but the successor address cannot be recovered:
   no probe-sign-*.log in $TESTDATA and no NEW_SIGNER in $BRIDGE/devnet/rotate.env.
   Re-run from step 2."
    note "successor read from rotate.env (no probe logs on disk): $SUCCESSOR"
  else
    note "successor read from the probe logs still in testdata: $SUCCESSOR"
  fi
  finish_step2
}
finish_step2() {
  # The check no existing script makes. A successor equal to the live key means the DKG
  # produced the key that is already in the contract — or, far more likely, that the probe
  # signed with the default `shares` tree because SHARE_SUBDIR did not reach it.
  # ...but "successor == live key" has two very different causes, and saying the wrong one
  # sends you looking in the wrong place. If rotate.env names this exact key as the rotation
  # target, the contract holding it means the hand-off ALREADY HAPPENED — which is the normal
  # state a `--from 6/7/8` resume starts in, and a hard stop for anything earlier.
  if [ "$SUCCESSOR" = "$CUR_SIGNER" ] \
     && [ "$(lc "$(envget "$BRIDGE/devnet/rotate.env" NEW_SIGNER)")" = "$CUR_SIGNER" ]; then
    if [ "$FROM" -gt 5 ]; then
      ok "successor : $SUCCESSOR"
      note "the rotation to this key is already live on chain — resuming past the hand-off"
      state_put SUCCESSOR "$SUCCESSOR"
      return 0
    fi
    fail "this ceremony's rotation is ALREADY LIVE on chain — currentSigner is $CUR_SIGNER,
   which is the NEW_SIGNER in $BRIDGE/devnet/rotate.env, at keyEpoch $CUR_EPOCH.
   Steps 1-5 have nothing left to do, and re-proposing would be rejected as StaleEpoch.
   Resume the remaining work with  --from 6, or start a fresh ceremony (a new DKG) instead."
  fi
  if [ "$SUCCESSOR" = "$CUR_SIGNER" ]; then
    fail "the successor address IS the address already in the contract ($CUR_SIGNER).
   Either the probe signed with devnet/shares instead of devnet/shares-next, or the DKG
   did not produce a new key. Rotating to it would be a no-op dressed up as a hand-off.
   Check the 'share dir :' line in $WORK/02-probe.log."
  fi
  ok "successor : $SUCCESSOR"
  ok "it differs from the live signer, and the new committee can sign"
  state_put SUCCESSOR "$SUCCESSOR"
}

# ===========================================================================================
# step 3 — the rotation preimage
# ===========================================================================================
load_rotate_env() {
  local f="$BRIDGE/devnet/rotate.env"
  [ -f "$f" ] || fail "no $f — run step 3."
  ROTATE_PREIMAGE="$(envget "$f" ROTATE_PREIMAGE)"
  ROTATE_DIGEST="$(envget "$f" ROTATE_DIGEST)"
  NEW_SIGNER="$(lc "$(envget "$f" NEW_SIGNER)")"
  NEW_KEY_EPOCH="$(envget "$f" NEW_KEY_EPOCH)"
  OUTGOING="$(lc "$(envget "$f" OUTGOING_SIGNER)")"
  ROTATE_TIMELOCK="$(envget "$f" ROTATE_TIMELOCK)"
  [ -n "$ROTATE_PREIMAGE" ] && [ -n "$NEW_SIGNER" ] || fail "$f is missing ROTATE_PREIMAGE or NEW_SIGNER"
  [ "${#ROTATE_PREIMAGE}" -eq 322 ] \
    || fail "the rotation preimage in $f is $(( ${#ROTATE_PREIMAGE} - 2 )) hex chars, expected 320
   (5 ABI words / 160 bytes). Re-run step 3."
}

step3() {
  banner "3 — build the rotation preimage (03-rotate-prep.sh)"
  STEP_TITLE="step 3, the rotation preimage"; FAILED_AT=3

  ( export RPC="$RPC"
    run_logged "03-prep.log" "$BRIDGE/devnet/03-rotate-prep.sh" "$SUCCESSOR" ) \
    || fail "03-rotate-prep.sh failed — see $WORK/03-prep.log. Nothing on chain has moved."
  load_rotate_env
  [ "$NEW_SIGNER" = "$SUCCESSOR" ] \
    || fail "rotate.env names $NEW_SIGNER as the successor, but step 2 probed $SUCCESSOR."
  ok "preimage : 320 hex chars, digest $ROTATE_DIGEST"
  ok "epoch    : $CUR_EPOCH -> $NEW_KEY_EPOCH, challenge window ${ROTATE_TIMELOCK}s"
  state_put ROTATE_DIGEST "$ROTATE_DIGEST"
  state_put NEW_KEY_EPOCH "$NEW_KEY_EPOCH"
}
skip3() {
  load_rotate_env
  note "step 3 skipped — rotate.env on disk: successor $NEW_SIGNER, epoch $NEW_KEY_EPOCH"
  note "digest $ROTATE_DIGEST"
}

# ===========================================================================================
# step 4 — the OUTGOING committee signs its own replacement
#
# This is the signature that makes the hand-off self-authorizing rather than an admin
# action, so it must come from the key that is currently in the contract — the default
# `shares` tree. SHARE_SUBDIR is explicitly unset for this call: sign-rotate.sh execs
# sign-pevm.sh, which honours it from the ambient environment, and an operator who exported
# it during step 2 would otherwise have the INCOMING committee authorise itself.
# ===========================================================================================
step4() {
  banner "4 — the outgoing committee signs the rotation"
  STEP_TITLE="step 4, the rotation signature"; FAILED_AT=4

  ( unset SHARE_SUBDIR LOG_PREFIX SHARE_GLOB
    run_logged "04-sign-rotate.log" "$LOCAL/sign-rotate.sh" "$ROTATE_PREIMAGE" ) \
    || fail "the outgoing committee failed to sign — see $WORK/04-sign-rotate.log.
   Nothing on chain has moved. devnet/shares and devnet/shares-next are both intact."

  local signed_by
  signed_by="$(scrape_signer rotate)"
  [ -n "$signed_by" ] || fail "rotate-sign-*.log has no 'wBDX signer' line"
  # 04-rotate.sh checks that the signers agreed and that they signed the right DIGEST, but
  # not WHICH KEY signed. Signing with shares-next produces a valid signature over exactly
  # the right message by exactly the wrong key, which the contract rejects as BadSigner with
  # nothing in the output pointing at the cause.
  if [ "$signed_by" = "$(lc "$NEW_SIGNER")" ]; then
    fail "the rotation was signed by the INCOMING committee ($signed_by), not the outgoing one.
   That is the new committee authorising itself, which proves nothing and would be rejected
   on chain as BadSigner. Something exported SHARE_SUBDIR=shares-next into this shell.
   Nothing has been submitted; re-run from step 4."
  fi
  [ "$signed_by" = "$OUTGOING" ] \
    || fail "the rotation was signed by $signed_by, but the contract's currentSigner is $OUTGOING.
   Only the key currently in the contract can authorise its own replacement."
  ok "signed by the outgoing key $signed_by, over $ROTATE_DIGEST"
}
skip4() {
  ls "$TESTDATA"/rotate-sign-*.log >/dev/null 2>&1 \
    || fail "step 4 was skipped but there are no rotate-sign-*.log files in $TESTDATA.
   04-rotate.sh scrapes the committee's signature out of them. Re-run from step 4."
  note "step 4 skipped — rotate-sign-*.log already in testdata"
}

# ===========================================================================================
# step 5 — propose, cross the window, activate.  THE IRREVERSIBLE ONE.
# ===========================================================================================
step5() {
  banner "5 — propose, challenge window, activate (04-rotate.sh)"
  STEP_TITLE="step 5, the on-chain rotation"; FAILED_AT=5
  CURRENT_STEP=5

  gate "hand the bridge over, on chain" <<EOF
04-rotate.sh will now submit the rotation the outgoing committee signed, warp anvil past
the ${ROTATE_TIMELOCK}s challenge window, and activate it.

  from  : $OUTGOING   (keyEpoch $CUR_EPOCH)
  to    : $NEW_SIGNER   (keyEpoch $NEW_KEY_EPOCH)

After activation the contract accepts mints signed by the NEW key only. This cannot be
undone by re-running anything here: rotating back would need a fresh proposal signed by
the new committee, and a failed activation leaves the bridge pointing at a key whose
shares are still sitting in devnet/shares-next, not devnet/shares.

Do NOT reach for breakGlassSetSigner if this goes wrong. Routine use of it reintroduces
exactly the admin trust assumption H.6 exists to remove; it is a Phase-K recovery path,
not a ceremony step.

The share trees on disk are NOT touched by this — that is step 7, and it is gated too.
EOF

  ( export TESTDATA="$TESTDATA" RPC="$RPC"
    run_logged "05-rotate.log" "$BRIDGE/devnet/04-rotate.sh" ) \
    || fail "04-rotate.sh failed — see $WORK/05-rotate.log.
   Read that log before doing anything else: whether the bridge moved depends on HOW FAR
   it got. Check the live state with

       cast call $PROXY 'currentSigner()(address)' --rpc-url $RPC
       cast call $PROXY 'pendingSigner()(address)' --rpc-url $RPC

   A non-zero pendingSigner means the proposal landed but the activation did not; the
   challenge window is still running and the bridge is still on the OLD key."
  ok "04-rotate.sh completed"
}
skip5() { note "step 5 skipped — assuming the rotation is already activated on chain (step 6 checks)"; }

# ===========================================================================================
# step 6 — verify independently of 04-rotate.sh's own assertions
# ===========================================================================================
step6() {
  banner "6 — independent on-chain verification"
  STEP_TITLE="step 6, verification"; FAILED_AT=6

  local sgn epo pnd
  sgn="$(lc "$(onchain 'currentSigner()(address)')")"
  epo="$(num "$(onchain 'keyEpoch()(uint64)')")"
  pnd="$(lc "$(onchain 'pendingSigner()(address)')")"
  printf '  currentSigner : %s\n  keyEpoch      : %s\n  pendingSigner : %s\n' "$sgn" "$epo" "$pnd"

  [ "$sgn" = "$(lc "$NEW_SIGNER")" ] \
    || fail "currentSigner is $sgn, expected the successor $NEW_SIGNER.
   The rotation did not take. Do NOT run step 7 — promoting the share trees now would
   leave every node signing with a key the contract does not accept."
  [ "$epo" = "$NEW_KEY_EPOCH" ] || fail "keyEpoch is $epo, expected $NEW_KEY_EPOCH"
  case "$pnd" in
    0x0000000000000000000000000000000000000000|"") ;;
    *) fail "pendingSigner was not cleared: $pnd" ;;
  esac
  ok "the contract is on the successor key, at the successor epoch, with nothing pending"

  local rotated
  rotated="$(cast logs --rpc-url "$RPC" --address "$PROXY" \
    0x269f54be3fd9dae2b1922d245de433f65deabdfa03c28c5f202cba783c153ba4 \
    --from-block 0 2>/dev/null || true)"
  if printf '%s' "$rotated" | grep -qi "${NEW_SIGNER#0x}"; then
    ok "a Rotated event carries the successor address"
  else
    note "no Rotated log mentions $NEW_SIGNER — the state above is what matters, but this is worth a look"
  fi
  printf '%s\n' "$rotated" > "$WORK/06-rotated-events.log"
}
skip6() { note "step 6 skipped"; }

# ===========================================================================================
# step 7 — promote the share trees.  IRREVERSIBLE ON DISK.
# ===========================================================================================
gen_dirs() { ls -d "$TESTDATA"/beldex-127.0.0.1-*/devnet/shares-gen* 2>/dev/null | sed 's#.*/##' | sort -u || true; }

step7() {
  banner "7 — promote shares-next to the live tree (promote-shares.sh)"
  STEP_TITLE="step 7, the share promotion"; FAILED_AT=7
  CURRENT_STEP=7

  run_logged "07-promote-dryrun.log" "$LOCAL/promote-shares.sh" --dry-run \
    || fail "the dry run failed — see $WORK/07-promote-dryrun.log. Nothing was moved."

  gate "move the live share trees on every node" <<EOF
The contract is already on the new key. Every sign-* script still defaults to devnet/shares,
which now holds a key the contract will reject. This swap fixes that:

  devnet/shares       ->  devnet/shares-gen<N>   (retired, KEPT — never deleted)
  devnet/shares-next  ->  devnet/shares          (live)

The dry run above lists exactly which directories move. Share material cannot be
regenerated, which is why the retired tree is archived rather than removed, and why this
is a gate: a half-applied swap leaves some nodes signing with one key and some with
another, and the resulting threshold signature is garbage.
EOF

  local before after archive
  before=" $(gen_dirs | tr '\n' ' ') "
  run_logged "07-promote.log" "$LOCAL/promote-shares.sh" \
    || fail "the promotion failed — see $WORK/07-promote.log.
   Check each node's devnet/ directory by hand before retrying: some may have been swapped
   and some not. The contract is already on the new key, so the nodes that DID swap are the
   correct ones."
  after="$(gen_dirs)"

  # Discover the archive rather than assuming shares-gen0. That assumption is right exactly
  # once — on the first rotation — and silently wrong on every one after it, which would
  # make step 8's retired-committee signature come from the wrong generation.
  archive=""
  for a in $after; do
    case "$before" in *" $a "*) ;; *) archive="$a" ;; esac
  done
  [ -n "$archive" ] || fail "the promotion reported success but no NEW shares-gen* directory appeared.
   Step 8 needs the retired tree to have the old committee sign with it. Look at
   $WORK/07-promote.log and set ARCHIVE_DIR=shares-genN by hand if you can identify it."
  ARCHIVE="$archive"
  ok "retired tree archived as devnet/$ARCHIVE"
  state_put ARCHIVE "$ARCHIVE"

  # The runbook's own confirmation: the DEFAULT signing path must now recover to the key
  # the contract holds. Cheap, and it is the difference between "the files moved" and "the
  # nodes now sign as the committee the bridge trusts".
  # unset, not merely unspecified: this run's whole purpose is to exercise the DEFAULT path,
  # so a SHARE_SUBDIR inherited from the caller's shell would send it at the tree we just
  # promoted away from and turn the confirmation into a lie.
  ( unset SHARE_SUBDIR LOG_PREFIX SHARE_GLOB
    run_logged "07-confirm.log" "$LOCAL/sign-pevm.sh" raw "$PROBE_BYTES" ) \
    || fail "the default share tree cannot sign after the promotion — see $WORK/07-confirm.log"
  local now
  now="$(scrape_signer raw)"
  [ "$now" = "$(lc "$NEW_SIGNER")" ] \
    || fail "after the promotion the default tree signs as $now, but the contract holds $NEW_SIGNER.
   The wrong tree was promoted. Every sign-* run from here would be rejected on chain."
  ok "the default share tree now signs as $now — the key the contract holds"
}
skip7() {
  ARCHIVE="${ARCHIVE_DIR:-$(state_get ARCHIVE)}"
  if [ -z "$ARCHIVE" ]; then
    ARCHIVE="$(gen_dirs | sed 's/^shares-gen//' | sort -n | tail -1)"
    [ -n "$ARCHIVE" ] || fail "step 7 was skipped but there is no shares-gen* tree anywhere.
   Step 8 needs the retired committee to sign from it. Re-run from step 7, or set
   ARCHIVE_DIR=shares-genN."
    ARCHIVE="shares-gen$ARCHIVE"
    note "retired tree guessed as the highest-numbered archive: $ARCHIVE"
    note "(06-handoff-proof.sh fails loudly with 'Wrong share tree' if that guess is wrong)"
  else
    note "step 7 skipped — retired tree is devnet/$ARCHIVE"
  fi
}

# ===========================================================================================
# step 8 — prove the hand-off in both directions
# ===========================================================================================
step8() {
  banner "8 — both-directions proof (05-mint-prep.sh, two signing runs, 06-handoff-proof.sh)"
  STEP_TITLE="step 8, the both-directions proof"; FAILED_AT=8

  local txid
  txid="${HANDOFF_TXID:-}"
  if [ -z "$txid" ]; then
    # Resuming into a step 8 that failed part-way should reuse the txid it prepared. Resuming
    # into one that SUCCEEDED must not: that txid is spent, and 05-mint-prep.sh would refuse
    # the whole step rather than let leg B mint twice.
    txid="$(state_get HANDOFF_TXID)"
    if [ -n "$txid" ] \
       && [ "$(onchain 'processedDeposits(bytes32)(bool)' "$txid")" = "true" ]; then
      note "the txid from the last run is already spent — drawing a fresh one"
      txid=""
    fi
  fi
  if [ -z "$txid" ]; then
    txid="0x$(od -An -v -tx1 -N32 /dev/urandom | tr -d ' \n')"
  fi
  state_put HANDOFF_TXID "$txid"
  note "beldex txid for this proof: $txid"
  note "(a fresh one each ceremony; 05-mint-prep.sh refuses any that is already spent)"

  ( export RPC="$RPC"
    run_logged "08-mint-prep.log" "$BRIDGE/devnet/05-mint-prep.sh" "$txid" ) \
    || fail "05-mint-prep.sh refused — see $WORK/08-mint-prep.log.
   Read the refusal: every one of them is a condition that would make a green proof
   meaningless rather than merely inconclusive."

  local preimage digest live retired
  preimage="$(envget "$BRIDGE/devnet/mint2.env" PREIMAGE)"
  digest="$(envget "$BRIDGE/devnet/mint2.env" DIGEST)"
  live="$(lc "$(envget "$BRIDGE/devnet/mint2.env" LIVE_SIGNER)")"
  retired="$(lc "$(envget "$BRIDGE/devnet/mint2.env" RETIRED_SIGNER)")"
  [ "${#preimage}" -eq 386 ] \
    || fail "the mint preimage is $(( ${#preimage} - 2 )) hex chars, expected 384 (6 ABI words)"
  ok "one preimage, 384 hex chars, digest $digest"

  # Both committees sign the SAME preimage. That is the whole point: same tag, chain id,
  # contract, recipient, amount and txid, so the only variable between the accepted and the
  # rejected attempt is which key signed. Different LOG_PREFIXes because sign-pevm.sh clears
  # its own prefix's logs on entry, and the comparison needs both sets to survive.
  say "the promoted committee signs (devnet/shares)"
  ( unset SHARE_SUBDIR LOG_PREFIX
    run_logged "08-sign-new.log" "$LOCAL/sign-pevm.sh" mint "$preimage" ) \
    || fail "the promoted committee could not sign — see $WORK/08-sign-new.log"
  local by_new; by_new="$(scrape_signer mint)"
  [ "$by_new" = "$live" ] \
    || fail "the default tree signed as $by_new but the contract holds $live — wrong tree promoted."
  ok "signed by $by_new, the key the contract holds"

  say "the retired committee signs the same preimage (devnet/$ARCHIVE)"
  ( export SHARE_SUBDIR="$ARCHIVE" LOG_PREFIX=mint-old
    run_logged "08-sign-old.log" "$LOCAL/sign-pevm.sh" mint "$preimage" ) \
    || fail "the retired committee could not sign from devnet/$ARCHIVE — see $WORK/08-sign-old.log.
   Without a VALID signature from the retired key, leg A of the proof degenerates from
   'a good signature by the wrong key was rejected' to 'a bad signature was rejected',
   which is not the claim."
  local by_old; by_old="$(scrape_signer mint-old)"
  [ "$by_old" = "$retired" ] \
    || fail "devnet/$ARCHIVE signs as $by_old, but the retired committee is $retired.
   That is the wrong archive. Set ARCHIVE_DIR=shares-genN and re-run from step 8."
  ok "signed by $by_old, the retired key"
  [ "$by_old" != "$by_new" ] || fail "both runs recovered to the same address — one share tree signed twice"

  say "the proof"
  ( export TESTDATA="$TESTDATA"
    run_logged "08-handoff-proof.log" "$BRIDGE/devnet/06-handoff-proof.sh" ) \
    || fail "06-handoff-proof.sh failed — see $WORK/08-handoff-proof.log.
   The rotation itself is done and verified; it is the both-directions PROOF that did not
   complete. Nothing above needs redoing: fix the cause and re-run --from 8. Note that if
   the mint broadcast succeeded, $txid is now spent and step 8 will pick a fresh one."
  ok "hand-off proved in both directions"
  state_put PROOF_DONE 1
}
skip8() { note "step 8 skipped"; }

# ===========================================================================================
# run
# ===========================================================================================
for n in 1 2 3 4 5 6 7 8; do
  CURRENT_STEP="$n"
  if [ "$FROM" -le "$n" ]; then "step$n"; else "skip$n"; fi
done

# ===========================================================================================
# the record
#
# The ceremony's durable output is not the green tick, it is the set of values somebody can
# check later: which key, which generation, which digest, which archive. Written where the
# other env files live so it is next to the artefacts it describes.
# ===========================================================================================
RECORD="$BRIDGE/devnet/ceremony-gen${KEYGEN}.md"
FINAL_SIGNER="$(lc "$(onchain 'currentSigner()(address)')")"
FINAL_EPOCH="$(num "$(onchain 'keyEpoch()(uint64)')")"
GROUPKEY="$(od -An -v -tx1 < "$(ls "$TESTDATA"/beldex-127.0.0.1-*/devnet/shares/pevm-*.groupkey 2>/dev/null | head -1)" 2>/dev/null | tr -d ' \n' || true)"

cat > "$RECORD" <<EOF
# H.6 rotation — DKG generation $KEYGEN

Run by rotate-ceremony.sh. Every value below was read back off the chain or off disk
after the fact, not carried forward from the step that produced it.

| | |
|---|---|
| contract | \`$PROXY\` (chain id $CHAIN_ID) |
| outgoing signer | \`$OUTGOING\` (keyEpoch $CUR_EPOCH, DKG generation $(( KEYGEN - 1 ))) |
| incoming signer | \`$FINAL_SIGNER\` (keyEpoch $FINAL_EPOCH, DKG generation $KEYGEN) |
| incoming group key | \`0x$GROUPKEY\` |
| rotation digest | \`$ROTATE_DIGEST\` |
| challenge window | ${ROTATE_TIMELOCK}s |
| retired share tree | \`devnet/$ARCHIVE\` (retained on every node) |
| hand-off proof txid | \`$(state_get HANDOFF_TXID)\` |

The outgoing committee threshold-signed its own replacement; no admin key was used at any
point, and \`breakGlassSetSigner\` was not called. The retired committee's signature over the
step-8 mint preimage is valid — the signer's own ecrecover confirms it — and the contract
rejected it anyway with \`BadSigner()\`. That is the hand-off biting rather than a broken
signature, and it is the half of the claim that a moved pointer alone does not establish.

Transcripts: \`$WORK\`
EOF

say "CEREMONY COMPLETE"
printf '
  %s -> %s
  keyEpoch %s -> %s, DKG generation %s -> %s
  retired shares kept at devnet/%s on every node

  record      : %s
  transcripts : %s

' "$OUTGOING" "$FINAL_SIGNER" "$CUR_EPOCH" "$FINAL_EPOCH" "$(( KEYGEN - 1 ))" "$KEYGEN" \
  "$ARCHIVE" "$RECORD" "$WORK"
ls -1 "$WORK" | sed 's/^/    /'
echo ""
