#!/usr/bin/env bash
# promote-shares.sh — step 7 of the H.6 rotation: make the successor committee the LIVE one.
#
#   runlog ./promote-shares.sh            # promote shares-next -> shares
#   runlog ./promote-shares.sh --dry-run  # show what would move, touch nothing
#
# After the contract has activated the rotation, the bridge trusts the key that lives in
# devnet/shares-next. The signing scripts default to devnet/shares, so the trees have to be
# swapped or every subsequent sign-* run will sign with a key the contract no longer accepts.
#
# This exists as a script rather than a paste-into-your-terminal loop for two reasons:
#   * macOS defaults to zsh, where an unmatched glob is a hard error that aborts the command
#     (bash quietly passes the pattern through). A loop that is correct in one shell is broken
#     in the other. A file with a bash shebang has one, known shell.
#   * the swap is irreversible-ish and easy to half-do. Guards belong somewhere they can be
#     reviewed, not retyped.
#
# Env:
#   ARCHIVE   name for the retired tree (default: first free shares-gen<N>)
#   SUBDIR    the incoming tree (default shares-next)

set -euo pipefail
cd "$(dirname "$0")/testdata"

SUBDIR="${SUBDIR:-shares-next}"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

# `find`, not a glob: this has to give the same answer under bash and zsh, and under zsh a
# no-match glob raises an error rather than expanding to nothing. See the header.
has_shares() { [ -n "$(find "$1" -name 'pevm-*.keyshare' -print -quit 2>/dev/null)" ]; }
groupkey()   { od -An -v -tx1 < "$(find "$1" -name 'pevm-*.groupkey' -print -quit)" | tr -d ' \n'; }

# --- who actually has an incoming tree ---------------------------------------------------------
INCOMING=""
NONMEMBER=""
for d in beldex-127.0.0.1-*/devnet; do
  [ -d "$d" ] || continue
  if has_shares "$d/$SUBDIR"; then INCOMING="$INCOMING $d"
  elif [ -d "$d/$SUBDIR" ];   then NONMEMBER="$NONMEMBER $d"
  fi
done

if [ -z "$INCOMING" ]; then
  # Not an error. Re-running after a successful promotion is the most likely way to get here,
  # and it should read as "already done", not as a failure.
  echo "  nothing to promote — no node has keyshares in $SUBDIR."
  echo ""
  echo "── current state ─────────────────────────────────────────────────────"
  for d in beldex-127.0.0.1-*/devnet; do
    [ -d "$d" ] || continue
    printf '  %-26s' "${d%%/*}"
    for s in shares shares-gen0 shares-gen1 shares-gen2; do
      [ -d "$d/$s" ] || continue
      has_shares "$d/$s" && printf ' %s(%s)' "$s" "$(groupkey "$d/$s" | cut -c1-10)…" || printf ' %s(empty)' "$s"
    done
    echo ""
  done
  echo ""
  echo "  If you already ran this after activating the rotation, that is the expected result:"
  echo "  shares holds the new key, shares-gen0 the retired one. Confirm with"
  echo ""
  echo "      runlog ./sign-pevm.sh raw 0x$(printf 'ab%.0s' {1..32})"
  echo ""
  echo "  the 'wBDX signer' line must equal currentSigner() on chain."
  exit 0
fi

# --- the incoming committee must agree on one key ------------------------------------------------
# Promoting a tree the participants never converged on installs a key that cannot sign, and the
# only way back is the admin break-glass.
FIRST=""; MISMATCH=0; N=0
for d in $INCOMING; do
  f="$(find "$d/$SUBDIR" -name 'pevm-*.groupkey' -print -quit 2>/dev/null || true)"
  [ -n "$f" ] || { echo "!! $d/$SUBDIR has a keyshare but no group key — refusing." >&2; exit 1; }
  N=$(( N + 1 ))
  if [ -z "$FIRST" ]; then FIRST="$f"; continue; fi
  cmp -s "$FIRST" "$f" || MISMATCH=1
done
if [ "$MISMATCH" -ne 0 ]; then
  echo "!! participants disagree on the $SUBDIR group key — do NOT promote it." >&2
  exit 1
fi
NEWKEY="$(od -An -v -tx1 < "$FIRST" | tr -d ' \n')"

OLDKEY=""
for d in $INCOMING; do
  if has_shares "$d/shares"; then OLDKEY="$(groupkey "$d/shares")"; break; fi
done

if [ -n "$OLDKEY" ] && [ "$OLDKEY" = "$NEWKEY" ]; then
  echo "!! $SUBDIR holds the SAME group key as shares — there is nothing to rotate to." >&2
  echo "   Did dkg-next.sh actually run with a fresh keygen number?" >&2
  exit 1
fi

# --- pick an archive name that is not already taken -------------------------------------------------
# Name it after the DKG generation being retired. Never reuse a name: the old tree is the only
# record of what the previous committee was, and mv-ing onto an existing directory nests it
# instead of replacing it, which quietly buries the older one.
if [ -z "${ARCHIVE:-}" ]; then
  i=0
  while :; do
    taken=0
    for d in $INCOMING; do [ -e "$d/shares-gen$i" ] && taken=1; done
    [ "$taken" -eq 0 ] && break
    i=$(( i + 1 ))
  done
  ARCHIVE="shares-gen$i"
fi
for d in $INCOMING; do
  if [ -e "$d/$ARCHIVE" ]; then
    echo "!! $d/$ARCHIVE already exists — pick another name with ARCHIVE=..." >&2
    exit 1
  fi
done

echo "  incoming tree : $(printf '%-12s' "$SUBDIR") ($N node(s), group key 0x${NEWKEY:0:12}…)"
echo "  retiring to   : $(printf '%-12s' "$ARCHIVE") (group key 0x${OLDKEY:0:12}…)"
[ "$DRY" -eq 1 ] && echo "  MODE          : dry run, nothing will be moved"
if [ -n "$NONMEMBER" ]; then
  echo ""
  echo "  skipping (empty $SUBDIR — not on the bridge committee):"
  for d in $NONMEMBER; do echo "    ${d%%/*}"; done
fi
echo ""

# --- swap ------------------------------------------------------------------------------------------
for d in $INCOMING; do
  if ! [ -d "$d/shares" ]; then
    # A node that joined the committee at this rotation has an incoming tree but nothing to
    # retire. Moving it in is still correct; there is just no archive step.
    echo "  ${d%%/*}: no existing shares/ to archive (new committee member)"
    [ "$DRY" -eq 1 ] || mv "$d/$SUBDIR" "$d/shares"
    continue
  fi
  echo "  ${d%%/*}: shares -> $ARCHIVE, $SUBDIR -> shares"
  [ "$DRY" -eq 1 ] && continue
  mv "$d/shares" "$d/$ARCHIVE"
  mv "$d/$SUBDIR" "$d/shares"
done

if [ "$DRY" -eq 1 ]; then
  echo ""
  echo "  dry run complete — re-run without --dry-run to apply."
  exit 0
fi

echo ""
echo "── promoted ──────────────────────────────────────────────────────────"
echo "  $(printf '%-12s' shares) : 0x$NEWKEY"
echo "  $(printf '%-12s' "$ARCHIVE") : 0x$OLDKEY   (retained)"
echo ""
echo "  The retired tree is kept, not deleted: it is the only record of what the previous"
echo "  committee was, and share material cannot be regenerated."
echo ""
echo "Confirm the default signing path now uses the key the contract holds:"
echo ""
echo "    runlog ./sign-pevm.sh raw 0x$(printf 'ab%.0s' {1..32})"
echo ""
echo "The 'wBDX signer' line must equal currentSigner() on chain."
