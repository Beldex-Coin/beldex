#!/usr/bin/env python3
"""External signer for Beldex gateway withdrawals (HF22).

`gateway_create_transfer` returns an UNSIGNED tx blob plus a `hash_to_sign`.
This script parses that blob itself, recomputes the hash locally, prints what
the withdrawal actually does, and only then signs it.

The recomputation is the entire point. A gateway input carries no key image, so
the owner signature is the only thing standing between an attacker and the
gateway balance. A compromised daemon can hand back a hash that does not match
the blob it showed you; a signer that blind-signs the RPC's `hash_to_sign` can
be tricked into authorizing arbitrary theft. So: never sign a bare hash, and
always check the printed summary (and ideally --expect-* flags) against what you
intended before answering the confirmation prompt.

The signing message is
    hash_to_sign = keccak256("gateway_input_sig" || genesis_hash || prefix_hash)
where prefix_hash = keccak256(serialized tx prefix). genesis_hash binds the
signature to one chain: without it a testnet withdrawal would replay on mainnet
wherever the same gateway exists. Pass it with --genesis-hash, pinned
out-of-band -- fetching it from the daemon you are defending against defeats the
purpose. Get it from a node you trust with:

    curl -s http://NODE/json_rpc -d '{"jsonrpc":"2.0","id":"0",
      "method":"getblockheaderbyheight","params":{"height":0}}' \
      -H 'Content-Type: application/json'

Typical use:

    gateway_create_transfer  ->  unsigned_tx_blob
    gateway_sign_withdraw.py --unsigned-tx-blob <hex> --genesis-hash <hex> \
        --key-type eddsa --secret-key-file owner.key \
        --expect-source <gwid> --expect-total-debit 1500000000000
    gateway_submit_transfer  <tx_blob> <signature>

Dependencies (only what your key type needs):
    pycryptodome  -- keccak (always; --verify-only needs nothing else)
    pynacl        -- schnorr and eddsa key types
    coincurve     -- eth key type
"""

import argparse
import os
import sys

# Domain separator from cryptonote_config.h (hashkey::GW_INPUT_SIG).
GW_INPUT_SIG = b"gateway_input_sig"

# Variant tags from cryptonote_basic.h. Gateway takes 0x4 in both variants.
TXIN_GEN = 0xFF
TXIN_TO_KEY = 0x2
TXIN_GATEWAY = 0x4
TXOUT_TO_KEY = 0x2
TXOUT_GATEWAY = 0x4

# gateway_owner_key_v / gateway_owner_sig_v alternative order.
KEY_TYPES = {0: "schnorr", 1: "eth", 2: "eddsa"}

NULL_AID = bytes(32)


class ParseError(Exception):
    pass


def keccak256(data):
    try:
        from Crypto.Hash import keccak
    except ImportError:
        sys.exit("need pycryptodome for keccak: pip install pycryptodome")
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ---- CryptoNote binary reader -------------------------------------------------
# Mirrors src/serialization: varints are LEB128, integral FIELDs are fixed-width
# little-endian, ENUM_FIELDs are varints, vectors are a varint count + elements,
# and a variant is a 1-byte tag + the alternative's fields.


class Reader:
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def byte(self):
        if self.pos >= len(self.buf):
            raise ParseError("truncated blob")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def take(self, n):
        if self.pos + n > len(self.buf):
            raise ParseError("truncated blob")
        b = self.buf[self.pos:self.pos + n]
        self.pos += n
        return b

    def varint(self):
        result = 0
        shift = 0
        while True:
            b = self.byte()
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                return result
            shift += 7
            if shift > 63:
                raise ParseError("varint overflow")


def parse_prefix(blob):
    """Walk the tx prefix, returning (facts, prefix_end).

    prefix_end is where the prefix stops, so keccak256(blob[:prefix_end]) is the
    prefix hash -- serializing the prefix alone produces these same leading
    bytes, so there is no need to re-serialize anything.
    """
    r = Reader(blob)

    version = r.varint()  # ENUM_FIELD(version)
    if version < 1 or version > 4:
        raise ParseError("unsupported tx version {}".format(version))
    if version >= 3:  # v3_per_output_unlock_times
        for _ in range(r.varint()):
            r.varint()  # output_unlock_times
        if version == 3:
            r.byte()  # is_state_change
    r.varint()  # unlock_time

    gateway_inputs = []
    for _ in range(r.varint()):
        tag = r.byte()
        if tag == TXIN_GEN:
            r.varint()  # height
        elif tag == TXIN_TO_KEY:
            r.varint()  # amount
            for _ in range(r.varint()):
                r.varint()  # key_offsets
            r.take(32)  # k_image
        elif tag == TXIN_GATEWAY:
            r.byte()  # version (uint8_t FIELD -> 1 raw byte)
            gw_addr = r.take(32)
            asset_id = r.take(32)
            amount = r.varint()
            gateway_inputs.append({"gateway_addr": gw_addr, "asset_id": asset_id, "amount": amount})
        else:
            raise ParseError("unknown txin variant tag 0x{:x}".format(tag))

    gateway_outputs = []
    stealth_outputs = 0
    for _ in range(r.varint()):
        r.varint()  # tx_out.amount
        tag = r.byte()
        if tag == TXOUT_TO_KEY:
            r.take(32)  # key
            stealth_outputs += 1
        elif tag == TXOUT_GATEWAY:
            r.byte()  # version
            gw_addr = r.take(32)
            asset_id = r.take(32)
            amount = r.varint()
            payment_id = r.varint()
            gateway_outputs.append({
                "gateway_addr": gw_addr, "asset_id": asset_id,
                "amount": amount, "payment_id": payment_id,
            })
        else:
            raise ParseError("unknown txout variant tag 0x{:x}".format(tag))

    r.take(r.varint())  # extra

    tx_type = r.varint() if version >= 4 else 0  # ENUM_FIELD(type)

    facts = {
        "version": version,
        "type": tx_type,
        "gateway_inputs": gateway_inputs,
        "gateway_outputs": gateway_outputs,
        "stealth_outputs": stealth_outputs,
    }
    return facts, r.pos


def summarize(blob, genesis_hash):
    """Independent equivalent of summarize_gateway_withdraw() + gateway_input_message().

    Enforces the same shape consensus does: exactly one native gateway input, no
    mixing of gateway and non-gateway inputs, and outputs all of one kind.
    """
    facts, prefix_end = parse_prefix(blob)

    gins = facts["gateway_inputs"]
    if not gins:
        raise ParseError("tx is not a gateway withdrawal (no gateway input)")
    if len(gins) > 1:
        raise ParseError("withdrawal has more than one gateway input")
    gin = gins[0]
    if gin["asset_id"] != NULL_AID:
        raise ParseError("gateway input asset must be native at HF22")

    gouts = facts["gateway_outputs"]
    if gouts and facts["stealth_outputs"]:
        raise ParseError("withdrawal mixes gateway and stealth outputs")

    prefix_hash = keccak256(blob[:prefix_end])
    hash_to_sign = keccak256(GW_INPUT_SIG + genesis_hash + prefix_hash)

    return {
        "source_gateway_id": gin["gateway_addr"],
        "total_debit": gin["amount"],
        "to_wallet": facts["stealth_outputs"] > 0,
        "gateway_dests": [(o["gateway_addr"], o["amount"]) for o in gouts],
        "stealth_outputs": facts["stealth_outputs"],
        "prefix_hash": prefix_hash,
        "hash_to_sign": hash_to_sign,
    }


# ---- signing ------------------------------------------------------------------


def sign_schnorr(msg32, sec):
    """Beldex-native ed25519 Schnorr, matching crypto::generate_signature.

        k = random scalar;  comm = k*G
        c = hash_to_scalar(prefix_hash || pub || comm)
        r = k - c*sec           (sc_mulsub)
        sig = c || r
    """
    try:
        from nacl import bindings as b
    except ImportError:
        sys.exit("need pynacl for the schnorr key type: pip install pynacl")
    if len(sec) != 32:
        sys.exit("schnorr secret key must be 32 bytes")
    if b.crypto_core_ed25519_scalar_reduce(sec + bytes(32)) != sec:
        sys.exit("schnorr secret key is not a reduced scalar")

    pub = b.crypto_scalarmult_ed25519_base_noclamp(sec)
    while True:
        # Uniform scalar mod l: reduce 64 uniform random bytes (bias is negligible).
        k = b.crypto_core_ed25519_scalar_reduce(os.urandom(64))
        comm = b.crypto_scalarmult_ed25519_base_noclamp(k)
        # hash_to_scalar = sc_reduce32(keccak(buf)); zero-extending the 32-byte
        # digest to 64 makes scalar_reduce agree with sc_reduce32.
        c = b.crypto_core_ed25519_scalar_reduce(keccak256(msg32 + pub + comm) + bytes(32))
        if c == bytes(32):
            continue
        r = b.crypto_core_ed25519_scalar_sub(k, b.crypto_core_ed25519_scalar_mul(c, sec))
        if r == bytes(32):
            continue
        return c + r


def sign_eth(msg32, sec):
    """secp256k1 ECDSA, 64-byte compact r||s.

    libsecp256k1 always emits low-S, which is what verify_eth_signature requires
    (EIP-2). That canonical form is consensus-critical here: with no key image, a
    malleated s -> -s would be a second valid txid paying out twice.
    """
    try:
        from coincurve import PrivateKey
    except ImportError:
        sys.exit("need coincurve for the eth key type: pip install coincurve")
    if len(sec) != 32:
        sys.exit("eth secret key must be 32 bytes")
    # sign_recoverable gives r||s||v; consensus wants the 64-byte r||s.
    return PrivateKey(sec).sign_recoverable(msg32, hasher=None)[:64]


def sign_eddsa(msg32, sec):
    """RFC-8032 Ed25519 over the 32-byte hash (libsodium crypto_sign_detached)."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        sys.exit("need pynacl for the eddsa key type: pip install pynacl")
    if len(sec) == 64:
        sec = sec[:32]  # libsodium sk is seed||pub; PyNaCl wants the seed
    elif len(sec) != 32:
        sys.exit("eddsa secret key must be 32 (seed) or 64 (libsodium) bytes")
    return SigningKey(sec).sign(msg32).signature


SIGNERS = {"schnorr": sign_schnorr, "eth": sign_eth, "eddsa": sign_eddsa}


# ---- cli ----------------------------------------------------------------------


def read_hex(value, name, length=None):
    try:
        raw = bytes.fromhex(value.strip())
    except ValueError:
        sys.exit("{} is not valid hex".format(name))
    if length is not None and len(raw) != length:
        sys.exit("{} must be {} bytes ({} hex chars)".format(name, length, length * 2))
    return raw


def main():
    ap = argparse.ArgumentParser(
        description="Verify and sign an unsigned Beldex gateway withdrawal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Two ways to supply what gets signed. The blob path is the safe one: it
    # recomputes hash_to_sign locally so you never trust the daemon's. The
    # --hash-to-sign path signs a bare 32-byte hash blindly -- use it only when
    # you have independently confirmed that hash matches the blob.
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--unsigned-tx-blob",
                     help="hex blob from gateway_create_transfer (or @file); hash is recomputed locally")
    src.add_argument("--hash-to-sign",
                     help="64-char hex hash to sign directly (BLIND: not verified against any blob)")
    ap.add_argument("--genesis-hash",
                    help="64-char hex genesis block hash of the target network, pinned out-of-band "
                         "(required with --unsigned-tx-blob)")
    ap.add_argument("--key-type", choices=sorted(SIGNERS),
                    help="owner key type; must match owner_key_type from the RPC")
    key = ap.add_mutually_exclusive_group()
    key.add_argument("--secret-key-file", help="file holding the owner secret key as hex")
    key.add_argument("--secret-key",
                     help="owner secret key as hex, directly on the command line "
                          "(convenient for dev/testnet; lands in shell history, so prefer "
                          "--secret-key-file for anything real)")
    ap.add_argument("--verify-only", action="store_true",
                    help="print the summary and hash, do not sign (no signing deps needed)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    ap.add_argument("--expect-hash", help="hash_to_sign the daemon reported; refuses to sign on mismatch")
    ap.add_argument("--expect-source", help="expected source gateway id (hex)")
    ap.add_argument("--expect-total-debit", type=int,
                    help="expected total debit in atomic units (Sum(amounts) + fee)")
    args = ap.parse_args()

    if args.hash_to_sign:
        # Direct mode: sign the given 32-byte hash as-is. No blob, so nothing can
        # be checked -- this is a blind signature over whatever you pass.
        if args.genesis_hash:
            sys.exit("--genesis-hash does not apply to --hash-to-sign (the hash is already final)")
        if args.expect_source or args.expect_total_debit is not None:
            sys.exit("--expect-source / --expect-total-debit need --unsigned-tx-blob to check against")
        hash_to_sign = read_hex(args.hash_to_sign, "hash-to-sign", 32)
        if args.expect_hash and read_hex(args.expect_hash, "expect-hash", 32) != hash_to_sign:
            sys.exit("refusing to sign: --hash-to-sign does not match --expect-hash")
        print("Direct hash signing (BLIND -- not verified against any tx blob)")
        print("  hash_to_sign   : {}".format(hash_to_sign.hex()))
        confirm_prompt = "Blind-sign this hash? [y/N] "
    else:
        blob_arg = args.unsigned_tx_blob
        if blob_arg.startswith("@"):
            with open(blob_arg[1:]) as f:
                blob_arg = f.read()
        blob = read_hex(blob_arg, "unsigned-tx-blob")
        if not args.genesis_hash:
            sys.exit("--genesis-hash is required with --unsigned-tx-blob")
        genesis = read_hex(args.genesis_hash, "genesis-hash", 32)

        try:
            s = summarize(blob, genesis)
        except ParseError as e:
            sys.exit("refusing to sign: {}".format(e))

        print("Gateway withdrawal")
        print("  source gateway : {}".format(s["source_gateway_id"].hex()))
        print("  total debit    : {} atomic (leaves this gateway, incl. fee)".format(s["total_debit"]))
        if s["to_wallet"]:
            print("  destinations   : {} stealth output(s) -- amounts hidden in commitments".format(
                s["stealth_outputs"]))
        else:
            for addr, amount in s["gateway_dests"]:
                print("  -> gateway     : {}  {} atomic".format(addr.hex(), amount))
            paid = sum(a for _, a in s["gateway_dests"])
            print("  implied fee    : {} atomic".format(s["total_debit"] - paid))
        print("  prefix hash    : {}".format(s["prefix_hash"].hex()))
        print("  hash_to_sign   : {}  (recomputed locally)".format(s["hash_to_sign"].hex()))

        # Compare against intent. A mismatch here is the compromised-daemon case.
        if args.expect_hash:
            if read_hex(args.expect_hash, "expect-hash", 32) != s["hash_to_sign"]:
                sys.exit("refusing to sign: daemon's hash_to_sign does not match the blob -- "
                         "the node may be lying about what you are signing")
            print("  daemon hash    : matches")
        if args.expect_source:
            if read_hex(args.expect_source, "expect-source", 32) != s["source_gateway_id"]:
                sys.exit("refusing to sign: source gateway is not the expected one")
        if args.expect_total_debit is not None and args.expect_total_debit != s["total_debit"]:
            sys.exit("refusing to sign: total debit is {}, expected {}".format(
                s["total_debit"], args.expect_total_debit))

        hash_to_sign = s["hash_to_sign"]
        confirm_prompt = "Sign this withdrawal? [y/N] "

    if args.verify_only:
        return
    if not args.key_type or not (args.secret_key_file or args.secret_key):
        sys.exit("--key-type and a key (--secret-key-file or --secret-key) are required to sign "
                 "(or use --verify-only)")

    if not args.yes:
        if input(confirm_prompt).strip().lower() not in ("y", "yes"):
            sys.exit("aborted")

    if args.secret_key_file:
        with open(args.secret_key_file) as f:
            sec = read_hex(f.read(), "secret key")
    else:
        sec = read_hex(args.secret_key, "secret key")

    sig = SIGNERS[args.key_type](hash_to_sign, sec)
    print()
    print("signature ({}): {}".format(args.key_type, sig.hex()))
    print("submit with: gateway_submit_transfer tx_blob=<the unsigned blob> signature={}".format(sig.hex()))


if __name__ == "__main__":
    main()
