#!/usr/bin/env python3
"""Off-node decoder for Beldex gateway bridge memos (HF22+).

A gateway deposit/withdrawal MAY carry a `tx_extra_gateway_bridge_memo` next to
its `tx_out_gateway` output: an encrypted `{chain_id, evm_addr}` pair, XOR'd
with a DH mask keyed to the gateway's identity (the same key the deposit's
`gateway_id` names, i.e. `gateway_addr` on-chain). Only someone holding the
gateway's secret key can recompute that mask and recover the plaintext.

The daemon NEVER handles that secret (mirrors `gateway_sign_withdraw.py`'s
owner-secret handling, and this codebase's broader "no owner secrets over RPC"
policy): this script fetches the transaction's raw `tx.extra` bytes via the
existing public `get_transactions` RPC (no secret sent), then does the DH
derivation and decryption entirely locally.

Fetches only `tx_extra_raw` -- not the whole tx -- via `get_transactions`, and
parses that blob itself. Scope note: this parser only understands a tx.extra
consisting of one `tx_extra_pub_key` followed by zero or more
`tx_extra_gateway_bridge_memo` entries, in that order -- which is exactly what
`construct_tx_with_tx_key`/`construct_gateway_withdraw_tx` produce for a
gateway deposit/withdrawal (no additional pubkeys, no legacy payment-id nonce
-- both are structurally excluded from gateway txs, see gateway_utils.cpp
validate_tx_gateway_operations_against_db). It is not a general tx_extra
parser and will refuse to guess past an unrecognized tag.

Typical use:

    gateway_decode_bridge_memo.py --node http://127.0.0.1:29091 \\
        --tx-hash <hex> --secret-key-file gateway_view.key

Dependencies:
    pycryptodome  -- keccak
    pynacl        -- ed25519 scalar/point arithmetic
"""

import argparse
import json
import struct
import sys
import urllib.request

# Domain separator from cryptonote_config.h (hashkey::GW_BRIDGE_MEMO_MASK).
GW_BRIDGE_MEMO_MASK = b"gateway_bridge_memo_mask"

TX_EXTRA_TAG_PUBKEY = 0x01
TX_EXTRA_TAG_GATEWAY_BRIDGE_MEMO = 0x7D

# Purely cosmetic: a decoded memo carries the destination chain's real EIP-155
# id, so decoding needs no table at all. This map only turns well-known ids into
# friendly names for display; an id that isn't listed decodes exactly the same
# and is simply shown as its number.
CHAIN_NAMES = {
    1: "ethereum",
    10: "optimism",
    56: "bsc",
    137: "polygon",
    250: "fantom",
    8453: "base",
    42161: "arbitrum",
    43114: "avalanche",
    97: "bsc-testnet",
    4002: "fantom-testnet",
    17000: "holesky",
    43113: "avalanche-fuji",
    80002: "polygon-amoy",
    84532: "base-sepolia",
    421614: "arbitrum-sepolia",
    11155111: "sepolia",
    11155420: "optimism-sepolia",
}


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


# ---- minimal tx_extra reader (see module docstring for the scope limit) ------


class Reader:
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def byte(self):
        if self.pos >= len(self.buf):
            raise ParseError("truncated tx_extra")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def take(self, n):
        if self.pos + n > len(self.buf):
            raise ParseError("truncated tx_extra")
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

    def eof(self):
        return self.pos >= len(self.buf)


def parse_tx_extra(blob):
    """Returns (tx_pub_key: bytes, memos: [{"output_index": int, "ciphertext": bytes}])."""
    r = Reader(blob)
    tx_pub_key = None
    memos = []
    while not r.eof():
        tag = r.byte()
        if tag == TX_EXTRA_TAG_PUBKEY:
            tx_pub_key = r.take(32)
        elif tag == TX_EXTRA_TAG_GATEWAY_BRIDGE_MEMO:
            version = r.byte()
            if version != 0:
                raise ParseError("unsupported gateway bridge memo version {}".format(version))
            output_index = r.varint()
            ciphertext = r.take(32)
            memos.append({"output_index": output_index, "ciphertext": ciphertext})
        else:
            raise ParseError(
                "unrecognized tx_extra tag 0x{:x} -- this is not a plain gateway "
                "deposit/withdrawal tx_extra (see module docstring)".format(tag))
    if tx_pub_key is None:
        raise ParseError("tx_extra has no tx_extra_pub_key -- cannot derive anything")
    return tx_pub_key, memos


# ---- DH derivation + decrypt ---------------------------------------------------


def generate_key_derivation(tx_pub_key, view_secret):
    """derivation = 8 * view_secret * tx_pub_key, matching crypto::generate_key_derivation."""
    try:
        from nacl import bindings as b
    except ImportError:
        sys.exit("need pynacl: pip install pynacl")
    if len(view_secret) != 32:
        sys.exit("secret key must be 32 bytes")
    point = b.crypto_scalarmult_ed25519_noclamp(view_secret, tx_pub_key)
    eight = bytes([8]) + bytes(31)
    return b.crypto_scalarmult_ed25519_noclamp(eight, point)


def write_varint(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def derivation_to_scalar(derivation, output_index):
    """h = sc_reduce32(keccak256(derivation || varint(output_index))), matching
    crypto::derivation_to_scalar. sc_reduce32 (narrow reduce) is emulated via the
    wide reducer by zero-extending to 64 bytes, same trick gateway_sign_withdraw.py
    uses for hash_to_scalar."""
    from nacl import bindings as b
    buf = derivation + write_varint(output_index)
    digest = keccak256(buf)
    return b.crypto_core_ed25519_scalar_reduce(digest + bytes(32))


def decrypt_memo(tx_pub_key, memo, view_secret):
    derivation = generate_key_derivation(tx_pub_key, view_secret)
    h = derivation_to_scalar(derivation, memo["output_index"])
    mask = keccak256(GW_BRIDGE_MEMO_MASK + h)
    plain = bytes(c ^ m for c, m in zip(memo["ciphertext"], mask))

    # Integrity check: bytes 28..31 must be zero (see encrypt_gateway_bridge_memo).
    if any(plain[28:32]):
        return None

    chain_id = struct.unpack("<Q", plain[0:8])[0]
    evm_addr = plain[8:28]
    return chain_id, evm_addr


# ---- RPC + CLI ------------------------------------------------------------------


def fetch_tx(node, tx_hash):
    """Returns (tx_extra bytes, vout list).

    vout is requested alongside tx_extra so each memo can be reported with the
    amount of the gateway output it is attached to. Gateway output amounts are
    PLAINTEXT on-chain (unlike stealth outputs), so this needs no secret and the
    node reveals nothing extra by returning them.
    """
    body = json.dumps({
        "jsonrpc": "2.0", "id": "0", "method": "get_transactions",
        "params": {"tx_hashes": [tx_hash], "tx_extra_raw": True, "decode_as_json": True},
    }).encode()
    req = urllib.request.Request(node.rstrip("/") + "/json_rpc", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        result = json.load(resp)
    if "error" in result:
        sys.exit("RPC error: {}".format(result["error"]))
    txs = result.get("result", {}).get("txs", [])
    if not txs:
        sys.exit("tx not found: {}".format(tx_hash))
    raw = txs[0].get("tx_extra_raw")
    if raw is None:
        sys.exit("node did not return tx_extra_raw (old daemon version?)")
    return bytes.fromhex(raw), txs[0].get("vout") or []


def gateway_output_amount(vout, output_index):
    """Plaintext amount of the tx_out_gateway at output_index, or None."""
    if output_index >= len(vout):
        return None
    gw = (vout[output_index].get("target") or {}).get("gateway")
    return gw.get("amount") if gw else None


def format_bdx(atomic):
    """Atomic units -> BDX (COIN = 1e9), matching the wallet's display."""
    return "{}.{:09d}".format(atomic // 10**9, atomic % 10**9)


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
        description="Decrypt gateway bridge memo(s) on a Beldex gateway tx.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--node", default="http://127.0.0.1:19091", help="daemon RPC base URL")
    ap.add_argument("--tx-hash", required=True, help="transaction hash (hex)")
    key = ap.add_mutually_exclusive_group(required=True)
    key.add_argument("--secret-key-file", help="file holding the gateway's secret key as hex")
    key.add_argument("--secret-key",
                     help="gateway secret key as hex, directly on the command line "
                          "(convenient for dev/testnet; lands in shell history, so prefer "
                          "--secret-key-file for anything real)")
    args = ap.parse_args()

    if args.secret_key_file:
        try:
            with open(args.secret_key_file) as f:
                key_hex = f.read()
        except OSError as e:
            sys.exit("cannot read --secret-key-file {}: {}\n"
                     "This must hold the gateway's view SECRET key as hex. The gateway id is the\n"
                     "registering wallet's view public key, so get it from that wallet with the\n"
                     "'viewkey' command and save the 'secret:' value, e.g.:\n"
                     "    echo <view_secret_hex> > {}"
                     .format(args.secret_key_file, e.strerror, args.secret_key_file))
    else:
        key_hex = args.secret_key
    sec = read_hex(key_hex, "secret key", 32)

    extra_blob, vout = fetch_tx(args.node, args.tx_hash)
    try:
        tx_pub_key, memos = parse_tx_extra(extra_blob)
    except ParseError as e:
        sys.exit("failed to parse tx_extra: {}".format(e))

    if not memos:
        print("no gateway bridge memos on this tx")
        return

    found = 0
    for memo in memos:
        result = decrypt_memo(tx_pub_key, memo, sec)
        if result is None:
            print("output[{}]: could not decrypt (wrong key, or not addressed to you)".format(
                memo["output_index"]))
            continue
        chain_id, evm_addr = result
        name = CHAIN_NAMES.get(chain_id, "unknown")
        amount = gateway_output_amount(vout, memo["output_index"])
        amount_str = "{} BDX".format(format_bdx(amount)) if amount is not None else "amount unavailable"
        found += 1
        print("output[{}]: {}  ->  evm_chain_id={} ({})  evm_addr=0x{}".format(
            memo["output_index"], amount_str, chain_id, name, evm_addr.hex()))

    if found == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
