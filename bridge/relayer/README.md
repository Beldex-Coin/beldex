# beldex-bridge-relayer (Phase I)

A **permissionless, keyless courier** for the Beldex Sovereign Bridge. It carries an
already-committee-signed wBDX payload to its destination EVM chain and pays gas to broadcast
it. It holds **no bridge key** and forges nothing — the authorizing signature is complete
before the relayer touches it, and the wBDX contract verifies it on-chain. Relayers are
therefore **never a trust component** (whitepaper §3.1): if every relayer disappears, any
user builds the same transaction from the signed payload and submits it themselves.

## What's here

```
src/abi.rs      byte-exact ABI calldata for mint(...) / rotateSigner(...) (selectors pinned)
src/payload.rs  RelayPayload (self-contained signed payload) + JSON codec + PreparedCall
src/submit.rs   TxSubmitter broadcast seam + a mock (real gas-key backend is a follow-on)
src/main.rs     `prepare` — emit the {chain_id, to, data} to broadcast
```

## Build & test

Standalone crate (like `bridge/signer/`):

```bash
cd bridge/relayer
cargo test
```

## Submit-your-own (the liveness guarantee)

`prepare` reads a signed payload and prints the exact call to broadcast — no bridge key, no
running service:

```bash
beldex-bridge-relayer prepare payload.json
# chain_id: 1
# to:       0x<wbdx contract>
# data:     0x96d66de0...        # mint(to, amount, beldexTxid, sig) calldata

# broadcast with any wallet / tooling, paying your own gas:
cast send 0x<contract> 0x<data> --rpc-url <chain rpc> --private-key <your gas key>
```

Payload JSON (produced by a signer, or hand-assembled):

```json
{ "kind": "mint", "contract": "<40hex>", "chain_id": 1, "to": "<40hex>",
  "amount": "1000", "beldex_txid": "<64hex>", "sig": "<130hex r‖s‖v>" }

{ "kind": "rotate", "contract": "<40hex>", "chain_id": 1,
  "new_signer": "<40hex>", "new_key_epoch": 7, "sig": "<130hex>" }
```

## Reference relayer (follow-on)

The automated service — watch for signed payloads, build+sign the outer EIP-1559 tx with a
funded gas key, `eth_sendRawTransaction`, and retry — plugs into the `TxSubmitter` seam
(`src/submit.rs`). It is deliberately not built here: it needs an EVM transaction library and
a funded key (deployment concerns), and it adds nothing to the trust model. The
`prepare`/`to_prepared` path already guarantees liveness without it.
