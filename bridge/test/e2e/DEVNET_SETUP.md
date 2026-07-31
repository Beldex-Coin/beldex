# Devnet Setup — from a fresh checkout to a hands-off round-trip

Step-by-step companion to `AUTONOMOUS_ROUNDTRIP.md`. Every value you need is either read out
of a file the tooling already wrote, or generated here — nothing is guessed.

Conventions: `$BLD` = the beldex repo root, `$BC` = the `bridge-contract` repo
(`~/Niyas/projects/bridge-contract`). The devnet's working tree is
`$BLD/utils/local-devnet/testdata/`, with one directory per node
(`beldex-127.0.0.1-<port>/`).

---

## 0. Build everything (once)

```bash
cd $BLD/build/Darwin/dkg-tss-implementation/release
cmake -D BUILD_TESTS=ON ../../../..
make beldexd beldex-wallet-rpc beldex-wallet-cli -j8

cd $BLD/bridge/signer
cargo build -p beldex-bridge-signer --features serve-live      # coordinated autonomy
cd $BLD/bridge/relayer
cargo build -p beldex-bridge-relayer --features submit-http    # gas-paying relayer
```

`serve-live` implies `live-dkg` + `live-pevm-dkg`, so this one binary also runs `dkg`/`sign`.

---

## 1. Start the devnet + anvil

```bash
cd $BLD/utils/local-devnet
source venv/bin/activate 2>/dev/null || true
python3 -c 'import master_node_network as m; m.run()'    # leave running; Ctrl-C to stop
```

Wait until it prints that nodes are synced and the bridge committee is active. The first
master node's RPC is pinned at **19191**; the rest are random.

In another shell:

```bash
anvil --chain-id 31337        # leave running
```

---

## 2. Dual DKG → this gives you `PGW_GROUP_VK`

Run the DKG across the committee (writes each node's shares under its own data dir):

```bash
cd $BLD/utils/local-devnet
runlog ./dkg-next.sh 0 2>/dev/null || true   # if you have no shares yet, see note below
```

> If `devnet/shares` doesn't exist yet, run the original C.2 DKG step you used before
> (`BRIDGE_SIGNER_DKG_LEG=both`, `BRIDGE_SIGNER_SHARE_DIR=<node>/devnet/shares`).
> `dkg-next.sh` deliberately refuses to write into `shares` — it exists for *rotations*.

After the DKG each participating node holds:

```
testdata/beldex-127.0.0.1-<port>/devnet/shares/
  pgw-<i>.keypackage  pgw-<i>.pubkeypackage  pgw-<i>.groupvk     ← Pgw (ed25519, FROST)
  pevm-<i>.keyshare   pevm-<i>.groupkey                          ← Pevm (secp256k1, CGGMP21)
```

### `PGW_GROUP_VK` — the committee's ed25519 group key (the gateway owner key)

It is written verbatim to `pgw-<i>.groupvk` (32 raw bytes, identical on every node):

```bash
cd $BLD/utils/local-devnet/testdata
PGW_GROUP_VK=$(od -An -v -tx1 < "$(ls beldex-127.0.0.1-*/devnet/shares/pgw-*.groupvk | head -1)" | tr -d ' \n')
echo "PGW_GROUP_VK=$PGW_GROUP_VK"

# Sanity: every node must agree, or they didn't complete the same DKG.
for f in beldex-127.0.0.1-*/devnet/shares/pgw-*.groupvk; do od -An -v -tx1 < "$f" | tr -d ' \n'; echo; done | sort -u | wc -l
# → must print 1
```

(The DKG also logs it: `Pgw DKG complete — group ed25519 key (gateway owner_key): <hex>`.)

### The `Pevm` address — the wBDX contract's initial signer

```bash
PEVM_ADDR=$(grep -h 'wBDX signer' ../*.log 2>/dev/null | head -1 | grep -o '0x[0-9a-f]*')
# or, definitively, probe it (also proves the committee can sign):
runlog ./sign-pevm.sh raw 0x$(printf 'ab%.0s' {1..32})   # read "wBDX signer : 0x…"
```

---

## 3. Deploy wBDX → this gives you `WBDX`

```bash
cd $BC
INITIAL_SIGNER=$PEVM_ADDR ADMIN=<timelock or an anvil address> ./devnet/01-deploy.sh
grep -i wbdx devnet/mint.env      # → WBDX=0x…  (the proxy address)
```

---

## 4. `view_secret_hex` — generate it, then register ONE gateway

The gateway's **id is its view public key**, so the secret you register with *is* the view
secret the signers use to decrypt A.5 memos. Generate a valid ed25519 scalar (pad the
most-significant byte — scalars are little-endian, so that's the last byte):

```bash
VIEW_SECRET=$(openssl rand -hex 31)00
echo "VIEW_SECRET=$VIEW_SECRET"        # SAVE THIS
```

One gateway serves **both legs** (deposits in, releases out) because the id key and the owner
key are independent. Register it with the committee's Pgw key as owner, and flag it as a
bridge reserve so consensus enforces the replay guard (§3.6).

You need a funded wallet. The devnet runs wallets under `beldex-wallet-rpc` (random ports);
`bridge_deposit` is a **CLI-only** command, so create a CLI wallet and fund it (§5), then:

```
[wallet]> register_gateway_address <VIEW_SECRET> eddsa <PGW_GROUP_VK> bridge_reserve
    (confirm the sticky-flag prompt, then the tx)
```

Note the printed `gwB…` address — that's `GATEWAY_ID`. Confirm it landed:

```bash
curl -s http://127.0.0.1:19191/json_rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"bridge_get_reserves","params":{"gateway_id":"<gwB…>"}}' | jq
# → registered:true, bridge_reserve:true, gateway_balance:…
```

> Prefer an unflagged gateway for a first smoke run? Omit `bridge_reserve`. The guard still
> dedupes refs that are present; the flag only forecloses omitting them.

---

## 5. Wallet CLI — how to get one, and how to fund it

The devnet's own wallets are held open by `beldex-wallet-rpc`, so don't reuse those files.
Create a **separate** CLI wallet pointed at devnet node 19191:

```bash
cd $BLD/build/Darwin/dkg-tss-implementation/release/bin
./beldex-wallet-cli --devnet --daemon-address 127.0.0.1:19191 \
                    --generate-new-wallet ~/bridge-test-wallet
# note its address:  [wallet]> address
```

Fund it from the devnet's mining wallet (**Mike**) over wallet RPC:

```bash
# find the wallet-rpc ports (Alice, Bob, Mike, Op1…):
ps ax | grep -o 'beldex-wallet-rpc.*--rpc-bind-port [0-9]*' | grep -o '[0-9]*$'
MIKE=http://127.0.0.1:<one of those>/json_rpc

curl -s $MIKE -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":"0","method":"transfer",
  "params":{"destinations":[{"address":"<your CLI wallet address>","amount":500000000000}],
            "priority":1}}' | jq
```

(`amount` is atomic units: 500000000000 = 500 BDX.) Then in the CLI: `refresh`, `balance`.
If Mike has nothing, mine a few blocks — the devnet harness exposes `mnn.mine(10)`.

**Pre-fund the reserve** (optional, for burn drills beyond what you bridge in): send a plain
transfer to the gateway address with **no memo** — a memo-less deposit is held
(`Unresolved{NoMemo}`) and never minted, so it adds reserve without creating wBDX:

```
[wallet]> transfer <gwB… gateway address> 200
```

---

## 6. Per-node environment + starting `serve --live` on all nodes

You do **not** hand-write env per node — `serve-live.sh` derives each node's committee index
from its own share filename and sets everything (sockets, MN key, share dir, mesh ports,
watchers, release config):

```bash
cd $BLD/utils/local-devnet
GATEWAY_ID=<gwB…> \
VIEW_SECRET=$VIEW_SECRET \
WBDX=<0x… proxy> \
CHAIN_ID=31337 EVM_RPC=http://127.0.0.1:8545 \
  runlog ./serve-live.sh
```

It starts **every** node that holds shares (t+1 = 4 must be up; more = failover headroom),
each with its own coordinator mesh port (`6200+index`), sign meshes at `6000+index` /
`6100+index`, and `BRIDGE_SIGNER_SERVE_LIVE=1`.

```bash
tail -f testdata/serve-*.log       # watch
pkill -f 'beldex-bridge-signer serve'   # stop
```

Expected per node: `serve: LIVE COORDINATED mode …`, the committee line, then quiet ticks.

Useful overrides: `NODES=0,1,2,3` (subset), `RELEASE_FEE=…`, `START_HEIGHT=…`,
`POLL_SECS=…`. To set anything not covered, edit the env block in `serve-live.sh` — it is a
plain `for` loop over the node dirs.

---

## 7. Run the round-trip

Now follow **`AUTONOMOUS_ROUNDTRIP.md`** §4 (mint) and §5 (release). In short:

```
# BDX → wBDX
[wallet]> bridge_deposit <gwB… gateway> 100 31337 <20-byte anvil address, no 0x>
#   → watch serve-*.log for opened/acked/signed, then a MINT-PAYLOAD line
#   → pipe it to the relayer:
echo '<MINT-PAYLOAD json>' | beldex-bridge-relayer relay -

# wBDX → BDX
cast send $WBDX 'redeemToNative(uint256,bytes)' <amount> <your BDX address bytes> \
     --private-key <anvil key> --rpc-url http://127.0.0.1:8545
#   → the leader builds + proposes, members verify R1–R6, Pgw signs, RELEASE submitted: 0x…
```

---

## 8. Quick troubleshooting

| Symptom | Cause / fix |
|---|---|
| `serve` exits immediately | Its log names the missing config key. Check the share dir has `pgw-<i>.*` and `pevm-<i>.keyshare`. |
| `this node is not on the current bridge committee` | That node has no bridge seat this epoch; it's skipped, fine as long as ≥ t+1 remain. |
| Ticks show `opened` but never `acked` | Members disagree with the leader's payload, or the deposit isn't finalized yet (checkpoint depth). Look for `nacked` and the NACK reason. |
| `acked` but never `signed` | Fewer than t+1 nodes serving, or a sign mesh port clash. Confirm 4+ processes and free `6000/6100/6200+index`. |
| Release rejected `must carry a release ref` | The gateway is flagged and the tx had no ref — the builder didn't pass the burn params. Check the leader is on this build. |
| `replays an already-discharged burn ref` | Working as intended: that burn was already released. |
| Deposit never becomes a duty | No/undecryptable memo (wrong `VIEW_SECRET`), unknown chain id, or over cap → held as `Unresolved`, never minted. |
