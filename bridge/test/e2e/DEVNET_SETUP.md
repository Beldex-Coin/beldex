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

### Keep the chain moving — the devnet does NOT mine on its own

The harness mines only when its `mine()` is called; once it prints `Use Ctrl-C to exit...`
**nothing mines**, so submitted txs sit in the mempool and balances never confirm. Worse for
bridge testing, a gateway deposit only becomes a mint duty after **checkpoint finality**
(height ≤ `get_info.immutable_height`), which needs a steady supply of blocks. Start a
background miner and leave it running for the whole session:

```bash
cd $BLD/utils/local-devnet
./mine.sh loop &          # 2 blocks every 20s; ./mine.sh 20 for a one-off burst
```

> On Apple Silicon the daemons need `export MONERO_RANDOMX_UMASK=8` (vendored RandomX
> predates M-series JIT support and segfaults otherwise — `DEBUG_LOG.md` Issue 4). If your
> daemons are already up and healthy, it's set.

---

## 2. Dual DKG → this gives you `PGW_GROUP_VK`

First confirm the bridge committee is active (the DKG needs it):

```bash
curl -s http://127.0.0.1:19191/json_rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"bridge_get_committee"}' | jq '.result.members | length'
# → 6 (if 0/absent, the seats aren't registered/active yet — mine a few epochs)
```

Then run the **initial** dual DKG (both legs, into each node's own `devnet/shares`):

```bash
cd $BLD/utils/local-devnet
runlog ./dkg-init.sh
```

It prints `PGW_GROUP_VK` at the end and verifies every participant agrees on it.
Expect it to take minutes: the Pevm aux-info phase generates Paillier safe primes and all
six signers contend for cores on one host (hence the 600 s default timeout).

> **Not `dkg-next.sh`.** That is the *rotation* script — it writes `shares-next` and refuses
> generation 0 by design, so `./dkg-next.sh 0` correctly errors out. Use it only when
> rotating to a successor key.

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
# Run from utils/local-devnet. The per-node DKG logs are written into testdata/,
# not one level up -- `../*.log` matches nothing from here OR from testdata/, and
# leaves PEVM_ADDR silently empty.
PEVM_ADDR=$(grep -h 'wBDX signer' testdata/*.log 2>/dev/null | head -1 | grep -o '0x[0-9a-f]*')
# Do NOT prefix this line with `runlog`: runlog execs "$@" directly rather than
# through a shell, so a leading VAR=value assignment is taken as the command name
# and fails with "PEVM_ADDR=: command not found".

# or, definitively, probe it (also proves the committee can sign):
runlog ./sign-pevm.sh raw 0x$(printf 'ab%.0s' {1..32})   # read "wBDX signer : 0x…"
```

---

## 3. Deploy wBDX → this gives you `WBDX`

```bash
cd $BC
# 01-deploy.sh reads SIGNER_ADDR -- NOT `INITIAL_SIGNER`. It has no ADMIN variable
# at all: `admin_` is always $DEPLOYER (anvil account #0 by default). To put admin
# somewhere else, override DEPLOYER *and* DEPLOYER_KEY together, since the deployer
# is also the tx sender.
SIGNER_ADDR=$PEVM_ADDR ./devnet/01-deploy.sh
grep -E '^(PROXY|IMPL|SIGNER_ADDR)=' devnet/mint.env    # → PROXY=0x…  (the proxy address)
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

The wallet prints two forms. `GATEWAY_ID` for the signers is the **hex** one, on the
`Gateway id  :` line — the signer parses it with `parse_hex32` and a `gwB…` address dies
at startup with `config key gateway_id is not 32-byte hex`. Keep the `gwB…` address too:
that is what wallet `transfer` / `bridge_deposit` and the RPC below want. Confirm it landed:

```bash
curl -s http://127.0.0.1:19191/json_rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"bridge_get_reserves","params":{"gateway_id":"<gwB…>"}}' \
  | tr ',' '\n' | grep -E 'registered|bridge_reserve|gateway_balance'
# → registered:true, bridge_reserve:true, gateway_balance:…
# (no jq — it is not installed, and `brew install jq` resolves to the Intel prefix
#  /usr/local/bin/brew on this machine, which would fetch an x86_64 build.)
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

Fund it from the devnet's mining wallet (**Mike**) over wallet RPC.

Find the wallet-rpc ports — each wallet's data dir is named after its port, so no `ps`
needed (run from `$BLD/utils/local-devnet`):

```bash
ls -d testdata/wallet-127.0.0.1-* | grep -v stderr | sed 's/.*-//' | sort -n
# → one port per wallet, in creation order: Alice, Bob, Mike, Op1, Op2, …
```

Identify Mike by balance rather than by position — he's the mining wallet, so he's the one
with funds:

```bash
for p in $(ls -d testdata/wallet-127.0.0.1-* | grep -v stderr | sed 's/.*-//' | sort -n); do
  bal=$(curl -s http://127.0.0.1:$p/json_rpc -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":"0","method":"get_balance","params":{"account_index":0}}' \
        | jq -r '.result.unlocked_balance // 0')
  echo "port $p  unlocked $bal"
done
MIKE=http://127.0.0.1:<the port with a large balance>/json_rpc
```

Then transfer (`amount` is atomic units; 500000000000 = 500 BDX):

```bash
curl -s $MIKE -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":"0","method":"transfer",
  "params":{"destinations":[{"address":"<your CLI wallet address>","amount":500000000000}],
            "priority":1}}' | jq
```

> If you do prefer `ps`: the flag is `--rpc-bind-port=<n>` (equals, not a space) and macOS
> truncates `ps ax`, so it must be
> `ps axww | grep -o 'beldex-wallet-rpc.*--rpc-bind-port=[0-9]*' | grep -o '[0-9]*$'`.

Then in the CLI: `refresh`, `balance`. If every wallet shows 0, mine a few blocks — the
devnet harness exposes `mnn.mine(10)` in the Python session that's running the network.

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
GATEWAY_ID=<64-char hex gateway id, NOT the gwB… address> \
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

### Two devnet-only knobs `serve-live.sh` sets for you

Both exist because a six-node local chain is not a network, and both are set by the script
so a normal run needs neither. Read them before changing them.

**`BELDEX_CONFIRMATIONS` (default 10) → `BRIDGE_SIGNER_BELDEX_CONFIRMATIONS`.** The signer's
production finality rule is the master-node checkpoint: a deposit is actionable only at or
below `get_info.immutable_height`, below which the chain cannot reorg. `beldexd` emits that
field only when `db.get_immutable_checkpoint` succeeds (`src/rpc/core_rpc_server.cpp`), and
a checkpointing quorum is only generated once the network has `CHECKPOINT_QUORUM_SIZE`
active masternodes — **20** in a normal build (`src/cryptonote_core/master_node_rules.h`;
the value is 5 only under `BELDEX_ENABLE_INTEGRATION_TEST_HOOKS`, i.e. a
`-DBUILD_INTEGRATION=ON` build). This devnet runs six. So it never checkpoints, the field is
absent from **every** `get_info`, the watcher's finality gate never opens, and no deposit can
ever become a mint duty — with nothing in the serve log to say so, because
`service.rs::poll_mints` treats a poll error as transient and returns an empty batch. The
symptom is the one that costs a whole session: a deposit that confirms on chain, ticks that
never print `opened`, and `gateway_get_history` never called once (confirm with
`grep -ac gateway_get_history testdata/beldex-127.0.0.1-19191/devnet/beldex.log` — zero,
against thousands of `on_get_info`).

Setting it to `N` relaxes the frontier to `top_height - N` **only on a chain that reports no
checkpoint at all**. It is a strict either/or, not a `max`: the moment the daemon reports an
`immutable_height`, that value wins outright and this setting is ignored, so it can never
widen finality on a network that has a frontier of its own. `BELDEX_CONFIRMATIONS=` (empty)
restores strict behaviour — useful to see the gate stay shut for yourself.

**`SIGN_SIGNERS` (default `0,1,2,3,4,5`) → `BRIDGE_SIGNER_SIGN_SIGNERS`.** `main.rs`'s
`build_live_signers` refuses to start a node whose committee index is not in that list, and
the default when the variable is unset is `0..threshold`. On a 6-of-4 devnet that kills
indices 4 and 5 at startup with `this node (4) is not in the signer set [0, 1, 2, 3]`, and
`serve-live.sh` then exits 1 with two dead children. The `0..threshold` default is a leftover
from the one-shot `sign` subcommand: under coordinated autonomy each round's participants are
the session's canonical ACK set, passed per duty into `pgw_sign`/`pevm_sign`, and the stored
`LiveSigners.signers` is never read again after the check. Listing the whole committee widens
the startup gate only — it does not change who signs, and it is what `AUTONOMOUS_ROUNDTRIP.md`
§1 already describes.

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
| Deposit never becomes a duty | No/undecryptable memo (wrong `VIEW_SECRET`), unknown chain id, or over cap → held as `Unresolved`, never minted. Also check blocks are still being mined: the watcher only acts past `immutable_height`. |
| Deposit confirms, ticks never print `opened`, serve log otherwise silent | The chain has no checkpoint, so `get_info` omits `immutable_height` and the finality gate never opens — the failure is swallowed as transient. Confirm with `grep -ac gateway_get_history testdata/beldex-127.0.0.1-19191/devnet/beldex.log` (zero = this). Fix: `BELDEX_CONFIRMATIONS=10` (§6), which `serve-live.sh` now sets by default. |
| `serve: this node (4) is not in the signer set [0, 1, 2, 3]` | The startup gate defaults to `0..threshold`. `serve-live.sh` now passes `SIGN_SIGNERS=0,1,2,3,4,5`; if you launch by hand, set `BRIDGE_SIGNER_SIGN_SIGNERS` to the whole committee (§6). |
| **Transfer succeeded but funds never arrive / balance stays 0** | Nothing is mining. The devnet mines on demand only. Run `./mine.sh loop &` (see §1), then `refresh` in the wallet. Confirm with `curl -s http://127.0.0.1:19191/get_height` — if the height is static, that's it. |
| Height static even while mining | Daemon died (Apple Silicon RandomX — set `MONERO_RANDOMX_UMASK=8` and restart the devnet), or `mining_status` shows `active:false` immediately → check the miner address is a valid devnet address. |
