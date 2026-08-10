#!/usr/bin/python3

import asyncio
import glob
import json
import os
import random
import shutil
import sys
import time
import uuid
from datetime import datetime
from os import path

from daemons import Daemon, Wallet

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Deliberately RELATIVE. beldexd binds a unix socket at
# <datadir>/beldex-<ip>-<port>/devnet/beldexd.sock, and macOS caps sun_path at 104
# bytes, so an absolute datadir makes the daemon abort with "File name too long".
# run() chdir()s to SCRIPT_DIR instead, which keeps the path short *and* makes it
# independent of where the script was invoked from.
datadirectory = os.environ.get("BELDEX_DEVNET_DATADIR", "testdata")

# Conservative: 104 (macOS sun_path) minus room for the longest per-daemon suffix.
MAX_SOCKET_PATH = 104

# Everything below must be deterministic across runs: each daemon/wallet stores its
# state in a directory named after its listen ip + rpc port, so randomized ports
# would mean a brand new (empty) chain on every restart.
LISTEN_IP = os.environ.get("BELDEX_DEVNET_IP", "127.0.0.1")
BASE_PORT = int(os.environ.get("BELDEX_DEVNET_BASE_PORT", "19200"))
# Pinned so bridge/signer/.env can point at a stable MN RPC endpoint.
MN0_RPC_PORT = int(os.environ.get("BELDEX_DEVNET_MN0_RPC_PORT", "19191"))
PORTS_PER_NODE = 5  # rpc, p2p, zmq, qnet, ss
STATE_VERSION = 1


def node_ports(index):
    """Fixed port block for the index'th daemon."""
    base = BASE_PORT + index * PORTS_PER_NODE
    return {
        "rpc_port": base,
        "p2p_port": base + 1,
        "zmq_port": base + 2,
        "qnet_port": base + 3,
        "ss_port": base + 4,
    }


def coins(*args):
    if len(args) != 1:
        return tuple(coins(x) for x in args)
    x = args[0]
    if type(x) in (tuple, list):
        return type(x)(coins(i) for i in x)
    return round(x * 1000000000)


def wait_for(callback, timeout=60):
    expires = time.time() + timeout
    while True:
        try:
            if callback():
                return
        except:
            pass
        if time.time() >= expires:
            raise RuntimeError("task timeout expired")
        time.sleep(0.25)


verbose = True


def vprint(*args, timestamp=True, **kwargs):
    global verbose
    if verbose:
        if timestamp:
            print(datetime.now(), end=" ")
        print(*args, **kwargs)


# Repo root: this file lives at <project>/utils/local-devnet/master_node_network.py
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def find_binpath():
    """Locate the directory holding beldexd/beldex-wallet-rpc.

    Resolution order:
      1. $BELDEX_BIN          - explicit bin directory
      2. $BELDEX_BUILD_DIR    - a build dir; searched for a bin/ subdir
      3. $BELDEX_PROJECT_DIR or the repo containing this script, searched under build/
    """
    def is_bin(d):
        return d and os.path.isfile(os.path.join(d, "beldexd"))

    env_bin = os.environ.get("BELDEX_BIN")
    if env_bin:
        env_bin = os.path.abspath(os.path.expanduser(env_bin))
        if not is_bin(env_bin):
            raise RuntimeError("BELDEX_BIN={} does not contain beldexd".format(env_bin))
        return env_bin

    project_dir = os.path.abspath(
        os.path.expanduser(os.environ.get("BELDEX_PROJECT_DIR", PROJECT_DIR))
    )
    build_dir = os.environ.get("BELDEX_BUILD_DIR") or os.path.join(project_dir, "build")
    build_dir = os.path.abspath(os.path.expanduser(build_dir))

    candidates = [build_dir, os.path.join(build_dir, "bin")]
    # e.g. build/bin, build/<platform>/<branch>/<config>/bin, build/*/bin, ...
    for depth in range(1, 5):
        candidates += glob.glob(os.path.join(build_dir, *(["*"] * depth), "bin"))

    found = [d for d in candidates if is_bin(d)]
    if not found:
        raise RuntimeError(
            "Could not find beldexd under '{}'. Set $BELDEX_BIN, $BELDEX_BUILD_DIR, "
            "or $BELDEX_PROJECT_DIR.".format(build_dir)
        )
    # Prefer the most recently built one.
    return max(found, key=lambda d: os.path.getmtime(os.path.join(d, "beldexd")))


class MNNetwork:
    # 6 MNs = the Sovereign Bridge Phase C devnet committee (4-of-6, plan §7).
    # Consensus enforces ONE bridge seat per operator identity, so each of the
    # first `bridge_seats` MNs is registered (and bonded) by its own operator
    # wallet; any additional MNs are plain (non-bridge) MNs owned by Mike.
    def __init__(
        self,
        datadir,
        *,
        binpath=None,
        mns=6,
        nodes=1,
        bridge_seats=6,
    ):
        self.datadir = datadir
        if not os.path.exists(self.datadir):
            os.makedirs(self.datadir)
        self.binpath = os.path.abspath(os.path.expanduser(binpath)) if binpath else find_binpath()
        self.state_path = os.path.join(self.datadir, "network_state.json")
        self.check_socket_path_length()

        state = self.load_state()
        self.resuming = state is not None
        if self.resuming:
            # Reuse the exact ip/ports of the previous run so every daemon and wallet
            # picks up its existing data directory (and therefore the existing chain,
            # master node keys and wallet files).
            self.listen_ip = state["listen_ip"]
            mn_ports = state["mns"]
            node_ports_ = state["nodes"]
            wallet_state = state["wallets"]
            mns, nodes = len(mn_ports), len(node_ports_)
            vprint("=== RESUMING existing devnet ({}) ===".format(self.state_path))
        else:
            vprint(
                "=== BOOTSTRAPPING a new devnet (no {}) ===".format(self.state_path)
            )
            stale = glob.glob(os.path.join(self.datadir, "beldex-*"))
            if stale:
                vprint(
                    "WARNING: '{}' already holds {} daemon dir(s) but no resumable state; "
                    "they will be ignored. Use --fresh to clear them.".format(
                        self.datadir, len(stale)
                    )
                )
            self.listen_ip = LISTEN_IP
            mn_ports = [node_ports(i) for i in range(mns)]
            mn_ports[0]["rpc_port"] = MN0_RPC_PORT
            node_ports_ = [node_ports(mns + i) for i in range(nodes)]
            wallet_names = ["Alice", "Bob", "Mike"]
            wallet_names += ["Op{}".format(i + 1) for i in range(min(bridge_seats, mns))]
            wallet_base = BASE_PORT + (mns + nodes) * PORTS_PER_NODE
            wallet_state = [
                {"name": n, "rpc_port": wallet_base + i, "file": "wallet"}
                for i, n in enumerate(wallet_names)
            ]

        vprint("Using '{}' for data files and logs".format(datadir))
        vprint("Using '{}' for binaries".format(self.binpath))

        nodeopts = dict(
            beldexd=self.binpath + "/beldexd", datadir=datadir, listen_ip=self.listen_ip
        )

        self.mns = [Daemon(master_node=True, **p, **nodeopts) for p in mn_ports]
        self.nodes = [Daemon(**p, **nodeopts) for p in node_ports_]

        self.all_nodes = self.mns + self.nodes

        self.wallets = []
        for w in wallet_state:
            self.wallets.append(
                Wallet(
                    node=self.nodes[len(self.wallets) % len(self.nodes)],
                    name=w["name"],
                    listen_ip=self.listen_ip,
                    rpc_port=w["rpc_port"],
                    rpc_wallet=self.binpath + "/beldex-wallet-rpc",
                    datadir=datadir,
                )
            )
        self.wallet_files = [w["file"] for w in wallet_state]

        self.alice, self.bob, self.mike = self.wallets[0:3]
        self.operators = self.wallets[3:]  # one operator wallet per bridge seat

        # NB: the state file is deliberately NOT written here. It is written by
        # bootstrap(), once the chain is actually being built, so that a crash during
        # startup (bad binary, port clash, ...) leaves nothing behind that would force
        # the next run to use --fresh.

        # Interconnections
        for i in range(len(self.all_nodes)):
            for j in (2, 3, 5, 7, 11):
                k = (i + j) % len(self.all_nodes)
                if i != k:
                    self.all_nodes[i].add_peer(self.all_nodes[k])

        vprint(
            "Starting master nodes with RPC on {} ports".format(self.mns[0].listen_ip),
            end="",
        )
        for mn in self.mns:
            vprint(" {}".format(mn.rpc_port), end="", flush=True, timestamp=False)
            mn.start()
        vprint(timestamp=False)
        vprint(
            "Starting regular nodes with RPC on {} ports".format(
                self.nodes[0].listen_ip
            ),
            end="",
        )
        for d in self.nodes:
            vprint(" {}".format(d.rpc_port), end="", flush=True, timestamp=False)
            d.start()
        vprint(timestamp=False)

        vprint("Waiting for all master's to get ready")
        for d in self.all_nodes:
            d.wait_for_json_rpc("get_info")

        vprint(
            "Beldexds are ready at heights {}".format(
                [d.height() for d in self.all_nodes]
            )
        )
        vprint("Starting wallets")

        for w in self.wallets:
            vprint(
                "Starting new RPC wallet {w.name} at {w.listen_ip}:{w.rpc_port}".format(
                    w=w
                )
            )
            w.start()
        for w, f in zip(self.wallets, self.wallet_files):
            # ready() opens the wallet file if it already exists (resume) and creates
            # it otherwise, so the same addresses come back on every restart.
            w.ready(wallet=f)
            w.refresh()
            vprint("Wallet {w.name} is ready: {a}".format(w=w, a=w.address()))

        for w in self.wallets:
            w.wait_for_json_rpc("refresh")

        if self.resuming:
            self.resume()
        else:
            self.bootstrap()

        vprint("Local Devnet MN network is up!")
        vprint(
            "Communicate with daemon on ip: {} port: {}".format(
                self.mns[0].listen_ip, self.mns[0].rpc_port
            )
        )
        self.write_config()

    def check_socket_path_length(self):
        """beldexd aborts ("File name too long") if its OxenMQ ipc socket path exceeds the
        OS sun_path limit, so fail here with a useful message rather than on a daemon crash."""
        sample = os.path.join(
            self.datadir,
            "beldex-{}-{}".format(LISTEN_IP, MN0_RPC_PORT),
            "devnet",
            "beldexd.sock",
        )
        if len(sample) > MAX_SOCKET_PATH:
            raise RuntimeError(
                "Data directory is too deep: beldexd's socket path would be {} chars "
                "(limit {}):\n  {}\nRun the script from '{}' (it does this itself), or set "
                "$BELDEX_DEVNET_DATADIR to a shorter path.".format(
                    len(sample), MAX_SOCKET_PATH, sample, SCRIPT_DIR
                )
            )

    # ---- persistence -------------------------------------------------------

    def load_state(self):
        """Loads the previous run's ip/port/wallet layout, or None for a fresh network."""
        if not os.path.exists(self.state_path):
            return None
        with open(self.state_path) as f:
            state = json.load(f)
        if state.get("version") != STATE_VERSION:
            raise RuntimeError(
                "{} is from an incompatible version; delete '{}' (or run with --fresh) "
                "to start a new devnet".format(self.state_path, self.datadir)
            )
        if not state.get("bootstrapped"):
            raise RuntimeError(
                "Previous devnet setup in '{}' did not finish; it cannot be resumed. "
                "Re-run with --fresh to start over.".format(self.datadir)
            )
        return state

    def save_state(self, *, bootstrapped):
        state = {
            "version": STATE_VERSION,
            "bootstrapped": bootstrapped,
            "listen_ip": self.listen_ip,
            "mns": [self.ports_of(d) for d in self.mns],
            "nodes": [self.ports_of(d) for d in self.nodes],
            "wallets": [
                {"name": w.name, "rpc_port": w.rpc_port, "file": f}
                for w, f in zip(self.wallets, self.wallet_files)
            ],
        }
        with open(self.state_path, "w") as f:
            json.dump(state, f, indent=2)

    @staticmethod
    def ports_of(d):
        return {
            "rpc_port": d.rpc_port,
            "p2p_port": d.p2p_port,
            "zmq_port": d.zmq_port,
            "qnet_port": d.qnet_port,
            "ss_port": d.ss_port,
        }

    def write_config(self):
        with open(os.path.join(self.datadir, "config.py"), "w") as filetowrite:
            filetowrite.write(
                '#!/usr/bin/python3\n# -*- coding: utf-8 -*-\nlisten_ip="{}"\nlisten_port="{}"\nwallet_listen_ip="{}"\nwallet_listen_port="{}"\nwallet_address="{}"\nexternal_address="{}"'.format(
                    self.mns[0].listen_ip,
                    self.mns[0].rpc_port,
                    self.mike.listen_ip,
                    self.mike.rpc_port,
                    self.mike.address(),
                    self.bob.address(),
                )
            )

    # ---- proofs ------------------------------------------------------------

    def ping_and_proof(self, mn):
        mn.ping()
        mn.send_uptime_proof()

    def wait_for_proofs(self):
        """Pings every MN and waits for the resulting uptime proofs to propagate.

        Uptime proof state is per-process, so this has to be redone after every
        restart, not just after the initial registrations."""
        vprint("Sending fake belnet/ss pings")
        for mn in self.mns:
            mn.ping()
        # Force a fresh uptime proof from each MN so it carries the versions we just pinged.
        # Otherwise the daemon keeps gossiping its pre-ping proof (default 0.0.0 versions), which
        # the network rejects at hf20+ (MIN_UPTIME_PROOF_VERSIONS), and the wait below times out.
        for mn in self.mns:
            mn.send_uptime_proof()

        all_master_nodes_proofed = lambda mn: all(
            x["quorumnet_port"] > 0
            for x in mn.json_rpc(
                "get_n_master_nodes", {"fields": {"quorumnet_port": True}}
            ).json()["result"]["master_node_states"]
        )

        vprint("Waiting for proofs to propagate: ", end="", flush=True)
        for mn in self.mns:
            wait_for(lambda: all_master_nodes_proofed(mn), timeout=120)
            vprint(".", end="", flush=True, timestamp=False)
        vprint(timestamp=False)
        time.sleep(10)
        for mn in self.mns:
            self.ping_and_proof(mn)
        vprint("Done.")

    # ---- resume ------------------------------------------------------------

    def resume(self):
        """Brings an already-bootstrapped network back up: no mining, funding,
        registration or bonding — just resync, re-prove and re-verify."""
        self.sync_nodes()
        self.refresh_wallets()
        self.print_wallet_balances()
        vprint("Resumed at height {}".format(self.mns[0].height()))
        self.wait_for_proofs()
        if self.operators:
            self.report_bridge_status(require_active=False)

    def report_bridge_status(self, *, require_active=True):
        seats = self.mns[0].json_rpc("bridge_get_seats").json()["result"]
        vprint(
            "Bridge seats: seated={} distinct_operators={} active={}".format(
                seats["seated_count"], seats["distinct_operators"], seats["active"]
            )
        )
        if require_active and not seats["active"]:
            raise RuntimeError("Bridge did not activate: {}".format(seats))

        committee = self.mns[0].json_rpc("bridge_get_committee").json()["result"]
        vprint(
            "Bridge committee (epoch {}): {} members, threshold {}, active={}".format(
                committee["epoch"],
                len(committee["members"]),
                committee["threshold"],
                committee["active"],
            )
        )
        if require_active and (
            not committee["active"] or len(committee["members"]) < committee["threshold"]
        ):
            raise RuntimeError("Bridge committee did not form: {}".format(committee))
        return seats, committee

    # ---- first-run bootstrap ----------------------------------------------

    def bootstrap(self):
        ping_and_proof = self.ping_and_proof

        # From here the chain is being mutated (mined blocks, stakes, bonds), so record
        # the layout. bootstrapped=False marks it as an incomplete setup: if we die
        # partway through, the result is not resumable and the next run must use --fresh.
        self.save_state(bootstrapped=False)

        # Mine some blocks. The height-1 "premine" block carries 1.4B BDX, which
        # funds everything (devnet staking requirement is 10,000 BDX per MN and
        # the bridge bond is 100,000 BDX per seat). We mine 100 blocks so the
        # premine output is past the 30-block coinbase lock and there are plenty
        # of coinbase outputs on chain for ring decoys.
        self.mine(100)
        self.print_wallet_balances()

        # Fund each operator wallet from Mike's premine in ONE multi-destination
        # transfer: 10,000 (stake) + 100,000 (bridge bond) + fee headroom.
        if self.operators:
            op_funding = coins(110050)
            vprint(
                "Funding {} operator wallets ({:.0f} BDX each)".format(
                    len(self.operators), op_funding * 1e-9
                )
            )
            self.mike.transfer_many([(op, op_funding) for op in self.operators])
            self.sync_nodes(self.mine(11))  # confirm + pass DEFAULT_TX_SPENDABLE_AGE
            self.refresh_wallets()

        vprint(
            "Submitting master node registrations (10,000 BDX stake each): ",
            end="",
            flush=True,
        )
        for i, mn in enumerate(self.mns):
            owner = self.operators[i] if i < len(self.operators) else self.mike
            owner.register_mn(mn)
            # Each registration stakes from one large output, so its change comes
            # back locked. Mine enough to confirm the stake and unlock the change
            # (DEFAULT_TX_SPENDABLE_AGE=10) before that wallet spends again.
            self.sync_nodes(self.mine(11))
            ping_and_proof(mn)
            owner.refresh()
            vprint(".", end="", flush=True, timestamp=False)
        vprint(timestamp=False)

        self.print_wallet_balances()

        vprint(
            "Mining 40 blocks (registrations + flash quorum lag) and waiting for nodes to sync"
        )
        self.sync_nodes(self.mine(40))

        self.print_wallet_balances()

        self.wait_for_proofs()

        # ---- Sovereign Bridge (HF23): bond the committee seats ----
        # Each operator wallet locks the 100k BDX BRIDGE_BOND for its own MN via
        # the daemon-signed registration blob (one seat per operator identity).
        if self.operators:
            vprint(
                "Bonding {} bridge seats (100,000 BDX bond each): ".format(
                    len(self.operators)
                ),
                end="",
                flush=True,
            )
            for i, op in enumerate(self.operators):
                op.bridge_register(self.mns[i])
                self.sync_nodes(self.mine(2))
                vprint(".", end="", flush=True, timestamp=False)
            vprint(timestamp=False)
            self.sync_nodes(self.mine(10))

            # The committee is (re)selected only at epoch-boundary heights
            # (devnet epoch = 120 blocks, cryptonote_config.h bridge_epoch_blocks).
            # Mine past the next boundary and verify the committee formed.
            epoch_blocks = 120
            height = self.mns[0].height()
            pad = (epoch_blocks - (height % epoch_blocks)) % epoch_blocks + 1
            vprint("Mining {} blocks to the next bridge epoch boundary".format(pad))
            self.sync_nodes(self.mine(pad))

            self.report_bridge_status()

        # From here on this datadir can be resumed instead of rebuilt.
        self.save_state(bootstrapped=True)
        vprint("Local Devnet MN network setup complete!")

    def refresh_wallets(self, *, extra=[]):
        vprint("Refreshing wallets")
        for w in self.wallets + extra:
            w.refresh()
        vprint("All wallets refreshed")

    def mine(self, blocks=None, wallet=None, *, sync=False):
        """Mine some blocks to the given wallet (or self.mike if None) on the wallet's daemon.
        Returns the daemon's height after mining the blocks.  If blocks is omitted, mines enough to
        confirm regular transfers (i.e. 10 blocks).  If sync is specified, sync all nodes and then
        refresh all wallets after mining."""
        if wallet is None:
            wallet = self.mike
        if blocks is None:
            blocks = 10
        node = wallet.node
        vprint("Mining {} blocks to wallet {.name}".format(blocks, wallet))
        start_height = node.height()
        end_height = start_height + blocks
        node.mine_blocks(blocks, wallet)
        while node.rpc("/mining_status").json()["active"]:
            height = node.height()
            vprint("Mined {}/{}".format(height, end_height))
            time.sleep(0.05 if height >= end_height else 0.25)
        height = node.height()
        vprint("Mined {}/{}".format(height, end_height))

        if sync:
            self.sync_nodes(height)
            self.refresh_wallets()

        return height

    # timeout=180: with the RandomX JIT disabled (MONERO_RANDOMX_UMASK=8,
    # required on Apple Silicon — see bridge/docs/DEBUG_LOG.md Issue 4), each
    # node verifies PoW in the interpreter, so syncing an 11-block burst can
    # take well over the old 10s window.
    def sync_nodes(self, height=None, *, extra=[], timeout=180):
        """Waits for all nodes to reach the given height, typically invoked after mine()"""
        nodes = self.all_nodes + extra
        heights = [x.height() for x in nodes]
        if height is None:
            height = max(heights)
        if min(heights) >= height:
            vprint("All nodes already synced to height >= {}".format(height))
            return
        vprint("Waiting for all nodes to sync to height {}".format(height))
        last = None
        expiry = time.time() + timeout
        while nodes and time.time() < expiry:
            if heights[-1] < height:
                heights[-1] = nodes[-1].height()
            if heights[-1] >= height:
                heights.pop()
                nodes.pop()
                last = None
                continue
            if heights[-1] != last:
                vprint(
                    "waiting for {} [{} -> {}]".format(
                        nodes[-1].name, heights[-1], height
                    )
                )
                last = heights[-1]
            time.sleep(0.1)
        if nodes:
            raise RuntimeError("Timed out waiting for node syncing")
        vprint("All nodes synced to height {}".format(height))

    def sync(self, extra_nodes=[], extra_wallets=[]):
        """Synchronizes everything: waits for all nodes to sync, then refreshes all wallets.  Can be
        given external wallets/nodes to sync."""
        self.sync_nodes(extra=extra_nodes)
        self.refresh_wallets(extra=extra_wallets)

    def print_wallet_balances(self):
        """Instructs the wallets to refresh and prints their balances (does nothing in non-verbose mode)"""
        global verbose
        if not verbose:
            return
        vprint("Balances:")
        for w in self.wallets:
            b = w.balances(refresh=True)
            vprint(
                "    {:5s}: {:.9f} (total) with {:.9f} (unlocked)".format(
                    w.name, b[0] * 1e-9, b[1] * 1e-9
                )
            )

    def shutdown(self):
        """Stops wallets and daemons and waits for them to exit, so the wallet caches and
        LMDB chain databases are flushed cleanly and the network can be resumed."""
        vprint("Shutting down wallets and daemons cleanly...")
        for w in self.wallets:
            w.stop()
        for n in self.all_nodes:
            n.stop()
        vprint("Devnet stopped; re-run without --fresh to resume from here.")

    def __del__(self):
        # getattr: __init__ can fail before these exist (e.g. a port conflict).
        for n in getattr(self, "all_nodes", []):
            n.terminate()
        for w in getattr(self, "wallets", []):
            w.terminate()


mnn = None


def run(fresh=False):
    global mnn, verbose
    # So `testdata` always refers to the same directory no matter where the script was
    # started from, without having to make the (socket-length-limited) path absolute.
    os.chdir(SCRIPT_DIR)
    if not mnn:
        if fresh and path.isdir(datadirectory + "/"):
            vprint("--fresh: wiping '{}'".format(datadirectory))
            shutil.rmtree(datadirectory + "/", ignore_errors=False, onerror=None)
        vprint("new MNN")
        mnn = MNNetwork(datadir=datadirectory + "/")
    else:
        vprint("reusing MNN")
        mnn.alice.new_wallet()
        mnn.bob.new_wallet()

        # Flush pools because some tests leave behind impossible txes
        for n in mnn.all_nodes:
            assert n.json_rpc("flush_txpool").json()["result"]["status"] == "OK"

        # Mine a few to clear out anything in the mempool that can be cleared
        mnn.mine(5, sync=True)

        vprint("Alice has new wallet: {}".format(mnn.alice.address()))
        vprint("Bob   has new wallet: {}".format(mnn.bob.address()))

    input("Use Ctrl-C to exit...")
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print(f"!!! AsyncApplication.run: got KeyboardInterrupt during start")
    finally:
        loop.close()
        # Clean exit matters here: a killed beldexd can leave its LMDB mid-write,
        # which would cost us the chain state we want to resume from.
        mnn.shutdown()


# Shortcuts for accessing the named wallets
def alice(net):
    return net.alice


def bob(net):
    return net.bob


def mike(net):
    return net.mike


if __name__ == "__main__":
    # By default the network resumes from whatever is in `datadirectory`; pass
    # --fresh (or -f) to wipe it and bootstrap a brand new devnet.
    args = set(sys.argv[1:])
    if args - {"--fresh", "-f"}:
        print("usage: {} [--fresh]".format(sys.argv[0]))
        sys.exit(1)
    run(fresh=bool(args))
