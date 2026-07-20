#!/usr/bin/python3

import asyncio
import glob
import os
import random
import shutil
import time
import uuid
from datetime import datetime
from os import path

from daemons import Daemon, Wallet

datadirectory = "testdata"


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


class MNNetwork:
    # 6 MNs = the Sovereign Bridge Phase C devnet committee (4-of-6, plan §7).
    # Consensus enforces ONE bridge seat per operator identity, so each of the
    # first `bridge_seats` MNs is registered (and bonded) by its own operator
    # wallet; any additional MNs are plain (non-bridge) MNs owned by Mike.
    def __init__(
        self,
        datadir,
        *,
        binpath="/Users/mac/Niyas/projects/beldex/build/Darwin/dkg-tss-implementation/release/bin",
        mns=6,
        nodes=1,
        bridge_seats=6,
    ):
        self.datadir = datadir
        if not os.path.exists(self.datadir):
            os.makedirs(self.datadir)
        self.binpath = binpath or os.environ.get(
            "BELDEX_BIN", "../../build/Darwin/dkg-tss-implementation/release/bin"
        )

        vprint("Using '{}' for data files and logs".format(datadir))
        vprint("Using '{}' for binaries".format(self.binpath))

        nodeopts = dict(beldexd=self.binpath + "/beldexd", datadir=datadir)

        # Pin the first MN's RPC port so bridge/signer/.env can point at it.
        self.mns = [Daemon(master_node=True, rpc_port=19191, **nodeopts)]
        self.mns += [Daemon(master_node=True, **nodeopts) for _ in range(mns - 1)]
        self.nodes = [Daemon(**nodeopts) for _ in range(nodes)]

        self.all_nodes = self.mns + self.nodes

        self.wallets = []
        wallet_names = ["Alice", "Bob", "Mike"]
        wallet_names += ["Op{}".format(i + 1) for i in range(min(bridge_seats, mns))]
        for name in wallet_names:
            self.wallets.append(
                Wallet(
                    node=self.nodes[len(self.wallets) % len(self.nodes)],
                    name=name,
                    rpc_wallet=self.binpath + "/beldex-wallet-rpc",
                    datadir=datadir,
                )
            )

        self.alice, self.bob, self.mike = self.wallets[0:3]
        self.operators = self.wallets[3:]  # one operator wallet per bridge seat

        # Interconnections
        for i in range(len(self.all_nodes)):
            for j in (2, 3, 5, 7, 11):
                k = (i + j) % len(self.all_nodes)
                if i != k:
                    self.all_nodes[i].add_peer(self.all_nodes[k])

        vprint(
            "Starting new master master nodes with RPC on {} ports".format(
                self.mns[0].listen_ip
            ),
            end="",
        )
        for mn in self.mns:
            vprint(" {}".format(mn.rpc_port), end="", flush=True, timestamp=False)
            mn.start()
        vprint(timestamp=False)
        vprint(
            "Starting new regular master nodes with RPC on {} ports".format(
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

        vprint("Beldexds are ready. Starting wallets")

        for w in self.wallets:
            vprint(
                "Starting new RPC wallet {w.name} at {w.listen_ip}:{w.rpc_port}".format(
                    w=w
                )
            )
            w.start()
        for w in self.wallets:
            w.ready()
            w.refresh()
            vprint("Wallet {w.name} is ready: {a}".format(w=w, a=w.address()))

        for w in self.wallets:
            w.wait_for_json_rpc("refresh")

        def ping_and_proof(mn):
            mn.ping()
            mn.send_uptime_proof()

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
            ping_and_proof(mn)
        vprint("Done.")

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

            seats = self.mns[0].json_rpc("bridge_get_seats").json()["result"]
            vprint(
                "Bridge seats: seated={} distinct_operators={} active={}".format(
                    seats["seated_count"], seats["distinct_operators"], seats["active"]
                )
            )
            if not seats["active"]:
                raise RuntimeError("Bridge did not activate: {}".format(seats))

            # The committee is (re)selected only at epoch-boundary heights
            # (devnet epoch = 120 blocks, cryptonote_config.h bridge_epoch_blocks).
            # Mine past the next boundary and verify the committee formed.
            epoch_blocks = 120
            height = self.mns[0].height()
            pad = (epoch_blocks - (height % epoch_blocks)) % epoch_blocks + 1
            vprint("Mining {} blocks to the next bridge epoch boundary".format(pad))
            self.sync_nodes(self.mine(pad))

            committee = self.mns[0].json_rpc("bridge_get_committee").json()["result"]
            vprint(
                "Bridge committee (epoch {}): {} members, threshold {}, active={}".format(
                    committee["epoch"],
                    len(committee["members"]),
                    committee["threshold"],
                    committee["active"],
                )
            )
            if (
                not committee["active"]
                or len(committee["members"]) < committee["threshold"]
            ):
                raise RuntimeError(
                    "Bridge committee did not form: {}".format(committee)
                )

        vprint("Local Devnet MN network setup complete!")
        vprint(
            "Communicate with daemon on ip: {} port: {}".format(
                self.mns[0].listen_ip, self.mns[0].rpc_port
            )
        )
        configfile = self.datadir + "config.py"
        with open(configfile, "w") as filetowrite:
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

    def __del__(self):
        for n in self.all_nodes:
            n.terminate()
        for w in self.wallets:
            w.terminate()


mnn = None


def run():
    global mnn, verbose
    if not mnn:
        if path.isdir(datadirectory + "/"):
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


# Shortcuts for accessing the named wallets
def alice(net):
    return net.alice


def bob(net):
    return net.bob


def mike(net):
    return net.mike


if __name__ == "__main__":
    run()
