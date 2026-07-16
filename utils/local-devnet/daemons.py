#!/usr/bin/python3

import sys
import random
import requests
import subprocess
import time

# On linux we can pick a random 127.x.y.z IP which is highly likely to not have anything listening
# on it (so we make bind conflicts highly unlikely).  On most other OSes we have to listen on
# 127.0.0.1 instead, so we pick a random starting port instead to try to minimize bind conflicts.
LISTEN_IP, NEXT_PORT = (
        ('127.' + '.'.join(str(random.randint(1, 254)) for _ in range(3)), 1100)
        if sys.platform == 'linux' else
        ('127.0.0.1', random.randint(5000, 20000)))

verbose = True
# verbose = False

def next_port():
    global NEXT_PORT
    port = NEXT_PORT
    NEXT_PORT += 1
    return port


class ProcessExited(RuntimeError):
    pass


class TransferFailed(RuntimeError):
    def __init__(self, message, json):
        super().__init__(message)
        self.message = message
        self.json = json


class RPCDaemon:
    def __init__(self, name):
        self.name = name
        self.proc = None
        self.terminated = False


    def __del__(self):
        self.stop()


    def terminate(self, repeat=False):
        """Sends a TERM signal if one hasn't already been sent (or even if it has, with
        repeat=True).  Does not wait for exit."""
        if self.proc and (repeat or not self.terminated):
            self.proc.terminate()
            self.terminated = True


    def start(self):
        global verbose
        sout=subprocess.DEVNULL
        if verbose == True:
            sout=sys.stdout
            verbose = False
        if self.proc and self.proc.poll() is None:
            raise RuntimeError("Cannot start process that is already running!")
        self.proc = subprocess.Popen(self.arguments(),
                stdin=subprocess.DEVNULL, stdout=sout, stderr=subprocess.DEVNULL)
        self.terminated = False


    def stop(self):
        """Tries stopping with a term at first, then a kill if the term hasn't worked after 10s"""
        if self.proc:
            self.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("{} took more than 10s to exit, killing it".format(self.name))
                self.proc.kill()
            self.proc = None


    def arguments(self):
        """Returns the startup arguments; default is just self.args, but subclasses can override."""
        return self.args


    def json_rpc(self, method, params=None, *, timeout=10):
        """Sends a json_rpc request to the rpc port.  Returns the response object."""
        if not self.proc:
            raise RuntimeError("Cannot make rpc request before calling start()")
        json = {
                "jsonrpc": "2.0",
                "id": "0",
                "method": method,
                }
        if params:
            json["params"] = params

        return requests.post('http://{}:{}/json_rpc'.format(self.listen_ip, self.rpc_port), json=json, timeout=timeout)


    def rpc(self, path, params=None, *, timeout=10):
        """Sends a non-json_rpc rpc request to the rpc port at path `path`, e.g. /get_info.  Returns the response object."""
        if not self.proc:
            raise RuntimeError("Cannot make rpc request before calling start()")
        return requests.post('http://{}:{}{}'.format(self.listen_ip, self.rpc_port, path), json=params, timeout=timeout)


    def wait_for_json_rpc(self, method, params=None, *, timeout=10):
        """Calls `json_rpc', sleeping if it fails for up time `timeout' seconds.  Returns the
        response if it succeeds, raises the last exception if timeout is reached.  If the process
        exit, raises a RuntimeError"""

        until = time.time() + timeout
        now = time.time()
        while now < until:
            exit_status = self.proc.poll()
            if exit_status is not None:
                raise ProcessExited("{} exited ({}) while waiting for an RPC response".format(self.name, exit_status))

            timeout = until - now
            try:
                return self.json_rpc(method, params, timeout=timeout)
            except:
                if time.time() + .25 >= until:
                    raise
                time.sleep(.25)
                now = time.time()
                if now >= until:
                    raise


class Daemon(RPCDaemon):
    base_args = ('--dev-allow-local-ips', '--fixed-difficulty=1', '--devnet', '--non-interactive')

    def __init__(self, *,
            beldexd='beldexd',
            listen_ip=None, p2p_port=None, rpc_port=None, zmq_port=None, qnet_port=None, ss_port=None,
            name=None,
            datadir=None,
            master_node=False,
            log_level=2,
            peers=()):
        self.rpc_port = rpc_port or next_port()
        if name is None:
            name = 'beldexd@{}'.format(self.rpc_port)
        super().__init__(name)
        self.listen_ip = listen_ip or LISTEN_IP
        self.p2p_port = p2p_port or next_port()
        self.zmq_port = zmq_port or next_port()
        self.qnet_port = qnet_port or next_port()
        self.ss_port = ss_port or next_port()
        self.peers = []

        self.args = [beldexd] + list(self.__class__.base_args)
        self.args += (
                '--data-dir={}/beldex-{}-{}'.format(datadir or '.', self.listen_ip, self.rpc_port),
                '--log-level={}'.format(log_level),
                '--log-file=beldex.log'.format(self.listen_ip, self.p2p_port),
                '--p2p-bind-ip={}'.format(self.listen_ip),
                '--p2p-bind-port={}'.format(self.p2p_port),
                '--rpc-admin={}:{}'.format(self.listen_ip, self.rpc_port),
                '--quorumnet-port={}'.format(self.qnet_port),
                )

        for d in peers:
            self.add_peer(d)

        if master_node:
            self.args += (
                    '--master-node',
                    '--master-node-public-ip={}'.format(self.listen_ip),
                    '--storage-server-port={}'.format(self.ss_port),
                    )


    def arguments(self):
        return self.args + [
            '--add-exclusive-node={}:{}'.format(node.listen_ip, node.p2p_port) for node in self.peers]


    def ready(self):
        """Waits for the daemon to get ready, i.e. for it to start returning something to a
        `get_info` rpc request.  Calls start() if it hasn't already been called."""
        if not self.proc:
            self.start()
        self.wait_for_json_rpc("get_info")


    def add_peer(self, node):
        """Adds a peer.  Must be called before starting."""
        if self.proc:
            raise RuntimeError("add_peer needs to be called before start()")
        self.peers.append(node)


    def remove_peer(self, node):
        """Removes a peer.  Must be called before starting."""
        if self.proc:
            raise RuntimeError("remove_peer needs to be called before start()")
        self.peers.remove(node)


    def mine_blocks(self, num_blocks, wallet, *, slow=True):
        a = wallet.address()
        self.rpc('/start_mining', {
            "miner_address": a,
            "threads_count": 1,
            "num_blocks": num_blocks,
            "slow_mining": slow
        });


    def height(self):
        return self.rpc("/get_height").json()["height"]


    def txpool_hashes(self):
        return [x['id_hash'] for x in self.rpc("/get_transaction_pool").json()['transactions']]


    def ping(self, *, storage=True, belnet=True):
        """Sends fake storage server and belnet pings to the running beldexd"""
        # Versions must meet MIN_UPTIME_PROOF_VERSIONS for the active hardfork or the daemon rejects
        # the uptime proof. hf20+ requires storage-server >= 2.4.0 and belnet >= 0.9.8. Each ping must
        # carry THIS daemon's own ed25519 pubkey, otherwise handle_ping rejects it as an invalid pubkey
        # and never records the version. Fetch it live so it's correct for every master node.
        def require_ok(response, name):
            result = response.json().get("result", {})
            if result.get("status") != "OK":
                raise RuntimeError("{} ping failed: {}".format(name, result))

        ed_pubkey = self.json_rpc("get_master_keys").json()["result"]["master_node_ed25519_pubkey"]
        if storage:
            require_ok(self.json_rpc("storage_server_ping", {
                "version": [2, 4, 1],
                "https_port": 0,
                "omq_port": 0,
                "pubkey_ed25519": ed_pubkey,
            }), "storage server")
        if belnet:
            require_ok(self.json_rpc("belnet_ping", {
                "version": [0, 9, 9],
                "pubkey_ed25519": ed_pubkey,
            }), "belnet")

    def send_uptime_proof(self):
        """Triggerst test uptime proof"""
        self.json_rpc("test_trigger_uptime_proof")


    def p2p_resync(self):
        """Triggers a p2p resync to happen soon (i.e. at the next p2p idle loop)."""
        self.json_rpc("test_trigger_p2p_resync")



class Wallet(RPCDaemon):
    base_args = ('--disable-rpc-login', '--non-interactive', '--password','', '--devnet', '--disable-rpc-long-poll',
 '--daemon-ssl=disabled')

    def __init__(
            self,
            node,
            *,
            rpc_wallet='beldex-wallet-rpc',
            name=None,
            datadir=None,
            listen_ip=None,
            rpc_port=None,
            log_level=2):

        self.listen_ip = listen_ip or LISTEN_IP
        self.rpc_port = rpc_port or next_port()
        self.node = node

        self.name = name or 'wallet@{}'.format(self.rpc_port)
        super().__init__(self.name)

        self.walletdir = '{}/wallet-{}-{}'.format(datadir or '.', self.listen_ip, self.rpc_port)
        self.args = [rpc_wallet] + list(self.__class__.base_args)
        self.args += (
                '--rpc-bind-ip={}'.format(self.listen_ip),
                '--rpc-bind-port={}'.format(self.rpc_port),
                '--log-level={}'.format(log_level),
                '--log-file={}/log.txt'.format(self.walletdir),
                '--daemon-address={}:{}'.format(node.listen_ip, node.rpc_port),
                '--wallet-dir={}'.format(self.walletdir),
                )
        self.wallet_address = None


    def ready(self, wallet="wallet", existing=False):
        """Makes the wallet ready, waiting for it to start up and create a new wallet (or load an
        existing one, if `existing`) within the rpc wallet.  Calls `start()` first if it hasn't
        already been called.  Does *not* explicitly refresh."""

        if not self.proc:
            self.start()

        self.wallet_filename = wallet
        if existing:
            r = self.wait_for_json_rpc("open_wallet", {"filename": wallet, "password": ""})
        else:
            r = self.wait_for_json_rpc("create_wallet", {"filename": wallet, "password": "", "language": "English"})
        if 'result' not in r.json():
            raise RuntimeError("Cannot open or create wallet: {}".format(r['error'] if 'error' in r else 'Unexpected response: {}'.format(r)))
        print('Started RPC Wallet - {}, on {}:{}'.format(self.name, self.listen_ip, self.rpc_port))


    def refresh(self):
        return self.json_rpc('refresh')


    def address(self):
        if not self.wallet_address:
            self.wallet_address = self.json_rpc("get_address").json()["result"]["address"]

        return self.wallet_address


    def new_wallet(self):
        self.wallet_address = None
        r = self.wait_for_json_rpc("close_wallet")
        if 'result' not in r.json():
            raise RuntimeError("Cannot close current wallet: {}".format(r['error'] if 'error' in r else 'Unexpected response: {}'.format(r)))
        if not hasattr(self, 'wallet_suffix'):
            self.wallet_suffix = 2
        else:
            self.wallet_suffix += 1
        r = self.wait_for_json_rpc("create_wallet", {"filename": "{}_{}".format(self.wallet_filename, self.wallet_suffix), "password": "", "language": "English"})
        if 'result' not in r.json():
            raise RuntimeError("Cannot create wallet: {}".format(r['error'] if 'error' in r else 'Unexpected response: {}'.format(r)))


    def balances(self, refresh=False):
        """Returns (total, unlocked) balances.  Can optionally refresh first."""
        if refresh:
            self.refresh()
        b = self.json_rpc("get_balance").json()['result']
        return (b['balance'], b['unlocked_balance'])


    def transfer(self, to, amount=None, *, priority=None, sweep=False):
        """Attempts a transfer.  Throws TransferFailed if it gets rejected by the daemon, otherwise
        returns the 'result' key."""
        if priority is None:
            priority = 1
        if sweep and not amount:
            r = self.json_rpc("sweep_all", {"address": to.address(), "priority": priority})
        elif amount and not sweep:
            r = self.json_rpc("transfer_split", {"destinations": [{"address": to.address(), "amount": amount}], "priority": priority})
        else:
            raise RuntimeError("Wallet.transfer: either `sweep` or `amount` must be given")

        r = r.json()
        if 'error' in r:
            raise TransferFailed("Transfer failed: {}".format(r['error']['message']), r)
        return r['result']


    def find_transfers(self, txids, in_=True, pool=True, out=True, pending=False, failed=False):
        transfers = self.json_rpc('get_transfers', {'in':in_, 'pool':pool, 'out':out, 'pending':pending, 'failed':failed }).json()['result']
        def find_tx(txid):
            for type_, txs in transfers.items():
                for tx in txs:
                    if tx['txid'] == txid:
                        return tx
        return [find_tx(txid) for txid in txids]


    def register_mn(self, mn):
        # Ensure the wallet has caught up to the daemon's tip before staking; the daemon rejects with
        # "Wallet is not synced" (is_synced check) if the wallet lags even one block behind.
        self.refresh()
        # Full single-operator stake. The daemon ignores the staking_requirement we pass and uses
        # get_staking_requirement(height), which is 100000*COIN (=1e14) below devnet height 56500.
        # The contribution amount must equal that requirement so it maps to 100% of the portions;
        # anything less produces sub-minimum portions, which convert_registration_args silently drops
        # (returning empty addresses with success=true) and then the wallet segfaults on addresses[0].
        staking_requirement = 100000 * 1000000000
        r = mn.json_rpc("get_master_node_registration_cmd", {
            "operator_cut": "100",
            "contributor_addresses": [self.address()],
            "contributor_amounts": [staking_requirement],
            "staking_requirement": staking_requirement
        }).json()
        if 'error' in r:
            raise RuntimeError("Registration cmd generation failed: {}".format(r['error']['message']))
        cmd = r['result']['registration_cmd']
        r = self.json_rpc("register_master_node", {"register_master_node_str": cmd}).json()
        if 'error' in r:
            raise RuntimeError("Failed to submit master node registration tx: {}".format(r['error']['message']))
