#!/usr/bin/python3

import argparse
import json
import sys

import requests

sys.path.append('../testdata')
import config


def instruct_daemon(method, params):
    payload = {"method": method, "params": params}
    headers = {'content-type': "application/json"}
    try:
        response = requests.request(
            "POST",
            "http://" + config.listen_ip + ":" + config.listen_port + "/json_rpc",
            data=json.dumps(payload, skipkeys=False),
            headers=headers,
        )
        response.raise_for_status()
        return json.loads(response.text)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    except json.JSONDecodeError:
        raise SystemExit('Invalid response from daemon, check daemon is running on this machine')


parser = argparse.ArgumentParser(description='List all master nodes.')
parser.add_argument("--active-only", action="store_true", help="Only list active master nodes")
parser.add_argument("--limit", type=int, help="Limit the number of master nodes returned")
parser.add_argument("--json", action="store_true", help="Print the full JSON-RPC response")
args = parser.parse_args()

params = {}
if args.active_only:
    params["active_only"] = True
if args.limit is not None:
    params["limit"] = args.limit

answer = instruct_daemon('get_master_nodes', params)

if args.json:
    print(json.dumps(answer, indent=4, sort_keys=True))
    sys.exit(0)

master_nodes = answer.get("result", {}).get("master_node_states", [])
if not master_nodes:
    print(json.dumps(answer, indent=4, sort_keys=True))
    sys.exit(0)

print("Master nodes: " + str(len(master_nodes)))
for index, master_node in enumerate(master_nodes, 1):
    pubkey = master_node.get("master_node_pubkey", "<unknown>")
    active = master_node.get("active", "unknown")
    funded = master_node.get("funded", "unknown")
    registration_height = master_node.get("registration_height", "unknown")
    last_uptime_proof = master_node.get("last_uptime_proof", "unknown")
    print(
        str(index) + ". "
        + pubkey
        + " active=" + str(active)
        + " funded=" + str(funded)
        + " registration_height=" + str(registration_height)
        + " last_uptime_proof=" + str(last_uptime_proof)
    )
