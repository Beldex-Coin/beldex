//! `beldex-bridge-relayer` — the reference courier + submit-your-own CLI (Phase I).
//!
//! ```text
//!   beldex-bridge-relayer prepare <payload.json | -->   # emit the ready-to-broadcast call
//! ```
//!
//! `prepare` reads a signed [`RelayPayload`] (a file path, or `-` for stdin) and prints the
//! exact `{chain_id, to, data}` to broadcast. Broadcast it yourself with any wallet, e.g.:
//!
//! ```text
//!   cast send <to> <data> --rpc-url <chain rpc> --private-key <your gas key>
//! ```
//!
//! This is the **liveness guarantee**: constructing this call needs no bridge key and no
//! running relayer service — the committee signature is already inside the payload.

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);

    match cmd {
        Some("prepare") => {
            let src = args.get(2).map(String::as_str).unwrap_or("-");
            match run_prepare(src) {
                Ok(out) => print!("{out}"),
                Err(e) => {
                    eprintln!("prepare: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("mint-digest") => match run_mint_digest(&args[2..]) {
            Ok(out) => print!("{out}"),
            Err(e) => {
                eprintln!("mint-digest: {e}");
                std::process::exit(1);
            }
        },
        Some("relay") => {
            let src = args.get(2).map(String::as_str).unwrap_or("-");
            match run_relay(src) {
                Ok(out) => print!("{out}"),
                Err(e) => {
                    eprintln!("relay: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!(
                "beldex-bridge-relayer {}\n\nusage:\n  \
                 beldex-bridge-relayer prepare <payload.json | ->\n  \
                 beldex-bridge-relayer relay   <payload.json | ->\n  \
                 beldex-bridge-relayer mint-digest --chain-id <n> --contract <20hex> --to <20hex> --amount <dec> --txid <32hex>\n\n\
                 `prepare`     reads a signed relay payload and prints the {{chain_id, to, data}} to broadcast.\n\
                 `relay`       signs + broadcasts it, paying gas (build with --features submit-http).\n\
                 `mint-digest` prints the 32-byte digest the Pevm committee signs for a mint\n\
                 (feed it to the signer as BRIDGE_SIGNER_SIGN_DIGEST).\n\n\
                 relay environment:\n  \
                 RELAYER_GAS_KEY   32-byte hex secp256k1 gas key (NOT a bridge key)\n  \
                 RELAYER_CHAINS    JSON: [{{\"chain_id\":31337,\"rpc_url\":\"http://127.0.0.1:8545\"}}]\n\
                 \t\t    optional per chain: max_fee_cap_wei, priority_fee_wei, gas_limit_pct",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(2);
        }
    }
}

/// `mint-digest --chain-id <n> --contract <20hex> --to <20hex> --amount <dec> --txid <32hex>`
/// → the 32-byte digest to feed the committee `sign` (`BRIDGE_SIGNER_SIGN_DIGEST`).
fn run_mint_digest(args: &[String]) -> Result<String, String> {
    let mut chain_id: Option<u64> = None;
    let mut contract: Option<[u8; 20]> = None;
    let mut to: Option<[u8; 20]> = None;
    let mut amount: Option<u128> = None;
    let mut txid: Option<[u8; 32]> = None;

    let mut i = 0;
    while i + 1 < args.len() {
        let val = args[i + 1].as_str();
        match args[i].as_str() {
            "--chain-id" => chain_id = Some(val.parse().map_err(|_| "bad --chain-id".to_string())?),
            "--contract" => contract = Some(hex20(val, "--contract")?),
            "--to" => to = Some(hex20(val, "--to")?),
            "--amount" => amount = Some(val.parse().map_err(|_| "bad --amount".to_string())?),
            "--txid" => txid = Some(hex32(val, "--txid")?),
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }

    let chain_id = chain_id.ok_or("missing --chain-id")?;
    let contract = contract.ok_or("missing --contract")?;
    let to = to.ok_or("missing --to")?;
    let amount = amount.ok_or("missing --amount")?;
    let txid = txid.ok_or("missing --txid")?;

    // The Pevm `sign` leg consumes the *preimage* (it keccaks it internally), so feed
    // `preimage` to BRIDGE_SIGNER_SIGN_PREIMAGE. `digest` = keccak256(preimage) is what the
    // contract recomputes and `ecrecover`s — shown for cross-checking.
    let preimage = beldex_bridge_relayer::mint_preimage(chain_id, contract, to, amount, txid);
    let digest = beldex_bridge_relayer::mint_digest(chain_id, contract, to, amount, txid);
    Ok(format!(
        "preimage: {}   # -> BRIDGE_SIGNER_SIGN_PREIMAGE (Pevm sign)\ndigest:   {}   # keccak256(preimage), the contract's ecrecover input\n",
        hex::encode(&preimage),
        hex::encode(digest),
    ))
}

fn hex20(s: &str, field: &str) -> Result<[u8; 20], String> {
    let b = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| format!("bad hex {field}"))?;
    b.try_into().map_err(|_| format!("{field} must be 20 bytes"))
}

fn hex32(s: &str, field: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| format!("bad hex {field}"))?;
    b.try_into().map_err(|_| format!("{field} must be 32 bytes"))
}

#[cfg(feature = "json")]
fn run_prepare(src: &str) -> Result<String, String> {
    let json = read_source(src)?;
    let payload = beldex_bridge_relayer::RelayPayload::from_json(&json)
        .map_err(|e| format!("invalid payload: {e:?}"))?;
    let call = payload.to_prepared();
    Ok(format!(
        "chain_id: {}\nto:       0x{}\ndata:     0x{}\n",
        call.chain_id,
        hex::encode(call.to),
        hex::encode(&call.data),
    ))
}

#[cfg(not(feature = "json"))]
fn run_prepare(_src: &str) -> Result<String, String> {
    Err("built without the `json` feature; rebuild with --features json".into())
}

/// `relay <payload>` — sign the outer EIP-1559 envelope with the configured gas key and
/// broadcast. Reverts (already minted, over cap, bad signature) are caught by the gas
/// estimation dry-run and reported without spending anything.
#[cfg(feature = "submit-http")]
fn run_relay(src: &str) -> Result<String, String> {
    use beldex_bridge_relayer::{ChainEndpoint, HttpSubmitter, RelayPayload, TxSubmitter};

    let json = read_source(src)?;
    let payload =
        RelayPayload::from_json(&json).map_err(|e| format!("invalid payload: {e:?}"))?;

    let key_hex = std::env::var("RELAYER_GAS_KEY")
        .map_err(|_| "set RELAYER_GAS_KEY (32-byte hex secp256k1 gas key)".to_string())?;
    let key = hex32(key_hex.trim(), "RELAYER_GAS_KEY")?;

    let chains_json = std::env::var("RELAYER_CHAINS")
        .map_err(|_| "set RELAYER_CHAINS (JSON array of {chain_id, rpc_url, …})".to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&chains_json).map_err(|e| format!("RELAYER_CHAINS: {e}"))?;
    let arr = v.as_array().ok_or("RELAYER_CHAINS must be a JSON array")?;
    let mut chains = Vec::new();
    for c in arr {
        let chain_id = c.get("chain_id").and_then(|x| x.as_u64()).ok_or("chain entry needs chain_id")?;
        let rpc_url = c.get("rpc_url").and_then(|x| x.as_str()).ok_or("chain entry needs rpc_url")?;
        let mut ep = ChainEndpoint::new(chain_id, rpc_url);
        if let Some(x) = c.get("max_fee_cap_wei").and_then(|x| x.as_u64()) {
            ep.max_fee_cap_wei = x as u128;
        }
        if let Some(x) = c.get("priority_fee_wei").and_then(|x| x.as_u64()) {
            ep.priority_fee_wei = x as u128;
        }
        if let Some(x) = c.get("gas_limit_pct").and_then(|x| x.as_u64()) {
            ep.gas_limit_pct = x;
        }
        chains.push(ep);
    }

    let submitter = HttpSubmitter::new(&key, chains).map_err(|e| format!("gas key: {e}"))?;
    let call = payload.to_prepared();
    let tx_hash = submitter.submit(&call).map_err(|e| format!("{e:?}"))?;
    Ok(format!(
        "relayed: chain_id {} → {}\n  gas wallet: 0x{}\n  tx: {}\n",
        call.chain_id,
        format_args!("0x{}", hex::encode(call.to)),
        hex::encode(submitter.address),
        tx_hash,
    ))
}

#[cfg(not(feature = "submit-http"))]
fn run_relay(_src: &str) -> Result<String, String> {
    Err("built without the `submit-http` feature; rebuild with --features submit-http \
         (or use `prepare` + `cast send`, which needs no service)"
        .into())
}

fn read_source(src: &str) -> Result<String, String> {
    if src == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| format!("stdin: {e}"))?;
        Ok(s)
    } else {
        std::fs::read_to_string(src).map_err(|e| format!("{src}: {e}"))
    }
}
