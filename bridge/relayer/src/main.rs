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
        _ => {
            eprintln!(
                "beldex-bridge-relayer {}\n\nusage:\n  \
                 beldex-bridge-relayer prepare <payload.json | ->\n  \
                 beldex-bridge-relayer mint-digest --chain-id <n> --contract <20hex> --to <20hex> --amount <dec> --txid <32hex>\n\n\
                 `prepare`     reads a signed relay payload and prints the {{chain_id, to, data}} to broadcast.\n\
                 `mint-digest` prints the 32-byte digest the Pevm committee signs for a mint\n\
                 (feed it to the signer as BRIDGE_SIGNER_SIGN_DIGEST).",
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

fn read_source(src: &str) -> Result<String, String> {
    if src == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| format!("stdin: {e}"))?;
        Ok(s)
    } else {
        std::fs::read_to_string(src).map_err(|e| format!("{src}: {e}"))
    }
}
