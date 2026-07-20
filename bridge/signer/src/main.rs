//! `beldex-bridge-signer` entry point (Phase C scaffold).
//!
//! At this stage the binary only loads and validates configuration and reports
//! the modules that are wired. The service loop (connect to `beldexd` OMQ, fetch
//! the committee, run DKG/refresh, serve signing sessions) is added as C.2–C.5
//! integrate the audited TSS crates — see `DUE_DILIGENCE.md`.

use std::collections::HashMap;
use std::process::ExitCode;

use beldex_bridge_signer::config::{self, Config};
use beldex_bridge_signer::SIGNER_VERSION;

const PREFIX: &str = "BRIDGE_SIGNER_";

/// Build the config map from (1) an optional `.env` file, then (2) real process
/// environment variables which override it. In both, keys are `BRIDGE_SIGNER_<KEY>`
/// and are lower-cased without the prefix (e.g. `BRIDGE_SIGNER_GATEWAY_ID` ->
/// `gateway_id`). The `.env` path defaults to `./.env` and can be overridden with
/// `BRIDGE_SIGNER_DOTENV` (or disabled by pointing it at a missing file).
fn config_map() -> HashMap<String, String> {
    let mut map = HashMap::new();

    // (1) .env file (lower priority).
    let dotenv_path = std::env::var(format!("{PREFIX}DOTENV")).unwrap_or_else(|_| ".env".to_string());
    match std::fs::read_to_string(&dotenv_path) {
        Ok(contents) => {
            for (k, v) in config::parse_dotenv(&contents) {
                if let Some(rest) = k.strip_prefix(PREFIX) {
                    map.insert(rest.to_ascii_lowercase(), v);
                }
            }
            eprintln!("(loaded config from {dotenv_path})");
        }
        Err(_) => eprintln!("(no {dotenv_path} file; using environment only)"),
    }

    // (2) real env vars (higher priority) override the .env.
    for (k, v) in std::env::vars() {
        if let Some(rest) = k.strip_prefix(PREFIX) {
            map.insert(rest.to_ascii_lowercase(), v);
        }
    }
    map
}

fn print_status(cfg: &Config) {
    let [a, b, c] = SIGNER_VERSION;
    println!("beldex-bridge-signer v{a}.{b}.{c}");
    println!("  beldexd RPC : {}", cfg.beldexd_rpc_url);
    println!("  OxenMQ      : {}", cfg.oxenmq_endpoint);
    println!("  gateway     : {}", hex(&cfg.gateway_id));
    println!("  self MN     : {}", hex(&cfg.self_mn_pubkey));
    println!("  epoch blocks: {}", cfg.bridge_epoch_blocks);
    println!("  threshold   : {}", cfg.committee_threshold);
    println!("  share store : {:?}", cfg.share_store);
    println!("  pool cap L  : {}", cfg.max_pool);
    if cfg!(feature = "live-dkg") {
        println!("subcommands: `dkg` — run the Pgw FROST DKG over the mesh");
    } else {
        println!("(build with --features live-dkg for the `dkg` subcommand)");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `dkg` subcommand: fetch the live committee and run the `Pgw` FROST DKG across
/// the authenticated mesh (C.2). Only built with `--features live-dkg`.
#[cfg(feature = "live-dkg")]
fn run_dkg(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::live::{run_live, MeshIdentity, PeerTransportAddr};
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    use beldex_bridge_signer::share_store::MemoryShareStore;
    use std::time::Duration;

    let env = |k: &str| std::env::var(k).map_err(|_| format!("missing env {k}"));
    let h32 = |s: &str, k: &str| config::parse_hex32(s).ok_or(format!("{k} must be 32-byte hex"));
    let h64 = |s: &str, k: &str| config::parse_hex64(s).ok_or(format!("{k} must be 64-byte hex"));

    // 1) Read the live committee (now carrying signer_keys, S4). Prefer the index
    //    the daemon reports for itself (OMQ `self_index`) so no per-node pubkey
    //    config is needed; fall back to matching the configured MN pubkey.
    let client = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    let committee = client.fetch_committee(None).map_err(|e| e.to_string())?;
    let self_index = committee
        .daemon_self_index
        .or_else(|| committee.self_index(&cfg.self_mn_pubkey))
        .ok_or("this node is not on the current bridge committee")? as u16;
    if !committee.has_signer_keys() {
        return Err("bridge.committee returned no signer_keys — update beldexd (mesh auth needs them)".into());
    }
    println!(
        "committee epoch {} height {} size {} threshold {}; self_index {}",
        committee.epoch, committee.height, committee.size(), committee.threshold, self_index
    );

    // A single-host deployment (local devnet) sets a port base: every node shares
    // the committee's IP but listens on `port_base + index`. **Dual DKG** (both
    // legs) requires this mode so each leg gets a distinct port range.
    let port_base: Option<u16> = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok());

    // 2) This node's mesh keys (x25519 channel + ed25519 message-auth), derived
    //    once. Turnkey path: read the masternode ed25519 key file
    //    (`<data-dir>/key_ed25519`, 64 bytes) and derive both — exactly as beldexd
    //    does. Fallback: explicit MESH_* env vars. The per-leg listen port is
    //    applied when building each leg's identity.
    let (curve_secret, curve_public, ed25519_secret) =
        if let Ok(key_path) = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE") {
            let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
            if sk_bytes.len() != 64 {
                return Err(format!("MN key {key_path} is {} bytes, expected 64 (key_ed25519)", sk_bytes.len()));
            }
            let mut ed25519_secret = [0u8; 64];
            ed25519_secret.copy_from_slice(&sk_bytes);
            let mut ed_pub = [0u8; 32];
            ed_pub.copy_from_slice(&ed25519_secret[32..64]); // libsodium sk = seed‖pub
            let cs = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
            let cp = ffi::ed25519_pk_to_x25519(&ed_pub)?;
            println!("mesh identity: derived from MN key {key_path}");
            (cs, cp, ed25519_secret)
        } else {
            (
                h32(&env("BRIDGE_SIGNER_MESH_CURVE_SK")?, "MESH_CURVE_SK")?,
                h32(&env("BRIDGE_SIGNER_MESH_CURVE_PK")?, "MESH_CURVE_PK")?,
                h64(&env("BRIDGE_SIGNER_MESH_ED25519_SK")?, "MESH_ED25519_SK")?,
            )
        };

    // Safety self-check: our derived x25519 must match what the committee advertises
    // (else peers dial the wrong key and every CURVE handshake fails).
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("this node's derived x25519 does not match its bridge.committee entry (wrong MN key file / curve key?)".into());
        }
    }

    let to_addr = |(index, endpoint, curve_pubkey): (u16, String, [u8; 32])| PeerTransportAddr {
        index,
        endpoint,
        curve_pubkey,
    };
    let make_identity = move |listen: String| MeshIdentity {
        listen_endpoint: listen,
        curve_secret,
        curve_public,
        ed25519_secret,
    };

    let key_generation: u32 = std::env::var("BRIDGE_SIGNER_DKG_KEYGEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let timeout = Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_DKG_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );
    // Channel encryption. Production: CURVE (needs libzmq built with CURVE). Set
    // BRIDGE_SIGNER_MESH_USE_CURVE=false for a libzmq without CURVE — plain sockets,
    // but per-message ed25519 auth (S4) stays on.
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    if !use_curve {
        println!("WARNING: mesh CURVE disabled (plain channel); message auth (S4) still enforced");
    }

    // 3) Which key(s) to generate: pgw | pevm | both (default `both` — the dual DKG).
    let leg_sel = std::env::var("BRIDGE_SIGNER_DKG_LEG").unwrap_or_else(|_| "both".into());
    let run_pgw = leg_sel == "both" || leg_sel == "pgw";
    let run_pevm = leg_sel == "both" || leg_sel == "pevm";
    if !run_pgw && !run_pevm {
        return Err(format!("BRIDGE_SIGNER_DKG_LEG must be pgw|pevm|both (got '{leg_sel}')"));
    }
    if run_pevm && port_base.is_none() {
        return Err("the Pevm leg / dual DKG needs BRIDGE_SIGNER_MESH_PORT_BASE (distinct port ranges per leg)".into());
    }

    // Pevm ports live PEVM_PORT_OFFSET above the Pgw ports, so the two legs never
    // collide when run back-to-back on one host. Kept small (100, not 1000) so the
    // Pevm range stays near the Pgw base and away from ports the host may already
    // use — e.g. macOS's AirPlay Receiver on :7000, which a base of 6000 + 1000
    // would hit for self_index 0. Overridable via BRIDGE_SIGNER_MESH_PEVM_OFFSET.
    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let check_size = |peers: &[PeerTransportAddr]| -> Result<(), String> {
        if peers.len() + 1 != committee.size() {
            return Err(format!(
                "peer book has {} peers; committee size is {} (need {} peers + self)",
                peers.len(), committee.size(), committee.size() - 1
            ));
        }
        Ok(())
    };

    // --- Pgw (ed25519 / FROST) ------------------------------------------------
    if run_pgw {
        let (identity, peers) = match port_base {
            Some(base) => {
                println!("Pgw peer book: bridge.committee, single-host ports {base}+index");
                let peers: Vec<PeerTransportAddr> = committee
                    .peer_transport_indexed(self_index as usize, base)
                    .into_iter()
                    .map(to_addr)
                    .collect();
                (make_identity(format!("tcp://0.0.0.0:{}", base + self_index)), peers)
            }
            None => {
                // Single-leg legacy resolution: explicit listen + (peers file or the
                // committee's shared mesh port).
                let listen = std::env::var("BRIDGE_SIGNER_MESH_LISTEN")
                    .map_err(|_| "set BRIDGE_SIGNER_MESH_PORT_BASE (or MESH_LISTEN + a peer source)".to_string())?;
                let peers: Vec<PeerTransportAddr> =
                    if let Ok(peers_path) = std::env::var("BRIDGE_SIGNER_PEERS_FILE") {
                        println!("Pgw peer book: peers file {peers_path}");
                        let text = std::fs::read_to_string(&peers_path)
                            .map_err(|e| format!("read peers file {peers_path}: {e}"))?;
                        let mut peers = Vec::new();
                        for (lineno, raw) in text.lines().enumerate() {
                            let line = raw.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() != 3 {
                                return Err(format!("peers file line {}: expected `index endpoint curve_hex`", lineno + 1));
                            }
                            let index: u16 = parts[0].parse().map_err(|_| format!("peers line {}: bad index", lineno + 1))?;
                            if index == self_index {
                                continue;
                            }
                            peers.push(PeerTransportAddr {
                                index,
                                endpoint: parts[1].to_string(),
                                curve_pubkey: h32(parts[2], "peer curve key")?,
                            });
                        }
                        peers
                    } else if committee.has_network_info() {
                        let mesh_port: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT")
                            .ok().and_then(|s| s.parse().ok()).unwrap_or(5580);
                        println!("Pgw peer book: bridge.committee shared port {mesh_port}");
                        committee.peer_transport(self_index as usize, mesh_port).into_iter().map(to_addr).collect()
                    } else {
                        return Err("no peer source: set BRIDGE_SIGNER_MESH_PORT_BASE or BRIDGE_SIGNER_PEERS_FILE".into());
                    };
                (make_identity(listen), peers)
            }
        };
        check_size(&peers)?;

        let mut store = MemoryShareStore::new();
        let mut rng = rand::rngs::OsRng;
        println!("running Pgw FROST DKG over the mesh (key generation {key_generation})…");
        let group_vk = run_live(
            &committee, self_index, key_generation, &identity, &peers, use_curve, &mut store, &mut rng, timeout,
        )
        .map_err(|e| format!("Pgw dkg failed: {e:?}"))?;
        println!("Pgw DKG complete — group ed25519 key (gateway owner_key): {}", hex(&group_vk));
    }

    // --- Pevm (secp256k1 / CGGMP21) -------------------------------------------
    if run_pevm {
        let base = port_base.expect("checked above") + pevm_offset;
        #[cfg(feature = "live-pevm-dkg")]
        {
            use beldex_bridge_signer::cggmp21_driver::live::run_live_pevm;
            println!("Pevm peer book: bridge.committee, single-host ports {base}+index");
            let peers: Vec<PeerTransportAddr> = committee
                .peer_transport_indexed(self_index as usize, base)
                .into_iter()
                .map(to_addr)
                .collect();
            check_size(&peers)?;
            let identity = make_identity(format!("tcp://0.0.0.0:{}", base + self_index));
            println!("running Pevm cggmp21 DKG over the mesh (key generation {key_generation})…");
            let (x33, _blob) = run_live_pevm(
                &committee, self_index, key_generation, &identity, &peers, use_curve, timeout,
            )
            .map_err(|e| format!("Pevm dkg failed: {e:?}"))?;
            // Derive the EVM signer address the wBDX contract checks (ecrecover):
            // decompress the group key, keccak256 the uncompressed point, take the
            // last 20 bytes.
            use k256::ecdsa::VerifyingKey;
            use sha3::{Digest, Keccak256};
            let addr = VerifyingKey::from_sec1_bytes(&x33)
                .map(|vk| {
                    let enc = vk.to_encoded_point(false);
                    let h = Keccak256::digest(&enc.as_bytes()[1..]);
                    let mut a = [0u8; 20];
                    a.copy_from_slice(&h[12..]);
                    a
                })
                .map_err(|e| format!("Pevm group key is not a valid secp256k1 point: {e}"))?;
            println!(
                "Pevm DKG complete — wBDX signer address 0x{} (group key {})",
                hex(&addr),
                hex(&x33)
            );
        }
        #[cfg(not(feature = "live-pevm-dkg"))]
        {
            let _ = base;
            return Err("the Pevm leg needs a build with --features live-pevm-dkg".into());
        }
    }

    println!("(shares in the scaffold in-memory store; production custody = Vault/enclave)");
    Ok(())
}

#[cfg(not(feature = "live-dkg"))]
fn run_dkg(_cfg: &Config) -> Result<(), String> {
    Err("the `dkg` subcommand requires a build with `--features live-dkg`".into())
}

fn main() -> ExitCode {
    let subcommand = std::env::args().nth(1);
    let cfg = match Config::from_map(&config_map()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            eprintln!("set BRIDGE_SIGNER_<KEY> env vars (gateway_id, self_mn_pubkey, ...)");
            return ExitCode::FAILURE;
        }
    };

    match subcommand.as_deref() {
        Some("dkg") => match run_dkg(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("dkg: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            print_status(&cfg);
            ExitCode::SUCCESS
        }
    }
}
