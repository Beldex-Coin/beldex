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
    // the committee's IP but listens on `port_base + index`.
    let port_base: Option<u16> = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok());

    // 2) This node's mesh identity. Turnkey path: read the masternode ed25519 key
    //    file (`<data-dir>/key_ed25519`, 64 bytes) and derive both the message-auth
    //    key and the x25519 channel keypair from it — exactly as beldexd does — so
    //    no secrets are copied by hand. Fallback: explicit MESH_* env vars.
    let listen_endpoint = match std::env::var("BRIDGE_SIGNER_MESH_LISTEN") {
        Ok(l) => l,
        Err(_) => match port_base {
            Some(base) => format!("tcp://0.0.0.0:{}", base + self_index),
            None => return Err("set BRIDGE_SIGNER_MESH_LISTEN or BRIDGE_SIGNER_MESH_PORT_BASE".into()),
        },
    };
    let identity = if let Ok(key_path) = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE") {
        let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
        if sk_bytes.len() != 64 {
            return Err(format!("MN key {key_path} is {} bytes, expected 64 (key_ed25519)", sk_bytes.len()));
        }
        let mut ed25519_secret = [0u8; 64];
        ed25519_secret.copy_from_slice(&sk_bytes);
        let mut ed_pub = [0u8; 32];
        ed_pub.copy_from_slice(&ed25519_secret[32..64]); // libsodium sk = seed‖pub
        let curve_secret = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
        let curve_public = ffi::ed25519_pk_to_x25519(&ed_pub)?;
        println!("mesh identity: derived from MN key {key_path}");
        MeshIdentity { listen_endpoint, curve_secret, curve_public, ed25519_secret }
    } else {
        MeshIdentity {
            listen_endpoint,
            curve_secret: h32(&env("BRIDGE_SIGNER_MESH_CURVE_SK")?, "MESH_CURVE_SK")?,
            curve_public: h32(&env("BRIDGE_SIGNER_MESH_CURVE_PK")?, "MESH_CURVE_PK")?,
            ed25519_secret: h64(&env("BRIDGE_SIGNER_MESH_ED25519_SK")?, "MESH_ED25519_SK")?,
        }
    };

    // 3) Peer transport address book. Precedence: explicit peers file > single-host
    //    indexed ports (PORT_BASE) > multi-host shared port. Each peer's curve key
    //    always comes from consensus (the committee), never from an ad-hoc file.
    let mesh_port: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5580);
    let to_addr = |(index, endpoint, curve_pubkey): (u16, String, [u8; 32])| PeerTransportAddr {
        index,
        endpoint,
        curve_pubkey,
    };
    let peers: Vec<PeerTransportAddr> = if let Ok(peers_path) = std::env::var("BRIDGE_SIGNER_PEERS_FILE") {
        println!("peer address book: from peers file {peers_path} (explicit override)");
        let peers_text = std::fs::read_to_string(&peers_path)
            .map_err(|e| format!("read peers file {peers_path}: {e}"))?;
        let mut peers = Vec::new();
        for (lineno, raw) in peers_text.lines().enumerate() {
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
                continue; // don't dial self
            }
            peers.push(PeerTransportAddr {
                index,
                endpoint: parts[1].to_string(),
                curve_pubkey: h32(parts[2], "peer curve key")?,
            });
        }
        peers
    } else if let Some(base) = port_base {
        println!("peer address book: from bridge.committee (single-host, ports {base}+index)");
        committee.peer_transport_indexed(self_index as usize, base).into_iter().map(to_addr).collect()
    } else if committee.has_network_info() {
        println!("peer address book: from bridge.committee (mesh port {mesh_port})");
        committee.peer_transport(self_index as usize, mesh_port).into_iter().map(to_addr).collect()
    } else {
        return Err("set BRIDGE_SIGNER_MESH_PORT_BASE or BRIDGE_SIGNER_PEERS_FILE, or update beldexd for ips/x25519".into());
    };
    if peers.len() + 1 != committee.size() {
        return Err(format!(
            "peer book has {} peers; committee size is {} (need {} peers + self)",
            peers.len(), committee.size(), committee.size() - 1
        ));
    }

    // Safety: peers dial this node using the x25519 key beldexd advertises for it,
    // so our own curve public key must match — otherwise every inbound connection
    // fails the CURVE handshake. Catch the misconfiguration up front. (With the MN
    // key file this is automatic, but it also catches a wrong key file.)
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && identity.curve_public != *expected {
            return Err("this node's derived x25519 does not match its bridge.committee entry (wrong MN key file / curve key?)".into());
        }
    }

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
    // Channel encryption. Production: CURVE (needs libzmq built with CURVE).
    // Set BRIDGE_SIGNER_MESH_USE_CURVE=false for a libzmq without CURVE — plain
    // sockets, but per-message ed25519 auth (S4) stays on.
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    if !use_curve {
        println!("WARNING: mesh CURVE disabled (plain channel); message auth (S4) still enforced");
    }

    // 4) Run. Production stores into Vault/enclave; the scaffold uses memory.
    let mut store = MemoryShareStore::new();
    let mut rng = rand::rngs::OsRng;
    println!("running Pgw FROST DKG over the mesh (key generation {key_generation})…");
    let group_vk = run_live(
        &committee, self_index, key_generation, &identity, &peers, use_curve, &mut store, &mut rng, timeout,
    )
    .map_err(|e| format!("dkg failed: {e:?}"))?;

    println!("Pgw DKG complete — group ed25519 key (gateway owner_key): {}", hex(&group_vk));
    println!("(share stored at pgw.share v{key_generation}; production custody = Vault/enclave)");
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
