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
        println!("subcommands:");
        println!("  dkg  — run the dual DKG over the mesh (persists Pgw share if SHARE_DIR set)");
        println!("  sign — run the Pgw FROST signing over the mesh (loads the persisted share)");
    } else {
        println!("(build with --features live-dkg for the `dkg` / `sign` subcommands)");
    }
    if cfg!(feature = "evm-watcher-http") {
        println!("  watch-evm — poll EVM chains for finalized wBDX burns (BRIDGE_SIGNER_EVM_CHAINS)");
    } else {
        println!("(build with --features evm-watcher-http for the `watch-evm` subcommand)");
    }
    if cfg!(feature = "autonomy") {
        println!("  serve — autonomous watcher pipeline: detect + dedup deposit/burn duties (dry-run backend)");
        println!("          with --features serve-live + BRIDGE_SIGNER_SERVE_LIVE=1: coordinated live signing");
    } else {
        println!("(build with --features autonomy for the `serve` subcommand)");
    }
    if cfg!(feature = "omq-client") {
        println!("  relay-watch — subscribe to the daemon's mint bus and broadcast each payload");
        println!("                (no bridge key needed; this is the relayer-operator command)");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `dkg` subcommand: fetch the live committee and run the `Pgw` FROST DKG across
/// the authenticated mesh (C.2). Only built with `--features live-dkg`.
#[cfg(feature = "live-dkg")]
fn run_dkg(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::live::{run_live_capture, MeshIdentity, PeerTransportAddr};
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
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

        let mut rng = rand::rngs::OsRng;
        println!("running Pgw FROST DKG over the mesh (key generation {key_generation})…");
        let (group_vk, kp_blob, pk_blob) = run_live_capture(
            &committee, self_index, key_generation, &identity, &peers, use_curve, &mut rng, timeout,
        )
        .map_err(|e| format!("Pgw dkg failed: {e:?}"))?;
        println!("Pgw DKG complete — group ed25519 key (gateway owner_key): {}", hex(&group_vk));
        // Persist the share material so a later `sign` invocation can load it. This
        // is a dev file store; production custody (Vault/enclave) is D.1.
        if let Ok(dir) = std::env::var("BRIDGE_SIGNER_SHARE_DIR") {
            persist_pgw_material(&dir, self_index, &kp_blob, &pk_blob, &group_vk)?;
            println!("Pgw share material written to {dir}/pgw-{self_index}.{{keypackage,pubkeypackage,groupvk}}");
        }
    }

    // --- Pevm (secp256k1 / CGGMP21) -------------------------------------------
    if run_pevm {
        let base = port_base.expect("checked above") + pevm_offset;
        #[cfg(feature = "live-pevm-dkg")]
        {
            use beldex_bridge_signer::cggmp21_aux_driver::{
                complete_key_share_blob, run_cggmp21_aux_over_transport,
            };
            use beldex_bridge_signer::cggmp21_driver::run_cggmp21_keygen_over_transport;
            use beldex_bridge_signer::dkg_driver::live::assemble_mesh;
            println!("Pevm peer book: bridge.committee, single-host ports {base}+index");
            let peers: Vec<PeerTransportAddr> = committee
                .peer_transport_indexed(self_index as usize, base)
                .into_iter()
                .map(to_addr)
                .collect();
            check_size(&peers)?;
            let identity = make_identity(format!("tcp://0.0.0.0:{}", base + self_index));

            // One mesh for both Pevm phases (keygen then aux) — avoids a port
            // rebind race between them and reuses the established links.
            let mut transport = assemble_mesh(&committee, self_index, &identity, &peers, use_curve)
                .map_err(|e| format!("Pevm mesh assembly failed: {e:?}"))?;

            println!("running Pevm cggmp21 keygen over the mesh (key generation {key_generation})…");
            let (x33, incomplete_blob) = run_cggmp21_keygen_over_transport(
                &committee, self_index, key_generation, &mut transport, timeout,
            )
            .map_err(|e| format!("Pevm keygen failed: {e:?}"))?;

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
                "Pevm keygen complete — wBDX signer address 0x{} (group key {})",
                hex(&addr),
                hex(&x33)
            );

            // Aux-info over the same mesh, then combine into the complete share the
            // signing driver needs. This is the slow safe-prime phase.
            println!("running Pevm aux-info generation over the mesh…");
            let aux_blob = run_cggmp21_aux_over_transport(
                &committee, self_index, key_generation, &mut transport, timeout,
            )
            .map_err(|e| format!("Pevm aux-info failed: {e:?}"))?;
            let complete_blob = complete_key_share_blob(&incomplete_blob, &aux_blob)
                .map_err(|e| format!("Pevm share completion failed: {e:?}"))?;
            println!("Pevm complete share ready (keygen + aux-info)");

            if let Ok(dir) = std::env::var("BRIDGE_SIGNER_SHARE_DIR") {
                persist_pevm_material(&dir, self_index, &complete_blob, &x33)?;
                println!("Pevm share material written to {dir}/pevm-{self_index}.{{keyshare,groupkey}}");
            }
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

/// Write this node's `Pgw` DKG material to `<dir>/pgw-<index>.{keypackage,
/// pubkeypackage,groupvk}` for a later `sign` invocation. Dev file store only.
#[cfg(feature = "live-dkg")]
fn persist_pgw_material(
    dir: &str,
    self_index: u16,
    kp: &[u8],
    pk: &[u8],
    vk: &[u8; 32],
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create share dir {dir}: {e}"))?;
    let write = |suffix: &str, bytes: &[u8]| {
        std::fs::write(format!("{dir}/pgw-{self_index}.{suffix}"), bytes)
            .map_err(|e| format!("write {suffix}: {e}"))
    };
    write("keypackage", kp)?;
    write("pubkeypackage", pk)?;
    write("groupvk", vk)?;
    Ok(())
}

/// Write this node's complete `Pevm` share to `<dir>/pevm-<index>.{keyshare,
/// groupkey}` for a later `sign` invocation. Dev file store only.
#[cfg(feature = "live-pevm-dkg")]
fn persist_pevm_material(
    dir: &str,
    self_index: u16,
    keyshare: &[u8],
    x33: &[u8; 33],
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create share dir {dir}: {e}"))?;
    std::fs::write(format!("{dir}/pevm-{self_index}.keyshare"), keyshare)
        .map_err(|e| format!("write keyshare: {e}"))?;
    std::fs::write(format!("{dir}/pevm-{self_index}.groupkey"), x33)
        .map_err(|e| format!("write groupkey: {e}"))?;
    Ok(())
}

/// `sign` subcommand: load this node's persisted share material and run the signing
/// driver for the selected leg across the authenticated mesh. `BRIDGE_SIGNER_SIGN_LEG`
/// = `pgw` (FROST → libsodium-verified ed25519 release; default) or `pevm` (cggmp21
/// → ecrecover'd wBDX mint). Only built with `--features live-dkg`; the `pevm` leg
/// additionally needs `live-pevm-dkg`. Run `dkg` first with `BRIDGE_SIGNER_SHARE_DIR`.
#[cfg(feature = "live-dkg")]
fn run_sign(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::live::{MeshIdentity, PeerTransportAddr};
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    use std::time::Duration;

    // 1) Committee + self_index.
    let client = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    let committee = client.fetch_committee(None).map_err(|e| e.to_string())?;
    let self_index = committee
        .daemon_self_index
        .or_else(|| committee.self_index(&cfg.self_mn_pubkey))
        .ok_or("this node is not on the current bridge committee")? as u16;
    if !committee.has_signer_keys() {
        return Err("bridge.committee returned no signer_keys — update beldexd".into());
    }

    // 2) Leg + signer set (default: the first `threshold` committee members).
    let leg = std::env::var("BRIDGE_SIGNER_SIGN_LEG").unwrap_or_else(|_| "pgw".into());
    let signers: Vec<u16> = match std::env::var("BRIDGE_SIGNER_SIGN_SIGNERS") {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => (0..committee.threshold as u16).collect(),
    };
    println!(
        "committee epoch {} size {} threshold {}; self_index {}; leg {}; signer set {:?}",
        committee.epoch, committee.size(), committee.threshold, self_index, leg, signers
    );
    if !signers.contains(&self_index) {
        println!("this node ({self_index}) is not in the signer set — nothing to do");
        return Ok(());
    }

    // 3) Shared config + mesh identity material (from the MN key).
    let dir = std::env::var("BRIDGE_SIGNER_SHARE_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_SHARE_DIR (where `dkg` wrote the shares)".to_string())?;
    let port_base: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or("set BRIDGE_SIGNER_MESH_PORT_BASE (single-host devnet)")?;
    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let key_path = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE")
        .map_err(|_| "set BRIDGE_SIGNER_MN_KEY_FILE".to_string())?;
    let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
    if sk_bytes.len() != 64 {
        return Err(format!("MN key {key_path} is {} bytes, expected 64", sk_bytes.len()));
    }
    let mut ed25519_secret = [0u8; 64];
    ed25519_secret.copy_from_slice(&sk_bytes);
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&ed25519_secret[32..64]);
    let curve_secret = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
    let curve_public = ffi::ed25519_pk_to_x25519(&ed_pub)?;
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("derived x25519 does not match this node's bridge.committee entry".into());
        }
    }
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    if !use_curve {
        println!("WARNING: mesh CURVE disabled (plain channel); message auth (S4) still enforced");
    }
    let timeout = Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_SIGN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );

    // Build this node's identity + peer book for a given single-host port base.
    let build_mesh = |base: u16| -> (MeshIdentity, Vec<PeerTransportAddr>) {
        let identity = MeshIdentity {
            listen_endpoint: format!("tcp://0.0.0.0:{}", base + self_index),
            curve_secret,
            curve_public,
            ed25519_secret,
        };
        let peers = committee
            .peer_transport_indexed(self_index as usize, base)
            .into_iter()
            .map(|(index, endpoint, curve_pubkey)| PeerTransportAddr { index, endpoint, curve_pubkey })
            .collect();
        (identity, peers)
    };

    match leg.as_str() {
        "pgw" => {
            let (identity, peers) = build_mesh(port_base);
            sign_pgw(&committee, self_index, &signers, &dir, &identity, &peers, use_curve, timeout)
        }
        "pevm" => {
            let (identity, peers) = build_mesh(port_base + pevm_offset);
            sign_pevm(&committee, self_index, &signers, &dir, &identity, &peers, use_curve, timeout)
        }
        other => Err(format!("BRIDGE_SIGNER_SIGN_LEG must be pgw|pevm (got '{other}')")),
    }
}

/// `Pgw` leg of `sign`: FROST threshold-sign a 32-byte digest over the mesh and
/// verify the aggregate under libsodium (the consensus check).
#[cfg(feature = "live-dkg")]
#[allow(clippy::too_many_arguments)]
fn sign_pgw(
    committee: &beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    signers: &[u16],
    dir: &str,
    identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    use_curve: bool,
    timeout: std::time::Duration,
) -> Result<(), String> {
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::frost_sign_driver::live::run_live_sign;
    use frost_ed25519 as frost;

    let message: [u8; 32] = match std::env::var("BRIDGE_SIGNER_SIGN_DIGEST") {
        Ok(h) => config::parse_hex32(&h).ok_or("BRIDGE_SIGNER_SIGN_DIGEST must be 32-byte hex")?,
        Err(_) => {
            println!("WARNING: no BRIDGE_SIGNER_SIGN_DIGEST set — signing a fixed demo digest");
            [0x5au8; 32]
        }
    };
    let read = |suffix: &str| {
        std::fs::read(format!("{dir}/pgw-{self_index}.{suffix}"))
            .map_err(|e| format!("read {suffix}: {e} (run `dkg` first with BRIDGE_SIGNER_SHARE_DIR set)"))
    };
    let key_package = frost::keys::KeyPackage::deserialize(&read("keypackage")?)
        .map_err(|e| format!("bad keypackage: {e}"))?;
    let pubkey_package = frost::keys::PublicKeyPackage::deserialize(&read("pubkeypackage")?)
        .map_err(|e| format!("bad pubkeypackage: {e}"))?;
    let group_vk: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("cannot serialize group verifying key")?;

    let mut rng = rand::rngs::OsRng;
    println!("running Pgw FROST signing over the mesh…");
    let sig = run_live_sign(
        committee, self_index, signers, key_package, pubkey_package, message, 0, identity, peers,
        use_curve, &mut rng, timeout,
    )
    .map_err(|e| format!("Pgw sign failed: {e:?}"))?;

    let ok = ffi::ed25519_verify_consensus(&sig, &message, &group_vk);
    println!("Pgw signature : {}", hex(&sig));
    println!("  over digest : {}", hex(&message));
    println!("  owner_key   : {}", hex(&group_vk));
    println!("  libsodium   : {}", if ok { "VERIFIED (consensus would accept)" } else { "REJECTED" });
    if !ok {
        return Err("the aggregated signature failed libsodium verification".into());
    }
    Ok(())
}

/// `Pevm` leg of `sign`: cggmp21 threshold-sign a mint preimage over the mesh and
/// `ecrecover` the aggregate to the wBDX signer address (the on-chain check).
#[cfg(feature = "live-pevm-dkg")]
#[allow(clippy::too_many_arguments)]
fn sign_pevm(
    committee: &beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    signers: &[u16],
    dir: &str,
    identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    use_curve: bool,
    timeout: std::time::Duration,
) -> Result<(), String> {
    use beldex_bridge_signer::cggmp21_sign_driver::live::run_live_pevm_sign;
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
    use sha3::{Digest, Keccak256};

    // The mint preimage the contract keccaks + ecrecovers. Demo default; in
    // production this is the ABI-encoded mint tuple.
    let preimage: Vec<u8> = match std::env::var("BRIDGE_SIGNER_SIGN_PREIMAGE") {
        Ok(h) => hex_to_bytes(&h).ok_or("BRIDGE_SIGNER_SIGN_PREIMAGE must be hex")?,
        Err(_) => {
            println!("WARNING: no BRIDGE_SIGNER_SIGN_PREIMAGE set — signing a fixed demo mint preimage");
            b"BELDEX_BRIDGE_MINT_V1 || chainid || wBDX || to || amount || beldexTxid".to_vec()
        }
    };
    let key_share = std::fs::read(format!("{dir}/pevm-{self_index}.keyshare"))
        .map_err(|e| format!("read pevm keyshare: {e} (run `dkg` first with SHARE_DIR set)"))?;

    println!("running Pevm cggmp21 signing over the mesh…");
    let (rs, x33) = run_live_pevm_sign(
        committee, self_index, signers, &key_share, &preimage, /*attempt=*/ 0, identity, peers,
        use_curve, timeout,
    )
    .map_err(|e| format!("Pevm sign failed: {e:?}"))?;

    // Derive the expected wBDX address from the group key, then ecrecover.
    let expected = VerifyingKey::from_sec1_bytes(&x33)
        .map(|vk| {
            let enc = vk.to_encoded_point(false);
            let h = Keccak256::digest(&enc.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&h[12..]);
            a
        })
        .map_err(|e| format!("Pevm group key invalid: {e}"))?;
    let digest32: [u8; 32] = Keccak256::digest(&preimage).into();
    let k_sig = K256Sig::from_slice(&rs).map_err(|e| format!("bad signature bytes: {e}"))?;
    let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
    let mut recovered = None;
    for rec in [0u8, 1u8] {
        if let Ok(vk) = VerifyingKey::recover_from_prehash(
            &digest32,
            &k_sig,
            RecoveryId::from_byte(rec).unwrap(),
        ) {
            let enc = vk.to_encoded_point(false);
            let h = Keccak256::digest(&enc.as_bytes()[1..]);
            if h[12..] == expected {
                recovered = Some(rec);
                break;
            }
        }
    }
    println!("Pevm signature: {}{}", hex(&rs[..32]), hex(&rs[32..]));
    println!("  over digest : {}", hex(&digest32));
    println!("  wBDX signer : 0x{}", hex(&expected));
    match recovered {
        Some(rec) => println!("  ecrecover   : VERIFIED (v={})", 27 + rec),
        None => {
            println!("  ecrecover   : FAILED");
            return Err("the aggregated signature did not ecrecover to the wBDX signer".into());
        }
    }
    Ok(())
}

#[cfg(all(feature = "live-dkg", not(feature = "live-pevm-dkg")))]
#[allow(clippy::too_many_arguments)]
fn sign_pevm(
    _committee: &beldex_bridge_signer::committee::CommitteeView,
    _self_index: u16,
    _signers: &[u16],
    _dir: &str,
    _identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    _peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    _use_curve: bool,
    _timeout: std::time::Duration,
) -> Result<(), String> {
    Err("the Pevm sign leg needs a build with --features live-pevm-dkg".into())
}

/// Parse an even-length hex string to bytes (for `BRIDGE_SIGNER_SIGN_PREIMAGE`).
#[cfg(feature = "live-pevm-dkg")]
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(not(feature = "live-dkg"))]
fn run_sign(_cfg: &Config) -> Result<(), String> {
    Err("the `sign` subcommand requires a build with `--features live-dkg`".into())
}

/// `watch-evm` subcommand: build one EVM watcher per chain from
/// `BRIDGE_SIGNER_EVM_CHAINS` and poll for finalized wBDX burns (E.2). Prints each
/// finalized `ReleaseEvent` and its canonical id (what members agree on). Only built
/// with `--features evm-watcher-http`.
#[cfg(feature = "evm-watcher-http")]
fn run_watch_evm(_cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::evm_watcher::{build_registry, parse_evm_chains};
    use std::time::Duration;

    let chains_json = std::env::var("BRIDGE_SIGNER_EVM_CHAINS").map_err(|_| {
        "set BRIDGE_SIGNER_EVM_CHAINS — a JSON array of \
         {chain_id, contract, confirmations, rpc, per_tx_max, per_epoch_cap, start_block}"
            .to_string()
    })?;
    let configs = parse_evm_chains(&chains_json)?;
    if configs.is_empty() {
        return Err("BRIDGE_SIGNER_EVM_CHAINS is empty — no chains to watch".into());
    }
    // Build the E.3 registry (validates uniqueness) even though the loop below only
    // needs the watchers — it is the config's single source of truth.
    let _registry = build_registry(&configs)?;

    // The L1 genesis binds every release canonical id (S6/S14, no cross-net replay).
    let genesis: [u8; 32] = match std::env::var("BRIDGE_SIGNER_GENESIS_HASH") {
        Ok(h) => config::parse_hex32(&h).ok_or("BRIDGE_SIGNER_GENESIS_HASH must be 32-byte hex")?,
        Err(_) => {
            println!("WARNING: no BRIDGE_SIGNER_GENESIS_HASH — using zeros for release canonical ids");
            [0u8; 32]
        }
    };
    let poll_secs: u64 = std::env::var("BRIDGE_SIGNER_WATCH_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    // Bound the loop for a scripted run; unset = run until interrupted.
    let max_iters: Option<u64> = std::env::var("BRIDGE_SIGNER_WATCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok());

    let mut watchers: Vec<_> = configs.iter().map(|c| (c.chain_id, c.build_watcher())).collect();
    println!(
        "watching {} EVM chain(s), polling every {poll_secs}s: {:?}",
        watchers.len(),
        configs.iter().map(|c| c.chain_id).collect::<Vec<_>>()
    );

    let mut iter = 0u64;
    loop {
        for (chain_id, w) in watchers.iter_mut() {
            match w.advance() {
                Ok(update) => {
                    for ev in &update.finalized {
                        let cid = ev.canonical_id(genesis);
                        println!(
                            "chain {chain_id}: RELEASE finalized — amount={} recipient=0x{} evm_txid=0x{} canonical_id=0x{}",
                            ev.amount,
                            hex(&ev.beldex_recipient),
                            hex(&ev.evm_txid),
                            hex(&cid),
                        );
                    }
                    for d in &update.dropped {
                        println!("chain {chain_id}: burn dropped (reorg) at height {}", d.inclusion_height);
                    }
                }
                Err(e) => eprintln!("chain {chain_id}: advance error: {e:?}"),
            }
        }
        iter += 1;
        if max_iters.is_some_and(|m| iter >= m) {
            break;
        }
        std::thread::sleep(Duration::from_secs(poll_secs));
    }
    Ok(())
}

#[cfg(not(feature = "evm-watcher-http"))]
fn run_watch_evm(_cfg: &Config) -> Result<(), String> {
    Err("the `watch-evm` subcommand requires a build with `--features evm-watcher-http`".into())
}

/// `serve` subcommand: the **autonomous watcher pipeline** (Phase L). Builds the Beldex
/// deposit watcher + one EVM burn watcher per chain, then runs the orchestrator loop
/// ([`service::serve`]) — each tick ingests finalized deposits/burns, deduplicates them into
/// duties, and (with the **dry-run** `LoggingBackend`) reports each detected duty. This
/// exercises the full autonomy pipeline (observe → resolve → dedup → duty) end to end; the
/// live signing+submission backend swaps in for `LoggingBackend`. Needs `--features autonomy`.
#[cfg(feature = "autonomy")]
fn run_serve(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::beldex_watcher::{BeldexWatcher, HttpBeldexRpc};
    use beldex_bridge_signer::evm_watcher::{build_registry, parse_evm_chains};
    use beldex_bridge_signer::orchestrator::{Duty, Orchestrator};
    use beldex_bridge_signer::service::{serve, LoggingBackend, ServeOptions, WatcherEventSource};
    use std::time::Duration;

    // EVM chains (burns → releases).
    let chains_json = std::env::var("BRIDGE_SIGNER_EVM_CHAINS")
        .map_err(|_| "set BRIDGE_SIGNER_EVM_CHAINS (a JSON array of chain configs; see watch-evm)".to_string())?;
    let configs = parse_evm_chains(&chains_json)?;
    if configs.is_empty() {
        return Err("BRIDGE_SIGNER_EVM_CHAINS is empty — no chains to watch".into());
    }
    let registry = build_registry(&configs)?;
    let evm: Vec<_> = configs.iter().map(|c| c.build_watcher()).collect();

    // Beldex gateway deposits (→ mints).
    let beldexd_rpc =
        std::env::var("BRIDGE_SIGNER_BELDEXD_RPC").unwrap_or_else(|_| cfg.beldexd_rpc_url.clone());
    let gateway_id = std::env::var("BRIDGE_SIGNER_GATEWAY_ID")
        .map_err(|_| "set BRIDGE_SIGNER_GATEWAY_ID (the bridge gateway to watch for deposits)".to_string())?;
    let start_height: u64 = std::env::var("BRIDGE_SIGNER_BELDEX_START_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let view_secret = config::parse_hex32(
        &std::env::var("BRIDGE_SIGNER_GATEWAY_VIEW_SECRET").map_err(|_| {
            "set BRIDGE_SIGNER_GATEWAY_VIEW_SECRET (32-byte hex; the gateway view secret that decrypts A.5 memos)"
                .to_string()
        })?,
    )
    .ok_or("BRIDGE_SIGNER_GATEWAY_VIEW_SECRET must be 32-byte hex")?;
    // Echo the watcher config: a wrong gateway id / RPC / start height otherwise reads as
    // an eternally quiet, "healthy" pipeline (the watcher successfully finds nothing).
    println!("  beldex watcher: gateway {gateway_id} via {beldexd_rpc}, from height {start_height}");

    // Cloned before the watcher consumes them — the live backend reuses both.
    let beldexd_rpc_for_live = beldexd_rpc.clone();
    let gateway_id_for_live = gateway_id.clone();
    // Finality posture. Strict by default: a deposit is only actionable at or below
    // `get_info.immutable_height`. beldexd omits that field entirely on a chain that has
    // never checkpointed — and it never will below CHECKPOINT_QUORUM_SIZE (20) active
    // masternodes, so every local devnet is in that bucket: deposits confirm and no mint
    // duty is ever created, silently, because a poll error is treated as transient.
    // Setting this to N falls back to `top_height - N` in exactly that case; a daemon that
    // does report a checkpoint ignores it outright.
    // An empty value counts as unset (strict), so a launcher can pass the variable
    // through unconditionally — `FOO=${X:+...}` does not work as an assignment prefix,
    // because a word produced by expansion is parsed as the command name, not a prefix.
    let beldex_confirmations: Option<u64> = match std::env::var("BRIDGE_SIGNER_BELDEX_CONFIRMATIONS") {
        Ok(s) if s.trim().is_empty() => None,
        Ok(s) => Some(s.trim().parse::<u64>().map_err(|_| {
            "BRIDGE_SIGNER_BELDEX_CONFIRMATIONS must be a non-negative integer".to_string()
        })?),
        Err(_) => None,
    };
    let mut beldex = BeldexWatcher::new(HttpBeldexRpc::new(beldexd_rpc), gateway_id, start_height);
    if let Some(n) = beldex_confirmations {
        println!("  beldex finality: RELAXED — a chain with no checkpoint falls back to top_height - {n}");
        beldex = beldex.with_fallback_confirmations(n);
    }

    let mut src = WatcherEventSource { beldex, evm, view_secret, registry };
    let mut orch = Orchestrator::new();

    let poll_secs: u64 = std::env::var("BRIDGE_SIGNER_WATCH_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let max_ticks: Option<u64> = std::env::var("BRIDGE_SIGNER_WATCH_ITERS").ok().and_then(|s| s.parse().ok());
    let opts = ServeOptions { interval: Duration::from_secs(poll_secs), max_ticks };

    // Live backend path (build with `--features serve-live`, enable with BRIDGE_SIGNER_SERVE_LIVE=1):
    // signs each duty over the mesh, emits mint payloads, self-submits releases.
    #[cfg(feature = "serve-live")]
    if std::env::var("BRIDGE_SIGNER_SERVE_LIVE").map(|v| v == "1" || v == "true").unwrap_or(false) {
        return run_serve_live(
            cfg,
            &mut src,
            &mut orch,
            &opts,
            &configs,
            &beldexd_rpc_for_live,
            &gateway_id_for_live,
            poll_secs,
        );
    }
    let _ = (&beldexd_rpc_for_live, &gateway_id_for_live); // consumed only by the live path

    println!(
        "serve: autonomous watcher pipeline — DRY-RUN backend (detects + dedups duties, does NOT sign/submit)"
    );
    println!("  polling every {poll_secs}s across {} EVM chain(s)", configs.len());

    let mut backend = LoggingBackend::new(|d: &Duty| match d {
        Duty::Mint(e) => println!(
            "MINT duty: beldex_txid=0x{} chain={} to=0x{} amount={}",
            hex(&e.beldex_txid),
            e.dst_chain.0,
            hex(&e.to),
            e.amount
        ),
        Duty::Release(e) => println!(
            "RELEASE duty: evm_txid=0x{} chain={} amount={} recipient=0x{}",
            hex(&e.evm_txid),
            e.chain.0,
            e.amount,
            hex(&e.beldex_recipient)
        ),
    });

    let reports = serve(&mut orch, &mut src, &mut backend, &opts, || false);
    let (pending, in_flight, done) = orch.counts();
    println!(
        "serve: finished after {} tick(s); duties pending={pending} in_flight={in_flight} done={done}",
        reports.len()
    );
    Ok(())
}

#[cfg(not(feature = "autonomy"))]
fn run_serve(_cfg: &Config) -> Result<(), String> {
    Err("the `serve` subcommand requires a build with `--features autonomy`".into())
}

/// `relay-watch` — subscribe to the daemon's mint bus and hand each payload to a broadcaster.
///
/// This is what a **relayer operator** runs. It needs no bridge key, no share material, no
/// signer-host access — only an OMQ endpoint it can reach — which is the whole point of
/// Phase I: relaying is permissionless and carries no authority. Each payload is piped to
/// `BRIDGE_SIGNER_RELAY_CMD` (default `beldex-bridge-relayer relay -`), whose own environment
/// holds the gas key.
///
/// Failures are logged and skipped, never retried in a tight loop: a payload that fails to
/// broadcast is still valid forever, another subscriber may carry it, and the wBDX contract
/// rejects a duplicate anyway.
#[cfg(feature = "omq-client")]
fn run_relay_watch_standalone() -> Result<(), String> {
    use beldex_bridge_signer::omq_client::OmqMintSubscriber;
    use std::time::Duration;

    // Comma-separated list: subscribe to EVERY endpoint given. Signers publish to their own
    // daemons by default, so a relayer that watches several daemons is robust to any one
    // signer being a straggler (its daemon then simply carries no publish that round);
    // duplicates across daemons are deduped below by txid.
    let endpoints = std::env::var("BRIDGE_SIGNER_OXENMQ_ENDPOINT").map_err(|_| {
        "set BRIDGE_SIGNER_OXENMQ_ENDPOINT (one or more comma-separated beldexd OMQ sockets \
         to subscribe to, e.g. ipc://<node>/devnet/beldexd.sock) — this is the only required \
         setting"
            .to_string()
    })?;
    let cmd = std::env::var("BRIDGE_SIGNER_RELAY_CMD")
        .unwrap_or_else(|_| "beldex-bridge-relayer relay -".to_string());
    let mut subs: Vec<OmqMintSubscriber> = endpoints
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|e| {
            println!("relay-watch: subscribing to {e}");
            OmqMintSubscriber::new(e.to_string())
        })
        .collect();
    if subs.is_empty() {
        return Err("BRIDGE_SIGNER_OXENMQ_ENDPOINT contained no endpoints".into());
    }
    println!("  each mint payload → `{cmd}`");
    println!("  (this process holds NO bridge key; the gas key lives in the relay command)");
    let mut count = 0u64;
    // Process-local dedup by beldex_txid: the daemon replays its retained backlog to a new
    // subscriber (so an outage is caught up), and reconnections can re-deliver — skip what
    // this process already handled instead of re-running gas estimation on it. The
    // contract's replay guard remains the real idempotency authority.
    let mut handled: std::collections::HashSet<String> = std::collections::HashSet::new();
    let per_sub_timeout = Duration::from_millis(5000 / subs.len().max(1) as u64);
    loop {
        for sub in subs.iter_mut() {
            match sub.poll(per_sub_timeout) {
                Ok(Some(payload)) => {
                    let txid = payload
                        .split(r#""beldex_txid":""#)
                        .nth(1)
                        .and_then(|s| s.split('"').next())
                        .unwrap_or("")
                        .to_string();
                    if !txid.is_empty() && !handled.insert(txid.clone()) {
                        println!("(skip: txid {txid} already handled this session)");
                        continue;
                    }
                    count += 1;
                    println!("[{count}] mint payload received: {payload}");
                    match pipe_to_relay(&cmd, &payload) {
                        Ok(out) => println!("     relayed: {}", out.trim()),
                        Err(e) => eprintln!("     RELAY FAILED ({e}) — payload above stays valid"),
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("relay-watch: {e}; will retry that endpoint");
                }
            }
        }
    }
}

#[cfg(not(feature = "omq-client"))]
fn run_relay_watch_standalone() -> Result<(), String> {
    Err("the `relay-watch` subcommand requires a build with `--features omq-client`".into())
}

/// Run `cmd` (via the shell, so it can carry arguments/pipes) and write `payload` to its
/// stdin — the mint hand-off from the keyless signer to a gas-paying relayer. Returns the
/// command's stdout on success. Best-effort by design: see the call site.
/// (`serve-live` implies `live-dkg` implies `omq-client`, so this one gate covers both the
/// `serve --live` hand-off and the standalone `relay-watch`.)
#[cfg(feature = "omq-client")]
fn pipe_to_relay(cmd: &str, payload: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn `{cmd}`: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("no stdin on the relay command")?
        .write_all(payload.as_bytes())
        .map_err(|e| format!("write to relay stdin: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("wait for relay: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "exit {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Loaded, reusable signing context for the live `serve` backend: the committee view, this
/// node's index + signer set, both legs' key material, and the mesh identity parameters. A
/// duty's sign closure ([`LiveSigners::pevm_sign`] / [`LiveSigners::pgw_sign`]) rebuilds the
/// per-leg mesh and runs one session — mirroring the `sign` subcommand, but driven by the
/// autonomy loop instead of an operator-supplied digest.
#[cfg(feature = "serve-live")]
struct LiveSigners {
    committee: beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    signers: Vec<u16>,
    pgw_key_package: frost_ed25519::keys::KeyPackage,
    pgw_pubkey_package: frost_ed25519::keys::PublicKeyPackage,
    pgw_group_vk: [u8; 32],
    pevm_key_share: Vec<u8>,
    curve_secret: [u8; 32],
    curve_public: [u8; 32],
    ed25519_secret: [u8; 64],
    port_base: u16,
    pevm_offset: u16,
    use_curve: bool,
    timeout: std::time::Duration,
}

#[cfg(feature = "serve-live")]
impl LiveSigners {
    fn build_mesh(
        &self,
        base: u16,
    ) -> (
        beldex_bridge_signer::dkg_driver::live::MeshIdentity,
        Vec<beldex_bridge_signer::dkg_driver::live::PeerTransportAddr>,
    ) {
        use beldex_bridge_signer::dkg_driver::live::{MeshIdentity, PeerTransportAddr};
        let identity = MeshIdentity {
            listen_endpoint: format!("tcp://0.0.0.0:{}", base + self.self_index),
            curve_secret: self.curve_secret,
            curve_public: self.curve_public,
            ed25519_secret: self.ed25519_secret,
        };
        let peers = self
            .committee
            .peer_transport_indexed(self.self_index as usize, base)
            .into_iter()
            .map(|(index, endpoint, curve_pubkey)| PeerTransportAddr { index, endpoint, curve_pubkey })
            .collect();
        (identity, peers)
    }

    /// `Pgw`: FROST-sign a 32-byte digest over the mesh, verify the aggregate under libsodium
    /// (the L1 consensus check), and return the 64-byte ed25519 signature.
    ///
    /// `signers` is the round's participant set — under coordinated autonomy this is the
    /// session's canonical ACK set (only members that independently verified the payload,
    /// C.5), not a static roster. `attempt` namespaces the round's mesh frames so a retry
    /// never ingests the failed attempt's messages.
    fn pgw_sign(&self, message: &[u8; 32], signers: &[u16], attempt: u32) -> Result<[u8; 64], String> {
        use beldex_bridge_signer::ffi;
        use beldex_bridge_signer::frost_sign_driver::live::run_live_sign;
        let (identity, peers) = self.build_mesh(self.port_base);
        let mut rng = rand::rngs::OsRng;
        let sig = run_live_sign(
            &self.committee,
            self.self_index,
            signers,
            self.pgw_key_package.clone(),
            self.pgw_pubkey_package.clone(),
            *message,
            attempt,
            &identity,
            &peers,
            self.use_curve,
            &mut rng,
            self.timeout,
        )
        .map_err(|e| format!("Pgw sign failed: {e:?}"))?;
        if !ffi::ed25519_verify_consensus(&sig, message, &self.pgw_group_vk) {
            return Err("Pgw aggregate failed libsodium verification".into());
        }
        Ok(sig)
    }

    /// `Pevm`: cggmp21-sign a mint preimage over the mesh, then `ecrecover` to find the
    /// recovery id and return the 65-byte `r‖s‖v` the wBDX contract verifies.
    /// `signers`/`attempt` as in [`LiveSigners::pgw_sign`].
    fn pevm_sign(&self, preimage: &[u8], signers: &[u16], attempt: u32) -> Result<[u8; 65], String> {
        use beldex_bridge_signer::cggmp21_sign_driver::live::run_live_pevm_sign;
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
        use sha3::{Digest, Keccak256};
        let (identity, peers) = self.build_mesh(self.port_base + self.pevm_offset);
        let (rs, x33) = run_live_pevm_sign(
            &self.committee,
            self.self_index,
            signers,
            &self.pevm_key_share,
            preimage,
            attempt,
            &identity,
            &peers,
            self.use_curve,
            self.timeout,
        )
        .map_err(|e| format!("Pevm sign failed: {e:?}"))?;

        let expected = VerifyingKey::from_sec1_bytes(&x33)
            .map(|vk| {
                let enc = vk.to_encoded_point(false);
                let h = Keccak256::digest(&enc.as_bytes()[1..]);
                let mut a = [0u8; 20];
                a.copy_from_slice(&h[12..]);
                a
            })
            .map_err(|e| format!("Pevm group key invalid: {e}"))?;
        let digest32: [u8; 32] = Keccak256::digest(preimage).into();
        let k_sig = K256Sig::from_slice(&rs).map_err(|e| format!("bad signature bytes: {e}"))?;
        let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
        for rec in [0u8, 1u8] {
            if let Ok(vk) =
                VerifyingKey::recover_from_prehash(&digest32, &k_sig, RecoveryId::from_byte(rec).unwrap())
            {
                let enc = vk.to_encoded_point(false);
                let h = Keccak256::digest(&enc.as_bytes()[1..]);
                if h[12..] == expected {
                    let mut out = [0u8; 65];
                    out[..64].copy_from_slice(&rs[..]);
                    out[64] = 27 + rec;
                    return Ok(out);
                }
            }
        }
        Err("Pevm aggregate did not ecrecover to the wBDX signer".into())
    }
}

/// Build the [`LiveSigners`] context: fetch the committee, resolve this node's index + signer
/// set, load both legs' key material (`dkg` output under `BRIDGE_SIGNER_SHARE_DIR`), and derive
/// the mesh identity from the MN key. Mirrors the `sign` subcommand's setup.
#[cfg(feature = "serve-live")]
fn build_live_signers(cfg: &Config) -> Result<LiveSigners, String> {
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    use frost_ed25519 as frost;
    use std::time::Duration;

    let client = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    let committee = client.fetch_committee(None).map_err(|e| e.to_string())?;
    let self_index = committee
        .daemon_self_index
        .or_else(|| committee.self_index(&cfg.self_mn_pubkey))
        .ok_or("this node is not on the current bridge committee")? as u16;
    if !committee.has_signer_keys() {
        return Err("bridge.committee returned no signer_keys — update beldexd".into());
    }
    let signers: Vec<u16> = match std::env::var("BRIDGE_SIGNER_SIGN_SIGNERS") {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => (0..committee.threshold as u16).collect(),
    };
    if !signers.contains(&self_index) {
        return Err(format!("this node ({self_index}) is not in the signer set {signers:?}"));
    }

    let dir = std::env::var("BRIDGE_SIGNER_SHARE_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_SHARE_DIR (where `dkg` wrote the shares)".to_string())?;
    let port_base: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or("set BRIDGE_SIGNER_MESH_PORT_BASE (single-host devnet)")?;
    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let key_path =
        std::env::var("BRIDGE_SIGNER_MN_KEY_FILE").map_err(|_| "set BRIDGE_SIGNER_MN_KEY_FILE".to_string())?;
    let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
    if sk_bytes.len() != 64 {
        return Err(format!("MN key {key_path} is {} bytes, expected 64", sk_bytes.len()));
    }
    let mut ed25519_secret = [0u8; 64];
    ed25519_secret.copy_from_slice(&sk_bytes);
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&ed25519_secret[32..64]);
    let curve_secret = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
    let curve_public = ffi::ed25519_pk_to_x25519(&ed_pub)?;
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("derived x25519 does not match this node's bridge.committee entry".into());
        }
    }
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    let timeout = Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_SIGN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );

    // Pgw FROST material. The share files are indexed by this node's committee index AT
    // DKG TIME; committee indices are canonical (pubkey-sorted) per epoch, so they are
    // stable while the committee's membership is stable. If the file for our CURRENT
    // index is missing but a differently-indexed share exists, the committee has changed
    // (membership, or a daemon predating the canonical-order rule) — say so explicitly,
    // because the bare ENOENT reads as "dkg never ran".
    if !std::path::Path::new(&format!("{dir}/pgw-{self_index}.keypackage")).exists() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let others: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with("pgw-") && n.ends_with(".keypackage"))
                .collect();
            if !others.is_empty() {
                return Err(format!(
                    "this node's committee index is now {self_index}, but its share dir holds \
                     {others:?} — the committee order/membership changed since the DKG ran. \
                     Re-run the DKG for the current committee (shares, the contract signer, \
                     and the gateway owner key must all be regenerated together)."
                ));
            }
        }
    }
    let read = |suffix: &str| {
        std::fs::read(format!("{dir}/pgw-{self_index}.{suffix}"))
            .map_err(|e| format!("read pgw {suffix}: {e} (run `dkg` first with BRIDGE_SIGNER_SHARE_DIR set)"))
    };
    let pgw_key_package = frost::keys::KeyPackage::deserialize(&read("keypackage")?)
        .map_err(|e| format!("bad pgw keypackage: {e}"))?;
    let pgw_pubkey_package = frost::keys::PublicKeyPackage::deserialize(&read("pubkeypackage")?)
        .map_err(|e| format!("bad pgw pubkeypackage: {e}"))?;
    let pgw_group_vk: [u8; 32] = pgw_pubkey_package
        .verifying_key()
        .serialize()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("cannot serialize pgw group verifying key")?;

    // Pevm cggmp21 keyshare (raw bytes; the driver deserializes).
    let pevm_key_share = std::fs::read(format!("{dir}/pevm-{self_index}.keyshare"))
        .map_err(|e| format!("read pevm keyshare: {e} (run `dkg` first with BRIDGE_SIGNER_SHARE_DIR set)"))?;

    Ok(LiveSigners {
        committee,
        self_index,
        signers,
        pgw_key_package,
        pgw_pubkey_package,
        pgw_group_vk,
        pevm_key_share,
        curve_secret,
        curve_public,
        ed25519_secret,
        port_base,
        pevm_offset,
        use_curve,
        timeout,
    })
}

/// The live `serve` path: the **coordinated autonomy loop**. Composes the
/// [`Coordinator`](beldex_bridge_signer::coordinator::Coordinator) (deterministic per-duty
/// sessions + leader over the S4-authenticated OMQ mesh) with
/// [`DualPolicy`](beldex_bridge_signer::release_policy::DualPolicy) (mint C.5 byte-rebuild +
/// release R1–R6 via the member's own daemon), [`LiveSigners`] (per-duty Pevm/Pgw mesh
/// sessions), and [`HttpGatewayRpc`] (release build with the replay-guard ref + verify +
/// submit). Enabled by `--features serve-live` + `BRIDGE_SIGNER_SERVE_LIVE=1`.
#[cfg(feature = "serve-live")]
#[allow(clippy::too_many_arguments)]
fn run_serve_live<B, C>(
    cfg: &Config,
    src: &mut beldex_bridge_signer::service::WatcherEventSource<B, C>,
    orch: &mut beldex_bridge_signer::orchestrator::Orchestrator,
    opts: &beldex_bridge_signer::service::ServeOptions,
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
    beldexd_rpc: &str,
    gateway_id: &str,
    poll_secs: u64,
) -> Result<(), String>
where
    B: beldex_bridge_signer::beldex_watcher::BeldexRpc,
    C: beldex_bridge_signer::evm_watcher::JsonRpcClient,
{
    use beldex_bridge_signer::coordinator::{BuildError, Coordinator, MintPolicy};
    use beldex_bridge_signer::live_backend::{mint_relay_payload_json, GatewayRpc, HttpGatewayRpc};
    use beldex_bridge_signer::omq_mesh::{MeshAuth, OmqMeshConfig, OmqPeerTransport, PeerAddr};
    use beldex_bridge_signer::evm_watcher::HttpJsonRpc;
    use beldex_bridge_signer::orchestrator::{Duty, EventSource, ExecOutcome};
    use beldex_bridge_signer::reconcile::{
        observe_reconciled, DualReconciler, EvmMintReconciler, GatewayReleaseReconciler,
        ObserveOutcome,
    };
    use beldex_bridge_signer::release_policy::{DualPolicy, ReleasePolicy, ReleaseProposal};
    use beldex_bridge_signer::transport::Leg;
    use beldex_bridge_signer::watch::ReleaseEvent;
    use beldex_bridge_signer::wire_auth::{LibsodiumEd25519, LibsodiumSigner};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    let ls = Rc::new(build_live_signers(cfg)?);
    let committee = ls.committee.clone();
    let self_index = ls.self_index;

    // --- Coordinator mesh: its own port range (the per-session sign meshes bind
    // port_base / port_base+pevm_offset per session; the coordinator's transport is
    // long-lived, so it gets a dedicated offset), CURVE + S4 auth from the committee.
    let coord_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_COORD_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let base = ls.port_base + coord_offset;
    let peers: Vec<PeerAddr> = committee
        .peer_transport_indexed(self_index as usize, base)
        .into_iter()
        .map(|(index, endpoint, curve_pubkey)| PeerAddr {
            index,
            endpoint,
            curve_pubkey,
            signer_ed25519: committee
                .signer_keys
                .get(index as usize)
                .copied()
                .unwrap_or([0u8; 32]),
        })
        .collect();
    let mesh_cfg = OmqMeshConfig {
        self_index,
        listen_endpoint: format!("tcp://0.0.0.0:{}", base + self_index),
        use_curve: ls.use_curve,
        self_curve_secret: ls.curve_secret,
        self_curve_public: ls.curve_public,
        peers,
    };
    let auth = MeshAuth::from_committee(
        Box::new(LibsodiumSigner { sk64: ls.ed25519_secret }),
        Box::new(LibsodiumEd25519),
        &committee,
    )
    .ok_or("bridge.committee returned no signer_keys — cannot authenticate the coordinator mesh")?;
    let mut net = OmqPeerTransport::bind(&mesh_cfg)
        .map_err(|e| format!("coordinator mesh bind: {e:?}"))?
        .with_auth(auth);

    // --- Policies. One shared daemon RPC client for build / inspect / submit (the loop is
    // single-threaded; the closures never call each other, so RefCell borrows never nest).
    let rpc = Rc::new(RefCell::new(HttpGatewayRpc::new(beldexd_rpc.to_string())));
    let contracts: BTreeMap<u64, [u8; 20]> = configs.iter().map(|c| (c.chain_id, c.contract)).collect();
    let release_gateway =
        std::env::var("BRIDGE_SIGNER_RELEASE_GATEWAY").unwrap_or_else(|_| gateway_id.to_string());
    let release_fee: u64 =
        std::env::var("BRIDGE_SIGNER_RELEASE_FEE").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let max_fee: u64 = std::env::var("BRIDGE_SIGNER_RELEASE_MAX_FEE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(release_fee);
    let per_tx_cap: u128 = std::env::var("BRIDGE_SIGNER_RELEASE_PER_TX_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(u128::MAX);

    // Leader-side release build: gateway_create_transfer + the HF23 replay-guard ref +
    // the disclosed tx key (verifiers open the stealth outputs with it).
    let build_rpc = rpc.clone();
    let build_gw = release_gateway.clone();
    let build_tx = move |ev: &ReleaseEvent| {
        let recipient = String::from_utf8(ev.beldex_recipient.clone())
            .map_err(|_| BuildError::Unactionable("burn recipient is not a utf-8 address".into()))?;
        let amount = ev
            .amount
            .checked_sub(u128::from(release_fee))
            .ok_or_else(|| BuildError::Unactionable("burn amount does not cover the fee".into()))?;
        build_rpc
            .borrow_mut()
            .create_release(&build_gw, &recipient, amount, release_fee, ev.chain.0, &ev.evm_txid, 0)
            .map_err(BuildError::Transient)
    };

    // Member-side inspection: this node's OWN daemon reads the proposed withdrawal.
    let insp_rpc = rpc.clone();
    let insp_gw = release_gateway.clone();
    let inspect = move |p: &ReleaseProposal, expected: &[u8]| {
        let addr = std::str::from_utf8(expected).map_err(|_| "recipient not utf-8".to_string())?;
        insp_rpc.borrow_mut().decode_withdrawal(p, addr, &insp_gw)
    };

    let policy = DualPolicy {
        mint: MintPolicy { contracts: contracts.clone() },
        release: ReleasePolicy {
            build_tx,
            inspect,
            release_gateway: release_gateway.clone(),
            max_fee,
            per_tx_cap,
        },
    };

    // --- The per-duty threshold signers: one mesh round per duty among the session's
    // canonical ACK set (only members that independently verified the payload — C.5),
    // namespaced by the session attempt so a retry never ingests stale frames.
    let sign_ls = ls.clone();
    let sign = move |leg: Leg, message: &[u8], signers: &[u16], attempt: u32| -> Result<Vec<u8>, String> {
        println!("  signing {leg:?} round: participants {signers:?} attempt {attempt}");
        match leg {
            Leg::Pevm => sign_ls.pevm_sign(message, signers, attempt).map(|s| s.to_vec()),
            Leg::Pgw => {
                let m: [u8; 32] =
                    message.try_into().map_err(|_| "Pgw signing message must be 32 bytes".to_string())?;
                sign_ls.pgw_sign(&m, signers, attempt).map(|s| s.to_vec())
            }
        }
    };

    // --- Completion: emit the mint relayer payload / self-submit the release.
    //
    // Mint hand-off. The signer holds no EVM gas key by design, so it does not broadcast:
    // it produces the signed payload and hands it off. Two mechanisms, in order:
    //
    //   1. `BRIDGE_SIGNER_RELAY_CMD` — spawn that command and write the payload JSON to its
    //      stdin (e.g. `beldex-bridge-relayer relay -`). The gas key lives in *that*
    //      process's environment, never here.
    //   2. Always: print `MINT-PAYLOAD <json>`. This line is the **durable artifact** — the
    //      committee's job is done once the signature exists, and anyone holding this line
    //      can broadcast it later with `relay -` or `prepare` + `cast send`.
    //
    // Broadcast failure therefore does NOT fail the duty: re-running a whole mesh signing
    // round to retry an HTTP call would be the wrong layer, and the payload is already
    // public and reusable. Failures are logged loudly instead.
    //
    // Enabling the hook on several nodes is safe but not free: a *late* duplicate costs
    // nothing (gas estimation catches `Replay()` before broadcasting), while *simultaneous*
    // duplicates all pass estimation and all but one revert on-chain, burning gas. Set
    // `BRIDGE_SIGNER_RELAY_STAGGER_MS` (multiplied by this node's committee index) so
    // configured relayers fire in sequence rather than at once. Each needs its own gas key —
    // a shared key means colliding nonces.
    // Preferred hand-off: publish to the daemon's mint bus (`bridge.mint_payload`), which
    // fans out to every subscribed relayer. Relayers then need no signer-host access at all.
    // The daemon dedups by beldex_txid, so all t+1 members publishing is expected and only
    // one fan-out occurs. Off by default only because it needs the OMQ endpoint.
    let publish_bus = std::env::var("BRIDGE_SIGNER_PUBLISH_MINT_BUS")
        .map(|v| v != "0" && v != "false")
        .unwrap_or(true);
    // The daemon accepts a publication only from a seated committee member, so we sign each
    // one with this node's `signer_ed25519` — the same key the mesh authenticates with, and
    // the one consensus records for our committee index.
    let bus_genesis: [u8; 32] = match std::env::var("BRIDGE_SIGNER_GENESIS_HASH") {
        Ok(h) => config::parse_hex32(&h).unwrap_or([0u8; 32]),
        Err(_) => [0u8; 32],
    };
    // Where to publish. Default: this node's own daemon — correct when relayers subscribe
    // broadly. But a publisher→own-daemon / subscriber→one-daemon topology only intersects
    // by luck (found live: the one subscribed daemon's signer was a straggler that round,
    // so every fan-out happened where nobody listened). BRIDGE_SIGNER_MINT_BUS_ENDPOINT
    // points all signers at a common bus daemon; publishing is signature-authenticated,
    // not socket-authenticated, so a remote daemon works fine.
    let bus_endpoint = std::env::var("BRIDGE_SIGNER_MINT_BUS_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| cfg.oxenmq_endpoint.clone());
    let bus_client = if publish_bus {
        println!("  mint hand-off: publishing to bridge.mint_payload at {bus_endpoint}");
        if bus_genesis == [0u8; 32] {
            println!("    WARNING: no BRIDGE_SIGNER_GENESIS_HASH — publications will not verify \
                      against a daemon that binds a real genesis");
        }
        Some(beldex_bridge_signer::omq_client::OmqCommitteeClient::new(bus_endpoint))
    } else {
        None
    };
    let bus_sign_key = ls.ed25519_secret;

    let relay_cmd = std::env::var("BRIDGE_SIGNER_RELAY_CMD").ok().filter(|s| !s.trim().is_empty());
    let relay_stagger_ms: u64 = std::env::var("BRIDGE_SIGNER_RELAY_STAGGER_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    match &relay_cmd {
        Some(c) => println!("  mint hand-off: piping payloads to `{c}` (stagger {}ms)", relay_stagger_ms * self_index as u64),
        None => println!("  mint hand-off: log only (set BRIDGE_SIGNER_RELAY_CMD to auto-broadcast)"),
    }

    let done_rpc = rpc.clone();
    let done_contracts = contracts;
    let complete = move |d: &Duty, proposal: &[u8], sig: &[u8]| -> ExecOutcome {
        match d {
            Duty::Mint(ev) => {
                let Some(&contract) = done_contracts.get(&ev.dst_chain.0) else {
                    return ExecOutcome::Abandon;
                };
                let payload = mint_relay_payload_json(ev, contract, sig);
                // Print first: the payload must survive even if every hand-off below fails.
                println!("MINT-PAYLOAD {payload}");
                if let Some(bus) = &bus_client {
                    use beldex_bridge_signer::omq_client::mint_publish_message;
                    let msg = mint_publish_message(&bus_genesis, &payload);
                    match beldex_bridge_signer::ffi::ed25519_sign_detached(&bus_sign_key, &msg) {
                        Ok(pub_sig) => match bus.publish_mint_payload(&payload, self_index, &pub_sig) {
                            // `DUPLICATE` = a peer in the same quorum published it first.
                            // Expected and desirable: one fan-out per deposit, not t+1.
                            Ok(status) => println!("  published to mint bus: {status}"),
                            Err(e) => {
                                eprintln!("  mint-bus publish failed ({e}) — payload still logged")
                            }
                        },
                        Err(e) => eprintln!("  mint-bus signing failed ({e}) — payload still logged"),
                    }
                }
                if let Some(cmd) = &relay_cmd {
                    if relay_stagger_ms > 0 && self_index > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(
                            relay_stagger_ms * self_index as u64,
                        ));
                    }
                    match pipe_to_relay(cmd, &payload) {
                        Ok(out) => println!("  relayed: {}", out.trim()),
                        Err(e) => eprintln!(
                            "  RELAY FAILED ({e}) — the MINT-PAYLOAD line above is still valid; \
                             broadcast it with `beldex-bridge-relayer relay -`"
                        ),
                    }
                }
                ExecOutcome::Submitted
            }
            Duty::Release(_) => {
                let Some(p) = ReleaseProposal::decode(proposal) else {
                    return ExecOutcome::Abandon; // cannot happen for an accepted proposal
                };
                if sig.len() != 64 {
                    return ExecOutcome::Retry;
                }
                let mut s64 = [0u8; 64];
                s64.copy_from_slice(sig);
                let blob_hex: String = p.unsigned_tx_blob.iter().map(|b| format!("{b:02x}")).collect();
                match done_rpc.borrow_mut().submit_transfer(&blob_hex, &s64) {
                    Ok(txid) => {
                        println!("RELEASE submitted: {txid}");
                        ExecOutcome::Submitted
                    }
                    Err(e) => {
                        // Every finalizing node submits the SAME signed tx; only the first
                        // lands, and the daemon reports the rest as duplicates / replays.
                        // That is success, not failure — retrying would reopen a session
                        // for a settled burn and churn against the consensus replay guard.
                        let el = e.to_lowercase();
                        if el.contains("already") || el.contains("replay") || el.contains("discharged")
                        {
                            println!("RELEASE already submitted by a peer (ok): {e}");
                            ExecOutcome::Submitted
                        } else {
                            eprintln!("release submit failed (will retry): {e}");
                            ExecOutcome::Retry
                        }
                    }
                }
            }
        }
    };

    let mut coord = Coordinator::new(committee, self_index, policy, sign, complete);
    if let Some(t) = std::env::var("BRIDGE_SIGNER_STAGE_TIMEOUT_TICKS").ok().and_then(|s| s.parse().ok()) {
        coord.stage_timeout_ticks = t;
    }

    println!("serve: LIVE COORDINATED mode — per-duty sessions over the authenticated mesh");
    println!("  committee epoch {} size {} threshold {}; self_index {self_index}", coord.committee.epoch, coord.committee.size(), coord.committee.threshold);
    println!("  coordinator mesh on port base {base}; polling every {poll_secs}s across {} EVM chain(s)", configs.len());

    // On-chain reconciliation: a restarted signer must not re-work settled duties. Each
    // newly observed duty is checked once (mints: processedDeposits; releases: the daemon's
    // release-ref set); an undeterminable answer leaves it unregistered so a later poll
    // retries. Disable with BRIDGE_SIGNER_RECONCILE=0 (then every duty is worked).
    let reconcile_on =
        std::env::var("BRIDGE_SIGNER_RECONCILE").map(|v| v != "0" && v != "false").unwrap_or(true);
    let mut reconciler = DualReconciler {
        // Per-chain client + contract, so a multi-chain deployment queries the right chain.
        mint: EvmMintReconciler {
            chains: configs
                .iter()
                .map(|c| (c.chain_id, (HttpJsonRpc::new(c.rpc_url.clone()), c.contract)))
                .collect(),
        },
        release: GatewayReleaseReconciler::new(beldexd_rpc.to_string(), release_gateway.clone()),
    };
    if !reconcile_on {
        println!("  reconciliation DISABLED (BRIDGE_SIGNER_RECONCILE=0)");
    }

    let mut ticks = 0u64;
    loop {
        // Ingest the watchers (re-emission is safe — the orchestrator dedups, and a duty is
        // reconciled against chain state at most once per process).
        let mut ingest = |orch: &mut beldex_bridge_signer::orchestrator::Orchestrator, d: Duty| {
            if reconcile_on {
                if observe_reconciled(orch, &mut reconciler, d) == ObserveOutcome::AlreadySettled {
                    println!("reconciled: duty already settled on-chain — not re-worked");
                }
            } else {
                orch.observe(d);
            }
        };
        for m in src.poll_mints() {
            ingest(orch, Duty::Mint(m));
        }
        for r in src.poll_releases() {
            ingest(orch, Duty::Release(r));
        }
        let rep = coord.step(orch, &mut net);
        if rep != Default::default() {
            let (pending, in_flight, done) = orch.counts();
            println!(
                "tick {ticks}: opened={} acked={} nacked={} signed={} completed={} requeued={} abandoned={} resolved={} | duties p={pending} f={in_flight} d={done}",
                rep.opened, rep.acked, rep.nacked, rep.signed, rep.completed, rep.requeued, rep.abandoned, rep.resolved
            );
        }
        // Idle heartbeat (~once a minute): proves the watchers are scanning and shows how
        // far finality has advanced — a stalled `finalized_up_to` means the chain (or the
        // miner) stopped; one that advances past a deposit with no duty means the deposit
        // didn't resolve (and the `deposit held` line above says why).
        if ticks % 12 == 0 {
            let (pending, in_flight, done) = orch.counts();
            // The EVM half matters as much as the Beldex half. A burn is held in the
            // watcher's `pending` set until its inclusion block is `confirmations` deep
            // (watch.rs FinalityGate: depth = tip - inclusion_height), so on an idle
            // automine chain — anvil started without --block-time — the tip stops at the
            // block containing the burn, depth stays 0, and the release never opens.
            // Without a pending count that is indistinguishable from "no burn happened",
            // which is the one thing the operator most needs to tell apart.
            let evm: Vec<String> = src
                .evm
                .iter()
                .map(|w| {
                    let tip = w
                        .tip()
                        .map(|t| t.to_string())
                        .unwrap_or_else(|e| format!("unreachable({e:?})"));
                    format!("chain {} tip={} pending={}", w.chain().0, tip, w.pending_len())
                })
                .collect();
            println!(
                "watch: beldex finalized_up_to={} | evm {} | duties p={pending} f={in_flight} d={done}",
                src.beldex.finalized_up_to(),
                evm.join("; ")
            );
        }
        ticks += 1;
        if opts.max_ticks.is_some_and(|max| ticks >= max) {
            break;
        }
        if !opts.interval.is_zero() {
            std::thread::sleep(opts.interval);
        }
    }

    let (pending, in_flight, done) = orch.counts();
    println!("serve: finished after {ticks} tick(s); duties pending={pending} in_flight={in_flight} done={done}");
    Ok(())
}

fn main() -> ExitCode {
    let subcommand = std::env::args().nth(1);

    // `relay-watch` is dispatched BEFORE the config load, deliberately: it is the
    // relayer-operator command, and a relayer holds no signer identity — no gateway, no MN
    // key, no shares. Requiring the full signer config here would force operators to invent
    // dummy values for keys they must not have. It needs exactly one setting: the OMQ
    // endpoint to subscribe to.
    if subcommand.as_deref() == Some("relay-watch") {
        return match run_relay_watch_standalone() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("relay-watch: {e}");
                ExitCode::FAILURE
            }
        };
    }

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
        Some("sign") => match run_sign(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sign: {e}");
                ExitCode::FAILURE
            }
        },
        Some("watch-evm") => match run_watch_evm(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("watch-evm: {e}");
                ExitCode::FAILURE
            }
        },
        Some("serve") => match run_serve(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("serve: {e}");
                ExitCode::FAILURE
            }
        },
        // ("relay-watch" is dispatched before the config load — see the top of main.)
        _ => {
            print_status(&cfg);
            ExitCode::SUCCESS
        }
    }
}
