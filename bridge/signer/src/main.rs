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
    } else {
        println!("(build with --features autonomy for the `serve` subcommand)");
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
        committee, self_index, signers, &key_share, &preimage, identity, peers, use_curve, timeout,
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
    let beldex = BeldexWatcher::new(HttpBeldexRpc::new(beldexd_rpc), gateway_id, start_height);

    let mut src = WatcherEventSource { beldex, evm, view_secret, registry };
    let mut orch = Orchestrator::new();

    let poll_secs: u64 = std::env::var("BRIDGE_SIGNER_WATCH_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let max_ticks: Option<u64> = std::env::var("BRIDGE_SIGNER_WATCH_ITERS").ok().and_then(|s| s.parse().ok());
    let opts = ServeOptions { interval: Duration::from_secs(poll_secs), max_ticks };

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
        _ => {
            print_status(&cfg);
            ExitCode::SUCCESS
        }
    }
}
