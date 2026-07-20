//! Signer configuration and validation.
//!
//! Parsed from a simple `key = value` map (env / config file), std-only so the
//! scaffold has no external dependencies. All consensus-derived values (committee
//! membership, seat status) come from `beldexd` at runtime, not from here — this
//! is only static wiring.

use std::collections::HashMap;

/// Where key shares and preprocessed material are stored (Phase D). The scaffold
/// ships the in-memory backend for tests/dev; production uses Vault or an enclave
/// (cold-hosted masternodes are ineligible for bridge seats — plan D.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareStoreBackend {
    Memory,
    Vault,
    Enclave,
}

/// Static signer configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Local `beldexd` RPC endpoint (deposits, gateway history, tx building).
    pub beldexd_rpc_url: String,
    /// Local `beldexd` OxenMQ endpoint (committee, session transport, slash reports).
    pub oxenmq_endpoint: String,
    /// The bridge gateway account id (`Pgw` owner) this signer serves.
    pub gateway_id: [u8; 32],
    /// This operator's masternode pubkey (its committee identity).
    pub self_mn_pubkey: [u8; 32],
    /// Bridge epoch length in blocks (must match consensus `BRIDGE_EPOCH_BLOCKS`).
    pub bridge_epoch_blocks: u64,
    /// Signing threshold `t + 1` (must match consensus `BRIDGE_COMMITTEE_THRESHOLD`).
    pub committee_threshold: usize,
    /// Share-custody backend.
    pub share_store: ShareStoreBackend,
    /// Preprocessed-pool hard cap `L` (S3: `L <= 128`).
    pub max_pool: usize,
}

/// Configuration errors, keyed by the offending field for actionable messages.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    BadHex(&'static str),
    OutOfRange(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Missing(k) => write!(f, "missing required config key: {k}"),
            ConfigError::BadHex(k) => write!(f, "config key {k} is not 32-byte hex"),
            ConfigError::OutOfRange(k) => write!(f, "config key {k} is out of range"),
        }
    }
}
impl std::error::Error for ConfigError {}

/// Parse a `.env`-style file into raw `KEY = VALUE` pairs (std-only; no external
/// crate). Ignores blank lines and `#` comments, tolerates a leading `export `,
/// and strips a single pair of surrounding single or double quotes from values.
/// Keys are returned verbatim (e.g. `BRIDGE_SIGNER_GATEWAY_ID`); prefix handling
/// is the caller's job so the same file works as real env vars.
pub fn parse_dotenv(contents: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() {
            continue;
        }
        let mut v = v.trim();
        if v.len() >= 2
            && ((v.starts_with('"') && v.ends_with('"'))
                || (v.starts_with('\'') && v.ends_with('\'')))
        {
            v = &v[1..v.len() - 1];
        }
        out.insert(k.to_string(), v.to_string());
    }
    out
}

/// Parse a 32-byte value from hex (optionally `0x`-prefixed, exactly 64 nibbles).
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Parse a 64-byte value from hex (optionally `0x`-prefixed, exactly 128 nibbles)
/// — e.g. a libsodium ed25519 secret key (seed‖pubkey) for mesh message auth.
pub fn parse_hex64(s: &str) -> Option<[u8; 64]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 128 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

impl Config {
    /// The absolute upper bound on the preprocessed pool (S3, Shoup–Groth).
    pub const MAX_POOL_LIMIT: usize = 128;

    /// Build a validated [`Config`] from a `key -> value` map.
    pub fn from_map(m: &HashMap<String, String>) -> Result<Config, ConfigError> {
        let req = |k: &'static str| m.get(k).map(String::as_str).ok_or(ConfigError::Missing(k));

        let beldexd_rpc_url = req("beldexd_rpc_url")?.to_string();
        let oxenmq_endpoint = req("oxenmq_endpoint")?.to_string();
        let gateway_id = parse_hex32(req("gateway_id")?).ok_or(ConfigError::BadHex("gateway_id"))?;
        let self_mn_pubkey =
            parse_hex32(req("self_mn_pubkey")?).ok_or(ConfigError::BadHex("self_mn_pubkey"))?;

        let bridge_epoch_blocks = req("bridge_epoch_blocks")?
            .parse::<u64>()
            .map_err(|_| ConfigError::OutOfRange("bridge_epoch_blocks"))?;
        if bridge_epoch_blocks == 0 {
            return Err(ConfigError::OutOfRange("bridge_epoch_blocks"));
        }

        let committee_threshold = req("committee_threshold")?
            .parse::<usize>()
            .map_err(|_| ConfigError::OutOfRange("committee_threshold"))?;
        if committee_threshold == 0 {
            return Err(ConfigError::OutOfRange("committee_threshold"));
        }

        let share_store = match m.get("share_store").map(String::as_str).unwrap_or("memory") {
            "memory" => ShareStoreBackend::Memory,
            "vault" => ShareStoreBackend::Vault,
            "enclave" => ShareStoreBackend::Enclave,
            _ => return Err(ConfigError::OutOfRange("share_store")),
        };

        let max_pool = match m.get("max_pool") {
            Some(v) => v.parse::<usize>().map_err(|_| ConfigError::OutOfRange("max_pool"))?,
            None => Self::MAX_POOL_LIMIT,
        };
        if max_pool == 0 || max_pool > Self::MAX_POOL_LIMIT {
            return Err(ConfigError::OutOfRange("max_pool"));
        }

        Ok(Config {
            beldexd_rpc_url,
            oxenmq_endpoint,
            gateway_id,
            self_mn_pubkey,
            bridge_epoch_blocks,
            committee_threshold,
            share_store,
            max_pool,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("beldexd_rpc_url".into(), "http://127.0.0.1:19091".into());
        m.insert("oxenmq_endpoint".into(), "ipc:///var/run/beldexd.sock".into());
        m.insert("gateway_id".into(), "11".repeat(32)); // 64 hex chars
        m.insert("self_mn_pubkey".into(), "ab".repeat(32));
        m.insert("bridge_epoch_blocks".into(), "2880".into());
        m.insert("committee_threshold".into(), "14".into());
        m
    }

    #[test]
    fn parses_a_valid_config() {
        let cfg = Config::from_map(&base_map()).expect("valid config");
        assert_eq!(cfg.bridge_epoch_blocks, 2880);
        assert_eq!(cfg.committee_threshold, 14);
        assert_eq!(cfg.gateway_id, [0x11u8; 32]);
        assert_eq!(cfg.self_mn_pubkey, [0xabu8; 32]);
        assert_eq!(cfg.share_store, ShareStoreBackend::Memory); // default
        assert_eq!(cfg.max_pool, Config::MAX_POOL_LIMIT); // default
    }

    #[test]
    fn missing_required_field_is_reported() {
        let mut m = base_map();
        m.remove("gateway_id");
        assert_eq!(Config::from_map(&m), Err(ConfigError::Missing("gateway_id")));
    }

    #[test]
    fn bad_hex_is_reported() {
        let mut m = base_map();
        m.insert("self_mn_pubkey".into(), "zz".repeat(32));
        assert_eq!(Config::from_map(&m), Err(ConfigError::BadHex("self_mn_pubkey")));
        // wrong length
        m.insert("self_mn_pubkey".into(), "ab".repeat(16));
        assert_eq!(Config::from_map(&m), Err(ConfigError::BadHex("self_mn_pubkey")));
    }

    #[test]
    fn zero_epoch_and_threshold_rejected() {
        let mut m = base_map();
        m.insert("bridge_epoch_blocks".into(), "0".into());
        assert_eq!(Config::from_map(&m), Err(ConfigError::OutOfRange("bridge_epoch_blocks")));
        let mut m = base_map();
        m.insert("committee_threshold".into(), "0".into());
        assert_eq!(Config::from_map(&m), Err(ConfigError::OutOfRange("committee_threshold")));
    }

    #[test]
    fn pool_cap_is_bounded() {
        let mut m = base_map();
        m.insert("max_pool".into(), "129".into()); // over the S3 hard cap
        assert_eq!(Config::from_map(&m), Err(ConfigError::OutOfRange("max_pool")));
        m.insert("max_pool".into(), "64".into());
        assert_eq!(Config::from_map(&m).unwrap().max_pool, 64);
    }

    #[test]
    fn hex32_prefix_and_case_insensitive() {
        assert_eq!(parse_hex32(&format!("0x{}", "AB".repeat(32))), Some([0xabu8; 32]));
        assert_eq!(parse_hex32("00"), None);
    }

    #[test]
    fn hex64_parsing() {
        assert_eq!(parse_hex64(&"cd".repeat(64)), Some([0xcdu8; 64]));
        assert_eq!(parse_hex64(&format!("0x{}", "01".repeat(64))), Some([0x01u8; 64]));
        assert_eq!(parse_hex64(&"ab".repeat(32)), None); // wrong length (32 bytes)
        assert_eq!(parse_hex64("zz"), None);
    }

    #[test]
    fn dotenv_parsing() {
        let contents = "\
# a comment
BRIDGE_SIGNER_BELDEXD_RPC_URL=http://127.0.0.1:19091

export BRIDGE_SIGNER_COMMITTEE_THRESHOLD = 14
BRIDGE_SIGNER_GATEWAY_ID=\"1111111111111111111111111111111111111111111111111111111111111111\"
BRIDGE_SIGNER_OXENMQ_ENDPOINT='ipc:///tmp/s.sock'
malformed_line_without_equals
";
        let m = parse_dotenv(contents);
        assert_eq!(m.get("BRIDGE_SIGNER_BELDEXD_RPC_URL").map(String::as_str), Some("http://127.0.0.1:19091"));
        assert_eq!(m.get("BRIDGE_SIGNER_COMMITTEE_THRESHOLD").map(String::as_str), Some("14")); // export + spaces trimmed
        assert_eq!(m.get("BRIDGE_SIGNER_GATEWAY_ID").map(String::as_str), Some(&"1".repeat(64)[..])); // quotes stripped
        assert_eq!(m.get("BRIDGE_SIGNER_OXENMQ_ENDPOINT").map(String::as_str), Some("ipc:///tmp/s.sock"));
        assert!(!m.contains_key("malformed_line_without_equals"));
    }
}
