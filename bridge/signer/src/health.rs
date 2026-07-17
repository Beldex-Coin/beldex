//! Bridge-signer liveness / heartbeat (plan §B.8).
//!
//! Each seated node publishes a bridge-signer heartbeat that extends `beldexd`'s
//! `uptime_proof`: a version marker, the TSS transport identity, an EVM-tip
//! freshness marker, and a liveness flag. Missed heartbeats feed the liveness
//! path (Phase F.4): *ejection-without-slash* (bond returned after unbonding), so
//! a benign outage is not punished as Byzantine.
//!
//! This module computes the local liveness the node would report. Publishing it
//! into the (consensus-gossiped) `uptime_proof` is done on the C++ side (Phase
//! B.8) — deliberately not modified from a wire-format perspective here.

use crate::committee::MemberId;

/// The liveness a seated signer reports each heartbeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthStatus {
    /// `beldex-bridge-signer` version (`crate::SIGNER_VERSION`).
    pub signer_version: [u16; 3],
    /// The TSS transport identity (ed25519), for committee addressing.
    pub tss_identity: MemberId,
    /// Height of the newest EVM block this node's own watcher has observed.
    pub evm_tip_height: u64,
    /// Height of the newest EVM block the network considers current.
    pub network_evm_tip_height: u64,
    /// Whether the local dual-scheme TSS engine answered its last self-check.
    pub tss_responsive: bool,
    /// Current bridge epoch this node is tracking.
    pub committee_epoch: u64,
}

impl HealthStatus {
    /// How many EVM confirmations behind the network this node's watcher is.
    pub fn evm_lag(&self) -> u64 {
        self.network_evm_tip_height.saturating_sub(self.evm_tip_height)
    }

    /// Whether the node is bridge-live: TSS responsive **and** its EVM tip is
    /// fresh (within `max_lag`). A node that is not live must not be selected /
    /// kept in the committee (feeds B.3/B.6 eligibility and F.4 liveness).
    pub fn is_live(&self, max_lag: u64) -> bool {
        self.tss_responsive && self.evm_lag() <= max_lag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(local_tip: u64, net_tip: u64, tss_ok: bool) -> HealthStatus {
        HealthStatus {
            signer_version: crate::SIGNER_VERSION,
            tss_identity: [1u8; 32],
            evm_tip_height: local_tip,
            network_evm_tip_height: net_tip,
            tss_responsive: tss_ok,
            committee_epoch: 42,
        }
    }

    #[test]
    fn evm_lag_saturates() {
        assert_eq!(status(100, 105, true).evm_lag(), 5);
        // Local ahead of the reported network tip -> lag clamps to 0, not negative.
        assert_eq!(status(110, 105, true).evm_lag(), 0);
    }

    #[test]
    fn liveness_requires_fresh_tip_and_responsive_tss() {
        assert!(status(100, 102, true).is_live(3)); // within lag, responsive
        assert!(!status(100, 110, true).is_live(3)); // stale EVM tip
        assert!(!status(100, 100, false).is_live(3)); // TSS not responding
    }
}
