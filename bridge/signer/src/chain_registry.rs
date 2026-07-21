//! Chain registry (**Phase E.3**): the single place every chain-specific parameter
//! lives — `{chain_id, contract, confirmations, per-epoch cap, per-tx max}` (+ an
//! optional RPC endpoint for the I/O layer).
//!
//! Nothing chain-specific belongs in the committee, gateway, or contract logic;
//! adding an EVM chain is "deploy the wBDX template + admin `addSigner` + a registry
//! row + one more watcher instance". This module is **std-only** and holds the
//! validation the watchers apply *before* a signing session is proposed:
//!   * the chain must be known (a burn/deposit on an unregistered chain is ignored),
//!   * `amount ≤ per_tx_max` (an oversized event never starts a session), and
//!   * a **fixed-window (β = 1) per-epoch cap** accumulator — the soft pre-check
//!     mirroring the hard cap enforced by consensus (L1 release) and the wBDX
//!     contract (EVM mint). Sizing follows `C·φ·β < (t+1)·B` (§7-bis); this module
//!     only accounts and gates, it does not choose the numbers.
//!
//! `confirmations` here is the EVM confirmation depth `E` (Phase E.2). Beldex
//! checkpoint finality (Phase E.1) is not a simple depth and lives in the Beldex
//! watcher, not a registry row.

use std::collections::BTreeMap;

/// An EVM chain id (e.g. 1 = Ethereum mainnet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId(pub u64);

/// One registered EVM chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRow {
    pub chain_id: ChainId,
    /// The wBDX contract address on this chain.
    pub contract: [u8; 20],
    /// Confirmation depth `E` before a burn is actionable (Phase E.2).
    pub confirmations: u64,
    /// Fixed-window per-epoch cap (atomic units) — mint and release accounted
    /// separately (see [`CapKind`]).
    pub per_epoch_cap: u128,
    /// Maximum single-event amount (atomic units).
    pub per_tx_max: u128,
    /// The watcher's own RPC endpoint for this chain (I/O layer; not used by the
    /// std-only core). Each member uses its **own** endpoint (no shared oracle).
    pub rpc_endpoint: Option<String>,
}

/// Which direction a cap accounts — mints (into EVM) and releases (out to L1) have
/// independent per-epoch budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapKind {
    Mint,
    Release,
}

/// Registry validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// No row for this chain id.
    UnknownChain(ChainId),
    /// `amount` exceeds the chain's `per_tx_max`.
    OverPerTxMax { chain: ChainId, amount: u128, max: u128 },
    /// This event would push the fixed-window epoch total past `per_epoch_cap`.
    OverEpochCap { chain: ChainId, kind: CapKind, would_be: u128, cap: u128 },
    /// A row with a duplicate chain id was inserted.
    DuplicateChain(ChainId),
}

/// The registry plus its fixed-window cap accounting.
#[derive(Debug, Clone, Default)]
pub struct ChainRegistry {
    rows: BTreeMap<ChainId, ChainRow>,
    /// Cumulative consumed amount per (chain, kind, epoch). Fixed windows (β = 1):
    /// a different epoch is a different key, so the total resets exactly on the
    /// boundary; stale epochs are pruned on consume.
    consumed: BTreeMap<(ChainId, CapKind, u64), u128>,
}

impl ChainRegistry {
    pub fn new() -> ChainRegistry {
        ChainRegistry::default()
    }

    /// Register a chain. Errors on a duplicate id (chain config is unique).
    pub fn add(&mut self, row: ChainRow) -> Result<(), RegistryError> {
        if self.rows.contains_key(&row.chain_id) {
            return Err(RegistryError::DuplicateChain(row.chain_id));
        }
        self.rows.insert(row.chain_id, row);
        Ok(())
    }

    pub fn get(&self, chain: ChainId) -> Option<&ChainRow> {
        self.rows.get(&chain)
    }

    pub fn is_known(&self, chain: ChainId) -> bool {
        self.rows.contains_key(&chain)
    }

    /// Per-event validation independent of caps: known chain + `amount ≤ per_tx_max`.
    pub fn check_event(&self, chain: ChainId, amount: u128) -> Result<(), RegistryError> {
        let row = self.rows.get(&chain).ok_or(RegistryError::UnknownChain(chain))?;
        if amount > row.per_tx_max {
            return Err(RegistryError::OverPerTxMax { chain, amount, max: row.per_tx_max });
        }
        Ok(())
    }

    /// The current fixed-window total for `(chain, kind, epoch)`.
    pub fn window_total(&self, chain: ChainId, kind: CapKind, epoch: u64) -> u128 {
        self.consumed.get(&(chain, kind, epoch)).copied().unwrap_or(0)
    }

    /// Would `amount` fit under the per-epoch cap for this window? (Pure check.)
    pub fn would_fit(
        &self,
        chain: ChainId,
        kind: CapKind,
        epoch: u64,
        amount: u128,
    ) -> Result<(), RegistryError> {
        let row = self.rows.get(&chain).ok_or(RegistryError::UnknownChain(chain))?;
        let would_be = self.window_total(chain, kind, epoch).saturating_add(amount);
        if would_be > row.per_epoch_cap {
            return Err(RegistryError::OverEpochCap {
                chain,
                kind,
                would_be,
                cap: row.per_epoch_cap,
            });
        }
        Ok(())
    }

    /// Validate (`check_event` + `would_fit`) **and** consume the amount into the
    /// fixed window. Call once an event is accepted for signing. Prunes windows for
    /// epochs older than `epoch` (fixed windows never look back).
    pub fn consume(
        &mut self,
        chain: ChainId,
        kind: CapKind,
        epoch: u64,
        amount: u128,
    ) -> Result<(), RegistryError> {
        self.check_event(chain, amount)?;
        self.would_fit(chain, kind, epoch, amount)?;
        // Prune stale windows (any earlier epoch for this chain+kind).
        self.consumed
            .retain(|(c, k, e), _| !(*c == chain && *k == kind && *e < epoch));
        *self.consumed.entry((chain, kind, epoch)).or_insert(0) += amount;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u64, per_tx_max: u128, per_epoch_cap: u128) -> ChainRow {
        ChainRow {
            chain_id: ChainId(id),
            contract: [0x11; 20],
            confirmations: 12,
            per_epoch_cap,
            per_tx_max,
            rpc_endpoint: Some("http://127.0.0.1:8545".into()),
        }
    }

    #[test]
    fn unknown_chain_and_per_tx_max() {
        let mut reg = ChainRegistry::new();
        reg.add(row(1, 100, 1000)).unwrap();
        assert_eq!(reg.check_event(ChainId(9), 10), Err(RegistryError::UnknownChain(ChainId(9))));
        assert!(reg.check_event(ChainId(1), 100).is_ok()); // exactly at the max
        assert_eq!(
            reg.check_event(ChainId(1), 101),
            Err(RegistryError::OverPerTxMax { chain: ChainId(1), amount: 101, max: 100 })
        );
    }

    #[test]
    fn duplicate_chain_rejected() {
        let mut reg = ChainRegistry::new();
        reg.add(row(1, 100, 1000)).unwrap();
        assert_eq!(reg.add(row(1, 5, 5)), Err(RegistryError::DuplicateChain(ChainId(1))));
    }

    #[test]
    fn fixed_window_cap_accumulates_and_resets_on_epoch() {
        let mut reg = ChainRegistry::new();
        reg.add(row(1, 1000, 250)).unwrap();
        let c = ChainId(1);

        reg.consume(c, CapKind::Mint, 5, 100).unwrap();
        reg.consume(c, CapKind::Mint, 5, 100).unwrap();
        assert_eq!(reg.window_total(c, CapKind::Mint, 5), 200);
        // 200 + 100 > 250 → rejected, total unchanged.
        assert_eq!(
            reg.consume(c, CapKind::Mint, 5, 100),
            Err(RegistryError::OverEpochCap { chain: c, kind: CapKind::Mint, would_be: 300, cap: 250 })
        );
        assert_eq!(reg.window_total(c, CapKind::Mint, 5), 200);

        // New epoch → fresh window (fixed window, β = 1).
        reg.consume(c, CapKind::Mint, 6, 250).unwrap();
        assert_eq!(reg.window_total(c, CapKind::Mint, 6), 250);
        assert_eq!(reg.window_total(c, CapKind::Mint, 5), 0, "stale window pruned");
    }

    #[test]
    fn mint_and_release_budgets_are_independent() {
        let mut reg = ChainRegistry::new();
        reg.add(row(1, 1000, 200)).unwrap();
        let c = ChainId(1);
        reg.consume(c, CapKind::Mint, 5, 200).unwrap(); // mint window full
        // Release window for the same epoch is untouched.
        assert!(reg.consume(c, CapKind::Release, 5, 200).is_ok());
        assert_eq!(
            reg.consume(c, CapKind::Mint, 5, 1),
            Err(RegistryError::OverEpochCap { chain: c, kind: CapKind::Mint, would_be: 201, cap: 200 })
        );
    }
}
