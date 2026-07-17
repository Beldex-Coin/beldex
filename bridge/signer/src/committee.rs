//! The epoch/committee view mirrored from `beldexd` (plan §6.2 B.9).
//!
//! The signer does **not** recompute consensus: it reads the current `bridge`
//! quorum from `beldexd`'s `bridge.committee` endpoint and represents it here.
//! This module is the local, read-only model of that state plus the small amount
//! of derived logic the signer needs (epoch math, membership, threshold).

/// A committee member identity — the masternode pubkey (its on-chain identity).
pub type MemberId = [u8; 32];

/// One epoch's signing committee, as reported by consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeView {
    /// Epoch index, `floor(height / bridge_epoch_blocks)`.
    pub epoch: u64,
    /// The epoch-boundary height the committee was selected at.
    pub height: u64,
    /// Ordered committee members (`n`), as the on-chain quorum lists them.
    pub members: Vec<MemberId>,
    /// Threshold `t + 1` required to produce a signature.
    pub threshold: usize,
}

impl CommitteeView {
    /// The epoch that contains `height`.
    pub fn epoch_for_height(height: u64, epoch_blocks: u64) -> u64 {
        debug_assert!(epoch_blocks > 0);
        height / epoch_blocks
    }

    /// This member's index within the committee, if seated.
    pub fn self_index(&self, me: &MemberId) -> Option<usize> {
        self.members.iter().position(|m| m == me)
    }

    /// Whether `id` is on this committee.
    pub fn is_member(&self, id: &MemberId) -> bool {
        self.members.iter().any(|m| m == id)
    }

    /// The committee size `n`.
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Whether the committee is large enough to sign (`n >= t + 1`). A committee
    /// that has dropped below threshold is dormant/frozen-but-safe — no signing.
    pub fn can_sign(&self) -> bool {
        self.members.len() >= self.threshold && self.threshold > 0
    }

    /// Whether `a`'s membership overlaps this committee by at least `t + 1`,
    /// i.e. a *reshare* (key-invariant) suffices for the transition rather than a
    /// full fresh DKG (plan §B.7 / S11).
    pub fn overlaps_for_reshare(&self, prev: &CommitteeView) -> bool {
        let overlap = self.members.iter().filter(|m| prev.is_member(m)).count();
        overlap >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> MemberId {
        [b; 32]
    }

    fn committee(members: &[u8], threshold: usize, epoch: u64) -> CommitteeView {
        CommitteeView {
            epoch,
            height: epoch * 2880,
            members: members.iter().map(|b| id(*b)).collect(),
            threshold,
        }
    }

    #[test]
    fn epoch_math() {
        assert_eq!(CommitteeView::epoch_for_height(0, 2880), 0);
        assert_eq!(CommitteeView::epoch_for_height(2879, 2880), 0);
        assert_eq!(CommitteeView::epoch_for_height(2880, 2880), 1);
        assert_eq!(CommitteeView::epoch_for_height(5761, 2880), 2);
    }

    #[test]
    fn membership_and_self_index() {
        let c = committee(&[1, 2, 3, 4], 3, 7);
        assert!(c.is_member(&id(3)));
        assert!(!c.is_member(&id(9)));
        assert_eq!(c.self_index(&id(2)), Some(1));
        assert_eq!(c.self_index(&id(9)), None);
        assert_eq!(c.size(), 4);
    }

    #[test]
    fn can_sign_requires_threshold() {
        assert!(committee(&[1, 2, 3], 3, 0).can_sign()); // n == t+1
        assert!(committee(&[1, 2, 3, 4], 3, 0).can_sign()); // n > t+1
        assert!(!committee(&[1, 2], 3, 0).can_sign()); // n < t+1 -> dormant
        assert!(!committee(&[], 0, 0).can_sign()); // no committee / zero threshold
    }

    #[test]
    fn reshare_needs_threshold_overlap() {
        let prev = committee(&[1, 2, 3, 4, 5], 3, 1);
        // 3 of the new members were in the previous committee -> reshare (>= t+1).
        let next = committee(&[1, 2, 3, 8, 9], 3, 2);
        assert!(next.overlaps_for_reshare(&prev));
        // Only 2 carried over -> below threshold -> requires fresh DKG.
        let churned = committee(&[1, 2, 7, 8, 9], 3, 2);
        assert!(!churned.overlaps_for_reshare(&prev));
    }
}
