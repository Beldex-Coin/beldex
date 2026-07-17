//! The epoch/committee view mirrored from `beldexd` (plan §6.2 B.9).
//!
//! The signer does **not** recompute consensus: it reads the current `bridge`
//! quorum from `beldexd`'s `bridge.committee` endpoint and represents it here.
//! This module is the local, read-only model of that state plus the small amount
//! of derived logic the signer needs (epoch math, membership, threshold).

/// A committee member identity — the masternode pubkey (its on-chain identity).
pub type MemberId = [u8; 32];

/// Errors fetching / parsing a committee view from `beldexd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitteeError {
    /// A required field was absent from the daemon's reply.
    MissingField(&'static str),
    /// A field was present but unparseable (non-numeric, malformed array…).
    BadValue(&'static str),
    /// A `members[]` entry was not 32-byte hex.
    BadMemberHex,
    /// The daemon replied but reported the bridge inactive (below the floor);
    /// carries the (epoch, height) so the caller can wait/retry.
    Inactive { epoch: u64, height: u64 },
    /// Transport failure (OMQ connect/timeout/status). String, so this module
    /// stays std-only and free of any transport crate types.
    Transport(String),
}

impl std::fmt::Display for CommitteeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitteeError::MissingField(k) => write!(f, "bridge.committee reply missing field: {k}"),
            CommitteeError::BadValue(k) => write!(f, "bridge.committee reply has bad value for: {k}"),
            CommitteeError::BadMemberHex => write!(f, "bridge.committee member is not 32-byte hex"),
            CommitteeError::Inactive { epoch, height } => {
                write!(f, "bridge inactive at epoch {epoch} (height {height})")
            }
            CommitteeError::Transport(m) => write!(f, "bridge.committee transport error: {m}"),
        }
    }
}
impl std::error::Error for CommitteeError {}

// ---- minimal, targeted parsing of the daemon's flat JSON reply --------------
//
// The reply is a single flat object produced by nlohmann `json.dump()`:
//   {"active":true,"epoch":2,"height":240,"members":["<64hex>",...],
//    "self_index":2,"size":6,"threshold":4}
// Keys are unique and values are numbers / bools / hex strings (no nesting, no
// escaping), so a narrow scanner is safe and keeps the scaffold std-only — the
// same philosophy as the hand-rolled dotenv parser in `config`.

/// Return the substring starting at the value for `"key":`, or None.
fn value_after_key<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\"");
    let idx = s.find(&pat)? + pat.len();
    let rest = s[idx..].trim_start().strip_prefix(':')?;
    Some(rest.trim_start())
}

/// Parse an unsigned integer field.
fn json_u64(s: &str, key: &'static str) -> Result<u64, CommitteeError> {
    let v = value_after_key(s, key).ok_or(CommitteeError::MissingField(key))?;
    let end = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    v[..end].parse::<u64>().map_err(|_| CommitteeError::BadValue(key))
}

/// Parse a boolean field (`true`/`false`).
fn json_bool(s: &str, key: &'static str) -> Result<bool, CommitteeError> {
    let v = value_after_key(s, key).ok_or(CommitteeError::MissingField(key))?;
    if v.starts_with("true") {
        Ok(true)
    } else if v.starts_with("false") {
        Ok(false)
    } else {
        Err(CommitteeError::BadValue(key))
    }
}

/// Parse a `["a","b",...]` string array field.
fn json_str_array(s: &str, key: &'static str) -> Result<Vec<String>, CommitteeError> {
    let v = value_after_key(s, key).ok_or(CommitteeError::MissingField(key))?;
    let v = v.strip_prefix('[').ok_or(CommitteeError::BadValue(key))?;
    let end = v.find(']').ok_or(CommitteeError::BadValue(key))?;
    let inner = &v[..end];
    let mut out = Vec::new();
    for piece in inner.split(',') {
        let p = piece.trim();
        if p.is_empty() {
            continue; // empty array
        }
        let p = p
            .strip_prefix('"')
            .and_then(|x| x.strip_suffix('"'))
            .ok_or(CommitteeError::BadValue(key))?;
        out.push(p.to_string());
    }
    Ok(out)
}

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

    /// Parse the daemon's `bridge.committee` (or `bridge_get_committee`) JSON
    /// reply into a [`CommitteeView`]. Returns [`CommitteeError::Inactive`] when
    /// the bridge is below the activation floor (no committee yet), so callers
    /// can distinguish "not seated yet" from a malformed reply.
    pub fn from_bridge_committee_json(s: &str) -> Result<CommitteeView, CommitteeError> {
        let epoch = json_u64(s, "epoch")?;
        let height = json_u64(s, "height")?;
        let threshold = json_u64(s, "threshold")? as usize;
        let active = json_bool(s, "active")?;

        let members_hex = json_str_array(s, "members")?;
        let mut members = Vec::with_capacity(members_hex.len());
        for h in members_hex {
            members.push(crate::config::parse_hex32(&h).ok_or(CommitteeError::BadMemberHex)?);
        }

        if !active || members.is_empty() {
            return Err(CommitteeError::Inactive { epoch, height });
        }

        Ok(CommitteeView { epoch, height, members, threshold })
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

    // The exact reply produced by the bridge.committee OMQ endpoint on the
    // 6-node devnet (verified live). self_index 2 => members[2] = 2bdc…
    const DEVNET_REPLY: &str = concat!(
        "{\"active\":true,\"epoch\":2,\"height\":240,\"members\":[",
        "\"750cdb0bc41aa8666aa383ac52f91d15fb8ab4155811007f917f3a4439c73454\",",
        "\"e91ca9b5ccc851cf842e9c65b97a025f7dcade0a94cdbe438a23cc700b86886a\",",
        "\"2bdc188b20c7977ce0e15d56aec2502c58fc10434b2b1cbab3d7c79f69ec6b8e\",",
        "\"c4deaf497f4aa2789334ea48f0e77ef8e00c6f6e93bd5a0a94d67b5b6bd4eda3\",",
        "\"5871a131f53ffadce5a0d5b5f343924f6dd2b5b4480f3c81ed6cc8f34840cdf5\",",
        "\"41203ed56ba121fa0ebc632997ad81adcdec9f18ad98b8d4ef9c9cbb9bfdb366\"],",
        "\"self_index\":2,\"size\":6,\"threshold\":4}"
    );

    #[test]
    fn parses_the_live_devnet_reply() {
        let c = CommitteeView::from_bridge_committee_json(DEVNET_REPLY).expect("parse");
        assert_eq!(c.epoch, 2);
        assert_eq!(c.height, 240);
        assert_eq!(c.threshold, 4);
        assert_eq!(c.size(), 6);
        assert!(c.can_sign());
        // The signer computes its own index from its configured MN pubkey; the
        // node whose pubkey is members[2] must resolve to self_index 2 (matching
        // the daemon's server-side self_index).
        let me = crate::config::parse_hex32(
            "2bdc188b20c7977ce0e15d56aec2502c58fc10434b2b1cbab3d7c79f69ec6b8e",
        )
        .unwrap();
        assert_eq!(c.self_index(&me), Some(2));
        let stranger = [0u8; 32];
        assert_eq!(c.self_index(&stranger), None);
    }

    #[test]
    fn parse_tolerates_whitespace() {
        let spaced = "{ \"epoch\" : 3 , \"height\" : 360 , \"active\" : true , \
                       \"threshold\" : 4 , \"size\" : 2 , \
                       \"members\" : [ \"11\", \"22\" ] }"
            .replace("\"11\"", &format!("\"{}\"", "11".repeat(32)))
            .replace("\"22\"", &format!("\"{}\"", "22".repeat(32)));
        let c = CommitteeView::from_bridge_committee_json(&spaced).expect("parse spaced");
        assert_eq!(c.epoch, 3);
        assert_eq!(c.members[0], [0x11u8; 32]);
        assert_eq!(c.members[1], [0x22u8; 32]);
    }

    #[test]
    fn inactive_committee_is_distinguished() {
        let inactive = "{\"active\":false,\"epoch\":0,\"height\":0,\"members\":[],\
                         \"self_index\":-1,\"size\":6,\"threshold\":4}";
        assert_eq!(
            CommitteeView::from_bridge_committee_json(inactive),
            Err(CommitteeError::Inactive { epoch: 0, height: 0 })
        );
    }

    #[test]
    fn malformed_reply_is_reported() {
        // Missing threshold.
        let bad = "{\"active\":true,\"epoch\":1,\"height\":120,\"members\":[\"aa\"]}";
        assert!(matches!(
            CommitteeView::from_bridge_committee_json(bad),
            Err(CommitteeError::MissingField("threshold"))
        ));
        // Member not 32-byte hex.
        let bad2 = "{\"active\":true,\"epoch\":1,\"height\":120,\"threshold\":4,\"members\":[\"aa\"]}";
        assert_eq!(
            CommitteeView::from_bridge_committee_json(bad2),
            Err(CommitteeError::BadMemberHex)
        );
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
