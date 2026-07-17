//! Share-custody interface (**Phase D / D.1**).
//!
//! Holds each member's *own* shares of `Pevm` and `Pgw` (plus the Paillier
//! private key for `Pevm`) and the preprocessed pools. The trait fixes the
//! **duties**, not the hardware (auditors verify the duties, plan D.1):
//!
//!   1. **Non-exportability** — the authenticated signer process may *use* a
//!      share via key ops but never read the raw secret out; the interface here
//!      is versioned blobs, and production backends (Vault transit, an enclave)
//!      keep the secret sealed. A full OS compromise yields detectable live use,
//!      not an exfiltrated share.
//!   2. **Versioning** — every proactive refresh writes a new version; the store
//!      keeps enough to support the restore path (Phase J.2) without a reshare.
//!   3. **Epoch-consistent erasure** — superseded shares, used presignatures and
//!      consumed nonces are provably destroyed *including in backup history*
//!      ([`ShareStore::erase_versions_below`]); a restorable pre-refresh share
//!      silently voids proactive security (Assumption 2).
//!
//! This scaffold ships the in-memory backend ([`MemoryShareStore`]) for tests and
//! devnet; the Vault / enclave backends implement the same trait. **No key is
//! ever assembled here (S1): the store holds individual shares only.**

use std::collections::BTreeMap;
use std::collections::HashMap;

/// Custody backend for versioned key material. Keys are logical names such as
/// `"pevm.share"`, `"pgw.share"`, `"pevm.paillier"`.
pub trait ShareStore {
    /// Store `blob` for `key` at `version` (overwrites that version if present).
    fn put(&mut self, key: &str, version: u32, blob: Vec<u8>);
    /// The highest-versioned blob for `key`, if any.
    fn get_latest(&self, key: &str) -> Option<(u32, Vec<u8>)>;
    /// A specific version's blob for `key`, if present.
    fn get_version(&self, key: &str, version: u32) -> Option<Vec<u8>>;
    /// All stored versions for `key`, ascending.
    fn versions(&self, key: &str) -> Vec<u32>;
    /// Remove every version of `key` (e.g. share destroyed on ejection).
    fn erase_key(&mut self, key: &str);
    /// Epoch-consistent erasure: destroy every version of `key` **below**
    /// `min_version`, so no pre-refresh share survives (including in backups).
    fn erase_versions_below(&mut self, key: &str, min_version: u32);
}

/// In-memory [`ShareStore`] for tests / devnet. **Not** for production custody
/// (a full-node compromise reads it) — production uses Vault or an enclave.
#[derive(Debug, Default)]
pub struct MemoryShareStore {
    map: HashMap<String, BTreeMap<u32, Vec<u8>>>,
}

impl MemoryShareStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ShareStore for MemoryShareStore {
    fn put(&mut self, key: &str, version: u32, blob: Vec<u8>) {
        self.map.entry(key.to_string()).or_default().insert(version, blob);
    }

    fn get_latest(&self, key: &str) -> Option<(u32, Vec<u8>)> {
        self.map
            .get(key)
            .and_then(|versions| versions.iter().next_back())
            .map(|(v, blob)| (*v, blob.clone()))
    }

    fn get_version(&self, key: &str, version: u32) -> Option<Vec<u8>> {
        self.map.get(key).and_then(|versions| versions.get(&version)).cloned()
    }

    fn versions(&self, key: &str) -> Vec<u32> {
        self.map.get(key).map(|v| v.keys().copied().collect()).unwrap_or_default()
    }

    fn erase_key(&mut self, key: &str) {
        self.map.remove(key);
    }

    fn erase_versions_below(&mut self, key: &str, min_version: u32) {
        if let Some(versions) = self.map.get_mut(key) {
            versions.retain(|&v, _| v >= min_version);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get_latest() {
        let mut s = MemoryShareStore::new();
        s.put("pgw.share", 1, vec![1, 1, 1]);
        s.put("pgw.share", 2, vec![2, 2, 2]);
        assert_eq!(s.get_latest("pgw.share"), Some((2, vec![2, 2, 2])));
        assert_eq!(s.get_version("pgw.share", 1), Some(vec![1, 1, 1]));
        assert_eq!(s.get_latest("absent"), None);
    }

    #[test]
    fn versions_are_sorted() {
        let mut s = MemoryShareStore::new();
        s.put("k", 3, vec![]);
        s.put("k", 1, vec![]);
        s.put("k", 2, vec![]);
        assert_eq!(s.versions("k"), vec![1, 2, 3]);
    }

    #[test]
    fn epoch_consistent_erasure_leaves_no_old_share() {
        // Simulate three refresh epochs, then erase everything below the current.
        let mut s = MemoryShareStore::new();
        s.put("pevm.share", 1, vec![10]);
        s.put("pevm.share", 2, vec![20]);
        s.put("pevm.share", 3, vec![30]);
        s.erase_versions_below("pevm.share", 3);
        // A pre-refresh share must NOT be restorable (Assumption 2).
        assert_eq!(s.get_version("pevm.share", 1), None);
        assert_eq!(s.get_version("pevm.share", 2), None);
        assert_eq!(s.versions("pevm.share"), vec![3]);
        assert_eq!(s.get_latest("pevm.share"), Some((3, vec![30])));
    }

    #[test]
    fn erase_key_destroys_the_share() {
        let mut s = MemoryShareStore::new();
        s.put("pgw.share", 5, vec![9]);
        s.erase_key("pgw.share");
        assert_eq!(s.get_latest("pgw.share"), None);
        assert!(s.versions("pgw.share").is_empty());
    }
}
