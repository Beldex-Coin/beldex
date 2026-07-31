//! The broadcast seam. A relayer's **only** key is a gas-paying EOA, entirely unrelated to
//! any bridge key — a [`TxSubmitter`] signs and broadcasts the outer EVM transaction that
//! carries an already-signed [`PreparedCall`]. The trait keeps the courier logic testable
//! (a [`MockSubmitter`] records calls) and lets the real broadcast backend be swapped in.
//!
//! The real backend now lives in [`crate::http_submit`] (feature `submit-http`): it builds the
//! EIP-1559 envelope ([`crate::eip1559`]) around the `PreparedCall`, signs it with a funded
//! gas key, and `eth_sendRawTransaction`s it. That key carries **no bridge authority** — the
//! committee signature is inside the calldata — so running the service is optional and
//! untrusted: [`RelayPayload::to_prepared`] still yields the `{chain_id, to, data}` any user
//! can broadcast with `cast send`, so the bridge is **never liveness-blocked on a relayer**.

use crate::payload::PreparedCall;

/// Broadcast failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// The submitter has no backend for this chain id.
    UnknownChain(u64),
    /// Transport / RPC failure (stringified to stay dep-free at the interface).
    Transport(String),
    /// The node rejected the transaction (e.g. reverted in estimation).
    Rejected(String),
}

/// Signs + broadcasts the outer EVM tx carrying a [`PreparedCall`], paying gas.
pub trait TxSubmitter {
    /// Returns the broadcast transaction hash (0x-hex) on success.
    fn submit(&self, call: &PreparedCall) -> Result<String, SubmitError>;
}

/// A test/inspection submitter: records every call and returns a canned hash. Never touches
/// a network. Useful for exercising the courier end to end without a chain.
#[derive(Debug, Default)]
pub struct MockSubmitter {
    pub calls: std::cell::RefCell<Vec<PreparedCall>>,
    pub tx_hash: String,
}

impl MockSubmitter {
    pub fn new(tx_hash: impl Into<String>) -> MockSubmitter {
        MockSubmitter { calls: std::cell::RefCell::new(Vec::new()), tx_hash: tx_hash.into() }
    }
}

impl TxSubmitter for MockSubmitter {
    fn submit(&self, call: &PreparedCall) -> Result<String, SubmitError> {
        self.calls.borrow_mut().push(call.clone());
        Ok(self.tx_hash.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::RelayPayload;

    #[test]
    fn mock_submitter_records_the_prepared_call() {
        let p = RelayPayload::Mint {
            contract: [0x22; 20],
            chain_id: 1,
            to: [0x11; 20],
            amount: 500,
            beldex_txid: [0xcd; 32],
            sig: vec![0xab; 65],
        };
        let sub = MockSubmitter::new("0xdeadbeef");
        let hash = sub.submit(&p.to_prepared()).unwrap();
        assert_eq!(hash, "0xdeadbeef");
        assert_eq!(sub.calls.borrow().len(), 1);
        assert_eq!(sub.calls.borrow()[0], p.to_prepared());
    }
}
