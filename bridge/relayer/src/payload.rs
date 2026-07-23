//! The unit of work a relayer carries: a **[`RelayPayload`]** — an already-committee-signed
//! wBDX call, fully self-contained. The relayer turns it into a [`PreparedCall`] (the exact
//! `{chain_id, to, data}` to broadcast) and either pays gas to submit it or hands it to the
//! user to submit themselves. The relayer verifies nothing and can forge nothing: the
//! authorizing signature is already inside the payload, and the destination contract checks
//! it. If every relayer vanishes, any user can build the same [`PreparedCall`] and broadcast.

use crate::abi::{build_mint_calldata, build_rotate_calldata};

/// A ready-to-broadcast EVM call: send `data` to `to` on chain `chain_id`, paying gas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCall {
    pub chain_id: u64,
    pub to: [u8; 20],
    pub data: Vec<u8>,
}

/// An already-signed wBDX payload a relayer carries to its destination chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPayload {
    /// A committee-signed `mint` (a finalized Beldex deposit → wBDX on `chain_id`).
    Mint {
        contract: [u8; 20],
        chain_id: u64,
        to: [u8; 20],
        amount: u128,
        beldex_txid: [u8; 32],
        /// The `Pevm` committee ECDSA signature (r‖s‖v, 65 bytes) — verified by `ecrecover`.
        sig: Vec<u8>,
    },
    /// An outgoing-committee-signed `rotateSigner` (the H.6 key hand-off).
    Rotate {
        contract: [u8; 20],
        chain_id: u64,
        new_signer: [u8; 20],
        new_key_epoch: u64,
        sig: Vec<u8>,
    },
}

impl RelayPayload {
    pub fn chain_id(&self) -> u64 {
        match self {
            RelayPayload::Mint { chain_id, .. } | RelayPayload::Rotate { chain_id, .. } => *chain_id,
        }
    }

    pub fn contract(&self) -> [u8; 20] {
        match self {
            RelayPayload::Mint { contract, .. } | RelayPayload::Rotate { contract, .. } => *contract,
        }
    }

    /// The ABI calldata for this payload's wBDX call.
    pub fn calldata(&self) -> Vec<u8> {
        match self {
            RelayPayload::Mint { to, amount, beldex_txid, sig, .. } => {
                build_mint_calldata(*to, *amount, *beldex_txid, sig)
            }
            RelayPayload::Rotate { new_signer, new_key_epoch, sig, .. } => {
                build_rotate_calldata(*new_signer, *new_key_epoch, sig)
            }
        }
    }

    /// The exact `{chain_id, to, data}` to broadcast (or hand to `cast send` / a wallet).
    pub fn to_prepared(&self) -> PreparedCall {
        PreparedCall { chain_id: self.chain_id(), to: self.contract(), data: self.calldata() }
    }
}

/// Payload decode/parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    MissingField(&'static str),
    BadHex(&'static str),
    BadLength(&'static str),
    BadAmount,
    UnknownKind(String),
    Json(String),
}

/// Decode a fixed-size hex field (no `0x`), erroring with the field name.
fn hex_fixed<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], PayloadError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|_| PayloadError::BadHex(field))?;
    if bytes.len() != N {
        return Err(PayloadError::BadLength(field));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_var(s: &str, field: &'static str) -> Result<Vec<u8>, PayloadError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|_| PayloadError::BadHex(field))
}

#[cfg(feature = "json")]
mod json {
    use super::*;
    use serde_json::Value;

    fn get_str<'a>(v: &'a Value, field: &'static str) -> Result<&'a str, PayloadError> {
        v.get(field).and_then(Value::as_str).ok_or(PayloadError::MissingField(field))
    }

    impl RelayPayload {
        /// Parse a payload from the JSON a signer (or a user) hands to the relayer:
        ///
        /// ```json
        /// { "kind": "mint", "contract": "<40hex>", "chain_id": 1, "to": "<40hex>",
        ///   "amount": "1000", "beldex_txid": "<64hex>", "sig": "<130hex>" }
        /// { "kind": "rotate", "contract": "<40hex>", "chain_id": 1,
        ///   "new_signer": "<40hex>", "new_key_epoch": 7, "sig": "<130hex>" }
        /// ```
        ///
        /// `amount` is a decimal **string** (a wBDX unit is 1 atomic BDX; u128 to be safe).
        pub fn from_json(s: &str) -> Result<RelayPayload, PayloadError> {
            let v: Value = serde_json::from_str(s).map_err(|e| PayloadError::Json(e.to_string()))?;
            let kind = get_str(&v, "kind")?;
            // Reject an unknown kind BEFORE parsing shared fields, so a bad kind
            // surfaces as UnknownKind rather than a field error on contract/sig.
            if kind != "mint" && kind != "rotate" {
                return Err(PayloadError::UnknownKind(kind.to_string()));
            }
            let chain_id = v.get("chain_id").and_then(Value::as_u64).ok_or(PayloadError::MissingField("chain_id"))?;
            let contract = hex_fixed::<20>(get_str(&v, "contract")?, "contract")?;
            let sig = hex_var(get_str(&v, "sig")?, "sig")?;

            match kind {
                "mint" => {
                    let to = hex_fixed::<20>(get_str(&v, "to")?, "to")?;
                    let beldex_txid = hex_fixed::<32>(get_str(&v, "beldex_txid")?, "beldex_txid")?;
                    let amount = get_str(&v, "amount")?
                        .parse::<u128>()
                        .map_err(|_| PayloadError::BadAmount)?;
                    Ok(RelayPayload::Mint { contract, chain_id, to, amount, beldex_txid, sig })
                }
                "rotate" => {
                    let new_signer = hex_fixed::<20>(get_str(&v, "new_signer")?, "new_signer")?;
                    let new_key_epoch = v
                        .get("new_key_epoch")
                        .and_then(Value::as_u64)
                        .ok_or(PayloadError::MissingField("new_key_epoch"))?;
                    Ok(RelayPayload::Rotate { contract, chain_id, new_signer, new_key_epoch, sig })
                }
                other => Err(PayloadError::UnknownKind(other.to_string())),
            }
        }

        /// Emit the payload as JSON (round-trips with [`from_json`](Self::from_json)).
        pub fn to_json(&self) -> String {
            let hexs = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            match self {
                RelayPayload::Mint { contract, chain_id, to, amount, beldex_txid, sig } => format!(
                    concat!(
                        r#"{{"kind":"mint","contract":"{}","chain_id":{},"to":"{}","#,
                        r#""amount":"{}","beldex_txid":"{}","sig":"{}"}}"#
                    ),
                    hexs(contract), chain_id, hexs(to), amount, hexs(beldex_txid), hexs(sig),
                ),
                RelayPayload::Rotate { contract, chain_id, new_signer, new_key_epoch, sig } => format!(
                    concat!(
                        r#"{{"kind":"rotate","contract":"{}","chain_id":{},"#,
                        r#""new_signer":"{}","new_key_epoch":{},"sig":"{}"}}"#
                    ),
                    hexs(contract), chain_id, hexs(new_signer), new_key_epoch, hexs(sig),
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_mint() -> RelayPayload {
        RelayPayload::Mint {
            contract: [0x22; 20],
            chain_id: 1,
            to: [0x11; 20],
            amount: 1000,
            beldex_txid: [0xcd; 32],
            sig: vec![0xab; 65],
        }
    }

    #[test]
    fn prepared_call_targets_the_contract_with_calldata() {
        let p = sample_mint();
        let call = p.to_prepared();
        assert_eq!(call.chain_id, 1);
        assert_eq!(call.to, [0x22; 20]);
        assert_eq!(&call.data[0..4], &crate::abi::MINT_SELECTOR);
        assert_eq!(call.data, p.calldata());
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_round_trips_mint_and_rotate() {
        let m = sample_mint();
        assert_eq!(RelayPayload::from_json(&m.to_json()).unwrap(), m);

        let r = RelayPayload::Rotate {
            contract: [0x22; 20],
            chain_id: 42,
            new_signer: [0x33; 20],
            new_key_epoch: 7,
            sig: vec![0xee; 65],
        };
        assert_eq!(RelayPayload::from_json(&r.to_json()).unwrap(), r);
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_rejects_bad_fields() {
        assert!(matches!(
            RelayPayload::from_json(r#"{"kind":"nope","contract":"22","chain_id":1,"sig":"ab"}"#),
            Err(PayloadError::UnknownKind(_))
        ));
        assert_eq!(
            RelayPayload::from_json(r#"{"kind":"mint","chain_id":1}"#),
            Err(PayloadError::MissingField("contract"))
        );
        // A 19-byte contract is the wrong length.
        let bad = format!(
            r#"{{"kind":"mint","contract":"{}","chain_id":1,"to":"{}","amount":"1","beldex_txid":"{}","sig":"ab"}}"#,
            "11".repeat(19), "22".repeat(20), "cd".repeat(32)
        );
        assert_eq!(RelayPayload::from_json(&bad), Err(PayloadError::BadLength("contract")));
    }
}
