//! Minimal RLP encoder (Ethereum Yellow Paper Appendix B) — enough to build a typed
//! EIP-1559 transaction, no more.
//!
//! Hand-rolled rather than pulled from a crate: the relayer's whole point is to be a small,
//! auditable, dependency-light courier, and RLP for our shape (byte strings + one flat list)
//! is a few dozen lines whose edge cases are exactly the ones the tests below pin — the
//! single-byte short form, the 55/56-byte length boundary, and the **minimal big-endian
//! integer** rule (a leading zero byte, or encoding 0 as `0x00` instead of the empty string,
//! silently changes the transaction hash and would produce a valid-looking but wrong tx).

/// Encode a byte string.
pub fn encode_bytes(b: &[u8]) -> Vec<u8> {
    // A single byte below 0x80 is its own encoding (no prefix).
    if b.len() == 1 && b[0] < 0x80 {
        return vec![b[0]];
    }
    let mut out = Vec::with_capacity(b.len() + 9);
    push_header(&mut out, b.len(), 0x80, 0xb7);
    out.extend_from_slice(b);
    out
}

/// Encode a list whose items are already RLP-encoded.
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload_len + 9);
    push_header(&mut out, payload_len, 0xc0, 0xf7);
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

/// `short_base` for payloads ≤ 55 bytes, `long_base` + big-endian length otherwise.
fn push_header(out: &mut Vec<u8>, len: usize, short_base: u8, long_base: u8) {
    if len <= 55 {
        out.push(short_base + len as u8);
    } else {
        let len_be = minimal_be(len as u128);
        out.push(long_base + len_be.len() as u8);
        out.extend_from_slice(&len_be);
    }
}

/// Big-endian bytes with no leading zeros; **zero encodes as empty** (RLP integer rule).
pub fn minimal_be(v: u128) -> Vec<u8> {
    if v == 0 {
        return Vec::new();
    }
    let full = v.to_be_bytes();
    let first = full.iter().position(|&b| b != 0).unwrap();
    full[first..].to_vec()
}

/// Encode an integer as an RLP byte string (minimal big-endian).
pub fn encode_uint(v: u128) -> Vec<u8> {
    encode_bytes(&minimal_be(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_vectors() {
        // From the Yellow Paper / common RLP test suites.
        assert_eq!(encode_bytes(b""), vec![0x80]);
        assert_eq!(encode_bytes(b"\x00"), vec![0x00]); // single byte < 0x80 is itself
        assert_eq!(encode_bytes(b"\x7f"), vec![0x7f]);
        assert_eq!(encode_bytes(b"\x80"), vec![0x81, 0x80]); // 0x80 needs the prefix
        assert_eq!(encode_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(encode_list(&[]), vec![0xc0]);
        assert_eq!(
            encode_list(&[encode_bytes(b"cat"), encode_bytes(b"dog")]),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
    }

    #[test]
    fn length_boundary_switches_to_the_long_form() {
        let s55 = vec![0xaau8; 55];
        let e55 = encode_bytes(&s55);
        assert_eq!(e55[0], 0x80 + 55, "55 bytes stays short-form");
        assert_eq!(e55.len(), 56);

        let s56 = vec![0xaau8; 56];
        let e56 = encode_bytes(&s56);
        assert_eq!(e56[0], 0xb7 + 1, "56 bytes uses long-form with a 1-byte length");
        assert_eq!(e56[1], 56);
        assert_eq!(e56.len(), 58);

        // A 256-byte string needs a 2-byte length.
        let s256 = vec![0x11u8; 256];
        let e256 = encode_bytes(&s256);
        assert_eq!(&e256[..3], &[0xb7 + 2, 0x01, 0x00]);
    }

    #[test]
    fn integers_are_minimal_big_endian() {
        assert_eq!(minimal_be(0), Vec::<u8>::new(), "zero is the EMPTY string, not 0x00");
        assert_eq!(encode_uint(0), vec![0x80]);
        assert_eq!(minimal_be(1), vec![0x01]);
        assert_eq!(encode_uint(1), vec![0x01]);
        assert_eq!(minimal_be(0x0100), vec![0x01, 0x00], "no leading zeros, inner zeros kept");
        assert_eq!(encode_uint(1024), vec![0x82, 0x04, 0x00]);
        assert_eq!(minimal_be(u128::MAX).len(), 16);
    }

    #[test]
    fn long_list_header_uses_the_long_form() {
        // 20 items of 4 bytes each = 100 bytes of payload → long-form list header.
        let items: Vec<Vec<u8>> = (0..20).map(|_| encode_bytes(&[1, 2, 3])).collect();
        let e = encode_list(&items);
        assert_eq!(e[0], 0xf7 + 1);
        assert_eq!(e[1] as usize, items.iter().map(Vec::len).sum::<usize>());
    }
}
