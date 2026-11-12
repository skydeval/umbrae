//! The commit digest's set hash (spec: "Commit digest").
//!
//! LtHash over 1024 little-endian `u16` lanes (2048 bytes). Each element is
//! expanded to 2048 bytes with BLAKE3 in XOF mode and added or subtracted
//! lane-wise, modulo 2^16. Both operations commute, so the state depends
//! only on the current multiset of elements. A commit carries
//! `sha256(state)`.

use sha2::{Digest, Sha256};

/// Number of `u16` lanes in the state.
pub const LANES: usize = 1024;
/// Size of the persisted state in bytes.
pub const STATE_BYTES: usize = LANES * 2;

/// The incremental set hash a repo host keeps for each space repo, and a
/// syncer keeps for its copy.
#[derive(Clone, PartialEq, Eq)]
pub struct LtHash {
    lanes: [u16; LANES],
}

impl Default for LtHash {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LtHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = self.digest();
        write!(f, "LtHash(")?;
        for b in &d[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// The persisted state had the wrong length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLengthError(pub usize);

impl std::fmt::Display for StateLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LtHash state must be {STATE_BYTES} bytes, got {}",
            self.0
        )
    }
}

impl std::error::Error for StateLengthError {}

impl LtHash {
    /// The empty set: all lanes zero.
    pub fn new() -> Self {
        Self { lanes: [0; LANES] }
    }

    /// Resume from a persisted 2048-byte state.
    pub fn from_state(state: &[u8]) -> Result<Self, StateLengthError> {
        if state.len() != STATE_BYTES {
            return Err(StateLengthError(state.len()));
        }
        let mut lanes = [0u16; LANES];
        for (lane, chunk) in lanes.iter_mut().zip(state.chunks_exact(2)) {
            *lane = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        Ok(Self { lanes })
    }

    /// The full state, for persistence.
    pub fn state(&self) -> [u8; STATE_BYTES] {
        let mut out = [0u8; STATE_BYTES];
        for (chunk, lane) in out.chunks_exact_mut(2).zip(self.lanes.iter()) {
            chunk.copy_from_slice(&lane.to_le_bytes());
        }
        out
    }

    /// Add one element.
    pub fn add(&mut self, element: &[u8]) -> &mut Self {
        let e = expand(element);
        for (lane, x) in self.lanes.iter_mut().zip(e.iter()) {
            *lane = lane.wrapping_add(*x);
        }
        self
    }

    /// Remove one element.
    pub fn remove(&mut self, element: &[u8]) -> &mut Self {
        let e = expand(element);
        for (lane, x) in self.lanes.iter_mut().zip(e.iter()) {
            *lane = lane.wrapping_sub(*x);
        }
        self
    }

    /// Add a record, as the element `{collection}/{rkey}/{cid}`.
    pub fn add_record(&mut self, collection: &str, rkey: &str, cid: &str) -> &mut Self {
        self.add(record_element(collection, rkey, cid).as_bytes())
    }

    /// Remove a record, as the element `{collection}/{rkey}/{cid}`.
    pub fn remove_record(&mut self, collection: &str, rkey: &str, cid: &str) -> &mut Self {
        self.remove(record_element(collection, rkey, cid).as_bytes())
    }

    /// `sha256(state)`: the commit's `data` field.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.state()).into()
    }

    /// True when every lane is zero (the empty repo).
    pub fn is_empty(&self) -> bool {
        self.lanes.iter().all(|l| *l == 0)
    }
}

/// The set-hash element for a record: `{collection}/{rkey}/{record_cid}`.
pub fn record_element(collection: &str, rkey: &str, cid: &str) -> String {
    let mut s = String::with_capacity(collection.len() + rkey.len() + cid.len() + 2);
    s.push_str(collection);
    s.push('/');
    s.push_str(rkey);
    s.push('/');
    s.push_str(cid);
    s
}

fn expand(element: &[u8]) -> [u16; LANES] {
    let mut bytes = [0u8; STATE_BYTES];
    let mut hasher = blake3::Hasher::new();
    hasher.update(element);
    hasher.finalize_xof().fill(&mut bytes);
    let mut lanes = [0u16; LANES];
    for (lane, chunk) in lanes.iter_mut().zip(bytes.chunks_exact(2)) {
        *lane = u16::from_le_bytes([chunk[0], chunk[1]]);
    }
    lanes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn empty_is_all_zero_and_digest_matches_spec() {
        let h = LtHash::new();
        assert!(h.is_empty());
        assert_eq!(h.state(), [0u8; STATE_BYTES]);
        // The empty repo's `data`, given in the spec ("Repo lifecycle").
        assert_eq!(
            hex(&h.digest()),
            "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"
        );
    }

    #[test]
    fn snapshot_vector_matches_reference() {
        // Same vector as the reference implementation's test suite.
        let mut h = LtHash::new();
        h.add(b"one").add(b"two");
        assert_eq!(
            hex(&h.digest()),
            "ae05cb6d224379d9710c290c8529945c5b0e0fde9ead30b9699057ce701c63e7"
        );
    }

    #[test]
    fn add_then_remove_is_empty() {
        let mut h = LtHash::new();
        h.add(b"a");
        assert!(!h.is_empty());
        h.remove(b"a");
        assert!(h.is_empty());
    }

    #[test]
    fn order_independent() {
        let mut a = LtHash::new();
        a.add(b"a").add(b"b");
        let mut b = LtHash::new();
        b.add(b"b").add(b"a");
        assert_eq!(a, b);
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn distinguishes_elements() {
        let mut a = LtHash::new();
        a.add(b"a");
        let mut b = LtHash::new();
        b.add(b"b");
        assert_ne!(a, b);
    }

    #[test]
    fn multiset_double_add_does_not_cancel() {
        let mut h = LtHash::new();
        h.add(b"a").add(b"a");
        assert!(!h.is_empty());
        h.remove(b"a");
        let mut one = LtHash::new();
        one.add(b"a");
        assert_eq!(h, one);
    }

    #[test]
    fn state_round_trips() {
        let mut h = LtHash::new();
        h.add(b"a").add(b"b");
        let resumed = LtHash::from_state(&h.state()).unwrap();
        assert_eq!(resumed, h);
    }

    #[test]
    fn rejects_wrong_length_state() {
        assert_eq!(LtHash::from_state(&[0u8; 32]), Err(StateLengthError(32)));
    }

    #[test]
    fn record_element_format() {
        assert_eq!(
            record_element("com.example.post", "3mwcj3b6uak2f", "bafyrei"),
            "com.example.post/3mwcj3b6uak2f/bafyrei"
        );
        let mut a = LtHash::new();
        a.add_record("com.example.post", "k", "c");
        let mut b = LtHash::new();
        b.add(b"com.example.post/k/c");
        assert_eq!(a, b);
    }

    #[test]
    fn wraps_modulo_2_16() {
        // Removing from the empty state wraps rather than panicking, and
        // adding back returns to zero.
        let mut h = LtHash::new();
        h.remove(b"x");
        assert!(!h.is_empty());
        h.add(b"x");
        assert!(h.is_empty());
    }
}
