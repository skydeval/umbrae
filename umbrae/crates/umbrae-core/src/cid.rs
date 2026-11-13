//! DASL CIDs (<https://dasl.ing/cid.html>).
//!
//! Always CID version 1 with a SHA-256 digest, and one of two codecs: DRISL
//! (`0x71`) for encoded records, raw (`0x55`) for blobs. The binary form is
//! a fixed 36 bytes; the string form is `b` followed by lowercase,
//! unpadded RFC 4648 base32.

use sha2::{Digest, Sha256};
use std::fmt;

const VERSION: u8 = 0x01;
const SHA256: u8 = 0x12;
const DIGEST_LEN: u8 = 0x20;
/// Length of a CID's binary form.
pub const CID_BYTES: usize = 36;
/// Length of a CID's string form: `b` plus 58 base32 characters.
const CID_STR_LEN: usize = 1 + 58;
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// What the CID's bytes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Codec {
    /// A DRISL-encoded value (a record).
    Drisl,
    /// Raw bytes (a blob).
    Raw,
}

impl Codec {
    fn code(self) -> u8 {
        match self {
            Codec::Drisl => 0x71,
            Codec::Raw => 0x55,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0x71 => Some(Codec::Drisl),
            0x55 => Some(Codec::Raw),
            _ => None,
        }
    }
}

/// A DASL CID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid {
    codec: Codec,
    digest: [u8; 32],
}

/// Why bytes or a string aren't a DASL CID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidError {
    Length,
    Version,
    Codec,
    Hash,
    Multibase,
    Base32,
}

impl fmt::Display for CidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CidError::Length => "CID has the wrong length",
            CidError::Version => "CID version must be 1",
            CidError::Codec => "CID codec must be DRISL (0x71) or raw (0x55)",
            CidError::Hash => "CID hash must be a 32-byte sha256",
            CidError::Multibase => "CID string must start with 'b'",
            CidError::Base32 => "CID string is not canonical lowercase base32",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CidError {}

impl Cid {
    /// The CID of DRISL-encoded bytes. Does not check the encoding; see
    /// [`crate::drisl::record_cid`] for records from outside.
    pub fn for_drisl(encoded: &[u8]) -> Self {
        Self::new(Codec::Drisl, Sha256::digest(encoded).into())
    }

    /// The CID of raw bytes (a blob).
    pub fn for_raw(bytes: &[u8]) -> Self {
        Self::new(Codec::Raw, Sha256::digest(bytes).into())
    }

    pub fn new(codec: Codec, digest: [u8; 32]) -> Self {
        Self { codec, digest }
    }

    pub fn codec(&self) -> Codec {
        self.codec
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The 36-byte binary form.
    pub fn to_bytes(&self) -> [u8; CID_BYTES] {
        let mut out = [0u8; CID_BYTES];
        out[0] = VERSION;
        out[1] = self.codec.code();
        out[2] = SHA256;
        out[3] = DIGEST_LEN;
        out[4..].copy_from_slice(&self.digest);
        out
    }

    /// Parse the binary form. The whole slice must be the CID.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CidError> {
        if bytes.len() < 4 {
            return Err(CidError::Length);
        }
        if bytes[0] != VERSION {
            return Err(CidError::Version);
        }
        let codec = Codec::from_code(bytes[1]).ok_or(CidError::Codec)?;
        if bytes[2] != SHA256 || bytes[3] != DIGEST_LEN {
            return Err(CidError::Hash);
        }
        if bytes.len() != CID_BYTES {
            return Err(CidError::Length);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[4..]);
        Ok(Self { codec, digest })
    }

    /// Parse the string form. Only canonical strings are accepted, so each
    /// CID has exactly one string, which the set hash depends on.
    pub fn parse(s: &str) -> Result<Self, CidError> {
        let Some(body) = s.strip_prefix('b') else {
            return Err(CidError::Multibase);
        };
        if s.len() != CID_STR_LEN {
            return Err(CidError::Length);
        }
        let bytes = base32_decode(body.as_bytes()).ok_or(CidError::Base32)?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("b")?;
        f.write_str(&base32_encode(&self.to_bytes()))
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({self})")
    }
}

impl std::str::FromStr for Cid {
    type Err = CidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Strict decode: lowercase alphabet only, no padding, and any leftover
/// bits must be zero (so the string is the canonical one).
fn base32_decode(chars: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(chars.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in chars {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits >= 5 || acc != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // From the reference implementation's tests: the CIDs of the DRISL
    // encodings of `{ text: 'hello' }` and `{ text: 'world' }`.
    const CID_A: &str = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244";
    const CID_B: &str = "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a";

    #[test]
    fn round_trips_reference_cids() {
        for s in [CID_A, CID_B] {
            let cid = Cid::parse(s).unwrap();
            assert_eq!(cid.codec(), Codec::Drisl);
            assert_eq!(cid.to_string(), s);
            assert_eq!(Cid::from_bytes(&cid.to_bytes()).unwrap(), cid);
        }
    }

    #[test]
    fn hashes_drisl_bytes() {
        // {"text": "hello"}: map(1), text(4) "text", text(5) "hello".
        let encoded = b"\xa1\x64text\x65hello";
        assert_eq!(Cid::for_drisl(encoded).to_string(), CID_A);
    }

    #[test]
    fn raw_codec() {
        let cid = Cid::for_raw(b"blob");
        assert_eq!(cid.codec(), Codec::Raw);
        assert!(cid.to_string().starts_with("bafkrei"));
        assert_eq!(Cid::parse(&cid.to_string()).unwrap(), cid);
    }

    #[test]
    fn rejects_non_canonical_strings() {
        assert_eq!(Cid::parse(&CID_A.to_uppercase()), Err(CidError::Multibase));
        let upper_body = format!("b{}", &CID_A[1..].to_uppercase());
        assert_eq!(Cid::parse(&upper_body), Err(CidError::Base32));
        assert_eq!(Cid::parse(&format!("{CID_A}=")), Err(CidError::Length));
        assert_eq!(Cid::parse(&CID_A[..58]), Err(CidError::Length));
        assert_eq!(
            Cid::parse(&format!("z{}", &CID_A[1..])),
            Err(CidError::Multibase)
        );
        // Flip the unused low bits of the last character: same bytes,
        // non-canonical string.
        let mut s = CID_A.as_bytes().to_vec();
        let last = s.len() - 1;
        s[last] = b'5'; // '4' -> '5' sets a trailing bit
        assert_eq!(
            Cid::parse(std::str::from_utf8(&s).unwrap()),
            Err(CidError::Base32)
        );
    }

    #[test]
    fn rejects_other_versions_codecs_and_hashes() {
        let good = Cid::parse(CID_A).unwrap().to_bytes();
        let mut b = good;
        b[0] = 0x00;
        assert_eq!(Cid::from_bytes(&b), Err(CidError::Version));
        let mut b = good;
        b[1] = 0x70; // dag-pb
        assert_eq!(Cid::from_bytes(&b), Err(CidError::Codec));
        let mut b = good;
        b[2] = 0x1e; // blake3
        assert_eq!(Cid::from_bytes(&b), Err(CidError::Hash));
        assert_eq!(Cid::from_bytes(&good[..35]), Err(CidError::Length));
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(Cid::from_bytes(&long), Err(CidError::Length));
    }
}
