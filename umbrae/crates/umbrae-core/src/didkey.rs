//! `did:key` encoding for the P-256 keys spaces use: credential binding
//! keys (`cnf.kid`), KEM keys (`#atproto_kem`) and MAC key shares.
//!
//! `did:key:z{base58btc(multicodec || compressed point)}`, with the P-256
//! public key multicodec `0x1200` (varint `80 24`).

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use std::fmt;

const PREFIX: &str = "did:key:z";
const P256_CODEC: [u8; 2] = [0x80, 0x24];

/// Why a string isn't a P-256 `did:key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidKeyError {
    /// Not `did:key:z…` with valid base58btc.
    Malformed,
    /// A key of another type.
    NotP256,
    /// Not a valid point on the curve.
    InvalidKey,
}

impl fmt::Display for DidKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DidKeyError::Malformed => "malformed did:key",
            DidKeyError::NotP256 => "did:key is not a P-256 key",
            DidKeyError::InvalidKey => "did:key holds an invalid P-256 point",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DidKeyError {}

/// Format a P-256 public key as a `did:key`, compressed.
pub fn format_p256(key: &PublicKey) -> String {
    let point = key.to_encoded_point(true);
    let mut bytes = P256_CODEC.to_vec();
    bytes.extend_from_slice(point.as_bytes());
    format!("{PREFIX}{}", bs58::encode(bytes).into_string())
}

/// Parse a P-256 `did:key`. Accepts the compressed form only, as did:key
/// requires, so each key has one string.
pub fn parse_p256(did: &str) -> Result<PublicKey, DidKeyError> {
    let body = did.strip_prefix(PREFIX).ok_or(DidKeyError::Malformed)?;
    let bytes = bs58::decode(body)
        .into_vec()
        .map_err(|_| DidKeyError::Malformed)?;
    let key = bytes
        .strip_prefix(&P256_CODEC)
        .ok_or(DidKeyError::NotP256)?;
    if key.len() != 33 {
        return Err(DidKeyError::InvalidKey);
    }
    PublicKey::from_sec1_bytes(key).map_err(|_| DidKeyError::InvalidKey)
}

/// Whether a string is a valid P-256 `did:key`.
pub fn is_p256(did: &str) -> bool {
    parse_p256(did).is_ok()
}

const K256_CODEC: [u8; 2] = [0xe7, 0x01];

/// An atproto signing key: P-256 (`ES256`) or secp256k1 (`ES256K`), as an
/// account's `#atproto` key may be either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyKey {
    P256(PublicKey),
    K256(k256::PublicKey),
}

impl AnyKey {
    /// The JWT `alg` this key signs with.
    pub fn jwt_alg(&self) -> &'static str {
        match self {
            AnyKey::P256(_) => "ES256",
            AnyKey::K256(_) => "ES256K",
        }
    }

    /// Verify a compact 64-byte ECDSA signature over SHA-256 of `msg`.
    /// High-S signatures are refused, as atproto requires.
    pub fn verify_low_s(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != 64 {
            return false;
        }
        match self {
            AnyKey::P256(pk) => {
                use p256::ecdsa::signature::Verifier;
                p256::ecdsa::Signature::from_slice(sig).is_ok_and(|sig| {
                    sig.normalize_s().is_none()
                        && p256::ecdsa::VerifyingKey::from(pk)
                            .verify(msg, &sig)
                            .is_ok()
                })
            }
            AnyKey::K256(pk) => {
                use k256::ecdsa::signature::Verifier;
                k256::ecdsa::Signature::from_slice(sig).is_ok_and(|sig| {
                    sig.normalize_s().is_none()
                        && k256::ecdsa::VerifyingKey::from(pk)
                            .verify(msg, &sig)
                            .is_ok()
                })
            }
        }
    }

    /// Verify a compact 64-byte ECDSA signature over SHA-256 of `msg`,
    /// accepting high-S as well as low-S, as standard JOSE does.
    pub fn verify_any_s(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != 64 {
            return false;
        }
        // (r, s) and (r, n - s) are both valid; check the low-S form.
        match self {
            AnyKey::P256(pk) => {
                use p256::ecdsa::signature::Verifier;
                p256::ecdsa::Signature::from_slice(sig).is_ok_and(|sig| {
                    let sig = sig.normalize_s().unwrap_or(sig);
                    p256::ecdsa::VerifyingKey::from(pk)
                        .verify(msg, &sig)
                        .is_ok()
                })
            }
            AnyKey::K256(pk) => {
                use k256::ecdsa::signature::Verifier;
                k256::ecdsa::Signature::from_slice(sig).is_ok_and(|sig| {
                    let sig = sig.normalize_s().unwrap_or(sig);
                    k256::ecdsa::VerifyingKey::from(pk)
                        .verify(msg, &sig)
                        .is_ok()
                })
            }
        }
    }
}

/// Parse a P-256 or secp256k1 `did:key`.
pub fn parse_any(did: &str) -> Result<AnyKey, DidKeyError> {
    let body = did.strip_prefix(PREFIX).ok_or(DidKeyError::Malformed)?;
    let bytes = bs58::decode(body)
        .into_vec()
        .map_err(|_| DidKeyError::Malformed)?;
    if let Some(key) = bytes.strip_prefix(&K256_CODEC) {
        if key.len() != 33 {
            return Err(DidKeyError::InvalidKey);
        }
        return k256::PublicKey::from_sec1_bytes(key)
            .map(AnyKey::K256)
            .map_err(|_| DidKeyError::InvalidKey);
    }
    parse_p256(did).map(AnyKey::P256)
}

/// Format a secp256k1 public key as a `did:key`, compressed.
pub fn format_k256(key: &k256::PublicKey) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;
    let point = key.to_encoded_point(true);
    let mut bytes = K256_CODEC.to_vec();
    bytes.extend_from_slice(point.as_bytes());
    format!("{PREFIX}{}", bs58::encode(bytes).into_string())
}

/// The uncompressed SEC1 encoding (`04 || x || y`), as HPKE uses.
pub fn uncompressed(key: &PublicKey) -> [u8; 65] {
    let point = key.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(point.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn round_trips_and_uses_dna_prefix() {
        // pkRm from the CFRG export-only DHKEM(P-256) vector.
        let pk = PublicKey::from_sec1_bytes(&hex(
            "046c6bb9e1976402c692fef72552f4aaeedd83a5e5079de3d7ae732da0f397b15921fb9c52c9866affc8e29c0271a35937023a9245982ec18bab1eb157cf16fc33",
        ))
        .unwrap();
        let did = format_p256(&pk);
        // Compressed P-256 did:keys all start `did:key:zDna`.
        assert!(did.starts_with("did:key:zDna"), "{did}");
        assert_eq!(parse_p256(&did).unwrap(), pk);
        assert!(is_p256(&did));
        assert_eq!(uncompressed(&pk).to_vec(), hex("046c6bb9e1976402c692fef72552f4aaeedd83a5e5079de3d7ae732da0f397b15921fb9c52c9866affc8e29c0271a35937023a9245982ec18bab1eb157cf16fc33"));
    }

    #[test]
    fn any_key_handles_both_curves() {
        let k = parse_any("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").unwrap();
        assert_eq!(k.jwt_alg(), "ES256K");
        let AnyKey::K256(pk) = k else { panic!() };
        assert_eq!(
            format_k256(&pk),
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
        );
        let p = parse_any("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169").unwrap();
        assert_eq!(p.jwt_alg(), "ES256");
        assert!(parse_any("did:key:zDnaExample").is_err());
    }

    #[test]
    fn known_p256_did_key() {
        // From the did:key method's P-256 test vectors.
        let did = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
        let pk = parse_p256(did).unwrap();
        assert_eq!(format_p256(&pk), did);
    }

    #[test]
    fn rejects_other_keys_and_garbage() {
        // A secp256k1 did:key (multicodec e7 01).
        assert_eq!(
            parse_p256("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"),
            Err(DidKeyError::NotP256)
        );
        assert_eq!(
            parse_p256("did:key:zDnaExample"),
            Err(DidKeyError::Malformed)
        );
        assert_eq!(
            parse_p256("did:web:example.com"),
            Err(DidKeyError::Malformed)
        );
        assert_eq!(parse_p256("did:key:z0OIl"), Err(DidKeyError::Malformed));
        // Right codec, wrong length.
        let short = format!(
            "{PREFIX}{}",
            bs58::encode([0x80, 0x24, 0x02, 0x01]).into_string()
        );
        assert_eq!(parse_p256(&short), Err(DidKeyError::InvalidKey));
        // Right codec and length, not on the curve.
        let mut bad = vec![0x80, 0x24, 0x02];
        bad.extend_from_slice(&[0xff; 32]);
        let bad = format!("{PREFIX}{}", bs58::encode(bad).into_string());
        assert_eq!(parse_p256(&bad), Err(DidKeyError::InvalidKey));
    }
}
