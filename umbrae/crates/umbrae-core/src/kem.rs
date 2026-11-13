//! The per-request shared secret behind commit and record MACs (spec:
//! "Shared secret", and the appendix "Shared secret without HPKE").
//!
//! HPKE secret export (RFC 9180 §6.2) in base mode with DHKEM(P-256,
//! HKDF-SHA256), HKDF-SHA256 and the Export-only AEAD, `info =
//! "atproto-mac"`, an empty exporter context and `L = 32`. Rather than
//! depend on an HPKE library, this spells out the ECDH and HKDF steps for
//! that one ciphersuite.
//!
//! The syncer encapsulates against the author's `#atproto_kem` key and
//! sends its ephemeral public key (HPKE's `enc`) as a `did:key`; the repo
//! host decapsulates with the author's private key. Use a fresh
//! encapsulation for every request, retries and pages included.

use crate::didkey::{self, DidKeyError};
use hkdf::Hkdf;
use p256::{ecdh, PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::Sha256;
use std::fmt;

/// The fixed `info` that ties the secret to this protocol.
pub const INFO: &[u8] = b"atproto-mac";

const KEM_ID: &[u8] = b"KEM\x00\x10";
const SUITE_ID: &[u8] = b"HPKE\x00\x10\x00\x01\xff\xff";
const VERSION: &[u8] = b"HPKE-v1";

/// A MAC key share and the secret it derives.
#[derive(Clone, PartialEq, Eq)]
pub struct Encapsulation {
    /// The syncer's ephemeral public key as a `did:key`: the MAC request's
    /// `keyid`.
    pub key_share: String,
    pub shared_secret: [u8; 32],
}

impl fmt::Debug for Encapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encapsulation")
            .field("key_share", &self.key_share)
            .field("shared_secret", &"…")
            .finish()
    }
}

/// Why a shared secret can't be derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemError(pub DidKeyError);

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid KEM key: {}", self.0)
    }
}

impl std::error::Error for KemError {}

/// Syncer side: a fresh ephemeral key and the secret it shares with the
/// author's KEM key (a P-256 `did:key`).
pub fn encapsulate(author_kem_key: &str) -> Result<Encapsulation, KemError> {
    let author = didkey::parse_p256(author_kem_key).map_err(KemError)?;
    let ephemeral = SecretKey::random(&mut OsRng);
    Ok(encapsulate_with(&ephemeral, &author, INFO))
}

/// Repo host side: the secret for a syncer's key share, under the author's
/// KEM private key.
pub fn decapsulate(author_kem: &SecretKey, key_share: &str) -> Result<[u8; 32], KemError> {
    let enc = didkey::parse_p256(key_share).map_err(KemError)?;
    Ok(decapsulate_with(author_kem, &enc, INFO))
}

fn encapsulate_with(ephemeral: &SecretKey, author: &PublicKey, info: &[u8]) -> Encapsulation {
    let enc = ephemeral.public_key();
    let dh = ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), author.as_affine());
    Encapsulation {
        key_share: didkey::format_p256(&enc),
        shared_secret: derive(dh.raw_secret_bytes(), &enc, author, info),
    }
}

fn decapsulate_with(author: &SecretKey, enc: &PublicKey, info: &[u8]) -> [u8; 32] {
    let dh = ecdh::diffie_hellman(author.to_nonzero_scalar(), enc.as_affine());
    derive(dh.raw_secret_bytes(), enc, &author.public_key(), info)
}

fn labeled_extract(id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let labeled = [VERSION, id, label, ikm].concat();
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

fn labeled_expand(id: &[u8], prk: &[u8; 32], label: &[u8], info: &[u8]) -> [u8; 32] {
    let labeled = [&32u16.to_be_bytes()[..], VERSION, id, label, info].concat();
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::from_prk(prk)
        .expect("a 32-byte PRK is valid")
        .expand(&labeled, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// The KEM's shared secret, from the ECDH result and both public keys.
fn kem_secret(dh: &[u8], enc: &PublicKey, author: &PublicKey) -> [u8; 32] {
    let eae_prk = labeled_extract(KEM_ID, b"", b"eae_prk", dh);
    let context = [didkey::uncompressed(enc), didkey::uncompressed(author)].concat();
    labeled_expand(KEM_ID, &eae_prk, b"shared_secret", &context)
}

/// The base-mode key schedule's exporter secret.
fn exporter_secret(kem_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let psk_id_hash = labeled_extract(SUITE_ID, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(SUITE_ID, b"", b"info_hash", info);
    let context = [&[0x00][..], &psk_id_hash[..], &info_hash[..]].concat();
    let secret = labeled_extract(SUITE_ID, kem_secret, b"secret", b"");
    labeled_expand(SUITE_ID, &secret, b"exp", &context)
}

fn derive(dh: &[u8], enc: &PublicKey, author: &PublicKey, info: &[u8]) -> [u8; 32] {
    let exp = exporter_secret(&kem_secret(dh, enc, author), info);
    // Export with an empty exporter context.
    labeled_expand(SUITE_ID, &exp, b"sec", b"")
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

    // The export-only DHKEM(P-256, HKDF-SHA256) base-mode entry of the CFRG
    // HPKE test vectors (github.com/cfrg/draft-irtf-cfrg-hpke).
    const ENC: &str = "04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d";
    const SK_RM: &str = "62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346";
    const PK_RM: &str = "046c6bb9e1976402c692fef72552f4aaeedd83a5e5079de3d7ae732da0f397b15921fb9c52c9866affc8e29c0271a35937023a9245982ec18bab1eb157cf16fc33";
    const CFRG_INFO: &[u8] = b"Ode on a Grecian Urn";

    fn author() -> SecretKey {
        SecretKey::from_slice(&hex(SK_RM)).unwrap()
    }

    fn enc() -> PublicKey {
        PublicKey::from_sec1_bytes(&hex(ENC)).unwrap()
    }

    #[test]
    fn cfrg_vector_steps() {
        let author = author();
        assert_eq!(
            didkey::uncompressed(&author.public_key()).to_vec(),
            hex(PK_RM)
        );
        let dh = ecdh::diffie_hellman(author.to_nonzero_scalar(), enc().as_affine());
        let ks = kem_secret(dh.raw_secret_bytes(), &enc(), &author.public_key());
        assert_eq!(
            ks.to_vec(),
            hex("7e5b6dd51bca56d4f30c95ff658af26c08eb0c073aa7180686cc4dbeabcb34f1")
        );
        assert_eq!(
            exporter_secret(&ks, CFRG_INFO).to_vec(),
            hex("7c0347d69a219f33301056411e78672ae2d78698d10ee067f883ba266ef586a1")
        );
        // Export with an empty context, L = 32.
        assert_eq!(
            decapsulate_with(&author, &enc(), CFRG_INFO).to_vec(),
            hex("8cf837d5bf1994f0fac3ee1faa671d07e9a38b7f6153bdbb8a66b90159ef7d13")
        );
    }

    #[test]
    fn atproto_mac_vector() {
        // The reference implementation's vector: the same keys with
        // info "atproto-mac", computed with Go's crypto/hpke.
        let key_share = didkey::format_p256(&enc());
        assert_eq!(
            decapsulate(&author(), &key_share).unwrap().to_vec(),
            hex("2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d")
        );
    }

    #[test]
    fn both_sides_agree_with_fresh_shares() {
        let author = SecretKey::random(&mut OsRng);
        let kem = didkey::format_p256(&author.public_key());
        let a = encapsulate(&kem).unwrap();
        let b = encapsulate(&kem).unwrap();
        assert_ne!(a.key_share, b.key_share);
        assert_ne!(a.shared_secret, b.shared_secret);
        assert_eq!(decapsulate(&author, &a.key_share).unwrap(), a.shared_secret);
        assert_eq!(decapsulate(&author, &b.key_share).unwrap(), b.shared_secret);
        let other = SecretKey::random(&mut OsRng);
        assert_ne!(decapsulate(&other, &a.key_share).unwrap(), a.shared_secret);
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(encapsulate("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").is_err());
        assert!(decapsulate(&author(), "did:key:nope").is_err());
    }

    #[test]
    fn debug_hides_the_secret() {
        let e = encapsulate(&didkey::format_p256(&author().public_key())).unwrap();
        assert!(!format!("{e:?}").contains(&format!("{:?}", e.shared_secret)));
    }
}
