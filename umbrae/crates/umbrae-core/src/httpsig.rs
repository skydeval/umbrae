//! The RFC 9421 HTTP Message Signatures subset spaces use (spec:
//! "Presenting a space credential", "Requesting a MAC").
//!
//! Two uses share the machinery here:
//! - a **credential use**: an `ecdsa-p256-sha256` signature by the key a
//!   space credential is bound to (`cnf.kid`), covering exactly
//!   `("authorization" "atproto-space-audience")`, tag
//!   `atproto-space-credential`;
//! - a **MAC** ([`crate::mac`]): `hmac-sha256` over one structured header.
//!
//! A signature is found by its `tag`, never its label, since intermediaries
//! may relabel. Exactly one signature may carry the tag; it must cover
//! exactly the expected components, in order; an `alg` or `keyid`
//! parameter, if present, must match. Other parameters are covered but not
//! interpreted.
//!
//! Callers pass header field values as received, with repeated field lines
//! already combined as HTTP allows. For `Authorization` and
//! `Atproto-Space-Audience`, which may not repeat, pass `None` when the
//! field appeared more than once.

use crate::didkey;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sfv::{
    BareItem, DictSerializer, Dictionary, InnerList, ItemSerializer, KeyRef, ListEntry, Parser,
    StringRef,
};
use std::fmt;

/// The credential-use signature's tag.
pub const CREDENTIAL_TAG: &str = "atproto-space-credential";
/// The credential-use signature's algorithm.
pub const CREDENTIAL_ALG: &str = "ecdsa-p256-sha256";
const CREDENTIAL_LABEL: &str = "sig";
/// The audience header a credential use covers.
pub const AUDIENCE_HEADER: &str = "atproto-space-audience";
const CREDENTIAL_COMPONENTS: &[Component] = &[
    Component {
        name: "authorization",
        sf: false,
    },
    Component {
        name: AUDIENCE_HEADER,
        sf: false,
    },
];

/// Why a signature or MAC is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// A required field is absent, empty or repeated.
    MissingField(&'static str),
    /// `Signature-Input`, `Signature`, `Accept-Signature` or a covered
    /// header isn't a valid Structured Field Dictionary.
    Malformed,
    /// More than one signature (or request) carries the tag.
    MultipleTagged,
    /// No well-formed signature carries the tag.
    MissingTagged,
    /// The covered components aren't exactly the expected ones, in order.
    Components,
    /// An `alg` parameter names another algorithm.
    Algorithm,
    /// A `keyid` parameter names another key.
    KeyIdMismatch,
    /// A MAC request asks for a parameter the host doesn't fulfil.
    UnsupportedParameter(String),
    /// The key isn't a P-256 `did:key`.
    InvalidKey,
    /// The signature or MAC doesn't verify.
    Invalid,
    /// The covered header describes another commit or record.
    CoveredMismatch,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::MissingField(n) => write!(f, "missing or malformed \"{n}\" field"),
            SignatureError::Malformed => f.write_str("malformed signature headers"),
            SignatureError::MultipleTagged => f.write_str("more than one signature with the tag"),
            SignatureError::MissingTagged => {
                f.write_str("missing or malformed signature with the tag")
            }
            SignatureError::Components => {
                f.write_str("signature must cover exactly the expected components, in order")
            }
            SignatureError::Algorithm => f.write_str("signature algorithm not allowed"),
            SignatureError::KeyIdMismatch => {
                f.write_str("signature keyid does not match the expected key")
            }
            SignatureError::UnsupportedParameter(p) => {
                write!(f, "unsupported signature parameter: {p}")
            }
            SignatureError::InvalidKey => f.write_str("key must be a P-256 did:key"),
            SignatureError::Invalid => f.write_str("signature does not verify"),
            SignatureError::CoveredMismatch => {
                f.write_str("covered header does not match the response")
            }
        }
    }
}

impl std::error::Error for SignatureError {}

/// A covered component: a header name, optionally flagged `sf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Component {
    pub name: &'static str,
    pub sf: bool,
}

/// What a verifier requires of the one signature it looks for.
#[derive(Debug, Clone, Copy)]
pub struct Requirements<'a> {
    pub tag: &'a str,
    pub components: &'a [Component],
    pub alg: &'a str,
    /// The key a `keyid` parameter must name, if present.
    pub key_id: &'a str,
}

/// The one signature that met the requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundSignature {
    /// Its parameters, serialized as they go into the signature base.
    pub signature_params: String,
    pub signature: Vec<u8>,
}

pub(crate) fn key(name: &str) -> &KeyRef {
    KeyRef::from_str(name).expect("static key is valid")
}

pub(crate) fn sf_string(s: &str) -> &StringRef {
    StringRef::from_str(s).expect("value is a valid sf-string")
}

pub(crate) fn parse_dict(value: &str) -> Result<Dictionary, SignatureError> {
    Parser::new(value)
        .parse::<Dictionary>()
        .map_err(|_| SignatureError::Malformed)
}

/// Re-serialize a parsed dictionary: the normalized form an `sf`-flagged
/// component is signed under.
pub(crate) fn serialize_dict(dict: &Dictionary) -> Result<String, SignatureError> {
    let mut ser = DictSerializer::new();
    ser.members(dict);
    ser.finish().ok_or(SignatureError::Malformed)
}

/// Serialize an inner list on its own, e.g. `("a" "b");tag="t"`.
pub(crate) fn serialize_inner_list(list: &InnerList) -> String {
    let mut ser = DictSerializer::new();
    {
        let mut il = ser.inner_list(key("x"));
        il.items(&list.items);
        let _ = il.finish().parameters(&list.params);
    }
    let s = ser.finish().expect("one member");
    s["x=".len()..].to_owned()
}

/// The component identifier, e.g. `"atproto-space-commit";sf`.
fn component_id(c: &Component) -> String {
    let ser = ItemSerializer::new().bare_item(sf_string(c.name));
    if c.sf {
        ser.parameter(key("sf"), true).finish()
    } else {
        ser.finish()
    }
}

/// An inner list of components with the given parameters, serialized.
pub(crate) fn signature_params(components: &[Component], params: &[(&str, &str)]) -> String {
    let mut ser = DictSerializer::new();
    {
        let mut il = ser.inner_list(key("x"));
        for c in components {
            let p = il.bare_item(sf_string(c.name));
            if c.sf {
                let _ = p.parameter(key("sf"), true);
            }
        }
        let mut p = il.finish();
        for (k, v) in params {
            p = p.parameter(key(k), sf_string(v));
        }
    }
    let s = ser.finish().expect("one member");
    s["x=".len()..].to_owned()
}

/// The signature base (RFC 9421 §2.5) for `components`, whose values are
/// given in order, under the serialized parameters.
pub(crate) fn signature_base(components: &[Component], values: &[&str], params: &str) -> Vec<u8> {
    let mut base = String::new();
    for (c, v) in components.iter().zip(values) {
        base.push_str(&component_id(c));
        base.push_str(": ");
        base.push_str(v.trim());
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(params);
    base.into_bytes()
}

/// The members of a `Signature-Input` or `Accept-Signature` dictionary that
/// carry `tag`, as `(label, inner list)`.
pub(crate) fn members_with_tag<'a>(
    dict: &'a Dictionary,
    tag: &str,
) -> Vec<(&'a str, &'a InnerList)> {
    dict.iter()
        .filter_map(|(label, member)| match member {
            ListEntry::InnerList(il)
                if il
                    .params
                    .get("tag")
                    .and_then(BareItem::as_string)
                    .map(|s| s.as_str())
                    == Some(tag) =>
            {
                Some((label.as_str(), il))
            }
            _ => None,
        })
        .collect()
}

/// Whether an inner list covers exactly `expected`, in order, with no
/// component parameters beyond `sf` where expected.
pub(crate) fn covers_exactly(list: &InnerList, expected: &[Component]) -> bool {
    list.items.len() == expected.len()
        && list.items.iter().zip(expected).all(|(item, c)| {
            let name_ok = item.bare_item.as_string().map(|s| s.as_str()) == Some(c.name);
            let params_ok = if c.sf {
                item.params.len() == 1 && item.params.get("sf") == Some(&BareItem::Boolean(true))
            } else {
                item.params.is_empty()
            };
            name_ok && params_ok
        })
}

fn string_param<'a>(list: &'a InnerList, name: &str) -> Option<Option<&'a str>> {
    list.params
        .get(name)
        .map(|v| v.as_string().map(|s| s.as_str()))
}

/// Find the one signature tagged `req.tag` and check it meets `req`.
pub fn find_signature(
    signature_input: Option<&str>,
    signature: Option<&str>,
    req: &Requirements<'_>,
) -> Result<FoundSignature, SignatureError> {
    let (Some(input), Some(sig)) = (signature_input, signature) else {
        return Err(SignatureError::Malformed);
    };
    let inputs = parse_dict(input)?;
    let sigs = parse_dict(sig)?;

    let tagged = members_with_tag(&inputs, req.tag);
    if tagged.len() > 1 {
        return Err(SignatureError::MultipleTagged);
    }
    let Some(&(label, list)) = tagged.first() else {
        return Err(SignatureError::MissingTagged);
    };
    let signature = match sigs.get(label) {
        Some(ListEntry::Item(item)) if item.params.is_empty() => item
            .bare_item
            .as_byte_sequence()
            .map(<[u8]>::to_vec)
            .ok_or(SignatureError::MissingTagged)?,
        _ => return Err(SignatureError::MissingTagged),
    };
    if !covers_exactly(list, req.components) {
        return Err(SignatureError::Components);
    }
    if let Some(alg) = string_param(list, "alg") {
        if alg != Some(req.alg) {
            return Err(SignatureError::Algorithm);
        }
    }
    if let Some(kid) = string_param(list, "keyid") {
        if kid != Some(req.key_id) {
            return Err(SignatureError::KeyIdMismatch);
        }
    }
    Ok(FoundSignature {
        signature_params: serialize_inner_list(list),
        signature,
    })
}

/// The `Signature-Input` and `Signature` field values a signer adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFields {
    pub signature_input: String,
    pub signature: String,
}

pub(crate) fn signature_field(label: &str, bytes: &[u8]) -> String {
    let mut ser = DictSerializer::new();
    let _ = ser.bare_item(key(label), bytes);
    ser.finish().expect("one member")
}

/// Sign a credential use: the `Authorization` value (the full
/// `Atproto-Space-Credential …` string) and the audience DID, with the key
/// the credential is bound to.
pub fn sign_credential_use(
    authorization: &str,
    audience: &str,
    key: &SigningKey,
) -> SignatureFields {
    let params = signature_params(CREDENTIAL_COMPONENTS, &[("tag", CREDENTIAL_TAG)]);
    let base = signature_base(CREDENTIAL_COMPONENTS, &[authorization, audience], &params);
    let sig: Signature = key.sign(&base);
    SignatureFields {
        signature_input: format!("{CREDENTIAL_LABEL}={params}"),
        signature: signature_field(CREDENTIAL_LABEL, &sig.to_bytes()),
    }
}

/// The header fields of a request presenting a space credential.
#[derive(Debug, Clone, Copy, Default)]
pub struct CredentialFields<'a> {
    pub authorization: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub signature_input: Option<&'a str>,
    pub signature: Option<&'a str>,
}

/// Verify a credential use against the credential's `cnf.kid`. Accepts
/// high-S as well as low-S signatures, as the spec requires. Checking the
/// credential itself, and that the audience is the one this request is
/// for, are separate steps.
pub fn verify_credential_use(
    fields: &CredentialFields<'_>,
    key_id: &str,
) -> Result<(), SignatureError> {
    let authorization = fields
        .authorization
        .filter(|s| !s.is_empty())
        .ok_or(SignatureError::MissingField("authorization"))?;
    let audience = fields
        .audience
        .filter(|s| !s.is_empty())
        .ok_or(SignatureError::MissingField(AUDIENCE_HEADER))?;
    let found = find_signature(
        fields.signature_input,
        fields.signature,
        &Requirements {
            tag: CREDENTIAL_TAG,
            components: CREDENTIAL_COMPONENTS,
            alg: CREDENTIAL_ALG,
            key_id,
        },
    )?;
    let public = didkey::parse_p256(key_id).map_err(|_| SignatureError::InvalidKey)?;
    let base = signature_base(
        CREDENTIAL_COMPONENTS,
        &[authorization, audience],
        &found.signature_params,
    );
    // Compact r || s only; a DER signature is the wrong length.
    if found.signature.len() != 64 {
        return Err(SignatureError::Invalid);
    }
    let sig = Signature::from_slice(&found.signature).map_err(|_| SignatureError::Invalid)?;
    VerifyingKey::from(&public)
        .verify(&base, &sig)
        .map_err(|_| SignatureError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use rand_core::OsRng;

    const AUTHORIZATION: &str = "Atproto-Space-Credential credential";
    const AUDIENCE: &str = "did:example:repo";

    fn signer() -> (SigningKey, String) {
        let sk = SecretKey::random(&mut OsRng);
        let kid = didkey::format_p256(&sk.public_key());
        (SigningKey::from(sk), kid)
    }

    fn fields<'a>(s: &'a SignatureFields) -> CredentialFields<'a> {
        CredentialFields {
            authorization: Some(AUTHORIZATION),
            audience: Some(AUDIENCE),
            signature_input: Some(&s.signature_input),
            signature: Some(&s.signature),
        }
    }

    fn b64(bytes: &[u8]) -> String {
        signature_field("x", bytes)["x=:".len()..]
            .trim_end_matches(':')
            .to_owned()
    }

    #[test]
    fn signs_the_rfc9421_base() {
        let (key, kid) = signer();
        let s = sign_credential_use(AUTHORIZATION, AUDIENCE, &key);
        let input =
            "(\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\"";
        assert_eq!(s.signature_input, format!("sig={input}"));
        assert!(s.signature.starts_with("sig=:"));
        // Independently verify over the expected base.
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {input}"
        );
        let found = find_signature(
            Some(&s.signature_input),
            Some(&s.signature),
            &Requirements {
                tag: CREDENTIAL_TAG,
                components: CREDENTIAL_COMPONENTS,
                alg: CREDENTIAL_ALG,
                key_id: &kid,
            },
        )
        .unwrap();
        assert_eq!(found.signature.len(), 64);
        let sig = Signature::from_slice(&found.signature).unwrap();
        VerifyingKey::from(&key)
            .verify(base.as_bytes(), &sig)
            .unwrap();
        verify_credential_use(&fields(&s), &kid).unwrap();
    }

    #[test]
    fn accepts_high_s() {
        let (key, kid) = signer();
        let s = sign_credential_use(AUTHORIZATION, AUDIENCE, &key);
        let found = find_signature(
            Some(&s.signature_input),
            Some(&s.signature),
            &Requirements {
                tag: CREDENTIAL_TAG,
                components: CREDENTIAL_COMPONENTS,
                alg: CREDENTIAL_ALG,
                key_id: &kid,
            },
        )
        .unwrap();
        // s' = n - s, by big-endian subtraction.
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut sig = found.signature.clone();
        let s_bytes = &found.signature[32..];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = N[i] as i16 - s_bytes[i] as i16 - borrow;
            borrow = if d < 0 {
                d += 256;
                1
            } else {
                0
            };
            sig[32 + i] = d as u8;
        }
        // Of s and n - s, exactly one is high-S; both must verify.
        assert_ne!(sig, found.signature);
        verify_credential_use(&fields(&s), &kid).unwrap();
        let high = SignatureFields {
            signature_input: s.signature_input.clone(),
            signature: signature_field("sig", &sig),
        };
        verify_credential_use(&fields(&high), &kid).unwrap();
    }

    #[test]
    fn finds_by_tag_under_any_label_with_optional_params() {
        let (key, kid) = signer();
        let input = format!(
            "(\"authorization\" \"atproto-space-audience\");alg=\"ecdsa-p256-sha256\";created=1618884473;keyid=\"{kid}\";tag=\"atproto-space-credential\""
        );
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {input}"
        );
        let sig: Signature = key.sign(base.as_bytes());
        let si = format!("other=(\"authorization\");keyid=\"other\", custom={input}");
        let sg = format!("other=:YWJj:, custom=:{}:", b64(&sig.to_bytes()));
        let f = CredentialFields {
            authorization: Some(AUTHORIZATION),
            audience: Some(AUDIENCE),
            signature_input: Some(&si),
            signature: Some(&sg),
        };
        verify_credential_use(&f, &kid).unwrap();
    }

    #[test]
    fn rejects_changed_or_missing_fields() {
        let (key, kid) = signer();
        let s = sign_credential_use(AUTHORIZATION, AUDIENCE, &key);
        let mut f = fields(&s);
        f.authorization = Some("Atproto-Space-Credential other");
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::Invalid)
        );
        let mut f = fields(&s);
        f.audience = Some("did:example:other");
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::Invalid)
        );
        let mut f = fields(&s);
        f.authorization = None;
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::MissingField("authorization"))
        );
        let mut f = fields(&s);
        f.audience = Some("");
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::MissingField(AUDIENCE_HEADER))
        );
        let mut f = fields(&s);
        f.signature = None;
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::Malformed)
        );
    }

    #[test]
    fn rejects_wrong_tags_and_duplicates() {
        let (key, kid) = signer();
        let s = sign_credential_use(AUTHORIZATION, AUDIENCE, &key);
        for tag in ["", ";tag=\"other\""] {
            let si = s
                .signature_input
                .replace(";tag=\"atproto-space-credential\"", tag);
            let mut f = fields(&s);
            f.signature_input = Some(&si);
            assert_eq!(
                verify_credential_use(&f, &kid),
                Err(SignatureError::MissingTagged)
            );
        }
        let si = format!(
            "{}, {}",
            s.signature_input,
            s.signature_input.replacen("sig=", "other=", 1)
        );
        let sg = format!(
            "{}, {}",
            s.signature,
            s.signature.replacen("sig=", "other=", 1)
        );
        let f = CredentialFields {
            signature_input: Some(&si),
            signature: Some(&sg),
            ..fields(&s)
        };
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::MultipleTagged)
        );
    }

    #[test]
    fn rejects_other_component_lists() {
        let (key, kid) = signer();
        let s = sign_credential_use(AUTHORIZATION, AUDIENCE, &key);
        for components in [
            "(\"atproto-space-audience\")",
            "(\"atproto-space-audience\" \"authorization\")",
            "(\"authorization\" \"atproto-space-audience\" \"content-type\")",
            "(\"authorization\" \"authorization\" \"atproto-space-audience\")",
            "(\"authorization\";sf \"atproto-space-audience\")",
        ] {
            let si = format!("sig={components};tag=\"atproto-space-credential\"");
            let mut f = fields(&s);
            f.signature_input = Some(&si);
            assert_eq!(
                verify_credential_use(&f, &kid),
                Err(SignatureError::Components),
                "{components}"
            );
        }
    }

    #[test]
    fn rejects_params_keys_and_encodings() {
        let (key, kid) = signer();
        let s = sign_credential_use(AUTHORIZATION, AUDIENCE, &key);
        // An added alg changes the signed parameters.
        let si = format!("{};alg=\"ecdsa-p256-sha256\"", s.signature_input);
        let mut f = fields(&s);
        f.signature_input = Some(&si);
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::Invalid)
        );
        let si = format!("{};alg=\"ecdsa-p384-sha384\"", s.signature_input);
        f.signature_input = Some(&si);
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::Algorithm)
        );
        let (_, other) = signer();
        let si = format!("{};keyid=\"{other}\"", s.signature_input);
        f.signature_input = Some(&si);
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::KeyIdMismatch)
        );
        // Another signer's key.
        assert_eq!(
            verify_credential_use(&fields(&s), &other),
            Err(SignatureError::Invalid)
        );
        // Not a P-256 did:key.
        assert_eq!(
            verify_credential_use(
                &fields(&s),
                "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
            ),
            Err(SignatureError::InvalidKey)
        );
        // Malformed input and signatures.
        let mut f = fields(&s);
        f.signature_input = Some("sig=not-a-list");
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::MissingTagged)
        );
        for bad in ["sig=not-a-byte-sequence", "sig=:YWJj:", "sig=:!!!:"] {
            let mut f = fields(&s);
            f.signature = Some(bad);
            assert!(verify_credential_use(&f, &kid).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_der_signature() {
        let (key, kid) = signer();
        let s = sign_credential_use(AUTHORIZATION, AUDIENCE, &key);
        let found = find_signature(
            Some(&s.signature_input),
            Some(&s.signature),
            &Requirements {
                tag: CREDENTIAL_TAG,
                components: CREDENTIAL_COMPONENTS,
                alg: CREDENTIAL_ALG,
                key_id: &kid,
            },
        )
        .unwrap();
        // SEQUENCE { INTEGER r, INTEGER s }, each with a leading zero if
        // its top bit is set.
        let mut ints = Vec::new();
        for half in [&found.signature[..32], &found.signature[32..]] {
            let mut v = half.to_vec();
            if v[0] & 0x80 != 0 {
                v.insert(0, 0);
            }
            ints.push(0x02);
            ints.push(v.len() as u8);
            ints.extend_from_slice(&v);
        }
        let mut der = vec![0x30, ints.len() as u8];
        der.extend_from_slice(&ints);
        let sg = signature_field("sig", &der);
        let mut f = fields(&s);
        f.signature = Some(&sg);
        assert_eq!(
            verify_credential_use(&f, &kid),
            Err(SignatureError::Invalid)
        );
    }
}
