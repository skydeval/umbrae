//! The three JWT classes of spaces access control (spec: "Delegation
//! token", "Client attestation", "Space credential").
//!
//! | Class | `typ` | Signed by | `aud` | Other |
//! |---|---|---|---|---|
//! | delegation token | `atproto-space-delegation+jwt` | the user's `#atproto` key | `{authority}#atproto_pds` | `sub` = space, single use, 60 s |
//! | client attestation | `atproto-client-attestation+jwt` | a key in the client's JWKS | `{authority}#atproto_pds` | `iss` = `sub` = client_id, single use |
//! | space credential | `atproto-space-credential+jwt` | the authority's `#atproto` key | none | `sub` = space, `cnf.kid`, ≤ 60 min |
//!
//! Delegation tokens and credentials carry `kid: "#atproto"`. Each class
//! has its own `typ`, so none can stand in for another, or for a service
//! auth token.
//!
//! Verification is split so the caller owns I/O: [`parse`] checks
//! structure, [`check_claims`] checks time and binding, and
//! [`verify_signature`] checks the signature against a key the caller
//! resolved. [`verify`] runs all three and retries once with a freshly
//! resolved key, for rotation. Single-use tokens' `jti`s must be
//! remembered by the caller until they expire.

use crate::didkey::{self, AnyKey};
use crate::uri::{is_valid_did, SpaceRef};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value as Json};
use std::fmt;

pub const DELEGATION_TYP: &str = "atproto-space-delegation+jwt";
pub const CREDENTIAL_TYP: &str = "atproto-space-credential+jwt";
pub const CLIENT_ATTESTATION_TYP: &str = "atproto-client-attestation+jwt";

/// Allowed clock skew, in seconds.
pub const CLOCK_SKEW_SEC: i64 = 5;
/// The longest a space credential may live.
pub const CREDENTIAL_MAX_AGE_SEC: i64 = 3600;
pub const DELEGATION_TTL_SEC: i64 = 60;
pub const CREDENTIAL_TTL_SEC: i64 = 600;
pub const CLIENT_ATTESTATION_TTL_SEC: i64 = 60;

const ATPROTO_KID: &str = "#atproto";

/// The token class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Delegation,
    Credential,
    ClientAttestation,
}

impl TokenKind {
    pub fn typ(self) -> &'static str {
        match self {
            TokenKind::Delegation => DELEGATION_TYP,
            TokenKind::Credential => CREDENTIAL_TYP,
            TokenKind::ClientAttestation => CLIENT_ATTESTATION_TYP,
        }
    }

    fn kid(self) -> Option<&'static str> {
        match self {
            TokenKind::ClientAttestation => None,
            _ => Some(ATPROTO_KID),
        }
    }

    fn requires_aud(self) -> bool {
        !matches!(self, TokenKind::Credential)
    }

    /// Whether each `jti` may be used once only.
    pub fn single_use(self) -> bool {
        !matches!(self, TokenKind::Credential)
    }
}

/// The audience a delegation token or client attestation names: the space
/// host, as the authority's `#atproto_pds` service.
pub fn space_host_aud(authority: &str) -> String {
    format!("{authority}#atproto_pds")
}

/// Why a token is rejected. The variants mirror the XRPC error names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    BadJwt(&'static str),
    BadJwtType,
    BadJwtIss,
    BadJwtSub,
    BadJwtAudience,
    BadJwtCnf,
    JwtExpired,
    BadJwtSignature,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::BadJwt(why) => write!(f, "invalid token: {why}"),
            TokenError::BadJwtType => f.write_str("wrong token type"),
            TokenError::BadJwtIss => f.write_str("missing or invalid token \"iss\""),
            TokenError::BadJwtSub => f.write_str("missing or mismatched token \"sub\""),
            TokenError::BadJwtAudience => f.write_str("missing or mismatched token \"aud\""),
            TokenError::BadJwtCnf => f.write_str("missing or invalid token \"cnf.kid\""),
            TokenError::JwtExpired => f.write_str("token expired"),
            TokenError::BadJwtSignature => f.write_str("invalid token signature"),
        }
    }
}

impl std::error::Error for TokenError {}

/// A token's header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub alg: String,
    pub typ: String,
    pub kid: Option<String>,
}

/// A token's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Option<String>,
    pub iat: Option<i64>,
    pub exp: i64,
    pub jti: String,
    /// `cnf.kid`: the key a credential is bound to.
    pub cnf_kid: Option<String>,
}

/// A structurally valid token, not yet checked against time, binding or
/// signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub kind: TokenKind,
    pub header: Header,
    pub claims: Claims,
    signing_input: String,
    signature: Vec<u8>,
}

fn decode_part(part: &str) -> Result<Map<String, Json>, TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| TokenError::BadJwt("part is not base64url"))?;
    match serde_json::from_slice(&bytes) {
        Ok(Json::Object(m)) => Ok(m),
        _ => Err(TokenError::BadJwt("part is not a JSON object")),
    }
}

fn str_field(m: &Map<String, Json>, k: &str) -> Option<String> {
    m.get(k)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn num_field(m: &Map<String, Json>, k: &str) -> Option<i64> {
    let n = m.get(k)?.as_f64()?;
    n.is_finite().then(|| n.floor() as i64)
}

/// Check a token's structure for its class. No signature check.
pub fn parse(kind: TokenKind, jwt: &str) -> Result<Parsed, TokenError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    let &[h, p, s] = &parts[..] else {
        return Err(TokenError::BadJwt("expected 3 parts"));
    };
    let header = decode_part(h)?;
    let payload = decode_part(p)?;

    if header.get("typ").and_then(Json::as_str) != Some(kind.typ()) {
        return Err(TokenError::BadJwtType);
    }
    let alg = str_field(&header, "alg").ok_or(TokenError::BadJwt("missing \"alg\""))?;
    let kid = str_field(&header, "kid");
    if let Some(expected) = kind.kid() {
        if kid.as_deref() != Some(expected) {
            return Err(TokenError::BadJwt("wrong \"kid\""));
        }
    }

    let iss = str_field(&payload, "iss").ok_or(TokenError::BadJwtIss)?;
    let sub = str_field(&payload, "sub").ok_or(TokenError::BadJwtSub)?;
    let exp = num_field(&payload, "exp").ok_or(TokenError::BadJwt("missing \"exp\""))?;
    let iat = num_field(&payload, "iat");
    let aud = str_field(&payload, "aud");
    if kind.requires_aud() && aud.is_none() {
        return Err(TokenError::BadJwtAudience);
    }
    let cnf_kid = payload
        .get("cnf")
        .and_then(|c| c.get("kid"))
        .and_then(Json::as_str)
        .map(str::to_owned);
    let jti = str_field(&payload, "jti").ok_or(TokenError::BadJwt("missing \"jti\""))?;

    match kind {
        TokenKind::Delegation | TokenKind::Credential => {
            if !is_valid_did(&iss) {
                return Err(TokenError::BadJwtIss);
            }
            let space = SpaceRef::parse(&sub).map_err(|_| TokenError::BadJwtSub)?;
            // Bind the token to the space it names, as the reference host
            // does: a credential is issued by that space's authority, and a
            // delegation is addressed to that authority's space host.
            if kind == TokenKind::Credential && iss != space.authority() {
                return Err(TokenError::BadJwtIss);
            }
            if kind == TokenKind::Delegation
                && aud.as_deref() != Some(space_host_aud(space.authority()).as_str())
            {
                return Err(TokenError::BadJwtAudience);
            }
        }
        TokenKind::ClientAttestation => {
            if iss != sub {
                return Err(TokenError::BadJwtIss);
            }
        }
    }
    if kind == TokenKind::Credential {
        // Bound to a P-256 did:key, the only kind a credential use can sign with.
        if !cnf_kid.as_deref().is_some_and(didkey::is_p256) {
            return Err(TokenError::BadJwtCnf);
        }
        match iat {
            Some(iat)
                if exp
                    .checked_sub(iat)
                    .is_some_and(|life| life > 0 && life <= CREDENTIAL_MAX_AGE_SEC) => {}
            _ => return Err(TokenError::BadJwt("invalid space credential lifetime")),
        }
    }

    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| TokenError::BadJwt("signature is not base64url"))?;
    Ok(Parsed {
        kind,
        header: Header {
            alg,
            typ: kind.typ().to_owned(),
            kid,
        },
        claims: Claims {
            iss,
            sub,
            aud,
            iat,
            exp,
            jti,
            cnf_kid,
        },
        signing_input: format!("{h}.{p}"),
        signature,
    })
}

/// What the verifier expects a token to be bound to.
#[derive(Debug, Clone, Copy, Default)]
pub struct Expect<'a> {
    /// This service, for tokens with an audience.
    pub aud: Option<&'a str>,
    /// The requested space.
    pub sub: Option<&'a str>,
}

/// Check expiry (with [`CLOCK_SKEW_SEC`]), a credential's issue time, and
/// the expected audience and subject. `now` is unix seconds.
pub fn check_claims(parsed: &Parsed, now: i64, expect: &Expect<'_>) -> Result<(), TokenError> {
    let c = &parsed.claims;
    if parsed.kind == TokenKind::Credential && c.iat.is_some_and(|iat| iat > now + CLOCK_SKEW_SEC) {
        return Err(TokenError::BadJwt("space credential issued in the future"));
    }
    if now - CLOCK_SKEW_SEC >= c.exp {
        return Err(TokenError::JwtExpired);
    }
    if let Some(aud) = expect.aud {
        if c.aud.as_deref() != Some(aud) {
            return Err(TokenError::BadJwtAudience);
        }
    }
    if let Some(sub) = expect.sub {
        if c.sub != sub {
            return Err(TokenError::BadJwtSub);
        }
    }
    Ok(())
}

/// Verify the signature with `key`. The header's `alg` must match the key
/// type. Delegation tokens and credentials must be low-S, as atproto JWTs
/// require. A client attestation is an OAuth client's JWT, which the
/// reference checks as standard JOSE, so either S is accepted there.
pub fn verify_signature(parsed: &Parsed, key: &AnyKey) -> Result<(), TokenError> {
    if parsed.header.alg != key.jwt_alg() || parsed.signature.len() != 64 {
        return Err(TokenError::BadJwtSignature);
    }
    let msg = parsed.signing_input.as_bytes();
    let ok = if parsed.kind == TokenKind::ClientAttestation {
        key.verify_any_s(msg, &parsed.signature)
    } else {
        key.verify_low_s(msg, &parsed.signature)
    };
    if ok {
        Ok(())
    } else {
        Err(TokenError::BadJwtSignature)
    }
}

/// Parse, check and verify a token whose key is a `did:key` resolved from
/// its `iss`. `resolve(iss, refresh)` returns the issuer's `#atproto` key;
/// it's called again with `refresh = true` if the first key fails, in case
/// it rotated. Not for client attestations, whose key comes from a JWKS.
pub fn verify(
    kind: TokenKind,
    jwt: &str,
    now: i64,
    expect: &Expect<'_>,
    mut resolve: impl FnMut(&str, bool) -> Option<String>,
) -> Result<Claims, TokenError> {
    let parsed = parse(kind, jwt)?;
    check_claims(&parsed, now, expect)?;
    let try_key = |k: Option<String>| -> Option<String> {
        let k = k?;
        let key = didkey::parse_any(&k).ok()?;
        verify_signature(&parsed, &key).ok().map(|_| k)
    };
    let first = resolve(&parsed.claims.iss, false);
    if try_key(first.clone()).is_some() {
        return Ok(parsed.claims);
    }
    let fresh = resolve(&parsed.claims.iss, true);
    if fresh != first && try_key(fresh).is_some() {
        return Ok(parsed.claims);
    }
    Err(TokenError::BadJwtSignature)
}

/// A key that signs tokens.
#[derive(Clone)]
pub enum Signer {
    P256(p256::ecdsa::SigningKey),
    K256(k256::ecdsa::SigningKey),
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Signer::P256(_) => "Signer::P256(…)",
            Signer::K256(_) => "Signer::K256(…)",
        })
    }
}

impl Signer {
    pub fn jwt_alg(&self) -> &'static str {
        match self {
            Signer::P256(_) => "ES256",
            Signer::K256(_) => "ES256K",
        }
    }

    /// The public key as a `did:key`.
    pub fn did_key(&self) -> String {
        match self {
            Signer::P256(k) => didkey::format_p256(&k.verifying_key().into()),
            Signer::K256(k) => didkey::format_k256(&k.verifying_key().into()),
        }
    }

    /// A compact, low-S ECDSA signature over SHA-256 of `msg`, as atproto
    /// signs JWTs, commits and labels.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let bytes = match self {
            Signer::P256(k) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = k.sign(msg);
                sig.normalize_s().unwrap_or(sig).to_bytes()
            }
            Signer::K256(k) => {
                use k256::ecdsa::signature::Signer as _;
                let sig: k256::ecdsa::Signature = k.sign(msg);
                sig.normalize_s().unwrap_or(sig).to_bytes()
            }
        };
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        out
    }
}

fn random_jti() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sign_token(header: Json, payload: Json, signer: &Signer) -> String {
    let h = URL_SAFE_NO_PAD.encode(header.to_string());
    let p = URL_SAFE_NO_PAD.encode(payload.to_string());
    let input = format!("{h}.{p}");
    let sig = signer.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

/// A user's delegation of a space to an app, signed with the user's
/// `#atproto` key and addressed to the authority's space host.
pub fn create_delegation_token(user: &str, space: &SpaceRef, signer: &Signer, now: i64) -> String {
    sign_token(
        json!({ "alg": signer.jwt_alg(), "typ": DELEGATION_TYP, "kid": ATPROTO_KID }),
        json!({
            "iss": user,
            "sub": space.to_string(),
            "aud": space_host_aud(space.authority()),
            "iat": now,
            "exp": now + DELEGATION_TTL_SEC,
            "jti": random_jti(),
        }),
        signer,
    )
}

/// A space credential, signed with the authority's `#atproto` key and
/// bound to `key_id` (a P-256 `did:key`). `ttl` is at most an hour.
pub fn create_space_credential(
    space: &SpaceRef,
    key_id: &str,
    signer: &Signer,
    now: i64,
    ttl: i64,
) -> Result<String, TokenError> {
    if ttl <= 0 || ttl > CREDENTIAL_MAX_AGE_SEC {
        return Err(TokenError::BadJwt("invalid space credential lifetime"));
    }
    if !didkey::is_p256(key_id) {
        return Err(TokenError::BadJwtCnf);
    }
    Ok(sign_token(
        json!({ "alg": signer.jwt_alg(), "typ": CREDENTIAL_TYP, "kid": ATPROTO_KID }),
        json!({
            "iss": space.authority(),
            "sub": space.to_string(),
            "cnf": { "kid": key_id },
            "iat": now,
            "exp": now + ttl,
            "jti": random_jti(),
        }),
        signer,
    ))
}

/// A client's proof of identity to a space host, signed with a key from
/// its JWKS, named by `kid`.
pub fn create_client_attestation(
    client_id: &str,
    authority: &str,
    kid: Option<&str>,
    signer: &Signer,
    now: i64,
) -> String {
    let mut header = json!({ "alg": signer.jwt_alg(), "typ": CLIENT_ATTESTATION_TYP });
    if let Some(kid) = kid {
        header["kid"] = json!(kid);
    }
    sign_token(
        header,
        json!({
            "iss": client_id,
            "sub": client_id,
            "aud": space_host_aud(authority),
            "iat": now,
            "exp": now + CLIENT_ATTESTATION_TTL_SEC,
            "jti": random_jti(),
        }),
        signer,
    )
}

/// A P-256 key from a JWK's `x` and `y` (base64url), for checking a client
/// attestation against the client's JWKS.
pub fn p256_from_jwk(x: &str, y: &str) -> Option<AnyKey> {
    let x = URL_SAFE_NO_PAD.decode(x).ok()?;
    let y = URL_SAFE_NO_PAD.decode(y).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let point = [&[0x04][..], &x, &y].concat();
    p256::PublicKey::from_sec1_bytes(&point)
        .ok()
        .map(AnyKey::P256)
}

/// The token from an `Authorization: Atproto-Space-Credential <token>`
/// value. The scheme matches case-insensitively.
pub fn credential_from_authorization(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("Atproto-Space-Credential") && !token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_738_368_000;
    const SPACE: &str = "at://did:example:space/space/com.example.space/key";

    fn space() -> SpaceRef {
        SpaceRef::parse(SPACE).unwrap()
    }

    fn p256_signer() -> Signer {
        Signer::P256(p256::ecdsa::SigningKey::random(&mut OsRng))
    }

    fn k256_signer() -> Signer {
        Signer::K256(k256::ecdsa::SigningKey::random(&mut OsRng))
    }

    fn bound_key() -> String {
        didkey::format_p256(&p256::SecretKey::random(&mut OsRng).public_key())
    }

    fn resolver(key: String) -> impl FnMut(&str, bool) -> Option<String> {
        move |_, _| Some(key.clone())
    }

    /// Re-sign a token with modified header or payload.
    fn forge(header: Json, payload: Json, signer: &Signer) -> String {
        sign_token(header, payload, signer)
    }

    #[test]
    fn credential_round_trip_both_curves() {
        for signer in [k256_signer(), p256_signer()] {
            let kid = bound_key();
            let jwt = create_space_credential(&space(), &kid, &signer, NOW, 600).unwrap();
            let claims = verify(
                TokenKind::Credential,
                &jwt,
                NOW + 10,
                &Expect {
                    sub: Some(SPACE),
                    ..Default::default()
                },
                resolver(signer.did_key()),
            )
            .unwrap();
            assert_eq!(claims.iss, "did:example:space");
            assert_eq!(claims.cnf_kid.as_deref(), Some(kid.as_str()));
            assert_eq!(claims.aud, None);
            assert_eq!(claims.exp, NOW + 600);
            assert_eq!(claims.jti.len(), 32);
            let parsed = parse(TokenKind::Credential, &jwt).unwrap();
            assert_eq!(parsed.header.kid.as_deref(), Some("#atproto"));
            assert_eq!(parsed.header.alg, signer.jwt_alg());
        }
    }

    #[test]
    fn delegation_round_trip() {
        let signer = k256_signer();
        let jwt = create_delegation_token("did:example:user", &space(), &signer, NOW);
        let aud = space_host_aud("did:example:space");
        let claims = verify(
            TokenKind::Delegation,
            &jwt,
            NOW,
            &Expect {
                aud: Some(&aud),
                sub: Some(SPACE),
            },
            resolver(signer.did_key()),
        )
        .unwrap();
        assert_eq!(claims.iss, "did:example:user");
        assert_eq!(claims.aud.as_deref(), Some("did:example:space#atproto_pds"));
        assert_eq!(claims.exp, NOW + 60);
        assert!(TokenKind::Delegation.single_use());
        assert!(!TokenKind::Credential.single_use());
    }

    #[test]
    fn client_attestation_round_trip() {
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let signer = Signer::P256(sk.clone());
        let cid = "https://app.example.com/client-metadata.json";
        let jwt = create_client_attestation(cid, "did:example:space", Some("key-1"), &signer, NOW);
        let parsed = parse(TokenKind::ClientAttestation, &jwt).unwrap();
        assert_eq!(parsed.claims.iss, cid);
        assert_eq!(parsed.header.kid.as_deref(), Some("key-1"));
        check_claims(
            &parsed,
            NOW,
            &Expect {
                aud: Some("did:example:space#atproto_pds"),
                sub: None,
            },
        )
        .unwrap();
        // The key as the client's JWKS would publish it.
        let pt = sk.verifying_key().to_encoded_point(false);
        let key = p256_from_jwk(
            &URL_SAFE_NO_PAD.encode(pt.x().unwrap()),
            &URL_SAFE_NO_PAD.encode(pt.y().unwrap()),
        )
        .unwrap();
        verify_signature(&parsed, &key).unwrap();
    }

    #[test]
    fn classes_are_not_interchangeable() {
        let signer = k256_signer();
        let delegation = create_delegation_token("did:example:user", &space(), &signer, NOW);
        assert_eq!(
            parse(TokenKind::Credential, &delegation).unwrap_err(),
            TokenError::BadJwtType
        );
        let cred = create_space_credential(&space(), &bound_key(), &signer, NOW, 600).unwrap();
        assert_eq!(
            parse(TokenKind::Delegation, &cred).unwrap_err(),
            TokenError::BadJwtType
        );
        // A service auth token (typ JWT) is none of them.
        let svc = forge(
            json!({"alg": "ES256K", "typ": "JWT"}),
            json!({"iss": "did:example:user", "aud": "did:example:space", "exp": NOW + 60, "lxm": "x.y.z", "jti": "a"}),
            &signer,
        );
        assert_eq!(
            parse(TokenKind::Delegation, &svc).unwrap_err(),
            TokenError::BadJwtType
        );
    }

    #[test]
    fn time_checks() {
        let signer = k256_signer();
        let jwt = create_space_credential(&space(), &bound_key(), &signer, NOW, 600).unwrap();
        let p = parse(TokenKind::Credential, &jwt).unwrap();
        let none = Expect::default();
        // Expired once now - skew >= exp.
        check_claims(&p, NOW + 600 + CLOCK_SKEW_SEC - 1, &none).unwrap();
        assert_eq!(
            check_claims(&p, NOW + 600 + CLOCK_SKEW_SEC, &none),
            Err(TokenError::JwtExpired)
        );
        check_claims(&p, NOW - CLOCK_SKEW_SEC, &none).unwrap();
        assert!(matches!(
            check_claims(&p, NOW - CLOCK_SKEW_SEC - 1, &none),
            Err(TokenError::BadJwt(_))
        ));
        assert!(create_space_credential(&space(), &bound_key(), &signer, NOW, 3601).is_err());
        assert!(create_space_credential(&space(), &bound_key(), &signer, NOW, 0).is_err());
        // A forged credential claiming a two-hour life.
        let long = forge(
            json!({"alg": "ES256K", "typ": CREDENTIAL_TYP, "kid": "#atproto"}),
            json!({"iss": "did:example:space", "sub": SPACE, "cnf": {"kid": bound_key()}, "iat": NOW, "exp": NOW + 7200, "jti": "j"}),
            &signer,
        );
        assert!(matches!(
            parse(TokenKind::Credential, &long),
            Err(TokenError::BadJwt(_))
        ));
    }

    #[test]
    fn binding_checks() {
        let signer = k256_signer();
        let jwt = create_delegation_token("did:example:user", &space(), &signer, NOW);
        let p = parse(TokenKind::Delegation, &jwt).unwrap();
        assert_eq!(
            check_claims(
                &p,
                NOW,
                &Expect {
                    aud: Some("did:example:other#atproto_pds"),
                    sub: None
                }
            ),
            Err(TokenError::BadJwtAudience)
        );
        assert_eq!(
            check_claims(
                &p,
                NOW,
                &Expect {
                    aud: None,
                    sub: Some("at://did:example:space/space/com.example.space/other")
                }
            ),
            Err(TokenError::BadJwtSub)
        );
    }

    #[test]
    fn structural_rejections() {
        let s = k256_signer();
        let base_h = json!({"alg": "ES256K", "typ": CREDENTIAL_TYP, "kid": "#atproto"});
        let base_p = json!({"iss": "did:example:space", "sub": SPACE, "cnf": {"kid": bound_key()}, "iat": NOW, "exp": NOW + 600, "jti": "j"});
        let with = |h: &Json, p: &Json| forge(h.clone(), p.clone(), &s);
        parse(TokenKind::Credential, &with(&base_h, &base_p)).unwrap();

        let mut h = base_h.clone();
        h["kid"] = json!("#other");
        assert!(matches!(
            parse(TokenKind::Credential, &with(&h, &base_p)),
            Err(TokenError::BadJwt(_))
        ));
        let mut h = base_h.clone();
        h.as_object_mut().unwrap().remove("alg");
        assert!(matches!(
            parse(TokenKind::Credential, &with(&h, &base_p)),
            Err(TokenError::BadJwt(_))
        ));

        for (field, value, err) in [
            (
                "cnf",
                json!({"kid": "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"}),
                TokenError::BadJwtCnf,
            ),
            ("cnf", json!({}), TokenError::BadJwtCnf),
            ("iss", json!("not-a-did"), TokenError::BadJwtIss),
            (
                "sub",
                json!("at://did:example:space/com.example.post/k"),
                TokenError::BadJwtSub,
            ),
            ("iss", json!(""), TokenError::BadJwtIss),
        ] {
            let mut p = base_p.clone();
            p[field] = value;
            assert_eq!(
                parse(TokenKind::Credential, &with(&base_h, &p)),
                Err(err),
                "{field}"
            );
        }
        let mut p = base_p.clone();
        p.as_object_mut().unwrap().remove("jti");
        assert!(matches!(
            parse(TokenKind::Credential, &with(&base_h, &p)),
            Err(TokenError::BadJwt(_))
        ));

        // Delegation without aud; attestation with iss != sub.
        let dh = json!({"alg": "ES256K", "typ": DELEGATION_TYP, "kid": "#atproto"});
        let dp = json!({"iss": "did:example:user", "sub": SPACE, "exp": NOW + 60, "jti": "j"});
        assert_eq!(
            parse(TokenKind::Delegation, &with(&dh, &dp)),
            Err(TokenError::BadJwtAudience)
        );
        let ah = json!({"alg": "ES256", "typ": CLIENT_ATTESTATION_TYP});
        let ap = json!({"iss": "https://a.example/c.json", "sub": "https://b.example/c.json", "aud": "x", "exp": NOW + 60, "jti": "j"});
        assert_eq!(
            parse(TokenKind::ClientAttestation, &with(&ah, &ap)),
            Err(TokenError::BadJwtIss)
        );

        for bad in ["a.b", "a.b.c.d", "!!!.e30.sig", "e30.e30.sig"] {
            assert!(parse(TokenKind::Credential, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn signature_checks() {
        let signer = k256_signer();
        let jwt = create_space_credential(&space(), &bound_key(), &signer, NOW, 600).unwrap();
        // Another key.
        let other = k256_signer();
        assert_eq!(
            verify(
                TokenKind::Credential,
                &jwt,
                NOW,
                &Expect::default(),
                resolver(other.did_key())
            ),
            Err(TokenError::BadJwtSignature)
        );
        // Rotation: the cached key is stale, the refreshed one works.
        let (stale, fresh) = (other.did_key(), signer.did_key());
        let mut calls = Vec::new();
        let claims = verify(
            TokenKind::Credential,
            &jwt,
            NOW,
            &Expect::default(),
            |iss, refresh| {
                calls.push((iss.to_owned(), refresh));
                Some(if refresh {
                    fresh.clone()
                } else {
                    stale.clone()
                })
            },
        );
        assert!(claims.is_ok());
        assert_eq!(
            calls,
            [
                ("did:example:space".to_owned(), false),
                ("did:example:space".to_owned(), true)
            ]
        );
        // alg must match the key type.
        let p256 = p256_signer();
        let mut parsed = parse(TokenKind::Credential, &jwt).unwrap();
        parsed.header.alg = "ES256".into();
        assert_eq!(
            verify_signature(&parsed, &didkey::parse_any(&p256.did_key()).unwrap()),
            Err(TokenError::BadJwtSignature)
        );
        // A tampered payload.
        let mut parts: Vec<&str> = jwt.split('.').collect();
        let other_payload = URL_SAFE_NO_PAD.encode(
            json!({"iss": "did:example:space", "sub": SPACE, "cnf": {"kid": bound_key()}, "iat": NOW, "exp": NOW + 600, "jti": "x"}).to_string(),
        );
        parts[1] = &other_payload;
        let tampered = parts.join(".");
        assert_eq!(
            verify(
                TokenKind::Credential,
                &tampered,
                NOW,
                &Expect::default(),
                resolver(signer.did_key())
            ),
            Err(TokenError::BadJwtSignature)
        );
    }

    #[test]
    fn high_s_jwt_is_rejected() {
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let signer = Signer::P256(sk.clone());
        let jwt = create_space_credential(&space(), &bound_key(), &signer, NOW, 600).unwrap();
        let parsed = parse(TokenKind::Credential, &jwt).unwrap();
        let key = didkey::parse_any(&signer.did_key()).unwrap();
        verify_signature(&parsed, &key).unwrap();
        // Flip s to n - s.
        let sig = p256::ecdsa::Signature::from_slice(&parsed.signature).unwrap();
        let (r, s) = sig.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s).unwrap();
        let mut flipped = parsed.clone();
        flipped.signature = high.to_bytes().to_vec();
        assert_eq!(
            verify_signature(&flipped, &key),
            Err(TokenError::BadJwtSignature)
        );
    }

    #[test]
    fn tokens_are_bound_to_the_space_they_name() {
        // Someone else's key, claiming a credential for this space.
        let mallory = k256_signer();
        let forged = forge(
            json!({"alg": "ES256K", "typ": CREDENTIAL_TYP, "kid": "#atproto"}),
            json!({"iss": "did:example:mallory", "sub": SPACE, "cnf": {"kid": bound_key()}, "iat": NOW, "exp": NOW + 600, "jti": "j"}),
            &mallory,
        );
        assert_eq!(
            verify(
                TokenKind::Credential,
                &forged,
                NOW,
                &Expect {
                    sub: Some(SPACE),
                    ..Default::default()
                },
                resolver(mallory.did_key())
            ),
            Err(TokenError::BadJwtIss)
        );
        // A delegation addressed to another authority's space host.
        let user = k256_signer();
        let elsewhere = forge(
            json!({"alg": "ES256K", "typ": DELEGATION_TYP, "kid": "#atproto"}),
            json!({"iss": "did:example:user", "sub": SPACE, "aud": "did:example:other#atproto_pds", "exp": NOW + 60, "jti": "j"}),
            &user,
        );
        assert_eq!(
            verify(
                TokenKind::Delegation,
                &elsewhere,
                NOW,
                &Expect::default(),
                resolver(user.did_key())
            ),
            Err(TokenError::BadJwtAudience)
        );
    }

    #[test]
    fn huge_lifetimes_do_not_overflow() {
        let s = k256_signer();
        for (iat, exp) in [(json!(-1), json!(1e300)), (json!(-1e300), json!(NOW))] {
            let jwt = forge(
                json!({"alg": "ES256K", "typ": CREDENTIAL_TYP, "kid": "#atproto"}),
                json!({"iss": "did:example:space", "sub": SPACE, "cnf": {"kid": bound_key()}, "iat": iat, "exp": exp, "jti": "j"}),
                &s,
            );
            assert!(matches!(
                parse(TokenKind::Credential, &jwt),
                Err(TokenError::BadJwt(_))
            ));
        }
    }

    #[test]
    fn client_attestations_accept_high_s() {
        let signer = p256_signer();
        let key = didkey::parse_any(&signer.did_key()).unwrap();
        let jwt = create_client_attestation(
            "https://app.example.com/client-metadata.json",
            "did:example:space",
            None,
            &signer,
            NOW,
        );
        let parsed = parse(TokenKind::ClientAttestation, &jwt).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&parsed.signature).unwrap();
        let (r, s) = sig.split_scalars();
        let mut high = parsed.clone();
        high.signature = p256::ecdsa::Signature::from_scalars(r, -*s)
            .unwrap()
            .to_bytes()
            .to_vec();
        // As a JOSE library would accept it.
        verify_signature(&parsed, &key).unwrap();
        verify_signature(&high, &key).unwrap();
        // Still bound to the signing input.
        let mut other = high.clone();
        other.signing_input.push('x');
        assert_eq!(
            verify_signature(&other, &key),
            Err(TokenError::BadJwtSignature)
        );
    }

    #[test]
    fn authorization_scheme() {
        assert_eq!(
            credential_from_authorization("Atproto-Space-Credential abc"),
            Some("abc")
        );
        assert_eq!(
            credential_from_authorization("atproto-space-credential abc"),
            Some("abc")
        );
        assert_eq!(credential_from_authorization("Bearer abc"), None);
        assert_eq!(
            credential_from_authorization("Atproto-Space-Credential "),
            None
        );
        assert_eq!(
            credential_from_authorization("Atproto-Space-Credential"),
            None
        );
    }
}
