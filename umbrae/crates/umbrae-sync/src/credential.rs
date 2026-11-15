//! Getting a space credential, and presenting it.

use crate::error::{SyncError, XrpcName};
use crate::transport::{Directory, Method, Request, Response, Transport};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use umbrae_core::didkey;
use umbrae_core::httpsig;
use umbrae_core::tokens::{self, Expect, TokenError, TokenKind};
use umbrae_core::uri::SpaceRef;

/// Where the host should send `notifySpaceUpdate`, and the secret token
/// that identifies the registration. Keep the token the same across
/// renewals ([`crate::notify::new_token`] makes one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    /// Base HTTPS URL the host calls `{endpoint}/xrpc/…` on.
    pub endpoint: String,
    pub token: String,
}

/// What to present to `authorizeSpaceSync`.
#[derive(Debug, Clone, Copy)]
pub struct Authorize<'a> {
    /// From `getDelegationToken` on a reader's own PDS. Single use, 60 s.
    pub delegation: &'a str,
    /// From [`tokens::create_client_attestation`], when the space limits
    /// apps (`allowedApps`).
    pub attestation: Option<&'a str>,
    pub notify: Option<&'a Notify>,
}

/// A space credential and the key it's bound to.
///
/// It serializes, so a restart can resume without a new delegation. The
/// serialized form holds the private key: store it as a secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "Stored", into = "Stored")]
pub struct Credential {
    space: SpaceRef,
    token: String,
    key: SigningKey,
    expires_at: i64,
    space_rev: Option<String>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct Stored {
    space: String,
    token: String,
    key: String,
    expires_at: i64,
    space_rev: Option<String>,
}

impl From<Credential> for Stored {
    fn from(c: Credential) -> Self {
        Stored {
            space: c.space.to_string(),
            token: c.token,
            key: URL_SAFE_NO_PAD.encode(c.key.to_bytes()),
            expires_at: c.expires_at,
            space_rev: c.space_rev,
        }
    }
}

impl TryFrom<Stored> for Credential {
    type Error = &'static str;

    fn try_from(s: Stored) -> Result<Self, Self::Error> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&s.key)
            .map_err(|_| "credential key")?;
        Ok(Credential {
            space: SpaceRef::parse(&s.space).map_err(|_| "credential space")?,
            token: s.token,
            key: SigningKey::from_slice(&bytes).map_err(|_| "credential key")?,
            expires_at: s.expires_at,
            space_rev: s.space_rev,
        })
    }
}

impl Credential {
    pub fn space(&self) -> &SpaceRef {
        &self.space
    }

    /// Unix seconds.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// The space revision the host reported when it issued the credential.
    pub fn space_rev(&self) -> Option<&str> {
        self.space_rev.as_deref()
    }

    /// Whether to renew: expired, or within `margin` seconds of it.
    pub fn needs_renewal(&self, now: i64, margin: i64) -> bool {
        now + margin >= self.expires_at
    }

    pub(crate) fn check_live(&self, now: i64) -> Result<(), SyncError> {
        if now >= self.expires_at {
            Err(SyncError::CredentialExpired)
        } else {
            Ok(())
        }
    }

    /// The headers that present this credential to `audience`: the DID
    /// whose data is read (the authority for `listWriters`, the repo's
    /// account for its repo).
    pub fn headers(&self, audience: &str) -> Vec<(&'static str, String)> {
        let authorization = format!("Atproto-Space-Credential {}", self.token);
        let s = httpsig::sign_credential_use(&authorization, audience, &self.key);
        vec![
            ("Authorization", authorization),
            ("Atproto-Space-Audience", audience.to_owned()),
            ("Signature-Input", s.signature_input),
            ("Signature", s.signature),
        ]
    }
}

pub(crate) fn xrpc_error(r: &Response) -> SyncError {
    let name = serde_json::from_slice::<serde_json::Value>(&r.body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(XrpcName::new))
        .unwrap_or_else(|| XrpcName::new(""));
    SyncError::Xrpc {
        status: r.status,
        error: name,
    }
}

pub(crate) fn json_body(r: &Response) -> Result<serde_json::Value, SyncError> {
    if r.status != 200 {
        return Err(xrpc_error(r));
    }
    serde_json::from_slice(&r.body).map_err(|_| SyncError::Malformed("response is not JSON"))
}

/// Exchange a delegation for a credential bound to a fresh key of ours, at
/// the space authority's PDS. The returned credential is verified: signed
/// by the authority, for this space, bound to our key.
pub async fn authorize<T: Transport, D: Directory>(
    transport: &T,
    directory: &D,
    space: &SpaceRef,
    req: Authorize<'_>,
    now: i64,
) -> Result<Credential, SyncError> {
    let authority = directory.resolve(space.authority(), false).await?;
    let key = SigningKey::random(&mut OsRng);
    let kid = didkey::format_p256(&key.verifying_key().into());
    let mut body = json!({
        "space": space.to_string(),
        "credentialKey": kid,
        "delegationToken": req.delegation,
    });
    if let Some(a) = req.attestation {
        body["clientAttestation"] = json!(a);
    }
    if let Some(n) = req.notify {
        body["notify"] = json!({ "endpoint": n.endpoint, "token": n.token });
    }
    let r = transport
        .send(Request {
            method: Method::Post,
            base: authority.pds.clone(),
            nsid: "com.atproto.space.authorizeSpaceSync",
            query: vec![],
            headers: vec![],
            body: Some(body),
        })
        .await?;
    let j = json_body(&r)?;
    let token = j["credential"]
        .as_str()
        .ok_or(SyncError::Malformed("no credential"))?
        .to_owned();
    let space_rev = j["spaceRev"].as_str().map(str::to_owned);

    let space_str = space.to_string();
    let expect = Expect {
        aud: None,
        sub: Some(&space_str),
    };
    let first = authority.signing_key.clone();
    let mut claims = tokens::verify(TokenKind::Credential, &token, now, &expect, |_, _| {
        first.clone()
    });
    if matches!(claims, Err(TokenError::BadJwtSignature)) {
        let fresh = directory
            .resolve(space.authority(), true)
            .await?
            .signing_key;
        claims = tokens::verify(TokenKind::Credential, &token, now, &expect, |_, _| {
            fresh.clone()
        });
    }
    let claims = claims.map_err(SyncError::Token)?;
    if claims.iss != space.authority() || claims.cnf_kid.as_deref() != Some(kid.as_str()) {
        return Err(SyncError::CredentialMismatch);
    }
    Ok(Credential {
        space: space.clone(),
        token,
        key,
        expires_at: claims.exp,
        space_rev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_without_showing_secrets_in_debug() {
        let space =
            SpaceRef::new("did:example:alice", "tools.umbrae.space", "3mbbbbbbbbbb2").unwrap();
        let c = Credential {
            space,
            token: "secret-token".into(),
            key: SigningKey::random(&mut OsRng),
            expires_at: 1000,
            space_rev: Some("3mbaaaaaaaaa2".into()),
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: Credential = serde_json::from_str(&s).unwrap();
        assert_eq!(back.space(), c.space());
        assert_eq!(back.key.to_bytes(), c.key.to_bytes());
        assert_eq!(
            back.headers("did:example:alice")[0],
            c.headers("did:example:alice")[0]
        );
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("secret-token") && !dbg.contains("did:example"));
        assert!(c.needs_renewal(950, 60) && !c.needs_renewal(900, 60));
        assert_eq!(c.check_live(1000), Err(SyncError::CredentialExpired));
        let bad = s.replace(&URL_SAFE_NO_PAD.encode(c.key.to_bytes()), "AAAA");
        assert!(serde_json::from_str::<Credential>(&bad).is_err());
    }

    #[test]
    fn hostile_error_names_are_dropped() {
        let r = |body: &str| Response {
            status: 400,
            headers: vec![],
            body: body.as_bytes().to_vec(),
        };
        assert_eq!(
            xrpc_error(&r(r#"{"error":"SpaceNotFound"}"#)),
            SyncError::Xrpc {
                status: 400,
                error: XrpcName::new("SpaceNotFound")
            }
        );
        assert!(xrpc_error(&r(r#"{"error":"SpaceNotFound"}"#)).is_space_not_found());
        match xrpc_error(&r(r#"{"error":"did:plc:leak with spaces"}"#)) {
            SyncError::Xrpc { error, .. } => assert_eq!(error.as_str(), ""),
            other => panic!("{other:?}"),
        }
        assert!(matches!(xrpc_error(&r("not json")), SyncError::Xrpc { .. }));
    }
}
