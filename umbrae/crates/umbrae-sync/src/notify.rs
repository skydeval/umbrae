//! The notification endpoint: `confirmRegistration` and
//! `notifySpaceUpdate`, which the space host calls on the endpoint passed
//! to `authorizeSpaceSync`.
//!
//! These calls are unauthenticated: the endpoint and the token together
//! identify the registration. Check the token with [`token_matches`]
//! against the one registered for the space before acting, and treat a
//! notification only as a prompt to sync: it never carries data to trust.

use crate::error::SyncError;
use crate::json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use umbrae_core::uri::SpaceRef;

pub const CONFIRM_NSID: &str = "com.atproto.space.confirmRegistration";
pub const NOTIFY_NSID: &str = "com.atproto.space.notifySpaceUpdate";

const REPO_WRITE: &str = "com.atproto.space.defs#repoWrite";
const REPO_REMOVED: &str = "com.atproto.space.defs#repoRemoved";
const SPACE_DELETED: &str = "com.atproto.space.notifySpaceUpdate#spaceDeleted";
const REGISTRATION_EXPIRED: &str = "com.atproto.space.notifySpaceUpdate#registrationExpired";

/// The lexicon's limit on tokens and challenges.
const MAX_TOKEN: usize = 512;

/// A fresh registration token: 32 random bytes, base64url.
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// Compare tokens in constant time for equal lengths.
pub fn token_matches(expected: &str, got: &str) -> bool {
    let (a, b) = (expected.as_bytes(), got.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A `confirmRegistration` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    pub space: SpaceRef,
    pub token: String,
    pub challenge: String,
}

impl Confirmation {
    /// The reply, once the token is checked: the challenge, echoed.
    pub fn reply(&self) -> Value {
        json!({ "challenge": self.challenge })
    }
}

/// What a `notifySpaceUpdate` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// A repo advanced: sync it (`listRepoOps` from the cursor).
    RepoWrite {
        repo: String,
        repo_rev: String,
        data: [u8; 32],
        space_rev: String,
        prev_space_rev: Option<String>,
    },
    /// A repo left the writer set: drop its records.
    RepoRemoved {
        repo: String,
        space_rev: String,
        prev_space_rev: Option<String>,
    },
    /// The space was deleted. Confirm with `authorizeSpaceSync` before
    /// dropping its data.
    SpaceDeleted,
    /// The registration lapsed with the credential: authorize again to keep
    /// getting notifications.
    RegistrationExpired { space_rev: String },
}

impl Update {
    /// The space revision before this update, if the host sent one.
    pub fn prev_space_rev(&self) -> Option<&str> {
        match self {
            Update::RepoWrite { prev_space_rev, .. }
            | Update::RepoRemoved { prev_space_rev, .. } => prev_space_rev.as_deref(),
            _ => None,
        }
    }

    /// Whether notifications were missed: the update's previous space
    /// revision isn't the last one seen. If so, sync the whole space.
    pub fn follows_gap(&self, last_seen: Option<&str>) -> bool {
        match (self.prev_space_rev(), last_seen) {
            (Some(prev), Some(seen)) => prev != seen,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }
}

/// A `notifySpaceUpdate` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub space: SpaceRef,
    pub token: String,
    pub update: Update,
}

fn text(v: &Value, k: &'static str) -> Result<String, SyncError> {
    v[k].as_str()
        .map(str::to_owned)
        .ok_or(SyncError::Malformed(k))
}

fn bounded(v: &Value, k: &'static str) -> Result<String, SyncError> {
    let s = text(v, k)?;
    if s.is_empty() || s.len() > MAX_TOKEN {
        return Err(SyncError::Malformed(k));
    }
    Ok(s)
}

fn space(v: &Value) -> Result<SpaceRef, SyncError> {
    SpaceRef::parse(&text(v, "space")?).map_err(|_| SyncError::Malformed("space"))
}

fn body(bytes: &[u8]) -> Result<Value, SyncError> {
    serde_json::from_slice(bytes).map_err(|_| SyncError::Malformed("body is not JSON"))
}

/// Parse a `confirmRegistration` body.
pub fn parse_confirmation(bytes: &[u8]) -> Result<Confirmation, SyncError> {
    let v = body(bytes)?;
    Ok(Confirmation {
        space: space(&v)?,
        token: bounded(&v, "token")?,
        challenge: bounded(&v, "challenge")?,
    })
}

/// Parse a `notifySpaceUpdate` body.
pub fn parse_notification(bytes: &[u8]) -> Result<Notification, SyncError> {
    let v = body(bytes)?;
    let u = &v["update"];
    let prev = u["prevSpaceRev"].as_str().map(str::to_owned);
    let update = match u["$type"].as_str() {
        Some(REPO_WRITE) => Update::RepoWrite {
            repo: text(u, "repo")?,
            repo_rev: text(u, "repoRev")?,
            data: json::digest(&u["data"]).ok_or(SyncError::Malformed("data"))?,
            space_rev: text(u, "spaceRev")?,
            prev_space_rev: prev,
        },
        Some(REPO_REMOVED) => Update::RepoRemoved {
            repo: text(u, "repo")?,
            space_rev: text(u, "spaceRev")?,
            prev_space_rev: prev,
        },
        Some(SPACE_DELETED) => Update::SpaceDeleted,
        Some(REGISTRATION_EXPIRED) => Update::RegistrationExpired {
            space_rev: text(u, "spaceRev")?,
        },
        _ => return Err(SyncError::Malformed("update type")),
    };
    Ok(Notification {
        space: space(&v)?,
        token: bounded(&v, "token")?,
        update,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: &str = "at://did:example:alice/space/tools.umbrae.space/3mbbbbbbbbbb2";

    #[test]
    fn tokens() {
        let a = new_token();
        assert_eq!(a.len(), 43);
        assert_ne!(a, new_token());
        assert!(token_matches(&a, &a.clone()));
        assert!(!token_matches(&a, &new_token()));
        assert!(!token_matches(&a, &a[..42]));
    }

    #[test]
    fn confirmations() {
        let body = json!({ "space": SPACE, "token": "t", "challenge": "c" }).to_string();
        let c = parse_confirmation(body.as_bytes()).unwrap();
        assert_eq!(c.reply(), json!({ "challenge": "c" }));
        let long =
            json!({ "space": SPACE, "token": "t", "challenge": "c".repeat(513) }).to_string();
        assert!(parse_confirmation(long.as_bytes()).is_err());
        assert!(parse_confirmation(b"{}").is_err());
    }

    #[test]
    fn notifications() {
        let n = |update: Value| {
            parse_notification(
                json!({ "space": SPACE, "token": "t", "update": update })
                    .to_string()
                    .as_bytes(),
            )
        };
        let w = n(
            json!({ "$type": REPO_WRITE, "repo": "did:example:bob", "repoRev": "3mbaaaaaaaaa3",
            "data": { "$bytes": base64::engine::general_purpose::STANDARD.encode([7u8; 32]) },
            "spaceRev": "3mbaaaaaaaab2", "prevSpaceRev": "3mbaaaaaaaab1" }),
        )
        .unwrap();
        match &w.update {
            Update::RepoWrite { data, .. } => assert_eq!(data, &[7u8; 32]),
            other => panic!("{other:?}"),
        }
        assert!(!w.update.follows_gap(Some("3mbaaaaaaaab1")));
        assert!(w.update.follows_gap(Some("3mbaaaaaaaaz9")));
        assert!(w.update.follows_gap(None));
        let r = n(json!({ "$type": REPO_REMOVED, "repo": "did:example:bob", "spaceRev": "3mbaaaaaaaab3" })).unwrap();
        assert!(!r.update.follows_gap(None));
        assert_eq!(
            n(json!({ "$type": SPACE_DELETED })).unwrap().update,
            Update::SpaceDeleted
        );
        assert_eq!(
            n(json!({ "$type": REGISTRATION_EXPIRED, "spaceRev": "3mbaaaaaaaab4" }))
                .unwrap()
                .update,
            Update::RegistrationExpired {
                space_rev: "3mbaaaaaaaab4".into()
            }
        );
        assert!(n(json!({ "$type": "com.example.other" })).is_err());
        assert!(n(json!({ "$type": REPO_WRITE, "repo": "did:example:bob" })).is_err());
    }
}
