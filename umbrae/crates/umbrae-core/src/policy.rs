//! The baseline space policies (spec: "Space policy", "Baseline
//! policies").
//!
//! | Policy | Who may read / be tracked as a writer |
//! |---|---|
//! | `com.atproto.personalspace.policy` | only the authority |
//! | `com.atproto.memberspace.policy` | members with `read` / `write`, or anyone under `publicRead` / `publicWrite` |
//! | `com.atproto.managedspace.policy` | whatever the managing app's `checkAccess` answers |
//!
//! Under every policy the authority itself is allowed both, so it can't
//! lock itself out. Read decides whether a credential is minted; write
//! decides whether the authority tracks a writer and notifies syncers of
//! its writes. Decisions here are pure: the caller looks up the member
//! entry or asks the managing app, and passes the answer in.

use crate::drisl::Value;
use crate::uri::is_valid_did;
use std::collections::BTreeMap;
use std::fmt;

pub const PERSONALSPACE_POLICY: &str = "com.atproto.personalspace.policy";
pub const MEMBERSPACE_POLICY: &str = "com.atproto.memberspace.policy";
pub const MANAGEDSPACE_POLICY: &str = "com.atproto.managedspace.policy";
/// The record a member list is published as, and its archive entries' type.
pub const MEMBER_RECORD: &str = "com.atproto.memberspace.member";
/// The record a policy is published as, under rkey `self`.
pub const POLICY_RECORD: &str = "com.atproto.space.policy";
pub const POLICY_RECORD_RKEY: &str = "self";

/// A DRISL map.
pub type Map = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPolicy {
    pub public_read: bool,
    pub public_write: bool,
    /// OAuth client IDs allowed to read; any app when `None`.
    pub allowed_apps: Option<Vec<String>>,
    pub publish_policy: bool,
    pub publish_members: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPolicy {
    /// A `did#serviceId` reference.
    pub managing_app: String,
    pub publish_policy: bool,
}

/// A policy this crate implements, with defaults filled in, so that what is
/// stored is exactly what is enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    Personal,
    Member(MemberPolicy),
    Managed(ManagedPolicy),
}

/// Why a policy object is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A `$type` this host doesn't implement (`UnsupportedPolicy`).
    Unsupported(String),
    /// A known policy with a malformed field, or malformed policy state.
    Invalid(&'static str),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Unsupported(t) => write!(f, "unsupported policy: {t}"),
            PolicyError::Invalid(why) => write!(f, "invalid policy: {why}"),
        }
    }
}

impl std::error::Error for PolicyError {}

fn bool_field(m: &Map, k: &'static str) -> Result<bool, PolicyError> {
    match m.get(k) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(PolicyError::Invalid(k)),
    }
}

/// `did:…#fragment`, with a valid DID and a non-empty fragment.
pub fn is_did_service_ref(s: &str) -> bool {
    match s.split_once('#') {
        Some((did, frag)) => {
            is_valid_did(did)
                && !frag.is_empty()
                && frag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        }
        None => false,
    }
}

impl Policy {
    /// Read a policy object, as `createSpace`, `updateSpace` or a space
    /// meta archive carries it. Unknown fields are dropped, as Lexicon
    /// evolution allows.
    pub fn from_map(m: &Map) -> Result<Self, PolicyError> {
        let ty = m
            .get("$type")
            .and_then(Value::as_text)
            .ok_or(PolicyError::Invalid("$type"))?;
        match ty {
            PERSONALSPACE_POLICY => Ok(Policy::Personal),
            MEMBERSPACE_POLICY => {
                let allowed_apps = match m.get("allowedApps") {
                    None => None,
                    Some(Value::Array(items)) => Some(
                        items
                            .iter()
                            .map(|v| {
                                v.as_text()
                                    .filter(|s| !s.is_empty())
                                    .map(str::to_owned)
                                    .ok_or(PolicyError::Invalid("allowedApps"))
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                    Some(_) => return Err(PolicyError::Invalid("allowedApps")),
                };
                Ok(Policy::Member(MemberPolicy {
                    public_read: bool_field(m, "publicRead")?,
                    public_write: bool_field(m, "publicWrite")?,
                    allowed_apps,
                    publish_policy: bool_field(m, "publishPolicy")?,
                    publish_members: bool_field(m, "publishMembers")?,
                }))
            }
            MANAGEDSPACE_POLICY => {
                let managing_app = m
                    .get("managingApp")
                    .and_then(Value::as_text)
                    .filter(|s| is_did_service_ref(s))
                    .ok_or(PolicyError::Invalid(
                        "managingApp must be a did#serviceId reference",
                    ))?;
                Ok(Policy::Managed(ManagedPolicy {
                    managing_app: managing_app.to_owned(),
                    publish_policy: bool_field(m, "publishPolicy")?,
                }))
            }
            other => Err(PolicyError::Unsupported(other.to_owned())),
        }
    }

    /// The normalized policy object, defaults included.
    pub fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.insert("$type".into(), Value::Text(self.type_name().into()));
        match self {
            Policy::Personal => {}
            Policy::Member(p) => {
                m.insert("publicRead".into(), Value::Bool(p.public_read));
                m.insert("publicWrite".into(), Value::Bool(p.public_write));
                if let Some(apps) = &p.allowed_apps {
                    m.insert(
                        "allowedApps".into(),
                        Value::Array(apps.iter().map(|a| Value::Text(a.clone())).collect()),
                    );
                }
                m.insert("publishPolicy".into(), Value::Bool(p.publish_policy));
                m.insert("publishMembers".into(), Value::Bool(p.publish_members));
            }
            Policy::Managed(p) => {
                m.insert("managingApp".into(), Value::Text(p.managing_app.clone()));
                m.insert("publishPolicy".into(), Value::Bool(p.publish_policy));
            }
        }
        m
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Policy::Personal => PERSONALSPACE_POLICY,
            Policy::Member(_) => MEMBERSPACE_POLICY,
            Policy::Managed(_) => MANAGEDSPACE_POLICY,
        }
    }

    /// Whether `updateSpace` to `next` migrates the space to another
    /// policy, discarding the current policy's state (the member list).
    pub fn is_migration_to(&self, next: &Policy) -> bool {
        self.type_name() != next.type_name()
    }

    /// Whether the policy is published as a `com.atproto.space.policy`
    /// record in the authority's repo.
    pub fn is_published(&self) -> bool {
        match self {
            Policy::Personal => false,
            Policy::Member(p) => p.publish_policy,
            Policy::Managed(p) => p.publish_policy,
        }
    }

    /// Whether the member list is published as member records.
    pub fn members_published(&self) -> bool {
        matches!(self, Policy::Member(p) if p.publish_members)
    }

    /// Only memberspace restricts apps, by the **attested** client_id, so
    /// an app that presents no client attestation is never an allowed one.
    pub fn is_app_authorized(&self, attested_client_id: Option<&str>) -> bool {
        match self {
            Policy::Member(MemberPolicy {
                allowed_apps: Some(apps),
                ..
            }) => attested_client_id.is_some_and(|c| apps.iter().any(|a| a == c)),
            _ => true,
        }
    }

    /// Whether minting a credential needs a delegation token: everywhere
    /// except a public-read memberspace (the authority's own reads aside).
    pub fn requires_delegation(&self) -> bool {
        !matches!(self, Policy::Member(p) if p.public_read)
    }

    /// Whether minting a credential needs a client attestation.
    pub fn requires_attestation(&self) -> bool {
        matches!(
            self,
            Policy::Member(MemberPolicy {
                allowed_apps: Some(_),
                ..
            })
        )
    }

    /// The published policy record's value.
    pub fn policy_record(&self) -> Map {
        Map::from([
            ("$type".to_owned(), Value::Text(POLICY_RECORD.into())),
            ("policy".to_owned(), Value::Map(self.to_map())),
        ])
    }
}

/// Read or write, decided independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// A member-list entry, or a managing app's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberAccess {
    pub read: bool,
    pub write: bool,
}

impl MemberAccess {
    pub fn allows(self, access: Access) -> bool {
        match access {
            Access::Read => self.read,
            Access::Write => self.write,
        }
    }

    /// The member record's value (also the archive entry's value).
    pub fn to_record(self) -> Map {
        Map::from([
            ("$type".to_owned(), Value::Text(MEMBER_RECORD.into())),
            ("read".to_owned(), Value::Bool(self.read)),
            ("write".to_owned(), Value::Bool(self.write)),
        ])
    }

    pub fn from_record(m: &Map) -> Result<Self, PolicyError> {
        match m.get("$type") {
            None => {}
            Some(Value::Text(t)) if t == MEMBER_RECORD => {}
            Some(_) => return Err(PolicyError::Invalid("member $type")),
        }
        match (m.get("read"), m.get("write")) {
            (Some(Value::Bool(read)), Some(Value::Bool(write))) => Ok(Self {
                read: *read,
                write: *write,
            }),
            _ => Err(PolicyError::Invalid(
                "member read and write are required booleans",
            )),
        }
    }
}

/// A policy's decision for one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    /// Ask the managing app (`checkAccess`, with service auth from the
    /// authority) and decide with [`MemberAccess::allows`]. Without an
    /// answer, fail the request upstream rather than allow or deny.
    AskManagingApp(String),
}

/// Whether the policy authorizes `repo` for `access`. `repo` is `None` for
/// a read with no delegation token. `member` is the account's member-list
/// entry, for a memberspace.
pub fn authorize_repo(
    policy: &Policy,
    authority: &str,
    repo: Option<&str>,
    access: Access,
    member: Option<MemberAccess>,
) -> Decision {
    if repo == Some(authority) {
        return Decision::Allow;
    }
    let allow = |b: bool| if b { Decision::Allow } else { Decision::Deny };
    match policy {
        Policy::Personal => Decision::Deny,
        Policy::Member(p) => match access {
            Access::Read if p.public_read => Decision::Allow,
            _ if repo.is_none() => Decision::Deny,
            Access::Read => allow(member.is_some_and(|m| m.read)),
            // A member without write access stays out even under publicWrite.
            Access::Write => allow(match member {
                Some(m) => m.write,
                None => p.public_write,
            }),
        },
        Policy::Managed(p) => Decision::AskManagingApp(p.managing_app.clone()),
    }
}

/// Why a credential is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRefusal {
    /// The account isn't authorized. Answered as though the space doesn't
    /// exist, so a refusal discloses nothing about it.
    SpaceNotFound,
    AppNotAuthorized,
}

/// Whether to mint a credential, given the read decision for the account
/// (resolved through the managing app if need be) and the attested client.
/// The account is checked first.
pub fn authorize_credential(
    policy: &Policy,
    account_may_read: bool,
    attested_client_id: Option<&str>,
) -> Result<(), CredentialRefusal> {
    if !account_may_read {
        return Err(CredentialRefusal::SpaceNotFound);
    }
    if !policy.is_app_authorized(attested_client_id) {
        return Err(CredentialRefusal::AppNotAuthorized);
    }
    Ok(())
}

/// A DID as a record key. `%` isn't allowed in record keys, so a localhost
/// did:web's encoded port is left unencoded:
/// `did:web:localhost%3A2583` ↔ `did:web:localhost:2583`.
pub fn did_to_record_key(did: &str) -> String {
    did.replace("%3A", ":")
}

/// The inverse of [`did_to_record_key`].
pub fn record_key_to_did(rkey: &str) -> String {
    if let Some(rest) = rkey.strip_prefix("did:web:") {
        if let Some((host, port)) = rest.split_once(':') {
            if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                return format!("did:web:{host}%3A{port}");
            }
        }
    }
    rkey.to_owned()
}

/// The space meta archive entry for a member: key and value.
pub fn member_state_entry(did: &str, access: MemberAccess) -> (String, Map) {
    (
        format!("{MEMBER_RECORD}/{}", did_to_record_key(did)),
        access.to_record(),
    )
}

/// Read the member list out of an archive's policy state. Any key the
/// policy doesn't define is refused rather than dropped, since dropping
/// it would quietly change who has access.
pub fn parse_policy_state(
    policy: &Policy,
    entries: &[(String, Map)],
) -> Result<Vec<(String, MemberAccess)>, PolicyError> {
    let prefix = format!("{MEMBER_RECORD}/");
    entries
        .iter()
        .map(|(key, value)| {
            let did = key.strip_prefix(&prefix).map(record_key_to_did);
            match (policy, did) {
                (Policy::Member(_), Some(did)) if is_valid_did(&did) => {
                    Ok((did, MemberAccess::from_record(value)?))
                }
                _ => Err(PolicyError::Invalid("unrecognized policy state")),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH: &str = "did:example:authority";
    const USER: &str = "did:example:user";

    fn map(entries: &[(&str, Value)]) -> Map {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    fn member(public_read: bool, public_write: bool, apps: Option<Vec<&str>>) -> Policy {
        Policy::Member(MemberPolicy {
            public_read,
            public_write,
            allowed_apps: apps.map(|a| a.into_iter().map(str::to_owned).collect()),
            publish_policy: false,
            publish_members: false,
        })
    }

    const RW: MemberAccess = MemberAccess {
        read: true,
        write: true,
    };
    const R: MemberAccess = MemberAccess {
        read: true,
        write: false,
    };
    const NONE: MemberAccess = MemberAccess {
        read: false,
        write: false,
    };

    #[test]
    fn normalizes_with_defaults_and_drops_unknown_fields() {
        let p = Policy::from_map(&map(&[
            ("$type", Value::Text(MEMBERSPACE_POLICY.into())),
            ("publicRead", Value::Bool(true)),
            ("futureField", Value::Integer(1)),
        ]))
        .unwrap();
        assert_eq!(p, member(true, false, None));
        let m = p.to_map();
        assert_eq!(m.get("publicWrite"), Some(&Value::Bool(false)));
        assert_eq!(m.get("publishMembers"), Some(&Value::Bool(false)));
        assert!(!m.contains_key("futureField"));
        assert!(!m.contains_key("allowedApps"));
        assert_eq!(Policy::from_map(&m).unwrap(), p);
        let personal =
            Policy::from_map(&map(&[("$type", Value::Text(PERSONALSPACE_POLICY.into()))])).unwrap();
        assert_eq!(personal.to_map().len(), 1);
    }

    #[test]
    fn rejects_unsupported_and_malformed() {
        assert_eq!(
            Policy::from_map(&map(&[("$type", Value::Text("com.example.policy".into()))])),
            Err(PolicyError::Unsupported("com.example.policy".into()))
        );
        assert!(Policy::from_map(&Map::new()).is_err());
        assert!(Policy::from_map(&map(&[
            ("$type", Value::Text(MEMBERSPACE_POLICY.into())),
            ("publicRead", Value::Text("yes".into())),
        ]))
        .is_err());
        assert!(Policy::from_map(&map(&[
            ("$type", Value::Text(MEMBERSPACE_POLICY.into())),
            ("allowedApps", Value::Array(vec![Value::Integer(1)])),
        ]))
        .is_err());
        for app in [
            "did:example:app",
            "not-a-did#svc",
            "did:example:app#",
            "https://x#y",
        ] {
            assert!(
                Policy::from_map(&map(&[
                    ("$type", Value::Text(MANAGEDSPACE_POLICY.into())),
                    ("managingApp", Value::Text(app.into())),
                ]))
                .is_err(),
                "{app}"
            );
        }
        let managed = Policy::from_map(&map(&[
            ("$type", Value::Text(MANAGEDSPACE_POLICY.into())),
            (
                "managingApp",
                Value::Text("did:web:app.example.com#umbrae".into()),
            ),
        ]))
        .unwrap();
        assert_eq!(
            managed.to_map().get("managingApp"),
            Some(&Value::Text("did:web:app.example.com#umbrae".into()))
        );
    }

    #[test]
    fn authority_always_allowed() {
        for p in [Policy::Personal, member(false, false, None)] {
            for a in [Access::Read, Access::Write] {
                assert_eq!(
                    authorize_repo(&p, AUTH, Some(AUTH), a, None),
                    Decision::Allow
                );
            }
        }
        let managed = Policy::Managed(ManagedPolicy {
            managing_app: "did:example:app#svc".into(),
            publish_policy: false,
        });
        assert_eq!(
            authorize_repo(&managed, AUTH, Some(AUTH), Access::Read, None),
            Decision::Allow
        );
    }

    #[test]
    fn personalspace_denies_everyone_else() {
        assert_eq!(
            authorize_repo(&Policy::Personal, AUTH, Some(USER), Access::Read, Some(RW)),
            Decision::Deny
        );
        assert_eq!(
            authorize_repo(&Policy::Personal, AUTH, None, Access::Read, None),
            Decision::Deny
        );
    }

    #[test]
    fn memberspace_reads() {
        let p = member(false, false, None);
        assert_eq!(
            authorize_repo(&p, AUTH, Some(USER), Access::Read, Some(R)),
            Decision::Allow
        );
        assert_eq!(
            authorize_repo(&p, AUTH, Some(USER), Access::Read, Some(NONE)),
            Decision::Deny
        );
        assert_eq!(
            authorize_repo(&p, AUTH, Some(USER), Access::Read, None),
            Decision::Deny
        );
        assert_eq!(
            authorize_repo(&p, AUTH, None, Access::Read, None),
            Decision::Deny
        );
        let public = member(true, false, None);
        assert_eq!(
            authorize_repo(&public, AUTH, None, Access::Read, None),
            Decision::Allow
        );
        assert!(!public.requires_delegation());
        assert!(p.requires_delegation());
    }

    #[test]
    fn memberspace_writes() {
        let p = member(false, false, None);
        assert_eq!(
            authorize_repo(&p, AUTH, Some(USER), Access::Write, Some(RW)),
            Decision::Allow
        );
        assert_eq!(
            authorize_repo(&p, AUTH, Some(USER), Access::Write, Some(R)),
            Decision::Deny
        );
        assert_eq!(
            authorize_repo(&p, AUTH, Some(USER), Access::Write, None),
            Decision::Deny
        );
        let pw = member(false, true, None);
        assert_eq!(
            authorize_repo(&pw, AUTH, Some(USER), Access::Write, None),
            Decision::Allow
        );
        // A member without write stays excluded under publicWrite.
        assert_eq!(
            authorize_repo(&pw, AUTH, Some(USER), Access::Write, Some(R)),
            Decision::Deny
        );
    }

    #[test]
    fn managedspace_asks_the_app() {
        let p = Policy::Managed(ManagedPolicy {
            managing_app: "did:example:app#svc".into(),
            publish_policy: true,
        });
        assert_eq!(
            authorize_repo(&p, AUTH, Some(USER), Access::Read, None),
            Decision::AskManagingApp("did:example:app#svc".into())
        );
        // A paid newsletter: subscribers read, only the authority writes.
        let answer = MemberAccess {
            read: true,
            write: false,
        };
        assert!(answer.allows(Access::Read));
        assert!(!answer.allows(Access::Write));
        assert!(p.is_published());
        assert!(!p.members_published());
    }

    #[test]
    fn credentials_check_account_then_app() {
        let open = member(false, false, None);
        assert_eq!(authorize_credential(&open, true, None), Ok(()));
        assert_eq!(
            authorize_credential(&open, false, None),
            Err(CredentialRefusal::SpaceNotFound)
        );
        let gated = member(false, false, Some(vec!["https://app.example/client.json"]));
        assert!(gated.requires_attestation());
        assert_eq!(
            authorize_credential(&gated, true, None),
            Err(CredentialRefusal::AppNotAuthorized)
        );
        assert_eq!(
            authorize_credential(&gated, true, Some("https://other.example/client.json")),
            Err(CredentialRefusal::AppNotAuthorized)
        );
        assert_eq!(
            authorize_credential(&gated, true, Some("https://app.example/client.json")),
            Ok(())
        );
        // The account check comes first, so a refused account learns nothing more.
        assert_eq!(
            authorize_credential(&gated, false, None),
            Err(CredentialRefusal::SpaceNotFound)
        );
    }

    #[test]
    fn migration_and_publishing() {
        let a = member(false, false, None);
        let b = member(true, true, None);
        assert!(!a.is_migration_to(&b));
        assert!(a.is_migration_to(&Policy::Personal));
        let rec = Policy::Personal.policy_record();
        assert_eq!(rec.get("$type"), Some(&Value::Text(POLICY_RECORD.into())));
    }

    #[test]
    fn did_record_keys() {
        assert_eq!(did_to_record_key("did:plc:abc"), "did:plc:abc");
        assert_eq!(
            did_to_record_key("did:web:localhost%3A2583"),
            "did:web:localhost:2583"
        );
        assert_eq!(
            record_key_to_did("did:web:localhost:2583"),
            "did:web:localhost%3A2583"
        );
        assert_eq!(record_key_to_did("did:plc:abc"), "did:plc:abc");
        assert_eq!(
            record_key_to_did("did:web:example.com"),
            "did:web:example.com"
        );
    }

    #[test]
    fn policy_state_round_trip_and_refusals() {
        let p = member(false, false, None);
        let entries = vec![
            member_state_entry("did:example:alice", RW),
            member_state_entry("did:web:localhost%3A2583", R),
        ];
        assert_eq!(
            entries[1].0,
            "com.atproto.memberspace.member/did:web:localhost:2583"
        );
        let parsed = parse_policy_state(&p, &entries).unwrap();
        assert_eq!(
            parsed,
            vec![
                ("did:example:alice".to_owned(), RW),
                ("did:web:localhost%3A2583".to_owned(), R),
            ]
        );
        // State under a policy that keeps none, an unknown key, a bad DID, a bad value.
        assert!(parse_policy_state(&Policy::Personal, &entries).is_err());
        assert!(parse_policy_state(&p, &[("com.example.other/x".into(), RW.to_record())]).is_err());
        assert!(parse_policy_state(
            &p,
            &[(
                "com.atproto.memberspace.member/not-a-did".into(),
                RW.to_record()
            )]
        )
        .is_err());
        let mut bad = RW.to_record();
        bad.remove("write");
        assert!(parse_policy_state(
            &p,
            &[("com.atproto.memberspace.member/did:example:a".into(), bad)]
        )
        .is_err());
    }
}
