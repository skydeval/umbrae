//! The `atproto-space-meta` STAR profile (spec: "Space meta archive").
//!
//! A space authority's host-side state for one space, carried between hosts
//! on account migration. The metadata is
//! `{$type: "atproto-space-meta", ver: 1, space}`; the body has three
//! sections, in this order, each in strict byte order of its keys:
//!
//! 1. `policy`: the space's policy object;
//! 2. policy state: other config the policy keeps (such as a member list),
//!    keyed like record paths, with values the policy defines;
//! 3. `writer/{did}`: one entry per repo in the writer set.
//!
//! This module checks the structure only. Whether the policy and its state
//! keys are ones the importing host implements is for the policy code to
//! decide, and it must reject what it doesn't recognise.

use crate::drisl::{self, Value};
use crate::star::{self, StarError, StarLimits};
use crate::uri::{is_valid_did, is_valid_tid, SpaceRef};
use std::collections::BTreeMap;
use std::fmt;

/// The profile's `$type`.
pub const SPACE_META_STAR_TYPE: &str = "atproto-space-meta";
/// The only space meta format version.
pub const SPACE_META_VERSION: i64 = 1;

const POLICY_KEY: &str = "policy";
const WRITER_PREFIX: &str = "writer/";

/// A DRISL map.
pub type Map = BTreeMap<String, Value>;

/// A repo in the writer set, as `listWriters` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writer {
    pub did: String,
    pub repo_rev: String,
    pub data: [u8; 32],
    pub space_rev: String,
}

/// A decoded space meta archive.
#[derive(Debug, Clone, PartialEq)]
pub struct SpaceMetaArchive {
    pub space: SpaceRef,
    pub policy: Map,
    /// Policy state entries: key and value.
    pub policy_state: Vec<(String, Map)>,
    pub writers: Vec<Writer>,
}

/// Why a space meta archive is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceMetaError {
    Star(StarError),
    WrongType,
    UnsupportedVersion,
    InvalidSpace,
    /// No `policy` entry.
    MissingPolicy,
    /// A section after a later one.
    SectionOrder,
    /// A key duplicated or out of order within its section.
    KeyOrder,
    /// A key that isn't UTF-8.
    InvalidKey,
    /// A value that isn't a canonical DRISL map.
    InvalidValue,
    /// A writer entry with a bad DID, revision or digest.
    InvalidWriter,
}

impl fmt::Display for SpaceMetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceMetaError::Star(e) => write!(f, "{e}"),
            SpaceMetaError::WrongType => f.write_str("archive is not an atproto-space-meta"),
            SpaceMetaError::UnsupportedVersion => f.write_str("unsupported space meta version"),
            SpaceMetaError::InvalidSpace => f.write_str("space meta has an invalid space ref"),
            SpaceMetaError::MissingPolicy => f.write_str("space meta archive has no policy"),
            SpaceMetaError::SectionOrder => f.write_str("space meta sections out of order"),
            SpaceMetaError::KeyOrder => f.write_str("space meta keys duplicated or out of order"),
            SpaceMetaError::InvalidKey => f.write_str("space meta key is not UTF-8"),
            SpaceMetaError::InvalidValue => f.write_str("space meta value is not a DRISL map"),
            SpaceMetaError::InvalidWriter => f.write_str("invalid writer entry"),
        }
    }
}

impl std::error::Error for SpaceMetaError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    Policy,
    PolicyState,
    Writers,
}

fn section_of(key: &str) -> Section {
    if key == POLICY_KEY {
        Section::Policy
    } else if key.starts_with(WRITER_PREFIX) {
        Section::Writers
    } else {
        Section::PolicyState
    }
}

impl SpaceMetaArchive {
    /// Encode, putting each section into key order.
    pub fn encode(&self) -> Result<Vec<u8>, SpaceMetaError> {
        let meta = Map::from([
            (
                "$type".to_owned(),
                Value::Text(SPACE_META_STAR_TYPE.to_owned()),
            ),
            ("ver".to_owned(), Value::Integer(SPACE_META_VERSION)),
            ("space".to_owned(), Value::Text(self.space.to_string())),
        ]);
        let encode_map = |m: &Map| {
            drisl::encode(&Value::Map(m.clone())).map_err(|_| SpaceMetaError::InvalidValue)
        };

        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> =
            vec![(POLICY_KEY.into(), encode_map(&self.policy)?)];

        let mut state = Vec::with_capacity(self.policy_state.len());
        for (k, v) in &self.policy_state {
            if section_of(k) != Section::PolicyState {
                return Err(SpaceMetaError::SectionOrder);
            }
            state.push((k.as_bytes().to_vec(), encode_map(v)?));
        }
        state.sort_by(|a, b| a.0.cmp(&b.0));

        let mut writers = Vec::with_capacity(self.writers.len());
        for w in &self.writers {
            if !is_valid_did(&w.did) || !is_valid_tid(&w.repo_rev) || !is_valid_tid(&w.space_rev) {
                return Err(SpaceMetaError::InvalidWriter);
            }
            let v = Map::from([
                ("repoRev".to_owned(), Value::Text(w.repo_rev.clone())),
                ("data".to_owned(), Value::Bytes(w.data.to_vec())),
                ("spaceRev".to_owned(), Value::Text(w.space_rev.clone())),
            ]);
            writers.push((
                format!("{WRITER_PREFIX}{}", w.did).into_bytes(),
                encode_map(&v)?,
            ));
        }
        writers.sort_by(|a, b| a.0.cmp(&b.0));

        for section in [&state, &writers] {
            if section.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(SpaceMetaError::KeyOrder);
            }
        }
        pairs.extend(state);
        pairs.extend(writers);
        star::write_star(
            &meta,
            pairs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        )
        .map_err(SpaceMetaError::Star)
    }

    /// Decode a whole archive. Read whole, since it holds a space's
    /// configuration and writer set, not its records.
    pub fn decode(bytes: &[u8]) -> Result<Self, SpaceMetaError> {
        let (meta, pairs) =
            star::read_star(bytes, StarLimits::SPACES).map_err(SpaceMetaError::Star)?;
        if meta.get("$type").and_then(Value::as_text) != Some(SPACE_META_STAR_TYPE) {
            return Err(SpaceMetaError::WrongType);
        }
        if meta.get("ver").and_then(Value::as_integer) != Some(SPACE_META_VERSION) {
            return Err(SpaceMetaError::UnsupportedVersion);
        }
        let space = meta
            .get("space")
            .and_then(Value::as_text)
            .and_then(|s| SpaceRef::parse(s).ok())
            .ok_or(SpaceMetaError::InvalidSpace)?;

        let mut policy = None;
        let mut policy_state = Vec::new();
        let mut writers = Vec::new();
        let mut section: Option<Section> = None;
        let mut prev: Option<&[u8]> = None;

        for (k, v) in &pairs {
            let key = std::str::from_utf8(k).map_err(|_| SpaceMetaError::InvalidKey)?;
            let s = section_of(key);
            if section != Some(s) {
                if section.is_some_and(|cur| s < cur) {
                    return Err(SpaceMetaError::SectionOrder);
                }
                section = Some(s);
                prev = None;
            }
            if prev.is_some_and(|p| k.as_slice() <= p) {
                return Err(SpaceMetaError::KeyOrder);
            }
            prev = Some(k);

            let Ok(Value::Map(value)) = drisl::decode(v) else {
                return Err(SpaceMetaError::InvalidValue);
            };
            match s {
                Section::Policy => policy = Some(value),
                Section::PolicyState => policy_state.push((key.to_owned(), value)),
                Section::Writers => {
                    writers.push(parse_writer(&key[WRITER_PREFIX.len()..], &value)?)
                }
            }
        }
        Ok(Self {
            space,
            policy: policy.ok_or(SpaceMetaError::MissingPolicy)?,
            policy_state,
            writers,
        })
    }
}

fn parse_writer(did: &str, value: &Map) -> Result<Writer, SpaceMetaError> {
    let text = |k: &str| value.get(k).and_then(Value::as_text);
    let (Some(repo_rev), Some(space_rev)) = (text("repoRev"), text("spaceRev")) else {
        return Err(SpaceMetaError::InvalidWriter);
    };
    let data: [u8; 32] = value
        .get("data")
        .and_then(Value::as_bytes)
        .and_then(|d| d.try_into().ok())
        .ok_or(SpaceMetaError::InvalidWriter)?;
    if !is_valid_did(did) || !is_valid_tid(repo_rev) || !is_valid_tid(space_rev) {
        return Err(SpaceMetaError::InvalidWriter);
    }
    Ok(Writer {
        did: did.to_owned(),
        repo_rev: repo_rev.to_owned(),
        data,
        space_rev: space_rev.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: &str = "at:space/did:example:forum/com.atmoboards.forum/general";

    fn member(read: bool, write: bool) -> Map {
        Map::from([
            (
                "$type".to_owned(),
                Value::Text("com.atproto.memberspace.member".into()),
            ),
            ("read".to_owned(), Value::Bool(read)),
            ("write".to_owned(), Value::Bool(write)),
        ])
    }

    fn writer(did: &str) -> Writer {
        Writer {
            did: did.into(),
            repo_rev: "3mwdjaaaaaaaa".into(),
            data: [7; 32],
            space_rev: "3mwdkaaaaaaaa".into(),
        }
    }

    fn sample() -> SpaceMetaArchive {
        SpaceMetaArchive {
            space: SpaceRef::parse(SPACE).unwrap(),
            policy: Map::from([
                (
                    "$type".to_owned(),
                    Value::Text("com.atproto.memberspace.policy".into()),
                ),
                ("publicRead".to_owned(), Value::Bool(false)),
            ]),
            // Given out of order; encoding sorts.
            policy_state: vec![
                (
                    "com.atproto.memberspace.member/did:example:carol".into(),
                    member(true, false),
                ),
                (
                    "com.atproto.memberspace.member/did:example:alice".into(),
                    member(true, true),
                ),
                (
                    "com.atproto.memberspace.member/did:example:bob".into(),
                    member(true, true),
                ),
            ],
            writers: vec![writer("did:example:bob"), writer("did:example:alice")],
        }
    }

    fn keys(bytes: &[u8]) -> Vec<String> {
        let (_, pairs) = star::read_star(bytes, StarLimits::SPACES).unwrap();
        pairs
            .into_iter()
            .map(|(k, _)| String::from_utf8(k).unwrap())
            .collect()
    }

    #[test]
    fn round_trip_in_section_and_key_order() {
        let a = sample();
        let bytes = a.encode().unwrap();
        assert_eq!(
            keys(&bytes),
            [
                "policy",
                "com.atproto.memberspace.member/did:example:alice",
                "com.atproto.memberspace.member/did:example:bob",
                "com.atproto.memberspace.member/did:example:carol",
                "writer/did:example:alice",
                "writer/did:example:bob",
            ]
        );
        let back = SpaceMetaArchive::decode(&bytes).unwrap();
        assert_eq!(back.space, a.space);
        assert_eq!(back.policy, a.policy);
        assert_eq!(back.policy_state.len(), 3);
        assert_eq!(
            back.policy_state[0].0,
            "com.atproto.memberspace.member/did:example:alice"
        );
        assert_eq!(
            back.writers,
            vec![writer("did:example:alice"), writer("did:example:bob")]
        );
    }

    fn meta() -> Map {
        Map::from([
            ("$type".to_owned(), Value::Text(SPACE_META_STAR_TYPE.into())),
            ("ver".to_owned(), Value::Integer(1)),
            ("space".to_owned(), Value::Text(SPACE.into())),
        ])
    }

    fn raw(meta: &Map, pairs: &[(&str, Map)]) -> Vec<u8> {
        let enc: Vec<(Vec<u8>, Vec<u8>)> = pairs
            .iter()
            .map(|(k, v)| {
                (
                    k.as_bytes().to_vec(),
                    drisl::encode(&Value::Map(v.clone())).unwrap(),
                )
            })
            .collect();
        star::write_star(meta, enc.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))).unwrap()
    }

    fn writer_value() -> Map {
        Map::from([
            ("repoRev".to_owned(), Value::Text("3mwdjaaaaaaaa".into())),
            ("data".to_owned(), Value::Bytes(vec![7; 32])),
            ("spaceRev".to_owned(), Value::Text("3mwdkaaaaaaaa".into())),
        ])
    }

    #[test]
    fn policy_state_keys_may_sort_before_policy() {
        // Sections order the body, not overall byte order: "a.b.c/x" sorts
        // before "policy" but belongs after it.
        let s = raw(&meta(), &[("policy", Map::new()), ("a.b.c/x", Map::new())]);
        assert_eq!(SpaceMetaArchive::decode(&s).unwrap().policy_state.len(), 1);
    }

    #[test]
    fn rejects_structure_errors() {
        let m = meta();
        let cases: Vec<(Vec<(&str, Map)>, SpaceMetaError)> = vec![
            (vec![], SpaceMetaError::MissingPolicy),
            (vec![("a.b.c/x", Map::new())], SpaceMetaError::MissingPolicy),
            (
                vec![("a.b.c/x", Map::new()), ("policy", Map::new())],
                SpaceMetaError::SectionOrder,
            ),
            (
                vec![
                    ("policy", Map::new()),
                    ("writer/did:example:a", writer_value()),
                    ("a.b.c/x", Map::new()),
                ],
                SpaceMetaError::SectionOrder,
            ),
            (
                vec![("policy", Map::new()), ("policy", Map::new())],
                SpaceMetaError::KeyOrder,
            ),
            (
                vec![
                    ("policy", Map::new()),
                    ("a.b.c/y", Map::new()),
                    ("a.b.c/x", Map::new()),
                ],
                SpaceMetaError::KeyOrder,
            ),
            (
                vec![
                    ("policy", Map::new()),
                    ("writer/did:example:a", writer_value()),
                    ("writer/did:example:a", writer_value()),
                ],
                SpaceMetaError::KeyOrder,
            ),
            (
                vec![("policy", Map::new()), ("writer/not-a-did", writer_value())],
                SpaceMetaError::InvalidWriter,
            ),
        ];
        for (pairs, err) in cases {
            assert_eq!(
                SpaceMetaArchive::decode(&raw(&m, &pairs)),
                Err(err.clone()),
                "{err}"
            );
        }
        let mut short = writer_value();
        short.insert("data".into(), Value::Bytes(vec![0; 31]));
        let s = raw(
            &m,
            &[("policy", Map::new()), ("writer/did:example:a", short)],
        );
        assert_eq!(
            SpaceMetaArchive::decode(&s),
            Err(SpaceMetaError::InvalidWriter)
        );
    }

    #[test]
    fn rejects_bad_metadata_and_values() {
        let mut m = meta();
        m.insert(
            "$type".into(),
            Value::Text(crate::repo_archive::REPO_STAR_TYPE.into()),
        );
        assert_eq!(
            SpaceMetaArchive::decode(&raw(&m, &[("policy", Map::new())])),
            Err(SpaceMetaError::WrongType)
        );
        let mut m = meta();
        m.insert("ver".into(), Value::Integer(2));
        assert_eq!(
            SpaceMetaArchive::decode(&raw(&m, &[("policy", Map::new())])),
            Err(SpaceMetaError::UnsupportedVersion)
        );
        let mut m = meta();
        m.insert(
            "space".into(),
            Value::Text("at://did:example:x/app.bsky.feed.post/k".into()),
        );
        assert_eq!(
            SpaceMetaArchive::decode(&raw(&m, &[("policy", Map::new())])),
            Err(SpaceMetaError::InvalidSpace)
        );
        // A policy value that isn't a map.
        let not_map = drisl::encode(&Value::Integer(1)).unwrap();
        let s = star::write_star(&meta(), [(b"policy".as_slice(), not_map.as_slice())]).unwrap();
        assert_eq!(
            SpaceMetaArchive::decode(&s),
            Err(SpaceMetaError::InvalidValue)
        );
    }

    #[test]
    fn encode_rejects_misplaced_or_duplicate_state() {
        let mut a = sample();
        a.policy_state
            .push(("writer/did:example:x".into(), Map::new()));
        assert_eq!(a.encode(), Err(SpaceMetaError::SectionOrder));
        let mut a = sample();
        a.writers.push(writer("did:example:alice"));
        assert_eq!(a.encode(), Err(SpaceMetaError::KeyOrder));
        let mut a = sample();
        a.policy_state.push(("policy".into(), Map::new()));
        assert_eq!(a.encode(), Err(SpaceMetaError::SectionOrder));
    }
}
