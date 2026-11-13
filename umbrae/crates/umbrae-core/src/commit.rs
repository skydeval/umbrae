//! Space repo commits (spec: "Space repos", "Commit MAC").
//!
//! A commit is `{ver, repo, space, rev, data}`, where `data` is
//! `sha256` of the repo's set-hash state. It carries no signature; the repo
//! host authenticates it to each syncer with a MAC over the
//! `Atproto-Space-Commit` header, a Structured Field Dictionary holding the
//! same five fields. The MAC itself is built elsewhere; this module builds
//! and reads the header, and checks a commit against the request.

use crate::cid::Cid;
use crate::drisl::Value;
use crate::lthash::LtHash;
use crate::uri::{is_valid_did, is_valid_nsid, is_valid_record_key, is_valid_tid, SpaceRef};
use sfv::{DictSerializer, Dictionary, KeyRef, ListEntry, Parser, StringRef};
use std::collections::BTreeMap;
use std::fmt;

/// The only commit format version.
pub const COMMIT_VERSION: i64 = 1;

/// The header a commit MAC covers (lowercase, as HTTP field names compare).
pub const COMMIT_HEADER: &str = "atproto-space-commit";

/// One repo, in one space, at one revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    ver: i64,
    repo: String,
    space: SpaceRef,
    rev: String,
    data: [u8; 32],
}

/// Why a commit is malformed, or doesn't match what was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError {
    UnsupportedVersion(i64),
    InvalidRepo,
    InvalidSpace,
    InvalidRev,
    /// `data` isn't 32 bytes.
    InvalidData,
    /// A required field is absent or has the wrong type.
    MissingField(&'static str),
    /// The commit is for another repo than the one requested.
    WrongRepo,
    /// The commit is for another space than the one requested.
    WrongSpace,
    /// The `Atproto-Space-Commit` header isn't a valid Structured Field
    /// Dictionary.
    MalformedHeader,
    /// The header describes a different commit.
    HeaderMismatch,
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitError::UnsupportedVersion(v) => write!(f, "unsupported commit version: {v}"),
            CommitError::InvalidRepo => f.write_str("commit repo is not a DID"),
            CommitError::InvalidSpace => f.write_str("commit space is not a space URI"),
            CommitError::InvalidRev => f.write_str("commit rev is not a TID"),
            CommitError::InvalidData => f.write_str("commit data must be 32 bytes"),
            CommitError::MissingField(n) => write!(f, "commit field missing or mistyped: {n}"),
            CommitError::WrongRepo => f.write_str("commit is for another repo"),
            CommitError::WrongSpace => f.write_str("commit is for another space"),
            CommitError::MalformedHeader => f.write_str("malformed Atproto-Space-Commit header"),
            CommitError::HeaderMismatch => {
                f.write_str("Atproto-Space-Commit header does not match the commit")
            }
        }
    }
}

impl std::error::Error for CommitError {}

impl Commit {
    /// A version-1 commit over a set hash's current contents.
    pub fn new(
        repo: &str,
        space: SpaceRef,
        rev: &str,
        set_hash: &LtHash,
    ) -> Result<Self, CommitError> {
        Self::from_parts(COMMIT_VERSION, repo, space, rev, set_hash.digest())
    }

    /// A commit from its fields, validated. Rejects versions other than 1.
    pub fn from_parts(
        ver: i64,
        repo: &str,
        space: SpaceRef,
        rev: &str,
        data: [u8; 32],
    ) -> Result<Self, CommitError> {
        if ver != COMMIT_VERSION {
            return Err(CommitError::UnsupportedVersion(ver));
        }
        if !is_valid_did(repo) {
            return Err(CommitError::InvalidRepo);
        }
        if !is_valid_tid(rev) {
            return Err(CommitError::InvalidRev);
        }
        Ok(Self {
            ver,
            repo: repo.to_owned(),
            space,
            rev: rev.to_owned(),
            data,
        })
    }

    pub fn ver(&self) -> i64 {
        self.ver
    }

    pub fn repo(&self) -> &str {
        &self.repo
    }

    pub fn space(&self) -> &SpaceRef {
        &self.space
    }

    pub fn rev(&self) -> &str {
        &self.rev
    }

    pub fn data(&self) -> &[u8; 32] {
        &self.data
    }

    /// Whether a set hash's contents match this commit. Only meaningful
    /// once the commit itself is authenticated.
    pub fn matches(&self, set_hash: &LtHash) -> bool {
        set_hash.digest() == self.data
    }

    /// Check the commit is for the repo and space that were requested.
    pub fn check_for(&self, repo: &str, space: &SpaceRef) -> Result<(), CommitError> {
        if self.repo != repo {
            return Err(CommitError::WrongRepo);
        }
        if &self.space != space {
            return Err(CommitError::WrongSpace);
        }
        Ok(())
    }

    /// The commit's fields as a DRISL map. Archive metadata adds `$type`.
    pub fn to_value(&self) -> Value {
        Value::Map(self.fields())
    }

    /// The five fields, for embedding in a larger map.
    pub fn fields(&self) -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("ver".to_owned(), Value::Integer(self.ver)),
            ("repo".to_owned(), Value::Text(self.repo.clone())),
            ("space".to_owned(), Value::Text(self.space.to_string())),
            ("rev".to_owned(), Value::Text(self.rev.clone())),
            ("data".to_owned(), Value::Bytes(self.data.to_vec())),
        ])
    }

    /// Read a commit from a DRISL map. Other keys are left to the caller.
    pub fn from_fields(map: &BTreeMap<String, Value>) -> Result<Self, CommitError> {
        let ver = map
            .get("ver")
            .and_then(Value::as_integer)
            .ok_or(CommitError::MissingField("ver"))?;
        let repo = map
            .get("repo")
            .and_then(Value::as_text)
            .ok_or(CommitError::MissingField("repo"))?;
        let space = map
            .get("space")
            .and_then(Value::as_text)
            .ok_or(CommitError::MissingField("space"))?;
        let rev = map
            .get("rev")
            .and_then(Value::as_text)
            .ok_or(CommitError::MissingField("rev"))?;
        let data = map
            .get("data")
            .and_then(Value::as_bytes)
            .ok_or(CommitError::MissingField("data"))?;
        let data: [u8; 32] = data.try_into().map_err(|_| CommitError::InvalidData)?;
        if ver != COMMIT_VERSION {
            return Err(CommitError::UnsupportedVersion(ver));
        }
        let space = SpaceRef::parse(space).map_err(|_| CommitError::InvalidSpace)?;
        Self::from_parts(ver, repo, space, rev, data)
    }

    /// The `Atproto-Space-Commit` header value, e.g.
    /// `ver=1, repo="did:…", space="at://…", rev="3mwcj3b6uak2f", data=:…=:`.
    pub fn header(&self) -> String {
        let space = self.space.to_string();
        let mut ser = DictSerializer::new();
        // Every field is validated ASCII without control characters, so
        // these conversions can't fail.
        // `ver` is always 1, well inside the sf-integer range.
        let _ = ser.bare_item(key("ver"), sfv::integer(self.ver));
        let _ = ser.bare_item(key("repo"), sf_string(&self.repo));
        let _ = ser.bare_item(key("space"), sf_string(&space));
        let _ = ser.bare_item(key("rev"), sf_string(&self.rev));
        let _ = ser.bare_item(key("data"), &self.data[..]);
        ser.finish().expect("five members")
    }

    /// Check that an `Atproto-Space-Commit` header describes this commit.
    /// Members are compared by value, ignoring parameters and any other
    /// members, as the reference implementation does.
    pub fn check_header(&self, value: &str) -> Result<(), CommitError> {
        let dict = parse_dictionary(value)?;
        let space = self.space.to_string();
        let matches = bare(&dict, "ver")
            .and_then(|b| b.as_integer())
            .map(i64::from)
            == Some(self.ver)
            && bare(&dict, "repo")
                .and_then(|b| b.as_string())
                .map(|s| s.as_str())
                == Some(self.repo.as_str())
            && bare(&dict, "space")
                .and_then(|b| b.as_string())
                .map(|s| s.as_str())
                == Some(space.as_str())
            && bare(&dict, "rev")
                .and_then(|b| b.as_string())
                .map(|s| s.as_str())
                == Some(self.rev.as_str())
            && bare(&dict, "data").and_then(|b| b.as_byte_sequence()) == Some(&self.data[..]);
        if matches {
            Ok(())
        } else {
            Err(CommitError::HeaderMismatch)
        }
    }
}

fn key(name: &'static str) -> &'static KeyRef {
    KeyRef::from_str(name).expect("static key is valid")
}

fn sf_string(s: &str) -> &StringRef {
    StringRef::from_str(s).expect("validated field is a valid sf-string")
}

/// Parse a header as a Structured Field Dictionary.
pub(crate) fn parse_dictionary(value: &str) -> Result<Dictionary, CommitError> {
    Parser::new(value)
        .parse::<Dictionary>()
        .map_err(|_| CommitError::MalformedHeader)
}

/// A dictionary member's bare item, if it's an item rather than an inner
/// list.
fn bare<'a>(dict: &'a Dictionary, name: &str) -> Option<&'a sfv::BareItem> {
    match dict.get(name) {
        Some(ListEntry::Item(item)) => Some(&item.bare_item),
        _ => None,
    }
}

/// One write to a repo, as an operation log entry carries it. A create has
/// no `prev`, a delete no `cid`, an update both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoOp {
    pub collection: String,
    pub rkey: String,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
}

/// Why a repo operation can't be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    InvalidCollection,
    InvalidRkey,
    /// Neither `cid` nor `prev`.
    Empty,
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OpError::InvalidCollection => "op collection is not an NSID",
            OpError::InvalidRkey => "op rkey is not a record key",
            OpError::Empty => "op has neither cid nor prev",
        };
        f.write_str(s)
    }
}

impl std::error::Error for OpError {}

impl LtHash {
    /// Fold a record in, by its path and CID.
    pub fn add_record_cid(&mut self, collection: &str, rkey: &str, cid: &Cid) -> &mut Self {
        self.add_record(collection, rkey, &cid.to_string())
    }

    /// Take a record out, by its path and CID.
    pub fn remove_record_cid(&mut self, collection: &str, rkey: &str, cid: &Cid) -> &mut Self {
        self.remove_record(collection, rkey, &cid.to_string())
    }

    /// Apply one operation: remove `prev`, then add `cid`.
    ///
    /// The path is validated, since the element format relies on the
    /// collection and CID being slash-free to stay unambiguous.
    pub fn apply_op(&mut self, op: &RepoOp) -> Result<&mut Self, OpError> {
        if !is_valid_nsid(&op.collection) {
            return Err(OpError::InvalidCollection);
        }
        if !is_valid_record_key(&op.rkey) {
            return Err(OpError::InvalidRkey);
        }
        if op.cid.is_none() && op.prev.is_none() {
            return Err(OpError::Empty);
        }
        if let Some(prev) = &op.prev {
            self.remove_record_cid(&op.collection, &op.rkey, prev);
        }
        if let Some(cid) = &op.cid {
            self.add_record_cid(&op.collection, &op.rkey, cid);
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drisl;

    // From the reference tests: CIDs of `{ text: 'hello' }` and `{ text: 'world' }`.
    fn cid_a() -> Cid {
        Cid::parse("bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244").unwrap()
    }
    fn cid_b() -> Cid {
        Cid::parse("bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a").unwrap()
    }

    const SPACE: &str = "at://did:example:space/space/app.bsky.group/test";
    const REPO: &str = "did:example:alice";
    // The reference tests use `3kbcq3p7ad400`, which isn't a valid TID.
    const REV: &str = "3kbcq3p7ad422";

    fn space() -> SpaceRef {
        SpaceRef::parse(SPACE).unwrap()
    }

    fn ones() -> Commit {
        Commit::from_parts(1, REPO, space(), REV, [1; 32]).unwrap()
    }

    #[test]
    fn header_matches_reference_format() {
        // The reference mac test's covered header, with a valid rev.
        assert_eq!(
            ones().header(),
            format!(
                "ver=1, repo=\"{REPO}\", space=\"{SPACE}\", rev=\"{REV}\", \
                 data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:"
            )
        );
    }

    #[test]
    fn header_round_trips_and_tolerates_whitespace() {
        let c = ones();
        c.check_header(&c.header()).unwrap();
        c.check_header(&c.header().replace(", ", ",   ")).unwrap();
        // Parameters and extra members are ignored.
        let extra = format!("{};x=1, other=?1", c.header());
        c.check_header(&extra).unwrap();
    }

    #[test]
    fn header_rejects_other_commits() {
        let c = ones();
        let header = c.header();
        let others = [
            Commit::from_parts(1, "did:example:bob", space(), REV, [1; 32]).unwrap(),
            Commit::from_parts(
                1,
                REPO,
                SpaceRef::parse("at://did:example:space/space/app.bsky.group/other").unwrap(),
                REV,
                [1; 32],
            )
            .unwrap(),
            Commit::from_parts(1, REPO, space(), "3kbcq3p7ad423", [1; 32]).unwrap(),
            Commit::from_parts(1, REPO, space(), REV, [2; 32]).unwrap(),
        ];
        for other in others {
            assert_eq!(
                other.check_header(&header),
                Err(CommitError::HeaderMismatch)
            );
        }
        // A field with the wrong type.
        let as_token = header.replace("ver=1", "ver=\"1\"");
        assert_eq!(c.check_header(&as_token), Err(CommitError::HeaderMismatch));
        // A missing field.
        let missing = header.replace(&format!("rev=\"{REV}\", "), "");
        assert_eq!(c.check_header(&missing), Err(CommitError::HeaderMismatch));
        assert_eq!(c.check_header("???"), Err(CommitError::MalformedHeader));
    }

    #[test]
    fn empty_repo_commit() {
        let c = Commit::new(REPO, space(), REV, &LtHash::new()).unwrap();
        assert_eq!(
            c.data()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"
        );
        assert!(c.matches(&LtHash::new()));
    }

    #[test]
    fn validates_fields() {
        assert_eq!(
            Commit::from_parts(2, REPO, space(), REV, [0; 32]),
            Err(CommitError::UnsupportedVersion(2))
        );
        assert_eq!(
            Commit::from_parts(1, "alice.example.com", space(), REV, [0; 32]),
            Err(CommitError::InvalidRepo)
        );
        assert_eq!(
            Commit::from_parts(1, REPO, space(), "3kbcq3p7ad400", [0; 32]),
            Err(CommitError::InvalidRev)
        );
    }

    #[test]
    fn check_for_request() {
        let c = ones();
        c.check_for(REPO, &space()).unwrap();
        assert_eq!(
            c.check_for("did:example:bob", &space()),
            Err(CommitError::WrongRepo)
        );
        let other = SpaceRef::parse("at://did:example:space/space/app.bsky.group/other").unwrap();
        assert_eq!(c.check_for(REPO, &other), Err(CommitError::WrongSpace));
    }

    #[test]
    fn drisl_round_trip() {
        let c = ones();
        let bytes = drisl::encode(&c.to_value()).unwrap();
        // Keys in DRISL order: rev, ver, data, repo, space.
        assert_eq!(&bytes[..5], &[0xa5, 0x63, b'r', b'e', b'v']);
        let v = drisl::decode(&bytes).unwrap();
        assert_eq!(Commit::from_fields(v.as_map().unwrap()).unwrap(), c);
    }

    #[test]
    fn from_fields_rejects_bad_maps() {
        let mut m = ones().fields();
        m.insert("data".into(), Value::Bytes(vec![0; 31]));
        assert_eq!(Commit::from_fields(&m), Err(CommitError::InvalidData));
        let mut m = ones().fields();
        m.insert("ver".into(), Value::Integer(2));
        assert_eq!(
            Commit::from_fields(&m),
            Err(CommitError::UnsupportedVersion(2))
        );
        let mut m = ones().fields();
        m.insert(
            "space".into(),
            Value::Text("at://did:example:x/app.bsky.feed.post/k".into()),
        );
        assert_eq!(Commit::from_fields(&m), Err(CommitError::InvalidSpace));
        let mut m = ones().fields();
        m.remove("rev");
        assert_eq!(
            Commit::from_fields(&m),
            Err(CommitError::MissingField("rev"))
        );
        let mut m = ones().fields();
        m.insert("repo".into(), Value::Integer(1));
        assert_eq!(
            Commit::from_fields(&m),
            Err(CommitError::MissingField("repo"))
        );
    }

    fn op(cid: Option<Cid>, prev: Option<Cid>) -> RepoOp {
        RepoOp {
            collection: "n.c.a".into(),
            rkey: "1".into(),
            cid,
            prev,
        }
    }

    #[test]
    fn ops_create_update_delete() {
        let mut h = LtHash::new();
        h.apply_op(&op(Some(cid_a()), None)).unwrap();
        let mut direct = LtHash::new();
        direct.add_record_cid("n.c.a", "1", &cid_a());
        assert_eq!(h, direct);
        h.apply_op(&op(Some(cid_b()), Some(cid_a()))).unwrap();
        let mut updated = LtHash::new();
        updated.add_record_cid("n.c.a", "1", &cid_b());
        assert_eq!(h, updated);
        h.apply_op(&op(None, Some(cid_b()))).unwrap();
        assert!(h.is_empty());
    }

    #[test]
    fn ops_converge_in_any_order() {
        let ops = [
            op(Some(cid_a()), None),
            RepoOp {
                collection: "n.c.b".into(),
                rkey: "2".into(),
                cid: Some(cid_b()),
                prev: None,
            },
        ];
        let mut fwd = LtHash::new();
        let mut back = LtHash::new();
        for o in &ops {
            fwd.apply_op(o).unwrap();
        }
        for o in ops.iter().rev() {
            back.apply_op(o).unwrap();
        }
        assert_eq!(fwd, back);
    }

    #[test]
    fn element_is_path_and_cid_string() {
        let mut h = LtHash::new();
        h.add_record_cid("n.c.a", "1", &cid_a());
        let mut raw = LtHash::new();
        raw.add(format!("n.c.a/1/{}", cid_a()).as_bytes());
        assert_eq!(h, raw);
        // Same CID at another path, and another CID at the same path, differ.
        let mut other_path = LtHash::new();
        other_path.add_record_cid("n.c.a", "2", &cid_a());
        assert_ne!(h, other_path);
        let mut other_cid = LtHash::new();
        other_cid.add_record_cid("n.c.a", "1", &cid_b());
        assert_ne!(h, other_cid);
    }

    #[test]
    fn ops_validate_paths() {
        let mut h = LtHash::new();
        let mut bad = op(Some(cid_a()), None);
        bad.collection = "n/c.a".into();
        assert_eq!(h.apply_op(&bad).unwrap_err(), OpError::InvalidCollection);
        let mut bad = op(Some(cid_a()), None);
        bad.rkey = "a/b".into();
        assert_eq!(h.apply_op(&bad).unwrap_err(), OpError::InvalidRkey);
        assert_eq!(h.apply_op(&op(None, None)).unwrap_err(), OpError::Empty);
        assert!(h.is_empty());
    }
}
