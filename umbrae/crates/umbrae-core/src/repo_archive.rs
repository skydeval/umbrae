//! The `atproto-space-repo` STAR profile (spec: "Repo serialization").
//!
//! The metadata is the commit plus `$type: "atproto-space-repo"`. Each pair
//! is a record: key `{collection}/{rkey}`, value the record's canonical
//! DRISL encoding, in strict byte order of the keys with no duplicates.
//!
//! Reading verifies as it streams: every path and record is checked, each
//! record's CID is folded into a running set hash, and at the end the hash
//! must equal the commit's `data`. Records seen before that final check
//! are not yet trustworthy; a caller keeps them provisional until
//! [`RepoEvent::Complete`]. Authenticating the commit itself (its MAC) is
//! the caller's job, before relying on any of it.

use crate::cid::Cid;
use crate::commit::{Commit, CommitError};
use crate::drisl::{self, DrislError, Value};
use crate::lthash::LtHash;
use crate::star::{self, StarDecoder, StarError, StarEvent, StarLimits};
use crate::uri::{is_valid_nsid, is_valid_record_key};
use std::collections::BTreeMap;
use std::fmt;

/// The profile's `$type`.
pub const REPO_STAR_TYPE: &str = "atproto-space-repo";

/// Why a repo archive is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoArchiveError {
    Star(StarError),
    /// `$type` isn't `atproto-space-repo`.
    WrongType,
    /// The metadata isn't a valid commit.
    Commit(CommitError),
    /// A key isn't a valid `{collection}/{rkey}`.
    InvalidPath,
    /// A key is duplicated or out of byte order.
    OutOfOrder,
    /// A value isn't a canonical DRISL map within the size limit.
    InvalidRecord(DrislError),
    /// The records don't hash to the commit's `data`.
    DigestMismatch,
}

impl fmt::Display for RepoArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepoArchiveError::Star(e) => write!(f, "{e}"),
            RepoArchiveError::WrongType => f.write_str("archive is not an atproto-space-repo"),
            RepoArchiveError::Commit(e) => write!(f, "invalid repo metadata: {e}"),
            RepoArchiveError::InvalidPath => f.write_str("invalid record path"),
            RepoArchiveError::OutOfOrder => f.write_str("records duplicated or out of order"),
            RepoArchiveError::InvalidRecord(e) => write!(f, "invalid record: {e}"),
            RepoArchiveError::DigestMismatch => f.write_str("records do not match the commit data"),
        }
    }
}

impl std::error::Error for RepoArchiveError {}

impl From<StarError> for RepoArchiveError {
    fn from(e: StarError) -> Self {
        RepoArchiveError::Star(e)
    }
}

/// A record read from an archive, with its computed CID.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchivedRecord {
    pub collection: String,
    pub rkey: String,
    pub cid: Cid,
    /// The record's canonical DRISL bytes, as stored.
    pub bytes: Vec<u8>,
    pub value: BTreeMap<String, Value>,
}

/// What the reader found next.
#[derive(Debug, Clone, PartialEq)]
pub enum RepoEvent {
    /// The commit from the metadata, always first. Check it against the
    /// request and its MAC before relying on the records.
    Commit(Commit),
    /// A record, provisional until `Complete`.
    Record(ArchivedRecord),
    /// Every record arrived and they hash to the commit's `data`.
    Complete,
}

/// Split a record path into `(collection, rkey)`, validating both.
pub fn parse_record_path(path: &str) -> Option<(&str, &str)> {
    let (collection, rkey) = path.split_once('/')?;
    (is_valid_nsid(collection) && is_valid_record_key(rkey)).then_some((collection, rkey))
}

/// An incremental, verifying reader for a repo archive.
#[derive(Debug)]
pub struct RepoArchiveReader {
    star: StarDecoder,
    commit: Option<Commit>,
    hash: LtHash,
    prev_key: Option<Vec<u8>>,
    error: Option<RepoArchiveError>,
}

impl Default for RepoArchiveReader {
    fn default() -> Self {
        Self::new()
    }
}

impl RepoArchiveReader {
    pub fn new() -> Self {
        Self {
            star: StarDecoder::new(StarLimits::SPACES),
            commit: None,
            hash: LtHash::new(),
            prev_key: None,
            error: None,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<(), RepoArchiveError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        self.star.push(bytes).map_err(|e| self.fail(e.into()))
    }

    pub fn finish(&mut self) {
        self.star.finish();
    }

    /// The next event, or `None` if more input is needed.
    pub fn next_event(&mut self) -> Result<Option<RepoEvent>, RepoArchiveError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let r = self.step();
        r.map_err(|e| self.fail(e))
    }

    fn fail(&mut self, e: RepoArchiveError) -> RepoArchiveError {
        self.error = Some(e.clone());
        e
    }

    fn step(&mut self) -> Result<Option<RepoEvent>, RepoArchiveError> {
        let Some(ev) = self.star.next_event()? else {
            return Ok(None);
        };
        match ev {
            StarEvent::Meta(meta) => {
                if meta.get("$type").and_then(Value::as_text) != Some(REPO_STAR_TYPE) {
                    return Err(RepoArchiveError::WrongType);
                }
                let commit = Commit::from_fields(&meta).map_err(RepoArchiveError::Commit)?;
                self.commit = Some(commit.clone());
                Ok(Some(RepoEvent::Commit(commit)))
            }
            StarEvent::Pair { key, value } => {
                let path = std::str::from_utf8(&key).map_err(|_| RepoArchiveError::InvalidPath)?;
                let (collection, rkey) =
                    parse_record_path(path).ok_or(RepoArchiveError::InvalidPath)?;
                if let Some(prev) = &self.prev_key {
                    if key.as_slice() <= prev.as_slice() {
                        return Err(RepoArchiveError::OutOfOrder);
                    }
                }
                let cid = drisl::record_cid(&value).map_err(RepoArchiveError::InvalidRecord)?;
                let Ok(Value::Map(map)) = drisl::decode(&value) else {
                    unreachable!("record_cid checked the value is a DRISL map");
                };
                self.hash.add_record_cid(collection, rkey, &cid);
                let record = ArchivedRecord {
                    collection: collection.to_owned(),
                    rkey: rkey.to_owned(),
                    cid,
                    bytes: value,
                    value: map,
                };
                self.prev_key = Some(key);
                Ok(Some(RepoEvent::Record(record)))
            }
            StarEvent::End => {
                let commit = self.commit.as_ref().expect("metadata precedes the end");
                if commit.matches(&self.hash) {
                    Ok(Some(RepoEvent::Complete))
                } else {
                    Err(RepoArchiveError::DigestMismatch)
                }
            }
        }
    }
}

/// Read and verify a whole repo archive in memory. The commit still needs
/// checking against the request and its MAC.
pub fn read_repo_archive(bytes: &[u8]) -> Result<(Commit, Vec<ArchivedRecord>), RepoArchiveError> {
    let mut r = RepoArchiveReader::new();
    r.push(bytes)?;
    r.finish();
    let mut commit = None;
    let mut records = Vec::new();
    while let Some(ev) = r.next_event()? {
        match ev {
            RepoEvent::Commit(c) => commit = Some(c),
            RepoEvent::Record(rec) => records.push(rec),
            RepoEvent::Complete => {
                return Ok((commit.expect("commit precedes completion"), records))
            }
        }
    }
    unreachable!("a finished reader ends in Complete or an error")
}

/// An incremental writer. Records must come in strict path order; the
/// writer checks the order and the paths, not the record bytes, which a
/// host is expected to hold canonically already.
#[derive(Debug, Default)]
pub struct RepoArchiveWriter {
    prev_key: Option<Vec<u8>>,
}

impl RepoArchiveWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The archive header for a commit.
    pub fn header(&self, commit: &Commit) -> Vec<u8> {
        let mut meta = commit.fields();
        meta.insert("$type".to_owned(), Value::Text(REPO_STAR_TYPE.to_owned()));
        star::encode_header(&meta).expect("a commit encodes as valid metadata")
    }

    /// One record's frame.
    pub fn record(
        &mut self,
        collection: &str,
        rkey: &str,
        bytes: &[u8],
    ) -> Result<Vec<u8>, RepoArchiveError> {
        if !is_valid_nsid(collection) || !is_valid_record_key(rkey) {
            return Err(RepoArchiveError::InvalidPath);
        }
        let key = format!("{collection}/{rkey}").into_bytes();
        if let Some(prev) = &self.prev_key {
            if key.as_slice() <= prev.as_slice() {
                return Err(RepoArchiveError::OutOfOrder);
            }
        }
        let frame = star::encode_pair(&key, bytes);
        self.prev_key = Some(key);
        Ok(frame)
    }

    /// The end byte.
    pub fn finish(self) -> [u8; 1] {
        star::END
    }
}

/// Write a whole repo archive. Records must be in strict path order.
pub fn write_repo_archive<'a>(
    commit: &Commit,
    records: impl IntoIterator<Item = (&'a str, &'a str, &'a [u8])>,
) -> Result<Vec<u8>, RepoArchiveError> {
    let mut w = RepoArchiveWriter::new();
    let mut out = w.header(commit);
    for (collection, rkey, bytes) in records {
        out.extend_from_slice(&w.record(collection, rkey, bytes)?);
    }
    out.extend_from_slice(&w.finish());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uri::SpaceRef;

    const SPACE: &str = "at:space/did:example:space/app.bsky.group/test";
    const AUTHOR: &str = "did:example:alice";
    const REV: &str = "3kbcq3p7ad42b";

    struct Rec {
        collection: &'static str,
        rkey: &'static str,
        bytes: Vec<u8>,
    }

    fn rec(collection: &'static str, rkey: &'static str, text: &str) -> Rec {
        let bytes = drisl::encode(&Value::map([("text", Value::Text(text.into()))])).unwrap();
        Rec {
            collection,
            rkey,
            bytes,
        }
    }

    /// In path order: likes sort before posts.
    fn records() -> Vec<Rec> {
        vec![
            rec("app.bsky.feed.like", "3kbcq3p7ad423", "at://x"),
            rec("app.bsky.feed.post", "3kbcq3p7ad422", "hello"),
            rec("app.bsky.feed.post", "3kbcq3p7ad424", "world"),
        ]
    }

    fn commit_for(recs: &[Rec]) -> Commit {
        let mut h = LtHash::new();
        for r in recs {
            h.add_record_cid(r.collection, r.rkey, &Cid::for_drisl(&r.bytes));
        }
        Commit::new(AUTHOR, SpaceRef::parse(SPACE).unwrap(), REV, &h).unwrap()
    }

    fn archive(commit: &Commit, recs: &[Rec]) -> Vec<u8> {
        write_repo_archive(
            commit,
            recs.iter()
                .map(|r| (r.collection, r.rkey, r.bytes.as_slice())),
        )
        .unwrap()
    }

    /// Bypass the writer's checks, to build archives it refuses to.
    fn raw(meta_extra: &[(&str, Value)], commit: &Commit, pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut meta = commit.fields();
        meta.insert("$type".into(), Value::Text(REPO_STAR_TYPE.into()));
        for (k, v) in meta_extra {
            meta.insert((*k).into(), v.clone());
        }
        star::write_star(&meta, pairs.iter().copied()).unwrap()
    }

    fn pairs(recs: &[Rec]) -> Vec<(Vec<u8>, Vec<u8>)> {
        recs.iter()
            .map(|r| {
                (
                    format!("{}/{}", r.collection, r.rkey).into_bytes(),
                    r.bytes.clone(),
                )
            })
            .collect()
    }

    fn refs(p: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
        p.iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect()
    }

    #[test]
    fn round_trip() {
        let recs = records();
        let commit = commit_for(&recs);
        let bytes = archive(&commit, &recs);
        let (got, read) = read_repo_archive(&bytes).unwrap();
        assert_eq!(got, commit);
        assert_eq!(read.len(), 3);
        let post = read.iter().find(|r| r.rkey == "3kbcq3p7ad422").unwrap();
        assert_eq!(post.value.get("text"), Some(&Value::Text("hello".into())));
        assert_eq!(
            post.cid.to_string(),
            "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"
        );
    }

    #[test]
    fn metadata_is_commit_plus_type() {
        let recs = records();
        let commit = commit_for(&recs);
        let (meta, _) = star::read_star(&archive(&commit, &recs), StarLimits::SPACES).unwrap();
        let mut expected = commit.fields();
        expected.insert("$type".into(), Value::Text(REPO_STAR_TYPE.into()));
        assert_eq!(meta, expected);
    }

    #[test]
    fn streams_byte_by_byte() {
        let recs = records();
        let commit = commit_for(&recs);
        let bytes = archive(&commit, &recs);
        let mut r = RepoArchiveReader::new();
        let mut events = Vec::new();
        for b in &bytes {
            r.push(std::slice::from_ref(b)).unwrap();
            while let Some(ev) = r.next_event().unwrap() {
                events.push(ev);
            }
        }
        r.finish();
        assert_eq!(r.next_event(), Ok(None));
        assert!(matches!(events.first(), Some(RepoEvent::Commit(_))));
        assert_eq!(events.last(), Some(&RepoEvent::Complete));
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn empty_repo() {
        let commit = commit_for(&[]);
        let (_, read) = read_repo_archive(&archive(&commit, &[])).unwrap();
        assert!(read.is_empty());
    }

    #[test]
    fn writer_refuses_out_of_order_and_bad_paths() {
        let recs = records();
        let commit = commit_for(&recs);
        let swapped = [&recs[1], &recs[0]];
        let err = write_repo_archive(
            &commit,
            swapped
                .iter()
                .map(|r| (r.collection, r.rkey, r.bytes.as_slice())),
        );
        assert_eq!(err, Err(RepoArchiveError::OutOfOrder));
        let mut w = RepoArchiveWriter::new();
        assert_eq!(
            w.record("not-a-nsid", "k", b"\xa0"),
            Err(RepoArchiveError::InvalidPath)
        );
    }

    #[test]
    fn rejects_missing_extra_and_swapped_records() {
        let recs = records();
        let p = pairs(&recs);
        // Missing a record.
        let missing = raw(&[], &commit_for(&recs), &refs(&p[..2]));
        assert_eq!(
            read_repo_archive(&missing),
            Err(RepoArchiveError::DigestMismatch)
        );
        // An extra one.
        let extra = raw(&[], &commit_for(&recs[..2]), &refs(&p));
        assert_eq!(
            read_repo_archive(&extra),
            Err(RepoArchiveError::DigestMismatch)
        );
        // A swapped value.
        let mut tampered = p.clone();
        tampered[0].1 = drisl::encode(&Value::map([("text", Value::Text("x".into()))])).unwrap();
        let swapped = raw(&[], &commit_for(&recs), &refs(&tampered));
        assert_eq!(
            read_repo_archive(&swapped),
            Err(RepoArchiveError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_out_of_order_and_duplicates() {
        let recs = records();
        let commit = commit_for(&recs);
        let p = pairs(&recs);
        let reordered = raw(
            &[],
            &commit,
            &refs(&[p[1].clone(), p[0].clone(), p[2].clone()]),
        );
        assert_eq!(
            read_repo_archive(&reordered),
            Err(RepoArchiveError::OutOfOrder)
        );
        let dup = raw(
            &[],
            &commit,
            &refs(&[p[0].clone(), p[0].clone(), p[1].clone(), p[2].clone()]),
        );
        assert_eq!(read_repo_archive(&dup), Err(RepoArchiveError::OutOfOrder));
    }

    #[test]
    fn rejects_bad_metadata() {
        let commit = commit_for(&[]);
        let wrong_type = raw(
            &[("$type", Value::Text("atproto-public-repo".into()))],
            &commit,
            &[],
        );
        assert_eq!(
            read_repo_archive(&wrong_type),
            Err(RepoArchiveError::WrongType)
        );
        let v2 = raw(&[("ver", Value::Integer(2))], &commit, &[]);
        assert_eq!(
            read_repo_archive(&v2),
            Err(RepoArchiveError::Commit(CommitError::UnsupportedVersion(2)))
        );
        let bad_rev = raw(&[("rev", Value::Text("not-a-tid".into()))], &commit, &[]);
        assert_eq!(
            read_repo_archive(&bad_rev),
            Err(RepoArchiveError::Commit(CommitError::InvalidRev))
        );
        let big = raw(
            &[("filler", Value::Text("x".repeat(64 * 1024)))],
            &commit,
            &[],
        );
        assert!(matches!(
            read_repo_archive(&big),
            Err(RepoArchiveError::Star(StarError::TooLong {
                limit: 65536,
                ..
            }))
        ));
    }

    #[test]
    fn rejects_bad_paths_and_records() {
        let commit = commit_for(&[]);
        let empty_map: &[u8] = &[0xa0];
        let post: &[u8] = b"app.bsky.feed.post/3kbcq3p7ad422";
        let bad_path = raw(&[], &commit, &[(b"not-a-path".as_slice(), empty_map)]);
        assert_eq!(
            read_repo_archive(&bad_path),
            Err(RepoArchiveError::InvalidPath)
        );
        let two_slashes = raw(
            &[],
            &commit,
            &[(b"app.bsky.feed.post/a/b".as_slice(), empty_map)],
        );
        assert_eq!(
            read_repo_archive(&two_slashes),
            Err(RepoArchiveError::InvalidPath)
        );
        let long_key = format!("app.bsky.feed.post/{}", "x".repeat(4 * 1024));
        let long = raw(&[], &commit, &[(long_key.as_bytes(), empty_map)]);
        assert!(matches!(
            read_repo_archive(&long),
            Err(RepoArchiveError::Star(StarError::TooLong {
                limit: 4096,
                ..
            }))
        ));
        let not_map = drisl::encode(&Value::Text("hi".into())).unwrap();
        let s = raw(&[], &commit, &[(post, not_map.as_slice())]);
        assert_eq!(
            read_repo_archive(&s),
            Err(RepoArchiveError::InvalidRecord(DrislError::NotAMap))
        );
        // Non-canonical record bytes: map keys out of order.
        let unsorted: &[u8] = &[0xa2, 0x62, b'a', b'a', 1, 0x61, b'b', 2];
        let s = raw(&[], &commit, &[(post, unsorted)]);
        assert_eq!(
            read_repo_archive(&s),
            Err(RepoArchiveError::InvalidRecord(DrislError::MapKeyOrder))
        );
    }

    #[test]
    fn rejects_oversized_record_from_its_length() {
        // Header, then a pair whose value length exceeds 1 MiB, cut off
        // before the value bytes.
        let commit = commit_for(&[]);
        let mut bytes = RepoArchiveWriter::new().header(&commit);
        bytes.extend_from_slice(&[0x01, 0x01, b'k', 0x81, 0x80, 0x40]); // 1 MiB + 1
        let mut r = RepoArchiveReader::new();
        r.push(&bytes).unwrap();
        assert!(matches!(r.next_event(), Ok(Some(RepoEvent::Commit(_)))));
        assert!(matches!(
            r.next_event(),
            Err(RepoArchiveError::Star(StarError::TooLong {
                limit: 1048576,
                ..
            }))
        ));
    }
}
