//! Reading a space: the writer set, each writer's repo, and the op log.
//!
//! Every response is checked before anything in it is used:
//! - a commit MAC under a fresh KEM key share to the repo's account;
//! - the commit is for the requested repo and space;
//! - a full repo's records hash to the commit;
//! - the op log, replayed onto our own set hash, reproduces the commit;
//! - every inline record value hashes to its op's CID.

use crate::credential::{json_body, Credential};
use crate::error::SyncError;
use crate::json;
use crate::transport::{Directory, Method, Request, Transport};
use crate::validate::{check, Checked};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use umbrae_core::cid::Cid;
use umbrae_core::commit::{Commit, RepoOp};
use umbrae_core::drisl::{self, Value as D};
use umbrae_core::kem::{self, Encapsulation};
use umbrae_core::mac::{self, MacFields, MacProfile};
use umbrae_core::repo_archive::read_repo_archive;
use umbrae_core::uri::SpaceRecordUri;
use umbrae_core::LtHash;

type Map = BTreeMap<String, D>;

/// Most pages read from one listing, so a host can't keep us paging.
const MAX_PAGES: usize = 1000;
const PAGE_SIZE: &str = "1000";

const REPO_WRITE: &str = "com.atproto.space.defs#repoWrite";
const REPO_REMOVED: &str = "com.atproto.space.defs#repoRemoved";

/// A repo in the writer set, at its latest revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writer {
    pub repo: String,
    pub repo_rev: String,
    /// The digest of the repo's set hash at that revision.
    pub data: [u8; 32],
}

/// The writer set: who's in it, and who's been removed from it recently.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Writers {
    pub active: Vec<Writer>,
    pub removed: Vec<String>,
}

/// A synced record, checked against the Umbrae lexicons where its space
/// type is one of Umbrae's.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncedRecord {
    pub uri: SpaceRecordUri,
    pub cid: Cid,
    pub value: Map,
    pub checked: Checked,
}

/// One entry of a repo's op log.
#[derive(Debug, Clone, PartialEq)]
pub struct Op {
    pub rev: String,
    pub collection: String,
    pub rkey: String,
    /// After the op; `None` for a delete.
    pub cid: Option<Cid>,
    /// Before the op; `None` for a create.
    pub prev: Option<Cid>,
    /// The record after the op, when the host included its value.
    pub record: Option<SyncedRecord>,
}

/// Where a repo was synced to: its revision and our own set hash for it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoCursor {
    pub repo: String,
    pub rev: String,
    /// The set hash state, base64url.
    state: String,
}

impl std::fmt::Debug for RepoCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoCursor")
            .field("rev", &self.rev)
            .finish_non_exhaustive()
    }
}

impl RepoCursor {
    fn new(repo: &str, rev: &str, hash: &LtHash) -> Self {
        Self {
            repo: repo.to_owned(),
            rev: rev.to_owned(),
            state: URL_SAFE_NO_PAD.encode(hash.state()),
        }
    }

    fn hash(&self) -> Result<LtHash, SyncError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.state)
            .map_err(|_| SyncError::Malformed("cursor state"))?;
        LtHash::from_state(&bytes).map_err(|_| SyncError::Malformed("cursor state"))
    }

    /// The digest of the repo's set hash at [`Self::rev`].
    pub fn digest(&self) -> Option<[u8; 32]> {
        self.hash().ok().map(|h| h.digest())
    }
}

/// Where a space was synced to, per repo. Persist it to resume.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SpaceCursor {
    pub repos: BTreeMap<String, RepoCursor>,
}

/// What changed in one repo since the cursor.
#[derive(Debug, Clone, PartialEq)]
pub enum RepoChange {
    /// The whole repo, fetched fresh: replace whatever was held for it.
    Replaced {
        repo: String,
        records: Vec<SyncedRecord>,
    },
    /// The ops since the cursor, in order. Every create or update that a
    /// view needs carries its record.
    Ops { repo: String, ops: Vec<Op> },
    /// No longer in the writer set: drop its records.
    Removed { repo: String },
    /// This repo couldn't be synced now; its cursor is kept and it's
    /// retried next time. Other repos are unaffected.
    Failed { repo: String, error: SyncError },
}

fn header_fields<'a>(r: &'a crate::transport::Response, p: MacProfile) -> MacFields<'a> {
    MacFields {
        covered: r.header(p.header()),
        signature_input: r.header("signature-input"),
        signature: r.header("signature"),
    }
}

fn mac_request(enc: &Encapsulation) -> (&'static str, String) {
    (
        "Accept-Signature",
        mac::format_mac_request(MacProfile::Commit, &enc.key_share),
    )
}

fn record(uri: SpaceRecordUri, cid: Cid, value: Map) -> SyncedRecord {
    let checked = check(&uri, &value);
    SyncedRecord {
        uri,
        cid,
        value,
        checked,
    }
}

/// The whole writer set, from the space authority's PDS.
pub async fn list_writers<T: Transport, D2: Directory>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    now: i64,
) -> Result<Writers, SyncError> {
    cred.check_live(now)?;
    let space = cred.space();
    let authority = space.authority();
    let host = directory.resolve(authority, false).await?;
    let mut latest: BTreeMap<String, Option<Writer>> = BTreeMap::new();
    let mut page: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut query = vec![
            ("space", space.to_string()),
            ("limit", PAGE_SIZE.to_owned()),
        ];
        if let Some(c) = &page {
            query.push(("cursor", c.clone()));
        }
        let r = transport
            .send(Request {
                method: Method::Get,
                base: host.pds.clone(),
                nsid: "com.atproto.space.listWriters",
                query,
                headers: cred.headers(authority),
                body: None,
            })
            .await?;
        let j = json_body(&r)?;
        let repos = j["repos"]
            .as_array()
            .ok_or(SyncError::Malformed("listWriters repos"))?;
        for e in repos {
            let repo = e["repo"]
                .as_str()
                .ok_or(SyncError::Malformed("listWriters repo"))?
                .to_owned();
            match e["$type"].as_str() {
                Some(REPO_WRITE) => {
                    let w = Writer {
                        repo: repo.clone(),
                        repo_rev: e["repoRev"]
                            .as_str()
                            .ok_or(SyncError::Malformed("listWriters repoRev"))?
                            .to_owned(),
                        data: json::digest(&e["data"])
                            .ok_or(SyncError::Malformed("listWriters data"))?,
                    };
                    latest.insert(repo, Some(w));
                }
                Some(REPO_REMOVED) => {
                    latest.insert(repo, None);
                }
                _ => return Err(SyncError::Malformed("listWriters entry type")),
            }
        }
        match j["cursor"].as_str() {
            Some(c) if !repos.is_empty() && page.as_deref() != Some(c) => page = Some(c.to_owned()),
            _ => {
                let mut out = Writers::default();
                for (repo, w) in latest {
                    match w {
                        Some(w) => out.active.push(w),
                        None => out.removed.push(repo),
                    }
                }
                return Ok(out);
            }
        }
    }
    Err(SyncError::Malformed("listWriters never ended"))
}

/// One repo in full, from its account's PDS, verified against its commit.
pub async fn fetch_repo<T: Transport, D2: Directory>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    repo: &str,
    now: i64,
) -> Result<(RepoCursor, Vec<SyncedRecord>), SyncError> {
    cred.check_live(now)?;
    let space = cred.space();
    let id = directory.resolve(repo, false).await?;
    let kem_key = id.kem_key.ok_or(SyncError::MissingKey("#atproto_kem"))?;
    let enc = kem::encapsulate(&kem_key).map_err(|_| SyncError::MissingKey("#atproto_kem"))?;
    let mut headers = cred.headers(repo);
    headers.push(mac_request(&enc));
    let r = transport
        .send(Request {
            method: Method::Get,
            base: id.pds,
            nsid: "com.atproto.space.getRepo",
            query: vec![("space", space.to_string()), ("repo", repo.to_owned())],
            headers,
            body: None,
        })
        .await?;
    if r.status != 200 {
        return Err(crate::credential::xrpc_error(&r));
    }
    let (commit, records) = read_repo_archive(&r.body).map_err(SyncError::Archive)?;
    verify_commit(
        &commit,
        repo,
        cred,
        &enc,
        &header_fields(&r, MacProfile::Commit),
    )?;
    let mut hash = LtHash::new();
    let mut out = Vec::with_capacity(records.len());
    for rec in records {
        hash.add_record_cid(&rec.collection, &rec.rkey, &rec.cid);
        let uri = space
            .record(repo, &rec.collection, &rec.rkey)
            .map_err(|_| SyncError::Malformed("record path"))?;
        out.push(record(uri, rec.cid, rec.value));
    }
    if !commit.matches(&hash) {
        return Err(SyncError::DigestMismatch);
    }
    Ok((RepoCursor::new(repo, commit.rev(), &hash), out))
}

fn verify_commit(
    commit: &Commit,
    repo: &str,
    cred: &Credential,
    enc: &Encapsulation,
    fields: &MacFields<'_>,
) -> Result<(), SyncError> {
    mac::verify_commit_mac(commit, enc, fields).map_err(SyncError::Mac)?;
    commit
        .check_for(repo, cred.space())
        .map_err(SyncError::Commit)
}

fn cid_field(v: &Value) -> Result<Option<Cid>, SyncError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Cid::parse(s)
            .map(Some)
            .map_err(|_| SyncError::Malformed("op cid")),
        _ => Err(SyncError::Malformed("op cid")),
    }
}

/// The ops after `cursor`, replayed onto its set hash and checked against
/// the repo's current commit. [`SyncError::DigestMismatch`] (or an
/// `InvalidCursor` from the host) means the log can't bridge the gap:
/// fetch the repo in full.
pub async fn fetch_ops<T: Transport, D2: Directory>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    cursor: &RepoCursor,
    now: i64,
) -> Result<(RepoCursor, Vec<Op>), SyncError> {
    cred.check_live(now)?;
    let space = cred.space();
    let repo = cursor.repo.as_str();
    let id = directory.resolve(repo, false).await?;
    let kem_key = id.kem_key.ok_or(SyncError::MissingKey("#atproto_kem"))?;
    let mut hash = cursor.hash()?;
    let mut ops = Vec::new();
    let mut page: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let enc = kem::encapsulate(&kem_key).map_err(|_| SyncError::MissingKey("#atproto_kem"))?;
        let mut headers = cred.headers(repo);
        headers.push(mac_request(&enc));
        let mut query = vec![
            ("space", space.to_string()),
            ("repo", repo.to_owned()),
            ("since", cursor.rev.clone()),
            ("limit", PAGE_SIZE.to_owned()),
        ];
        if let Some(c) = &page {
            query.push(("cursor", c.clone()));
        }
        let r = transport
            .send(Request {
                method: Method::Get,
                base: id.pds.clone(),
                nsid: "com.atproto.space.listRepoOps",
                query,
                headers,
                body: None,
            })
            .await?;
        let j = json_body(&r)?;
        let commit = json::commit(&j["commit"])?;
        verify_commit(
            &commit,
            repo,
            cred,
            &enc,
            &header_fields(&r, MacProfile::Commit),
        )?;
        let entries = j["ops"].as_array().ok_or(SyncError::Malformed("ops"))?;
        for e in entries {
            let collection = e["collection"]
                .as_str()
                .ok_or(SyncError::Malformed("op collection"))?
                .to_owned();
            let rkey = e["rkey"]
                .as_str()
                .ok_or(SyncError::Malformed("op rkey"))?
                .to_owned();
            let cid = cid_field(&e["cid"])?;
            let prev = cid_field(&e["prev"])?;
            hash.apply_op(&RepoOp {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid,
                prev,
            })
            .map_err(SyncError::Op)?;
            let record = match (e.get("value").filter(|v| !v.is_null()), cid) {
                (Some(v), Some(c)) => {
                    let value = json::to_map(v)?;
                    let ours = drisl::encode(&D::Map(value.clone()))
                        .map(|b| Cid::for_drisl(&b))
                        .map_err(|_| SyncError::Malformed("op value"))?;
                    if ours != c {
                        return Err(SyncError::Malformed("op value doesn't match its CID"));
                    }
                    let uri = space
                        .record(repo, &collection, &rkey)
                        .map_err(|_| SyncError::Malformed("op path"))?;
                    Some(record(uri, c, value))
                }
                _ => None,
            };
            ops.push(Op {
                rev: e["rev"]
                    .as_str()
                    .ok_or(SyncError::Malformed("op rev"))?
                    .to_owned(),
                collection,
                rkey,
                cid,
                prev,
                record,
            });
        }
        match j["cursor"].as_str() {
            Some(c) if !entries.is_empty() && page.as_deref() != Some(c) => {
                page = Some(c.to_owned())
            }
            _ => {
                if !commit.matches(&hash) {
                    return Err(SyncError::DigestMismatch);
                }
                return Ok((RepoCursor::new(repo, commit.rev(), &hash), ops));
            }
        }
    }
    Err(SyncError::Malformed("listRepoOps never ended"))
}

/// Whether every path's last op that leaves a record behind carries it.
fn ops_complete(ops: &[Op]) -> bool {
    let mut last: BTreeMap<(&str, &str), &Op> = BTreeMap::new();
    for op in ops {
        last.insert((&op.collection, &op.rkey), op);
    }
    last.values()
        .all(|op| op.cid.is_none() || op.record.is_some())
}

fn needs_full_fetch(e: &SyncError) -> bool {
    match e {
        SyncError::DigestMismatch | SyncError::Op(_) => true,
        SyncError::Xrpc { error, .. } => error.as_str() == "InvalidCursor",
        _ => false,
    }
}

/// Bring a space up to date from `cursor`: list the writer set, then for
/// each writer, skip it if unchanged, replay its op log, or fetch it in
/// full. Returns the new cursor and what changed. A writer whose host fails
/// shows up as [`RepoChange::Failed`] and keeps its old cursor.
pub async fn sync_space<T: Transport, D2: Directory>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    cursor: &SpaceCursor,
    now: i64,
) -> Result<(SpaceCursor, Vec<RepoChange>), SyncError> {
    let writers = list_writers(transport, directory, cred, now).await?;
    let mut next = SpaceCursor::default();
    let mut changes = Vec::new();
    let active: BTreeSet<&str> = writers.active.iter().map(|w| w.repo.as_str()).collect();
    for w in &writers.active {
        let held = cursor.repos.get(&w.repo);
        if let Some(c) = held {
            if c.rev == w.repo_rev && c.digest() == Some(w.data) {
                next.repos.insert(w.repo.clone(), c.clone());
                continue;
            }
            match fetch_ops(transport, directory, cred, c, now).await {
                Ok((nc, ops)) if ops_complete(&ops) => {
                    next.repos.insert(w.repo.clone(), nc);
                    changes.push(RepoChange::Ops {
                        repo: w.repo.clone(),
                        ops,
                    });
                    continue;
                }
                Ok(_) => {}
                Err(e) if needs_full_fetch(&e) => {}
                Err(error) => {
                    next.repos.insert(w.repo.clone(), c.clone());
                    changes.push(RepoChange::Failed {
                        repo: w.repo.clone(),
                        error,
                    });
                    continue;
                }
            }
        }
        match fetch_repo(transport, directory, cred, &w.repo, now).await {
            Ok((nc, records)) => {
                next.repos.insert(w.repo.clone(), nc);
                changes.push(RepoChange::Replaced {
                    repo: w.repo.clone(),
                    records,
                });
            }
            Err(error) => {
                if let Some(c) = held {
                    next.repos.insert(w.repo.clone(), c.clone());
                }
                changes.push(RepoChange::Failed {
                    repo: w.repo.clone(),
                    error,
                });
            }
        }
    }
    for repo in cursor.repos.keys() {
        if !active.contains(repo.as_str()) {
            changes.push(RepoChange::Removed { repo: repo.clone() });
        }
    }
    Ok((next, changes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(path: (&str, &str), cid: Option<Cid>, with_record: bool) -> Op {
        let uri =
            umbrae_core::uri::SpaceRef::new("did:example:a", "tools.umbrae.space", "3mbbbbbbbbbb2")
                .unwrap()
                .record("did:example:a", path.0, path.1)
                .unwrap();
        Op {
            rev: "3mbaaaaaaaaa2".into(),
            collection: path.0.into(),
            rkey: path.1.into(),
            cid,
            prev: None,
            record: with_record.then(|| record(uri, cid.unwrap(), Map::new())),
        }
    }

    #[test]
    fn op_batches_need_the_last_value_of_each_path() {
        let c = Some(Cid::for_drisl(b"a"));
        let p = ("tools.umbrae.post", "3mbaaaaaaaaa2");
        let q = ("tools.umbrae.post", "3mbaaaaaaaaa3");
        // Created without a value, then updated with one: fine.
        assert!(ops_complete(&[op(p, c, false), op(p, c, true)]));
        // Created, then deleted: nothing to fetch.
        assert!(ops_complete(&[op(p, c, false), op(p, None, false)]));
        // The last op of a path leaves a record without its value.
        assert!(!ops_complete(&[op(p, c, true), op(q, c, false)]));
        assert!(ops_complete(&[]));
    }

    #[test]
    fn cursors_round_trip_and_hide_state_in_debug() {
        let mut h = LtHash::new();
        h.add_record(
            "tools.umbrae.post",
            "3mbaaaaaaaaa2",
            &Cid::for_drisl(b"x").to_string(),
        );
        let c = RepoCursor::new("did:example:a", "3mbaaaaaaaaa2", &h);
        assert_eq!(c.digest(), Some(h.digest()));
        let mut s = SpaceCursor::default();
        s.repos.insert(c.repo.clone(), c.clone());
        let back: SpaceCursor = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
        assert!(!format!("{c:?}").contains(&c.state));
        let broken = RepoCursor {
            state: "AAAA".into(),
            ..c
        };
        assert_eq!(broken.digest(), None);
    }

    #[test]
    fn full_fetch_fallbacks() {
        assert!(needs_full_fetch(&SyncError::DigestMismatch));
        assert!(needs_full_fetch(&SyncError::Xrpc {
            status: 400,
            error: crate::error::XrpcName::new("InvalidCursor")
        }));
        assert!(!needs_full_fetch(&SyncError::Xrpc {
            status: 400,
            error: crate::error::XrpcName::new("SpaceNotFound")
        }));
        assert!(!needs_full_fetch(&SyncError::CredentialExpired));
    }
}
