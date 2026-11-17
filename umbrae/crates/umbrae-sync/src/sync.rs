//! Reading a space: the writer set, each writer's repo, and the op log.
//!
//! Every response is checked before anything in it is used:
//! - a commit MAC under a fresh KEM key share to the repo's account;
//! - the commit is for the requested repo and space;
//! - a full repo's records hash to the commit;
//! - the op log is in order, after the cursor, and each op's `prev` is what
//!   the caller holds; replayed onto our own set hash, it reproduces the
//!   commit;
//! - a repo is never older than its cursor;
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
use umbrae_core::uri::{is_valid_tid, SpaceRecordUri};
use umbrae_core::LtHash;

type Map = BTreeMap<String, D>;

/// Most pages read from one listing, so a host can't keep us paging.
const MAX_PAGES: usize = 1000;
/// The `limit` asked for. In an op log only a full page is followed by
/// another, as the reference host sends a cursor only then
/// (`listRepoOps`), so a host can't drive us with tiny pages; a log cut
/// short only misses the commit and falls back to a full fetch.
const PAGE_LIMIT: usize = 1000;
/// The most op-log pages read for one repo before fetching it in full.
const MAX_OP_PAGES: usize = 16;
const PAGE_SIZE: &str = "1000";
/// The most `listWriters` entries read for one listing. Counted, not
/// sized: each entry is kept as a small `Writer` (a `data` that isn't a
/// digest is dropped), and a response's own size is the transport's to
/// cap, so writers can't fail the listing by sending large `data`.
const MAX_LIST_ENTRIES: usize = 200_000;
/// The most op-log response bytes held for one repo before its commit can
/// be checked. Past this, the repo is fetched in full instead.
const MAX_LOG_BYTES: usize = 16 * 1024 * 1024;

const REPO_WRITE: &str = "com.atproto.space.defs#repoWrite";
const REPO_REMOVED: &str = "com.atproto.space.defs#repoRemoved";

/// A repo in the writer set, at its latest revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writer {
    pub repo: String,
    pub repo_rev: String,
    /// The digest of the repo's set hash at that revision. `None` when the
    /// host listed bytes that aren't a digest: the lexicon doesn't fix the
    /// length, and the repo's own host supplies them, so one writer's bad
    /// value mustn't stop the whole listing. Such a writer is never skipped
    /// as unchanged.
    pub data: Option<[u8; 32]>,
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
#[non_exhaustive]
pub enum RepoChange {
    /// The whole repo, fetched fresh: replace whatever was held for it. No
    /// records when its host no longer has the repo.
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
    let mut listed = 0usize;
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
        listed = listed.saturating_add(repos.len());
        if listed > MAX_LIST_ENTRIES {
            return Err(SyncError::Malformed("listWriters too long"));
        }
        for e in repos {
            let kind = e["$type"].as_str();
            // The union is open: skip entries of a kind this version doesn't
            // know, as the reference syncer does.
            if !matches!(kind, Some(REPO_WRITE | REPO_REMOVED)) {
                continue;
            }
            let repo = e["repo"]
                .as_str()
                .ok_or(SyncError::Malformed("listWriters repo"))?
                .to_owned();
            match kind {
                Some(REPO_WRITE) => {
                    let w = Writer {
                        repo: repo.clone(),
                        repo_rev: e["repoRev"]
                            .as_str()
                            .ok_or(SyncError::Malformed("listWriters repoRev"))?
                            .to_owned(),
                        data: match json::bytes(&e["data"]) {
                            Some(b) => b.try_into().ok(),
                            None => return Err(SyncError::Malformed("listWriters data")),
                        },
                    };
                    latest.insert(repo, Some(w));
                }
                _ => {
                    latest.insert(repo, None);
                }
            }
        }
        // Follow any new cursor on a non-empty page, as the reference syncer
        // does: stopping early would read held writers as removed. Paging
        // is bounded by `MAX_PAGES` and `MAX_LIST_ENTRIES`.
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

/// Whether a failure may come from a stale `#atproto_kem` key, so is worth
/// one retry with the DID document re-resolved past any cache.
fn kem_may_be_stale(e: &SyncError) -> bool {
    matches!(e, SyncError::Mac(_) | SyncError::MissingKey(_))
}

/// One repo in full, from its account's PDS, verified against its commit.
/// A failed MAC is retried once with the account's KEM key re-resolved, as
/// it may have rotated.
pub async fn fetch_repo<T: Transport, D2: Directory>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    repo: &str,
    now: i64,
) -> Result<(RepoCursor, Vec<SyncedRecord>), SyncError> {
    match fetch_repo_once(transport, directory, cred, repo, now, false).await {
        Err(e) if kem_may_be_stale(&e) => {
            fetch_repo_once(transport, directory, cred, repo, now, true).await
        }
        r => r,
    }
}

async fn fetch_repo_once<T: Transport, D2: Directory>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    repo: &str,
    now: i64,
    refresh: bool,
) -> Result<(RepoCursor, Vec<SyncedRecord>), SyncError> {
    cred.check_live(now)?;
    let space = cred.space();
    let id = directory.resolve(repo, refresh).await?;
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

/// An op's `cid` or `prev`: required, but nullable.
fn cid_field(v: Option<&Value>) -> Result<Option<Cid>, SyncError> {
    match v.ok_or(SyncError::Malformed("op cid"))? {
        Value::Null => Ok(None),
        Value::String(s) => Cid::parse(s)
            .map(Some)
            .map_err(|_| SyncError::Malformed("op cid")),
        _ => Err(SyncError::Malformed("op cid")),
    }
}

/// The ops after `cursor`, checked against what the caller holds and
/// replayed onto the cursor's set hash, which must then match the repo's
/// current commit.
///
/// `held(collection, rkey)` is the CID the caller holds for that record of
/// this repo, as of the cursor (`None` if it holds none). Each op's `prev`
/// must be that, or what an earlier op in the log left, so the ops the
/// caller applies are the ones the commit covers.
///
/// [`SyncError::DigestMismatch`], [`SyncError::Gap`],
/// [`SyncError::RecordMismatch`] (or an `InvalidCursor` from the host) mean
/// the log can't bridge the gap: fetch the repo in full. A failed MAC is
/// retried once with the account's KEM key re-resolved.
pub async fn fetch_ops<T, D2, H>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    cursor: &RepoCursor,
    held: &H,
    now: i64,
) -> Result<(RepoCursor, Vec<Op>), SyncError>
where
    T: Transport,
    D2: Directory,
    H: Fn(&str, &str) -> Option<Cid> + Sync,
{
    match fetch_ops_once(transport, directory, cred, cursor, held, now, false).await {
        Err(e) if kem_may_be_stale(&e) => {
            fetch_ops_once(transport, directory, cred, cursor, held, now, true).await
        }
        r => r,
    }
}

async fn fetch_ops_once<T, D2, H>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    cursor: &RepoCursor,
    held: &H,
    now: i64,
    refresh: bool,
) -> Result<(RepoCursor, Vec<Op>), SyncError>
where
    T: Transport,
    D2: Directory,
    H: Fn(&str, &str) -> Option<Cid> + Sync,
{
    cred.check_live(now)?;
    let space = cred.space();
    let repo = cursor.repo.as_str();
    let id = directory.resolve(repo, refresh).await?;
    let kem_key = id.kem_key.ok_or(SyncError::MissingKey("#atproto_kem"))?;
    // A cursor whose state won't decode can't be replayed onto: fetch in full.
    let mut hash = cursor
        .hash()
        .map_err(|_| SyncError::Gap("cursor state won't decode"))?;
    let mut log_bytes = 0usize;
    let mut ops = Vec::new();
    // What each path touched so far holds after its latest op.
    let mut current: BTreeMap<(String, String), Option<Cid>> = BTreeMap::new();
    let mut last_rev = cursor.rev.clone();
    let mut page: Option<String> = None;
    for n in 0..MAX_OP_PAGES {
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
        // The digest can only be checked after the last page, so cap what a
        // log may hold until then; a longer gap is cheaper as one getRepo.
        log_bytes = log_bytes.saturating_add(r.body.len());
        if log_bytes > MAX_LOG_BYTES {
            return Err(SyncError::Gap("op log too long"));
        }
        let j = json_body(&r)?;
        let commit = json::commit(&j["commit"])?;
        match verify_commit(
            &commit,
            repo,
            cred,
            &enc,
            &header_fields(&r, MacProfile::Commit),
        ) {
            Ok(()) => {}
            // Earlier pages verified under this key, so it isn't stale:
            // don't replay the log with a refreshed one, fetch in full.
            Err(SyncError::Mac(_)) if n > 0 => {
                return Err(SyncError::Gap("MAC failed partway through the log"))
            }
            Err(e) => return Err(e),
        }
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
            let cid = cid_field(e.get("cid"))?;
            let prev = cid_field(e.get("prev"))?;
            let rev = e["rev"]
                .as_str()
                .filter(|r| is_valid_tid(r))
                .ok_or(SyncError::Malformed("op rev"))?
                .to_owned();
            // Ops come in revision order, all after the cursor; ops that
            // share a revision were one commit.
            if rev <= cursor.rev || rev < last_rev {
                return Err(SyncError::Gap("ops out of order"));
            }
            last_rev.clone_from(&rev);
            let path = (collection.clone(), rkey.clone());
            let before = match current.get(&path) {
                Some(c) => *c,
                None => held(&collection, &rkey),
            };
            if prev != before {
                return Err(SyncError::Gap("an op's prev isn't what we hold"));
            }
            current.insert(path, cid);
            hash.apply_op(&RepoOp {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid,
                prev,
            })
            .map_err(SyncError::Op)?;
            let record = match e.get("value").filter(|v| !v.is_null()) {
                Some(v) => {
                    let c = cid.ok_or(SyncError::RecordMismatch)?;
                    let value = json::to_map(v).map_err(|_| SyncError::RecordMismatch)?;
                    let ours = drisl::encode(&D::Map(value.clone()))
                        .map(|b| Cid::for_drisl(&b))
                        .map_err(|_| SyncError::RecordMismatch)?;
                    if ours != c {
                        return Err(SyncError::RecordMismatch);
                    }
                    let uri = space
                        .record(repo, &collection, &rkey)
                        .map_err(|_| SyncError::Malformed("op path"))?;
                    Some(record(uri, c, value))
                }
                None => None,
            };
            ops.push(Op {
                rev,
                collection,
                rkey,
                cid,
                prev,
                record,
            });
        }
        match j["cursor"].as_str() {
            // The host sends a cursor only on a full page; a short one is
            // the last, and its commit is the one to check.
            Some(c) if entries.len() >= PAGE_LIMIT && page.as_deref() != Some(c) => {
                page = Some(c.to_owned())
            }
            _ => {
                if commit.rev() < cursor.rev.as_str() {
                    return Err(SyncError::Gap("repo is older than its cursor"));
                }
                if !commit.matches(&hash) {
                    return Err(SyncError::DigestMismatch);
                }
                return Ok((RepoCursor::new(repo, commit.rev(), &hash), ops));
            }
        }
    }
    // A longer log is cheaper, and as safe, as one getRepo.
    Err(SyncError::Gap("op log has too many pages"))
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
        SyncError::DigestMismatch
        | SyncError::Op(_)
        | SyncError::Gap(_)
        | SyncError::RecordMismatch
        | SyncError::Mac(_)
        | SyncError::Commit(_) => true,
        SyncError::Xrpc { error, .. } => error.as_str() == "InvalidCursor",
        _ => false,
    }
}

/// Bring a space up to date from `cursor`: list the writer set, then for
/// each writer, skip it if unchanged, replay its op log, or fetch it in
/// full. Returns the new cursor and what changed.
///
/// `held(repo, collection, rkey)` is the CID the caller holds for a record,
/// as of `cursor`: every record synced so far, whatever it was
/// [`Checked`] as. Op logs are checked against it (see [`fetch_ops`]).
///
/// - A writer whose host fails shows up as [`RepoChange::Failed`] and keeps
///   its old cursor.
/// - A writer whose host has no repo for it (`RepoNotFound`) is
///   [`RepoChange::Replaced`] with no records, if anything was held.
/// - A repo older than its cursor is refused as `Failed`.
pub async fn sync_space<T, D2, H>(
    transport: &T,
    directory: &D2,
    cred: &Credential,
    cursor: &SpaceCursor,
    held: &H,
    now: i64,
) -> Result<(SpaceCursor, Vec<RepoChange>), SyncError>
where
    T: Transport,
    D2: Directory,
    H: Fn(&str, &str, &str) -> Option<Cid> + Sync,
{
    let writers = list_writers(transport, directory, cred, now).await?;
    let mut next = SpaceCursor::default();
    let mut changes = Vec::new();
    let active: BTreeSet<&str> = writers.active.iter().map(|w| w.repo.as_str()).collect();
    for w in &writers.active {
        let repo = w.repo.as_str();
        // A stored cursor filed under another repo's key isn't this repo's.
        let held_cursor = cursor.repos.get(repo).filter(|c| c.repo == repo);
        let gone = || RepoChange::Replaced {
            repo: repo.to_owned(),
            records: Vec::new(),
        };
        if let Some(c) = held_cursor {
            if c.rev == w.repo_rev && w.data.is_some() && c.digest() == w.data {
                next.repos.insert(repo.to_owned(), c.clone());
                continue;
            }
            let lookup = |collection: &str, rkey: &str| held(repo, collection, rkey);
            match fetch_ops(transport, directory, cred, c, &lookup, now).await {
                Ok((nc, ops)) if ops_complete(&ops) => {
                    next.repos.insert(repo.to_owned(), nc);
                    changes.push(RepoChange::Ops {
                        repo: repo.to_owned(),
                        ops,
                    });
                    continue;
                }
                Ok(_) => {}
                Err(e) if e.is_repo_not_found() => {
                    changes.push(gone());
                    continue;
                }
                Err(e) if needs_full_fetch(&e) => {}
                Err(error) => {
                    next.repos.insert(repo.to_owned(), c.clone());
                    changes.push(RepoChange::Failed {
                        repo: repo.to_owned(),
                        error,
                    });
                    continue;
                }
            }
        }
        match fetch_repo(transport, directory, cred, repo, now).await {
            Ok((nc, _)) if held_cursor.is_some_and(|c| nc.rev < c.rev) => {
                if let Some(c) = held_cursor {
                    next.repos.insert(repo.to_owned(), c.clone());
                }
                changes.push(RepoChange::Failed {
                    repo: repo.to_owned(),
                    error: SyncError::Gap("repo is older than its cursor"),
                });
            }
            Ok((nc, records)) => {
                next.repos.insert(repo.to_owned(), nc);
                changes.push(RepoChange::Replaced {
                    repo: repo.to_owned(),
                    records,
                });
            }
            Err(e) if e.is_repo_not_found() => {
                if held_cursor.is_some() {
                    changes.push(gone());
                }
            }
            Err(error) => {
                if let Some(c) = held_cursor {
                    next.repos.insert(repo.to_owned(), c.clone());
                }
                changes.push(RepoChange::Failed {
                    repo: repo.to_owned(),
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
        assert!(needs_full_fetch(&SyncError::Gap("x")));
        assert!(needs_full_fetch(&SyncError::RecordMismatch));
        assert!(needs_full_fetch(&SyncError::Mac(
            umbrae_core::SignatureError::Invalid
        )));
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

    /// A repo host and directory in one, answering with real MACs.
    mod fake {
        use super::super::*;
        use crate::transport::{Identity, ResolveError, Response, TransportError};
        use base64::engine::general_purpose::STANDARD;
        use p256::SecretKey;
        use rand_core::OsRng;
        use serde_json::json;
        use std::future::Future;
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        use umbrae_core::didkey;
        use umbrae_core::repo_archive::write_repo_archive;
        use umbrae_core::uri::SpaceRef;

        pub const REPO: &str = "did:example:bob";
        pub const POST: &str = "tools.umbrae.post";
        pub const RKEY: &str = "3mbaaaaaaaaa2";
        pub const R1: &str = "3mbaaaaaaab22";
        pub const R2: &str = "3mbaaaaaaab33";
        pub const R3: &str = "3mbaaaaaaab44";

        pub fn block_on<F: Future>(f: F) -> F::Output {
            let mut f = pin!(f);
            let mut cx = Context::from_waker(Waker::noop());
            loop {
                if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                    return v;
                }
            }
        }

        pub fn space() -> SpaceRef {
            SpaceRef::new("did:example:alice", "tools.umbrae.space", "3mbbbbbbbbbb2").unwrap()
        }

        /// A post's JSON, DRISL bytes and CID.
        pub fn post(text: &str) -> (Value, Vec<u8>, Cid) {
            let v = json!({ "$type": POST, "text": text, "createdAt": "2026-11-14T10:00:00Z" });
            let bytes = drisl::encode(&D::Map(json::to_map(&v).unwrap())).unwrap();
            let cid = Cid::for_drisl(&bytes);
            (v, bytes, cid)
        }

        pub fn hash_of(records: &[(Vec<u8>, Cid)]) -> LtHash {
            let mut h = LtHash::new();
            for (_, cid) in records {
                h.add_record_cid(POST, RKEY, cid);
            }
            h
        }

        /// One repo, `REPO`, holding at most one post at `RKEY`.
        pub struct Host {
            pub kem: SecretKey,
            /// The KEM key a cached (unrefreshed) resolve returns.
            pub cached_kem: Option<String>,
            pub rev: &'static str,
            pub records: Vec<(Vec<u8>, Cid)>,
            pub ops: Value,
            pub extra_writers: Vec<Value>,
            /// An error name for every repo request.
            pub refuse: Option<&'static str>,
            /// What `listWriters` lists as `data`, in place of the digest.
            pub writer_data: Option<Value>,
            /// Paged answers, in place of `ops` or the one-page listing:
            /// page `i` is asked for with cursor `p{i}` (none for page 0),
            /// and carries the cursor given with it.
            pub ops_pages: Vec<(Value, Option<&'static str>)>,
            pub writer_pages: Vec<(Vec<Value>, Option<&'static str>)>,
            /// From this op-log page on, MACs are made with a wrong secret.
            pub bad_mac_from_page: Option<usize>,
            /// How many requests reached the host.
            pub requests: std::sync::atomic::AtomicUsize,
        }

        /// Which page a request asks for.
        fn page_of(req: &Request) -> usize {
            req.query
                .iter()
                .find(|(k, _)| *k == "cursor")
                .and_then(|(_, v)| v.strip_prefix('p')?.parse().ok())
                .unwrap_or(0)
        }

        impl Host {
            pub fn new(rev: &'static str, records: Vec<(Vec<u8>, Cid)>) -> Self {
                Host {
                    kem: SecretKey::random(&mut OsRng),
                    cached_kem: None,
                    rev,
                    records,
                    ops: json!([]),
                    extra_writers: Vec::new(),
                    refuse: None,
                    writer_data: None,
                    ops_pages: Vec::new(),
                    writer_pages: Vec::new(),
                    bad_mac_from_page: None,
                    requests: Default::default(),
                }
            }

            fn commit(&self) -> Commit {
                Commit::from_parts(1, REPO, space(), self.rev, hash_of(&self.records).digest())
                    .unwrap()
            }

            fn mac(&self, req: &Request) -> Vec<(String, String)> {
                let asked = req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("accept-signature"))
                    .map(|(_, v)| v.as_str());
                let r = mac::parse_mac_request(asked, MacProfile::Commit)
                    .unwrap()
                    .unwrap();
                let mut secret = kem::decapsulate(&self.kem, &r.key_share).unwrap();
                if self.bad_mac_from_page.is_some_and(|p| page_of(req) >= p) {
                    secret = [0u8; 32];
                }
                let h = mac::commit_mac_headers(&self.commit(), &r, &secret);
                vec![
                    (h.covered_name.into(), h.covered_value),
                    ("signature-input".into(), h.signature_input),
                    ("signature".into(), h.signature),
                ]
            }
        }

        fn reply(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Response {
            Response {
                status,
                headers,
                body,
            }
        }

        impl Transport for Host {
            async fn send(&self, req: Request) -> Result<Response, TransportError> {
                self.requests
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if req.nsid == "com.atproto.space.listWriters" && !self.writer_pages.is_empty() {
                    let (repos, cursor) = self
                        .writer_pages
                        .get(page_of(&req))
                        .cloned()
                        .unwrap_or_default();
                    let body = json!({ "repos": repos, "cursor": cursor }).to_string();
                    return Ok(reply(200, vec![], body.into_bytes()));
                }
                if req.nsid == "com.atproto.space.listWriters" {
                    let mut repos = self.extra_writers.clone();
                    let data = self.writer_data.clone().unwrap_or_else(
                        || json!({ "$bytes": STANDARD.encode(hash_of(&self.records).digest()) }),
                    );
                    repos.push(json!({
                        "$type": REPO_WRITE, "repo": REPO, "repoRev": self.rev,
                        "data": data, "spaceRev": "3mbaaaaaaaaz2",
                    }));
                    let body = json!({ "repos": repos }).to_string();
                    return Ok(reply(200, vec![], body.into_bytes()));
                }
                if let Some(name) = self.refuse {
                    let body = json!({ "error": name }).to_string();
                    return Ok(reply(400, vec![], body.into_bytes()));
                }
                match req.nsid {
                    "com.atproto.space.getRepo" => {
                        let body = write_repo_archive(
                            &self.commit(),
                            self.records.iter().map(|(b, _)| (POST, RKEY, b.as_slice())),
                        )
                        .unwrap();
                        Ok(reply(200, self.mac(&req), body))
                    }
                    "com.atproto.space.listRepoOps" => {
                        let c = self.commit();
                        let commit = json!({
                            "ver": 1, "repo": REPO, "space": space().to_string(), "rev": c.rev(),
                            "data": { "$bytes": STANDARD.encode(c.data()) },
                        });
                        let body = match self.ops_pages.get(page_of(&req)) {
                            Some((ops, cursor)) => {
                                json!({ "ops": ops, "commit": commit, "cursor": cursor })
                            }
                            None if self.ops_pages.is_empty() => {
                                json!({ "ops": self.ops, "commit": commit })
                            }
                            None => json!({ "ops": [], "commit": commit }),
                        };
                        Ok(reply(200, self.mac(&req), body.to_string().into_bytes()))
                    }
                    _ => Err(TransportError::Refused),
                }
            }
        }

        impl Directory for Host {
            async fn resolve(&self, _: &str, refresh: bool) -> Result<Identity, ResolveError> {
                let real = didkey::format_p256(&self.kem.public_key());
                let kem_key = match (&self.cached_kem, refresh) {
                    (Some(stale), false) => stale.clone(),
                    _ => real,
                };
                Ok(Identity {
                    pds: "https://pds.example".into(),
                    signing_key: None,
                    kem_key: Some(kem_key),
                    label_key: None,
                })
            }
        }
    }

    use fake::*;
    use serde_json::json;

    fn cred() -> Credential {
        Credential::for_tests(space())
    }

    fn holding(rev: &str, records: &[(Vec<u8>, Cid)]) -> SpaceCursor {
        let mut s = SpaceCursor::default();
        s.repos
            .insert(REPO.into(), RepoCursor::new(REPO, rev, &hash_of(records)));
        s
    }

    fn op_entry(rev: &str, cid: Option<Cid>, prev: Option<Cid>, value: Option<Value>) -> Value {
        let mut e = json!({
            "rev": rev, "collection": POST, "rkey": RKEY,
            "cid": cid.map(|c| c.to_string()), "prev": prev.map(|c| c.to_string()),
        });
        if let Some(v) = value {
            e["value"] = v;
        }
        e
    }

    #[test]
    fn op_logs_must_start_from_what_we_hold() {
        let (_, zb, z) = post("z");
        let (yv, yb, y) = post("y");
        let held_z = |_: &str, _: &str| Some(z);
        let cursor = holding(R1, &[(zb.clone(), z)]).repos[REPO].clone();

        // The host is honestly still at P = Z. Its ops cancel in the set
        // hash, but would have the caller show P = Y.
        let mut host = Host::new(R2, vec![(zb.clone(), z)]);
        host.ops = json!([
            op_entry(R2, None, Some(y), None),
            op_entry(R2, Some(y), None, Some(yv.clone())),
        ]);
        assert_eq!(
            block_on(fetch_ops(&host, &host, &cred(), &cursor, &held_z, 0)).unwrap_err(),
            SyncError::Gap("an op's prev isn't what we hold")
        );
        // `sync_space` falls back to the full repo, which says Z.
        let (_, changes) = block_on(sync_space(
            &host,
            &host,
            &cred(),
            &holding(R1, &[(zb.clone(), z)]),
            &|_: &str, _: &str, _: &str| Some(z),
            0,
        ))
        .unwrap();
        match changes.as_slice() {
            [RepoChange::Replaced { records, .. }] => assert_eq!(records[0].cid, z),
            other => panic!("{other:?}"),
        }

        // The honest update from Z to Y replays.
        let mut host = Host::new(R2, vec![(yb, y)]);
        host.ops = json!([op_entry(R2, Some(y), Some(z), Some(yv.clone()))]);
        let (next, ops) = block_on(fetch_ops(&host, &host, &cred(), &cursor, &held_z, 0)).unwrap();
        assert_eq!(next.rev, R2);
        assert_eq!(ops[0].record.as_ref().map(|r| r.cid), Some(y));

        // Ops at or before the cursor, or out of order, are refused.
        host.ops = json!([op_entry(R1, Some(y), Some(z), Some(yv.clone()))]);
        assert_eq!(
            block_on(fetch_ops(&host, &host, &cred(), &cursor, &held_z, 0)).unwrap_err(),
            SyncError::Gap("ops out of order")
        );
        host.ops = json!([
            op_entry(R3, None, Some(z), None),
            op_entry(R2, Some(y), None, Some(yv.clone())),
        ]);
        assert_eq!(
            block_on(fetch_ops(&host, &host, &cred(), &cursor, &held_z, 0)).unwrap_err(),
            SyncError::Gap("ops out of order")
        );

        // A value on a delete is refused.
        let mut host = Host::new(R2, vec![]);
        host.ops = json!([op_entry(R2, None, Some(z), Some(yv))]);
        assert_eq!(
            block_on(fetch_ops(&host, &host, &cred(), &cursor, &held_z, 0)).unwrap_err(),
            SyncError::RecordMismatch
        );
    }

    #[test]
    fn repos_older_than_the_cursor_are_refused() {
        let (_, zb, z) = post("z");
        // We're at R3, where the author had deleted Z; the host serves R2,
        // which still has it.
        let host = Host::new(R2, vec![(zb, z)]);
        let cursor = holding(R3, &[]);
        let (next, changes) = block_on(sync_space(
            &host,
            &host,
            &cred(),
            &cursor,
            &|_: &str, _: &str, _: &str| None,
            0,
        ))
        .unwrap();
        match changes.as_slice() {
            [RepoChange::Failed { error, .. }] => {
                assert_eq!(error, &SyncError::Gap("repo is older than its cursor"))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(next, cursor);
    }

    #[test]
    fn stale_kem_keys_are_refreshed_and_bad_values_fall_back() {
        let (_, zb, z) = post("z");
        let (_, yb, y) = post("y");
        let (other, _, _) = post("not y");
        let mut host = Host::new(R2, vec![(yb, y)]);
        host.cached_kem = Some(umbrae_core::didkey::format_p256(
            &p256::SecretKey::random(&mut rand_core::OsRng).public_key(),
        ));
        let (cursor, records) = block_on(fetch_repo(&host, &host, &cred(), REPO, 0)).unwrap();
        assert_eq!((cursor.rev.as_str(), records.len()), (R2, 1));

        // An op value that doesn't hash to its CID: fetch in full instead.
        host.ops = json!([op_entry(R2, Some(y), Some(z), Some(other))]);
        let (next, changes) = block_on(sync_space(
            &host,
            &host,
            &cred(),
            &holding(R1, &[(zb, z)]),
            &|_: &str, _: &str, _: &str| Some(z),
            0,
        ))
        .unwrap();
        match changes.as_slice() {
            [RepoChange::Replaced { records, .. }] => assert_eq!(records[0].cid, y),
            other => panic!("{other:?}"),
        }
        assert_eq!(next.repos[REPO].rev, R2);
    }

    #[test]
    fn repos_the_host_no_longer_has_are_dropped() {
        let (_, zb, z) = post("z");
        let mut host = Host::new(R2, vec![(zb.clone(), z)]);
        host.refuse = Some("RepoNotFound");
        let held_z = |_: &str, _: &str, _: &str| Some(z);
        let (next, changes) = block_on(sync_space(
            &host,
            &host,
            &cred(),
            &holding(R1, &[(zb.clone(), z)]),
            &held_z,
            0,
        ))
        .unwrap();
        assert_eq!(
            changes,
            [RepoChange::Replaced {
                repo: REPO.into(),
                records: vec![]
            }]
        );
        assert!(next.repos.is_empty());
        // Nothing held: nothing to drop.
        let (_, changes) = block_on(sync_space(
            &host,
            &host,
            &cred(),
            &SpaceCursor::default(),
            &held_z,
            0,
        ))
        .unwrap();
        assert!(changes.is_empty());
        // Other refusals keep what's held, to retry.
        host.refuse = Some("RepoTakendown");
        let held = holding(R1, &[(zb, z)]);
        let (next, changes) =
            block_on(sync_space(&host, &host, &cred(), &held, &held_z, 0)).unwrap();
        assert!(matches!(changes.as_slice(), [RepoChange::Failed { .. }]));
        assert_eq!(next, held);
    }

    #[test]
    fn one_writers_bad_digest_doesnt_stop_the_listing() {
        let (_, zb, z) = post("z");
        // The writer's own host reported two bytes as its digest; the
        // authority stores and lists them as given.
        let mut host = Host::new(R1, vec![(zb.clone(), z)]);
        host.writer_data = Some(json!({ "$bytes": "AAA=" }));
        let w = block_on(list_writers(&host, &host, &cred(), 0)).unwrap();
        assert_eq!(w.active[0].data, None);
        // Never skipped as unchanged: it's fetched and checked as usual.
        let held = holding(R1, &[(zb.clone(), z)]);
        let (next, changes) = block_on(sync_space(
            &host,
            &host,
            &cred(),
            &held,
            &|_: &str, _: &str, _: &str| Some(z),
            0,
        ))
        .unwrap();
        assert!(
            matches!(changes.as_slice(), [RepoChange::Ops { ops, .. }] if ops.is_empty()),
            "{changes:?}"
        );
        assert_eq!(next, held);
    }

    #[test]
    fn op_logs_are_capped_before_the_commit_check() {
        let (_, zb, z) = post("z");
        let (_, _, y) = post("y");
        let mut host = Host::new(R2, vec![(zb.clone(), z)]);
        let huge = json!({ "$type": POST, "text": "x".repeat(MAX_LOG_BYTES), "createdAt": "2026-11-14T10:00:00Z" });
        host.ops = json!([op_entry(R2, Some(y), Some(z), Some(huge))]);
        let cursor = holding(R1, &[(zb, z)]).repos[REPO].clone();
        assert_eq!(
            block_on(fetch_ops(
                &host,
                &host,
                &cred(),
                &cursor,
                &|_: &str, _: &str| Some(z),
                0
            ))
            .unwrap_err(),
            SyncError::Gap("op log too long")
        );
    }

    #[test]
    fn broken_or_misfiled_cursors_fetch_in_full() {
        let (_, zb, z) = post("z");
        let host = Host::new(R2, vec![(zb.clone(), z)]);
        let any = |_: &str, _: &str, _: &str| Some(z);
        // A state that won't decode.
        let mut broken = holding(R1, &[(zb.clone(), z)]);
        broken.repos.get_mut(REPO).unwrap().state = "AAAA".into();
        // A cursor for another repo, filed under this one.
        let mut misfiled = holding(R1, &[(zb, z)]);
        misfiled.repos.get_mut(REPO).unwrap().repo = "did:example:carol".into();
        for cursor in [broken, misfiled] {
            let (next, changes) =
                block_on(sync_space(&host, &host, &cred(), &cursor, &any, 0)).unwrap();
            assert!(
                matches!(changes.as_slice(), [RepoChange::Replaced { .. }]),
                "{changes:?}"
            );
            assert_eq!(next.repos[REPO].repo, REPO);
        }
    }

    #[test]
    fn listings_follow_every_cursor_and_are_capped() {
        let entry = |i: usize| {
            json!({
                "$type": REPO_WRITE, "repo": format!("did:example:w{i}"), "repoRev": R1,
                "data": { "$bytes": base64::engine::general_purpose::STANDARD.encode([0u8; 32]) },
                "spaceRev": R1,
            })
        };
        let mut host = Host::new(R1, vec![]);
        // A host that pages below the asked limit: every page is read, so
        // no held writer is mistaken for removed.
        host.writer_pages = vec![
            (vec![entry(0)], Some("p1")),
            (vec![entry(1)], Some("p2")),
            (vec![entry(2)], None),
        ];
        let w = block_on(list_writers(&host, &host, &cred(), 0)).unwrap();
        assert_eq!(w.active.len(), 3);
        // A repeated cursor ends the listing.
        host.writer_pages = vec![(vec![entry(0)], Some("p1")), (vec![entry(1)], Some("p1"))];
        let w = block_on(list_writers(&host, &host, &cred(), 0)).unwrap();
        assert_eq!(w.active.len(), 2);
        // Writers listing huge `data` (16 MiB in all) don't fail the
        // listing: the bad values are dropped.
        let big = |i: usize| {
            let mut e = entry(i);
            e["data"] = json!({ "$bytes": "A".repeat(1 << 20) });
            e
        };
        host.writer_pages = vec![((0..16).map(big).collect(), None)];
        let w = block_on(list_writers(&host, &host, &cred(), 0)).unwrap();
        assert_eq!(w.active.len(), 16);
        assert!(w.active.iter().all(|w| w.data.is_none()));
        // A listing past its entry cap is refused.
        host.writer_pages = vec![(vec![json!({}); MAX_LIST_ENTRIES + 1], None)];
        assert_eq!(
            block_on(list_writers(&host, &host, &cred(), 0)).unwrap_err(),
            SyncError::Malformed("listWriters too long")
        );
    }

    #[test]
    fn op_logs_page_only_after_full_pages() {
        let (zv, zb, z) = post("z");
        let none = |_: &str, _: &str| None;
        let cursor = holding(R1, &[]).repos[REPO].clone();
        // A full page of creates and deletes, then the create that stays:
        // replayed across both pages against the last page's commit.
        let churn = (0..PAGE_LIMIT)
            .map(|i| match i % 2 {
                0 => op_entry(R2, Some(z), None, None),
                _ => op_entry(R2, None, Some(z), None),
            })
            .collect();
        let mut host = Host::new(R2, vec![(zb, z)]);
        host.ops_pages = vec![
            (Value::Array(churn), Some("p1")),
            (json!([op_entry(R2, Some(z), None, Some(zv.clone()))]), None),
        ];
        let (next, ops) = block_on(fetch_ops(&host, &host, &cred(), &cursor, &none, 0)).unwrap();
        assert_eq!((next.rev.as_str(), ops.len()), (R2, PAGE_LIMIT + 1));
        // A short page's cursor isn't followed: the page after it, which
        // would delete Z and so miss the commit, is never read.
        host.ops_pages = vec![
            (json!([op_entry(R2, Some(z), None, Some(zv))]), Some("p1")),
            (json!([op_entry(R3, None, Some(z), None)]), None),
        ];
        let (_, ops) = block_on(fetch_ops(&host, &host, &cred(), &cursor, &none, 0)).unwrap();
        assert_eq!(ops.len(), 1);
    }

    /// A full page of ops that create and delete Z at R2.
    fn churn(z: Cid) -> Value {
        (0..PAGE_LIMIT)
            .map(|i| match i % 2 {
                0 => op_entry(R2, Some(z), None, None),
                _ => op_entry(R2, None, Some(z), None),
            })
            .collect()
    }

    #[test]
    fn one_hostile_log_costs_few_requests() {
        use std::sync::atomic::Ordering::Relaxed;
        let (_, _, z) = post("z");
        let none = |_: &str, _: &str| None;
        let cursor = holding(R1, &[]).repos[REPO].clone();
        // Full pages without end: cut off after `MAX_OP_PAGES`.
        const CURSORS: [&str; 20] = [
            "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13",
            "p14", "p15", "p16", "p17", "p18", "p19", "p20",
        ];
        let mut host = Host::new(R2, vec![]);
        host.ops_pages = CURSORS.iter().map(|c| (churn(z), Some(*c))).collect();
        assert_eq!(
            block_on(fetch_ops(&host, &host, &cred(), &cursor, &none, 0)).unwrap_err(),
            SyncError::Gap("op log has too many pages")
        );
        assert_eq!(host.requests.load(Relaxed), MAX_OP_PAGES);
        // A MAC that fails after the first page isn't a stale key: no
        // replay of the log under a refreshed one.
        let mut host = Host::new(R2, vec![]);
        host.ops_pages = vec![(churn(z), Some("p1")), (json!([]), None)];
        host.bad_mac_from_page = Some(1);
        assert_eq!(
            block_on(fetch_ops(&host, &host, &cred(), &cursor, &none, 0)).unwrap_err(),
            SyncError::Gap("MAC failed partway through the log")
        );
        assert_eq!(host.requests.load(Relaxed), 2);
    }

    #[test]
    fn unknown_writer_entries_are_skipped() {
        let mut host = Host::new(R1, vec![]);
        host.extra_writers = vec![
            json!({ "$type": "com.atproto.space.defs#repoSomethingNew", "x": 1 }),
            json!({ "repo": "did:example:carol" }),
        ];
        let w = block_on(list_writers(&host, &host, &cred(), 0)).unwrap();
        assert_eq!(w.active.len(), 1);
        assert_eq!(w.active[0].repo, REPO);
        assert!(w.removed.is_empty());
    }
}
