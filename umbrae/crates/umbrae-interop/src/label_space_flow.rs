//! In-space labels (`com.atproto.label.record`) and `!takedown`, against a
//! stand-in managing app.
//!
//! The harness stands in for the app (prism, or a PDS such as
//! Aurora-Locus), under one DID in the mock PLC, managing one community and
//! everyone spaces. It answers `checkAccess` as the design says:
//! - a community space: nothing unless the service auth names the space's
//!   authority and `checkAccess` and the authority is a writer; then rule
//!   4a, write only, for the community's named labeler with no `clientId`;
//!   nothing for any other account; read for its own attested client;
//! - an everyone space: read and write for an admitted account, write only
//!   for a configured labeler, read for its own attested client.
//!
//! Then: the community's labeler labels and takes down a writer's posts,
//! is pushed out with `removeWriter` and comes back; a configured labeler
//! labels an everyone post next to an untrusted replier; a group owner
//! takes down a member's reply; and, on atproto-pds only, a host record
//! takedown through `umbrae-sync`. Every decision is the `umbrae` crate's,
//! from what was synced.

use crate::labeler_flow::Client;
use crate::sync_flow::{apply, block_on, lookup, Blocking, Plc, Store};
use crate::umbrae_flow::{delegation, read_space, state_of, sync, Synced};
use crate::{create_account, expect_refusal, same_answer, Account, Pds, Report, Resp};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;
use umbrae::access::{can_view_record, is_label_writer};
use umbrae::community::{referenced_post, ReferencedPost};
use umbrae::labeler::{apply_takedowns, can_view_space_label, current_space_labels};
use umbrae::space::{community_space, everyone_space, group_policy, group_space};
use umbrae::{SpaceState, Tri, ViewContext, SPACE_TYPE};
use umbrae_core::didkey;
use umbrae_core::drisl::Value as D;
use umbrae_core::policy::MemberAccess;
use umbrae_core::uri::{SpaceRecordUri, SpaceRef};
use umbrae_lexicons::{
    community_skey, validate_space_label, CommunityRef, SpaceLabel, EVERYONE_SKEY, POST,
    SPACE_LABEL, TAKEDOWN,
};
use umbrae_sync::{authorize, sync_space, Authorize, RepoChange, SpaceCursor};

const APP_DID: &str = "did:plc:labelsappaaaaaaaaaaaaaaa";
const APP_SERVICE: &str = "umbrae_app";
/// The TLS front end, which proxies `/xrpc/` to the harness.
const HOST: &str = "https://client.interop.test";
const CHECK: &str = "com.atproto.managedspace.checkAccess";
const KEY: &str = "labels";
const CREATED: &str = "2026-11-27T12:00:00.000Z";
const NOTHING: (bool, bool) = (false, false);
const RW: MemberAccess = MemberAccess {
    read: true,
    write: true,
};

#[derive(Debug, Clone)]
struct Call {
    space: String,
    repo: Option<String>,
    client_id: Option<String>,
    answer: (bool, bool),
}

static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());
static APP_CLIENT: Mutex<String> = Mutex::new(String::new());
/// The community's writers, and its named labeler.
static WRITERS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
static LABELER: Mutex<String> = Mutex::new(String::new());
/// Everyone spaces: their owners, the accounts the app admits, and the
/// labelers it applies.
static OWNERS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
static ADMITTED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
static LABELERS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn app() -> String {
    format!("{APP_DID}#{APP_SERVICE}")
}

fn community() -> CommunityRef {
    CommunityRef::new(&app(), KEY).expect("a valid community ref")
}

fn has(set: &Mutex<BTreeSet<String>>, did: &str) -> bool {
    set.lock().unwrap().contains(did)
}

fn add(set: &Mutex<BTreeSet<String>>, did: &str) {
    set.lock().unwrap().insert(did.to_owned());
}

fn claims(authorization: Option<&str>) -> Value {
    authorization
        .and_then(|a| a.strip_prefix("Bearer "))
        .and_then(|t| t.split('.').nth(1))
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

/// Answer a checkAccess call addressed to this app.
pub(crate) fn handle(url: &str, authorization: Option<&str>) -> Option<(u16, Value)> {
    let (p, query) = url.split_once('?').unwrap_or((url, ""));
    if p != format!("/xrpc/{CHECK}") {
        return None;
    }
    let c = claims(authorization);
    if c["aud"].as_str() != Some(app().as_str()) {
        return None;
    }
    let param = |k: &str| {
        query.split('&').find_map(|kv| {
            let (a, b) = kv.split_once('=')?;
            (a == k)
                .then(|| crate::plc::percent_decode(b))
                .filter(|v| !v.is_empty())
        })
    };
    let mut call = Call {
        space: param("space").unwrap_or_default(),
        repo: param("repo"),
        client_id: param("clientId"),
        answer: NOTHING,
    };
    call.answer = answer(&call, &c);
    let (read, write) = call.answer;
    CALLS.lock().unwrap().push(call);
    Some((200, json!({ "read": read, "write": write })))
}

fn answer(call: &Call, c: &Value) -> (bool, bool) {
    let Ok(space) = SpaceRef::parse(&call.space) else {
        return NOTHING;
    };
    let authority = space.authority();
    if space.space_type() != SPACE_TYPE
        || c["iss"].as_str() != Some(authority)
        || c["lxm"].as_str() != Some(CHECK)
    {
        return NOTHING;
    }
    let own_client = call.client_id.as_deref() == Some(APP_CLIENT.lock().unwrap().as_str());
    if space.skey() == community_skey(&community()) {
        if !has(&WRITERS, authority) {
            return NOTHING;
        }
        return match &call.repo {
            // Rule 4a: the community's named labeler, with no clientId.
            Some(r) if call.client_id.is_none() && *r == *LABELER.lock().unwrap() => (false, true),
            Some(_) => NOTHING,
            None => (own_client, false),
        };
    }
    if space.skey() == EVERYONE_SKEY && has(&OWNERS, authority) {
        return match &call.repo {
            Some(r) if call.client_id.is_none() && has(&LABELERS, r) => (false, true),
            Some(r) if has(&ADMITTED, r) => (true, true),
            Some(_) => NOTHING,
            None => (own_client, false),
        };
    }
    NOTHING
}

fn ncalls() -> usize {
    CALLS.lock().unwrap().len()
}

fn calls_since(n: usize) -> Vec<Call> {
    CALLS.lock().unwrap()[n..].to_vec()
}

/// What was asked about `did`, and answered.
fn asked(calls: &[Call], did: &str) -> Vec<(bool, (bool, bool))> {
    calls
        .iter()
        .filter(|c| c.repo.as_deref() == Some(did))
        .map(|c| (c.client_id.is_some(), c.answer))
        .collect()
}

fn settle() {
    std::thread::sleep(Duration::from_millis(2500));
}

struct Everyone;
impl ViewContext for Everyone {
    fn is_active(&self, _: &str) -> Tri {
        Tri::Yes
    }
    fn blocked(&self, _: &str, _: &str) -> Tri {
        Tri::No
    }
}

fn create_space(pds: &Pds, who: &Account, space: &SpaceRef, policy: Value) -> Result<(), String> {
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": SPACE_TYPE, "skey": space.skey(), "policy": policy }),
        &who.auth(),
    )?
    .ok("createSpace")
    .map(|_| ())
}

fn write(
    pds: &Pds,
    space: &SpaceRef,
    who: &Account,
    collection: &str,
    rkey: &str,
    record: Value,
) -> Result<Resp, String> {
    pds.post(
        "com.atproto.space.createRecord",
        &json!({ "space": space.to_string(), "repo": who.did, "collection": collection,
            "rkey": rkey, "record": record }),
        &who.auth(),
    )
}

/// Write a record, and return its URI and strong ref.
fn put(
    pds: &Pds,
    space: &SpaceRef,
    who: &Account,
    collection: &str,
    rkey: &str,
    record: Value,
) -> Result<(SpaceRecordUri, Value), String> {
    let r = write(pds, space, who, collection, rkey, record)?.ok(collection)?;
    let uri = space
        .record(&who.did, collection, rkey)
        .map_err(|e| e.to_string())?;
    let cid = r.json()["cid"].as_str().unwrap_or_default().to_owned();
    Ok((uri.clone(), json!({ "uri": uri.to_string(), "cid": cid })))
}

fn delete(pds: &Pds, who: &Account, uri: &SpaceRecordUri) -> Result<(), String> {
    pds.post(
        "com.atproto.space.deleteRecord",
        &json!({ "space": uri.space().to_string(), "repo": who.did,
            "collection": uri.collection(), "rkey": uri.rkey() }),
        &who.auth(),
    )?
    .ok("deleteRecord")
    .map(|_| ())
}

fn label(subject: &SpaceRecordUri, val: &str) -> Value {
    json!({ "$type": SPACE_LABEL, "uri": subject.to_string(), "val": val, "cts": CREATED })
}

fn post(text: &str) -> Value {
    json!({ "$type": POST, "text": text, "createdAt": CREATED })
}

/// The app syncs a space with its attested client and no delegation: the
/// writer set and every writer's repo.
fn app_sync(
    pds: &Pds,
    dir: &crate::plc::Directory,
    space: &SpaceRef,
    client: &Client,
) -> Result<Synced, String> {
    let key = SigningKey::random(&mut OsRng);
    let body = json!({ "space": space.to_string(),
        "credentialKey": didkey::format_p256(&key.verifying_key().into()),
        "clientAttestation": client.attest(space.authority()) });
    let credential = pds
        .post("com.atproto.space.authorizeSpaceSync", &body, &vec![])?
        .ok("the app's authorizeSpaceSync")?
        .json()["credential"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    read_space(pds, dir, space, credential, key, None)
}

/// Every label record synced, validated against its own URI.
fn labels(space: &SpaceRef, s: &Synced) -> Vec<(SpaceRecordUri, SpaceLabel)> {
    let mut out = Vec::new();
    for (did, records) in &s.repos {
        for r in records.iter().filter(|r| r.collection == SPACE_LABEL) {
            let Ok(uri) = space.record(did, &r.collection, &r.rkey) else {
                continue;
            };
            if let Ok(l) = validate_space_label(&uri, &r.value) {
                out.push((uri, l));
            }
        }
    }
    out
}

fn current(v: &[(SpaceRecordUri, SpaceLabel)]) -> Vec<(&SpaceRecordUri, &SpaceLabel)> {
    current_space_labels(v.iter().map(|(u, l)| (u, l)), crate::now() * 1000)
}

/// The labels `viewer` is shown, as `writer val rkey`.
fn shown(
    viewer: &str,
    state: &SpaceState,
    v: &[(SpaceRecordUri, SpaceLabel)],
    trusted: &BTreeSet<String>,
) -> Vec<String> {
    current(v)
        .into_iter()
        .filter(|(u, l)| {
            can_view_space_label(Some(viewer), l, u.author(), state, trusted, &Everyone)
        })
        .map(|(u, l)| {
            let d = u.author();
            format!(
                "..{} {} {}",
                &d[d.len().saturating_sub(4)..],
                l.val,
                l.record().map(|r| r.rkey()).unwrap_or_default()
            )
        })
        .collect()
}

fn short(d: &str) -> &str {
    &d[d.len().saturating_sub(6)..]
}

fn set(dids: &[&str]) -> BTreeSet<String> {
    dids.iter().map(|d| d.to_string()).collect()
}

pub(crate) fn run(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
) -> Result<(), String> {
    let client_dir = std::env::var("CLIENT_DIR").unwrap_or_else(|_| "/client".into());
    let client = Client::publish(&client_dir, "labels-app")?;
    *APP_CLIENT.lock().unwrap() = client.id.clone();
    dir.put(
        APP_DID,
        json!({
            "type": "plc_operation",
            "verificationMethods": {},
            "rotationKeys": [],
            "alsoKnownAs": [],
            "services": { APP_SERVICE: { "type": "UmbraeManagingApp", "endpoint": HOST } },
            "prev": null,
        }),
    );
    communities(pds, dir, report, &client)?;
    everyone(pds, dir, report, &client)?;
    groups(pds, dir, report)
}

fn communities(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    client: &Client,
) -> Result<(), String> {
    let alice = create_account(pds, "lcalice")?;
    let bob = create_account(pds, "lcbob")?;
    let lab = create_account(pds, "lclabeler")?;
    let dan = create_account(pds, "lcdan")?;
    add(&WRITERS, &alice.did);
    add(&WRITERS, &bob.did);
    *LABELER.lock().unwrap() = lab.did.clone();
    report.check(
        "labels: community setup",
        Ok(format!(
            "alice ..{} bob ..{} (writers), labeler ..{}, dan ..{} (outside); token lengths {} {} {} {}",
            short(&alice.did),
            short(&bob.did),
            short(&lab.did),
            short(&dan.did),
            alice.access.len(),
            bob.access.len(),
            lab.access.len(),
            dan.access.len()
        )),
    );
    let space = community_space(&alice.did, &community()).map_err(|e| e.to_string())?;
    create_space(
        pds,
        &alice,
        &space,
        json!({ "$type": "com.atproto.managedspace.policy", "managingApp": app(), "publishPolicy": true }),
    )?;
    let (p1, _) = put(pds, &space, &alice, POST, "3mbaaaaaaal32", post("first"))?;
    let (p2, _) = put(pds, &space, &alice, POST, "3mbaaaaaaal33", post("second"))?;
    let state = |s: &Synced| {
        let mut st = state_of(&space, s);
        st.community = Some(community());
        for d in WRITERS.lock().unwrap().iter() {
            st.members.insert(d, RW);
        }
        st.label_writers.insert(lab.did.clone());
        st
    };
    let trusted = set(&[&lab.did]);

    // Rule 4a: the labeler's label write is asked about with repo = the
    // labeler and no clientId, and answered write.
    let n = ncalls();
    let (spam, _) = put(
        pds,
        &space,
        &lab,
        SPACE_LABEL,
        "3mbaaaaaaal42",
        label(&p1, "spam"),
    )?;
    settle();
    let c = calls_since(n);
    let s1 = app_sync(pds, dir, &space, client)?;
    let st1 = state(&s1);
    let l1 = labels(&space, &s1);
    let bob_sees = shown(&bob.did, &st1, &l1, &trusted);
    let dan_sees = shown(&dan.did, &st1, &l1, &trusted);
    report.check(
        "labels: rule 4a: the named labeler's label write is asked about with repo = the labeler and no clientId, answered write; it enters the writer set, the app syncs it, and a member is shown it, an outsider not",
        if asked(&c, &lab.did) == [(false, (false, true))]
            && s1.writers.contains(&lab.did)
            && bob_sees.len() == 1
            && dan_sees.is_empty()
        {
            Ok(format!("writers {}; bob sees {bob_sees:?}", s1.writers.len()))
        } else {
            Err(format!("calls {c:?}; writers {:?}; bob {bob_sees:?} dan {dan_sees:?}", s1.writers))
        },
    );

    // The labeler's own credential request: the same question, and read is
    // false, so it's refused.
    let n = ncalls();
    let r = sync(pds, dir, &space, &lab, None);
    let c = calls_since(n);
    report.check(
        "labels: rule 4a: the labeler's own delegation gets no credential (asked as for a write, read is false)",
        match &r {
            Err(e) if e.contains("SpaceNotFound") && asked(&c, &lab.did) == [(false, (false, true))] => {
                Ok("SpaceNotFound".into())
            }
            Err(e) => Err(format!("{e}; calls {c:?}")),
            Ok(_) => Err("got a credential".into()),
        },
    );

    // Bob, a writer of his own space, writes a label into Alice's: his PDS
    // takes it, the app answers nothing, he's not in the writer set and not
    // a label writer.
    let n = ncalls();
    let bw = write(
        pds,
        &space,
        &bob,
        SPACE_LABEL,
        "3mbaaaaaaal43",
        label(&p1, "spam"),
    )?;
    settle();
    let c = calls_since(n);
    let s = app_sync(pds, dir, &space, client)?;
    let st = state(&s);
    let fetched = {
        let kem = dir.key(&bob.did, "atproto_kem").ok_or("no #atproto_kem")?;
        let enc = umbrae_core::kem::encapsulate(&kem).map_err(|e| e.to_string())?;
        pds.get(
            "com.atproto.space.getRepo",
            &[("space", &space.to_string()), ("repo", &bob.did)],
            &crate::with_mac(
                crate::credential_headers(&s.credential, &bob.did, &s.key),
                umbrae_core::mac::MacProfile::Commit,
                &enc,
            ),
        )?
    };
    let direct = if fetched.status == 200 {
        "served".to_owned()
    } else {
        fetched.error_name()
    };
    report.check(
        "labels: another writer's label write into Alice's space: answered nothing, outside the writer set, not a label writer, and not shown",
        if asked(&c, &bob.did) == [(false, NOTHING)]
            && !s.writers.contains(&bob.did)
            && !is_label_writer(&bob.did, &st)
            && shown(&bob.did, &st, &labels(&space, &s), &set(&[&bob.did, &lab.did])).len() == 1
        {
            Ok(format!("write HTTP {}; writers {}", bw.status, s.writers.len()))
        } else {
            Err(format!("write HTTP {}; calls {c:?}; writers {:?}", bw.status, s.writers))
        },
    );
    report.check(
        "labels: a repo outside the writer set, fetched directly (expected difference)",
        if same_answer("served", &direct) {
            Ok(direct)
        } else {
            Err(format!("HTTP {} {direct}", fetched.status))
        },
    );

    // The labeler's !takedown is the community's takedown.
    let (down, _) = put(
        pds,
        &space,
        &lab,
        SPACE_LABEL,
        "3mbaaaaaaal44",
        label(&p2, TAKEDOWN),
    )?;
    settle();
    let s2 = app_sync(pds, dir, &space, client)?;
    let held = labels(&space, &s2);
    let mut st2 = state(&s2);
    apply_takedowns(&mut st2, current(&held));
    let hidden = [&bob.did, &alice.did]
        .iter()
        .all(|v| !can_view_record(Some(v), &p2, &st2, &Everyone));
    report.check(
        "labels: the named labeler's !takedown on Alice's post hides it from every viewer, Alice included, with a placeholder; her other post stays",
        if hidden
            && can_view_record(Some(&bob.did), &p1, &st2, &Everyone)
            && referenced_post(Some(&bob.did), &p2, Some(&st2), &Everyone) == ReferencedPost::Unavailable
        {
            Ok(format!("taken down {:?}", st2.taken_down.len()))
        } else {
            Err(format!("taken down {:?}", st2.taken_down))
        },
    );

    // Alice pushes the labeler out of the writer set. The app keeps its
    // last-synced labels, the !takedown included.
    let rw = pds
        .post(
            "com.atproto.space.removeWriter",
            &json!({ "space": space.to_string(), "repo": lab.did }),
            &alice.auth(),
        )?
        .ok("removeWriter")?;
    settle();
    let s3 = app_sync(pds, dir, &space, client)?;
    let mut kept = state(&s3);
    apply_takedowns(&mut kept, current(&held));
    let mut dropped = state(&s3);
    apply_takedowns(&mut dropped, current(&labels(&space, &s3)));
    report.check(
        "labels: after removeWriter the labeler's repo is out of the writer set and not synced; the app's kept labels still hide the post and show the label (without them it would show)",
        if rw.status == 200
            && !s3.writers.contains(&lab.did)
            && !s3.repos.contains_key(&lab.did)
            && !can_view_record(Some(&bob.did), &p2, &kept, &Everyone)
            && shown(&bob.did, &kept, &held, &trusted).len() == 1
            && can_view_record(Some(&bob.did), &p2, &dropped, &Everyone)
        {
            Ok(format!("writers {}", s3.writers.len()))
        } else {
            Err(format!("writers {:?}", s3.writers))
        },
    );

    // Its next write there brings the repo back, whole.
    let n = ncalls();
    put(
        pds,
        &space,
        &lab,
        SPACE_LABEL,
        "3mbaaaaaaal45",
        label(&p1, "rude"),
    )?;
    settle();
    let c = calls_since(n);
    let s4 = app_sync(pds, dir, &space, client)?;
    let back: Vec<_> = s4
        .repos
        .get(&lab.did)
        .map(|r| r.iter().map(|x| x.rkey.clone()).collect())
        .unwrap_or_default();
    report.check(
        "labels: the labeler's next write is asked about again, re-adds it, and its repo syncs whole, earlier labels included",
        if asked(&c, &lab.did) == [(false, (false, true))]
            && s4.writers.contains(&lab.did)
            && ["3mbaaaaaaal42", "3mbaaaaaaal44", "3mbaaaaaaal45"]
                .iter()
                .all(|k| back.iter().any(|b| b == k))
        {
            Ok(format!("labeler records {back:?}"))
        } else {
            Err(format!("calls {c:?}; writers {:?}; labeler records {back:?}", s4.writers))
        },
    );

    // Removing labels: the labeler deletes its records.
    delete(pds, &lab, &spam)?;
    delete(pds, &lab, &down)?;
    settle();
    let s5 = app_sync(pds, dir, &space, client)?;
    let l5 = labels(&space, &s5);
    let mut st5 = state(&s5);
    apply_takedowns(&mut st5, current(&l5));
    let now_shown = shown(&bob.did, &st5, &l5, &trusted);
    report.check(
        "labels: deleting the label records removes them from the next sync: the post is back, only the newer label shows",
        if can_view_record(Some(&bob.did), &p2, &st5, &Everyone)
            && st5.taken_down.is_empty()
            && now_shown.len() == 1
            && now_shown[0].contains("rude")
        {
            Ok(format!("{now_shown:?}"))
        } else {
            Err(format!("{now_shown:?}; taken down {:?}", st5.taken_down))
        },
    );
    Ok(())
}

fn everyone(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    client: &Client,
) -> Result<(), String> {
    let owner = create_account(pds, "leowner")?;
    let bob = create_account(pds, "lebob")?;
    let lab = create_account(pds, "lelabeler")?;
    let carol = create_account(pds, "lecarol")?;
    add(&OWNERS, &owner.did);
    add(&ADMITTED, &bob.did);
    add(&LABELERS, &lab.did);
    report.check(
        "labels: everyone setup",
        Ok(format!(
            "owner ..{} bob ..{} (admitted), labeler ..{} (configured), carol ..{} (neither); token lengths {} {} {} {}",
            short(&owner.did),
            short(&bob.did),
            short(&lab.did),
            short(&carol.did),
            owner.access.len(),
            bob.access.len(),
            lab.access.len(),
            carol.access.len()
        )),
    );
    let space = everyone_space(&owner.did).map_err(|e| e.to_string())?;
    create_space(
        pds,
        &owner,
        &space,
        json!({ "$type": "com.atproto.managedspace.policy", "managingApp": app(), "publishPolicy": true }),
    )?;
    let (p, pref) = put(
        pds,
        &space,
        &owner,
        POST,
        "3mbaaaaaaal52",
        post("for everyone"),
    )?;
    let n = ncalls();
    let (reply, _) = put(
        pds,
        &space,
        &bob,
        POST,
        "3mbaaaaaaal53",
        json!({ "$type": POST, "text": "a reply", "createdAt": CREATED,
            "reply": { "root": pref, "parent": pref } }),
    )?;
    put(
        pds,
        &space,
        &bob,
        SPACE_LABEL,
        "3mbaaaaaaal54",
        label(&p, "spam"),
    )?;
    let (lab_label, _) = put(
        pds,
        &space,
        &lab,
        SPACE_LABEL,
        "3mbaaaaaaal55",
        label(&p, "spam"),
    )?;
    let cw = write(
        pds,
        &space,
        &carol,
        SPACE_LABEL,
        "3mbaaaaaaal56",
        label(&p, "spam"),
    )?;
    settle();
    let c = calls_since(n);
    let s = app_sync(pds, dir, &space, client)?;
    let state = |s: &Synced| {
        let mut st = state_of(&space, s);
        for d in ADMITTED.lock().unwrap().iter() {
            st.members.insert(d, RW);
        }
        st.label_writers = s
            .writers
            .iter()
            .filter(|w| *w != &owner.did)
            .cloned()
            .collect();
        st
    };
    let st = state(&s);
    let l = labels(&space, &s);
    let trusted = set(&[&lab.did]);
    let sees = shown(&bob.did, &st, &l, &trusted);
    let answers = (
        asked(&c, &bob.did).iter().all(|a| a.1 == (true, true)) && !asked(&c, &bob.did).is_empty(),
        asked(&c, &lab.did).iter().all(|a| a.1 == (false, true)) && !asked(&c, &lab.did).is_empty(),
        asked(&c, &carol.did).iter().all(|a| a.1 == NOTHING) && !asked(&c, &carol.did).is_empty(),
    );
    report.check(
        "labels: everyone: the app answers read and write for an admitted replier, write only for its labeler, nothing for anyone else; the reply counts; the trusted labeler's label shows, the untrusted replier's doesn't",
        if answers == (true, true, true)
            && st.label_writers == set(&[&bob.did, &lab.did])
            && can_view_record(Some(&bob.did), &reply, &st, &Everyone)
            && sees.len() == 1
            && sees[0].starts_with(&format!("..{}", &lab.did[lab.did.len() - 4..]))
            && shown(&bob.did, &st, &l, &set(&[&bob.did, &lab.did])).len() == 2
        {
            Ok(format!("carol's write HTTP {}; writers {}; bob sees {sees:?}", cw.status, s.writers.len()))
        } else {
            Err(format!("answers {answers:?}; calls {c:?}; label writers {:?}; bob sees {sees:?}", st.label_writers))
        },
    );
    report.check(
        "labels: everyone: the labeler can't read the space itself",
        expect_refusal(
            &{
                let key = SigningKey::random(&mut OsRng);
                let token = delegation(pds, &space.to_string(), &lab)?;
                pds.post(
                    "com.atproto.space.authorizeSpaceSync",
                    &json!({ "space": space.to_string(), "delegationToken": token,
                        "credentialKey": didkey::format_p256(&key.verifying_key().into()) }),
                    &vec![],
                )?
            },
            Some("SpaceNotFound"),
        ),
    );
    delete(pds, &lab, &lab_label)?;
    settle();
    let s = app_sync(pds, dir, &space, client)?;
    let st = state(&s);
    let l = labels(&space, &s);
    let gone = !l.iter().any(|(u, _)| u == &lab_label);
    report.check(
        "labels: everyone: once the labeler deletes its label, the next sync has none of its labels to show",
        if gone && shown(&bob.did, &st, &l, &trusted).is_empty() {
            Ok(format!("{} label record(s) left", l.len()))
        } else {
            Err(format!("still there {}", !gone))
        },
    );
    Ok(())
}

fn groups(pds: &Pds, dir: &crate::plc::Directory, report: &mut Report) -> Result<(), String> {
    let alice = create_account(pds, "lgalice")?;
    let bob = create_account(pds, "lgbob")?;
    let carol = create_account(pds, "lgcarol")?;
    report.check(
        "labels: group setup",
        Ok(format!(
            "alice ..{} bob ..{} carol ..{}; token lengths {} {} {}",
            short(&alice.did),
            short(&bob.did),
            short(&carol.did),
            alice.access.len(),
            bob.access.len(),
            carol.access.len()
        )),
    );
    let space = group_space(&alice.did, "3mbbbbbbbbbl2").map_err(|e| e.to_string())?;
    let mut policy = json!({ "$type": "com.atproto.memberspace.policy" });
    for (k, v) in group_policy(None).to_map() {
        if let D::Bool(b) = v {
            policy[k] = json!(b);
        }
    }
    create_space(pds, &alice, &space, policy)?;
    pds.post(
        "com.atproto.memberspace.putMembers",
        &json!({ "space": space.to_string(), "members": [
            { "did": bob.did, "read": true, "write": true },
            { "did": carol.did, "read": true, "write": true } ] }),
        &alice.auth(),
    )?
    .ok("putMembers")?;
    let (p, pref) = put(
        pds,
        &space,
        &alice,
        POST,
        "3mbaaaaaaal62",
        post("group post"),
    )?;
    let (reply, _) = put(
        pds,
        &space,
        &bob,
        POST,
        "3mbaaaaaaal63",
        json!({ "$type": POST, "text": "bob's reply", "createdAt": CREATED,
            "reply": { "root": pref, "parent": pref } }),
    )?;
    let (down, _) = put(
        pds,
        &space,
        &alice,
        SPACE_LABEL,
        "3mbaaaaaaal64",
        label(&reply, TAKEDOWN),
    )?;
    put(
        pds,
        &space,
        &carol,
        SPACE_LABEL,
        "3mbaaaaaaal65",
        label(&p, TAKEDOWN),
    )?;
    settle();
    let view = |via: &Account| -> Result<SpaceState, String> {
        let s = sync(pds, dir, &space, via, None)?;
        let mut st = state_of(&space, &s);
        apply_takedowns(&mut st, current(&labels(&space, &s)));
        Ok(st)
    };
    let st = view(&carol)?;
    let hidden = [&alice.did, &bob.did, &carol.did]
        .iter()
        .all(|v| !can_view_record(Some(v), &reply, &st, &Everyone));
    report.check(
        "labels: a group owner's !takedown hides Bob's reply from every member, Bob included, with a placeholder; a member's !takedown of the owner's post does nothing",
        if hidden
            && referenced_post(Some(&carol.did), &reply, Some(&st), &Everyone) == ReferencedPost::Unavailable
            && can_view_record(Some(&carol.did), &p, &st, &Everyone)
            && st.members.len() == 2
        {
            Ok(format!("taken down {}", st.taken_down.len()))
        } else {
            Err(format!("taken down {:?}", st.taken_down))
        },
    );
    delete(pds, &alice, &down)?;
    settle();
    let st = view(&bob)?;
    report.check(
        "labels: once the owner deletes the !takedown, Bob's reply shows again",
        if can_view_record(Some(&carol.did), &reply, &st, &Everyone) && st.taken_down.is_empty() {
            Ok("shown".into())
        } else {
            Err(format!("taken down {:?}", st.taken_down))
        },
    );
    if crate::crates_pds() {
        record_takedown(pds, dir, report, &space, &alice, &carol, &p)?;
    }
    Ok(())
}

/// atproto-pds only: a host takedown of one of Alice's records, seen
/// through `umbrae-sync`.
fn record_takedown(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    space: &SpaceRef,
    alice: &Account,
    via: &Account,
    kept: &SpaceRecordUri,
) -> Result<(), String> {
    let pw = std::env::var("ADMIN_PW").map_err(|_| "ADMIN_PW is not set".to_owned())?;
    let transport = Blocking(&pds.agent);
    let directory = Plc { dir, pds: &pds.url };
    let d = delegation(pds, &space.to_string(), via)?;
    let cred = block_on(authorize(
        &transport,
        &directory,
        space,
        Authorize {
            delegation: &d,
            attestation: None,
            notify: None,
        },
        crate::now(),
    ))
    .map_err(|e| e.to_string())?;
    let mut store = Store::new();
    let sync_from = |cursor: &SpaceCursor, store: &Store| {
        block_on(sync_space(
            &transport,
            &directory,
            &cred,
            cursor,
            &lookup(store),
            crate::now(),
        ))
        .map_err(|e| e.to_string())
    };
    let (c0, changes) = sync_from(&SpaceCursor::default(), &store)?;
    apply(&mut store, &changes);
    let (tp, _) = put(
        pds,
        space,
        alice,
        POST,
        "3mbaaaaaaal72",
        post("to be taken down"),
    )?;
    let (_, changes) = sync_from(&c0, &store)?;
    apply(&mut store, &changes);
    let key = |u: &SpaceRecordUri| {
        (
            u.author().to_owned(),
            u.collection().to_owned(),
            u.rkey().to_owned(),
        )
    };
    let held_before = store.contains_key(&key(&tp));
    let basic = format!("Basic {}", STANDARD.encode(format!("admin:{pw}")));
    let td = pds
        .post(
            "com.atproto.admin.takedownSpaceRecord",
            &json!({ "space": space.to_string(), "collection": POST, "rkey": tp.rkey() }),
            &vec![("Authorization", basic)],
        )?
        .ok("takedownSpaceRecord")?;
    // The daily resync: every cursor dropped.
    let (next, changes) = sync_from(&SpaceCursor::default(), &store)?;
    let taken = changes.iter().find_map(|c| match c {
        RepoChange::TakenDown { repo, listed } if repo == &alice.did => Some(listed.clone()),
        _ => None,
    });
    apply(&mut store, &changes);
    report.check(
        "labels: atproto-pds: after a host takedown of Alice's post, a full sync answers RecordsTakendown for her repo; the syncer keeps no cursor for it and drops only that record",
        match &taken {
            Some(listed)
                if held_before
                    && td.status == 200
                    && !listed.iter().any(|(c, r, _)| c == POST && r == tp.rkey())
                    && !store.contains_key(&key(&tp))
                    && store.contains_key(&key(kept))
                    && !next.repos.contains_key(&alice.did) =>
            {
                Ok(format!("{} record(s) still listed for her", listed.len()))
            }
            _ => Err(format!("held before {held_before}; changes {changes:?}")),
        },
    );
    // Known limit: op replay from an older cursor still carries the value.
    let (_, changes) = sync_from(&c0, &store)?;
    let replayed = changes.iter().any(|c| match c {
        RepoChange::Ops { repo, ops } if repo == &alice.did => ops
            .iter()
            .any(|o| o.rkey == tp.rkey() && o.record.is_some()),
        _ => false,
    });
    report.check(
        "labels: atproto-pds: known limit: an op replay from an older cursor still carries the taken-down post",
        if replayed {
            Ok("carried, as recorded in the design's known limits".into())
        } else {
            Err(format!("not carried (changed upstream?): {changes:?}"))
        },
    );
    Ok(())
}
