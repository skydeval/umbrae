//! A private account on the reference PDS, against a stand-in serving app.
//!
//! The harness stands in for Alice's serving app, behind the TLS front end,
//! under a DID in the mock PLC. It answers `checkAccess` for her private
//! space (`tools.umbrae.private` at `self`) as the design says: nothing
//! unless the service auth names the space's authority, the app and
//! `checkAccess`; with `repo` absent, `read` for its own attested client
//! only; with `repo` set, never `read`, and `write` while that account
//! passes Alice's rules (`can_view_private`). Her rules admit approved
//! followers: Bob, until he's removed. Carol is outside.
//!
//! Alice's public history moves in as a client's mover moves it, looking up
//! each space copy first. Bob and Carol interact, Bob loses access, and
//! Alice goes public again, keeping inside what must stay. Each step is
//! checked by its side effects on both sides.

use crate::labeler_flow::Client;
use crate::umbrae_flow::{read_space, state_of, sync, Synced};
use crate::{
    create_account, credential_headers, expect_refusal, lexjson, Account, Pds, Report, Resp,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use umbrae::placement::{leaks_hidden, like_space, reply_space};
use umbrae::private::{
    can_view_private, going_public_value, interaction_counts, stays_private, PrivateInputs,
};
use umbrae::space::{check_private_policy, private_space, private_uri, public_uri};
use umbrae::{Tri, ViewContext, PRIVATE_SPACE_TYPE};
use umbrae_core::cid::Cid;
use umbrae_core::didkey;
use umbrae_core::uri::{SpaceRecordUri, SpaceRef};
use umbrae_lexicons::{
    validate_private_record, PrivateRecord, PublicUri, Rule, Rules, Target, BSKY_LIKE, BSKY_POST,
    BSKY_REPOST, BSKY_THREADGATE, PRIVATE_RULES, PRIVATE_RULE_APPROVED_FOLLOWERS, SELF_RKEY,
};
use umbrae_sync::{check, Checked};

/// The serving app, registered in the mock PLC.
const APP_DID: &str = "did:plc:privateappaaaaaaaaaaaaaa";
const APP_SERVICE: &str = "umbrae_app";
/// The TLS front end, which proxies `/xrpc/` to the harness.
const HOST: &str = "https://client.interop.test";
const CHECK: &str = "com.atproto.managedspace.checkAccess";
const TOKEN: &str = "private-notify-token-0123456789abcdef";
const CREATED: &str = "2026-11-27T12:00:00.000Z";
const PNG_1X1: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

#[derive(Debug, Clone)]
struct Call {
    space: String,
    repo: Option<String>,
    client_id: Option<String>,
    iss: String,
    answer: (bool, bool),
}

/// Alice's approved followers, as the app holds them.
static ALLOWED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
/// Alice's rules, as the app read them from her space.
static RULES: Mutex<Option<Rules>> = Mutex::new(None);
static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());
static APP_CLIENT: Mutex<String> = Mutex::new(String::new());
static NOTES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
/// When set, the app doesn't answer.
static DOWN: AtomicBool = AtomicBool::new(false);

fn app() -> String {
    format!("{APP_DID}#{APP_SERVICE}")
}

/// The app's inputs for the rules: its followers table, and no public
/// follows, lists or list blocks.
struct AppInputs;
impl PrivateInputs for AppInputs {
    fn approved_follower(&self, _: &str, viewer: &str) -> Tri {
        if ALLOWED.lock().unwrap().contains(viewer) {
            Tri::Yes
        } else {
            Tri::No
        }
    }
    fn follows(&self, _: &str, _: &str) -> Tri {
        Tri::No
    }
    fn on_list(&self, _: &PublicUri, _: &str) -> Tri {
        Tri::No
    }
    fn list_blocked(&self, _: &str, _: &str) -> Tri {
        Tri::No
    }
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

fn claims(token: &str) -> Value {
    token
        .split('.')
        .nth(1)
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

/// Answer a checkAccess call to the serving app, or take a notification
/// carrying its token.
pub(crate) fn handle(
    url: &str,
    path: &str,
    body: &[u8],
    authorization: Option<&str>,
) -> Option<(u16, Value)> {
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        if v["token"].as_str() == Some(TOKEN) {
            return match path {
                "/xrpc/com.atproto.space.confirmRegistration" => {
                    Some((200, json!({ "challenge": v["challenge"] })))
                }
                "/xrpc/com.atproto.space.notifySpaceUpdate" => {
                    NOTES.lock().unwrap().push(v);
                    Some((200, json!({})))
                }
                _ => None,
            };
        }
    }
    let (p, query) = url.split_once('?').unwrap_or((url, ""));
    if p != format!("/xrpc/{CHECK}") {
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
    let c = authorization
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(claims)
        .unwrap_or(Value::Null);
    if c["aud"].as_str() != Some(app().as_str()) {
        return None;
    }
    let mut call = Call {
        space: param("space").unwrap_or_default(),
        repo: param("repo"),
        client_id: param("clientId"),
        iss: c["iss"].as_str().unwrap_or_default().to_owned(),
        answer: (false, false),
    };
    if DOWN.load(Ordering::SeqCst) {
        CALLS.lock().unwrap().push(call);
        return Some((500, json!({ "error": "InternalServerError" })));
    }
    let space = SpaceRef::parse(&call.space).ok().filter(|s| {
        s.space_type() == PRIVATE_SPACE_TYPE
            && s.skey() == SELF_RKEY
            && call.iss == s.authority()
            && c["lxm"].as_str() == Some(CHECK)
    });
    if let Some(s) = space {
        call.answer = match &call.repo {
            Some(r) => {
                let rules = RULES.lock().unwrap().clone();
                let write = can_view_private(
                    Some(r),
                    s.authority(),
                    rules.as_ref(),
                    &AppInputs,
                    &Everyone,
                );
                (false, write)
            }
            None => (
                call.client_id.as_deref() == Some(APP_CLIENT.lock().unwrap().as_str()),
                false,
            ),
        };
    }
    let (read, write) = call.answer;
    CALLS.lock().unwrap().push(call);
    Some((200, json!({ "read": read, "write": write })))
}

fn ncalls() -> usize {
    CALLS.lock().unwrap().len()
}

fn calls_since(n: usize) -> Vec<Call> {
    CALLS.lock().unwrap()[n..].to_vec()
}

fn settle() {
    std::thread::sleep(Duration::from_millis(2500));
}

fn show(r: &Resp) -> String {
    format!("HTTP {} {}", r.status, String::from_utf8_lossy(&r.body))
}

fn pub_get(pds: &Pds, did: &str, coll: &str, rkey: &str) -> Result<Resp, String> {
    pds.get(
        "com.atproto.repo.getRecord",
        &[("repo", did), ("collection", coll), ("rkey", rkey)],
        &vec![],
    )
}

/// A record in `who`'s own repo in the space, read with its own session.
fn space_get(
    pds: &Pds,
    who: &Account,
    space: &SpaceRef,
    coll: &str,
    rkey: &str,
) -> Result<Resp, String> {
    pds.get(
        "com.atproto.space.getRecord",
        &[
            ("space", &space.to_string()),
            ("repo", &who.did),
            ("collection", coll),
            ("rkey", rkey),
        ],
        &who.auth(),
    )
}

fn pub_create(
    pds: &Pds,
    who: &Account,
    coll: &str,
    rkey: &str,
    rec: &Value,
) -> Result<Value, String> {
    Ok(pds
        .post(
            "com.atproto.repo.createRecord",
            &json!({ "repo": who.did, "collection": coll, "rkey": rkey, "record": rec }),
            &who.auth(),
        )?
        .ok(&format!("public create {coll}/{rkey}"))?
        .json())
}

fn space_writes(
    pds: &Pds,
    who: &Account,
    space: &SpaceRef,
    writes: Vec<Value>,
    validate: Option<bool>,
) -> Result<Resp, String> {
    let mut body = json!({ "space": space.to_string(), "repo": who.did, "writes": writes });
    if let Some(v) = validate {
        body["validate"] = json!(v);
    }
    pds.post("com.atproto.space.applyWrites", &body, &who.auth())
}

fn screate(coll: &str, rkey: &str, value: &Value) -> Value {
    json!({ "$type": "com.atproto.space.applyWrites#create", "collection": coll, "rkey": rkey, "value": value })
}

fn supdate(coll: &str, rkey: &str, value: &Value) -> Value {
    json!({ "$type": "com.atproto.space.applyWrites#update", "collection": coll, "rkey": rkey, "value": value })
}

fn sdelete(coll: &str, rkey: &str) -> Value {
    json!({ "$type": "com.atproto.space.applyWrites#delete", "collection": coll, "rkey": rkey })
}

fn pdelete(coll: &str, rkey: &str) -> Value {
    json!({ "$type": "com.atproto.repo.applyWrites#delete", "collection": coll, "rkey": rkey })
}

fn pcreate(coll: &str, rkey: &str, value: &Value) -> Value {
    json!({ "$type": "com.atproto.repo.applyWrites#create", "collection": coll, "rkey": rkey, "value": value })
}

/// One batch of the move in, as a client's mover does it: look each
/// record's space copy up first (none: create; the same CID: no write; a
/// different CID: update), write with `validate: false`, and only once the
/// space write succeeded, delete the public copies.
struct Moved {
    /// What was sent: `create coll/rkey` or `update coll/rkey`.
    sent: Vec<String>,
    /// The public CIDs, by item.
    public_cids: Vec<String>,
    /// The space batch's result, if anything was sent.
    write: Option<Resp>,
    delete: Resp,
}

fn move_in(
    pds: &Pds,
    who: &Account,
    space: &SpaceRef,
    items: &[(&str, &str)],
) -> Result<Moved, String> {
    let mut writes = Vec::new();
    let mut sent = Vec::new();
    let mut public_cids = Vec::new();
    for (c, k) in items {
        let j = pub_get(pds, &who.did, c, k)?
            .ok(&format!("public getRecord {c}/{k}"))?
            .json();
        let cid = j["cid"].as_str().unwrap_or_default().to_owned();
        let there = space_get(pds, who, space, c, k)?;
        if there.status != 200 {
            writes.push(screate(c, k, &j["value"]));
            sent.push(format!("create {c}/{k}"));
        } else if there.json()["cid"].as_str() != Some(cid.as_str()) {
            writes.push(supdate(c, k, &j["value"]));
            sent.push(format!("update {c}/{k}"));
        }
        public_cids.push(cid);
    }
    let write = if writes.is_empty() {
        None
    } else {
        Some(space_writes(pds, who, space, writes, Some(false))?.ok("the space batch")?)
    };
    let dels: Vec<Value> = items.iter().map(|(c, k)| pdelete(c, k)).collect();
    let delete = pds.post(
        "com.atproto.repo.applyWrites",
        &json!({ "repo": who.did, "writes": dels }),
        &who.auth(),
    )?;
    Ok(Moved {
        sent,
        public_cids,
        write,
        delete,
    })
}

/// The space copies' CIDs, by item, read back with the owner's session.
fn space_cids(
    pds: &Pds,
    who: &Account,
    space: &SpaceRef,
    items: &[(&str, &str)],
) -> Result<Vec<String>, String> {
    items
        .iter()
        .map(|(c, k)| {
            Ok(space_get(pds, who, space, c, k)?.json()["cid"]
                .as_str()
                .unwrap_or_default()
                .to_owned())
        })
        .collect()
}

/// Whether every item is gone from the public repo.
fn all_gone(pds: &Pds, did: &str, items: &[(&str, &str)]) -> Result<bool, String> {
    for (c, k) in items {
        if pub_get(pds, did, c, k)?.status == 200 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn app_sync(
    pds: &Pds,
    dir: &crate::plc::Directory,
    space: &SpaceRef,
    client: &Client,
    register: bool,
) -> Result<Synced, String> {
    let key = SigningKey::random(&mut OsRng);
    let mut body = json!({ "space": space.to_string(),
        "credentialKey": didkey::format_p256(&key.verifying_key().into()),
        "clientAttestation": client.attest(space.authority()) });
    if register {
        body["notify"] = json!({ "endpoint": HOST, "token": TOKEN });
    }
    let r = pds.post("com.atproto.space.authorizeSpaceSync", &body, &vec![])?;
    let credential = r.ok("the app's authorizeSpaceSync")?.json()["credential"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    read_space(pds, dir, space, credential, key, None)
}

fn own_delegation_sync(pds: &Pds, space: &SpaceRef, who: &Account) -> Result<Resp, String> {
    let token = crate::umbrae_flow::delegation(pds, &space.to_string(), who)?;
    let key = SigningKey::random(&mut OsRng);
    pds.post(
        "com.atproto.space.authorizeSpaceSync",
        &json!({ "space": space.to_string(),
            "credentialKey": didkey::format_p256(&key.verifying_key().into()),
            "delegationToken": token }),
        &vec![],
    )
}

fn has(s: &Synced, did: &str, coll: &str, rkey: &str) -> Option<Cid> {
    s.repos
        .get(did)
        .and_then(|rs| rs.iter().find(|r| r.collection == coll && r.rkey == rkey))
        .map(|r| r.cid)
}

/// Every synced record with its URI and what `umbrae-sync` makes of it.
fn checked(space: &SpaceRef, s: &Synced) -> Vec<(SpaceRecordUri, Checked)> {
    let mut out = Vec::new();
    for (did, records) in &s.repos {
        for r in records {
            if let Ok(uri) = space.record(did, &r.collection, &r.rkey) {
                let c = check(&uri, &r.value);
                out.push((uri, c));
            }
        }
    }
    out
}

/// The records the app shows now: valid, and counting under the rules.
fn shown(space: &SpaceRef, s: &Synced) -> BTreeSet<SpaceRecordUri> {
    let rules = RULES.lock().unwrap().clone();
    checked(space, s)
        .into_iter()
        .filter(|(u, c)| {
            matches!(c, Checked::Private(_))
                && interaction_counts(u, rules.as_ref(), &AppInputs, &Everyone)
        })
        .map(|(u, _)| u)
        .collect()
}

pub(crate) fn run(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
) -> Result<(), String> {
    let client_dir = std::env::var("CLIENT_DIR").unwrap_or_else(|_| "/client".into());
    let app_client = Client::publish(&client_dir, "private-app")?;
    *APP_CLIENT.lock().unwrap() = app_client.id.clone();
    dir.put(
        APP_DID,
        json!({ "type": "plc_operation", "verificationMethods": {}, "rotationKeys": [],
            "alsoKnownAs": [], "prev": null,
            "services": { APP_SERVICE: { "type": "UmbraeManagingApp", "endpoint": HOST } } }),
    );
    let alice = create_account(pds, "pvalice")?;
    let bob = create_account(pds, "pvbob")?;
    let carol = create_account(pds, "pvcarol")?;
    ALLOWED.lock().unwrap().insert(bob.did.clone());

    // ---- Alice's public history, and others' public interactions.
    let png = STANDARD.decode(PNG_1X1).map_err(|e| e.to_string())?;
    let blob_cid = Cid::for_raw(&png);
    let blob_s = blob_cid.to_string();
    let blob = pds
        .post_bytes(
            "com.atproto.repo.uploadBlob",
            "image/png",
            &png,
            &alice.auth(),
        )?
        .ok("uploadBlob")?
        .json()["blob"]
        .clone();
    let img = |text: &str| {
        json!({ "$type": BSKY_POST, "text": text, "createdAt": CREATED,
            "embed": { "$type": "app.bsky.embed.images", "images": [{ "image": blob, "alt": "" }] } })
    };
    let (p1, p3, r1) = ("3mbpaaaaaaa22", "3mbpaaaaaaa23", "3mbpaaaaaaa24");
    let p1w = pub_create(pds, &alice, BSKY_POST, p1, &img("public with an image"))?;
    let p1_uri = p1w["uri"].as_str().unwrap_or_default().to_owned();
    let p1_cid = p1w["cid"].as_str().unwrap_or_default().to_owned();
    pub_create(pds, &alice, BSKY_POST, p3, &img("same image again"))?;
    let p1ref = json!({ "uri": p1_uri, "cid": p1_cid });
    let r1w = pub_create(
        pds,
        &alice,
        BSKY_POST,
        r1,
        &json!({ "$type": BSKY_POST, "text": "self reply", "createdAt": CREATED,
            "reply": { "root": p1ref, "parent": p1ref } }),
    )?;
    let r1_cid = r1w["cid"].as_str().unwrap_or_default().to_owned();
    pub_create(
        pds,
        &alice,
        BSKY_THREADGATE,
        p1,
        &json!({ "$type": BSKY_THREADGATE, "post": p1_uri,
            "allow": [{ "$type": "app.bsky.feed.threadgate#mentionRule" }], "createdAt": CREATED }),
    )?;
    let cpw = pub_create(
        pds,
        &carol,
        BSKY_POST,
        "3mbpaaaaaaa25",
        &json!({ "$type": BSKY_POST, "text": "carol public", "createdAt": CREATED }),
    )?;
    let cpref = json!({ "uri": cpw["uri"], "cid": cpw["cid"] });
    let (lk, rp) = ("3mbpaaaaaaa26", "3mbpaaaaaaa27");
    pub_create(
        pds,
        &alice,
        BSKY_LIKE,
        lk,
        &json!({ "$type": BSKY_LIKE, "subject": cpref, "createdAt": CREATED }),
    )?;
    pub_create(
        pds,
        &alice,
        BSKY_REPOST,
        rp,
        &json!({ "$type": BSKY_REPOST, "subject": cpref, "createdAt": CREATED }),
    )?;
    report.check(
        "private: accounts and public history",
        Ok(format!(
            "alice {} ({}), bob {} ({}), carol {} ({}); p1 {p1_uri}",
            alice.did,
            alice.access.len(),
            bob.did,
            bob.access.len(),
            carol.did,
            carol.access.len()
        )),
    );

    // ---- The private space, its policy and the rules. The owner's writes
    // ask the app nothing, from here to the app's first sync.
    let n_owner = ncalls();
    let space = private_space(&alice.did).map_err(|e| e.to_string())?;
    let cs = pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": PRIVATE_SPACE_TYPE, "skey": SELF_RKEY,
            "policy": { "$type": "com.atproto.managedspace.policy", "managingApp": app(), "publishPolicy": true } }),
        &alice.auth(),
    )?;
    let rules_json = json!({ "$type": PRIVATE_RULES,
        "allow": [{ "$type": PRIVATE_RULE_APPROVED_FOLLOWERS }], "createdAt": CREATED });
    let rw = space_writes(
        pds,
        &alice,
        &space,
        vec![screate(PRIVATE_RULES, SELF_RKEY, &rules_json)],
        None,
    )?;
    let back = space_get(pds, &alice, &space, PRIVATE_RULES, SELF_RKEY)?;
    let rules_uri = space
        .record(&alice.did, PRIVATE_RULES, SELF_RKEY)
        .map_err(|e| e.to_string())?;
    let parsed = crate::umbrae_flow::map(&back.json()["value"])
        .ok()
        .and_then(|m| validate_private_record(&rules_uri, &m).ok().flatten());
    let rules_ok =
        matches!(&parsed, Some(PrivateRecord::Rules(r)) if r.allow == [Rule::ApprovedFollowers]);
    if let Some(PrivateRecord::Rules(r)) = parsed {
        *RULES.lock().unwrap() = Some(r);
    }
    report.check(
        "private: createSpace for tools.umbrae.private at self with a managed policy naming the app; the rules record reads back and validates as approved followers",
        if cs.status == 200 && rw.status == 200 && back.status == 200 && rules_ok {
            Ok(format!("{space}; rules validationStatus {}", rw.json()["results"][0]["validationStatus"]))
        } else {
            Err(format!("{} / {} / {}", show(&cs), show(&rw), show(&back)))
        },
    );

    // ---- The move: posts with their gates, then reposts, then likes.
    let items = [
        (BSKY_POST, p1),
        (BSKY_THREADGATE, p1),
        (BSKY_POST, r1),
        (BSKY_REPOST, rp),
        (BSKY_LIKE, lk),
    ];
    let mv = move_in(pds, &alice, &space, &items)?;
    let in_space = space_cids(pds, &alice, &space, &items)?;
    let all_created =
        mv.sent.iter().all(|s| s.starts_with("create ")) && mv.sent.len() == items.len();
    report.check(
        "private: one space batch moves a post with an image, its threadgate, a self-reply, a repost and a like at the same rkeys; every space CID equals the public one",
        if all_created && in_space == mv.public_cids && mv.write.is_some() {
            Ok(format!("sent {}", mv.sent.join(", ")))
        } else {
            Err(format!("sent {:?}; space {in_space:?} public {:?}", mv.sent, mv.public_cids))
        },
    );
    let gone = all_gone(pds, &alice.did, &items)?;
    let p1_gone = pub_get(pds, &alice.did, BSKY_POST, p1)?;
    let pub_blob = pds.get(
        "com.atproto.sync.getBlob",
        &[("did", &alice.did), ("cid", &blob_s)],
        &vec![],
    )?;
    report.check(
        "private: after the space write, the public deletes; public getRecord refuses every moved record; the blob stays public while an unmoved post uses it",
        if mv.delete.status == 200 && gone && pub_blob.status == 200 {
            Ok(format!("getRecord {}; sync.getBlob {}", p1_gone.error_name(), pub_blob.status))
        } else {
            Err(format!("{} / gone {gone} / blob {}", show(&mv.delete), pub_blob.status))
        },
    );

    // ---- Legacy blob refs, while the blob is still public.
    let bad = json!({ "$type": BSKY_POST, "text": "no createdAt" });
    let v_def = space_writes(
        pds,
        &alice,
        &space,
        vec![screate(BSKY_POST, "3mbpaaaaaaa2b", &bad)],
        None,
    )?;
    let v_off = space_writes(
        pds,
        &alice,
        &space,
        vec![screate(BSKY_POST, "3mbpaaaaaaa2c", &bad)],
        Some(false),
    )?;
    let legacy = |image: Value| {
        json!({ "$type": BSKY_POST, "text": "legacy", "createdAt": CREATED,
            "embed": { "$type": "app.bsky.embed.images", "images": [{ "alt": "", "image": image }] } })
    };
    let v_leg = space_writes(
        pds,
        &alice,
        &space,
        vec![screate(
            BSKY_POST,
            "3mbpaaaaaaa2d",
            &legacy(json!({ "cid": blob_s, "mimeType": "image/png" })),
        )],
        Some(false),
    )?;
    // Expected difference: atproto-pds takes the legacy ref; start over.
    let leg = if v_leg.status == 200 {
        "accepted"
    } else {
        "refused"
    };
    if v_leg.status == 200 {
        space_writes(
            pds,
            &alice,
            &space,
            vec![sdelete(BSKY_POST, "3mbpaaaaaaa2d")],
            None,
        )?
        .ok("deleting the legacy-ref post")?;
    }
    let size: i64 = pub_blob
        .header("content-length")
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    let rewritten = legacy(
        json!({ "$type": "blob", "ref": { "$link": blob_s }, "mimeType": "image/png", "size": size }),
    );
    let v_new = space_writes(
        pds,
        &alice,
        &space,
        vec![screate(BSKY_POST, "3mbpaaaaaaa2d", &rewritten)],
        Some(false),
    )?;
    let stored = space_get(pds, &alice, &space, BSKY_POST, "3mbpaaaaaaa2d")?.json();
    let image = &stored["value"]["embed"]["images"][0]["image"];
    // The record written with validation off was only a test: remove it.
    let cleanup = space_writes(
        pds,
        &alice,
        &space,
        vec![sdelete(BSKY_POST, "3mbpaaaaaaa2c")],
        None,
    )?;
    report.check(
        "private: the space validates native schemas by default and skips them with validate:false; a legacy blob ref is refused even then (an expected difference), and once rewritten to $type blob with the size from sync.getBlob it's accepted",
        if v_def.status != 200
            && v_off.status == 200
            && crate::same_answer("refused", leg)
            && v_new.status == 200
            && size == png.len() as i64
            && image["$type"] == "blob"
            && image["size"] == json!(size)
            && cleanup.status == 200
        {
            Ok(format!("default {}; legacy {}; rewritten size {size}", v_def.error_name(), String::from_utf8_lossy(&v_leg.body)))
        } else {
            Err(format!("{} / {} / {} / {} / size {size} / {image}", show(&v_def), show(&v_off), show(&v_leg), show(&v_new)))
        },
    );

    // ---- The last public use moves.
    let m3 = move_in(pds, &alice, &space, &[(BSKY_POST, p3)])?;
    let pub_blob = pds.get(
        "com.atproto.sync.getBlob",
        &[("did", &alice.did), ("cid", &blob_s)],
        &vec![],
    )?;
    let listed = pds
        .get(
            "com.atproto.sync.listBlobs",
            &[("did", &alice.did)],
            &vec![],
        )?
        .json();
    let in_list = listed["cids"]
        .as_array()
        .is_some_and(|a| a.iter().any(|c| c == &json!(blob_s)));
    let own_blob = pds.get(
        "com.atproto.space.getBlob",
        &[
            ("space", &space.to_string()),
            ("repo", &alice.did),
            ("cid", &blob_s),
        ],
        &alice.auth(),
    )?;
    let asked = calls_since(n_owner);
    report.check(
        "private: once the last public use moves, sync.getBlob refuses and listBlobs leaves the blob out; space getBlob serves the owner the right bytes; no owner write asked the app",
        if m3.delete.status == 200
            && pub_blob.status != 200
            && !in_list
            && own_blob.status == 200
            && Cid::for_raw(&own_blob.body) == blob_cid
            && asked.is_empty()
        {
            Ok(format!("public {}; app calls 0", pub_blob.error_name()))
        } else {
            Err(format!("delete {} public {} listed {in_list} own {} calls {asked:?}", m3.delete.status, show(&pub_blob), own_blob.status))
        },
    );

    // ---- Resuming: a stopped move left one space copy as it was and
    // another out of date. The lookup sends only what's needed.
    let (f1, f2, f3) = ("3mbpaaaaaaa2l", "3mbpaaaaaaa2m", "3mbpaaaaaaa2n");
    let fv = |text: &str| json!({ "$type": BSKY_POST, "text": text, "createdAt": CREATED });
    for f in [f1, f2, f3] {
        pub_create(pds, &alice, BSKY_POST, f, &fv(f))?;
    }
    space_writes(
        pds,
        &alice,
        &space,
        vec![
            screate(BSKY_POST, f1, &fv(f1)),
            screate(BSKY_POST, f2, &fv("before an edit")),
        ],
        None,
    )?
    .ok("the stopped move's space copies")?;
    let fitems = [(BSKY_POST, f1), (BSKY_POST, f2), (BSKY_POST, f3)];
    let resumed = move_in(pds, &alice, &space, &fitems)?;
    let fcids = space_cids(pds, &alice, &space, &fitems)?;
    let fgone = all_gone(pds, &alice.did, &fitems)?;
    let expected = [
        format!("update {BSKY_POST}/{f2}"),
        format!("create {BSKY_POST}/{f3}"),
    ];
    report.check(
        "private: resuming looks each space copy up first: the same CID sends nothing, a different one an update, a missing one a create; then every space CID equals the public one and the public copies are gone",
        if resumed.sent == expected && fcids == resumed.public_cids && fgone && resumed.delete.status == 200 {
            Ok(format!("sent {}", resumed.sent.join(", ")))
        } else {
            Err(format!("sent {:?}; space {fcids:?} public {:?}; gone {fgone}", resumed.sent, resumed.public_cids))
        },
    );
    // What the lookup avoids: a repeated create sinks the whole batch.
    let again = space_writes(
        pds,
        &alice,
        &space,
        vec![screate(BSKY_POST, f1, &fv(f1))],
        Some(false),
    )?;
    let fresh = "3mbpaaaaaaa2a";
    let mixed = space_writes(
        pds,
        &alice,
        &space,
        vec![
            screate(BSKY_POST, fresh, &fv("new")),
            screate(BSKY_POST, f1, &fv(f1)),
        ],
        Some(false),
    )?;
    let fresh_there = space_get(pds, &alice, &space, BSKY_POST, fresh)?;
    report.check(
        "private: without the lookup, re-creating a moved record refuses the whole batch (RecordAlreadyExists) and nothing in it lands",
        if again.error_name() == "RecordAlreadyExists"
            && mixed.error_name() == "RecordAlreadyExists"
            && fresh_there.status != 200
        {
            Ok(format!("{} / {}; fresh getRecord {}", again.error_name(), mixed.error_name(), fresh_there.status))
        } else {
            Err(format!("{} / {} / {}", show(&again), show(&mixed), fresh_there.status))
        },
    );

    // ---- The app's sync, with its attestation and no delegation.
    let n = ncalls();
    let s = app_sync(pds, dir, &space, &app_client, true)?;
    let c = calls_since(n);
    let policy = state_of(&space, &s).policy;
    let policy_ok = policy
        .as_ref()
        .is_some_and(|p| check_private_policy(&space, &app(), p).is_ok());
    let lookalike = policy.as_ref().is_some_and(|p| {
        check_private_policy(&space, "did:plc:lookalikeappaaaaaaaaaaaa#umbrae_app", p).is_err()
    });
    let alices: Vec<_> = checked(&space, &s)
        .into_iter()
        .filter(|(u, _)| u.author() == alice.did)
        .collect();
    let invalid: Vec<_> = alices
        .iter()
        .filter(|(_, c)| matches!(c, Checked::Invalid(_)))
        .collect();
    let private_n = alices
        .iter()
        .filter(|(_, c)| matches!(c, Checked::Private(_)))
        .count();
    let app_blob = pds.get(
        "com.atproto.space.getBlob",
        &[
            ("space", &space.to_string()),
            ("repo", &alice.did),
            ("cid", &blob_s),
        ],
        &credential_headers(&s.credential, &alice.did, &s.key),
    )?;
    report.check(
        "private: the app syncs with its attestation (one call, repo absent, read); the published policy passes check_private_policy for this app and fails for another; every moved record validates as a private record; the app reads the post and blob",
        if has(&s, &alice.did, BSKY_POST, p1).map(|c| c.to_string()) == Some(p1_cid.clone())
            && app_blob.status == 200
            && Cid::for_raw(&app_blob.body) == blob_cid
            && c.len() == 1
            && c[0].repo.is_none()
            && c[0].answer == (true, false)
            && policy_ok
            && lookalike
            && invalid.is_empty()
            && private_n >= 10
        {
            Ok(format!("{private_n} private record(s) of alice"))
        } else {
            Err(format!("blob {} calls {c:?} policy {policy:?} invalid {invalid:?} private {private_n}", app_blob.status))
        },
    );

    // ---- Interactions inside the owner's space.
    let priv_p1 = space
        .record(&alice.did, BSKY_POST, p1)
        .map_err(|e| e.to_string())?;
    let alias = PublicUri::parse(&p1_uri).ok_or("p1's URI")?;
    let placed_reply =
        reply_space(&bob.did, &Target::Hidden(priv_p1.clone())).map_err(|e| e.to_string())?;
    let placed_like = like_space(&bob.did, &private_uri(&alias).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let pref = json!({ "uri": priv_p1.to_string(), "cid": p1_cid });
    let (b_reply_k, b_like_k, c_reply_k) = ("3mbpaaaaaaa2e", "3mbpaaaaaaa2f", "3mbpaaaaaaa2g");
    let n = ncalls();
    let b_reply = space_writes(
        pds,
        &bob,
        &placed_reply.clone().ok_or("no reply space")?,
        vec![screate(
            BSKY_POST,
            b_reply_k,
            &json!({ "$type": BSKY_POST, "text": "inside", "createdAt": CREATED, "reply": { "root": pref, "parent": pref } }),
        )],
        None,
    )?;
    let b_like = space_writes(
        pds,
        &bob,
        &placed_like,
        vec![screate(
            BSKY_LIKE,
            b_like_k,
            &json!({ "$type": BSKY_LIKE, "subject": p1ref, "createdAt": CREATED }),
        )],
        None,
    )?;
    let c_reply = space_writes(
        pds,
        &carol,
        &space,
        vec![screate(
            BSKY_POST,
            c_reply_k,
            &json!({ "$type": BSKY_POST, "text": "carol inside", "createdAt": CREATED, "reply": { "root": pref, "parent": pref } }),
        )],
        None,
    )?;
    // Alice answers Bob inside: her reply names his in-boundary record.
    let b_reply_cid = b_reply.json()["results"][0]["cid"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let bob_uri = space
        .record(&bob.did, BSKY_POST, b_reply_k)
        .map_err(|e| e.to_string())?;
    let a1 = "3mbpaaaaaaa2o";
    space_writes(
        pds,
        &alice,
        &space,
        vec![screate(BSKY_POST, a1, &json!({ "$type": BSKY_POST, "text": "answering bob", "createdAt": CREATED,
            "reply": { "root": pref, "parent": { "uri": bob_uri.to_string(), "cid": b_reply_cid } } }))],
        None,
    )?
    .ok("alice's reply to bob")?;
    settle();
    let c = calls_since(n);
    let bob_w: Vec<_> = c
        .iter()
        .filter(|x| x.repo.as_deref() == Some(bob.did.as_str()))
        .collect();
    let carol_w: Vec<_> = c
        .iter()
        .filter(|x| x.repo.as_deref() == Some(carol.did.as_str()))
        .collect();
    let s2 = app_sync(pds, dir, &space, &app_client, true)?;
    let bobs: Vec<_> = checked(&space, &s2)
        .into_iter()
        .filter(|(u, _)| u.author() == bob.did)
        .collect();
    let bobs_valid = bobs.len() == 2 && bobs.iter().all(|(_, c)| matches!(c, Checked::Private(_)));
    let visible = shown(&space, &s2);
    report.check(
        "private: Bob (allowed) replies by the at:space URI and likes by the public alias, both placed in Alice's space; Carol (not allowed) replies too. The app answers write per account by the rules: Bob is tracked, Carol isn't; Bob's records validate and show",
        if placed_reply.as_ref() == Some(&space)
            && placed_like == space
            && b_reply.status == 200
            && b_like.status == 200
            && c_reply.status == 200
            && !bob_w.is_empty()
            && bob_w.iter().all(|x| x.answer == (false, true))
            && !carol_w.is_empty()
            && carol_w.iter().all(|x| x.answer == (false, false))
            && c.iter().all(|x| x.client_id.is_none() && x.repo.is_some())
            && s2.writers.contains(&bob.did)
            && !s2.writers.contains(&carol.did)
            && bobs_valid
            && visible.contains(&bob_uri)
        {
            Ok(format!("calls {}; writers {:?}; {} shown", c.len(), s2.writers, visible.len()))
        } else {
            Err(format!("{} / {} / {}; calls {c:?}; writers {:?}; bob's {bobs:?}", show(&b_reply), show(&b_like), show(&c_reply), s2.writers))
        },
    );

    // ---- Accounts never get credentials; the owner does.
    let n = ncalls();
    let b_del = own_delegation_sync(pds, &space, &bob)?;
    let c_del = own_delegation_sync(pds, &space, &carol)?;
    let a_del = own_delegation_sync(pds, &space, &alice)?;
    let c = calls_since(n);
    report.check(
        "private: Bob's (allowed) and Carol's own delegations are refused as SpaceNotFound; the app is asked read for each and says no; the owner's own delegation works",
        match (expect_refusal(&b_del, Some("SpaceNotFound")), expect_refusal(&c_del, Some("SpaceNotFound"))) {
            (Ok(_), Ok(_)) if a_del.status == 200 && c.len() == 2 && c.iter().all(|x| !x.answer.0) => {
                Ok(format!("answers {:?}", c.iter().map(|x| x.answer).collect::<Vec<_>>()))
            }
            (x, y) => Err(format!("{x:?} {y:?} owner {} calls {c:?}", a_del.status)),
        },
    );

    // ---- Bob loses access; he stays a writer at the PDS, and the app
    // filters.
    ALLOWED.lock().unwrap().remove(&bob.did);
    let n = ncalls();
    let b2_k = "3mbpaaaaaaa2h";
    let b2 = space_writes(
        pds,
        &bob,
        &space,
        vec![screate(
            BSKY_POST,
            b2_k,
            &json!({ "$type": BSKY_POST, "text": "after losing access", "createdAt": CREATED, "reply": { "root": pref, "parent": pref } }),
        )],
        None,
    )?;
    settle();
    let c = calls_since(n);
    let s3 = app_sync(pds, dir, &space, &app_client, false)?;
    let visible = shown(&space, &s3);
    let bob_held = s3.repos.get(&bob.did).map_or(0, |r| r.len());
    let bob_shown = visible.iter().filter(|u| u.author() == bob.did).count();
    let alice_shown = visible.iter().filter(|u| u.author() == alice.did).count();
    report.check(
        "private: after Bob loses access his next write is asked and refused, yet he stays a writer and the app's credential still reads all his records; the app shows none of them, and still shows Alice's",
        if b2.status == 200
            && c.iter().any(|x| x.repo.as_deref() == Some(bob.did.as_str()) && x.answer == (false, false))
            && s3.writers.contains(&bob.did)
            && has(&s3, &bob.did, BSKY_POST, b2_k).is_some()
            && bob_held == 3
            && bob_shown == 0
            && alice_shown > 0
        {
            Ok(format!("bob: {bob_held} held, {bob_shown} shown; alice: {alice_shown} shown"))
        } else {
            Err(format!("{} calls {c:?} writers {:?} bob held {bob_held} shown {bob_shown}", show(&b2), s3.writers))
        },
    );

    // ---- A public record naming the private URI: the PDS can't stop it,
    // and a client's leak check refuses to write one.
    let public_reply = json!({ "$type": BSKY_POST, "text": "public reply to a private post", "createdAt": CREATED, "reply": { "root": pref, "parent": pref } });
    let pr = pds.post(
        "com.atproto.repo.createRecord",
        &json!({ "repo": carol.did, "collection": BSKY_POST, "rkey": "3mbpaaaaaaa2i", "record": public_reply }),
        &carol.auth(),
    )?;
    let leaks = crate::umbrae_flow::map(&public_reply)
        .map(|m| leaks_hidden(&umbrae_core::drisl::Value::Map(m)))
        .unwrap_or(false);
    report.check(
        "private: the public repo accepts a public reply naming an at:space URI (it can't be prevented), and leaks_hidden flags it",
        if pr.status == 200 && leaks {
            Ok("accepted; flagged".into())
        } else {
            Err(format!("{} leaks {leaks}", show(&pr)))
        },
    );

    // ---- Going public: what stays, worked out before anything moves;
    // the rest goes back with the owner's own references rewritten.
    let owner_view = sync(pds, dir, &space, &alice, None)?;
    let records: Vec<(SpaceRecordUri, _)> = owner_view
        .repos
        .iter()
        .flat_map(|(did, rs)| {
            rs.iter().filter_map(|r| {
                space
                    .record(did, &r.collection, &r.rkey)
                    .ok()
                    .map(|u| (u, r.value.clone()))
            })
        })
        .collect();
    let stay = stays_private(&space, records.iter().map(|(u, v)| (u, v)));
    let a1_uri = space
        .record(&alice.did, BSKY_POST, a1)
        .map_err(|e| e.to_string())?;
    let mut back = Vec::new();
    let mut back_keys = Vec::new();
    let mut refused = Vec::new();
    for (u, v) in &records {
        if stay.contains(u) {
            continue;
        }
        match going_public_value(&space, v) {
            Some(out) => {
                back.push(pcreate(
                    u.collection(),
                    u.rkey(),
                    &lexjson::to_json(&umbrae_core::drisl::Value::Map(out)),
                ));
                back_keys.push((u.collection().to_owned(), u.rkey().to_owned()));
            }
            None => refused.push(u.to_string()),
        }
    }
    let pc = pds.post(
        "com.atproto.repo.applyWrites",
        &json!({ "repo": alice.did, "validate": false, "writes": back }),
        &alice.auth(),
    )?;
    if pc.status != 200 {
        return Err(format!("the public batch: {}", show(&pc)));
    }
    let sd = space_writes(
        pds,
        &alice,
        &space,
        back_keys.iter().map(|(c, k)| sdelete(c, k)).collect(),
        None,
    )?;
    let pub_blob = pds.get(
        "com.atproto.sync.getBlob",
        &[("did", &alice.did), ("cid", &blob_s)],
        &vec![],
    )?;
    let p1_back = pub_get(pds, &alice.did, BSKY_POST, p1)?.json();
    let r1_back = pub_get(pds, &alice.did, BSKY_POST, r1)?.json();
    let tg_back = pub_get(pds, &alice.did, BSKY_THREADGATE, p1)?;
    let a1_public = pub_get(pds, &alice.did, BSKY_POST, a1)?;
    let a1_inside = space_get(pds, &alice, &space, BSKY_POST, a1)?;
    let rules_inside = space_get(pds, &alice, &space, PRIVATE_RULES, SELF_RKEY)?;
    let p1_inside = space_get(pds, &alice, &space, BSKY_POST, p1)?;
    let bob_stays = stay.iter().filter(|u| u.author() == bob.did).count();
    let s4 = app_sync(pds, dir, &space, &app_client, false)?;
    report.check(
        "private: going public keeps the rules, Bob's records and Alice's reply to Bob inside; everything else goes back at the same rkeys with the same CIDs (the blob served again); the space and the app's sync stay",
        if sd.status == 200
            && refused.is_empty()
            && stay.contains(&a1_uri)
            && bob_stays == 3
            && back_keys.len() >= 10
            && pub_blob.status == 200
            && p1_back["cid"].as_str() == Some(p1_cid.as_str())
            && r1_back["cid"].as_str() == Some(r1_cid.as_str())
            && tg_back.status == 200
            && a1_public.status != 200
            && a1_inside.status == 200
            && rules_inside.status == 200
            && p1_inside.status != 200
            && s4.repos.get(&bob.did).map_or(0, |r| r.len()) == 3
            && has(&s4, &alice.did, BSKY_POST, a1).is_some()
            && public_uri(&priv_p1).map(|u| u.to_string()) == Some(p1_uri.clone())
        {
            Ok(format!("{} back, {} stay", back_keys.len(), stay.len()))
        } else {
            Err(format!("{} / {}; refused {refused:?}; stay {stay:?}; p1 {p1_back}; blob {}", show(&pc), show(&sd), pub_blob.status))
        },
    );

    // ---- The app is down: the PDS fails closed for the app's sync.
    DOWN.store(true, Ordering::SeqCst);
    let down = app_sync(pds, dir, &space, &app_client, false);
    DOWN.store(false, Ordering::SeqCst);
    let up = app_sync(pds, dir, &space, &app_client, false);
    report.check(
        "private: with the app down, the app's sync fails closed; back up, it works again",
        match (down, up) {
            (Err(e), Ok(_)) => Ok(e.chars().take(120).collect()),
            (Ok(_), _) => Err("got a credential with the app down".into()),
            (Err(_), Err(e)) => Err(format!("still failing once up: {e}")),
        },
    );

    // ---- Deleting the space, a separate act, orphans others' records.
    let del = pds.post(
        "com.atproto.space.deleteSpace",
        &json!({ "space": space.to_string() }),
        &alice.auth(),
    )?;
    let after = app_sync(pds, dir, &space, &app_client, false);
    let bob_own = pds.get(
        "com.atproto.space.listRecords",
        &[("space", &space.to_string()), ("repo", &bob.did)],
        &bob.auth(),
    )?;
    let n_bob = bob_own.json()["records"].as_array().map_or(0, |a| a.len());
    report.check(
        "private: deleting the space: the app can no longer sync it; Bob's records stay in his own repo, readable only by him",
        if del.status == 200 && after.is_err() && bob_own.status == 200 && n_bob == 3 {
            Ok(format!("app sync {}; bob's own listRecords {n_bob} record(s)", after.err().unwrap_or_default().chars().take(80).collect::<String>()))
        } else {
            Err(format!("{} / {:?} / {}", show(&del), after.map(|s| s.writers), show(&bob_own)))
        },
    );

    // Every call carried iss = the authority.
    let all = CALLS.lock().unwrap().clone();
    let bad: Vec<_> = all.iter().filter(|c| c.iss != alice.did).collect();
    report.check(
        "private: every checkAccess call carried iss = the owner",
        if bad.is_empty() && !all.is_empty() {
            Ok(format!(
                "{} call(s); {} notification(s)",
                all.len(),
                NOTES.lock().unwrap().len()
            ))
        } else {
            Err(format!("{bad:?}"))
        },
    );
    Ok(())
}
