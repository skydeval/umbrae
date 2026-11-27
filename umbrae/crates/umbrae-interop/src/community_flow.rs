//! A community on the reference PDS, as v2 has it: per-author community
//! spaces, read only by the community's app.
//!
//! The harness stands in for the managing app (prism, or a PDS managing its
//! own communities), behind the TLS front end, under a DID in the mock PLC.
//! It answers `com.atproto.managedspace.checkAccess` as the design says:
//! nothing unless the service auth names the space's authority, the app and
//! `checkAccess`; nothing for a space it doesn't map, or whose authority
//! isn't a writer; nothing, ever, for an account; and with no account,
//! read only for its own attested client. It also receives the PDS's
//! update notifications. A second stand-in app, which says yes to
//! everything, backs a lookalike space.
//!
//! Alice and Bob are writers, Dan a reader, Carol outside. Eve, a writer,
//! makes the lookalike.

use crate::labeler_flow::Client;
use crate::umbrae_flow::{read_space, state_of, sync, umbrae_records, Synced};
use crate::{create_account, expect_refusal, Account, Pds, Report, Resp};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use umbrae::access::{can_view_record, can_view_repost, is_writer};
use umbrae::community::{can_view_feed_post, referenced_post, ReferencedPost, Role};
use umbrae::placement::{like_space, quote_space, reply_space, repost_space};
use umbrae::profile::{can_view_profile, AudienceSource};
use umbrae::space::{
    check_community_policy, check_policy, community_space, managed_policy, profile_space,
};
use umbrae::{SpaceState, Tri, ViewContext, SPACE_TYPE};
use umbrae_core::didkey;
use umbrae_core::policy::{MemberAccess, Policy};
use umbrae_core::uri::{SpaceRecordUri, SpaceRef};
use umbrae_lexicons::{
    community_skey, CommunityRef, Profile, Record, Target, AUDIENCE_COMMUNITY, FEED, LIKE, POST,
    PROFILE, REPOST, SELF_RKEY,
};

/// The community's app, registered in the mock PLC.
const APP_DID: &str = "did:plc:managerappaaaaaaaaaaaaaa";
/// The lookalike's app, which says yes to everything.
const OTHER_DID: &str = "did:plc:lookalikeappaaaaaaaaaaaa";
const APP_SERVICE: &str = "umbrae_app";
/// The TLS front end, which proxies `/xrpc/` to the harness.
const HOST: &str = "https://client.interop.test";
const CHECK: &str = "com.atproto.managedspace.checkAccess";
const KEY: &str = "art";
const TOKEN: &str = "community-notify-token-0123456789abcdef";
const CREATED: &str = "2026-11-27T12:00:00.000Z";

#[derive(Debug, Clone)]
struct Call {
    space: String,
    repo: Option<String>,
    client_id: Option<String>,
    iss: String,
    aud: String,
    lxm: String,
    answer: (bool, bool),
}

/// The app's membership table for the community.
static ROLES: Mutex<BTreeMap<String, Role>> = Mutex::new(BTreeMap::new());
/// When set, the app doesn't answer.
static DOWN: AtomicBool = AtomicBool::new(false);
static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());
static APP_CLIENT: Mutex<String> = Mutex::new(String::new());
/// Notifications the PDS sent with the app's registration token.
static NOTES: Mutex<Vec<Value>> = Mutex::new(Vec::new());

fn app() -> String {
    format!("{APP_DID}#{APP_SERVICE}")
}

fn other_app() -> String {
    format!("{OTHER_DID}#{APP_SERVICE}")
}

fn art() -> CommunityRef {
    CommunityRef::new(&app(), KEY).expect("a valid community ref")
}

fn role(did: &str) -> Option<Role> {
    ROLES.lock().unwrap().get(did).copied()
}

fn jwt_claims(token: &str) -> Value {
    token
        .split('.')
        .nth(1)
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

/// Answer a checkAccess call to either stand-in app, or take a
/// notification carrying the app's token.
pub(crate) fn handle(
    url: &str,
    path: &str,
    body: &[u8],
    authorization: Option<&str>,
) -> Option<(u16, Value)> {
    if let Some(answer) = notification(path, body) {
        return Some(answer);
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
        .map(jwt_claims)
        .unwrap_or(Value::Null);
    let text = |k: &str| c[k].as_str().unwrap_or_default().to_owned();
    let mut call = Call {
        space: param("space").unwrap_or_default(),
        repo: param("repo"),
        client_id: param("clientId"),
        iss: text("iss"),
        aud: text("aud"),
        lxm: text("lxm"),
        answer: (false, false),
    };
    if call.aud == other_app() {
        call.answer = (true, true);
    } else if call.aud == app() {
        if DOWN.load(Ordering::SeqCst) {
            CALLS.lock().unwrap().push(call);
            return Some((500, json!({ "error": "InternalServerError" })));
        }
        call.answer = answer(&call);
    } else {
        return None;
    }
    let (read, write) = call.answer;
    CALLS.lock().unwrap().push(call);
    Some((200, json!({ "read": read, "write": write })))
}

/// The community app's answer.
fn answer(call: &Call) -> (bool, bool) {
    let Ok(space) = SpaceRef::parse(&call.space) else {
        return (false, false);
    };
    let ours = space.space_type() == SPACE_TYPE && space.skey() == community_skey(&art());
    let signed = call.iss == space.authority() && call.lxm == CHECK;
    if !ours || !signed || role(space.authority()) != Some(Role::Writer) {
        return (false, false);
    }
    match &call.repo {
        // Never for an account.
        Some(_) => (false, false),
        None => {
            let own = call.client_id.as_deref() == Some(APP_CLIENT.lock().unwrap().as_str());
            (own, false)
        }
    }
}

fn notification(path: &str, body: &[u8]) -> Option<(u16, Value)> {
    let v: Value = serde_json::from_slice(body).ok()?;
    if v["token"].as_str() != Some(TOKEN) {
        return None;
    }
    match path {
        "/xrpc/com.atproto.space.confirmRegistration" => {
            Some((200, json!({ "challenge": v["challenge"] })))
        }
        "/xrpc/com.atproto.space.notifySpaceUpdate" => {
            NOTES.lock().unwrap().push(v);
            Some((200, json!({})))
        }
        _ => None,
    }
}

fn ncalls() -> usize {
    CALLS.lock().unwrap().len()
}

fn calls_since(n: usize) -> Vec<Call> {
    CALLS.lock().unwrap()[n..].to_vec()
}

fn notes_for(space: &SpaceRef) -> usize {
    let s = space.to_string();
    NOTES
        .lock()
        .unwrap()
        .iter()
        .filter(|n| n["space"].as_str() == Some(s.as_str()))
        .count()
}

/// Wait up to 15 s for more than `seen` notifications for `space`.
fn wait_notes(space: &SpaceRef, seen: usize) -> usize {
    for _ in 0..60 {
        if notes_for(space) > seen {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    notes_for(space)
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

/// The app's audiences: only the community it keeps.
struct AppAudiences;
impl AudienceSource for AppAudiences {
    fn state(&self, _: &SpaceRef) -> Option<&SpaceState> {
        None
    }
    fn admits(&self, _: &str) -> bool {
        false
    }
    fn community_member(&self, community: &CommunityRef, did: &str) -> Option<Role> {
        if *community == art() {
            role(did)
        } else {
            None
        }
    }
}

/// The app's own authorization: no delegation, optionally its client
/// attestation and a notification registration.
fn app_authorize(
    pds: &Pds,
    space: &SpaceRef,
    attestation: Option<&str>,
    register: bool,
) -> Result<(Resp, SigningKey), String> {
    let key = SigningKey::random(&mut OsRng);
    let mut body = json!({ "space": space.to_string(),
        "credentialKey": didkey::format_p256(&key.verifying_key().into()) });
    if let Some(a) = attestation {
        body["clientAttestation"] = json!(a);
    }
    if register {
        body["notify"] = json!({ "endpoint": HOST, "token": TOKEN });
    }
    let r = pds.post("com.atproto.space.authorizeSpaceSync", &body, &vec![])?;
    Ok((r, key))
}

/// The app syncs a member's space with its attested client: the writer
/// set, and the authority's repo, the only one that counts.
fn app_sync(
    pds: &Pds,
    dir: &crate::plc::Directory,
    space: &SpaceRef,
    client: &Client,
    register: bool,
) -> Result<Synced, String> {
    let (r, key) = app_authorize(
        pds,
        space,
        Some(&client.attest(space.authority())),
        register,
    )?;
    let credential = r.ok("the app's authorizeSpaceSync")?.json()["credential"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    read_space(pds, dir, space, credential, key, Some(space.authority()))
}

/// The app's state for a space it holds: the published policy, the ref it
/// maps the key to, and roles from its own table.
fn app_state(space: &SpaceRef, s: &Synced) -> SpaceState {
    let mut st = state_of(space, s);
    if space.skey() == community_skey(&art()) {
        st.community = Some(art());
    }
    for (did, r) in ROLES.lock().unwrap().iter() {
        st.members.insert(
            did,
            MemberAccess {
                read: true,
                write: *r == Role::Writer,
            },
        );
    }
    st
}

fn record(space: &SpaceRef, s: &Synced, uri: &SpaceRecordUri) -> Option<Record> {
    umbrae_records(space, s)
        .into_iter()
        .find_map(|(u, r)| match r {
            Ok(Some(r)) if &u == uri => Some(r),
            _ => None,
        })
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
        &json!({ "space": space.to_string(), "repo": who.did, "collection": collection, "rkey": rkey, "record": record }),
        &who.auth(),
    )
}

fn created(r: Result<Resp, String>, what: &str) -> Result<String, String> {
    Ok(r?.ok(what)?.json()["cid"]
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

fn post(text: &str) -> Value {
    json!({ "$type": POST, "text": text, "createdAt": CREATED })
}

fn refused_as(r: Result<Synced, String>, name: &str) -> Result<String, String> {
    match r {
        Err(e) if e.contains(name) => Ok(name.to_owned()),
        Err(e) => Err(e),
        Ok(_) => Err("got a credential".into()),
    }
}

/// The profiles the app holds, by owner.
type Held = BTreeMap<String, (SpaceState, SpaceRecordUri, Profile)>;

/// `registerProfile {key, delegationToken}`: the owner's client fetches a
/// delegation for its profile space, and the app syncs it with that and
/// its attestation. `Err` is the error name the app answers.
fn register_profile(
    pds: &Pds,
    dir: &crate::plc::Directory,
    client: &Client,
    held: &mut Held,
    owner: &Account,
    key: &str,
) -> Result<String, String> {
    if key != KEY {
        return Err("CommunityNotFound".into());
    }
    if role(&owner.did).is_none() {
        return Err("NotAllowed".into());
    }
    let space = profile_space(&owner.did).map_err(|e| e.to_string())?;
    let s = sync(pds, dir, &space, owner, Some(&client.attest(&owner.did)))
        .map_err(|e| format!("ProfileNotFound ({e})"))?;
    let uri = space
        .record(&owner.did, PROFILE, SELF_RKEY)
        .map_err(|e| e.to_string())?;
    match record(&space, &s, &uri) {
        Some(Record::Profile(p)) => {
            let name = p.display_name.clone().unwrap_or_default();
            held.insert(owner.did.clone(), (state_of(&space, &s), uri, *p));
            Ok(name)
        }
        _ => Err("ProfileNotFound (no profile)".into()),
    }
}

/// The app drops a profile when its owner belongs to none of its
/// communities.
fn removed(held: &mut Held, did: &str) {
    ROLES.lock().unwrap().remove(did);
    if role(did).is_none() {
        held.remove(did);
    }
}

pub(crate) fn run(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
) -> Result<(), String> {
    let client_dir = std::env::var("CLIENT_DIR").unwrap_or_else(|_| "/client".into());
    let app_client = Client::publish(&client_dir, "community-app")?;
    let other_client = Client::publish(&client_dir, "community-other")?;
    let serving = Client::publish(&client_dir, "community-serving")?;
    *APP_CLIENT.lock().unwrap() = app_client.id.clone();
    for did in [APP_DID, OTHER_DID] {
        dir.put(
            did,
            json!({
                "type": "plc_operation",
                "verificationMethods": {},
                "rotationKeys": [],
                "alsoKnownAs": [],
                "services": { APP_SERVICE: { "type": "UmbraeManagingApp", "endpoint": HOST } },
                "prev": null,
            }),
        );
    }
    let alice = create_account(pds, "cmalice")?;
    let bob = create_account(pds, "cmbob")?;
    let dan = create_account(pds, "cmdan")?;
    let carol = create_account(pds, "cmcarol")?;
    let eve = create_account(pds, "cmeve")?;
    {
        let mut r = ROLES.lock().unwrap();
        r.insert(alice.did.clone(), Role::Writer);
        r.insert(bob.did.clone(), Role::Writer);
        r.insert(eve.did.clone(), Role::Writer);
        r.insert(dan.did.clone(), Role::Reader);
    }
    let space_of = |a: &Account| community_space(&a.did, &art()).map_err(|e| e.to_string());
    let (a_space, b_space, d_space) = (space_of(&alice)?, space_of(&bob)?, space_of(&dan)?);
    report.check(
        "community: setup",
        Ok(format!(
            "skey {}; alice {} bob {} (writers), dan {} (reader), carol {} (outside), eve {}",
            a_space.skey(),
            alice.did,
            bob.did,
            dan.did,
            carol.did,
            eve.did
        )),
    );

    // Each author creates their own community space.
    let n = ncalls();
    let policy = json!({ "$type": "com.atproto.managedspace.policy", "managingApp": app(), "publishPolicy": true });
    for (who, space) in [(&alice, &a_space), (&bob, &b_space), (&dan, &d_space)] {
        pds.post(
            "com.atproto.space.createSpace",
            &json!({ "spaceType": SPACE_TYPE, "skey": space.skey(), "policy": policy }),
            &who.auth(),
        )?
        .ok("createSpace community")?;
    }
    let got = pds
        .get(
            "com.atproto.space.getSpace",
            &[("space", &a_space.to_string())],
            &alice.auth(),
        )?
        .ok("getSpace community")?
        .json();
    let stored = crate::umbrae_flow::map(&got["policy"])
        .and_then(|m| Policy::from_map(&m).map_err(|e| e.to_string()));
    report.check(
        "community: the PDS stores each author's managed policy, and it passes check_community_policy",
        match stored {
            Ok(p) if p == managed_policy(&app())
                && check_community_policy(&a_space, &art(), &p).is_ok()
                && check_policy(&a_space, &p).is_ok() =>
            {
                Ok(a_space.to_string())
            }
            Ok(p) => Err(format!("{p:?}")),
            Err(e) => Err(e),
        },
    );

    // Alice posts and makes a feed in her space; Bob replies, likes,
    // reposts, quotes and posts to her feed, each in his own space, where
    // the placement helpers send him.
    let a_post = a_space
        .record(&alice.did, POST, "3mbaaaaaaac22")
        .map_err(|e| e.to_string())?;
    let a_cid = created(
        write(
            pds,
            &a_space,
            &alice,
            POST,
            "3mbaaaaaaac22",
            post("hello art"),
        ),
        "alice's post",
    )?;
    let feed_uri = a_space
        .record(&alice.did, FEED, "3mbaaaaaaac2a")
        .map_err(|e| e.to_string())?;
    let feed_cid = created(
        write(
            pds,
            &a_space,
            &alice,
            FEED,
            "3mbaaaaaaac2a",
            json!({ "$type": FEED, "name": "Art", "authors": [bob.did], "createdAt": CREATED }),
        ),
        "alice's feed",
    )?;
    let parent = json!({ "uri": a_post.to_string(), "cid": a_cid });
    let target = Target::Hidden(a_post.clone());
    let uri_err = |e: umbrae_core::uri::UriError| e.to_string();
    let into = [
        reply_space(&bob.did, &target).map_err(uri_err)?,
        Some(like_space(&bob.did, &a_post).map_err(uri_err)?),
        Some(repost_space(&bob.did, &a_post).map_err(uri_err)?),
        quote_space(&bob.did, &target).map_err(uri_err)?,
    ];
    let placed = into.iter().all(|s| s.as_ref() == Some(&b_space));
    let at_b = |collection: &str, rkey: &str| {
        b_space
            .record(&bob.did, collection, rkey)
            .map_err(|e| e.to_string())
    };
    let (reply_uri, like_uri, repost_uri, quote_uri, feed_post_uri) = (
        at_b(POST, "3mbaaaaaaac23")?,
        at_b(LIKE, "3mbaaaaaaac24")?,
        at_b(REPOST, "3mbaaaaaaac25")?,
        at_b(POST, "3mbaaaaaaac26")?,
        at_b(POST, "3mbaaaaaaac27")?,
    );
    let bobs = [
        (
            &reply_uri,
            json!({ "$type": POST, "text": "lovely", "createdAt": CREATED,
                "reply": { "root": parent, "parent": parent } }),
        ),
        (
            &like_uri,
            json!({ "$type": LIKE, "subject": parent, "createdAt": CREATED }),
        ),
        (
            &repost_uri,
            json!({ "$type": REPOST, "subject": parent, "createdAt": CREATED }),
        ),
        (
            &quote_uri,
            json!({ "$type": POST, "text": "see this", "createdAt": CREATED,
                "embed": { "$type": "app.bsky.embed.record", "record": parent } }),
        ),
        (
            &feed_post_uri,
            json!({ "$type": POST, "text": "for the feed", "createdAt": CREATED,
                "feeds": [{ "uri": feed_uri.to_string(), "cid": feed_cid }] }),
        ),
    ];
    let mut statuses = Vec::new();
    for (uri, rec) in &bobs {
        let r = write(
            pds,
            &b_space,
            &bob,
            uri.collection(),
            uri.rkey(),
            rec.clone(),
        )?;
        statuses.push(r.status);
    }
    // The authors read their own spaces with their own sessions.
    let own_a = pds.get(
        "com.atproto.space.listRecords",
        &[("space", &a_space.to_string()), ("repo", &alice.did)],
        &alice.auth(),
    )?;
    let own_b = pds.get(
        "com.atproto.space.getRecord",
        &[
            ("space", &b_space.to_string()),
            ("repo", &bob.did),
            ("collection", POST),
            ("rkey", reply_uri.rkey()),
        ],
        &bob.auth(),
    )?;
    settle();
    let asked = calls_since(n);
    report.check(
        "community: replies, likes, reposts and quotes of Alice's post go into Bob's own space; the PDS takes them",
        if placed && statuses.iter().all(|s| *s == 200) {
            Ok(format!("{} write(s) in {}", statuses.len(), b_space))
        } else {
            Err(format!("placement {into:?}, statuses {statuses:?}"))
        },
    );
    report.check(
        "community: creating spaces, every write and the authors' own reads ask the app nothing",
        if asked.is_empty() && own_a.status == 200 && own_b.status == 200 {
            Ok("0 checkAccess calls".into())
        } else {
            Err(format!(
                "listRecords {} getRecord {}; calls {asked:?}",
                own_a.status, own_b.status
            ))
        },
    );

    // The app syncs both writers' spaces with no delegation, registering
    // for notifications.
    let n = ncalls();
    let a_sync = app_sync(pds, dir, &a_space, &app_client, true)?;
    let b_sync = app_sync(pds, dir, &b_space, &app_client, true)?;
    let c = calls_since(n);
    let own_client = c.len() == 2
        && c.iter().all(|c| {
            c.repo.is_none()
                && c.client_id.as_deref() == Some(app_client.id.as_str())
                && c.answer == (true, false)
        });
    let bad: Vec<_> = [(&a_space, &a_sync), (&b_space, &b_sync)]
        .into_iter()
        .flat_map(|(s, y)| umbrae_records(s, y))
        .filter_map(|(u, r)| r.err().map(|e| format!("{u}: {e}")))
        .collect();
    let held = umbrae_records(&a_space, &a_sync).len() + umbrae_records(&b_space, &b_sync).len();
    report.check(
        "community: the app syncs both spaces with its attested client and no delegation; every record validates",
        if own_client && bad.is_empty() && held == 7 {
            Ok(format!("{held} record(s); calls {:?}", c.iter().map(|c| c.answer).collect::<Vec<_>>()))
        } else {
            Err(format!("{held} record(s), bad {bad:?}, calls {c:?}"))
        },
    );
    let (na, nb) = (notes_for(&a_space), notes_for(&b_space));
    created(
        write(
            pds,
            &a_space,
            &alice,
            POST,
            "3mbaaaaaaac28",
            post("more art"),
        ),
        "alice again",
    )?;
    created(
        write(
            pds,
            &b_space,
            &bob,
            POST,
            "3mbaaaaaaac29",
            post("bob again"),
        ),
        "bob again",
    )?;
    let (na2, nb2) = (wait_notes(&a_space, na), wait_notes(&b_space, nb));
    report.check(
        "community: each author's own write notifies the app's registration",
        if na2 > na && nb2 > nb {
            Ok(format!("alice {na} -> {na2}, bob {nb} -> {nb2}"))
        } else {
            Err(format!("alice {na} -> {na2}, bob {nb} -> {nb2}"))
        },
    );

    // Refusals: no attestation, another client's, a forged one, a replay.
    let n = ncalls();
    let (none, _) = app_authorize(pds, &a_space, None, false)?;
    let (other, _) = app_authorize(pds, &a_space, Some(&other_client.attest(&alice.did)), false)?;
    let c = calls_since(n);
    report.check(
        "community: without an attestation, or with another client's, the app answers nothing",
        match (
            expect_refusal(&none, Some("SpaceNotFound")),
            expect_refusal(&other, Some("SpaceNotFound")),
            c.as_slice(),
        ) {
            (Ok(_), Ok(_), [x, y])
                if x.client_id.is_none()
                    && y.client_id.as_deref() == Some(other_client.id.as_str())
                    && x.answer == (false, false)
                    && y.answer == (false, false) =>
            {
                Ok("SpaceNotFound twice".into())
            }
            (x, y, _) => Err(format!("{x:?} {y:?} {c:?}")),
        },
    );
    let n = ncalls();
    let forged = umbrae_core::tokens::create_client_attestation(
        &app_client.id,
        &alice.did,
        Some(crate::labeler_flow::KID),
        &other_client.signer,
        crate::now(),
    );
    let (f, _) = app_authorize(pds, &a_space, Some(&forged), false)?;
    let att = app_client.attest(&alice.did);
    let (first, _) = app_authorize(pds, &a_space, Some(&att), false)?;
    let before_replay = ncalls();
    let (replay, _) = app_authorize(pds, &a_space, Some(&att), false)?;
    let replay_calls = ncalls() - before_replay;
    let forged_calls = calls_since(n).len();
    report.check(
        "community: a forged attestation and a replayed one are refused before the app is asked",
        match (
            expect_refusal(&f, Some("InvalidClientAttestation")),
            expect_refusal(&replay, Some("InvalidClientAttestation")),
        ) {
            (Ok(_), Ok(_)) if first.status == 200 && replay_calls == 0 && forged_calls == 1 => {
                Ok("InvalidClientAttestation twice; the first use got a credential".into())
            }
            (x, y) => Err(format!(
                "{x:?} {y:?}; first use HTTP {}; calls {forged_calls} {replay_calls}",
                first.status
            )),
        },
    );

    // Rule 4: no member, reader or outsider gets a credential for Alice's
    // space with their own delegation.
    let mut rows = Vec::new();
    for (name, who) in [("bob", &bob), ("dan", &dan), ("carol", &carol)] {
        let n = ncalls();
        let s = refused_as(sync(pds, dir, &a_space, who, None), "SpaceNotFound");
        let c = calls_since(n);
        let asked = c.len() == 1
            && c[0].repo.as_deref() == Some(who.did.as_str())
            && c[0].answer == (false, false);
        rows.push((name, s.is_ok() && asked, format!("{s:?} {c:?}")));
    }
    report.check(
        "community: Bob (writer), Dan (reader) and Carol (outside) get no credential for Alice's space; the app was asked for each and said nothing",
        if rows.iter().all(|r| r.1) {
            Ok("SpaceNotFound for all three".into())
        } else {
            Err(format!("{rows:?}"))
        },
    );

    // Rule 3: a reader's space is never synced.
    let n = ncalls();
    let (r, _) = app_authorize(pds, &d_space, Some(&app_client.attest(&dan.did)), false)?;
    let c = calls_since(n);
    report.check(
        "community: the app can't sync Dan's space: a reader isn't a writer",
        match (expect_refusal(&r, Some("SpaceNotFound")), c.as_slice()) {
            (Ok(s), [x])
                if x.client_id.as_deref() == Some(app_client.id.as_str())
                    && x.answer == (false, false) =>
            {
                Ok(s)
            }
            (e, _) => Err(format!("{e:?} {c:?}")),
        },
    );

    // The app's view.
    let a_state = app_state(&a_space, &a_sync);
    let b_state = app_state(&b_space, &b_sync);
    let d = Some(dan.did.as_str());
    let cl = Some(carol.did.as_str());
    let feed_rec = record(&a_space, &a_sync, &feed_uri);
    let feed_post = record(&b_space, &b_sync, &feed_post_uri);
    let in_feed = match (&feed_rec, &feed_post) {
        (Some(Record::Feed(f)), Some(Record::Post(p))) => {
            can_view_feed_post(
                d,
                &feed_post_uri,
                p,
                &b_state,
                &feed_uri,
                f,
                &a_state,
                &Everyone,
            ) && !can_view_feed_post(
                cl,
                &feed_post_uri,
                p,
                &b_state,
                &feed_uri,
                f,
                &a_state,
                &Everyone,
            )
        }
        _ => false,
    };
    let views = [
        can_view_record(d, &a_post, &a_state, &Everyone),
        !can_view_record(cl, &a_post, &a_state, &Everyone),
        can_view_record(d, &reply_uri, &b_state, &Everyone),
        can_view_record(d, &like_uri, &b_state, &Everyone),
        can_view_record(d, &quote_uri, &b_state, &Everyone),
        referenced_post(d, &a_post, Some(&a_state), &Everyone) == ReferencedPost::Visible,
        can_view_repost(d, &repost_uri, &b_state, &a_post, &a_state, &Everyone),
        !can_view_repost(cl, &repost_uri, &b_state, &a_post, &a_state, &Everyone),
        in_feed,
    ];
    report.check(
        "community: the app shows the thread, the repost and the feed across both spaces to Dan, not to Carol",
        if views.iter().all(|v| *v) {
            Ok(format!("{} decisions", views.len()))
        } else {
            Err(format!("{views:?}"))
        },
    );

    // Bob writes into Alice's space: his PDS may take it, but it never
    // counts.
    let n = ncalls();
    let stray = write(
        pds,
        &a_space,
        &bob,
        POST,
        "3mbaaaaaaac2b",
        post("in alice's space"),
    )?;
    settle();
    let c = calls_since(n);
    let again = app_sync(pds, dir, &a_space, &app_client, true)?;
    let stray_uri = a_space
        .record(&bob.did, POST, "3mbaaaaaaac2b")
        .map_err(|e| e.to_string())?;
    let st = app_state(&a_space, &again);
    report.check(
        "community: Bob writing into Alice's space: the app answers nothing for him, he isn't a writer there, and it never counts",
        if again.writers == [alice.did.clone()]
            && c.iter().any(|c| c.repo.as_deref() == Some(bob.did.as_str()))
            && c.iter().all(|c| c.answer == (false, false))
            && !is_writer(&bob.did, &st)
            && !can_view_record(Some(&alice.did), &stray_uri, &st, &Everyone)
        {
            Ok(format!("write HTTP {}; {} call(s); writers {:?}", stray.status, c.len(), again.writers))
        } else {
            Err(format!("write {}; calls {c:?}; writers {:?}", stray.status, again.writers))
        },
    );

    // Alice is removed.
    let mut held = Held::new();
    removed(&mut held, &alice.did);
    let n = ncalls();
    let (r, _) = app_authorize(pds, &a_space, Some(&app_client.attest(&alice.did)), true)?;
    let c = calls_since(n);
    let (na, nb) = (notes_for(&a_space), notes_for(&b_space));
    created(
        write(
            pds,
            &a_space,
            &alice,
            POST,
            "3mbaaaaaaac2c",
            post("after removal"),
        ),
        "alice after removal",
    )?;
    created(
        write(
            pds,
            &b_space,
            &bob,
            POST,
            "3mbaaaaaaac2d",
            post("bob after"),
        ),
        "bob after alice's removal",
    )?;
    let nb2 = wait_notes(&b_space, nb);
    settle();
    let na2 = notes_for(&a_space);
    report.check(
        "community: after Alice's removal the app's reauthorization is refused and its registration withdrawn; Bob's still notifies",
        match expect_refusal(&r, Some("SpaceNotFound")) {
            Ok(s) if c.len() == 1 && c[0].answer == (false, false) && na2 == na && nb2 > nb => {
                Ok(format!("{s}; alice notifications {na} -> {na2}, bob {nb} -> {nb2}"))
            }
            e => Err(format!("{e:?}; calls {c:?}; alice {na} -> {na2}, bob {nb} -> {nb2}")),
        },
    );
    let own = pds
        .get(
            "com.atproto.space.listRecords",
            &[("space", &a_space.to_string()), ("repo", &alice.did)],
            &alice.auth(),
        )?
        .ok("alice's own listRecords")?
        .json();
    let kept = own["records"]
        .as_array()
        .is_some_and(|a| a.iter().any(|r| r["rkey"] == a_post.rkey()));
    // The app's cached copy of Alice's space, with her role as it is now.
    let cached = app_state(&a_space, &a_sync);
    let b_now = app_sync(pds, dir, &b_space, &app_client, false)?;
    let b_state = app_state(&b_space, &b_now);
    let views = [
        !can_view_record(d, &a_post, &cached, &Everyone),
        can_view_record(d, &reply_uri, &b_state, &Everyone),
        referenced_post(d, &a_post, Some(&cached), &Everyone) == ReferencedPost::Unavailable,
        referenced_post(d, &a_post, None, &Everyone) == ReferencedPost::Unavailable,
        !can_view_repost(d, &repost_uri, &b_state, &a_post, &cached, &Everyone),
        can_view_record(d, &repost_uri, &b_state, &Everyone),
    ];
    report.check(
        "community: the app's view drops Alice's post and keeps Bob's reply, under a placeholder; her records stay in her repo",
        if kept && views.iter().all(|v| *v) {
            Ok(format!("{} decisions", views.len()))
        } else {
            Err(format!("kept {kept}, {views:?}"))
        },
    );

    // Every call to the community's app: iss the authority, for checkAccess.
    let all: Vec<_> = CALLS
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.aud == app())
        .cloned()
        .collect();
    let bad: Vec<_> = all
        .iter()
        .filter(|c| {
            SpaceRef::parse(&c.space)
                .map(|s| s.authority().to_owned())
                .ok()
                != Some(c.iss.clone())
                || c.lxm != CHECK
        })
        .collect();
    let granted = all
        .iter()
        .filter(|c| c.repo.is_some() && c.answer != (false, false))
        .count();
    report.check(
        "community: every checkAccess call carries iss = the space's authority and lxm = checkAccess; none with an account was granted anything",
        if !all.is_empty() && bad.is_empty() && granted == 0 {
            Ok(format!("{} call(s)", all.len()))
        } else {
            Err(format!("bad {bad:?}, granted {granted}"))
        },
    );

    // A lookalike: Eve's space under the community's key, naming the other
    // app, which says yes to everything. Bob replies to her post there, in
    // his own space.
    let e_space = space_of(&eve)?;
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": SPACE_TYPE, "skey": e_space.skey(),
            "policy": { "$type": "com.atproto.managedspace.policy", "managingApp": other_app(), "publishPolicy": true } }),
        &eve.auth(),
    )?
    .ok("createSpace lookalike")?;
    let e_post = e_space
        .record(&eve.did, POST, "3mbaaaaaaac2e")
        .map_err(|e| e.to_string())?;
    let e_cid = created(
        write(
            pds,
            &e_space,
            &eve,
            POST,
            "3mbaaaaaaac2e",
            post("in the lookalike"),
        ),
        "eve's post",
    )?;
    let e_ref = json!({ "uri": e_post.to_string(), "cid": e_cid });
    let into = reply_space(&bob.did, &Target::Hidden(e_post.clone())).map_err(uri_err)?;
    let lr_uri = at_b(POST, "3mbaaaaaaac2f")?;
    created(
        write(
            pds,
            &b_space,
            &bob,
            POST,
            "3mbaaaaaaac2f",
            json!({ "$type": POST, "text": "replying to eve", "createdAt": CREATED,
                "reply": { "root": e_ref, "parent": e_ref } }),
        ),
        "bob's reply to the lookalike",
    )?;
    let n = ncalls();
    let e_sync = app_sync(pds, dir, &e_space, &app_client, false)?;
    let c = calls_since(n);
    let e_state = app_state(&e_space, &e_sync);
    let b_now = app_sync(pds, dir, &b_space, &app_client, false)?;
    let b_state = app_state(&b_space, &b_now);
    let read_it = matches!(record(&e_space, &e_sync, &e_post), Some(Record::Post(_)));
    let reply_ok = matches!(record(&b_space, &b_now, &lr_uri), Some(Record::Post(_)));
    let mut fixed = e_state.clone();
    fixed.policy = Some(managed_policy(&app()));
    let shown = referenced_post(d, &e_post, Some(&e_state), &Everyone);
    report.check(
        "community: a lookalike under the same key, naming another app that says yes: the app reads it, but its policy check fails and Bob's reply to it shows the parent as unavailable",
        if into.as_ref() == Some(&b_space)
            && read_it
            && reply_ok
            && c.iter().all(|c| c.aud == other_app() && c.answer == (true, true))
            && !c.is_empty()
            && check_community_policy(&e_space, &art(), e_state.policy.as_ref().ok_or("no policy")?).is_err()
            && !can_view_record(d, &e_post, &e_state, &Everyone)
            && shown == ReferencedPost::Unavailable
            && can_view_record(d, &lr_uri, &b_state, &Everyone)
            // With the community's own policy, the same copy would show:
            // the policy is what decides.
            && referenced_post(d, &e_post, Some(&fixed), &Everyone) == ReferencedPost::Visible
        {
            Ok(format!("{} call(s), all to the other app; parent {shown:?}", c.len()))
        } else {
            Err(format!(
                "read {read_it} reply {reply_ok} parent {shown:?} policy {:?} calls {c:?}",
                e_state.policy
            ))
        },
    );

    // Dan's profile, limited by allowedApps, for the community audience.
    let p_space = profile_space(&dan.did).map_err(|e| e.to_string())?;
    let member_policy = |apps: Vec<&str>| {
        json!({ "$type": "com.atproto.memberspace.policy", "publicRead": false, "publicWrite": false,
            "allowedApps": apps, "publishPolicy": true, "publishMembers": true })
    };
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": SPACE_TYPE, "skey": p_space.skey(), "policy": member_policy(vec![&serving.id]) }),
        &dan.auth(),
    )?
    .ok("createSpace profile")?;
    let put_profile = |name: &str| {
        pds.post(
            "com.atproto.space.putRecord",
            &json!({ "space": p_space.to_string(), "repo": dan.did, "collection": PROFILE, "rkey": SELF_RKEY,
                "record": { "$type": PROFILE, "displayName": name, "createdAt": CREATED, "audiences": [
                    { "$type": AUDIENCE_COMMUNITY, "community": { "app": app(), "key": KEY } } ] } }),
            &dan.auth(),
        )?
        .ok("putRecord profile")
    };
    put_profile("Dan")?;
    let refused = register_profile(pds, dir, &app_client, &mut held, &dan, KEY);
    let up = pds
        .post(
            "com.atproto.space.updateSpace",
            &json!({ "space": p_space.to_string(), "policy": member_policy(vec![&serving.id, &app_client.id]) }),
            &dan.auth(),
        )?
        .ok("updateSpace allowedApps")
        .map(|r| r.status);
    let accepted = register_profile(pds, dir, &app_client, &mut held, &dan, KEY);
    let sees = |held: &Held, v: &str| {
        held.get(&dan.did).is_some_and(|(state, uri, p)| {
            can_view_profile(Some(v), uri, p, state, &AppAudiences, &Everyone)
        })
    };
    report.check(
        "community: a profile space limited by allowedApps refuses the community app until Dan adds its client ID; then registerProfile works",
        match (&refused, &up, &accepted) {
            (Err(e), Ok(_), Ok(name))
                if e.contains("ProfileNotFound")
                    && e.contains("AppNotAuthorized")
                    && name == "Dan"
                    && sees(&held, &bob.did)
                    && !sees(&held, &carol.did) =>
            {
                Ok("refused, then held; Bob sees it, Carol doesn't".into())
            }
            other => Err(format!("{other:?}")),
        },
    );

    // Dan is removed: the app drops his profile and won't take it back
    // until he rejoins.
    removed(&mut held, &dan.did);
    let dropped = !held.contains_key(&dan.did);
    put_profile("Dan again")?;
    let while_out = register_profile(pds, dir, &app_client, &mut held, &dan, KEY);
    let out_none = !held.contains_key(&dan.did);
    ROLES.lock().unwrap().insert(dan.did.clone(), Role::Reader);
    let rejoined = register_profile(pds, dir, &app_client, &mut held, &dan, KEY);
    report.check(
        "community: after Dan's removal the app holds no copy of his profile; after he rejoins and calls registerProfile, it holds the current one",
        match (&while_out, &rejoined) {
            (Err(e), Ok(name))
                if e == "NotAllowed" && dropped && out_none && name == "Dan again" && sees(&held, &bob.did) =>
            {
                Ok(format!("dropped; NotAllowed while out; then {name:?}"))
            }
            other => Err(format!("dropped {dropped} out {out_none} {other:?}")),
        },
    );

    // The app is down: no credential, rather than one by default.
    DOWN.store(true, Ordering::SeqCst);
    let n = ncalls();
    let down = app_authorize(pds, &b_space, Some(&app_client.attest(&bob.did)), false);
    let c = calls_since(n);
    DOWN.store(false, Ordering::SeqCst);
    report.check(
        "community: with the app down, the PDS fails closed",
        match down {
            Ok((r, _)) if r.status != 200 && !c.is_empty() => Ok(format!(
                "HTTP {} {}; the app was asked {} time(s)",
                r.status,
                r.error_name(),
                c.len()
            )),
            Ok((r, _)) => Err(format!("HTTP {}; calls {c:?}", r.status)),
            Err(e) => Err(e),
        },
    );
    Ok(())
}
