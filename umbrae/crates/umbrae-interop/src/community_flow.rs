//! A community on the reference PDS: a managed `tools.umbrae.space` space
//! with key `community`, whose authority is the community's own account.
//! The harness stands in for the managing app (prism, or a PDS managing
//! its own communities): it answers `com.atproto.managedspace.checkAccess`
//! from a table, behind the TLS front end, under a DID in the mock PLC.

use crate::umbrae_flow::{map, sync, umbrae_records, Synced};
use crate::{create_account, Account, Pds, Report};
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use umbrae::access::can_view_record;
use umbrae::community::can_view_feed_post;
use umbrae::space::{check_policy, community_space, managed_policy};
use umbrae::{Members, SpaceState, Tri, ViewContext, SPACE_TYPE};
use umbrae_core::policy::{MemberAccess, Policy};
use umbrae_lexicons::{Record, COMMUNITY_SKEY, FEED, POST};

/// The managing app's DID, registered in the mock PLC.
const APP_DID: &str = "did:plc:managerappaaaaaaaaaaaaaa";
const APP_SERVICE: &str = "umbrae_app";
/// The TLS front end, which proxies `/xrpc/` to the harness.
const APP_ENDPOINT: &str = "https://client.interop.test";
const CHECK_NSID: &str = "com.atproto.managedspace.checkAccess";
const CREATED: &str = "2026-11-26T10:00:00.000Z";

/// The managing app's answers, by DID: (read, write).
static ACCESS: Mutex<BTreeMap<String, (bool, bool)>> = Mutex::new(BTreeMap::new());
/// When set, the app doesn't answer.
static DOWN: AtomicBool = AtomicBool::new(false);
/// Each call: (repo, the service-auth token's iss, its lxm).
static CALLS: Mutex<Vec<(String, String, String)>> = Mutex::new(Vec::new());

fn jwt_claims(token: &str) -> Value {
    token
        .split('.')
        .nth(1)
        .and_then(|p| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

/// Answer a checkAccess call, if this is one.
pub(crate) fn handle(url: &str, authorization: Option<&str>) -> Option<(u16, Value)> {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    if path != format!("/xrpc/{CHECK_NSID}") {
        return None;
    }
    let param = |k: &str| {
        query.split('&').find_map(|kv| {
            let (a, b) = kv.split_once('=')?;
            (a == k).then(|| crate::plc::percent_decode(b))
        })
    };
    let repo = param("repo").unwrap_or_default();
    let claims = authorization
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(jwt_claims)
        .unwrap_or(Value::Null);
    CALLS.lock().unwrap().push((
        repo.clone(),
        claims["iss"].as_str().unwrap_or_default().to_owned(),
        claims["lxm"].as_str().unwrap_or_default().to_owned(),
    ));
    if DOWN.load(Ordering::SeqCst) {
        return Some((500, json!({ "error": "InternalServerError" })));
    }
    let (read, write) = ACCESS.lock().unwrap().get(&repo).copied().unwrap_or((false, false));
    Some((200, json!({ "read": read, "write": write })))
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

/// The reader's state: the policy the PDS published, and members as the
/// managing app answers.
fn state(space: &umbrae_core::uri::SpaceRef, policy: Policy) -> SpaceState {
    let mut s = SpaceState::new(space.clone(), Some(policy));
    let mut m = Members::default();
    for (did, (read, write)) in ACCESS.lock().unwrap().iter() {
        m.insert(did, MemberAccess { read: *read, write: *write });
    }
    s.members = m;
    s
}

pub(crate) fn run(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    alice: &Account,
    bob: &Account,
    carol: &Account,
) -> Result<(), String> {
    dir.put(
        APP_DID,
        json!({
            "type": "plc_operation",
            "verificationMethods": {},
            "rotationKeys": [],
            "alsoKnownAs": [],
            "services": { APP_SERVICE: { "type": "UmbraeManagingApp", "endpoint": APP_ENDPOINT } },
            "prev": null,
        }),
    );
    let community = create_account(pds, "commune")?;
    {
        let mut a = ACCESS.lock().unwrap();
        a.insert(alice.did.clone(), (true, true));
        a.insert(bob.did.clone(), (true, true));
    }
    let app = format!("{APP_DID}#{APP_SERVICE}");
    let space = community_space(&community.did).map_err(|e| e.to_string())?;
    let space_str = space.to_string();
    pds.post(
        "com.atproto.space.createSpace",
        &json!({
            "spaceType": SPACE_TYPE,
            "skey": COMMUNITY_SKEY,
            "policy": { "$type": "com.atproto.managedspace.policy", "managingApp": app, "publishPolicy": true },
        }),
        &community.auth(),
    )?
    .ok("createSpace community")?;
    let got = pds
        .get("com.atproto.space.getSpace", &[("space", &space_str)], &community.auth())?
        .ok("getSpace community")?
        .json();
    let stored = map(&got["policy"]).and_then(|m| Policy::from_map(&m).map_err(|e| e.to_string()));
    let policy = match stored {
        Ok(p) if p == managed_policy(&app) && check_policy(&space, &p).is_ok() => p,
        Ok(p) => return Err(format!("community policy stored as {p:?}")),
        Err(e) => return Err(e),
    };
    report.check(
        "community: the PDS stores the managed policy (managing app, published), and it passes check_policy",
        Ok(space_str.clone()),
    );

    let write = |who: &Account, collection: &str, rkey: &str, record: Value| {
        pds.post(
            "com.atproto.space.createRecord",
            &json!({ "space": space_str, "repo": who.did, "collection": collection, "rkey": rkey, "record": record }),
            &who.auth(),
        )
    };
    let feed = space
        .record(&alice.did, FEED, "3mbaaaaaaae22")
        .map_err(|e| e.to_string())?;
    let feed_cid = write(
        alice,
        FEED,
        "3mbaaaaaaae22",
        json!({ "$type": FEED, "name": "Art", "authors": [bob.did], "createdAt": CREATED }),
    )?
    .ok("feed")?
    .json()["cid"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let bob_post = space
        .record(&bob.did, POST, "3mbaaaaaaae23")
        .map_err(|e| e.to_string())?;
    write(
        bob,
        POST,
        "3mbaaaaaaae23",
        json!({ "$type": POST, "text": "to the art feed", "feeds": [{ "uri": feed.to_string(), "cid": feed_cid }], "createdAt": CREATED }),
    )?
    .ok("bob's community post")?;
    write(
        alice,
        POST,
        "3mbaaaaaaae24",
        json!({ "$type": POST, "text": "hello community", "createdAt": CREATED }),
    )?
    .ok("alice's community post")?;
    // Carol's own PDS takes her write; the managing app says she isn't a
    // member, so the community never tracks it.
    let carol_write = write(
        carol,
        POST,
        "3mbaaaaaaae25",
        json!({ "$type": POST, "text": "let me in", "createdAt": CREATED }),
    )?;

    let synced: Synced = sync(pds, dir, &space, bob, None)?;
    let tracked = synced.writers.contains(&alice.did)
        && synced.writers.contains(&bob.did)
        && !synced.writers.contains(&carol.did);
    report.check(
        "community: the PDS asks the managing app; members' writes are tracked, an outsider's isn't",
        if tracked {
            Ok(format!("{} writer(s); carol's write HTTP {}", synced.writers.len(), carol_write.status))
        } else {
            Err(format!("writers {:?}", synced.writers))
        },
    );

    let s = state(&space, policy.clone());
    let records = umbrae_records(&space, &synced);
    let bad: Vec<_> = records
        .iter()
        .filter_map(|(u, r)| r.as_ref().err().map(|e| format!("{u}: {e}")))
        .collect();
    let feed_rec = records.iter().find_map(|(u, r)| match r {
        Ok(Some(Record::Feed(f))) if u == &feed => Some(f.clone()),
        _ => None,
    });
    let post_rec = records.iter().find_map(|(u, r)| match r {
        Ok(Some(Record::Post(p))) if u == &bob_post => Some(p.clone()),
        _ => None,
    });
    let in_feed = match (&feed_rec, &post_rec) {
        (Some(f), Some(p)) => {
            can_view_feed_post(Some(&alice.did), &bob_post, p, &feed, f, &s, &Everyone)
                && !can_view_feed_post(Some(&carol.did), &bob_post, p, &feed, f, &s, &Everyone)
        }
        _ => false,
    };
    report.check(
        "community: the feed and posts validate; the feed shows Bob's post to members, not to Carol",
        if bad.is_empty() && in_feed {
            Ok(format!("{} record(s)", records.len()))
        } else {
            Err(format!("bad {bad:?}, in feed {in_feed}"))
        },
    );

    let refused = sync(pds, dir, &space, carol, None);
    report.check(
        "community: a non-member gets no credential (the managing app says no)",
        match refused {
            Err(e) if e.contains("SpaceNotFound") => Ok("SpaceNotFound".into()),
            Err(e) => Err(e),
            Ok(_) => Err("carol got a credential".into()),
        },
    );

    let calls = CALLS.lock().unwrap().clone();
    let signed = !calls.is_empty()
        && calls
            .iter()
            .all(|(_, iss, lxm)| iss == &community.did && lxm == CHECK_NSID);
    report.check(
        "community: every checkAccess call carried service auth from the community, for checkAccess",
        if signed {
            Ok(format!("{} call(s)", calls.len()))
        } else {
            Err(format!("{calls:?}"))
        },
    );

    // Bob is removed: the app says no, and the community drops him as a
    // writer. His posts leave the community.
    ACCESS.lock().unwrap().insert(bob.did.clone(), (false, false));
    pds.post(
        "com.atproto.space.removeWriter",
        &json!({ "space": space_str, "repo": bob.did }),
        &community.auth(),
    )?
    .ok("removeWriter")?;
    let after = sync(pds, dir, &space, alice, None)?;
    let s = state(&space, policy);
    let gone = !after.writers.contains(&bob.did)
        && !can_view_record(Some(&alice.did), &bob_post, &s, &Everyone);
    report.check(
        "community: after removal Bob isn't a writer, and his posts leave the community",
        if gone {
            Ok(format!("{} writer(s)", after.writers.len()))
        } else {
            Err(format!("writers {:?}", after.writers))
        },
    );

    // The app is down: no credential, rather than one by default.
    DOWN.store(true, Ordering::SeqCst);
    let down = sync(pds, dir, &space, alice, None);
    DOWN.store(false, Ordering::SeqCst);
    report.check(
        "community: with the managing app down, the PDS fails closed",
        match down {
            Err(e) => Ok(e.chars().take(80).collect()),
            Ok(_) => Err("got a credential with the app down".into()),
        },
    );
    Ok(())
}
