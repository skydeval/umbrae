//! Prism-facing mode: a fixture for testing a real managing app against
//! the reference PDS, instead of running the checks here.
//!
//! It creates a writer, a member and an outsider. The writer gets a
//! community space whose policy names the app under test, with one post.
//! The accounts and the space are written to `$OUT_DIR/prism-fixture.json`,
//! and then the mock PLC directory keeps serving until the container stops.
//! Started by `scripts/prism-harness.sh`.

use crate::{create_account, wait_ready, Account, Pds};
use serde_json::{json, Value};
use umbrae::space::{community_space, managed_policy};
use umbrae_core::policy::Policy;
use umbrae_lexicons::{CommunityRef, POST};

const CREATED: &str = "2026-11-27T12:00:00.000Z";

fn policy_json(policy: &Policy) -> Value {
    let mut p = json!({ "$type": "com.atproto.managedspace.policy" });
    for (k, v) in policy.to_map() {
        match v {
            umbrae_core::drisl::Value::Bool(b) => p[k] = json!(b),
            umbrae_core::drisl::Value::Text(t) => p[k] = json!(t),
            _ => {}
        }
    }
    p
}

fn account(a: &Account, name: &str) -> Value {
    json!({ "did": a.did, "handle": format!("{name}.test"),
        "password": format!("{name}-interop-password") })
}

pub(crate) fn run(pds: &Pds) -> Result<(), String> {
    let app = std::env::var("PRISM_APP").map_err(|_| "PRISM_APP is not set")?;
    let key = std::env::var("PRISM_KEY").unwrap_or_else(|_| "interop".into());
    let out = std::env::var("OUT_DIR").unwrap_or_else(|_| "/out".into());
    let community = CommunityRef::new(&app, &key).map_err(|e| format!("community ref: {e:?}"))?;

    wait_ready(pds)?;
    // Plain words like "member" are reserved handles on the PDS.
    let writer = create_account(pds, "pwriter")?;
    let member = create_account(pds, "pmember")?;
    let outsider = create_account(pds, "poutsider")?;

    let space = community_space(&writer.did, &community).map_err(|e| e.to_string())?;
    let policy = managed_policy(&app);
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": space.space_type(), "skey": space.skey(),
            "policy": policy_json(&policy) }),
        &writer.auth(),
    )?
    .ok("createSpace community")?;
    let rkey = "3mbaaaaaaaaa2";
    pds.post(
        "com.atproto.space.createRecord",
        &json!({ "space": space.to_string(), "repo": writer.did, "collection": POST,
            "rkey": rkey, "record": { "$type": POST, "text": "hello community",
                "createdAt": CREATED } }),
        &writer.auth(),
    )?
    .ok("community post")?;

    let fixture = json!({
        "pds": pds.url,
        "community": { "app": app, "key": key },
        "space": space.to_string(),
        "skey": space.skey(),
        "post": space.record(&writer.did, POST, rkey).map_err(|e| e.to_string())?.to_string(),
        "writer": account(&writer, "pwriter"),
        "member": account(&member, "pmember"),
        "outsider": account(&outsider, "poutsider"),
    });
    let path = format!("{out}/prism-fixture.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&fixture).unwrap_or_default(),
    )
    .map_err(|e| format!("write {path}: {e}"))?;
    println!("fixture ready: {path}");
    println!("{fixture:#}");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
