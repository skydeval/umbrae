//! The hidden-post flow, end to end against the reference PDS, using the
//! `umbrae` and `umbrae-lexicons` crates as a client and an app would.
//!
//! Alice creates a group with the Umbrae policy, names it and adds Bob. She
//! posts; Bob replies and likes in the same space. Carol is outside. An app
//! syncs the space through a member's delegation, rebuilds the member list
//! from what the PDS published, validates every record and decides who sees
//! what. Then Alice removes Bob and the app's view follows.

use crate::{credential_headers, expect_refusal, lexjson, with_mac, Account, Pds, Report, Resp};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use umbrae::access::{can_view_record, can_view_space, can_write, visible_members};
use umbrae::placement::{leaks_hidden, like_space, reply_space};
use umbrae::space::{check_policy, group_policy, group_space};
use umbrae::{SpaceState, Tri, ViewContext, SPACE_TYPE};
use umbrae_core::cid::Cid;
use umbrae_core::drisl::{self, Value as D};
use umbrae_core::mac::{self, MacProfile};
use umbrae_core::policy::{MemberAccess, Policy};
use umbrae_core::repo_archive::{read_repo_archive, ArchivedRecord};
use umbrae_core::uri::{SpaceRecordUri, SpaceRef};
use umbrae_core::{didkey, kem};
use umbrae_lexicons::{validate_record, Record, Target, GROUP, GROUP_RKEY, LIKE, POST};

const SKEY: &str = "3mbbbbbbbbbb2";
const CREATED: &str = "2026-11-13T10:00:00.000Z";

/// Everyone active, and only the listed blocks.
struct Ctx(BTreeSet<(String, String)>);

impl ViewContext for Ctx {
    fn is_active(&self, _: &str) -> Tri {
        Tri::Yes
    }

    fn blocked(&self, a: &str, b: &str) -> Tri {
        let hit = self
            .0
            .iter()
            .any(|(x, y)| (x == a && y == b) || (x == b && y == a));
        if hit {
            Tri::Yes
        } else {
            Tri::No
        }
    }
}

pub(crate) fn map(v: &Value) -> Result<BTreeMap<String, D>, String> {
    match lexjson::to_drisl(v)? {
        D::Map(m) => Ok(m),
        _ => Err("not an object".into()),
    }
}

fn cid_of(v: &Value) -> Result<String, String> {
    drisl::encode(&lexjson::to_drisl(v)?)
        .map(|b| Cid::for_drisl(&b).to_string())
        .map_err(|e| e.to_string())
}

pub(crate) fn delegation(pds: &Pds, space: &str, who: &Account) -> Result<String, String> {
    Ok(pds
        .get(
            "com.atproto.space.getDelegationToken",
            &[("space", space)],
            &who.auth(),
        )?
        .ok("getDelegationToken")?
        .json()["token"]
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

/// An app's view of the space: a credential, the writer set and every
/// writer's repo, each MAC-checked and verified against its commit.
pub(crate) struct Synced {
    pub(crate) writers: Vec<String>,
    pub(crate) repos: BTreeMap<String, Vec<ArchivedRecord>>,
}

/// Sync through `via`'s delegation, presenting `attestation` when the
/// space restricts apps.
pub(crate) fn sync(
    pds: &Pds,
    dir: &crate::plc::Directory,
    space: &SpaceRef,
    via: &Account,
    attestation: Option<&str>,
) -> Result<Synced, String> {
    let space_str = space.to_string();
    let key = SigningKey::random(&mut OsRng);
    let kid = didkey::format_p256(&key.verifying_key().into());
    let token = delegation(pds, &space_str, via)?;
    let mut body = json!({ "space": space_str, "credentialKey": kid, "delegationToken": token });
    if let Some(a) = attestation {
        body["clientAttestation"] = json!(a);
    }
    let credential = pds
        .post("com.atproto.space.authorizeSpaceSync", &body, &vec![])?
        .ok("authorizeSpaceSync")?
        .json()["credential"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let authority = space.authority();
    let w = pds
        .get(
            "com.atproto.space.listWriters",
            &[("space", &space_str)],
            &credential_headers(&credential, authority, &key),
        )?
        .ok("listWriters")?
        .json();
    let mut writers: Vec<String> = w["repos"]
        .as_array()
        .map(|a| {
            // Removed repos are listed too, as repoRemoved: they aren't writers.
            a.iter()
                .filter(|r| r["$type"] == "com.atproto.space.defs#repoWrite")
                .filter_map(|r| r["repo"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    writers.sort();
    let mut repos = BTreeMap::new();
    for did in &writers {
        let author_kem = dir
            .key(did, "atproto_kem")
            .ok_or_else(|| format!("no #atproto_kem for {did}"))?;
        let enc = kem::encapsulate(&author_kem).map_err(|e| e.to_string())?;
        let r: Resp = pds
            .get(
                "com.atproto.space.getRepo",
                &[("space", &space_str), ("repo", did)],
                &with_mac(
                    credential_headers(&credential, did, &key),
                    MacProfile::Commit,
                    &enc,
                ),
            )?
            .ok("getRepo")?;
        let (commit, records) = read_repo_archive(&r.body).map_err(|e| format!("{did}: {e}"))?;
        mac::verify_commit_mac(&commit, &enc, &r.mac_fields(MacProfile::Commit))
            .map_err(|e| format!("{did} MAC: {e}"))?;
        commit
            .check_for(did, space)
            .map_err(|e| format!("{did}: {e}"))?;
        repos.insert(did.clone(), records);
    }
    Ok(Synced { writers, repos })
}

fn state_of(space: &SpaceRef, s: &Synced) -> SpaceState {
    let empty = Vec::new();
    let records = s.repos.get(space.authority()).unwrap_or(&empty);
    SpaceState::from_authority_records(
        space.clone(),
        records
            .iter()
            .map(|r| (r.collection.as_str(), r.rkey.as_str(), &r.value)),
    )
}

fn umbrae_records(
    space: &SpaceRef,
    s: &Synced,
) -> Vec<(SpaceRecordUri, Result<Option<Record>, String>)> {
    let mut out = Vec::new();
    for (did, records) in &s.repos {
        for r in records {
            let Ok(uri) = space.record(did, &r.collection, &r.rkey) else {
                continue;
            };
            let v = validate_record(&uri, &r.value).map_err(|e| e.to_string());
            if !matches!(v, Ok(None)) {
                out.push((uri, v));
            }
        }
    }
    out
}

pub(crate) fn run(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    alice: &Account,
    bob: &Account,
    carol: &Account,
) -> Result<(), String> {
    let space = group_space(&alice.did, SKEY).map_err(|e| e.to_string())?;
    let space_str = space.to_string();
    let wanted = group_policy(None);

    // The group, created with Umbrae's policy, as the PDS stores it.
    let mut policy_json = json!({ "$type": "com.atproto.memberspace.policy" });
    for (k, v) in wanted.to_map() {
        if let D::Bool(b) = v {
            policy_json[k] = json!(b);
        }
    }
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": SPACE_TYPE, "skey": SKEY, "policy": policy_json }),
        &alice.auth(),
    )?
    .ok("createSpace umbrae")?;
    let got = pds
        .get(
            "com.atproto.space.getSpace",
            &[("space", &space_str)],
            &alice.auth(),
        )?
        .ok("getSpace")?
        .json();
    let stored = map(&got["policy"]).and_then(|m| Policy::from_map(&m).map_err(|e| e.to_string()));
    report.check(
        "umbrae: the PDS stores the group policy exactly, and it passes check_policy",
        match stored {
            Ok(p) if p == wanted && check_policy(&space, &p).is_ok() => Ok(space_str.clone()),
            Ok(p) => Err(format!("{p:?}")),
            Err(e) => Err(e),
        },
    );

    // Name the group, add Bob.
    let write = |who: &Account,
                 collection: &str,
                 rkey: &str,
                 record: &Value|
     -> Result<Resp, String> {
        pds.post(
            "com.atproto.space.createRecord",
            &json!({ "space": space_str, "repo": who.did, "collection": collection, "rkey": rkey, "record": record }),
            &who.auth(),
        )
    };
    let group = json!({ "$type": GROUP, "name": "close friends", "createdAt": CREATED });
    write(alice, GROUP, GROUP_RKEY, &group)?.ok("group record")?;
    pds.post(
        "com.atproto.memberspace.putMembers",
        &json!({ "space": space_str, "members": [{ "did": bob.did, "read": true, "write": true }] }),
        &alice.auth(),
    )?
    .ok("putMembers umbrae")?;

    // Alice posts; Bob replies and likes, into the parent's space.
    let post_rkey = "3mbaaaaaaaab2";
    let post = json!({ "$type": POST, "text": "only for you", "createdAt": CREATED });
    let post_uri = space
        .record(&alice.did, POST, post_rkey)
        .map_err(|e| e.to_string())?;
    let post_cid = write(alice, POST, post_rkey, &post)?.ok("post")?.json()["cid"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let parent = json!({ "uri": post_uri.to_string(), "cid": post_cid });
    let reply_into = reply_space(&Target::Hidden(post_uri.clone()));
    let like_into = like_space(&post_uri);
    report.check(
        "umbrae: a reply and a like go into the parent's space",
        if reply_into.as_ref() == Some(&space) && like_into == space {
            Ok("same space".into())
        } else {
            Err(format!("{reply_into:?} {like_into}"))
        },
    );
    let reply = json!({ "$type": POST, "text": "thanks", "createdAt": CREATED,
        "reply": { "root": parent, "parent": parent } });
    let like = json!({ "$type": LIKE, "subject": parent, "createdAt": CREATED });
    let reply_uri = space
        .record(&bob.did, POST, "3mbaaaaaaaab3")
        .map_err(|e| e.to_string())?;
    let r = write(bob, POST, "3mbaaaaaaaab3", &reply)?.ok("reply")?;
    let reply_cid_ok = r.json()["cid"] == json!(cid_of(&reply)?);
    write(bob, LIKE, "3mbaaaaaaaab4", &like)?.ok("like")?;
    report.check(
        "umbrae: leaks_hidden refuses a public quote of the hidden post; the reply's CID matches the PDS",
        {
            let quote = json!({ "$type": "app.bsky.feed.post", "text": "look",
                "embed": { "$type": "app.bsky.embed.record", "record": parent } });
            if leaks_hidden(&lexjson::to_drisl(&quote)?) && reply_cid_ok {
                Ok("leaks_hidden".into())
            } else {
                Err(format!(
                    "leak check failed or reply CID differs ({reply_cid_ok})"
                ))
            }
        },
    );

    // Carol, outside, writes into her own repo for the space.
    let carol_post = json!({ "$type": POST, "text": "let me in", "createdAt": CREATED });
    let carol_write = write(carol, POST, "3mbaaaaaaaab5", &carol_post)?;

    // An app syncs through Bob's delegation.
    let synced = sync(pds, dir, &space, bob, None)?;
    let expect: BTreeSet<_> = [alice.did.clone(), bob.did.clone()].into();
    let got: BTreeSet<_> = synced.writers.iter().cloned().collect();
    report.check(
        "umbrae: the writer set is Alice and Bob; Carol's write isn't tracked",
        // Carol's PDS accepts the write into her own repo; only then does
        // leaving her out of the writer set prove anything.
        if carol_write.status != 200 {
            Err(format!(
                "carol's write was refused (HTTP {} {}), so the writer set proves nothing",
                carol_write.status,
                carol_write.error_name()
            ))
        } else if got == expect {
            Ok(format!("carol's write: HTTP {}", carol_write.status))
        } else {
            Err(format!("{got:?}"))
        },
    );
    let state = state_of(&space, &synced);
    report.check(
        "umbrae: policy and member list rebuilt from what the PDS published",
        if state.policy.as_ref() == Some(&wanted)
            && state.members.len() == 1
            && state.members.get(&bob.did)
                == Some(MemberAccess {
                    read: true,
                    write: true,
                })
        {
            Ok("bob read+write".into())
        } else {
            Err(format!("{state:?}"))
        },
    );
    let records = umbrae_records(&space, &synced);
    let bad: Vec<_> = records
        .iter()
        .filter(|(_, v)| v.is_err())
        .map(|(u, v)| format!("{} {v:?}", u.rkey()))
        .collect();
    let kinds: Vec<_> = records
        .iter()
        .map(|(_, v)| match v {
            Ok(Some(Record::Post(p))) if p.reply.is_some() => "reply",
            Ok(Some(Record::Post(_))) => "post",
            Ok(Some(Record::Like(_))) => "like",
            Ok(Some(Record::Group(_))) => "group",
            _ => "?",
        })
        .collect();
    report.check(
        "umbrae: every synced record validates (group, post, reply, like)",
        if bad.is_empty() && records.len() == 4 {
            Ok(kinds.join(", "))
        } else {
            Err(format!("{kinds:?} {bad:?}"))
        },
    );

    let ctx = Ctx(BTreeSet::new());
    let a = Some(alice.did.as_str());
    let b = Some(bob.did.as_str());
    let c = Some(carol.did.as_str());
    let carol_uri = space
        .record(&carol.did, POST, "3mbaaaaaaaab5")
        .map_err(|e| e.to_string())?;
    let views = [
        can_view_space(a, &state, &ctx),
        can_view_space(b, &state, &ctx),
        !can_view_space(c, &state, &ctx),
        !can_view_space(None, &state, &ctx),
        can_view_record(a, &reply_uri, &state, &ctx),
        can_view_record(b, &post_uri, &state, &ctx),
        !can_view_record(c, &post_uri, &state, &ctx),
        !can_view_record(a, &carol_uri, &state, &ctx),
        can_write(&bob.did, &state, &ctx),
        !can_write(&carol.did, &state, &ctx),
    ];
    report.check(
        "umbrae: Alice and Bob see the posts; Carol and signed-out viewers don't",
        if views.iter().all(|v| *v) {
            Ok(format!("{} decisions", views.len()))
        } else {
            Err(format!("{views:?}"))
        },
    );
    report.check(
        "umbrae: members see the member list; outsiders don't",
        match (
            visible_members(b, &state, &ctx),
            visible_members(c, &state, &ctx),
        ) {
            (Some(m), None) if m.get(&bob.did).is_some() => Ok(format!("{} member(s)", m.len())),
            other => Err(format!("{other:?}")),
        },
    );
    let blocked = Ctx(BTreeSet::from([(bob.did.clone(), alice.did.clone())]));
    report.check(
        "umbrae: a block between Bob and Alice hides the group from Bob",
        if !can_view_space(b, &state, &blocked) && can_view_space(a, &state, &blocked) {
            Ok("hidden".into())
        } else {
            Err("still visible".into())
        },
    );

    // Carol can't sync the group at all.
    let token = delegation(pds, &space_str, carol)?;
    let key = SigningKey::random(&mut OsRng);
    let r = pds.post(
        "com.atproto.space.authorizeSpaceSync",
        &json!({ "space": space_str, "credentialKey": didkey::format_p256(&key.verifying_key().into()), "delegationToken": token }),
        &vec![],
    )?;
    report.check(
        "umbrae: an outsider gets no credential for the group",
        expect_refusal(&r, Some("SpaceNotFound")),
    );

    // Alice removes Bob; a fresh sync (through Alice) follows.
    pds.post(
        "com.atproto.memberspace.removeMembers",
        &json!({ "space": space_str, "dids": [bob.did] }),
        &alice.auth(),
    )?
    .ok("removeMembers")?;
    let after = sync(pds, dir, &space, alice, None)?;
    let state = state_of(&space, &after);
    report.check(
        "umbrae: after removal Bob's member record is gone, and so are his view and his reply",
        if state.members.get(&bob.did).is_none()
            && !can_view_space(b, &state, &ctx)
            && !can_view_record(a, &reply_uri, &state, &ctx)
            && can_view_record(a, &post_uri, &state, &ctx)
        {
            Ok(format!("{} member(s) left", state.members.len()))
        } else {
            Err(format!("{state:?}"))
        },
    );
    Ok(())
}
