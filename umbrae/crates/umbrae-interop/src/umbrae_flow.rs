//! The hidden-post flow, end to end against the reference PDS, using the
//! `umbrae` and `umbrae-lexicons` crates as a client and an app would.
//!
//! Alice creates a group with the Umbrae policy, names it and adds Bob. She
//! posts; Bob replies and likes in the same space. Carol is outside. An app
//! syncs the space through a member's delegation, rebuilds the member list
//! from what the PDS published, validates every record and decides who sees
//! what. Then Alice removes Bob and the app's view follows.

use crate::{credential_headers, expect_refusal, lexjson, with_mac, Account, Pds, Report, Resp};
use base64::Engine as _;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use umbrae::access::{
    can_view_record, can_view_repost, can_view_space, can_write, visible_members,
};
use umbrae::placement::{leaks_hidden, like_space, quote_space, reply_space, repost_space};
use umbrae::space::{
    check_list_policy, check_policy, followers_space, group_policy, group_space, list_policy,
    list_space, subscriber,
};
use umbrae::{SpaceState, Tri, ViewContext, SPACE_TYPE};
use umbrae_core::cid::Cid;
use umbrae_core::drisl::{self, Value as D};
use umbrae_core::mac::{self, MacProfile};
use umbrae_core::policy::{MemberAccess, Policy};
use umbrae_core::repo_archive::{read_repo_archive, ArchivedRecord};
use umbrae_core::uri::{SpaceRecordUri, SpaceRef};
use umbrae_core::{didkey, kem};
use umbrae_lexicons::{
    validate_list_record, validate_record, ListRecord, Record, ReplyRule, Target, GROUP,
    GROUP_RKEY, LIKE, LIST, LISTITEM, LIST_SPACE_TYPE, POST, POSTGATE, PROFILE, REPOST,
    RULE_DISABLE, RULE_FOLLOWER, SELF_RKEY, THREADGATE,
};

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
    /// The space credential and the key it's bound to, for further reads.
    pub(crate) credential: String,
    pub(crate) key: SigningKey,
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
    Ok(Synced {
        writers,
        repos,
        credential,
        key,
    })
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

pub(crate) fn umbrae_records(
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
    // A repost and a same-group quote, written wherever the helpers say.
    // The URIs checked later are the group's, so a helper that answered
    // any other space fails the sync and visibility checks below too.
    let write_in = |into: &SpaceRef,
                    who: &Account,
                    collection: &str,
                    rkey: &str,
                    record: &Value|
     -> Result<Resp, String> {
        pds.post(
            "com.atproto.space.createRecord",
            &json!({ "space": into.to_string(), "repo": who.did, "collection": collection, "rkey": rkey, "record": record }),
            &who.auth(),
        )
    };
    let repost_into = repost_space(&post_uri);
    let quote_into = quote_space(&Target::Hidden(post_uri.clone()))
        .ok_or("quote_space gave no space for a hidden quote")?;
    let repost = json!({ "$type": REPOST, "subject": parent, "createdAt": CREATED });
    let quote = json!({ "$type": POST, "text": "this", "createdAt": CREATED,
        "embed": { "$type": "app.bsky.embed.record", "record": parent } });
    let repost_uri = space
        .record(&bob.did, REPOST, "3mbaaaaaaaab6")
        .map_err(|e| e.to_string())?;
    let quote_uri = space
        .record(&bob.did, POST, "3mbaaaaaaaab7")
        .map_err(|e| e.to_string())?;
    let rp = write_in(&repost_into, bob, REPOST, "3mbaaaaaaaab6", &repost)?;
    let qt = write_in(&quote_into, bob, POST, "3mbaaaaaaaab7", &quote)?;
    report.check(
        "umbrae: a repost and a quote go into the post's space, and the PDS takes both",
        if repost_into == space && quote_into == space && rp.status == 200 && qt.status == 200 {
            Ok("same space".into())
        } else {
            Err(format!(
                "{repost_into} {quote_into} repost HTTP {} {}, quote HTTP {} {}",
                rp.status,
                rp.error_name(),
                qt.status,
                qt.error_name()
            ))
        },
    );
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
            Ok(Some(Record::Post(p)))
                if p.quote.as_ref().and_then(|q| q.target.hidden()) == Some(&post_uri) =>
            {
                "quote"
            }
            Ok(Some(Record::Repost(r))) if r.subject.target.hidden() == Some(&post_uri) => "repost",
            Ok(Some(Record::Post(_))) => "post",
            Ok(Some(Record::Like(_))) => "like",
            Ok(Some(Record::Group(_))) => "group",
            _ => "?",
        })
        .collect();
    report.check(
        "umbrae: every synced record validates (group, post, reply, like, repost, quote)",
        if bad.is_empty()
            && records.len() == 6
            && ["group", "post", "reply", "like", "repost", "quote"]
                .iter()
                .all(|k| kinds.contains(k))
        {
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
        can_view_repost(a, &repost_uri, &post_uri, &state, &ctx),
        !can_view_repost(c, &repost_uri, &post_uri, &state, &ctx),
        can_view_record(a, &quote_uri, &state, &ctx),
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
            && !can_view_repost(a, &repost_uri, &post_uri, &state, &ctx)
            && !can_view_record(a, &quote_uri, &state, &ctx)
            && can_view_record(a, &post_uri, &state, &ctx)
        {
            Ok(format!("{} member(s) left", state.members.len()))
        } else {
            Err(format!("{state:?}"))
        },
    );
    Ok(())
}

/// A shared list: Alice owns it, Bob subscribes read-only, Carol is out.
pub(crate) fn lists(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    alice: &Account,
    bob: &Account,
    carol: &Account,
) -> Result<(), String> {
    const LIST_SKEY: &str = "3mbbbbbbbbbc2";
    let space = list_space(&alice.did, LIST_SKEY).map_err(|e| e.to_string())?;
    let space_str = space.to_string();
    let wanted = list_policy(None);
    let mut policy_json = json!({ "$type": "com.atproto.memberspace.policy" });
    for (k, v) in wanted.to_map() {
        if let D::Bool(b) = v {
            policy_json[k] = json!(b);
        }
    }
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": LIST_SPACE_TYPE, "skey": LIST_SKEY, "policy": policy_json }),
        &alice.auth(),
    )?
    .ok("createSpace list")?;
    let got = pds
        .get(
            "com.atproto.space.getSpace",
            &[("space", &space_str)],
            &alice.auth(),
        )?
        .ok("getSpace list")?
        .json();
    let stored = map(&got["policy"]).and_then(|m| Policy::from_map(&m).map_err(|e| e.to_string()));
    report.check(
        "lists: the PDS stores the shared-list policy (members unpublished), and it passes check_list_policy",
        match stored {
            Ok(p) if p == wanted && check_list_policy(&space, &p).is_ok() => Ok(space_str.clone()),
            Ok(p) => Err(format!("{p:?}")),
            Err(e) => Err(e),
        },
    );
    let write = |who: &Account, collection: &str, rkey: &str, record: &Value| {
        pds.post(
            "com.atproto.space.createRecord",
            &json!({ "space": space_str, "repo": who.did, "collection": collection, "rkey": rkey, "record": record }),
            &who.auth(),
        )
    };
    let list = json!({ "$type": LIST, "purpose": "mute", "name": "noisy", "createdAt": CREATED });
    write(alice, LIST, SELF_RKEY, &list)?.ok("list record")?;
    let entry = json!({ "$type": LISTITEM, "subject": carol.did, "createdAt": CREATED });
    write(alice, LISTITEM, "3mbaaaaaaaac2", &entry)?.ok("list item")?;
    let s = subscriber();
    pds.post(
        "com.atproto.memberspace.putMembers",
        &json!({ "space": space_str, "members": [{ "did": bob.did, "read": s.read, "write": s.write }] }),
        &alice.auth(),
    )?
    .ok("putMembers list")?;
    // A subscriber's own PDS takes a write into their repo; the list's
    // owner never counts it.
    let bob_entry = json!({ "$type": LISTITEM, "subject": alice.did, "createdAt": CREATED });
    let bob_write = write(bob, LISTITEM, "3mbaaaaaaaac3", &bob_entry)?;
    // Bob reads it: only Alice writes, her records validate, and no member
    // records are published.
    let synced = sync(pds, dir, &space, bob, None)?;
    let empty = Vec::new();
    let records = synced.repos.get(&alice.did).unwrap_or(&empty);
    let mut kinds = Vec::new();
    let mut bad = Vec::new();
    let mut members = 0;
    for r in records {
        if r.collection == "com.atproto.memberspace.member" {
            members += 1;
            continue;
        }
        let uri = space
            .record(&alice.did, &r.collection, &r.rkey)
            .map_err(|e| e.to_string())?;
        match validate_list_record(&uri, &r.value) {
            Ok(Some(ListRecord::List(l))) if l.name == "noisy" => kinds.push("list"),
            Ok(Some(ListRecord::Item(i))) if i.subject == carol.did => kinds.push("item"),
            Ok(None) => {}
            other => bad.push(format!("{} {other:?}", r.rkey)),
        }
    }
    kinds.sort();
    report.check(
        "lists: a subscriber reads the list and its entry; their own write isn't tracked, and no member list is published",
        if bob_write.status != 200 {
            Err(format!(
                "bob's write was refused (HTTP {} {}), so the writer set proves nothing",
                bob_write.status,
                bob_write.error_name()
            ))
        } else if synced.writers == [alice.did.clone()]
            && kinds == ["item", "list"]
            && bad.is_empty()
            && members == 0
        {
            Ok("1 list, 1 item, 0 member records".into())
        } else {
            Err(format!(
                "writers {:?} kinds {kinds:?} bad {bad:?} members {members}",
                synced.writers
            ))
        },
    );
    // Carol, not subscribed, gets nothing.
    let token = delegation(pds, &space_str, carol)?;
    let key = SigningKey::random(&mut OsRng);
    let r = pds.post(
        "com.atproto.space.authorizeSpaceSync",
        &json!({ "space": space_str, "credentialKey": didkey::format_p256(&key.verifying_key().into()), "delegationToken": token }),
        &vec![],
    )?;
    report.check(
        "lists: a non-subscriber gets no credential for the list",
        expect_refusal(&r, Some("SpaceNotFound")),
    );
    Ok(())
}

/// A 1×1 PNG, for the hidden profile's avatar.
const PNG_1X1: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

/// A private account: Alice's followers space holds her hidden profile,
/// whose avatar is a blob, and a gated post. Bob is an approved follower;
/// Carol isn't.
pub(crate) fn followers(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    alice: &Account,
    bob: &Account,
    carol: &Account,
) -> Result<(), String> {
    let space = followers_space(&alice.did).map_err(|e| e.to_string())?;
    let space_str = space.to_string();
    let wanted = group_policy(None);
    let mut policy_json = json!({ "$type": "com.atproto.memberspace.policy" });
    for (k, v) in wanted.to_map() {
        if let D::Bool(b) = v {
            policy_json[k] = json!(b);
        }
    }
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": SPACE_TYPE, "skey": space.skey(), "policy": policy_json }),
        &alice.auth(),
    )?
    .ok("createSpace followers")?;
    let got = pds
        .get(
            "com.atproto.space.getSpace",
            &[("space", &space_str)],
            &alice.auth(),
        )?
        .ok("getSpace followers")?
        .json();
    let stored = map(&got["policy"]).and_then(|m| Policy::from_map(&m).map_err(|e| e.to_string()));
    report.check(
        "followers: the PDS takes skey followers with the group policy, and it passes check_policy",
        match stored {
            Ok(p) if p == wanted && check_policy(&space, &p).is_ok() => Ok(space_str.clone()),
            Ok(p) => Err(format!("{p:?}")),
            Err(e) => Err(e),
        },
    );

    // The avatar: a PNG uploaded to Alice's PDS and referenced only here.
    let png = base64::engine::general_purpose::STANDARD
        .decode(PNG_1X1)
        .map_err(|e| e.to_string())?;
    let avatar_cid = Cid::for_raw(&png);
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
    let write = |who: &Account, collection: &str, rkey: &str, record: &Value| {
        pds.post(
            "com.atproto.space.createRecord",
            &json!({ "space": space_str, "repo": who.did, "collection": collection, "rkey": rkey, "record": record }),
            &who.auth(),
        )
    };
    let profile = json!({ "$type": PROFILE, "displayName": "Alice",
        "website": "https://alice.example", "avatar": blob, "createdAt": CREATED });
    write(alice, PROFILE, SELF_RKEY, &profile)?.ok("profile")?;
    let post_rkey = "3mbaaaaaaaae2";
    let post_uri = space
        .record(&alice.did, POST, post_rkey)
        .map_err(|e| e.to_string())?;
    let post = json!({ "$type": POST, "text": "followers only", "createdAt": CREATED });
    let post_cid = write(alice, POST, post_rkey, &post)?
        .ok("followers post")?
        .json()["cid"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    pds.post(
        "com.atproto.memberspace.putMembers",
        &json!({ "space": space_str, "members": [{ "did": bob.did, "read": true, "write": true }] }),
        &alice.auth(),
    )?
    .ok("putMembers followers")?;
    let parent = json!({ "uri": post_uri.to_string(), "cid": post_cid });
    let reply_rkey = "3mbaaaaaaaae3";
    let reply_uri = space
        .record(&bob.did, POST, reply_rkey)
        .map_err(|e| e.to_string())?;
    let reply = json!({ "$type": POST, "text": "hello", "createdAt": CREATED,
        "reply": { "root": parent, "parent": parent } });
    write(bob, POST, reply_rkey, &reply)?.ok("follower reply")?;
    let threadgate = json!({ "$type": THREADGATE, "post": post_uri.to_string(),
        "allow": [{ "$type": RULE_FOLLOWER }], "hiddenReplies": [reply_uri.to_string()],
        "createdAt": CREATED });
    write(alice, THREADGATE, post_rkey, &threadgate)?.ok("threadgate")?;
    let postgate = json!({ "$type": POSTGATE, "post": post_uri.to_string(),
        "embeddingRules": [{ "$type": RULE_DISABLE }], "createdAt": CREATED });
    write(alice, POSTGATE, post_rkey, &postgate)?.ok("postgate")?;

    // Bob syncs, and every record validates.
    let synced = sync(pds, dir, &space, bob, None)?;
    let mut kinds = Vec::new();
    let mut bad = Vec::new();
    for (u, v) in umbrae_records(&space, &synced) {
        match v {
            Ok(Some(Record::Profile(p)))
                if p.avatar.as_ref().map(|a| a.cid) == Some(avatar_cid) =>
            {
                kinds.push("profile")
            }
            Ok(Some(Record::Post(p))) if p.reply.is_some() => kinds.push("reply"),
            Ok(Some(Record::Post(_))) => kinds.push("post"),
            Ok(Some(Record::Threadgate(g)))
                if g.post == post_uri
                    && g.allow == Some(vec![ReplyRule::Follower])
                    && g.hidden_replies == [reply_uri.clone()] =>
            {
                kinds.push("threadgate")
            }
            Ok(Some(Record::Postgate(g))) if g.post == post_uri && g.disable_quotes => {
                kinds.push("postgate")
            }
            other => bad.push(format!("{} {} {other:?}", u.collection(), u.rkey())),
        }
    }
    kinds.sort();
    report.check(
        "followers: a follower's sync validates the profile (avatar intact), the post, a reply and both gates",
        if bad.is_empty() && kinds == ["post", "postgate", "profile", "reply", "threadgate"] {
            Ok(kinds.join(", "))
        } else {
            Err(format!("{kinds:?} {bad:?}"))
        },
    );
    let state = state_of(&space, &synced);
    let profile_uri = space
        .record(&alice.did, PROFILE, SELF_RKEY)
        .map_err(|e| e.to_string())?;
    let ctx = Ctx(BTreeSet::new());
    report.check(
        "followers: the approved follower sees the profile; Carol and signed-out viewers don't",
        if can_view_record(Some(&bob.did), &profile_uri, &state, &ctx)
            && !can_view_record(Some(&carol.did), &profile_uri, &state, &ctx)
            && !can_view_record(None, &profile_uri, &state, &ctx)
            && can_write(&bob.did, &state, &ctx)
        {
            Ok("bob only".into())
        } else {
            Err(format!("{state:?}"))
        },
    );

    // The avatar isn't public, but the follower can fetch it. The space
    // fetch proves the blob is there, so the public refusal means something.
    let avatar = avatar_cid.to_string();
    let public = pds.get(
        "com.atproto.sync.getBlob",
        &[("did", &alice.did), ("cid", &avatar)],
        &vec![],
    )?;
    let listed = pds
        .get(
            "com.atproto.sync.listBlobs",
            &[("did", &alice.did)],
            &vec![],
        )?
        .ok("listBlobs")?
        .json();
    let in_listing = listed["cids"]
        .as_array()
        .is_some_and(|a| a.iter().any(|c| c == &json!(avatar)));
    let via_space = pds.get(
        "com.atproto.space.getBlob",
        &[
            ("space", &space_str),
            ("repo", &alice.did),
            ("cid", &avatar),
        ],
        &credential_headers(&synced.credential, &alice.did, &synced.key),
    )?;
    report.check(
        "followers: the avatar isn't served or listed publicly; the follower gets it through space getBlob, and it hashes to its CID",
        match (expect_refusal(&public, Some("BlobNotFound")), in_listing) {
            (Ok(refused), false)
                if via_space.status == 200 && Cid::for_raw(&via_space.body) == avatar_cid =>
            {
                Ok(format!(
                    "public {refused}; space getBlob {} bytes",
                    via_space.body.len()
                ))
            }
            (public, listed) => Err(format!(
                "public {public:?}, listed {listed}, space getBlob HTTP {} {}",
                via_space.status,
                via_space.error_name()
            )),
        },
    );
    Ok(())
}

/// What the stand-in serving app holds for a profile's audiences.
struct Held(Vec<SpaceState>);

impl umbrae::profile::AudienceSource for Held {
    fn state(&self, space: &SpaceRef) -> Option<&SpaceState> {
        self.0.iter().find(|s| s.space == *space)
    }
    fn admits(&self, _: &str) -> bool {
        false
    }
}

/// The one profile: Alice keeps it in her profile space, which has no
/// members. An app reads it on her delegation and shows it to her
/// followers; Bob can't read the space himself.
pub(crate) fn profile(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    alice: &Account,
    bob: &Account,
    carol: &Account,
) -> Result<(), String> {
    use umbrae::profile::{can_view_profile, can_view_profile_blob};
    use umbrae::space::profile_space;
    use umbrae_lexicons::AUDIENCE_FOLLOWERS;

    let space = profile_space(&alice.did).map_err(|e| e.to_string())?;
    let space_str = space.to_string();
    let wanted = group_policy(None);
    let mut policy_json = json!({ "$type": "com.atproto.memberspace.policy" });
    for (k, v) in wanted.to_map() {
        if let D::Bool(b) = v {
            policy_json[k] = json!(b);
        }
    }
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": SPACE_TYPE, "skey": space.skey(), "policy": policy_json }),
        &alice.auth(),
    )?
    .ok("createSpace profile")?;

    let png = base64::engine::general_purpose::STANDARD
        .decode(PNG_1X1)
        .map_err(|e| e.to_string())?;
    let avatar_cid = Cid::for_raw(&png);
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
    let record = json!({ "$type": PROFILE, "displayName": "Alice", "avatar": blob,
        "audiences": [{ "$type": AUDIENCE_FOLLOWERS }], "createdAt": CREATED });
    pds.post(
        "com.atproto.space.putRecord",
        &json!({ "space": space_str, "repo": alice.did, "collection": PROFILE,
            "rkey": SELF_RKEY, "record": record }),
        &alice.auth(),
    )?
    .ok("putRecord profile")?;

    // The app syncs on Alice's delegation; Bob's own is refused.
    let synced = sync(pds, dir, &space, alice, None)?;
    let state = state_of(&space, &synced);
    let bob_direct = sync(pds, dir, &space, bob, None);
    let uri = space
        .record(&alice.did, PROFILE, SELF_RKEY)
        .map_err(|e| e.to_string())?;
    let found = umbrae_records(&space, &synced)
        .into_iter()
        .find(|(u, _)| *u == uri)
        .map(|(_, v)| v);
    let profile = match found {
        Some(Ok(Some(Record::Profile(p)))) => *p,
        other => return Err(format!("profile space record: {other:?}")),
    };
    report.check(
        "profile: the one profile validates with its audiences, its space passes check_policy with no members, and only the owner's delegation reads it",
        match (&state.policy, &bob_direct) {
            (Some(p), Err(_))
                if check_policy(&space, p).is_ok()
                    && state.members.is_empty()
                    && profile.audiences.as_ref().is_some_and(|a| a.len() == 1) =>
            {
                Ok("members none; bob refused".into())
            }
            (p, b) => Err(format!(
                "policy {p:?}, members {}, bob {:?}",
                state.members.len(),
                b.as_ref().map(|_| "synced")
            )),
        },
    );

    // The app's view: Bob is an approved follower (from the followers
    // space), Carol isn't.
    let followers = followers_space(&alice.did).map_err(|e| e.to_string())?;
    let held = Held(vec![state_of(
        &followers,
        &sync(pds, dir, &followers, alice, None)?,
    )]);
    let ctx = Ctx(BTreeSet::new());
    let via_space = pds.get(
        "com.atproto.space.getBlob",
        &[
            ("space", &space_str),
            ("repo", &alice.did),
            ("cid", &avatar_cid.to_string()),
        ],
        &credential_headers(&synced.credential, &alice.did, &synced.key),
    )?;
    report.check(
        "profile: a follower sees it and its avatar, which the app fetches through the profile space; Carol sees neither",
        if can_view_profile(Some(&bob.did), &uri, &profile, &state, &held, &ctx)
            && can_view_profile_blob(Some(&bob.did), &avatar_cid, &uri, &profile, &state, &held, &ctx)
            && !can_view_profile(Some(&carol.did), &uri, &profile, &state, &held, &ctx)
            && via_space.status == 200
            && Cid::for_raw(&via_space.body) == avatar_cid
        {
            Ok(format!("avatar {} bytes", via_space.body.len()))
        } else {
            Err(format!(
                "space getBlob HTTP {} {}",
                via_space.status,
                via_space.error_name()
            ))
        },
    );
    Ok(())
}
