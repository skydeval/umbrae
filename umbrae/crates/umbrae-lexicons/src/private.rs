//! Private accounts: the private space (`tools.umbrae.private`, key `self`)
//! and the records it holds.
//!
//! The space holds native `app.bsky.feed.*` records, so moving a record in
//! is an exact copy at the same key, and the owner's `rules`. The PDS
//! validates the native schemas on ordinary writes; Umbrae checks only what
//! its rules use:
//! - one of the six collections, with `$type` matching;
//! - TID keys, except the gates, which take their post's key, and `rules`,
//!   at `self`;
//! - a record in this space is named by its `at:space` URI or, for the
//!   owner's records, by its public `at://` alias. A space URI of any other
//!   space doesn't count;
//! - the owner's records may also name public records;
//! - another account's record counts only if it acts on the owner's thread:
//!   a reply whose root is the owner's post and whose parent is in this
//!   space, a like, repost or quote of a record in this space, or a postgate
//!   on its own post here. A top-level post doesn't count;
//! - `rules` only by the owner;
//! - `approval` (`tools.umbrae.private.approval`) only by the owner, at a
//!   TID, naming a DID other than the owner. The owner's approvals are its
//!   approved followers. Approvals aren't one of the six: no public alias
//!   names one, and they stay inside when the owner goes public.

use crate::validate::{
    datetime, is_datetime, strong_ref, Invalid, PublicUri, Reply, StrongRef, Target,
};
use crate::{
    BSKY_LIKE, BSKY_POST, BSKY_POSTGATE, BSKY_REPOST, BSKY_THREADGATE, PRIVATE_APPROVAL,
    PRIVATE_COLLECTIONS, PRIVATE_RULES, PRIVATE_RULE_APPROVED_FOLLOWERS, PRIVATE_RULE_FOLLOWING,
    PRIVATE_RULE_LIST, PRIVATE_RULE_MUTUALS, PRIVATE_SPACE_TYPE, SELF_RKEY,
};
use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{
    contains_space_uri, is_space_uri, is_valid_did, is_valid_tid, SpaceRecordUri, SpaceRef,
};

type Map = BTreeMap<String, Value>;

/// One way to pass the owner's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rule {
    /// Accounts the owner approved: named by at least one of the owner's
    /// `tools.umbrae.private.approval` records in the private space.
    ApprovedFollowers,
    /// Accounts the owner follows publicly.
    Following,
    /// Accounts that follow each other publicly with the owner.
    Mutuals,
    /// Members of a public `app.bsky.graph.list`. Grants nothing unless the
    /// list is the owner's own.
    List(PublicUri),
}

/// `tools.umbrae.private.rules`: who may see a private account's records.
/// Rule types this version doesn't know, and malformed rules, are dropped,
/// so they grant nothing. An empty `allow` means the owner alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rules {
    pub allow: Vec<Rule>,
    pub created_at: String,
    pub updated_at: Option<String>,
    /// `approvalsInSpace`: approved followers are the owner's approvals
    /// only. `false` (or absent) while an account made private before
    /// approvals may still be migrating from its followers space.
    pub approvals_in_space: bool,
}

/// `tools.umbrae.private.approval`: the owner approves one follower.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Approval {
    /// The approved account's DID, never the owner's.
    pub subject: String,
    pub created_at: String,
}

/// The parts of a native post that the rules use.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrivatePost {
    pub reply: Option<Reply>,
    /// The quoted record, from `app.bsky.embed.record` or
    /// `app.bsky.embed.recordWithMedia`.
    pub quote: Option<StrongRef>,
}

/// A record in a private space. New record types may be added in a
/// compatible release.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivateRecord {
    Post(Box<PrivatePost>),
    /// A repost, by its subject.
    Repost(StrongRef),
    /// A like, by its subject.
    Like(StrongRef),
    /// A threadgate, by its post.
    Threadgate(Target),
    /// A postgate, by its post.
    Postgate(Target),
    Rules(Rules),
    /// The owner's approval of one follower.
    Approval(Approval),
}

/// Validate a record synced from a private space, given its full URI.
///
/// `Ok(None)` for a collection that isn't one of the six or an approval
/// (the PDS's published policy, or another app's): the caller handles or
/// ignores it.
pub fn validate_private_record(
    uri: &SpaceRecordUri,
    value: &Map,
) -> Result<Option<PrivateRecord>, Invalid> {
    let space = uri.space();
    if space.space_type() != PRIVATE_SPACE_TYPE || space.skey() != SELF_RKEY {
        return Err(Invalid("not a tools.umbrae.private space"));
    }
    let collection = uri.collection();
    if collection == PRIVATE_APPROVAL {
        return approval(uri, value).map(|a| Some(PrivateRecord::Approval(a)));
    }
    if !PRIVATE_COLLECTIONS.contains(&collection) {
        return Ok(None);
    }
    match value.get("$type") {
        Some(Value::Text(t)) if t == collection => {}
        _ => return Err(Invalid("$type must match the collection")),
    }
    if names_other_space(&Value::Map(value.clone()), space) {
        return Err(Invalid(
            "a private record names records only in its own space",
        ));
    }
    let own = uri.author() == space.authority();
    if collection == PRIVATE_RULES {
        if !own || uri.rkey() != SELF_RKEY {
            return Err(Invalid("the rules are the owner's, at rkey self"));
        }
        return Ok(Some(PrivateRecord::Rules(rules(value)?)));
    }
    if !is_valid_tid(uri.rkey()) {
        return Err(Invalid("record key must be a TID"));
    }
    Ok(Some(match collection {
        BSKY_POST => {
            let p = post(value)?;
            let acts = p.reply.as_ref().is_some_and(|r| {
                owner_post(&r.root.target, space) && in_space(&r.parent.target, space)
            }) || p.quote.as_ref().is_some_and(|q| in_space(&q.target, space));
            if !own && !acts {
                return Err(Invalid(
                    "another account's post counts only as a reply or quote in the owner's thread",
                ));
            }
            PrivateRecord::Post(Box::new(p))
        }
        BSKY_LIKE | BSKY_REPOST => {
            let subject = strong_ref(value.get("subject"))?;
            if !own && !in_space(&subject.target, space) {
                return Err(Invalid(
                    "another account's like or repost counts only on a record in this space",
                ));
            }
            if collection == BSKY_LIKE {
                PrivateRecord::Like(subject)
            } else {
                PrivateRecord::Repost(subject)
            }
        }
        _ => {
            if !own && collection == BSKY_THREADGATE {
                return Err(Invalid("only the owner's threadgates count"));
            }
            let post = match value.get("post") {
                Some(Value::Text(t)) => Target::parse(t)?,
                _ => return Err(Invalid("a gate names its post")),
            };
            let at_its_post = match &post {
                Target::Hidden(u) => {
                    u.space() == space
                        && u.author() == uri.author()
                        && u.collection() == BSKY_POST
                        && u.rkey() == uri.rkey()
                }
                Target::Public(p) => {
                    own && p.did == uri.author()
                        && p.collection == BSKY_POST
                        && p.rkey == uri.rkey()
                }
            };
            if !at_its_post {
                return Err(Invalid("a gate is its author's, at its own post's key"));
            }
            if collection == BSKY_POSTGATE {
                PrivateRecord::Postgate(post)
            } else {
                PrivateRecord::Threadgate(post)
            }
        }
    }))
}

/// Whether `target` names a record in `space`: by its space URI, or by the
/// owner's public alias for one of the space's collections.
fn in_space(target: &Target, space: &SpaceRef) -> bool {
    match target {
        Target::Hidden(u) => u.space() == space,
        Target::Public(p) => {
            p.did == space.authority() && PRIVATE_COLLECTIONS.contains(&p.collection.as_str())
        }
    }
}

/// Whether `target` names one of the owner's posts, in either form.
fn owner_post(target: &Target, space: &SpaceRef) -> bool {
    match target {
        Target::Hidden(u) => {
            u.space() == space && u.author() == space.authority() && u.collection() == BSKY_POST
        }
        Target::Public(p) => p.did == space.authority() && p.collection == BSKY_POST,
    }
}

/// Whether any string in `v` names a space URI that isn't a record in
/// `space`, exactly. A space URI inside other text counts too.
fn names_other_space(v: &Value, space: &SpaceRef) -> bool {
    match v {
        Value::Text(t) => {
            contains_space_uri(t)
                && !(is_space_uri(t) && SpaceRecordUri::parse(t).is_ok_and(|u| u.space() == space))
        }
        Value::Array(a) => a.iter().any(|x| names_other_space(x, space)),
        Value::Map(m) => m.values().any(|x| names_other_space(x, space)),
        _ => false,
    }
}

fn post(m: &Map) -> Result<PrivatePost, Invalid> {
    let reply = match m.get("reply") {
        None => None,
        Some(Value::Map(r)) => Some(Reply {
            root: strong_ref(r.get("root"))?,
            parent: strong_ref(r.get("parent"))?,
        }),
        Some(_) => return Err(Invalid("reply must be an object")),
    };
    let quote = match m.get("embed") {
        Some(Value::Map(e)) => match e.get("$type") {
            Some(Value::Text(t)) if t == "app.bsky.embed.record" => {
                Some(strong_ref(e.get("record"))?)
            }
            Some(Value::Text(t)) if t == "app.bsky.embed.recordWithMedia" => {
                match e.get("record") {
                    Some(Value::Map(r)) => Some(strong_ref(r.get("record"))?),
                    _ => return Err(Invalid("recordWithMedia needs a record object")),
                }
            }
            _ => None,
        },
        _ => None,
    };
    Ok(PrivatePost { reply, quote })
}

fn approval(uri: &SpaceRecordUri, m: &Map) -> Result<Approval, Invalid> {
    let owner = uri.space().authority();
    if uri.author() != owner {
        return Err(Invalid("only the owner's approvals count"));
    }
    if !is_valid_tid(uri.rkey()) {
        return Err(Invalid("record key must be a TID"));
    }
    match m.get("$type") {
        Some(Value::Text(t)) if t == PRIVATE_APPROVAL => {}
        _ => return Err(Invalid("$type must match the collection")),
    }
    let subject = match m.get("subject") {
        Some(Value::Text(d)) if is_valid_did(d) => d.clone(),
        _ => return Err(Invalid("an approval's subject is a DID")),
    };
    if subject == owner {
        return Err(Invalid("the owner doesn't approve itself"));
    }
    Ok(Approval {
        subject,
        created_at: datetime(m, "createdAt")?,
    })
}

fn rules(m: &Map) -> Result<Rules, Invalid> {
    let Some(Value::Array(items)) = m.get("allow") else {
        return Err(Invalid("the rules list what they allow"));
    };
    let allow = items
        .iter()
        .filter_map(|item| {
            let Value::Map(r) = item else {
                return None;
            };
            match r.get("$type") {
                Some(Value::Text(t)) if t == PRIVATE_RULE_APPROVED_FOLLOWERS => {
                    Some(Rule::ApprovedFollowers)
                }
                Some(Value::Text(t)) if t == PRIVATE_RULE_FOLLOWING => Some(Rule::Following),
                Some(Value::Text(t)) if t == PRIVATE_RULE_MUTUALS => Some(Rule::Mutuals),
                Some(Value::Text(t)) if t == PRIVATE_RULE_LIST => match r.get("list") {
                    Some(Value::Text(l)) => PublicUri::parse(l).map(Rule::List),
                    _ => None,
                },
                _ => None,
            }
        })
        .collect();
    Ok(Rules {
        allow,
        created_at: datetime(m, "createdAt")?,
        updated_at: match m.get("updatedAt") {
            None => None,
            Some(Value::Text(t)) if is_datetime(t) => Some(t.clone()),
            Some(_) => return Err(Invalid("updatedAt must be an atproto datetime")),
        },
        approvals_in_space: match m.get("approvalsInSpace") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(Invalid("approvalsInSpace must be a boolean")),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SPACE_TYPE;
    use umbrae_core::cid::Cid;

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
    const P1: &str = "3mbpaaaaaaa22";
    const RKEY: &str = "3mbpaaaaaaa2e";
    const NOW: &str = "2026-11-27T12:00:00.000Z";

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn map(pairs: &[(&str, Value)]) -> Map {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    fn space(owner: &str) -> SpaceRef {
        SpaceRef::new(owner, PRIVATE_SPACE_TYPE, SELF_RKEY).unwrap()
    }

    fn at(author: &str, coll: &str, rkey: &str) -> SpaceRecordUri {
        space(ALICE).record(author, coll, rkey).unwrap()
    }

    fn sref(uri: &str) -> Value {
        Value::Map(map(&[
            ("uri", t(uri)),
            ("cid", t(&Cid::for_drisl(b"x").to_string())),
        ]))
    }

    /// Alice's post p1, in its space form and its public alias.
    fn p1_forms() -> [String; 2] {
        [
            at(ALICE, BSKY_POST, P1).to_string(),
            format!("at://{ALICE}/{BSKY_POST}/{P1}"),
        ]
    }

    fn post(extra: &[(&str, Value)]) -> Map {
        let mut m = map(&[
            ("$type", t(BSKY_POST)),
            ("text", t("hi")),
            ("createdAt", t(NOW)),
        ]);
        m.extend(extra.iter().map(|(k, v)| ((*k).to_owned(), v.clone())));
        m
    }

    fn reply(root: &str, parent: &str) -> Map {
        post(&[(
            "reply",
            Value::Map(map(&[("root", sref(root)), ("parent", sref(parent))])),
        )])
    }

    fn quote(target: &str) -> Map {
        post(&[(
            "embed",
            Value::Map(map(&[
                ("$type", t("app.bsky.embed.record")),
                ("record", sref(target)),
            ])),
        )])
    }

    fn subject(coll: &str, target: &str) -> Map {
        map(&[
            ("$type", t(coll)),
            ("subject", sref(target)),
            ("createdAt", t(NOW)),
        ])
    }

    fn check(
        author: &str,
        coll: &str,
        rkey: &str,
        m: &Map,
    ) -> Result<Option<PrivateRecord>, Invalid> {
        validate_private_record(&at(author, coll, rkey), m)
    }

    #[test]
    fn the_owners_records_name_public_records_and_this_space() {
        let carols = format!("at://{CAROL}/{BSKY_POST}/3mbpaaaaaaa25");
        // A top-level post, and moved likes and reposts of public posts.
        assert!(matches!(
            check(ALICE, BSKY_POST, P1, &post(&[])),
            Ok(Some(PrivateRecord::Post(_)))
        ));
        assert!(matches!(
            check(ALICE, BSKY_LIKE, RKEY, &subject(BSKY_LIKE, &carols)),
            Ok(Some(PrivateRecord::Like(s))) if matches!(s.target, Target::Public(_))
        ));
        assert!(matches!(
            check(ALICE, BSKY_REPOST, RKEY, &subject(BSKY_REPOST, &carols)),
            Ok(Some(PrivateRecord::Repost(_)))
        ));
        // A moved reply and quote of a public post, and both forms of p1.
        assert!(check(ALICE, BSKY_POST, RKEY, &reply(&carols, &carols)).is_ok());
        assert!(check(ALICE, BSKY_POST, RKEY, &quote(&carols)).is_ok());
        for p1 in p1_forms() {
            assert!(
                check(ALICE, BSKY_POST, RKEY, &reply(&p1, &p1)).is_ok(),
                "{p1}"
            );
            assert!(
                check(ALICE, BSKY_LIKE, RKEY, &subject(BSKY_LIKE, &p1)).is_ok(),
                "{p1}"
            );
        }
        // Not a TID; $type not matching; another collection is the caller's.
        assert!(check(ALICE, BSKY_POST, "self", &post(&[])).is_err());
        assert!(check(ALICE, BSKY_LIKE, RKEY, &post(&[])).is_err());
        assert_eq!(
            check(ALICE, "com.atproto.space.policy", "self", &map(&[])),
            Ok(None)
        );
    }

    #[test]
    fn anothers_records_count_only_on_the_owners_thread() {
        for p1 in p1_forms() {
            // Bob's reply, like, repost and quote, by either form.
            assert!(matches!(
                check(BOB, BSKY_POST, RKEY, &reply(&p1, &p1)),
                Ok(Some(PrivateRecord::Post(p))) if p.reply.is_some()
            ));
            assert!(check(BOB, BSKY_LIKE, RKEY, &subject(BSKY_LIKE, &p1)).is_ok());
            assert!(check(BOB, BSKY_REPOST, RKEY, &subject(BSKY_REPOST, &p1)).is_ok());
            assert!(check(BOB, BSKY_POST, RKEY, &quote(&p1)).is_ok());
        }
        // A reply under Carol's reply in the thread: root is Alice's post.
        let carols_reply = at(CAROL, BSKY_POST, "3mbpaaaaaaa2g").to_string();
        let [p1, alias] = p1_forms();
        assert!(check(BOB, BSKY_POST, RKEY, &reply(&p1, &carols_reply)).is_ok());
        assert!(check(BOB, BSKY_POST, RKEY, &reply(&alias, &carols_reply)).is_ok());
        // A thread rooted at Carol's post, or at a public post, doesn't count.
        assert!(check(BOB, BSKY_POST, RKEY, &reply(&carols_reply, &carols_reply)).is_err());
        let public = format!("at://{CAROL}/{BSKY_POST}/3mbpaaaaaaa25");
        assert!(check(BOB, BSKY_POST, RKEY, &reply(&public, &public)).is_err());
        // Bob's top-level post, and his like of a public post.
        assert!(check(BOB, BSKY_POST, RKEY, &post(&[])).is_err());
        assert!(check(BOB, BSKY_LIKE, RKEY, &subject(BSKY_LIKE, &public)).is_err());
        // Carol's public alias isn't a record here: only the owner's is.
        let carol_alias = format!("at://{CAROL}/{BSKY_POST}/3mbpaaaaaaa2g");
        assert!(check(BOB, BSKY_LIKE, RKEY, &subject(BSKY_LIKE, &carol_alias)).is_err());
        // The owner's follow isn't in the space's collections.
        let follow = format!("at://{ALICE}/app.bsky.graph.follow/{RKEY}");
        assert!(check(BOB, BSKY_LIKE, RKEY, &subject(BSKY_LIKE, &follow)).is_err());
    }

    #[test]
    fn other_spaces_dont_count() {
        let other_private = space(BOB).record(BOB, BSKY_POST, P1).unwrap().to_string();
        let group = SpaceRef::new(ALICE, SPACE_TYPE, "3mbbbbbbbbbb2")
            .unwrap()
            .record(ALICE, "tools.umbrae.post", P1)
            .unwrap()
            .to_string();
        for there in [&other_private, &group] {
            assert!(
                check(ALICE, BSKY_POST, RKEY, &reply(there, there)).is_err(),
                "{there}"
            );
            assert!(check(ALICE, BSKY_LIKE, RKEY, &subject(BSKY_LIKE, there)).is_err());
            assert!(check(BOB, BSKY_POST, RKEY, &quote(there)).is_err());
            // Pasted into text, too.
            let text = post(&[("text", t(&format!("see {there}")))]);
            assert!(check(ALICE, BSKY_POST, RKEY, &text).is_err());
        }
        // A reply in the owner's thread that also quotes another space.
        let [p1, _] = p1_forms();
        let mut both = reply(&p1, &p1);
        both.extend(
            quote(&other_private)
                .into_iter()
                .filter(|(k, _)| k == "embed"),
        );
        assert!(check(BOB, BSKY_POST, RKEY, &both).is_err());
        // Not a private space at all.
        let in_group = SpaceRef::new(ALICE, SPACE_TYPE, "self")
            .unwrap()
            .record(ALICE, BSKY_POST, P1)
            .unwrap();
        assert!(validate_private_record(&in_group, &post(&[])).is_err());
        let wrong_key = SpaceRef::new(ALICE, PRIVATE_SPACE_TYPE, "other")
            .unwrap()
            .record(ALICE, BSKY_POST, P1)
            .unwrap();
        assert!(validate_private_record(&wrong_key, &post(&[])).is_err());
    }

    #[test]
    fn gates_sit_at_their_posts_key() {
        let gate = |coll: &str, post: &str| {
            map(&[("$type", t(coll)), ("post", t(post)), ("createdAt", t(NOW))])
        };
        for p1 in p1_forms() {
            for coll in [BSKY_THREADGATE, BSKY_POSTGATE] {
                assert!(
                    check(ALICE, coll, P1, &gate(coll, &p1)).is_ok(),
                    "{coll} {p1}"
                );
                assert!(
                    check(ALICE, coll, RKEY, &gate(coll, &p1)).is_err(),
                    "{coll} {p1}"
                );
            }
        }
        // Bob's postgate on his own post here; never his threadgate, nor a
        // gate on Alice's post, nor by alias.
        let bobs = at(BOB, BSKY_POST, RKEY).to_string();
        assert!(matches!(
            check(BOB, BSKY_POSTGATE, RKEY, &gate(BSKY_POSTGATE, &bobs)),
            Ok(Some(PrivateRecord::Postgate(_)))
        ));
        assert!(check(BOB, BSKY_THREADGATE, RKEY, &gate(BSKY_THREADGATE, &bobs)).is_err());
        let [p1, _] = p1_forms();
        assert!(check(BOB, BSKY_POSTGATE, P1, &gate(BSKY_POSTGATE, &p1)).is_err());
        let bob_alias = format!("at://{BOB}/{BSKY_POST}/{RKEY}");
        assert!(check(BOB, BSKY_POSTGATE, RKEY, &gate(BSKY_POSTGATE, &bob_alias)).is_err());
    }

    #[test]
    fn rules_are_the_owners() {
        let list = format!("at://{ALICE}/app.bsky.graph.list/3mbpaaaaaaa2k");
        let rule = |ty: &str| Value::Map(map(&[("$type", t(ty))]));
        let r = map(&[
            ("$type", t(PRIVATE_RULES)),
            (
                "allow",
                Value::Array(vec![
                    rule(PRIVATE_RULE_APPROVED_FOLLOWERS),
                    rule(PRIVATE_RULE_FOLLOWING),
                    rule(PRIVATE_RULE_MUTUALS),
                    Value::Map(map(&[("$type", t(PRIVATE_RULE_LIST)), ("list", t(&list))])),
                    // Unknown, and malformed: dropped.
                    rule("tools.umbrae.private.rules#futureRule"),
                    Value::Map(map(&[("$type", t(PRIVATE_RULE_LIST)), ("list", t("nope"))])),
                    t("not an object"),
                ]),
            ),
            ("createdAt", t(NOW)),
        ]);
        let Ok(Some(PrivateRecord::Rules(parsed))) = check(ALICE, PRIVATE_RULES, SELF_RKEY, &r)
        else {
            panic!("rules should validate");
        };
        assert_eq!(
            parsed.allow,
            [
                Rule::ApprovedFollowers,
                Rule::Following,
                Rule::Mutuals,
                Rule::List(PublicUri::parse(&list).unwrap())
            ]
        );
        // By someone else, or not at self.
        assert!(check(BOB, PRIVATE_RULES, SELF_RKEY, &r).is_err());
        assert!(check(ALICE, PRIVATE_RULES, RKEY, &r).is_err());
        // allow and createdAt are required.
        let mut bare = r.clone();
        bare.remove("allow");
        assert!(check(ALICE, PRIVATE_RULES, SELF_RKEY, &bare).is_err());
        let mut undated = r.clone();
        undated.remove("createdAt");
        assert!(check(ALICE, PRIVATE_RULES, SELF_RKEY, &undated).is_err());
        // The migration marker: absent is false, a boolean is read, and
        // anything else refuses the record.
        assert!(!parsed.approvals_in_space);
        for (v, want) in [
            (Value::Bool(true), Some(true)),
            (Value::Bool(false), Some(false)),
            (t("yes"), None),
        ] {
            let mut marked = r.clone();
            marked.insert("approvalsInSpace".into(), v);
            let got = match check(ALICE, PRIVATE_RULES, SELF_RKEY, &marked) {
                Ok(Some(PrivateRecord::Rules(x))) => Some(x.approvals_in_space),
                _ => None,
            };
            assert_eq!(got, want);
        }
    }

    fn approval(subject: Value) -> Map {
        map(&[
            ("$type", t(PRIVATE_APPROVAL)),
            ("subject", subject),
            ("createdAt", t(NOW)),
        ])
    }

    #[test]
    fn approvals_are_the_owners_and_name_another_did() {
        let ok = approval(t(BOB));
        assert_eq!(
            check(ALICE, PRIVATE_APPROVAL, RKEY, &ok),
            Ok(Some(PrivateRecord::Approval(Approval {
                subject: BOB.into(),
                created_at: NOW.into()
            })))
        );
        // A did:web with a port is a fine subject; that's why the key is a
        // TID, not the DID.
        let web = "did:web:localhost%3A8080";
        assert!(check(ALICE, PRIVATE_APPROVAL, RKEY, &approval(t(web))).is_ok());
        // By anyone else, even naming someone else: it counts for nothing.
        assert!(check(BOB, PRIVATE_APPROVAL, RKEY, &approval(t(CAROL))).is_err());
        assert!(check(CAROL, PRIVATE_APPROVAL, RKEY, &ok).is_err());
        // The owner as subject; a subject that isn't a DID, or is missing.
        assert!(check(ALICE, PRIVATE_APPROVAL, RKEY, &approval(t(ALICE))).is_err());
        assert!(check(ALICE, PRIVATE_APPROVAL, RKEY, &approval(t("bob.test"))).is_err());
        let mut bare = ok.clone();
        bare.remove("subject");
        assert!(check(ALICE, PRIVATE_APPROVAL, RKEY, &bare).is_err());
        // Not a TID; no createdAt; the wrong $type.
        assert!(check(ALICE, PRIVATE_APPROVAL, "self", &ok).is_err());
        let mut undated = ok.clone();
        undated.remove("createdAt");
        assert!(check(ALICE, PRIVATE_APPROVAL, RKEY, &undated).is_err());
        let mut typed = ok.clone();
        typed.insert("$type".into(), t(PRIVATE_RULES));
        assert!(check(ALICE, PRIVATE_APPROVAL, RKEY, &typed).is_err());
        // No public alias names an approval: it isn't a record "in this
        // space" for a like.
        let alias = format!("at://{ALICE}/{PRIVATE_APPROVAL}/{RKEY}");
        assert!(check(BOB, BSKY_LIKE, RKEY, &subject(BSKY_LIKE, &alias)).is_err());
    }
}
