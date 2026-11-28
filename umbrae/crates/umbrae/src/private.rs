//! Private accounts: who sees a private account's records, which
//! interactions count, and what stays inside when the owner goes public.
//!
//! A private account keeps its posts, reposts, likes and their gates in its
//! private space ([`crate::space::private_space`]), with the rules that say
//! who may see them. The serving app is the space's only reader. It checks
//! the rules live, on every read, like a block, so a change applies to every
//! record at once:
//! - the owner sees everything;
//! - anyone else must pass **any** rule, have no block with the owner
//!   either way (blocks, and list blocks either one subscribes to), and be
//!   active;
//! - fail closed: an empty `allow` means the owner alone; an unknown rule
//!   type grants nothing; with no rules record, `#approvedFollowers` alone
//!   applies; an input the app can't answer right now grants nothing.
//!
//! Others' replies, likes, reposts and quotes of the owner's records sit in
//! the private space, in their own repos. They show only while their author
//! passes the rules too ([`interaction_counts`]). The PDS keeps listing an
//! author who lost access as a writer, and the app's credential still reads
//! their repo, so the app filters.
//!
//! The serving app's moderators see private content through its moderation
//! paths, whatever the rules say. They don't pass the rules: no
//! `checkAccess` write, and they're never shown as followers.
//!
//! Takedowns and labels here follow the rules for spaces in general
//! ([`crate::labeler`]): the owner's `!takedown` on a record in this space
//! hides it where the serving app's spaces configuration honors it for this
//! type (on by default; [`crate::labeler::apply_takedowns`]). An in-space
//! label counts only from an account the app lists in `label_writers` (the
//! writer set minus the owner), where the reader trusts it as a labeler.
//!
//! Approved followers are the owner's approvals in the private space
//! ([`approved_followers`]), which the app syncs with its own attestation,
//! so a change reaches it while the owner is offline. Only the owner and the
//! app read them, and the app never serves them, or the rules, to viewers.
//!
//! Going public moves the owner's records back, except those that must
//! stay: the rules and approvals, every record by another account, and any owner's record that
//! names, even through another, a record that stays ([`stays_private`]).
//! What goes public has its own `at:space` references rewritten to the
//! public form ([`going_public_value`]).

use crate::access::{Tri, ViewContext};
use crate::placement::leaks_hidden;
use std::collections::{BTreeMap, BTreeSet};
use umbrae_core::drisl::Value;
use umbrae_core::uri::{contains_space_uri, SpaceRecordUri, SpaceRef};
use umbrae_lexicons::{
    validate_private_record, PrivateRecord, PublicUri, Rule, Rules, Target, BSKY_LIST,
    PRIVATE_APPROVAL, PRIVATE_COLLECTIONS, PRIVATE_RULES, PRIVATE_SPACE_TYPE, SELF_RKEY,
};

type Map = BTreeMap<String, Value>;

/// What the serving app knows for the rules. Each answer is `Unknown` when
/// the app can't say right now, and then it grants nothing.
pub trait PrivateInputs {
    /// Whether `owner` approved `viewer`: at least one of the owner's
    /// approvals in its private space names them ([`approved_followers`]),
    /// from the app's current sync of the space, made with its own
    /// attestation. `Unknown` without a current state.
    fn approved_follower(&self, owner: &str, viewer: &str) -> Tri;
    /// Whether `a` follows `b` publicly (`app.bsky.graph.follow`).
    fn follows(&self, a: &str, b: &str) -> Tri;
    /// Whether `did` is on the public list `list`.
    fn on_list(&self, list: &PublicUri, did: &str) -> Tri;
    /// Whether either account subscribes to a block list
    /// (`app.bsky.graph.listblock`) that has the other on it.
    fn list_blocked(&self, a: &str, b: &str) -> Tri;
}

/// Whether `viewer` may see `owner`'s private records. `rules` is the
/// owner's rules record, `None` when there's none. A record that fails
/// validation shows to the owner alone: pass `Some(&Rules::default())`.
pub fn can_view_private(
    viewer: Option<&str>,
    owner: &str,
    rules: Option<&Rules>,
    inputs: &impl PrivateInputs,
    ctx: &impl ViewContext,
) -> bool {
    let Some(viewer) = viewer else {
        return false;
    };
    if viewer == owner {
        return true;
    }
    if ctx.is_active(viewer) != Tri::Yes
        || ctx.blocked(viewer, owner) != Tri::No
        || inputs.list_blocked(viewer, owner) != Tri::No
    {
        return false;
    }
    let default = [Rule::ApprovedFollowers];
    let allow = rules.map_or(&default[..], |r| &r.allow[..]);
    allow.iter().any(|rule| passes(rule, viewer, owner, inputs))
}

fn passes(rule: &Rule, viewer: &str, owner: &str, inputs: &impl PrivateInputs) -> bool {
    let yes = |t: Tri| t == Tri::Yes;
    match rule {
        Rule::ApprovedFollowers => yes(inputs.approved_follower(owner, viewer)),
        Rule::Following => yes(inputs.follows(owner, viewer)),
        Rule::Mutuals => yes(inputs.follows(owner, viewer)) && yes(inputs.follows(viewer, owner)),
        Rule::List(list) => {
            list.did == owner && list.collection == BSKY_LIST && yes(inputs.on_list(list, viewer))
        }
        _ => false,
    }
}

/// Whether a record in a private space, which passed
/// `validate_private_record`, shows now: the owner's always, another
/// account's only while its author passes the owner's rules. Viewers must
/// pass the rules too ([`can_view_private`]).
pub fn interaction_counts(
    uri: &SpaceRecordUri,
    rules: Option<&Rules>,
    inputs: &impl PrivateInputs,
    ctx: &impl ViewContext,
) -> bool {
    let space = uri.space();
    if space.space_type() != PRIVATE_SPACE_TYPE || space.skey() != SELF_RKEY {
        return false;
    }
    let owner = space.authority();
    uri.author() == owner || can_view_private(Some(uri.author()), owner, rules, inputs, ctx)
}

/// The owner's approved followers: the subjects of the owner's valid
/// `tools.umbrae.private.approval` records in private space `space`.
/// Another author's approvals, which a tracked writer can put there, count
/// for nothing; so do invalid ones and records of any other space. Several
/// approvals of one account are harmless: it stays approved until the last
/// is deleted.
pub fn approved_followers<'a>(
    space: &SpaceRef,
    records: impl IntoIterator<Item = (&'a SpaceRecordUri, &'a Map)>,
) -> BTreeSet<String> {
    records
        .into_iter()
        .filter(|(uri, _)| uri.space() == space && uri.collection() == PRIVATE_APPROVAL)
        .filter_map(|(uri, value)| match validate_private_record(uri, value) {
            Ok(Some(PrivateRecord::Approval(a))) => Some(a.subject),
            _ => None,
        })
        .collect()
}

/// The records of private space `space` that stay in it when the owner goes
/// public: the rules (and anything else outside the native collections,
/// such as the PDS's policy record), every record by another account, and
/// every owner's record that names a record that stays, applied until
/// nothing more changes. A
/// reference names a record in the space by its `at:space` URI or, for the
/// owner's, its public alias. An owner's record naming any other space URI
/// stays too. The client computes this before moving anything; the owner's
/// records not in the set go public.
pub fn stays_private<'a>(
    space: &SpaceRef,
    records: impl IntoIterator<Item = (&'a SpaceRecordUri, &'a Map)>,
) -> BTreeSet<SpaceRecordUri> {
    let owner = space.authority();
    let mut stay = BTreeSet::new();
    let mut own = Vec::new();
    for (uri, value) in records {
        if uri.space() != space {
            continue;
        }
        let native =
            PRIVATE_COLLECTIONS.contains(&uri.collection()) && uri.collection() != PRIVATE_RULES;
        if uri.author() != owner || !native {
            stay.insert(uri.clone());
            continue;
        }
        let mut refs = Vec::new();
        let mut foreign = false;
        references(&Value::Map(value.clone()), space, &mut refs, &mut foreign);
        if foreign {
            stay.insert(uri.clone());
        } else {
            own.push((uri, refs));
        }
    }
    loop {
        let before = stay.len();
        for (uri, refs) in &own {
            if !stay.contains(*uri) && refs.iter().any(|r| r.author() != owner || stay.contains(r))
            {
                stay.insert((*uri).clone());
            }
        }
        if stay.len() == before {
            return stay;
        }
    }
}

/// Collect the records in `space` that `v` names, mapping the owner's
/// public aliases to the space form. `foreign` is set for a space URI that
/// isn't a record of `space`.
fn references(v: &Value, space: &SpaceRef, out: &mut Vec<SpaceRecordUri>, foreign: &mut bool) {
    match v {
        Value::Text(t) => match Target::parse(t) {
            Ok(Target::Hidden(u)) if u.space() == space => out.push(u),
            Ok(Target::Public(p)) if p.did == space.authority() => {
                if let Ok(u) = space.record(&p.did, &p.collection, &p.rkey) {
                    out.push(u);
                }
            }
            _ if contains_space_uri(t) => *foreign = true,
            _ => {}
        },
        Value::Array(a) => a.iter().for_each(|x| references(x, space, out, foreign)),
        Value::Map(m) => m.values().for_each(|x| references(x, space, out, foreign)),
        _ => {}
    }
}

/// The value an owner's record takes when it goes public from private
/// space `space`: each `at:space` URI of the owner's own records there is
/// rewritten to its public form. CIDs stay, since readers match the owner's
/// records by URI. `None` if the result would still name a hidden record:
/// that record stays ([`stays_private`]).
pub fn going_public_value(space: &SpaceRef, value: &Map) -> Option<Map> {
    let out: Map = value
        .iter()
        .map(|(k, v)| (k.clone(), rewrite(v, space)))
        .collect();
    (!leaks_hidden(&Value::Map(out.clone()))).then_some(out)
}

fn rewrite(v: &Value, space: &SpaceRef) -> Value {
    match v {
        Value::Text(t) => match Target::parse(t) {
            Ok(Target::Hidden(u)) if u.space() == space && u.author() == space.authority() => {
                Value::Text(format!(
                    "at://{}/{}/{}",
                    u.author(),
                    u.collection(),
                    u.rkey()
                ))
            }
            _ => v.clone(),
        },
        Value::Array(a) => Value::Array(a.iter().map(|x| rewrite(x, space)).collect()),
        Value::Map(m) => Value::Map(
            m.iter()
                .map(|(k, x)| (k.clone(), rewrite(x, space)))
                .collect(),
        ),
        _ => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::{private_space, public_uri};
    use umbrae_core::cid::Cid;
    use umbrae_core::scope::SpacePermission;
    use umbrae_lexicons::{BSKY_LIKE, BSKY_POST};

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
    const DAN: &str = "did:plc:danddddddddddddddddddddd";
    const NOW: &str = "2026-11-27T12:00:00.000Z";

    /// Answers from fixed tables; anything listed in `unknown` is
    /// `Unknown`.
    #[derive(Default)]
    struct Inputs {
        followers: Vec<&'static str>,
        follows: Vec<(&'static str, &'static str)>,
        lists: Vec<(String, &'static str)>,
        list_blocks: Vec<(&'static str, &'static str)>,
        /// Accounts whose follower, follow and list answers are unknown.
        unknown: Vec<&'static str>,
        /// Accounts whose list blocks are unknown.
        unknown_blocks: Vec<&'static str>,
    }
    impl Inputs {
        fn tri(&self, who: &str, hit: bool) -> Tri {
            if self.unknown.contains(&who) {
                Tri::Unknown
            } else if hit {
                Tri::Yes
            } else {
                Tri::No
            }
        }
    }
    impl PrivateInputs for Inputs {
        fn approved_follower(&self, owner: &str, viewer: &str) -> Tri {
            self.tri(viewer, owner == ALICE && self.followers.contains(&viewer))
        }
        fn follows(&self, a: &str, b: &str) -> Tri {
            let hit = self.follows.iter().any(|&(x, y)| (x, y) == (a, b));
            self.tri(if a == ALICE { b } else { a }, hit)
        }
        fn on_list(&self, list: &PublicUri, did: &str) -> Tri {
            let hit = self
                .lists
                .iter()
                .any(|(l, d)| *l == list.to_string() && *d == did);
            self.tri(did, hit)
        }
        fn list_blocked(&self, a: &str, b: &str) -> Tri {
            let hit = self
                .list_blocks
                .iter()
                .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a));
            if self.unknown_blocks.contains(&a) {
                Tri::Unknown
            } else if hit {
                Tri::Yes
            } else {
                Tri::No
            }
        }
    }

    struct Ctx {
        blocked: Vec<(&'static str, &'static str)>,
        inactive: Vec<&'static str>,
    }
    impl ViewContext for Ctx {
        fn is_active(&self, did: &str) -> Tri {
            if self.inactive.contains(&did) {
                Tri::No
            } else {
                Tri::Yes
            }
        }
        fn blocked(&self, a: &str, b: &str) -> Tri {
            let hit = self
                .blocked
                .iter()
                .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a));
            if hit {
                Tri::Yes
            } else {
                Tri::No
            }
        }
    }
    const OK: Ctx = Ctx {
        blocked: Vec::new(),
        inactive: Vec::new(),
    };

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn map(pairs: &[(&str, Value)]) -> Map {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    fn rules(allow: Vec<Rule>) -> Rules {
        let mut r = Rules::default();
        r.allow = allow;
        r
    }

    fn alices_list() -> PublicUri {
        PublicUri::parse(&format!("at://{ALICE}/app.bsky.graph.list/3mbpaaaaaaa2k")).unwrap()
    }

    fn sees(viewer: &str, r: Option<&Rules>, inputs: &Inputs, ctx: &Ctx) -> bool {
        can_view_private(Some(viewer), ALICE, r, inputs, ctx)
    }

    #[test]
    fn each_rule_admits_its_own() {
        let inputs = Inputs {
            followers: vec![BOB],
            follows: vec![(ALICE, CAROL), (ALICE, DAN), (DAN, ALICE)],
            lists: vec![(alices_list().to_string(), BOB)],
            ..Inputs::default()
        };
        let only = |rule: Rule| rules(vec![rule]);
        let followers = only(Rule::ApprovedFollowers);
        assert!(sees(BOB, Some(&followers), &inputs, &OK));
        assert!(!sees(CAROL, Some(&followers), &inputs, &OK));
        // Following: Carol and Dan, whom Alice follows.
        let following = only(Rule::Following);
        assert!(sees(CAROL, Some(&following), &inputs, &OK));
        assert!(sees(DAN, Some(&following), &inputs, &OK));
        assert!(!sees(BOB, Some(&following), &inputs, &OK));
        // Mutuals: only Dan follows back.
        let mutuals = only(Rule::Mutuals);
        assert!(sees(DAN, Some(&mutuals), &inputs, &OK));
        assert!(!sees(CAROL, Some(&mutuals), &inputs, &OK));
        // A list of Alice's.
        let list = only(Rule::List(alices_list()));
        assert!(sees(BOB, Some(&list), &inputs, &OK));
        assert!(!sees(CAROL, Some(&list), &inputs, &OK));
        // Any rule admits.
        let either = rules(vec![Rule::ApprovedFollowers, Rule::Mutuals]);
        assert!(sees(BOB, Some(&either), &inputs, &OK));
        assert!(sees(DAN, Some(&either), &inputs, &OK));
        assert!(!sees(CAROL, Some(&either), &inputs, &OK));
        // Nobody signed out; the owner always.
        assert!(!can_view_private(None, ALICE, Some(&either), &inputs, &OK));
        assert!(sees(ALICE, Some(&rules(vec![])), &inputs, &OK));
    }

    #[test]
    fn a_list_that_isnt_the_owners_grants_nothing() {
        let bobs =
            PublicUri::parse(&format!("at://{BOB}/app.bsky.graph.list/3mbpaaaaaaa2k")).unwrap();
        let not_a_list =
            PublicUri::parse(&format!("at://{ALICE}/app.bsky.graph.follow/3mbpaaaaaaa2k")).unwrap();
        for list in [bobs, not_a_list] {
            let inputs = Inputs {
                lists: vec![(list.to_string(), CAROL)],
                ..Inputs::default()
            };
            assert!(
                !sees(
                    CAROL,
                    Some(&rules(vec![Rule::List(list.clone())])),
                    &inputs,
                    &OK
                ),
                "{list}"
            );
        }
    }

    #[test]
    fn blocks_list_blocks_and_inactive_accounts() {
        let inputs = Inputs {
            followers: vec![BOB, CAROL, DAN],
            list_blocks: vec![(CAROL, ALICE)],
            ..Inputs::default()
        };
        let r = rules(vec![Rule::ApprovedFollowers]);
        let ctx = Ctx {
            blocked: vec![(ALICE, BOB)],
            inactive: vec![DAN],
        };
        assert!(!sees(BOB, Some(&r), &inputs, &ctx), "a block");
        assert!(!sees(CAROL, Some(&r), &inputs, &ctx), "a list block");
        assert!(!sees(DAN, Some(&r), &inputs, &ctx), "inactive");
        assert!(sees(BOB, Some(&r), &inputs, &OK));
        // The other way round: Alice subscribes to a list blocking Bob.
        let theirs = Inputs {
            followers: vec![BOB],
            list_blocks: vec![(ALICE, BOB)],
            ..Inputs::default()
        };
        assert!(!sees(BOB, Some(&r), &theirs, &OK));
    }

    #[test]
    fn rules_fail_closed() {
        let inputs = Inputs {
            followers: vec![BOB],
            follows: vec![(ALICE, CAROL)],
            ..Inputs::default()
        };
        // Empty: the owner alone.
        let empty = rules(vec![]);
        assert!(!sees(BOB, Some(&empty), &inputs, &OK));
        assert!(sees(ALICE, Some(&empty), &inputs, &OK));
        // A record that failed validation, passed as the default.
        assert!(!sees(BOB, Some(&Rules::default()), &inputs, &OK));
        // No record: approved followers alone.
        assert!(sees(BOB, None, &inputs, &OK));
        assert!(!sees(CAROL, None, &inputs, &OK));
        // An unknown rule type is dropped when read, so it grants nothing.
        let r = map(&[
            ("$type", t("tools.umbrae.private.rules")),
            (
                "allow",
                Value::Array(vec![Value::Map(map(&[(
                    "$type",
                    t("tools.umbrae.private.rules#futureRule"),
                )]))]),
            ),
            ("createdAt", t(NOW)),
        ]);
        let uri = private_space(ALICE)
            .unwrap()
            .record(ALICE, "tools.umbrae.private.rules", "self")
            .unwrap();
        let Ok(Some(PrivateRecord::Rules(unknown))) = validate_private_record(&uri, &r) else {
            panic!("rules should validate");
        };
        assert!(unknown.allow.is_empty());
        assert!(!sees(BOB, Some(&unknown), &inputs, &OK));
        // An input the app can't answer grants nothing: Bob's follower
        // state, and Carol's follow, unknown.
        let unsure = Inputs {
            unknown: vec![BOB, CAROL],
            ..inputs
        };
        assert!(!sees(BOB, None, &unsure, &OK));
        assert!(!sees(
            CAROL,
            Some(&rules(vec![Rule::Following])),
            &unsure,
            &OK
        ));
        // An unknown list block denies, even for an approved follower.
        let mut blocks_unknown = Inputs {
            followers: vec![DAN],
            ..Inputs::default()
        };
        assert!(sees(DAN, None, &blocks_unknown, &OK));
        blocks_unknown.unknown_blocks.push(DAN);
        assert!(!sees(DAN, None, &blocks_unknown, &OK));
    }

    #[test]
    fn interactions_count_while_their_author_passes() {
        let space = private_space(ALICE).unwrap();
        let bobs = space.record(BOB, BSKY_POST, "3mbpaaaaaaa2e").unwrap();
        let alices = space.record(ALICE, BSKY_POST, "3mbpaaaaaaa22").unwrap();
        let mut inputs = Inputs {
            followers: vec![BOB],
            ..Inputs::default()
        };
        assert!(interaction_counts(&bobs, None, &inputs, &OK));
        assert!(interaction_counts(&alices, None, &inputs, &OK));
        // Bob loses access: his reply hides, Alice's stays.
        inputs.followers.clear();
        assert!(!interaction_counts(&bobs, None, &inputs, &OK));
        assert!(interaction_counts(&alices, None, &inputs, &OK));
        // Not a private space.
        let group = crate::space::group_space(ALICE, "3mbbbbbbbbbb2")
            .unwrap()
            .record(ALICE, BSKY_POST, "3mbpaaaaaaa22")
            .unwrap();
        assert!(!interaction_counts(&group, None, &inputs, &OK));
    }

    fn sref(uri: &str) -> Value {
        Value::Map(map(&[
            ("uri", t(uri)),
            ("cid", t(&Cid::for_drisl(b"x").to_string())),
        ]))
    }

    fn reply_to(parent: &str, root: &str) -> Map {
        map(&[
            ("$type", t(BSKY_POST)),
            ("text", t("hi")),
            (
                "reply",
                Value::Map(map(&[("root", sref(root)), ("parent", sref(parent))])),
            ),
            ("createdAt", t(NOW)),
        ])
    }

    #[test]
    fn what_stays_is_a_fixpoint() {
        let space = private_space(ALICE).unwrap();
        let at = |author: &str, coll: &str, rkey: &str| space.record(author, coll, rkey).unwrap();
        let p1 = at(ALICE, BSKY_POST, "3mbpaaaaaaa22");
        let p1_alias = format!("at://{ALICE}/{BSKY_POST}/3mbpaaaaaaa22");
        // Bob's reply in Alice's thread; Alice's reply to it (names Bob's
        // in-boundary record); Alice's reply to that, by alias (a chain
        // through an owner's record that stays); Alice's like of it.
        let bobs = at(BOB, BSKY_POST, "3mbpaaaaaaa2e");
        let a1 = at(ALICE, BSKY_POST, "3mbpaaaaaaa2f");
        let a2 = at(ALICE, BSKY_POST, "3mbpaaaaaaa2g");
        let like = at(ALICE, BSKY_LIKE, "3mbpaaaaaaa2h");
        // Alice's own reply to p1, and a like of a public post: they go.
        let own_reply = at(ALICE, BSKY_POST, "3mbpaaaaaaa2i");
        let public_like = at(ALICE, BSKY_LIKE, "3mbpaaaaaaa2j");
        let carol_public = format!("at://{CAROL}/{BSKY_POST}/3mbpaaaaaaa25");
        let a2_alias = format!("at://{ALICE}/{BSKY_POST}/3mbpaaaaaaa2g");
        let p1_value = map(&[
            ("$type", t(BSKY_POST)),
            ("text", t("hi")),
            ("createdAt", t(NOW)),
        ]);
        let rules = at(ALICE, PRIVATE_RULES, SELF_RKEY);
        let rules_value = map(&[
            ("$type", t(PRIVATE_RULES)),
            ("allow", Value::Array(vec![])),
            ("createdAt", t(NOW)),
        ]);
        let policy = at(ALICE, "com.atproto.space.policy", SELF_RKEY);
        let records = [
            (policy.clone(), map(&[])),
            (rules.clone(), rules_value),
            (p1.clone(), p1_value),
            (bobs.clone(), reply_to(&p1.to_string(), &p1_alias)),
            (a1.clone(), reply_to(&bobs.to_string(), &p1.to_string())),
            (
                a2.clone(),
                reply_to(
                    &format!("at://{ALICE}/{BSKY_POST}/3mbpaaaaaaa2f"),
                    &p1_alias,
                ),
            ),
            (
                like.clone(),
                map(&[
                    ("$type", t(BSKY_LIKE)),
                    ("subject", sref(&a2_alias)),
                    ("createdAt", t(NOW)),
                ]),
            ),
            (
                own_reply.clone(),
                reply_to(&p1.to_string(), &p1.to_string()),
            ),
            (
                public_like.clone(),
                map(&[
                    ("$type", t(BSKY_LIKE)),
                    ("subject", sref(&carol_public)),
                    ("createdAt", t(NOW)),
                ]),
            ),
        ];
        // The order they're given in doesn't matter.
        for order in [records.to_vec(), records.iter().rev().cloned().collect()] {
            let stay = stays_private(&space, order.iter().map(|(u, v)| (u, v)));
            assert_eq!(
                stay,
                BTreeSet::from([
                    policy.clone(),
                    rules.clone(),
                    bobs.clone(),
                    a1.clone(),
                    a2.clone(),
                    like.clone()
                ])
            );
        }
        // Naming a record by another account that the client doesn't hold
        // (deleted, say) still stays; so does naming another space.
        let gone = at(DAN, BSKY_POST, "3mbpaaaaaaa2k").to_string();
        let elsewhere = private_space(BOB)
            .unwrap()
            .record(BOB, BSKY_POST, "3mbpaaaaaaa2k")
            .unwrap()
            .to_string();
        for target in [gone, elsewhere] {
            let r = [(own_reply.clone(), reply_to(&target, &p1.to_string()))];
            let stay = stays_private(&space, r.iter().map(|(u, v)| (u, v)));
            assert!(stay.contains(&own_reply), "{target}");
        }
    }

    fn approval_of(subject: &str) -> Map {
        map(&[
            ("$type", t(PRIVATE_APPROVAL)),
            ("subject", t(subject)),
            ("createdAt", t(NOW)),
        ])
    }

    #[test]
    fn approved_followers_are_the_owners_approvals() {
        let space = private_space(ALICE).unwrap();
        let at = |author: &str, rkey: &str| space.record(author, PRIVATE_APPROVAL, rkey).unwrap();
        // Bob twice, Carol once; Bob (a writer) approving Dan; Alice
        // "approving" herself; a malformed one; Dan approved in Bob's space.
        let bobs_space = private_space(BOB).unwrap();
        let in_bobs = bobs_space
            .record(BOB, PRIVATE_APPROVAL, "3mbqaaaaaaa2a")
            .unwrap();
        let mut records = vec![
            (at(ALICE, "3mbqaaaaaaa22"), approval_of(BOB)),
            (at(ALICE, "3mbqaaaaaaa23"), approval_of(BOB)),
            (at(ALICE, "3mbqaaaaaaa24"), approval_of(CAROL)),
            (at(BOB, "3mbqaaaaaaa25"), approval_of(DAN)),
            (at(ALICE, "3mbqaaaaaaa26"), approval_of(ALICE)),
            (at(ALICE, "3mbqaaaaaaa27"), approval_of("not a did")),
            (in_bobs, approval_of(DAN)),
            (
                space.record(ALICE, BSKY_POST, "3mbqaaaaaaa28").unwrap(),
                map(&[
                    ("$type", t(BSKY_POST)),
                    ("text", t("hi")),
                    ("createdAt", t(NOW)),
                ]),
            ),
        ];
        let set = |rs: &[(SpaceRecordUri, Map)]| {
            approved_followers(&space, rs.iter().map(|(u, v)| (u, v)))
        };
        assert_eq!(set(&records), BTreeSet::from([BOB.into(), CAROL.into()]));
        // Bob stays approved until his last approval goes.
        records.remove(0);
        assert!(set(&records).contains(BOB));
        records.remove(0);
        assert_eq!(set(&records), BTreeSet::from([CAROL.into()]));
        // Approvals stay inside when the owner goes public.
        let stay = stays_private(&space, records.iter().map(|(u, v)| (u, v)));
        assert!(stay.contains(&at(ALICE, "3mbqaaaaaaa24")));
        assert!(!stay.contains(&space.record(ALICE, BSKY_POST, "3mbqaaaaaaa28").unwrap()));
    }

    #[test]
    fn going_public_rewrites_the_owners_references() {
        let space = private_space(ALICE).unwrap();
        let p1 = space.record(ALICE, BSKY_POST, "3mbpaaaaaaa22").unwrap();
        let reply = reply_to(&p1.to_string(), &p1.to_string());
        let out = going_public_value(&space, &reply).unwrap();
        let public = public_uri(&p1).unwrap().to_string();
        assert_eq!(out, reply_to(&public, &public));
        assert!(!leaks_hidden(&Value::Map(out)));
        // Already public references are left as they are.
        let carol = format!("at://{CAROL}/{BSKY_POST}/3mbpaaaaaaa25");
        let plain = reply_to(&carol, &carol);
        assert_eq!(going_public_value(&space, &plain), Some(plain));
        // A reference to another account's record in the space can't go
        // public: that record stays, and so does this one.
        let bobs = space.record(BOB, BSKY_POST, "3mbpaaaaaaa2e").unwrap();
        assert_eq!(
            going_public_value(&space, &reply_to(&bobs.to_string(), &p1.to_string())),
            None
        );
    }

    #[test]
    fn the_scopes_parse() {
        let owner = "space:tools.umbrae.private?collection=app.bsky.feed.post&collection=app.bsky.feed.repost&collection=app.bsky.feed.like&collection=app.bsky.feed.threadgate&collection=app.bsky.feed.postgate&collection=tools.umbrae.private.rules&collection=tools.umbrae.private.approval&manage=create&manage=update&manage=delete";
        let others = "space:tools.umbrae.private?authority=*&collection=app.bsky.feed.post&collection=app.bsky.feed.repost&collection=app.bsky.feed.like&collection=app.bsky.feed.postgate";
        for s in [owner, others] {
            assert!(SpacePermission::parse(s).is_some(), "{s}");
        }
        // Only the owner's scope writes approvals.
        let writes_approvals = |s: &str| {
            SpacePermission::parse(s)
                .and_then(|p| p.collection)
                .is_some_and(|c| {
                    c.iter()
                        .any(|x| matches!(x, umbrae_core::scope::Pattern::Is(n) if n == PRIVATE_APPROVAL))
                })
        };
        assert!(writes_approvals(owner));
        assert!(!writes_approvals(others));
    }
}
