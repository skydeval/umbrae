//! Who may see what. The spec leaves this to the serving app ("Access
//! control in applications"): a syncer's credential lets it read the whole
//! space, and it decides per viewer what to show.
//!
//! - **The author** (the space authority) sees everything in their spaces.
//! - **A group** is visible to members with `read`, from the member list the
//!   PDS publishes into the authority's repo. That list is shown only to
//!   people who can see the space.
//! - **A community or everyone space** (a managedspace) is visible to the
//!   accounts its managing app says may read. The reader fills `members`
//!   from that app (or is that app): nothing is published in the space.
//! - **Only me** is visible to the author alone.
//! - **A record** shows only if its author is the authority or a member
//!   with `write` (a removed member's records drop out), and its author is
//!   active.
//! - **Always:** a block between viewer and authority or record author
//!   hides it; an inactive authority hides the whole space; a deleted space
//!   shows nothing; nobody signed out sees anything.
//! - **Fail closed:** `Unknown` from the consumer's oracles denies.
//!
//! A reader can't tell unreadable from missing: callers omit denied records
//! from lists and answer not-found for a single fetch.

use crate::space::{check_policy, is_only_me};
use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::policy::{
    record_key_to_did, MemberAccess, Policy, MEMBER_RECORD, POLICY_RECORD, POLICY_RECORD_RKEY,
};
use umbrae_core::uri::{SpaceRecordUri, SpaceRef};

type Map = BTreeMap<String, Value>;

/// An answer the consumer may not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    Yes,
    No,
    Unknown,
}

/// What the consumer knows about accounts and the social graph.
pub trait ViewContext {
    /// Whether the account is active (not deactivated, taken down or deleted).
    fn is_active(&self, did: &str) -> Tri;
    /// Whether either account blocks the other.
    fn blocked(&self, a: &str, b: &str) -> Tri;
}

/// A space's members: a group's, as published into the space, or a managed
/// space's, as its managing app answers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Members(BTreeMap<String, MemberAccess>);

impl Members {
    pub fn get(&self, did: &str) -> Option<MemberAccess> {
        self.0.get(did).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, MemberAccess)> {
        self.0.iter().map(|(d, a)| (d.as_str(), *a))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, did: &str, access: MemberAccess) {
        self.0.insert(did.to_owned(), access);
    }
}

/// What a reader holds for one space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceState {
    pub space: SpaceRef,
    /// `None` until the policy is known; then only the authority sees it.
    pub policy: Option<Policy>,
    pub members: Members,
    pub deleted: bool,
}

impl SpaceState {
    pub fn new(space: SpaceRef, policy: Option<Policy>) -> Self {
        Self {
            space,
            policy,
            members: Members::default(),
            deleted: false,
        }
    }

    /// Build the state from the records in the **authority's** repo in the
    /// space: the published policy (`com.atproto.space.policy`, rkey
    /// `self`) and member records (`com.atproto.memberspace.member`, rkey
    /// the member's DID). Other records are ignored, and so is a malformed
    /// entry, which leaves that DID out (fail closed).
    pub fn from_authority_records<'a>(
        space: SpaceRef,
        records: impl IntoIterator<Item = (&'a str, &'a str, &'a Map)>,
    ) -> Self {
        let mut state = Self::new(space, None);
        for (collection, rkey, value) in records {
            if collection == POLICY_RECORD && rkey == POLICY_RECORD_RKEY {
                state.policy = match value.get("policy") {
                    Some(Value::Map(p)) => Policy::from_map(p).ok(),
                    _ => None,
                };
            } else if collection == MEMBER_RECORD {
                if let Ok(a) = MemberAccess::from_record(value) {
                    state.members.insert(&record_key_to_did(rkey), a);
                }
            }
        }
        state
    }

    fn authority(&self) -> &str {
        self.space.authority()
    }

    fn member(&self, did: &str) -> MemberAccess {
        let none = MemberAccess {
            read: false,
            write: false,
        };
        match &self.policy {
            Some(Policy::Member(_) | Policy::Managed(_)) => self.members.get(did).unwrap_or(none),
            _ => none,
        }
    }
}

/// Whether `viewer` may see the space at all.
pub fn can_view_space(viewer: Option<&str>, state: &SpaceState, ctx: &impl ViewContext) -> bool {
    let Some(viewer) = viewer else {
        return false;
    };
    let Some(policy) = &state.policy else {
        return false;
    };
    if state.deleted || ctx.is_active(state.authority()) != Tri::Yes {
        return false;
    }
    if viewer == state.authority() {
        return true;
    }
    check_policy(&state.space, policy).is_ok()
        && state.member(viewer).read
        && ctx.is_active(viewer) == Tri::Yes
        && ctx.blocked(viewer, state.authority()) == Tri::No
}

/// The member list, for someone who can see the space; `None` otherwise.
pub fn visible_members<'a>(
    viewer: Option<&str>,
    state: &'a SpaceState,
    ctx: &impl ViewContext,
) -> Option<&'a Members> {
    can_view_space(viewer, state, ctx).then_some(&state.members)
}

/// Whether a record's author counts as a writer in the space.
pub fn is_writer(author: &str, state: &SpaceState) -> bool {
    author == state.authority() || state.member(author).write
}

/// Whether `viewer` may see one record of the space.
pub fn can_view_record(
    viewer: Option<&str>,
    uri: &SpaceRecordUri,
    state: &SpaceState,
    ctx: &impl ViewContext,
) -> bool {
    let author = uri.author();
    uri.space() == &state.space
        && can_view_space(viewer, state, ctx)
        && is_writer(author, state)
        && ctx.is_active(author) == Tri::Yes
        && (viewer == Some(author) || viewer.is_some_and(|v| ctx.blocked(v, author) == Tri::No))
}

/// Whether `viewer` may post, reply or like in the space.
pub fn can_write(viewer: &str, state: &SpaceState, ctx: &impl ViewContext) -> bool {
    can_view_space(Some(viewer), state, ctx) && is_writer(viewer, state)
}

/// Whether `viewer` may see a bookmark: they may see the bookmark itself
/// (in its owner's only-me space, so only the owner) **and** the post it
/// points at, in that post's space. Without the post's state, no. A
/// bookmark anywhere but its author's own only-me space never shows.
pub fn can_view_bookmark(
    viewer: Option<&str>,
    bookmark: &SpaceRecordUri,
    only_me: &SpaceState,
    subject: &SpaceRecordUri,
    subject_space: Option<&SpaceState>,
    ctx: &impl ViewContext,
) -> bool {
    is_only_me(bookmark.space())
        && bookmark.author() == bookmark.space().authority()
        && can_view_record(viewer, bookmark, only_me, ctx)
        && subject_space.is_some_and(|s| can_view_record(viewer, subject, s, ctx))
}

/// Whether `viewer` may see a repost: it and the post it reposts are in
/// the same space (`state`), and they may see both. A repost naming a post
/// in any other space never shows.
pub fn can_view_repost(
    viewer: Option<&str>,
    repost: &SpaceRecordUri,
    subject: &SpaceRecordUri,
    state: &SpaceState,
    ctx: &impl ViewContext,
) -> bool {
    repost.space() == subject.space()
        && can_view_record(viewer, repost, state, ctx)
        && can_view_record(viewer, subject, state, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::{group_policy, group_space, only_me_policy, only_me_space};
    use std::collections::BTreeSet;
    use umbrae_lexicons::POST;

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
    const DAVE: &str = "did:plc:davedddddddddddddddddddddd";
    const SKEY: &str = "3mbbbbbbbbbb2";

    #[derive(Default)]
    struct Ctx {
        inactive: BTreeSet<&'static str>,
        unknown: BTreeSet<&'static str>,
        blocks: BTreeSet<(&'static str, &'static str)>,
        blocks_unknown: bool,
    }

    impl ViewContext for Ctx {
        fn is_active(&self, did: &str) -> Tri {
            if self.unknown.contains(did) {
                Tri::Unknown
            } else if self.inactive.contains(did) {
                Tri::No
            } else {
                Tri::Yes
            }
        }

        fn blocked(&self, a: &str, b: &str) -> Tri {
            if self.blocks_unknown {
                Tri::Unknown
            } else if self
                .blocks
                .iter()
                .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a))
            {
                Tri::Yes
            } else {
                Tri::No
            }
        }
    }

    fn rw(read: bool, write: bool) -> MemberAccess {
        MemberAccess { read, write }
    }

    fn group() -> SpaceState {
        let mut s = SpaceState::new(group_space(ALICE, SKEY).unwrap(), Some(group_policy(None)));
        s.members.insert(BOB, rw(true, true));
        s.members.insert(DAVE, rw(true, false));
        s
    }

    fn post(author: &str) -> SpaceRecordUri {
        group().space.record(author, POST, "3mbaaaaaaaaa2").unwrap()
    }

    #[test]
    fn members_see_the_space_others_do_not() {
        let (s, c) = (group(), Ctx::default());
        assert!(can_view_space(Some(ALICE), &s, &c));
        assert!(can_view_space(Some(BOB), &s, &c));
        assert!(can_view_space(Some(DAVE), &s, &c));
        assert!(!can_view_space(Some(CAROL), &s, &c));
        assert!(!can_view_space(None, &s, &c));
    }

    #[test]
    fn member_list_only_for_those_inside() {
        let (s, c) = (group(), Ctx::default());
        let seen = visible_members(Some(BOB), &s, &c).unwrap();
        assert_eq!(seen.len(), 2);
        assert!(visible_members(Some(CAROL), &s, &c).is_none());
        assert!(visible_members(None, &s, &c).is_none());
    }

    #[test]
    fn only_me_is_only_me() {
        let s = SpaceState::new(only_me_space(ALICE).unwrap(), Some(only_me_policy()));
        let c = Ctx::default();
        assert!(can_view_space(Some(ALICE), &s, &c));
        assert!(!can_view_space(Some(BOB), &s, &c));
    }

    #[test]
    fn bookmarks_follow_their_owner_and_the_post() {
        let c = Ctx::default();
        let me = SpaceState::new(only_me_space(BOB).unwrap(), Some(only_me_policy()));
        let mark = me
            .space
            .record(BOB, umbrae_lexicons::BOOKMARK, "3mbaaaaaaaaa2")
            .unwrap();
        let g = group();
        let p = post(ALICE);
        // Bob bookmarked a post in a group he's in.
        assert!(can_view_bookmark(Some(BOB), &mark, &me, &p, Some(&g), &c));
        // Nobody else sees Bob's bookmarks, even a group member.
        assert!(!can_view_bookmark(
            Some(ALICE),
            &mark,
            &me,
            &p,
            Some(&g),
            &c
        ));
        assert!(!can_view_bookmark(None, &mark, &me, &p, Some(&g), &c));
        // Without the post's space state: hidden.
        assert!(!can_view_bookmark(Some(BOB), &mark, &me, &p, None, &c));
        // Once Bob leaves the group, his bookmark of its post hides too.
        let mut left = group();
        left.members = Members::default();
        assert!(!can_view_bookmark(
            Some(BOB),
            &mark,
            &me,
            &p,
            Some(&left),
            &c
        ));
        // A "bookmark" written into the group itself shows to nobody, even
        // when the caller didn't drop it at validation.
        let stray = g
            .space
            .record(BOB, umbrae_lexicons::BOOKMARK, "3mbaaaaaaaaa3")
            .unwrap();
        for viewer in [ALICE, BOB, DAVE] {
            assert!(!can_view_bookmark(
                Some(viewer),
                &stray,
                &g,
                &p,
                Some(&g),
                &c
            ));
        }
        // Nor one by someone else in Alice's key-self space, even if that
        // space was misconfigured as a memberspace with them writing.
        let mut odd = SpaceState::new(only_me_space(ALICE).unwrap(), Some(group_policy(None)));
        odd.members.insert(BOB, rw(true, true));
        let foreign = odd
            .space
            .record(BOB, umbrae_lexicons::BOOKMARK, "3mbaaaaaaaaa4")
            .unwrap();
        assert!(!can_view_bookmark(
            Some(ALICE),
            &foreign,
            &odd,
            &p,
            Some(&g),
            &c
        ));
    }

    #[test]
    fn reposts_follow_both_records() {
        let c = Ctx::default();
        let g = group();
        let p = post(ALICE);
        let rp = g
            .space
            .record(BOB, umbrae_lexicons::REPOST, "3mbaaaaaaaaa5")
            .unwrap();
        assert!(can_view_repost(Some(DAVE), &rp, &p, &g, &c));
        let stranger = "did:plc:strangerssssssssssssssssss";
        assert!(!can_view_repost(Some(stranger), &rp, &p, &g, &c));
        assert!(!can_view_repost(None, &rp, &p, &g, &c));
        // Once the reposter leaves, their repost drops out.
        let mut left = group();
        left.members = Members::default();
        left.members.insert(DAVE, rw(true, false));
        assert!(!can_view_repost(Some(DAVE), &rp, &p, &left, &c));
        // A repost whose subject is in another space never shows.
        let elsewhere = crate::space::group_space(ALICE, "3mbbbbbbbbbb3")
            .unwrap()
            .record(ALICE, umbrae_lexicons::POST, "3mbaaaaaaaaa2")
            .unwrap();
        assert!(!can_view_repost(Some(ALICE), &rp, &elsewhere, &g, &c));
        // The repost still shows on its own, but the post it reposts
        // doesn't: its author left, or the viewer blocks them. Then the
        // repost hides too.
        let bobs = post(BOB);
        let arp = g
            .space
            .record(ALICE, umbrae_lexicons::REPOST, "3mbaaaaaaaaa6")
            .unwrap();
        assert!(can_view_repost(Some(DAVE), &arp, &bobs, &g, &c));
        assert!(can_view_record(Some(DAVE), &arp, &left, &c));
        assert!(!can_view_repost(Some(DAVE), &arp, &bobs, &left, &c));
        let blocks = Ctx {
            blocks: BTreeSet::from([(DAVE, BOB)]),
            ..Ctx::default()
        };
        assert!(can_view_record(Some(DAVE), &arp, &g, &blocks));
        assert!(!can_view_repost(Some(DAVE), &arp, &bobs, &g, &blocks));
    }

    #[test]
    fn records_from_non_writers_drop_out() {
        let (s, c) = (group(), Ctx::default());
        assert!(can_view_record(Some(BOB), &post(ALICE), &s, &c));
        assert!(can_view_record(Some(DAVE), &post(BOB), &s, &c));
        // Dave can read but not write; Carol was never a member.
        assert!(!can_view_record(Some(BOB), &post(DAVE), &s, &c));
        assert!(!can_view_record(Some(ALICE), &post(CAROL), &s, &c));
        assert!(can_write(BOB, &s, &c));
        assert!(!can_write(DAVE, &s, &c));
        assert!(!can_write(CAROL, &s, &c));
    }

    #[test]
    fn blocks_and_inactive_accounts_hide() {
        let s = group();
        let c = Ctx {
            blocks: BTreeSet::from([(BOB, ALICE)]),
            ..Ctx::default()
        };
        assert!(!can_view_space(Some(BOB), &s, &c));
        let c = Ctx {
            blocks: BTreeSet::from([(DAVE, BOB)]),
            ..Ctx::default()
        };
        assert!(can_view_record(Some(DAVE), &post(ALICE), &s, &c));
        assert!(!can_view_record(Some(DAVE), &post(BOB), &s, &c));
        let c = Ctx {
            inactive: BTreeSet::from([ALICE]),
            ..Ctx::default()
        };
        assert!(!can_view_space(Some(ALICE), &s, &c));
        let c = Ctx {
            inactive: BTreeSet::from([BOB]),
            ..Ctx::default()
        };
        assert!(!can_view_record(Some(DAVE), &post(BOB), &s, &c));
    }

    #[test]
    fn unknown_denies() {
        let s = group();
        let c = Ctx {
            unknown: BTreeSet::from([ALICE]),
            ..Ctx::default()
        };
        assert!(!can_view_space(Some(BOB), &s, &c));
        let c = Ctx {
            blocks_unknown: true,
            ..Ctx::default()
        };
        assert!(!can_view_space(Some(BOB), &s, &c));
        // The authority still sees their own space without the graph.
        assert!(can_view_space(Some(ALICE), &s, &c));
        assert!(can_view_record(Some(ALICE), &post(ALICE), &s, &c));
    }

    #[test]
    fn misconfigured_unknown_or_deleted_spaces_show_nothing_to_others() {
        let c = Ctx::default();
        let mut s = group();
        s.policy = None;
        assert!(!can_view_space(Some(BOB), &s, &c));
        assert!(!can_view_space(Some(ALICE), &s, &c));
        let mut s = group();
        if let Some(Policy::Member(p)) = &mut s.policy {
            p.public_read = true;
        }
        assert!(!can_view_space(Some(BOB), &s, &c));
        let mut s = group();
        s.deleted = true;
        assert!(!can_view_space(Some(ALICE), &s, &c));
    }

    #[test]
    fn state_from_published_records() {
        let space = group_space(ALICE, SKEY).unwrap();
        let policy = group_policy(None).policy_record();
        let bob = rw(true, true).to_record();
        let bad = Map::from([("read".to_string(), Value::Text("yes".into()))]);
        let post = Map::new();
        let records = [
            (POLICY_RECORD, POLICY_RECORD_RKEY, &policy),
            (MEMBER_RECORD, BOB, &bob),
            (MEMBER_RECORD, CAROL, &bad),
            (POST, "3mbaaaaaaaaa2", &post),
        ];
        let s = SpaceState::from_authority_records(space, records);
        assert_eq!(s.policy, Some(group_policy(None)));
        assert_eq!(s.members.get(BOB), Some(rw(true, true)));
        assert_eq!(s.members.get(CAROL), None);
        assert!(can_view_space(Some(BOB), &s, &Ctx::default()));
    }
}
