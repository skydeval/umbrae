//! Communities, feeds, placeholders, scoped profiles and list subscriptions.
//!
//! - **A community** is a membership kept by a managing app (prism, or a PDS
//!   such as Aurora-Locus that manages its own communities), named by a
//!   [`CommunityRef`]. Each writer keeps their records in their own
//!   community space ([`crate::space::community_space`]); the app is the
//!   only reader, and it assembles the community from those spaces. A
//!   member who is removed, demoted to reader or leaves stops being a
//!   writer, so their posts drop out at the app's next request.
//! - **A feed** shows the posts that name it, from any member's space for
//!   the same community, by accounts on its current author list.
//! - **A placeholder** stands in for a referenced post the viewer can't
//!   see ([`referenced_post`]), so a thread keeps its shape.
//! - **Legacy profile copies** (0.7.0 to 0.7.2 wrote one per audience): a
//!   viewer sees the copy for the narrowest audience they're in. Read them
//!   only until the owner has, or has deleted, a profile space; see
//!   [`crate::profile`], which replaces them.
//! - **A list subscription** shows only to its owner, and only while they
//!   may still see the list.

use crate::access::{can_view_record, in_same_community, SpaceState, Tri, ViewContext};
use crate::space::{is_community_space, is_only_me};
use umbrae_core::uri::{is_valid_tid, SpaceRecordUri};
pub use umbrae_lexicons::CommunityRef;
use umbrae_lexicons::{
    Feed, ListSubscription, Post, Profile, Target, EVERYONE_SKEY, FEED, FOLLOWERS_SKEY, POST,
};

/// A member's role in a community, as its app keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Reads the community, through its app.
    Reader,
    /// Also posts, replies, likes and reposts, in their own space.
    Writer,
}

/// Whether `viewer` may see `post` in `feed`. Both are in spaces of one
/// community ([`in_same_community`], so a lookalike fails), the viewer may
/// see both, the post names the feed, and its author is on the feed's
/// current author list.
#[allow(clippy::too_many_arguments)]
pub fn can_view_feed_post(
    viewer: Option<&str>,
    post_uri: &SpaceRecordUri,
    post: &Post,
    post_space: &SpaceState,
    feed_uri: &SpaceRecordUri,
    feed: &Feed,
    feed_space: &SpaceState,
    ctx: &impl ViewContext,
) -> bool {
    is_community_space(post_uri.space())
        && post_uri.collection() == POST
        && feed_uri.collection() == FEED
        && in_same_community(post_space, feed_space)
        && post
            .feeds
            .iter()
            .any(|f| matches!(&f.target, Target::Hidden(u) if u == feed_uri))
        && feed.authors.iter().any(|a| a == post_uri.author())
        && can_view_record(viewer, feed_uri, feed_space, ctx)
        && can_view_record(viewer, post_uri, post_space, ctx)
}

/// What a thread view shows for a post it refers to: a reply's parent,
/// root or ancestor, or a quoted post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferencedPost {
    /// The post itself.
    Visible,
    /// The usual block notice: a block between the viewer and the post's
    /// author or authority is the only thing hiding it.
    Blocked,
    /// `tools.umbrae.community.defs#unavailablePost`, with no author, text
    /// or reason: deleted, its author no longer a writer, its space failing
    /// the policy check, or not held. A removal looks like a deletion.
    Unavailable,
}

/// Decide what `viewer` sees in place of the post at `uri`, whose space
/// state is `space` (`None` when the app doesn't hold it, or the post is
/// deleted). The referring reply's own visibility doesn't depend on this.
/// For an unavailable post, the app doesn't pass on the raw reference
/// either: the URI names its author.
pub fn referenced_post(
    viewer: Option<&str>,
    uri: &SpaceRecordUri,
    space: Option<&SpaceState>,
    ctx: &impl ViewContext,
) -> ReferencedPost {
    let Some(space) = space else {
        return ReferencedPost::Unavailable;
    };
    if uri.collection() != POST {
        return ReferencedPost::Unavailable;
    }
    if can_view_record(viewer, uri, space, ctx) {
        return ReferencedPost::Visible;
    }
    let blocks = |did: &str| viewer.is_some_and(|v| v != did && ctx.blocked(v, did) == Tri::Yes);
    let blocked = blocks(uri.author()) || blocks(space.space.authority());
    if blocked && can_view_record(viewer, uri, space, &Unblocked(ctx)) {
        ReferencedPost::Blocked
    } else {
        ReferencedPost::Unavailable
    }
}

/// `ctx`, with every block lifted: to tell a block from everything else.
struct Unblocked<'a, C>(&'a C);

impl<C: ViewContext> ViewContext for Unblocked<'_, C> {
    fn is_active(&self, did: &str) -> Tri {
        self.0.is_active(did)
    }

    fn blocked(&self, _: &str, _: &str) -> Tri {
        Tri::No
    }
}

/// How narrow a profile copy's audience is: lower is narrower. `None` for
/// a space no profile belongs in.
fn audience_rank(uri: &SpaceRecordUri) -> Option<u8> {
    match uri.space().skey() {
        k if is_valid_tid(k) => Some(0),
        FOLLOWERS_SKEY => Some(1),
        EVERYONE_SKEY => Some(2),
        _ => None,
    }
}

/// One copy of an account's profile, with the state of the space it's in.
pub struct ProfileCopy<'a> {
    pub uri: &'a SpaceRecordUri,
    pub profile: &'a Profile,
    pub state: &'a SpaceState,
}

/// Legacy: only for owners who have never had a profile space (a deleted
/// one counts; see [`crate::profile`]). Which of an account's profile
/// copies `viewer` sees, by index: the
/// narrowest audience they may see, ties to the latest. Copies by anyone
/// but `account` are ignored. `None` if they may see none.
pub fn profile_for_viewer(
    viewer: Option<&str>,
    account: &str,
    copies: &[ProfileCopy<'_>],
    ctx: &impl ViewContext,
) -> Option<usize> {
    copies
        .iter()
        .enumerate()
        .filter(|(_, c)| c.uri.author() == account)
        .filter_map(|(i, c)| Some((i, c, audience_rank(c.uri)?)))
        .filter(|(_, c, _)| can_view_record(viewer, c.uri, c.state, ctx))
        .min_by(|(_, a, ra), (_, b, rb)| {
            let at = |c: &ProfileCopy<'_>| {
                c.profile
                    .updated_at
                    .clone()
                    .unwrap_or_else(|| c.profile.created_at.clone())
            };
            // Narrowest first, then the latest change.
            ra.cmp(rb).then_with(|| at(b).cmp(&at(a)))
        })
        .map(|(i, _, _)| i)
}

/// Whether `viewer` may see a list subscription: it's in its owner's
/// only-me space, they may see it (so they're the owner), and they may
/// still see the list it names.
pub fn can_view_list_subscription(
    viewer: Option<&str>,
    subscription: &SpaceRecordUri,
    sub: &ListSubscription,
    only_me: &SpaceState,
    list_space: Option<&SpaceState>,
    ctx: &impl ViewContext,
) -> bool {
    let Target::Hidden(list) = &sub.list.target else {
        return false;
    };
    is_only_me(subscription.space())
        && subscription.author() == subscription.space().authority()
        && can_view_record(viewer, subscription, only_me, ctx)
        && list_space.is_some_and(|s| can_view_record(viewer, list, s, ctx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Members;
    use crate::space::{
        community_space, everyone_space, followers_space, group_policy, group_space,
        managed_policy, only_me_policy, only_me_space,
    };
    use std::collections::BTreeMap;
    use umbrae_core::cid::Cid;
    use umbrae_core::drisl::Value;
    use umbrae_core::policy::{MemberAccess, Policy};
    use umbrae_core::uri::SpaceRef;
    use umbrae_lexicons::{validate_record, Record, LIST, LIST_SUBSCRIPTION, PROFILE};

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
    const APP: &str = "did:web:app.example#umbrae_app";
    const GROUP: &str = "3mbbbbbbbbbb2";
    const RKEY: &str = "3mbaaaaaaaaa2";
    const RKEY2: &str = "3mbaaaaaaaaa3";

    struct Ctx(Vec<(&'static str, &'static str)>);
    impl ViewContext for Ctx {
        fn is_active(&self, _: &str) -> Tri {
            Tri::Yes
        }
        fn blocked(&self, a: &str, b: &str) -> Tri {
            if self
                .0
                .iter()
                .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a))
            {
                Tri::Yes
            } else {
                Tri::No
            }
        }
    }
    const OK: Ctx = Ctx(Vec::new());

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn map(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    fn sref(uri: &SpaceRecordUri) -> Value {
        Value::Map(map(&[
            ("uri", t(&uri.to_string())),
            ("cid", t(&Cid::for_drisl(b"x").to_string())),
        ]))
    }

    fn rw(read: bool, write: bool) -> MemberAccess {
        MemberAccess { read, write }
    }

    fn art() -> CommunityRef {
        CommunityRef::new(APP, "art").unwrap()
    }

    /// `author`'s art space, as the app holds it: Alice and Bob are
    /// writers, Carol isn't a member.
    fn space_of(author: &str) -> SpaceState {
        let mut s = SpaceState::new(
            community_space(author, &art()).unwrap(),
            Some(managed_policy(APP)),
        );
        s.community = Some(art());
        let mut m = Members::default();
        m.insert(ALICE, rw(true, true));
        m.insert(BOB, rw(true, true));
        s.members = m;
        s
    }

    fn post_in(space: &SpaceState, feeds: &[&SpaceRecordUri]) -> (SpaceRecordUri, Post) {
        let uri = space
            .space
            .record(space.space.authority(), POST, RKEY2)
            .unwrap();
        let v = map(&[
            ("$type", t(POST)),
            ("text", t("hi")),
            (
                "feeds",
                Value::Array(feeds.iter().map(|f| sref(f)).collect()),
            ),
            ("createdAt", t("2026-11-26T10:00:00Z")),
        ]);
        match validate_record(&uri, &v) {
            Ok(Some(Record::Post(p))) => (uri, *p),
            other => panic!("{other:?}"),
        }
    }

    fn a_feed(space: &SpaceState, authors: &[&str]) -> (SpaceRecordUri, Feed) {
        let uri = space
            .space
            .record(space.space.authority(), FEED, RKEY)
            .unwrap();
        let v = map(&[
            ("$type", t(FEED)),
            ("name", t("Art")),
            (
                "authors",
                Value::Array(authors.iter().map(|a| t(a)).collect()),
            ),
            ("createdAt", t("2026-11-26T10:00:00Z")),
        ]);
        match validate_record(&uri, &v) {
            Ok(Some(Record::Feed(f))) => (uri, *f),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn feeds_show_their_current_authors_posts_across_members_spaces() {
        // Alice's feed, in her space; Bob's post to it, in his.
        let (alices, bobs) = (space_of(ALICE), space_of(BOB));
        let (feed_uri, feed) = a_feed(&alices, &[BOB]);
        let (post_uri, post) = post_in(&bobs, &[&feed_uri]);
        let sees = |v: &str, feed: &Feed, feed_space: &SpaceState| {
            can_view_feed_post(
                Some(v),
                &post_uri,
                &post,
                &bobs,
                &feed_uri,
                feed,
                feed_space,
                &OK,
            )
        };
        assert!(sees(ALICE, &feed, &alices));
        assert!(!sees(CAROL, &feed, &alices));
        // Off the author list: out of the feed.
        let (_, without_bob) = a_feed(&alices, &[ALICE]);
        assert!(!sees(ALICE, &without_bob, &alices));
        // A post that wasn't sent to it isn't in it.
        let (other_uri, other) = post_in(&bobs, &[]);
        assert!(!can_view_feed_post(
            Some(ALICE),
            &other_uri,
            &other,
            &bobs,
            &feed_uri,
            &feed,
            &alices,
            &OK
        ));
        // A lookalike: the feed's space names another app.
        let mut lookalike = space_of(ALICE);
        lookalike.policy = Some(managed_policy("did:web:other.example#umbrae_app"));
        assert!(!sees(ALICE, &feed, &lookalike));
        // The feed's author removed: the feed drops out.
        let mut removed = space_of(ALICE);
        removed.members.insert(ALICE, rw(false, false));
        assert!(!sees(BOB, &feed, &removed));
    }

    #[test]
    fn placeholders_keep_the_thread_and_never_replace_a_block() {
        let (alices, bobs) = (space_of(ALICE), space_of(BOB));
        let alice_post = alices.space.record(ALICE, POST, RKEY).unwrap();
        let bob_reply = bobs.space.record(BOB, POST, RKEY2).unwrap();
        assert_eq!(
            referenced_post(Some(BOB), &alice_post, Some(&alices), &OK),
            ReferencedPost::Visible
        );
        // Alice removed: her post is unavailable; Bob's reply still shows.
        let mut removed = space_of(ALICE);
        removed.members.insert(ALICE, rw(false, false));
        let bobs_now = {
            let mut s = space_of(BOB);
            s.members.insert(ALICE, rw(false, false));
            s
        };
        assert_eq!(
            referenced_post(Some(BOB), &alice_post, Some(&removed), &OK),
            ReferencedPost::Unavailable
        );
        assert!(can_view_record(Some(BOB), &bob_reply, &bobs_now, &OK));
        // Deleted, or not held: the same placeholder.
        assert_eq!(
            referenced_post(Some(BOB), &alice_post, None, &OK),
            ReferencedPost::Unavailable
        );
        // A lookalike space: unavailable.
        let mut lookalike = space_of(ALICE);
        lookalike.policy = Some(managed_policy("did:web:other.example#umbrae_app"));
        assert_eq!(
            referenced_post(Some(BOB), &alice_post, Some(&lookalike), &OK),
            ReferencedPost::Unavailable
        );
        // A block is a block notice, not a placeholder...
        let blocks = Ctx(vec![(BOB, ALICE)]);
        assert_eq!(
            referenced_post(Some(BOB), &alice_post, Some(&alices), &blocks),
            ReferencedPost::Blocked
        );
        // ...but it doesn't uncover a post that's unavailable anyway.
        assert_eq!(
            referenced_post(Some(BOB), &alice_post, Some(&removed), &blocks),
            ReferencedPost::Unavailable
        );
        // An outsider sees nothing.
        assert_eq!(
            referenced_post(Some(CAROL), &alice_post, Some(&alices), &OK),
            ReferencedPost::Unavailable
        );
    }

    fn profile_at(space: &SpaceRef, author: &str, updated: &str) -> (SpaceRecordUri, Profile) {
        let uri = space.record(author, PROFILE, "self").unwrap();
        let v = map(&[
            ("$type", t(PROFILE)),
            ("displayName", t(space.skey())),
            ("createdAt", t("2026-11-26T10:00:00Z")),
            ("updatedAt", t(updated)),
        ]);
        match validate_record(&uri, &v) {
            Ok(Some(Record::Profile(p))) => (uri, *p),
            other => panic!("{other:?}"),
        }
    }

    fn member_state(space: SpaceRef, policy: Policy, members: &[&str]) -> SpaceState {
        let mut s = SpaceState::new(space, Some(policy));
        for m in members {
            s.members.insert(m, rw(true, true));
        }
        s
    }

    #[test]
    fn the_narrowest_profile_copy_wins() {
        let group = member_state(
            group_space(ALICE, GROUP).unwrap(),
            group_policy(None),
            &[BOB],
        );
        let followers = member_state(
            followers_space(ALICE).unwrap(),
            group_policy(None),
            &[BOB, CAROL],
        );
        let everyone = member_state(
            everyone_space(ALICE).unwrap(),
            managed_policy(APP),
            &[BOB, CAROL],
        );
        let (gu, gp) = profile_at(&group.space, ALICE, "2026-11-26T10:00:00Z");
        let (fu, fp) = profile_at(&followers.space, ALICE, "2026-11-26T11:00:00Z");
        let (eu, ep) = profile_at(&everyone.space, ALICE, "2026-11-26T12:00:00Z");
        // A copy in a community space has no rank: never shown.
        let comm = space_of(ALICE);
        let (cu, cp) = profile_at(&comm.space, ALICE, "2026-11-26T13:00:00Z");
        let copies = [
            ProfileCopy {
                uri: &eu,
                profile: &ep,
                state: &everyone,
            },
            ProfileCopy {
                uri: &cu,
                profile: &cp,
                state: &comm,
            },
            ProfileCopy {
                uri: &fu,
                profile: &fp,
                state: &followers,
            },
            ProfileCopy {
                uri: &gu,
                profile: &gp,
                state: &group,
            },
        ];
        // Bob is in the group: the group copy. Carol: followers. Someone in
        // none sees nothing.
        assert_eq!(profile_for_viewer(Some(BOB), ALICE, &copies, &OK), Some(3));
        assert_eq!(
            profile_for_viewer(Some(CAROL), ALICE, &copies, &OK),
            Some(2)
        );
        assert_eq!(profile_for_viewer(None, ALICE, &copies, &OK), None);
        assert_eq!(
            profile_for_viewer(Some(BOB), ALICE, &copies[1..2], &OK),
            None
        );
        // Ties go to the latest change.
        let (fu2, fp2) = profile_at(&followers.space, ALICE, "2026-11-26T09:00:00Z");
        let tie = [
            ProfileCopy {
                uri: &fu2,
                profile: &fp2,
                state: &followers,
            },
            ProfileCopy {
                uri: &fu,
                profile: &fp,
                state: &followers,
            },
        ];
        assert_eq!(profile_for_viewer(Some(CAROL), ALICE, &tie, &OK), Some(1));
    }

    #[test]
    fn list_subscriptions_follow_the_list() {
        let group = member_state(
            group_space(ALICE, GROUP).unwrap(),
            group_policy(None),
            &[BOB],
        );
        let list = group.space.record(ALICE, LIST, RKEY).unwrap();
        let only_me = SpaceState::new(only_me_space(BOB).unwrap(), Some(only_me_policy()));
        let uri = only_me.space.record(BOB, LIST_SUBSCRIPTION, RKEY2).unwrap();
        let v = map(&[
            ("$type", t(LIST_SUBSCRIPTION)),
            ("list", sref(&list)),
            ("createdAt", t("2026-11-26T10:00:00Z")),
        ]);
        let Ok(Some(Record::ListSubscription(sub))) = validate_record(&uri, &v) else {
            panic!("subscription should validate");
        };
        assert!(can_view_list_subscription(
            Some(BOB),
            &uri,
            &sub,
            &only_me,
            Some(&group),
            &OK
        ));
        assert!(!can_view_list_subscription(
            Some(ALICE),
            &uri,
            &sub,
            &only_me,
            Some(&group),
            &OK
        ));
        assert!(!can_view_list_subscription(
            Some(BOB),
            &uri,
            &sub,
            &only_me,
            None,
            &OK
        ));
        let mut left = group.clone();
        left.members = Members::default();
        assert!(!can_view_list_subscription(
            Some(BOB),
            &uri,
            &sub,
            &only_me,
            Some(&left),
            &OK
        ));
    }
}
