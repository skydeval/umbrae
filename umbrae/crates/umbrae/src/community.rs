//! Communities, feeds, scoped profiles and list subscriptions.
//!
//! - **A community** is a managed `tools.umbrae.space` space with the key
//!   `community`, whose authority is the community's own account. Its
//!   managing app (prism, or a PDS such as Aurora-Locus that manages its own
//!   communities) answers who may read and write. A removed member stops
//!   being a writer, so their posts drop out of the community, as in a
//!   group.
//! - **A feed** shows the posts that name it, from accounts on its current
//!   author list, to anyone who may see the community.
//! - **Legacy profile copies** (0.7.0 to 0.7.2 wrote one per audience): a
//!   viewer sees the copy for the narrowest audience they're in. Read them
//!   only while the owner has no profile-space record; see
//!   [`crate::profile`], which replaces them.
//! - **A list subscription** shows only to its owner, and only while they
//!   may still see the list.

use crate::access::{can_view_record, SpaceState, ViewContext};
use crate::space::is_only_me;
use umbrae_core::uri::{is_valid_tid, SpaceRecordUri};
use umbrae_lexicons::{
    Feed, ListSubscription, Post, Profile, Target, COMMUNITY_SKEY, EVERYONE_SKEY, FEED,
    FOLLOWERS_SKEY, POST,
};

/// Whether `viewer` may see `post` in `feed`: both are in the same
/// community space, the viewer may see both, the post names the feed, and
/// its author is on the feed's current author list.
pub fn can_view_feed_post(
    viewer: Option<&str>,
    post_uri: &SpaceRecordUri,
    post: &Post,
    feed_uri: &SpaceRecordUri,
    feed: &Feed,
    state: &SpaceState,
    ctx: &impl ViewContext,
) -> bool {
    post_uri.space().skey() == COMMUNITY_SKEY
        && post_uri.collection() == POST
        && feed_uri.collection() == FEED
        && post_uri.space() == feed_uri.space()
        && post
            .feeds
            .iter()
            .any(|f| matches!(&f.target, Target::Hidden(u) if u == feed_uri))
        && feed.authors.iter().any(|a| a == post_uri.author())
        && can_view_record(viewer, feed_uri, state, ctx)
        && can_view_record(viewer, post_uri, state, ctx)
}

/// How narrow a profile copy's audience is: lower is narrower. `None` for
/// a space no profile belongs in.
fn audience_rank(uri: &SpaceRecordUri) -> Option<u8> {
    match uri.space().skey() {
        k if is_valid_tid(k) => Some(0),
        FOLLOWERS_SKEY => Some(1),
        COMMUNITY_SKEY => Some(2),
        EVERYONE_SKEY => Some(3),
        _ => None,
    }
}

/// One copy of an account's profile, with the state of the space it's in.
pub struct ProfileCopy<'a> {
    pub uri: &'a SpaceRecordUri,
    pub profile: &'a Profile,
    pub state: &'a SpaceState,
}

/// Legacy: for owners not yet moved to the one profile in
/// [`crate::profile`]. Which of an account's profile copies `viewer` sees, by index: the
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
    use crate::access::{Members, Tri};
    use crate::space::{
        check_policy, community_space, everyone_space, followers_space, group_policy, group_space,
        managed_policy, only_me_policy, only_me_space,
    };
    use std::collections::BTreeMap;
    use umbrae_core::cid::Cid;
    use umbrae_core::drisl::Value;
    use umbrae_core::policy::{MemberAccess, Policy};
    use umbrae_core::uri::SpaceRef;
    use umbrae_lexicons::{validate_record, Record, LIST, LIST_SUBSCRIPTION, PROFILE};

    const COMMUNITY: &str = "did:plc:communityccccccccccccccc";
    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
    const APP: &str = "did:web:app.example#umbrae_app";
    const GROUP: &str = "3mbbbbbbbbbb2";
    const RKEY: &str = "3mbaaaaaaaaa2";
    const RKEY2: &str = "3mbaaaaaaaaa3";

    struct Ctx;
    impl ViewContext for Ctx {
        fn is_active(&self, _: &str) -> Tri {
            Tri::Yes
        }
        fn blocked(&self, _: &str, _: &str) -> Tri {
            Tri::No
        }
    }

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

    /// A community whose managing app says Alice and Bob are members, and
    /// Carol isn't.
    fn community() -> SpaceState {
        let mut s = SpaceState::new(
            community_space(COMMUNITY).unwrap(),
            Some(managed_policy(APP)),
        );
        let mut m = Members::default();
        m.insert(ALICE, rw(true, true));
        m.insert(BOB, rw(true, true));
        s.members = m;
        s
    }

    #[test]
    fn managed_spaces_check_and_use_the_apps_answers() {
        let c = community();
        assert_eq!(check_policy(&c.space, c.policy.as_ref().unwrap()), Ok(()));
        let e = everyone_space(ALICE).unwrap();
        assert_eq!(check_policy(&e, &managed_policy(APP)), Ok(()));
        // A community or everyone space must be managed, and published.
        assert!(check_policy(&c.space, &group_policy(None)).is_err());
        assert!(check_policy(&e, &only_me_policy()).is_err());
        let unpublished = Policy::Managed(umbrae_core::policy::ManagedPolicy {
            managing_app: APP.into(),
            publish_policy: false,
        });
        assert!(check_policy(&c.space, &unpublished).is_err());
        // And a group can't be managed.
        let g = group_space(ALICE, GROUP).unwrap();
        assert!(check_policy(&g, &managed_policy(APP)).is_err());
        let post = c.space.record(BOB, POST, RKEY).unwrap();
        assert!(can_view_record(Some(ALICE), &post, &c, &Ctx));
        assert!(!can_view_record(Some(CAROL), &post, &c, &Ctx));
        // Removed: Bob's posts drop out of the community.
        let mut removed = community();
        removed.members.insert(BOB, rw(false, false));
        assert!(!can_view_record(Some(ALICE), &post, &removed, &Ctx));
    }

    fn post_in(feeds: &[&SpaceRecordUri], author: &str) -> (SpaceRecordUri, Post) {
        let uri = community_space(COMMUNITY)
            .unwrap()
            .record(author, POST, RKEY2)
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

    fn a_feed(authors: &[&str]) -> (SpaceRecordUri, Feed) {
        let uri = community_space(COMMUNITY)
            .unwrap()
            .record(ALICE, FEED, RKEY)
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
    fn feeds_show_their_current_authors_posts_to_the_community() {
        let c = community();
        let (feed_uri, feed) = a_feed(&[BOB]);
        let (post_uri, post) = post_in(&[&feed_uri], BOB);
        assert!(can_view_feed_post(
            Some(ALICE),
            &post_uri,
            &post,
            &feed_uri,
            &feed,
            &c,
            &Ctx
        ));
        assert!(!can_view_feed_post(
            Some(CAROL),
            &post_uri,
            &post,
            &feed_uri,
            &feed,
            &c,
            &Ctx
        ));
        // Off the author list: out of the feed.
        let (_, without_bob) = a_feed(&[ALICE]);
        assert!(!can_view_feed_post(
            Some(ALICE),
            &post_uri,
            &post,
            &feed_uri,
            &without_bob,
            &c,
            &Ctx
        ));
        // A post that wasn't sent to it isn't in it.
        let (other_uri, other) = post_in(&[], BOB);
        assert!(!can_view_feed_post(
            Some(ALICE),
            &other_uri,
            &other,
            &feed_uri,
            &feed,
            &c,
            &Ctx
        ));
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
        let comm = community();
        let (gu, gp) = profile_at(&group.space, ALICE, "2026-11-26T10:00:00Z");
        let (fu, fp) = profile_at(&followers.space, ALICE, "2026-11-26T11:00:00Z");
        let (eu, ep) = profile_at(&everyone.space, ALICE, "2026-11-26T12:00:00Z");
        let (cu, cp) = profile_at(&comm.space, ALICE, "2026-11-26T12:00:00Z");
        let (bu, bp) = profile_at(&comm.space, BOB, "2026-11-26T12:00:00Z");
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
            ProfileCopy {
                uri: &bu,
                profile: &bp,
                state: &comm,
            },
        ];
        // Bob is in the group: the group copy. Carol: followers. Someone in
        // none sees nothing.
        assert_eq!(profile_for_viewer(Some(BOB), ALICE, &copies, &Ctx), Some(3));
        assert_eq!(
            profile_for_viewer(Some(CAROL), ALICE, &copies, &Ctx),
            Some(2)
        );
        assert_eq!(profile_for_viewer(None, ALICE, &copies, &Ctx), None);
        // Bob's own community copy is Bob's, never Alice's.
        assert_eq!(profile_for_viewer(Some(ALICE), BOB, &copies, &Ctx), Some(4));
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
        assert_eq!(profile_for_viewer(Some(CAROL), ALICE, &tie, &Ctx), Some(1));
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
            &Ctx
        ));
        assert!(!can_view_list_subscription(
            Some(ALICE),
            &uri,
            &sub,
            &only_me,
            Some(&group),
            &Ctx
        ));
        assert!(!can_view_list_subscription(
            Some(BOB),
            &uri,
            &sub,
            &only_me,
            None,
            &Ctx
        ));
        let mut left = group.clone();
        left.members = Members::default();
        assert!(!can_view_list_subscription(
            Some(BOB),
            &uri,
            &sub,
            &only_me,
            Some(&left),
            &Ctx
        ));
    }
}
