//! The hidden profile: one record, shown to the audiences it lists.
//!
//! An account keeps one `tools.umbrae.profile` at `self` in its profile
//! space (key `profile`). The space has no members, so only the owner and
//! the serving app it delegates to can read the record. The serving app
//! shows the profile, and serves its blobs, to anyone in a listed audience:
//! - **followers:** members of the owner's followers space;
//! - **a group:** members of one of the owner's groups;
//! - **a community:** members of the community, while the owner is still one;
//! - **everyone:** anyone the serving app admits.
//!
//! Every audience sees the same record, so an edit reaches all of them at
//! once. The audience list is for the owner and moderation only: a serving
//! app never returns it to anyone else. Others read the profile through
//! their serving app's `tools.umbrae.actor.getProfile` and
//! `getProfileBlob`. After every write to the profile space, the owner's
//! client hands the serving app a fresh delegation so it re-syncs.
//!
//! Before 0.7.3 a profile had one copy per audience. Those copies are
//! legacy: read them with [`crate::community::profile_for_viewer`] only
//! until the owner has, or has deleted, a profile space. Migration lists
//! only the audiences whose copy matches the newest, and the owner
//! confirms before the copies are deleted.

use crate::access::{can_view_record, can_view_space, is_writer, SpaceState, Tri, ViewContext};
use crate::space::{check_policy, followers_space};
use umbrae_core::cid::Cid;
use umbrae_core::uri::{SpaceRecordUri, SpaceRef};
use umbrae_lexicons::{Audience, Profile, PROFILE, PROFILE_SKEY, SELF_RKEY};

/// What a serving app knows about a profile's audiences.
pub trait AudienceSource {
    /// The state it holds for an audience space, if any. A space it
    /// doesn't hold grants nothing.
    fn state(&self, space: &SpaceRef) -> Option<&SpaceState>;
    /// Whether it admits `viewer`: the "everyone with Umbrae" audience.
    fn admits(&self, viewer: &str) -> bool;
}

/// Whether `uri` is the owner's one profile, in a sound profile space: at
/// `self`, by the space's authority, the policy known and passing
/// [`check_policy`] (so the member list is published and nobody reads it
/// publicly), and the published member list empty. Then no member can
/// exist unseen.
fn is_sound(uri: &SpaceRecordUri, profile_space: &SpaceState) -> bool {
    let space = uri.space();
    space.skey() == PROFILE_SKEY
        && uri.collection() == PROFILE
        && uri.rkey() == SELF_RKEY
        && uri.author() == space.authority()
        && profile_space.space == *space
        && profile_space
            .policy
            .as_ref()
            .is_some_and(|p| check_policy(space, p).is_ok())
        && profile_space.members.is_empty()
}

/// Whether `viewer` may see the profile at `uri`. The owner may; anyone
/// else must be in a listed audience, active, and not blocking or blocked
/// by the owner. A profile space whose policy fails `check_policy` or that
/// has members, or a record that isn't the owner's profile, shows to
/// nobody, the owner included, so the owner's client notices and repairs
/// it.
pub fn can_view_profile(
    viewer: Option<&str>,
    uri: &SpaceRecordUri,
    profile: &Profile,
    profile_space: &SpaceState,
    audiences: &impl AudienceSource,
    ctx: &impl ViewContext,
) -> bool {
    let owner = uri.author();
    let (Some(viewer), Some(listed)) = (viewer, &profile.audiences) else {
        return false;
    };
    // The owner reads its own record; nobody else reads it directly.
    if !is_sound(uri, profile_space) || !can_view_record(Some(owner), uri, profile_space, ctx) {
        return false;
    }
    if viewer == owner {
        return true;
    }
    if ctx.is_active(viewer) != Tri::Yes || ctx.blocked(viewer, owner) != Tri::No {
        return false;
    }
    let member_of = |space: &SpaceRef| {
        audiences
            .state(space)
            .is_some_and(|s| s.space == *space && can_view_space(Some(viewer), s, ctx))
    };
    listed.iter().any(|a| match a {
        Audience::Followers => followers_space(owner).is_ok_and(|f| member_of(&f)),
        Audience::Group(g) => g.authority() == owner && member_of(g),
        Audience::Community(c) => {
            member_of(c) && audiences.state(c).is_some_and(|s| is_writer(owner, s))
        }
        Audience::Everyone => audiences.admits(viewer),
        _ => false,
    })
}

/// Whether `viewer` may fetch blob `cid` of the profile: they may see the
/// profile, and the profile refers to the blob.
pub fn can_view_profile_blob(
    viewer: Option<&str>,
    cid: &Cid,
    uri: &SpaceRecordUri,
    profile: &Profile,
    profile_space: &SpaceState,
    audiences: &impl AudienceSource,
    ctx: &impl ViewContext,
) -> bool {
    profile.blobs().any(|b| b.cid == *cid)
        && can_view_profile(viewer, uri, profile, profile_space, audiences, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Tri;
    use crate::space::{community_space, group_policy, group_space, managed_policy, profile_space};
    use std::collections::BTreeMap;
    use umbrae_core::drisl::Value;
    use umbrae_core::policy::MemberAccess;
    use umbrae_lexicons::{
        validate_record, Record, AUDIENCE_COMMUNITY, AUDIENCE_EVERYONE, AUDIENCE_FOLLOWERS,
        AUDIENCE_GROUP,
    };

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
    const DAN: &str = "did:plc:danddddddddddddddddddddd";
    const COMMUNITY: &str = "did:plc:communityccccccccccccccc";
    const APP: &str = "did:web:app.example#umbrae_app";
    const GROUP: &str = "3mbbbbbbbbbb2";
    fn png() -> Cid {
        Cid::for_raw(b"avatar")
    }

    struct Ctx {
        blocked: Vec<(&'static str, &'static str)>,
    }
    impl ViewContext for Ctx {
        fn is_active(&self, _: &str) -> Tri {
            Tri::Yes
        }
        fn blocked(&self, a: &str, b: &str) -> Tri {
            if self
                .blocked
                .iter()
                .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a))
            {
                Tri::Yes
            } else {
                Tri::No
            }
        }
    }
    const OK: Ctx = Ctx {
        blocked: Vec::new(),
    };

    struct Source {
        states: Vec<SpaceState>,
        admitted: Vec<&'static str>,
    }
    impl AudienceSource for Source {
        fn state(&self, space: &SpaceRef) -> Option<&SpaceState> {
            self.states.iter().find(|s| s.space == *space)
        }
        fn admits(&self, viewer: &str) -> bool {
            self.admitted.contains(&viewer)
        }
    }

    fn rw() -> MemberAccess {
        MemberAccess {
            read: true,
            write: true,
        }
    }

    fn state(space: SpaceRef, policy: umbrae_core::policy::Policy, members: &[&str]) -> SpaceState {
        let mut s = SpaceState::new(space, Some(policy));
        for m in members {
            s.members.insert(m, rw());
        }
        s
    }

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn audience(ty: &str, space: Option<&SpaceRef>) -> Value {
        let mut m = BTreeMap::from([("$type".to_string(), t(ty))]);
        if let Some(s) = space {
            m.insert("space".into(), t(&s.to_string()));
        }
        Value::Map(m)
    }

    fn record(audiences: Vec<Value>) -> BTreeMap<String, Value> {
        let blob = Value::Map(BTreeMap::from([
            ("$type".to_string(), t("blob")),
            ("ref".to_string(), Value::Link(png())),
            ("mimeType".to_string(), t("image/png")),
            ("size".to_string(), Value::Integer(68)),
        ]));
        BTreeMap::from([
            ("$type".to_string(), t(PROFILE)),
            ("displayName".to_string(), t("Alice")),
            ("avatar".to_string(), blob),
            ("audiences".to_string(), Value::Array(audiences)),
            ("createdAt".to_string(), t("2026-11-27T00:00:00.000Z")),
        ])
    }

    fn uri() -> SpaceRecordUri {
        profile_space(ALICE)
            .unwrap()
            .record(ALICE, PROFILE, SELF_RKEY)
            .unwrap()
    }

    fn parse(m: &BTreeMap<String, Value>) -> Profile {
        match validate_record(&uri(), m) {
            Ok(Some(Record::Profile(p))) => *p,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn each_audience_sees_the_one_profile() {
        let group = group_space(ALICE, GROUP).unwrap();
        let community = community_space(COMMUNITY).unwrap();
        let followers = followers_space(ALICE).unwrap();
        let p = parse(&record(vec![
            audience(AUDIENCE_GROUP, Some(&group)),
            audience(AUDIENCE_COMMUNITY, Some(&community)),
        ]));
        let home = state(profile_space(ALICE).unwrap(), group_policy(None), &[]);
        let src = Source {
            states: vec![
                state(group.clone(), group_policy(None), &[BOB]),
                state(community.clone(), managed_policy(APP), &[ALICE, CAROL]),
                state(followers, group_policy(None), &[DAN]),
            ],
            admitted: vec![BOB, CAROL, DAN],
        };
        let sees = |v| can_view_profile(Some(v), &uri(), &p, &home, &src, &OK);
        assert!(sees(ALICE), "the owner");
        assert!(sees(BOB), "a group member");
        assert!(sees(CAROL), "a community member");
        assert!(!sees(DAN), "a follower, when followers aren't listed");
        assert!(!can_view_profile(None, &uri(), &p, &home, &src, &OK));

        // The same CID for everyone who may see it; nobody else.
        let cid = png();
        let blob = |v| can_view_profile_blob(Some(v), &cid, &uri(), &p, &home, &src, &OK);
        assert!(blob(BOB) && blob(CAROL) && !blob(DAN));
        let other = Cid::for_raw(b"banner");
        assert!(!can_view_profile_blob(
            Some(BOB),
            &other,
            &uri(),
            &p,
            &home,
            &src,
            &OK
        ));

        // Blocks cut either way.
        let blocked = Ctx {
            blocked: vec![(ALICE, BOB)],
        };
        assert!(!can_view_profile(
            Some(BOB),
            &uri(),
            &p,
            &home,
            &src,
            &blocked
        ));
    }

    #[test]
    fn followers_everyone_and_leaving_a_community() {
        let community = community_space(COMMUNITY).unwrap();
        let home = state(profile_space(ALICE).unwrap(), group_policy(None), &[]);
        let followers = state(followers_space(ALICE).unwrap(), group_policy(None), &[DAN]);
        let p = parse(&record(vec![
            audience(AUDIENCE_FOLLOWERS, None),
            audience(AUDIENCE_COMMUNITY, Some(&community)),
        ]));
        // Alice left the community: its members no longer see her profile.
        let src = Source {
            states: vec![
                followers.clone(),
                state(community, managed_policy(APP), &[CAROL]),
            ],
            admitted: vec![],
        };
        assert!(can_view_profile(Some(DAN), &uri(), &p, &home, &src, &OK));
        assert!(!can_view_profile(Some(CAROL), &uri(), &p, &home, &src, &OK));

        let everyone = parse(&record(vec![audience(AUDIENCE_EVERYONE, None)]));
        let src = Source {
            states: vec![],
            admitted: vec![BOB],
        };
        assert!(can_view_profile(
            Some(BOB),
            &uri(),
            &everyone,
            &home,
            &src,
            &OK
        ));
        assert!(!can_view_profile(
            Some(CAROL),
            &uri(),
            &everyone,
            &home,
            &src,
            &OK
        ));

        // No audiences: the owner alone.
        let none = parse(&record(vec![]));
        let src = Source {
            states: vec![followers],
            admitted: vec![DAN],
        };
        assert!(can_view_profile(
            Some(ALICE),
            &uri(),
            &none,
            &home,
            &src,
            &OK
        ));
        assert!(!can_view_profile(
            Some(DAN),
            &uri(),
            &none,
            &home,
            &src,
            &OK
        ));
    }

    #[test]
    fn a_profile_space_with_members_shows_to_nobody() {
        let p = parse(&record(vec![audience(AUDIENCE_EVERYONE, None)]));
        let leaky = state(profile_space(ALICE).unwrap(), group_policy(None), &[BOB]);
        let src = Source {
            states: vec![],
            admitted: vec![BOB],
        };
        assert!(!can_view_profile(Some(BOB), &uri(), &p, &leaky, &src, &OK));
        assert!(!can_view_profile(
            Some(ALICE),
            &uri(),
            &p,
            &leaky,
            &src,
            &OK
        ));
    }

    #[test]
    fn a_profile_space_with_the_wrong_policy_shows_to_nobody() {
        use umbrae_core::policy::{MemberPolicy, Policy};
        let p = parse(&record(vec![audience(AUDIENCE_EVERYONE, None)]));
        let src = Source {
            states: vec![],
            admitted: vec![BOB],
        };
        let member = |public_read, publish_members| {
            Policy::Member(MemberPolicy {
                public_read,
                public_write: false,
                allowed_apps: None,
                publish_policy: true,
                publish_members,
            })
        };
        let home = profile_space(ALICE).unwrap();
        // Unpublished members (a hidden member reads it), public read, and a
        // managed policy: each refused for the owner and for an admitted viewer.
        for space in [
            state(home.clone(), member(false, false), &[]),
            state(home.clone(), member(true, true), &[]),
            state(home.clone(), managed_policy(APP), &[]),
            SpaceState::new(home.clone(), None),
        ] {
            for v in [ALICE, BOB] {
                assert!(
                    !can_view_profile(Some(v), &uri(), &p, &space, &src, &OK),
                    "{v} {:?}",
                    space.policy
                );
            }
        }
    }

    #[test]
    fn audiences_validate() {
        let at = |m: &BTreeMap<String, Value>| validate_record(&uri(), m);
        // Required in the profile space.
        let mut missing = record(vec![]);
        missing.remove("audiences");
        assert!(at(&missing).is_err());
        // Someone else's group, a non-community space, a duplicate.
        let bobs = group_space(BOB, GROUP).unwrap();
        assert!(at(&record(vec![audience(AUDIENCE_GROUP, Some(&bobs))])).is_err());
        let fake = group_space(ALICE, GROUP).unwrap();
        assert!(at(&record(vec![audience(AUDIENCE_COMMUNITY, Some(&fake))])).is_err());
        assert!(at(&record(vec![
            audience(AUDIENCE_FOLLOWERS, None),
            audience(AUDIENCE_FOLLOWERS, None)
        ]))
        .is_err());
        // Unknown types are dropped: they grant nothing.
        let p = parse(&record(vec![audience(
            "tools.umbrae.profile#futureAudience",
            None,
        )]));
        assert_eq!(p.audiences, Some(vec![]));
        // Only the owner's profile goes in its profile space.
        let bob_here = profile_space(ALICE)
            .unwrap()
            .record(BOB, PROFILE, SELF_RKEY)
            .unwrap();
        assert!(validate_record(&bob_here, &record(vec![])).is_err());
        // A legacy copy may not list audiences.
        let legacy = followers_space(ALICE)
            .unwrap()
            .record(ALICE, PROFILE, SELF_RKEY)
            .unwrap();
        assert!(validate_record(&legacy, &record(vec![])).is_err());
        let mut plain = record(vec![]);
        plain.remove("audiences");
        assert!(matches!(
            validate_record(&legacy, &plain),
            Ok(Some(Record::Profile(p))) if p.audiences.is_none()
        ));
    }
}
