//! The spaces Umbrae creates.
//!
//! | Audience | skey | Policy |
//! |---|---|---|
//! | a group | a TID | memberspace, not public, policy and members published |
//! | a private account's approved followers | `followers` | memberspace, as a group |
//! | only me | `self` | personalspace |
//! | a shared list | a TID | memberspace, not public, policy published, members **not** published |
//! | one author's records for a community | `c-` and 32 base32 characters ([`community_skey`]) | managedspace naming the community's app, policy published |
//! | everyone with Umbrae | `everyone` | managedspace, policy published |
//! | the owner's profile | `profile` | memberspace, as a group, with **no** members |
//! | a private account (type `tools.umbrae.private`) | `self` | managedspace naming the owner's serving app, policy published |
//!
//! A private account's space ([`private_space`]) is read only by its
//! serving app, which answers `checkAccess` as a community's app does, with
//! one difference: for an account it answers `write` while that account
//! passes the owner's rules, so the PDS tracks it as a writer. `write`
//! grants nothing else, and `read` is never true for an account. The app
//! checks the space with [`check_private_policy`]. A moved record keeps
//! its collection and key, so [`private_uri`] and [`public_uri`] map one
//! form of its URI to the other.
//!
//! The profile space holds an account's one hidden profile. Only the owner
//! and the apps it delegates to (its serving app) read it; the serving app
//! shows the profile to the audiences the record lists. Members would read
//! the audience list and bypass it, so a reader refuses a profile space
//! that has any members, or whose policy fails [`check_policy`] (see
//! [`crate::profile`]). A client never calls `putMembers` on it.
//!
//! A managed space's membership is held by its managing app, which the
//! PDS asks through `com.atproto.managedspace.checkAccess`. That app may be
//! prism, or a PDS such as Aurora-Locus managing its own communities:
//! Umbrae doesn't care which. Nothing is published as member records; a
//! reader learns who may see what from the managing app.
//!
//! A community has no space of its own. Each writer keeps a community space
//! ([`community_space`]) whose policy names the community's app, and only
//! they write in it. The app answers `checkAccess` for it:
//! - nothing unless the service auth's `iss` is the space's authority, its
//!   `aud` the app, and its `lxm` `checkAccess`;
//! - nothing for a space it doesn't map to one of its communities, or whose
//!   authority isn't a writer;
//! - nothing, ever, when `repo` names an account: members read through the
//!   app, and nobody writes into another's space;
//! - with `repo` absent, `read` only for its own attested client ID, and
//!   never `write`.
//!
//! So the app is the only reader of community spaces, and it checks each
//! one with [`check_community_policy`] before syncing or serving it.
//!
//! A shared list's subscribers are read-only members who can't see each
//! other. With no published member list, no app can serve the list: each
//! subscriber's client reads it from the owner's PDS. Personal lists and
//! exemptions sit in only-me.
//!
//! Publishing the member list puts it in the authority's repo inside the
//! space, so only people who can read the space see it. That is also how an
//! app serving the posts learns who may see them.

use umbrae_core::policy::MemberAccess;
use umbrae_core::policy::{ManagedPolicy, MemberPolicy, Policy};
use umbrae_core::uri::{is_valid_tid, SpaceRecordUri, SpaceRef, UriError};
use umbrae_lexicons::{
    community_skey, is_community_skey, CommunityRef, PublicUri, EVERYONE_SKEY, FOLLOWERS_SKEY,
    LIST_SPACE_TYPE, PRIVATE_SPACE_TYPE, PROFILE_SKEY, SELF_RKEY, SPACE_TYPE,
};

/// The only-me space's key.
pub const ONLY_ME_SKEY: &str = "self";

/// A group's space. The key must be a TID.
pub fn group_space(author: &str, skey: &str) -> Result<SpaceRef, UriError> {
    if !is_valid_tid(skey) {
        return Err(UriError::InvalidSkey);
    }
    SpaceRef::new(author, SPACE_TYPE, skey)
}

/// A private account's followers space. It takes the group policy;
/// approved followers are members with read and write.
pub fn followers_space(author: &str) -> Result<SpaceRef, UriError> {
    SpaceRef::new(author, SPACE_TYPE, FOLLOWERS_SKEY)
}

/// `author`'s own space for `community`. Create it with
/// [`managed_policy`] naming the community's app, before the first write
/// there, then call `tools.umbrae.community.registerSpace`.
pub fn community_space(author: &str, community: &CommunityRef) -> Result<SpaceRef, UriError> {
    SpaceRef::new(author, SPACE_TYPE, &community_skey(community))
}

/// Whether `space` has a community space's shape: `tools.umbrae.space`
/// with a `c-` key. Which community it is takes the ref
/// ([`check_community_policy`]).
pub fn is_community_space(space: &SpaceRef) -> bool {
    space.space_type() == SPACE_TYPE && is_community_skey(space.skey())
}

/// Check that `space` is a member's space for `community`: the key is
/// [`community_skey`], and the published policy is a managed one whose
/// `managingApp` is the community's app. A lookalike, with the same key
/// and a policy naming another app, fails. The app checks before it syncs
/// or serves a community space.
pub fn check_community_policy(
    space: &SpaceRef,
    community: &CommunityRef,
    policy: &Policy,
) -> Result<(), Misconfigured> {
    if space.space_type() != SPACE_TYPE {
        return Err(Misconfigured::NotUmbrae);
    }
    if space.skey() != community_skey(community) {
        return Err(Misconfigured::WrongPolicy);
    }
    match policy {
        Policy::Managed(p) if p.managing_app != community.app() => Err(Misconfigured::WrongPolicy),
        Policy::Managed(p) if p.publish_policy => Ok(()),
        Policy::Managed(_) => Err(Misconfigured::Unpublished),
        _ => Err(Misconfigured::WrongPolicy),
    }
}

/// A private account's space. Create it with [`managed_policy`] naming the
/// owner's serving app, then call `tools.umbrae.private.register` there.
pub fn private_space(owner: &str) -> Result<SpaceRef, UriError> {
    SpaceRef::new(owner, PRIVATE_SPACE_TYPE, SELF_RKEY)
}

/// Check that `space` is a private account's space served by `app`: type
/// `tools.umbrae.private`, key `self`, and a published managed policy whose
/// `managingApp` is `app`. The app checks before it syncs or serves one.
pub fn check_private_policy(
    space: &SpaceRef,
    app: &str,
    policy: &Policy,
) -> Result<(), Misconfigured> {
    if space.space_type() != PRIVATE_SPACE_TYPE {
        return Err(Misconfigured::NotUmbrae);
    }
    if space.skey() != SELF_RKEY {
        return Err(Misconfigured::WrongPolicy);
    }
    match policy {
        Policy::Managed(p) if p.managing_app != app => Err(Misconfigured::WrongPolicy),
        Policy::Managed(p) if p.publish_policy => Ok(()),
        Policy::Managed(_) => Err(Misconfigured::Unpublished),
        _ => Err(Misconfigured::WrongPolicy),
    }
}

/// The private-space form of a record's public URI: `at://{did}/{coll}/{rkey}`
/// is `at:space/{did}/tools.umbrae.private/self/{did}/{coll}/{rkey}`.
pub fn private_uri(public: &PublicUri) -> Result<SpaceRecordUri, UriError> {
    private_space(&public.did)?.record(&public.did, &public.collection, &public.rkey)
}

/// The public form of the owner's record in its private space, or `None`
/// for any other record.
pub fn public_uri(uri: &SpaceRecordUri) -> Option<PublicUri> {
    let space = uri.space();
    (space.space_type() == PRIVATE_SPACE_TYPE
        && space.skey() == SELF_RKEY
        && uri.author() == space.authority())
    .then(|| PublicUri {
        did: uri.author().to_owned(),
        collection: uri.collection().to_owned(),
        rkey: uri.rkey().to_owned(),
    })
}

/// An account's "everyone with Umbrae" space.
pub fn everyone_space(owner: &str) -> Result<SpaceRef, UriError> {
    SpaceRef::new(owner, SPACE_TYPE, EVERYONE_SKEY)
}

/// An account's profile space. Create it with [`group_policy`], whose
/// `allowed_apps` limits which serving apps may read it, and add no members.
pub fn profile_space(owner: &str) -> Result<SpaceRef, UriError> {
    SpaceRef::new(owner, SPACE_TYPE, PROFILE_SKEY)
}

/// Whether the space's members come from a managing app.
pub fn is_managed(space: &SpaceRef) -> bool {
    space.space_type() == SPACE_TYPE
        && (is_community_skey(space.skey()) || space.skey() == EVERYONE_SKEY)
}

/// The policy a community or everyone space is created with.
/// `managing_app` is the `did#serviceId` that answers `checkAccess`: for an
/// everyone space, read for any admitted account and write for the owner;
/// for a community space, the community's app (see the module docs).
pub fn managed_policy(managing_app: &str) -> Policy {
    Policy::Managed(ManagedPolicy {
        managing_app: managing_app.to_owned(),
        publish_policy: true,
    })
}

pub fn only_me_space(author: &str) -> Result<SpaceRef, UriError> {
    SpaceRef::new(author, SPACE_TYPE, ONLY_ME_SKEY)
}

pub fn is_only_me(space: &SpaceRef) -> bool {
    space.skey() == ONLY_ME_SKEY
}

/// The policy a group is created with. `allowed_apps` limits which apps
/// may read (by attested client ID); `None` allows any app a member uses.
pub fn group_policy(allowed_apps: Option<Vec<String>>) -> Policy {
    Policy::Member(MemberPolicy {
        public_read: false,
        public_write: false,
        allowed_apps,
        publish_policy: true,
        publish_members: true,
    })
}

pub fn only_me_policy() -> Policy {
    Policy::Personal
}

/// A shared list's space. The key must be a TID.
pub fn list_space(owner: &str, skey: &str) -> Result<SpaceRef, UriError> {
    if !is_valid_tid(skey) {
        return Err(UriError::InvalidSkey);
    }
    SpaceRef::new(owner, LIST_SPACE_TYPE, skey)
}

/// The policy a shared list is created with: members are subscribers and
/// the member list stays unpublished.
pub fn list_policy(allowed_apps: Option<Vec<String>>) -> Policy {
    Policy::Member(MemberPolicy {
        public_read: false,
        public_write: false,
        allowed_apps,
        publish_policy: true,
        publish_members: false,
    })
}

/// A subscriber's access: read, never write.
pub fn subscriber() -> MemberAccess {
    MemberAccess {
        read: true,
        write: false,
    }
}

/// Check that `policy` is what a shared list must have. A published member
/// list would show subscribers to each other: `WrongPolicy`.
pub fn check_list_policy(space: &SpaceRef, policy: &Policy) -> Result<(), Misconfigured> {
    if space.space_type() != LIST_SPACE_TYPE {
        return Err(Misconfigured::NotUmbrae);
    }
    match policy {
        Policy::Member(p) if p.public_read => Err(Misconfigured::PublicRead),
        Policy::Member(p) if p.public_write => Err(Misconfigured::PublicWrite),
        Policy::Member(p) if !p.publish_policy => Err(Misconfigured::Unpublished),
        Policy::Member(p) if !p.publish_members && is_valid_tid(space.skey()) => Ok(()),
        _ => Err(Misconfigured::WrongPolicy),
    }
}

/// Why a space isn't one Umbrae will post into or show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misconfigured {
    NotUmbrae,
    /// Anyone could read it: posts there wouldn't be hidden.
    PublicRead,
    PublicWrite,
    /// A group must publish its policy and member list to its members.
    Unpublished,
    WrongPolicy,
    /// A labeler space must name the apps allowed to read it.
    NoAllowedApps,
}

/// Check that `policy` is what Umbrae expects for `space`. A client checks
/// before writing; a reader before showing.
pub fn check_policy(space: &SpaceRef, policy: &Policy) -> Result<(), Misconfigured> {
    if space.space_type() != SPACE_TYPE {
        return Err(Misconfigured::NotUmbrae);
    }
    if is_managed(space) {
        return match policy {
            Policy::Managed(p) if p.publish_policy => Ok(()),
            Policy::Managed(_) => Err(Misconfigured::Unpublished),
            _ => Err(Misconfigured::WrongPolicy),
        };
    }
    match (is_only_me(space), policy) {
        (true, Policy::Personal) => Ok(()),
        (false, Policy::Member(p)) if p.public_read => Err(Misconfigured::PublicRead),
        (false, Policy::Member(p)) if p.public_write => Err(Misconfigured::PublicWrite),
        (false, Policy::Member(p)) if !(p.publish_policy && p.publish_members) => {
            Err(Misconfigured::Unpublished)
        }
        (false, Policy::Member(_))
            if is_valid_tid(space.skey())
                || space.skey() == FOLLOWERS_SKEY
                || space.skey() == PROFILE_SKEY =>
        {
            Ok(())
        }
        _ => Err(Misconfigured::WrongPolicy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const SKEY: &str = "3mbbbbbbbbbb2";

    #[test]
    fn followers_space_is_a_group() {
        let f = followers_space(ALICE).unwrap();
        assert_eq!(f.skey(), FOLLOWERS_SKEY);
        assert!(!is_only_me(&f));
        assert_eq!(check_policy(&f, &group_policy(None)), Ok(()));
        assert_eq!(
            check_policy(&f, &only_me_policy()),
            Err(Misconfigured::WrongPolicy)
        );
        assert_eq!(
            check_policy(&f, &list_policy(None)),
            Err(Misconfigured::Unpublished)
        );
        // Any other non-TID key is still refused.
        let odd = SpaceRef::new(ALICE, SPACE_TYPE, "friends").unwrap();
        assert_eq!(
            check_policy(&odd, &group_policy(None)),
            Err(Misconfigured::WrongPolicy)
        );
    }

    #[test]
    fn shared_lists() {
        let l = list_space(ALICE, SKEY).unwrap();
        assert_eq!(
            l.to_string(),
            format!("at:space/{ALICE}/{LIST_SPACE_TYPE}/{SKEY}")
        );
        assert!(list_space(ALICE, "self").is_err());
        let p = list_policy(None);
        assert_eq!(Policy::from_map(&p.to_map()).unwrap(), p);
        assert_eq!(check_list_policy(&l, &p), Ok(()));
        // Published members, a group's policy, public reads, wrong type.
        assert_eq!(
            check_list_policy(&l, &group_policy(None)),
            Err(Misconfigured::WrongPolicy)
        );
        assert_eq!(
            check_list_policy(&l, &only_me_policy()),
            Err(Misconfigured::WrongPolicy)
        );
        let mut open = list_policy(None);
        if let Policy::Member(m) = &mut open {
            m.public_read = true;
        }
        assert_eq!(check_list_policy(&l, &open), Err(Misconfigured::PublicRead));
        let mut unpublished = list_policy(None);
        if let Policy::Member(m) = &mut unpublished {
            m.publish_policy = false;
        }
        assert_eq!(
            check_list_policy(&l, &unpublished),
            Err(Misconfigured::Unpublished)
        );
        let mut writable = list_policy(None);
        if let Policy::Member(m) = &mut writable {
            m.public_write = true;
        }
        assert_eq!(
            check_list_policy(&l, &writable),
            Err(Misconfigured::PublicWrite)
        );
        let at_self = SpaceRef::new(ALICE, LIST_SPACE_TYPE, "self").unwrap();
        assert_eq!(
            check_list_policy(&at_self, &p),
            Err(Misconfigured::WrongPolicy)
        );
        let g = group_space(ALICE, SKEY).unwrap();
        assert_eq!(check_list_policy(&g, &p), Err(Misconfigured::NotUmbrae));
        // And a list space is never a group.
        assert_eq!(check_policy(&l, &p), Err(Misconfigured::NotUmbrae));
        assert!(subscriber().read && !subscriber().write);
    }

    #[test]
    fn community_spaces_and_their_policy() {
        const APP: &str = "did:web:app.example#umbrae_app";
        let art = CommunityRef::new(APP, "art").unwrap();
        let s = community_space(ALICE, &art).unwrap();
        assert_eq!(s.authority(), ALICE);
        assert_eq!(s.skey(), community_skey(&art));
        assert!(is_community_space(&s) && is_managed(&s));
        let p = managed_policy(APP);
        assert_eq!(check_community_policy(&s, &art, &p), Ok(()));
        // check_policy, which sees no ref, takes the shape as managed.
        assert_eq!(check_policy(&s, &p), Ok(()));
        assert_eq!(
            check_policy(&s, &group_policy(None)),
            Err(Misconfigured::WrongPolicy)
        );
        // The wrong app: a lookalike naming another app.
        assert_eq!(
            check_community_policy(
                &s,
                &art,
                &managed_policy("did:web:other.example#umbrae_app")
            ),
            Err(Misconfigured::WrongPolicy)
        );
        // The wrong key: another community's space, or a group.
        let music = CommunityRef::new(APP, "music").unwrap();
        assert_eq!(
            check_community_policy(&s, &music, &p),
            Err(Misconfigured::WrongPolicy)
        );
        assert_eq!(
            check_community_policy(&group_space(ALICE, SKEY).unwrap(), &art, &p),
            Err(Misconfigured::WrongPolicy)
        );
        // The wrong type, under the right key.
        let listy = SpaceRef::new(ALICE, LIST_SPACE_TYPE, s.skey()).unwrap();
        assert!(!is_community_space(&listy));
        assert_eq!(
            check_community_policy(&listy, &art, &p),
            Err(Misconfigured::NotUmbrae)
        );
        // Unpublished, or not managed.
        let unpublished = Policy::Managed(ManagedPolicy {
            managing_app: APP.into(),
            publish_policy: false,
        });
        assert_eq!(
            check_community_policy(&s, &art, &unpublished),
            Err(Misconfigured::Unpublished)
        );
        assert_eq!(
            check_community_policy(&s, &art, &group_policy(None)),
            Err(Misconfigured::WrongPolicy)
        );
        // The old fixed key is no community space.
        let old = SpaceRef::new(ALICE, SPACE_TYPE, "community").unwrap();
        assert!(!is_community_space(&old) && !is_managed(&old));
    }

    #[test]
    fn private_spaces_and_their_policy() {
        const APP: &str = "did:web:app.example#umbrae_app";
        let s = private_space(ALICE).unwrap();
        assert_eq!(
            s.to_string(),
            format!("at:space/{ALICE}/{PRIVATE_SPACE_TYPE}/self")
        );
        let p = managed_policy(APP);
        assert_eq!(check_private_policy(&s, APP, &p), Ok(()));
        // Another app, unpublished, not managed.
        assert_eq!(
            check_private_policy(&s, "did:web:other.example#umbrae_app", &p),
            Err(Misconfigured::WrongPolicy)
        );
        let unpublished = Policy::Managed(ManagedPolicy {
            managing_app: APP.into(),
            publish_policy: false,
        });
        assert_eq!(
            check_private_policy(&s, APP, &unpublished),
            Err(Misconfigured::Unpublished)
        );
        for other in [group_policy(None), only_me_policy()] {
            assert_eq!(
                check_private_policy(&s, APP, &other),
                Err(Misconfigured::WrongPolicy)
            );
        }
        // Another key, or another type at self.
        let elsewhere = SpaceRef::new(ALICE, PRIVATE_SPACE_TYPE, "other").unwrap();
        assert_eq!(
            check_private_policy(&elsewhere, APP, &p),
            Err(Misconfigured::WrongPolicy)
        );
        assert_eq!(
            check_private_policy(&only_me_space(ALICE).unwrap(), APP, &p),
            Err(Misconfigured::NotUmbrae)
        );
        // And it's never an Umbrae group.
        assert_eq!(check_policy(&s, &p), Err(Misconfigured::NotUmbrae));
    }

    #[test]
    fn private_and_public_uris_round_trip() {
        let public = PublicUri::parse(&format!("at://{ALICE}/app.bsky.feed.post/{SKEY}")).unwrap();
        let private = private_uri(&public).unwrap();
        assert_eq!(
            private.to_string(),
            format!("at:space/{ALICE}/{PRIVATE_SPACE_TYPE}/self/{ALICE}/app.bsky.feed.post/{SKEY}")
        );
        assert_eq!(public_uri(&private), Some(public.clone()));
        assert_eq!(
            public_uri(&private).unwrap().to_string(),
            public.to_string()
        );
        // Another account's record in the space has no public form; nor a
        // record in any other space.
        const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
        let bobs = private_space(ALICE)
            .unwrap()
            .record(BOB, "app.bsky.feed.post", SKEY)
            .unwrap();
        assert_eq!(public_uri(&bobs), None);
        let in_only_me = only_me_space(ALICE)
            .unwrap()
            .record(ALICE, "app.bsky.feed.post", SKEY)
            .unwrap();
        assert_eq!(public_uri(&in_only_me), None);
        let at_other_key = SpaceRef::new(ALICE, PRIVATE_SPACE_TYPE, "other")
            .unwrap()
            .record(ALICE, "app.bsky.feed.post", SKEY)
            .unwrap();
        assert_eq!(public_uri(&at_other_key), None);
    }

    #[test]
    fn spaces() {
        let g = group_space(ALICE, SKEY).unwrap();
        assert_eq!(
            g.to_string(),
            format!("at:space/{ALICE}/{SPACE_TYPE}/{SKEY}")
        );
        assert!(group_space(ALICE, "friends").is_err());
        assert!(group_space(ALICE, ONLY_ME_SKEY).is_err());
        assert!(is_only_me(&only_me_space(ALICE).unwrap()));
    }

    #[test]
    fn policies_round_trip_and_check() {
        let g = group_space(ALICE, SKEY).unwrap();
        let p = group_policy(None);
        assert_eq!(Policy::from_map(&p.to_map()).unwrap(), p);
        assert_eq!(check_policy(&g, &p), Ok(()));
        let me = only_me_space(ALICE).unwrap();
        assert_eq!(check_policy(&me, &only_me_policy()), Ok(()));
        assert_eq!(check_policy(&me, &p), Err(Misconfigured::WrongPolicy));
        assert_eq!(
            check_policy(&g, &only_me_policy()),
            Err(Misconfigured::WrongPolicy)
        );
    }

    #[test]
    fn refuses_public_or_unpublished_groups() {
        let g = group_space(ALICE, SKEY).unwrap();
        let with = |f: fn(&mut MemberPolicy)| {
            let mut p = match group_policy(None) {
                Policy::Member(p) => p,
                _ => unreachable!(),
            };
            f(&mut p);
            Policy::Member(p)
        };
        assert_eq!(
            check_policy(&g, &with(|p| p.public_read = true)),
            Err(Misconfigured::PublicRead)
        );
        assert_eq!(
            check_policy(&g, &with(|p| p.public_write = true)),
            Err(Misconfigured::PublicWrite)
        );
        assert_eq!(
            check_policy(&g, &with(|p| p.publish_members = false)),
            Err(Misconfigured::Unpublished)
        );
        let other = SpaceRef::new(ALICE, "com.example.space", SKEY).unwrap();
        assert_eq!(
            check_policy(&other, &group_policy(None)),
            Err(Misconfigured::NotUmbrae)
        );
    }
}
