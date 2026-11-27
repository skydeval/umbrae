//! Lexicons for Umbrae (hidden posts and private labelers), and the checks
//! a reader applies to records it syncs from a space.
//!
//! | NSID | What |
//! |---|---|
//! | `tools.umbrae.space` | the space type: one author's hidden posts for one group |
//! | `tools.umbrae.post` | a hidden post (the fields of `app.bsky.feed.post`) |
//! | `tools.umbrae.like` | a like of a hidden post |
//! | `tools.umbrae.group` | the group's name, written by the authority |
//! | `tools.umbrae.repost` | a repost of a hidden post, in that post's space |
//! | `tools.umbrae.bookmark` | a bookmark of a hidden post, in the author's only-me space |
//! | `tools.umbrae.list` | a hidden list (block, mute or curate) |
//! | `tools.umbrae.listitem` | one account on a hidden list |
//! | `tools.umbrae.exemption` | don't apply a label, labeler or list to one account |
//! | `tools.umbrae.profile` | the hidden profile, for approved followers |
//! | `tools.umbrae.follow` | a hidden follow |
//! | `tools.umbrae.threadgate` | who may reply to a hidden post, and hidden replies |
//! | `tools.umbrae.postgate` | detached and disabled quotes of a hidden post |
//! | `tools.umbrae.feed` | an author-driven feed in a community |
//! | `tools.umbrae.listSubscription` | a subscription to a list, in only-me |
//! | `tools.umbrae.listSpace` | the space type: one shared list |
//! | `tools.umbrae.labeler` | the space type: one private labeler |
//! | `tools.umbrae.label` | a label (the fields of `com.atproto.label.defs#label`) |
//! | `tools.umbrae.labelerProfile` | the labeler's name, description and images |
//! | `tools.umbrae.labelerPolicies` | label values and definitions, report scope |
//! | `tools.umbrae.labelerReasons` | report reasons, localized |
//! | `tools.umbrae.labelerAudience` | a permitted list for restricted labels |
//!
//! Validation works on decoded DRISL maps, as they come out of a space
//! repo (STAR archive, `listRepoOps` or `getRecord`). Unknown fields are
//! allowed, as Lexicon evolution allows. A record that fails is dropped
//! from views; it is never an error for the space as a whole.

mod community;
mod labeler;
mod list;
mod migrate;
mod social;
mod validate;

pub use community::{
    validate_community_declaration, CommunityDeclaration, Feed, ListSubscription,
    MAX_FEEDS_PER_POST, MAX_FEED_AUTHORS,
};
pub use migrate::upgrade_space_uris;

pub use labeler::{
    is_public_subject, label_subject, validate_labeler_record, BlobRef, Label, LabelSubject,
    LabelerAudience, LabelerPolicies, LabelerProfile, LabelerReasons, LabelerRecord, Reason,
    ReasonGroup, ReasonStrings, RetiredKey,
};
pub use list::{
    validate_list_record, Exemption, ExemptionKind, List, ListItem, ListRecord, ListRef, Purpose,
    EXEMPTION_LABEL, EXEMPTION_LABELER, EXEMPTION_LIST,
};
pub use social::{
    Audience, Follow, Postgate, Profile, ProfileLink, PronounSet, ReplyRule, Threadgate,
    AUDIENCE_COMMUNITY, AUDIENCE_EVERYONE, AUDIENCE_FOLLOWERS, AUDIENCE_GROUP, MAX_LINK_TITLE,
    MAX_PROFILE_AUDIENCES, MAX_PROFILE_LINKS, MAX_PRONOUN_FORMS, MAX_PRONOUN_SETS, RULE_DISABLE,
    RULE_FOLLOWER, RULE_FOLLOWING, RULE_LIST, RULE_MENTION,
};
pub use validate::{
    validate_record, Bookmark, Group, Invalid, Like, Post, PublicUri, Record, Reply, Repost,
    StrongRef, Target,
};

pub const SPACE_TYPE: &str = "tools.umbrae.space";
pub const POST: &str = "tools.umbrae.post";
pub const LIKE: &str = "tools.umbrae.like";
pub const GROUP: &str = "tools.umbrae.group";
pub const BOOKMARK: &str = "tools.umbrae.bookmark";
pub const REPOST: &str = "tools.umbrae.repost";
pub const LIST: &str = "tools.umbrae.list";
pub const LISTITEM: &str = "tools.umbrae.listitem";
pub const EXEMPTION: &str = "tools.umbrae.exemption";
pub const PROFILE: &str = "tools.umbrae.profile";
pub const FOLLOW: &str = "tools.umbrae.follow";
pub const THREADGATE: &str = "tools.umbrae.threadgate";
pub const POSTGATE: &str = "tools.umbrae.postgate";
pub const FEED: &str = "tools.umbrae.feed";
pub const LIST_SUBSCRIPTION: &str = "tools.umbrae.listSubscription";
/// Community membership methods, served by a community's managing app.
pub const COMMUNITY_GET: &str = "tools.umbrae.community.getCommunity";
pub const COMMUNITY_JOIN: &str = "tools.umbrae.community.join";
pub const COMMUNITY_LEAVE: &str = "tools.umbrae.community.leave";
pub const COMMUNITY_LIST_MEMBERS: &str = "tools.umbrae.community.listMembers";
pub const COMMUNITY_DECIDE: &str = "tools.umbrae.community.decide";
pub const COMMUNITY_INVITE: &str = "tools.umbrae.community.invite";
pub const COMMUNITY_REMOVE: &str = "tools.umbrae.community.remove";
/// A community's public declaration of its managing app, at `self` in its
/// public repo.
pub const COMMUNITY_DECLARATION: &str = "tools.umbrae.community.declaration";
/// Reading a hidden profile through the viewer's serving app.
pub const ACTOR_GET_PROFILE: &str = "tools.umbrae.actor.getProfile";
pub const ACTOR_GET_PROFILE_BLOB: &str = "tools.umbrae.actor.getProfileBlob";
/// The followers space's key: a private account's approved followers.
pub const FOLLOWERS_SKEY: &str = "followers";
/// A community's space key: the space whose authority is the community's
/// own account, with membership held by its managing app.
pub const COMMUNITY_SKEY: &str = "community";
/// An account's "everyone with Umbrae" space key.
pub const EVERYONE_SKEY: &str = "everyone";
/// An account's profile space key: the one space that holds its hidden
/// profile. It has no members; the owner reads it as authority, and the
/// serving app on the owner's delegation, showing the profile to the
/// audiences it lists.
pub const PROFILE_SKEY: &str = "profile";
/// The space type of a shared list.
pub const LIST_SPACE_TYPE: &str = "tools.umbrae.listSpace";
/// The record key for singletons, and the labeler space's key.
pub const SELF_RKEY: &str = "self";
/// The group record's only record key.
pub const GROUP_RKEY: &str = SELF_RKEY;

pub const LABELER_SPACE_TYPE: &str = "tools.umbrae.labeler";
pub const LABEL: &str = "tools.umbrae.label";
pub const LABELER_PROFILE: &str = "tools.umbrae.labelerProfile";
pub const LABELER_POLICIES: &str = "tools.umbrae.labelerPolicies";
pub const LABELER_REASONS: &str = "tools.umbrae.labelerReasons";
pub const LABELER_AUDIENCE: &str = "tools.umbrae.labelerAudience";

/// Every Umbrae lexicon document, by NSID.
pub const LEXICONS: &[(&str, &str)] = &[
    (
        SPACE_TYPE,
        include_str!("../lexicons/tools/umbrae/space.json"),
    ),
    (POST, include_str!("../lexicons/tools/umbrae/post.json")),
    (LIKE, include_str!("../lexicons/tools/umbrae/like.json")),
    (GROUP, include_str!("../lexicons/tools/umbrae/group.json")),
    (REPOST, include_str!("../lexicons/tools/umbrae/repost.json")),
    (LIST, include_str!("../lexicons/tools/umbrae/list.json")),
    (
        LISTITEM,
        include_str!("../lexicons/tools/umbrae/listitem.json"),
    ),
    (
        EXEMPTION,
        include_str!("../lexicons/tools/umbrae/exemption.json"),
    ),
    (
        PROFILE,
        include_str!("../lexicons/tools/umbrae/profile.json"),
    ),
    (FOLLOW, include_str!("../lexicons/tools/umbrae/follow.json")),
    (
        THREADGATE,
        include_str!("../lexicons/tools/umbrae/threadgate.json"),
    ),
    (
        POSTGATE,
        include_str!("../lexicons/tools/umbrae/postgate.json"),
    ),
    (FEED, include_str!("../lexicons/tools/umbrae/feed.json")),
    (
        LIST_SUBSCRIPTION,
        include_str!("../lexicons/tools/umbrae/listSubscription.json"),
    ),
    (
        LIST_SPACE_TYPE,
        include_str!("../lexicons/tools/umbrae/listSpace.json"),
    ),
    (
        BOOKMARK,
        include_str!("../lexicons/tools/umbrae/bookmark.json"),
    ),
    (
        LABELER_SPACE_TYPE,
        include_str!("../lexicons/tools/umbrae/labeler.json"),
    ),
    (LABEL, include_str!("../lexicons/tools/umbrae/label.json")),
    (
        LABELER_PROFILE,
        include_str!("../lexicons/tools/umbrae/labelerProfile.json"),
    ),
    (
        LABELER_POLICIES,
        include_str!("../lexicons/tools/umbrae/labelerPolicies.json"),
    ),
    (
        LABELER_REASONS,
        include_str!("../lexicons/tools/umbrae/labelerReasons.json"),
    ),
    (
        LABELER_AUDIENCE,
        include_str!("../lexicons/tools/umbrae/labelerAudience.json"),
    ),
    (
        COMMUNITY_GET,
        include_str!("../lexicons/tools/umbrae/community/getCommunity.json"),
    ),
    (
        COMMUNITY_JOIN,
        include_str!("../lexicons/tools/umbrae/community/join.json"),
    ),
    (
        COMMUNITY_LEAVE,
        include_str!("../lexicons/tools/umbrae/community/leave.json"),
    ),
    (
        COMMUNITY_LIST_MEMBERS,
        include_str!("../lexicons/tools/umbrae/community/listMembers.json"),
    ),
    (
        COMMUNITY_DECIDE,
        include_str!("../lexicons/tools/umbrae/community/decide.json"),
    ),
    (
        COMMUNITY_INVITE,
        include_str!("../lexicons/tools/umbrae/community/invite.json"),
    ),
    (
        COMMUNITY_REMOVE,
        include_str!("../lexicons/tools/umbrae/community/remove.json"),
    ),
    (
        COMMUNITY_DECLARATION,
        include_str!("../lexicons/tools/umbrae/community/declaration.json"),
    ),
    (
        ACTOR_GET_PROFILE,
        include_str!("../lexicons/tools/umbrae/actor/getProfile.json"),
    ),
    (
        ACTOR_GET_PROFILE_BLOB,
        include_str!("../lexicons/tools/umbrae/actor/getProfileBlob.json"),
    ),
];

/// A lexicon document by NSID.
pub fn get(nsid: &str) -> Option<&'static str> {
    LEXICONS.iter().find(|(n, _)| *n == nsid).map(|(_, d)| *d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn documents_parse_and_carry_their_ids() {
        for (nsid, doc) in LEXICONS {
            let v: Value = serde_json::from_str(doc).unwrap();
            assert_eq!(v["lexicon"], 1, "{nsid}");
            assert_eq!(v["id"], *nsid);
            assert!(v["defs"]["main"].is_object(), "{nsid}");
        }
        assert!(get(POST).is_some());
        assert!(get("tools.umbrae.nope").is_none());
    }

    #[test]
    fn space_type_declares_its_collections() {
        let v: Value = serde_json::from_str(get(SPACE_TYPE).unwrap()).unwrap();
        let main = &v["defs"]["main"];
        assert_eq!(main["type"], "space");
        assert_eq!(main["key"], "any");
        let cols: Vec<_> = main["collections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(
            cols,
            [
                POST,
                LIKE,
                GROUP,
                BOOKMARK,
                REPOST,
                LIST,
                LISTITEM,
                EXEMPTION,
                PROFILE,
                FOLLOW,
                THREADGATE,
                POSTGATE,
                FEED,
                LIST_SUBSCRIPTION
            ]
        );
    }

    #[test]
    fn labeler_space_type_declares_its_collections() {
        let v: Value = serde_json::from_str(get(LABELER_SPACE_TYPE).unwrap()).unwrap();
        let main = &v["defs"]["main"];
        assert_eq!(main["type"], "space");
        assert_eq!(main["key"], "literal:self");
        let cols: Vec<_> = main["collections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(
            cols,
            [
                LABEL,
                LABELER_PROFILE,
                LABELER_POLICIES,
                LABELER_REASONS,
                LABELER_AUDIENCE
            ]
        );
    }
}
