//! Lexicons for Umbrae (hidden posts, private labelers and private
//! accounts), and the checks
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
//! | `tools.umbrae.private` | the space type: one private account's posts, reposts, likes and gates |
//! | `tools.umbrae.private.rules` | who may see a private account's records |
//! | `tools.umbrae.private.declaration` | in the public repo: the account is private, and its serving app |
//!
//! Validation works on decoded DRISL maps, as they come out of a space
//! repo (STAR archive, `listRepoOps` or `getRecord`). Unknown fields are
//! allowed, as Lexicon evolution allows. A record that fails is dropped
//! from views; it is never an error for the space as a whole.

mod community;
mod labeler;
mod list;
mod migrate;
mod private;
mod social;
mod validate;

pub use community::{
    community_skey, is_community_skey, CommunityRef, Feed, ListSubscription, MAX_FEEDS_PER_POST,
    MAX_FEED_AUTHORS,
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
pub use private::{validate_private_record, PrivatePost, PrivateRecord, Rule, Rules};
pub use social::{
    Audience, Follow, Postgate, Profile, ProfileLink, PronounSet, ReplyRule, Threadgate,
    AUDIENCE_COMMUNITY, AUDIENCE_EVERYONE, AUDIENCE_FOLLOWERS, AUDIENCE_GROUP, AUDIENCE_PRIVATE,
    MAX_LINK_TITLE, MAX_PROFILE_AUDIENCES, MAX_PROFILE_LINKS, MAX_PRONOUN_FORMS, MAX_PRONOUN_SETS,
    RULE_DISABLE, RULE_FOLLOWER, RULE_FOLLOWING, RULE_LIST, RULE_MENTION,
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
pub const COMMUNITY_LIST_MINE: &str = "tools.umbrae.community.listMyCommunities";
pub const COMMUNITY_REGISTER_SPACE: &str = "tools.umbrae.community.registerSpace";
pub const COMMUNITY_REGISTER_PROFILE: &str = "tools.umbrae.community.registerProfile";
/// Shared community definitions: `#communityRef` and `#unavailablePost`.
pub const COMMUNITY_DEFS: &str = "tools.umbrae.community.defs";
/// The placeholder a community app shows for a post the viewer can't see.
pub const UNAVAILABLE_POST: &str = "tools.umbrae.community.defs#unavailablePost";
/// Reading a hidden profile through the viewer's serving app.
pub const ACTOR_GET_PROFILE: &str = "tools.umbrae.actor.getProfile";
pub const ACTOR_GET_PROFILE_BLOB: &str = "tools.umbrae.actor.getProfileBlob";
/// The followers space's key: a private account's approved followers.
pub const FOLLOWERS_SKEY: &str = "followers";
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

/// The space type of a private account: one per account, at key `self`.
pub const PRIVATE_SPACE_TYPE: &str = "tools.umbrae.private";
pub const PRIVATE_RULES: &str = "tools.umbrae.private.rules";
pub const PRIVATE_DECLARATION: &str = "tools.umbrae.private.declaration";
/// Private-account methods, served by the account's serving app.
pub const PRIVATE_REGISTER: &str = "tools.umbrae.private.register";
pub const PRIVATE_UNREGISTER: &str = "tools.umbrae.private.unregister";
pub const PRIVATE_REQUEST_FOLLOW: &str = "tools.umbrae.private.requestFollow";
pub const PRIVATE_WITHDRAW_REQUEST: &str = "tools.umbrae.private.withdrawRequest";
pub const PRIVATE_LIST_REQUESTS: &str = "tools.umbrae.private.listRequests";
pub const PRIVATE_GET_ACCESS: &str = "tools.umbrae.private.getAccess";
pub const PRIVATE_LIST_RECORDS: &str = "tools.umbrae.private.listRecords";
pub const PRIVATE_GET_RECORDS: &str = "tools.umbrae.private.getRecords";
pub const PRIVATE_LIST_INTERACTIONS: &str = "tools.umbrae.private.listInteractions";
pub const PRIVATE_GET_BLOB: &str = "tools.umbrae.private.getBlob";
/// The native move, served by a PDS for the authenticated account.
pub const PRIVATE_MOVE: &str = "tools.umbrae.private.move";
/// The rule types of `tools.umbrae.private.rules`.
pub const PRIVATE_RULE_APPROVED_FOLLOWERS: &str = "tools.umbrae.private.rules#approvedFollowers";
pub const PRIVATE_RULE_FOLLOWING: &str = "tools.umbrae.private.rules#following";
pub const PRIVATE_RULE_MUTUALS: &str = "tools.umbrae.private.rules#mutuals";
pub const PRIVATE_RULE_LIST: &str = "tools.umbrae.private.rules#list";

/// The native collections a private space holds.
pub const BSKY_POST: &str = "app.bsky.feed.post";
pub const BSKY_REPOST: &str = "app.bsky.feed.repost";
pub const BSKY_LIKE: &str = "app.bsky.feed.like";
pub const BSKY_THREADGATE: &str = "app.bsky.feed.threadgate";
pub const BSKY_POSTGATE: &str = "app.bsky.feed.postgate";
/// A public list, as a `#list` rule names it.
pub const BSKY_LIST: &str = "app.bsky.graph.list";
/// Every collection of a private space.
pub const PRIVATE_COLLECTIONS: [&str; 6] = [
    BSKY_POST,
    BSKY_REPOST,
    BSKY_LIKE,
    BSKY_THREADGATE,
    BSKY_POSTGATE,
    PRIVATE_RULES,
];

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
        COMMUNITY_LIST_MINE,
        include_str!("../lexicons/tools/umbrae/community/listMyCommunities.json"),
    ),
    (
        COMMUNITY_REGISTER_SPACE,
        include_str!("../lexicons/tools/umbrae/community/registerSpace.json"),
    ),
    (
        COMMUNITY_REGISTER_PROFILE,
        include_str!("../lexicons/tools/umbrae/community/registerProfile.json"),
    ),
    (
        COMMUNITY_DEFS,
        include_str!("../lexicons/tools/umbrae/community/defs.json"),
    ),
    (
        ACTOR_GET_PROFILE,
        include_str!("../lexicons/tools/umbrae/actor/getProfile.json"),
    ),
    (
        ACTOR_GET_PROFILE_BLOB,
        include_str!("../lexicons/tools/umbrae/actor/getProfileBlob.json"),
    ),
    (
        PRIVATE_SPACE_TYPE,
        include_str!("../lexicons/tools/umbrae/private.json"),
    ),
    (
        PRIVATE_RULES,
        include_str!("../lexicons/tools/umbrae/private/rules.json"),
    ),
    (
        PRIVATE_DECLARATION,
        include_str!("../lexicons/tools/umbrae/private/declaration.json"),
    ),
    (
        PRIVATE_REGISTER,
        include_str!("../lexicons/tools/umbrae/private/register.json"),
    ),
    (
        PRIVATE_UNREGISTER,
        include_str!("../lexicons/tools/umbrae/private/unregister.json"),
    ),
    (
        PRIVATE_MOVE,
        include_str!("../lexicons/tools/umbrae/private/move.json"),
    ),
    (
        PRIVATE_REQUEST_FOLLOW,
        include_str!("../lexicons/tools/umbrae/private/requestFollow.json"),
    ),
    (
        PRIVATE_WITHDRAW_REQUEST,
        include_str!("../lexicons/tools/umbrae/private/withdrawRequest.json"),
    ),
    (
        PRIVATE_LIST_REQUESTS,
        include_str!("../lexicons/tools/umbrae/private/listRequests.json"),
    ),
    (
        PRIVATE_GET_ACCESS,
        include_str!("../lexicons/tools/umbrae/private/getAccess.json"),
    ),
    (
        PRIVATE_LIST_RECORDS,
        include_str!("../lexicons/tools/umbrae/private/listRecords.json"),
    ),
    (
        PRIVATE_GET_RECORDS,
        include_str!("../lexicons/tools/umbrae/private/getRecords.json"),
    ),
    (
        PRIVATE_LIST_INTERACTIONS,
        include_str!("../lexicons/tools/umbrae/private/listInteractions.json"),
    ),
    (
        PRIVATE_GET_BLOB,
        include_str!("../lexicons/tools/umbrae/private/getBlob.json"),
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
            // A defs document holds only named definitions.
            assert_eq!(
                v["defs"]["main"].is_object(),
                !nsid.ends_with(".defs"),
                "{nsid}"
            );
        }
        let defs: Value = serde_json::from_str(get(COMMUNITY_DEFS).unwrap()).unwrap();
        assert!(defs["defs"]["communityRef"].is_object());
        let (doc, name) = UNAVAILABLE_POST.split_once('#').unwrap();
        assert_eq!(doc, COMMUNITY_DEFS);
        assert!(defs["defs"][name].is_object());
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

    #[test]
    fn private_space_type_declares_its_collections() {
        let v: Value = serde_json::from_str(get(PRIVATE_SPACE_TYPE).unwrap()).unwrap();
        let main = &v["defs"]["main"];
        assert_eq!(main["type"], "space");
        assert_eq!(main["key"], "literal:self");
        let cols: Vec<_> = main["collections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(cols, PRIVATE_COLLECTIONS);
        // The rule types and the private audience are defined where their
        // NSIDs say.
        let rules: Value = serde_json::from_str(get(PRIVATE_RULES).unwrap()).unwrap();
        for ty in [
            PRIVATE_RULE_APPROVED_FOLLOWERS,
            PRIVATE_RULE_FOLLOWING,
            PRIVATE_RULE_MUTUALS,
            PRIVATE_RULE_LIST,
        ] {
            let (doc, name) = ty.split_once('#').unwrap();
            assert_eq!(doc, PRIVATE_RULES);
            assert!(rules["defs"][name].is_object(), "{ty}");
            assert!(
                rules["defs"]["main"]["record"]["properties"]["allow"]["items"]["refs"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::from(format!("#{name}")))
            );
        }
        let profile: Value = serde_json::from_str(get(PROFILE).unwrap()).unwrap();
        let (_, name) = AUDIENCE_PRIVATE.split_once('#').unwrap();
        assert!(profile["defs"][name].is_object());
        // Every record and method is listed, and the shared record def that
        // listRecords and listInteractions refer to exists.
        for nsid in [
            PRIVATE_DECLARATION,
            PRIVATE_REGISTER,
            PRIVATE_UNREGISTER,
            PRIVATE_MOVE,
            PRIVATE_REQUEST_FOLLOW,
            PRIVATE_WITHDRAW_REQUEST,
            PRIVATE_LIST_REQUESTS,
            PRIVATE_GET_ACCESS,
            PRIVATE_LIST_RECORDS,
            PRIVATE_GET_RECORDS,
            PRIVATE_LIST_INTERACTIONS,
            PRIVATE_GET_BLOB,
        ] {
            assert!(get(nsid).is_some(), "{nsid}");
        }
        let records: Value = serde_json::from_str(get(PRIVATE_GET_RECORDS).unwrap()).unwrap();
        assert!(records["defs"]["record"].is_object());
        assert!(records["defs"]["notFound"].is_object());
    }
}
