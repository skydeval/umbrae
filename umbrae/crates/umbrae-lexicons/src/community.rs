//! Communities: feeds and list subscriptions.
//!
//! A community is a `tools.umbrae.space` space with the key `community`,
//! whose authority is the community's own account and whose policy is a
//! `managedspace`. Its managing app holds membership: prism, or a PDS such
//! as Aurora-Locus that manages the space itself. Posts, replies, likes,
//! reposts and gates there follow the same rules as in a group.
//!
//! - `tools.umbrae.feed`: by any member, in the community space. It names
//!   who may send posts to it; posts name it in `feeds`.
//! - `tools.umbrae.listSubscription`: in the subscriber's own only-me
//!   space, naming a `tools.umbrae.list` in any Umbrae space.

use crate::labeler::{blob, BlobRef};
use crate::validate::{datetime, mentions_space_uri, string, strong_ref, Invalid, StrongRef, Target};
use crate::{COMMUNITY_SKEY, LIST, SELF_RKEY, SPACE_TYPE};
use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{is_valid_did, SpaceRecordUri};

type Map = BTreeMap<String, Value>;

/// At most this many accounts on a feed's author list.
pub const MAX_FEED_AUTHORS: usize = 5000;
/// At most this many feeds one post is sent to.
pub const MAX_FEEDS_PER_POST: usize = 3;

/// An author-driven feed in a community.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Feed {
    pub name: String,
    pub description: Option<String>,
    pub avatar: Option<BlobRef>,
    /// Who may send posts to it.
    pub authors: Vec<String>,
    pub created_at: String,
}

/// A subscription to a hidden list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListSubscription {
    /// A `tools.umbrae.list` in a `tools.umbrae.space` space.
    pub list: StrongRef,
    pub created_at: String,
}

pub(crate) fn feed(m: &Map, uri: &SpaceRecordUri) -> Result<Feed, Invalid> {
    if uri.space().skey() != COMMUNITY_SKEY {
        return Err(Invalid("a feed lives only in a community space"));
    }
    if mentions_space_uri(&Value::Map(m.clone())) {
        return Err(Invalid("a feed names no hidden record"));
    }
    let authors = match m.get("authors") {
        Some(Value::Array(a)) if a.len() <= MAX_FEED_AUTHORS => a
            .iter()
            .map(|d| match d {
                Value::Text(d) if is_valid_did(d) => Ok(d.clone()),
                _ => Err(Invalid("feed authors must be DIDs")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(Invalid("feed authors must be at most 5000 DIDs")),
    };
    Ok(Feed {
        name: string(m, "name", 1, 640, 64)?.ok_or(Invalid("a feed needs a name"))?,
        description: string(m, "description", 0, 3000, 300)?,
        avatar: blob(m.get("avatar"))?,
        authors,
        created_at: datetime(m, "createdAt")?,
    })
}

pub(crate) fn list_subscription(
    m: &Map,
    uri: &SpaceRecordUri,
) -> Result<ListSubscription, Invalid> {
    let space = uri.space();
    if space.skey() != SELF_RKEY || uri.author() != space.authority() {
        return Err(Invalid(
            "a list subscription lives only in its owner's only-me space",
        ));
    }
    let mut rest = m.clone();
    rest.remove("list");
    if mentions_space_uri(&Value::Map(rest)) {
        return Err(Invalid("a list subscription names a hidden record only in list"));
    }
    let list = strong_ref(m.get("list"))?;
    match &list.target {
        Target::Hidden(u) if u.space().space_type() == SPACE_TYPE && u.collection() == LIST => {}
        _ => {
            return Err(Invalid(
                "a list subscription names a tools.umbrae.list in an Umbrae space",
            ))
        }
    }
    Ok(ListSubscription {
        list,
        created_at: datetime(m, "createdAt")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{validate_record, Record, EVERYONE_SKEY, FEED, LIST_SUBSCRIPTION, POST};
    use umbrae_core::cid::Cid;
    use umbrae_core::uri::SpaceRef;

    const COMMUNITY: &str = "did:plc:communityccccccccccccccc";
    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const GROUP: &str = "3mbbbbbbbbbb2";
    const RKEY: &str = "3mbaaaaaaaaa2";
    const RKEY2: &str = "3mbaaaaaaaaa3";
    const NOW: &str = "2026-11-26T10:00:00Z";

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn map(pairs: &[(&str, Value)]) -> Map {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    fn at(authority: &str, skey: &str, author: &str, coll: &str, rkey: &str) -> SpaceRecordUri {
        SpaceRef::new(authority, SPACE_TYPE, skey)
            .unwrap()
            .record(author, coll, rkey)
            .unwrap()
    }

    fn sref(uri: &SpaceRecordUri) -> Value {
        Value::Map(map(&[
            ("uri", t(&uri.to_string())),
            ("cid", t(&Cid::for_drisl(b"x").to_string())),
        ]))
    }

    fn a_feed(authors: &[&str]) -> Map {
        map(&[
            ("$type", t(FEED)),
            ("name", t("Art")),
            (
                "authors",
                Value::Array(authors.iter().map(|a| t(a)).collect()),
            ),
            ("createdAt", t(NOW)),
        ])
    }

    fn a_post(feeds: Vec<Value>) -> Map {
        map(&[
            ("$type", t(POST)),
            ("text", t("hi")),
            ("feeds", Value::Array(feeds)),
            ("createdAt", t(NOW)),
        ])
    }

    #[test]
    fn feeds_live_in_communities() {
        let uri = at(COMMUNITY, COMMUNITY_SKEY, ALICE, FEED, RKEY);
        assert!(matches!(
            validate_record(&uri, &a_feed(&[ALICE, BOB])),
            Ok(Some(Record::Feed(f))) if f.authors == [ALICE, BOB] && f.name == "Art"
        ));
        for bad in [
            at(ALICE, GROUP, ALICE, FEED, RKEY),
            at(ALICE, EVERYONE_SKEY, ALICE, FEED, RKEY),
            at(COMMUNITY, COMMUNITY_SKEY, ALICE, FEED, "self"),
        ] {
            assert!(validate_record(&bad, &a_feed(&[ALICE])).is_err(), "{bad}");
        }
        let mut bad = a_feed(&[ALICE]);
        bad.insert("authors".into(), Value::Array(vec![t("alice.example")]));
        assert!(validate_record(&uri, &bad).is_err());
        let mut nameless = a_feed(&[ALICE]);
        nameless.remove("name");
        assert!(validate_record(&uri, &nameless).is_err());
        let mut leak = a_feed(&[ALICE]);
        leak.insert("description".into(), t(&uri.to_string()));
        assert!(validate_record(&uri, &leak).is_err());
    }

    #[test]
    fn posts_name_feeds_in_their_own_community() {
        let feed = at(COMMUNITY, COMMUNITY_SKEY, ALICE, FEED, RKEY);
        let post = at(COMMUNITY, COMMUNITY_SKEY, BOB, POST, RKEY2);
        let Ok(Some(Record::Post(p))) = validate_record(&post, &a_post(vec![sref(&feed)])) else {
            panic!("post should validate");
        };
        assert_eq!(p.feeds.len(), 1);
        // Not in a group; not a feed in another space; not something else;
        // not more than 3.
        let in_group = at(ALICE, GROUP, BOB, POST, RKEY2);
        assert!(validate_record(&in_group, &a_post(vec![sref(&feed)])).is_err());
        let elsewhere = at(BOB, COMMUNITY_SKEY, ALICE, FEED, RKEY);
        assert!(validate_record(&post, &a_post(vec![sref(&elsewhere)])).is_err());
        let a_post_ref = at(COMMUNITY, COMMUNITY_SKEY, ALICE, POST, RKEY);
        assert!(validate_record(&post, &a_post(vec![sref(&a_post_ref)])).is_err());
        assert!(validate_record(&post, &a_post(vec![sref(&feed); 4])).is_err());
        assert!(validate_record(&post, &a_post(vec![sref(&feed); 3])).is_ok());
    }

    #[test]
    fn list_subscriptions_live_in_only_me() {
        let list = at(ALICE, GROUP, ALICE, LIST, RKEY);
        let sub = map(&[
            ("$type", t(LIST_SUBSCRIPTION)),
            ("list", sref(&list)),
            ("createdAt", t(NOW)),
        ]);
        let uri = at(BOB, SELF_RKEY, BOB, LIST_SUBSCRIPTION, RKEY2);
        assert!(matches!(
            validate_record(&uri, &sub),
            Ok(Some(Record::ListSubscription(s))) if matches!(&s.list.target, Target::Hidden(u) if u == &list)
        ));
        for bad in [
            at(BOB, GROUP, BOB, LIST_SUBSCRIPTION, RKEY2),
            at(ALICE, SELF_RKEY, BOB, LIST_SUBSCRIPTION, RKEY2),
        ] {
            assert!(validate_record(&bad, &sub).is_err(), "{bad}");
        }
        // It names a list, and nothing else hidden.
        let not_a_list = at(ALICE, GROUP, ALICE, POST, RKEY);
        let mut wrong = sub.clone();
        wrong.insert("list".into(), sref(&not_a_list));
        assert!(validate_record(&uri, &wrong).is_err());
        let mut leak = sub.clone();
        leak.insert("note".into(), t(&list.to_string()));
        assert!(validate_record(&uri, &leak).is_err());
    }
}
