//! Communities: the community ref, its space key, feeds and list
//! subscriptions.
//!
//! A community is a membership kept by a managing app, named by
//! [`CommunityRef`] `{app, key}`. It has no account or repo. Each writer
//! keeps its records in their own `tools.umbrae.space` space, whose key is
//! [`community_skey`]: posts, replies, likes, reposts, quotes, feeds, gates
//! and shared lists. The app reads those spaces and assembles the
//! community.
//!
//! - `tools.umbrae.feed`: by a writer, in their own community space. It
//!   names who may send posts to it; posts in any member's space for the
//!   same community name it in `feeds`.
//! - `tools.umbrae.listSubscription`: in the subscriber's own only-me
//!   space, naming a `tools.umbrae.list` in any Umbrae space.

use crate::labeler::{blob, BlobRef};
use crate::validate::{
    datetime, mentions_space_uri, string, strong_ref, Invalid, StrongRef, Target,
};
use crate::{LIST, SELF_RKEY, SPACE_TYPE};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{is_valid_did, SpaceRecordUri};

type Map = BTreeMap<String, Value>;

/// At most this many accounts on a feed's author list.
pub const MAX_FEED_AUTHORS: usize = 5000;
/// At most this many feeds one post is sent to.
pub const MAX_FEEDS_PER_POST: usize = 3;

/// A community: `{app, key}`, `tools.umbrae.community.defs#communityRef`.
/// Two refs are the same community exactly when both parts are equal, byte
/// for byte.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommunityRef {
    app: String,
    key: String,
}

impl CommunityRef {
    /// `app` is the managing app's `did#serviceId`; `key` is
    /// `[a-z0-9][a-z0-9-]{0,62}`.
    pub fn new(app: &str, key: &str) -> Result<Self, Invalid> {
        if !is_service_ref(app) {
            return Err(Invalid(
                "a community's app must be a did#serviceId reference",
            ));
        }
        if !is_community_key(key) {
            return Err(Invalid(
                "a community's key is 1 to 63 lowercase letters, digits and hyphens",
            ));
        }
        Ok(Self {
            app: app.to_owned(),
            key: key.to_owned(),
        })
    }

    /// The managing app's service ref: the `atproto-proxy` target, and the
    /// `managingApp` of every member's community space.
    pub fn app(&self) -> &str {
        &self.app
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

fn is_service_ref(s: &str) -> bool {
    s.len() <= 2048
        && s.split_once('#').is_some_and(|(did, id)| {
            is_valid_did(did)
                && !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'~'))
        })
}

fn is_community_key(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// The key of every member's space for `community`: `c-` and the first 32
/// characters of base32lower-nopad(sha256("tools.umbrae.community\n" + app
/// + "\n" + key)). 34 characters, never TID-shaped.
pub fn community_skey(community: &CommunityRef) -> String {
    let digest = Sha256::digest(
        format!(
            "tools.umbrae.community\n{}\n{}",
            community.app, community.key
        )
        .as_bytes(),
    );
    let mut s = String::from("c-");
    s.push_str(&base32lower(&digest)[..32]);
    s
}

/// Whether `skey` has a community space key's shape: `c-` and 32
/// characters of `[a-z2-7]`. Only the app, which knows the ref, can check
/// that it's a given community's.
pub fn is_community_skey(skey: &str) -> bool {
    skey.strip_prefix("c-").is_some_and(|rest| {
        rest.len() == 32
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    })
}

/// RFC 4648 base32, lowercase, without padding.
fn base32lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// A `communityRef` object in a record.
pub(crate) fn community_ref(v: Option<&Value>) -> Result<CommunityRef, Invalid> {
    match v {
        Some(Value::Map(m)) => match (m.get("app"), m.get("key")) {
            (Some(Value::Text(app)), Some(Value::Text(key))) => CommunityRef::new(app, key),
            _ => Err(Invalid("a community ref needs app and key strings")),
        },
        _ => Err(Invalid("a community ref must be an object")),
    }
}

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
    if !is_community_skey(uri.space().skey()) {
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
        return Err(Invalid(
            "a list subscription names a hidden record only in list",
        ));
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
    use umbrae_core::uri::{is_valid_record_key, is_valid_tid, SpaceRef};

    const APP: &str = "did:web:app.example#umbrae_app";
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

    fn skey(key: &str) -> String {
        community_skey(&CommunityRef::new(APP, key).unwrap())
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
    fn community_refs() {
        assert!(CommunityRef::new(APP, "art").is_ok());
        assert!(CommunityRef::new(APP, "0-a").is_ok());
        assert!(CommunityRef::new(APP, &"a".repeat(63)).is_ok());
        for key in ["", "-art", "Art", "a_b", "a.b", &"a".repeat(64)] {
            assert!(CommunityRef::new(APP, key).is_err(), "{key:?}");
        }
        for app in [
            "did:web:app.example",
            "did:web:app.example#",
            "https://app.example#x",
            "did:web:app.example#a b",
        ] {
            assert!(CommunityRef::new(app, "art").is_err(), "{app}");
        }
        let v = Value::Map(map(&[("app", t(APP)), ("key", t("art"))]));
        assert_eq!(
            community_ref(Some(&v)),
            Ok(CommunityRef::new(APP, "art").unwrap())
        );
        assert!(community_ref(Some(&t(APP))).is_err());
        assert!(community_ref(None).is_err());
    }

    #[test]
    fn community_skeys() {
        let s = skey("art");
        // Deterministic, and the RFC 4648 lowercase alphabet.
        assert_eq!(s, "c-jp6l2tlwfzreu2sziihzejgq3u6ldy2d");
        assert_eq!(s, skey("art"));
        assert_eq!(s.len(), 34);
        assert!(is_community_skey(&s));
        assert!(is_valid_record_key(&s) && !is_valid_tid(&s));
        // Another key, or the same key at another app: another space.
        assert_ne!(s, skey("music"));
        let other = CommunityRef::new("did:web:other.example#umbrae_app", "art").unwrap();
        assert_ne!(s, community_skey(&other));
        // Another spelling of the same DID is another community.
        let spelled = CommunityRef::new("did:web:APP.example#umbrae_app", "art").unwrap();
        assert_ne!(s, community_skey(&spelled));
        for bad in [
            "community",
            "c-",
            "c-jp6l2tlwfzreu2sziihzejgq3u6ldy2",
            "c-jp6l2tlwfzreu2sziihzejgq3u6ldy2da",
            "c-JP6L2TLWFZREU2SZIIHZEJGQ3U6LDY2D",
            "c-jp6l2tlwfzreu2sziihzejgq3u6ldy21",
            "d-jp6l2tlwfzreu2sziihzejgq3u6ldy2d",
            GROUP,
        ] {
            assert!(!is_community_skey(bad), "{bad}");
        }
    }

    #[test]
    fn feeds_live_in_communities() {
        let uri = at(ALICE, &skey("art"), ALICE, FEED, RKEY);
        assert!(matches!(
            validate_record(&uri, &a_feed(&[ALICE, BOB])),
            Ok(Some(Record::Feed(f))) if f.authors == [ALICE, BOB] && f.name == "Art"
        ));
        for bad in [
            at(ALICE, GROUP, ALICE, FEED, RKEY),
            at(ALICE, EVERYONE_SKEY, ALICE, FEED, RKEY),
            at(ALICE, "community", ALICE, FEED, RKEY),
            at(ALICE, &skey("art"), ALICE, FEED, "self"),
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
        let art = skey("art");
        // Alice's feed, in her space; Bob's post, in his.
        let feed = at(ALICE, &art, ALICE, FEED, RKEY);
        let post = at(BOB, &art, BOB, POST, RKEY2);
        let Ok(Some(Record::Post(p))) = validate_record(&post, &a_post(vec![sref(&feed)])) else {
            panic!("post should validate");
        };
        assert_eq!(p.feeds.len(), 1);
        // Not in a group; not a feed in another community; not something
        // else; not more than 3.
        let in_group = at(ALICE, GROUP, BOB, POST, RKEY2);
        assert!(validate_record(&in_group, &a_post(vec![sref(&feed)])).is_err());
        let elsewhere = at(ALICE, &skey("music"), ALICE, FEED, RKEY);
        assert!(validate_record(&post, &a_post(vec![sref(&elsewhere)])).is_err());
        let a_post_ref = at(ALICE, &art, ALICE, POST, RKEY);
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
