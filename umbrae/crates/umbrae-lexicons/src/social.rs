//! Hidden profiles, hidden follows, thread gates and post gates.
//!
//! - `tools.umbrae.profile`: one copy per audience, at `self`. The owner
//!   writes it into its followers space, a group or its everyone space; a
//!   member writes its own into a community space. Never in only-me.
//! - `tools.umbrae.follow`: a DID, in the follower's own only-me space.
//! - `tools.umbrae.threadgate` and `tools.umbrae.postgate`: by a post's
//!   author, in the post's space, at the post's record key. They name
//!   hidden records only in `post`, `hiddenReplies` and
//!   `detachedEmbeddingUris`, and only posts in their own space.
//!
//! Gates are enforced where posts are shown, as on Bluesky: each member
//! writes into their own repo, so nothing stops a reply being written.

use crate::labeler::{blob, BlobRef};
use crate::validate::{bounded, datetime, is_datetime, mentions_space_uri, string, Invalid};
use crate::{COMMUNITY_SKEY, POST, SELF_RKEY};
use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{is_space_uri, is_valid_did, is_valid_tid, SpaceRecordUri, SpaceRef};

type Map = BTreeMap<String, Value>;

pub const RULE_MENTION: &str = "tools.umbrae.threadgate#mentionRule";
pub const RULE_FOLLOWING: &str = "tools.umbrae.threadgate#followingRule";
pub const RULE_FOLLOWER: &str = "tools.umbrae.threadgate#followerRule";
pub const RULE_LIST: &str = "tools.umbrae.threadgate#listRule";
pub const RULE_DISABLE: &str = "tools.umbrae.postgate#disableRule";

/// At most this many profile links, as on the public profile.
pub const MAX_PROFILE_LINKS: usize = 10;
/// A link title's limit in graphemes, as on the public profile.
pub const MAX_LINK_TITLE: usize = 30;
/// At most this many pronoun sets, as in `app.nearhorizon.actor.pronouns`.
pub const MAX_PRONOUN_SETS: usize = 10;
/// At most this many forms in one pronoun set.
pub const MAX_PRONOUN_FORMS: usize = 12;

/// An account's hidden profile, for its approved followers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Profile {
    pub display_name: Option<String>,
    pub description: Option<String>,
    /// The short form, for simple readers.
    pub pronouns: Option<String>,
    /// The full sets, as in `app.nearhorizon.actor.pronouns`. Empty sets
    /// show nothing, and hide the short form too.
    pub pronoun_sets: Option<Vec<PronounSet>>,
    /// `all` or `firstOnly`; anything else, or none, reads as `all`.
    pub pronoun_display_mode: Option<String>,
    pub website: Option<String>,
    /// Up to [`MAX_PROFILE_LINKS`], https only.
    pub links: Vec<ProfileLink>,
    pub avatar: Option<BlobRef>,
    pub avatar_alt: Option<String>,
    pub banner: Option<BlobRef>,
    pub banner_alt: Option<String>,
    pub created_at: String,
    /// When it last changed. Breaks ties between copies a viewer could see.
    pub updated_at: Option<String>,
}

/// One pronoun set: its forms, such as `["she", "her"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PronounSet {
    pub forms: Vec<String>,
}

/// One profile link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileLink {
    /// An https URL. Readers also hide general-purpose shorteners and
    /// duplicates when showing links, as the public side does.
    pub url: String,
    pub title: Option<String>,
    /// The site's icon, served through space `getBlob`.
    pub icon: Option<BlobRef>,
}

/// A hidden follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Follow {
    pub subject: String,
    pub created_at: String,
}

/// Who may reply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplyRule {
    Mention,
    /// The author's public or hidden follows.
    Following,
    /// Members of the author's followers space.
    Follower,
    /// One of the author's own personal lists, by record key.
    List(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Threadgate {
    pub post: SpaceRecordUri,
    /// `None`: everyone who can see the post. Empty: nobody.
    pub allow: Option<Vec<ReplyRule>>,
    pub hidden_replies: Vec<SpaceRecordUri>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Postgate {
    pub post: SpaceRecordUri,
    pub detached_embedding_uris: Vec<SpaceRecordUri>,
    /// Quoting is turned off.
    pub disable_quotes: bool,
    pub created_at: String,
}

pub(crate) fn profile(m: &Map, uri: &SpaceRecordUri) -> Result<Profile, Invalid> {
    // One copy per audience, at self: the owner's followers space, a
    // group, or its everyone space, written by the authority; or a member's
    // own copy in a community space. Never in only-me, which nobody else
    // reads.
    let space = uri.space();
    let placed = uri.rkey() == SELF_RKEY
        && space.skey() != SELF_RKEY
        && (space.skey() == COMMUNITY_SKEY || uri.author() == space.authority());
    if !placed {
        return Err(Invalid(
            "a hidden profile is its owner's, at self, in an audience space it writes to",
        ));
    }
    no_hidden(m)?;
    let website = string(m, "website", 0, 2048, 2048)?;
    if let Some(w) = &website {
        if !is_https(w) {
            return Err(Invalid("website must be an https URL"));
        }
    }
    Ok(Profile {
        display_name: string(m, "displayName", 0, 640, 64)?,
        description: string(m, "description", 0, 2560, 256)?,
        pronouns: string(m, "pronouns", 0, 200, 20)?,
        pronoun_sets: pronoun_sets(m.get("pronounSets"))?,
        pronoun_display_mode: string(m, "pronounDisplayMode", 1, 64, 64)?,
        website,
        links: links(m.get("links"))?,
        avatar: blob(m.get("avatar"))?,
        avatar_alt: string(m, "avatarAlt", 1, 20000, 2000)?,
        banner: blob(m.get("banner"))?,
        banner_alt: string(m, "bannerAlt", 1, 20000, 2000)?,
        created_at: datetime(m, "createdAt")?,
        updated_at: match m.get("updatedAt") {
            None => None,
            Some(Value::Text(t)) if is_datetime(t) => Some(t.clone()),
            Some(_) => return Err(Invalid("updatedAt must be an atproto datetime")),
        },
    })
}

fn is_https(url: &str) -> bool {
    url.len() > "https://".len()
        && url.len() <= 2048
        && url.starts_with("https://")
        && !url.contains(char::is_whitespace)
}

fn pronoun_sets(v: Option<&Value>) -> Result<Option<Vec<PronounSet>>, Invalid> {
    let sets = match v {
        None => return Ok(None),
        Some(Value::Array(a)) if a.len() <= MAX_PRONOUN_SETS => a,
        Some(_) => return Err(Invalid("pronounSets must be at most 10 sets")),
    };
    sets.iter()
        .map(|s| {
            let forms = match s {
                Value::Map(s) => match s.get("forms") {
                    Some(Value::Array(f)) if (1..=MAX_PRONOUN_FORMS).contains(&f.len()) => f,
                    _ => return Err(Invalid("a pronoun set has 1 to 12 forms")),
                },
                _ => return Err(Invalid("a pronoun set must be an object")),
            };
            Ok(PronounSet {
                forms: forms
                    .iter()
                    .map(|f| bounded(f, 1, 64, 24))
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect::<Result<_, _>>()
        .map(Some)
}

fn links(v: Option<&Value>) -> Result<Vec<ProfileLink>, Invalid> {
    let links = match v {
        None => return Ok(Vec::new()),
        Some(Value::Array(a)) if a.len() <= MAX_PROFILE_LINKS => a,
        Some(_) => return Err(Invalid("links must be at most 10")),
    };
    links
        .iter()
        .map(|l| {
            let Value::Map(l) = l else {
                return Err(Invalid("a link must be an object"));
            };
            let url = match l.get("url") {
                Some(u) => bounded(u, 1, 2048, 2048)?,
                None => return Err(Invalid("a link needs a url")),
            };
            if !is_https(&url) {
                return Err(Invalid("a link must be an https URL"));
            }
            Ok(ProfileLink {
                url,
                title: string(l, "title", 1, 300, MAX_LINK_TITLE)?,
                icon: blob(l.get("icon"))?,
            })
        })
        .collect()
}

pub(crate) fn follow(m: &Map, uri: &SpaceRecordUri) -> Result<Follow, Invalid> {
    let space = uri.space();
    if space.skey() != SELF_RKEY || uri.author() != space.authority() {
        return Err(Invalid(
            "a hidden follow lives in its owner's only-me space",
        ));
    }
    no_hidden(m)?;
    let subject = match m.get("subject") {
        Some(Value::Text(d)) if is_valid_did(d) => d.clone(),
        _ => return Err(Invalid("a follow's subject must be a DID")),
    };
    Ok(Follow {
        subject,
        created_at: datetime(m, "createdAt")?,
    })
}

pub(crate) fn threadgate(m: &Map, uri: &SpaceRecordUri) -> Result<Threadgate, Invalid> {
    let post = gated_post(m, uri)?;
    let hidden_replies = posts_here(m.get("hiddenReplies"), uri.space(), 300)?;
    let allow = match m.get("allow") {
        None => None,
        Some(Value::Array(rules)) if rules.len() <= 5 => Some(
            rules
                .iter()
                .map(reply_rule)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err(Invalid("allow must be an array of at most 5 rules")),
    };
    let mut rest = m.clone();
    for k in ["post", "hiddenReplies"] {
        rest.remove(k);
    }
    no_hidden(&rest)?;
    Ok(Threadgate {
        post,
        allow,
        hidden_replies,
        created_at: datetime(m, "createdAt")?,
    })
}

pub(crate) fn postgate(m: &Map, uri: &SpaceRecordUri) -> Result<Postgate, Invalid> {
    let post = gated_post(m, uri)?;
    let detached_embedding_uris = posts_here(m.get("detachedEmbeddingUris"), uri.space(), 50)?;
    let disable_quotes = match m.get("embeddingRules") {
        None => false,
        Some(Value::Array(rules)) if rules.len() <= 5 => {
            for r in rules {
                match r {
                    Value::Map(r) if r.len() == 1 && rule_type(r) == Some(RULE_DISABLE) => {}
                    _ => return Err(Invalid("unknown embedding rule")),
                }
            }
            !rules.is_empty()
        }
        Some(_) => return Err(Invalid("embeddingRules must be an array of at most 5")),
    };
    let mut rest = m.clone();
    for k in ["post", "detachedEmbeddingUris"] {
        rest.remove(k);
    }
    no_hidden(&rest)?;
    Ok(Postgate {
        post,
        detached_embedding_uris,
        disable_quotes,
        created_at: datetime(m, "createdAt")?,
    })
}

/// A gate's `post`: the post at the gate's own record key, by the gate's
/// author, in the gate's space.
fn gated_post(m: &Map, uri: &SpaceRecordUri) -> Result<SpaceRecordUri, Invalid> {
    if !is_valid_tid(uri.rkey()) {
        return Err(Invalid("record key must be a TID"));
    }
    let want = uri
        .space()
        .record(uri.author(), POST, uri.rkey())
        .map_err(|_| Invalid("malformed space record URI"))?;
    match m.get("post") {
        Some(Value::Text(s)) if SpaceRecordUri::parse(s).ok().as_ref() == Some(&want) => Ok(want),
        _ => Err(Invalid(
            "a gate's post is its author's post in the same space, at the same key",
        )),
    }
}

/// An optional array of URIs of posts in `space`.
fn posts_here(
    v: Option<&Value>,
    space: &SpaceRef,
    max: usize,
) -> Result<Vec<SpaceRecordUri>, Invalid> {
    let a = match v {
        None => return Ok(Vec::new()),
        Some(Value::Array(a)) if a.len() <= max => a,
        Some(_) => return Err(Invalid("too many or malformed post URIs")),
    };
    a.iter()
        .map(|v| match v {
            Value::Text(s) if is_space_uri(s) => match SpaceRecordUri::parse(s) {
                Ok(u) if u.space() == space && u.collection() == POST => Ok(u),
                _ => Err(Invalid("a gated post must be in the same space")),
            },
            _ => Err(Invalid("a gated post must be in the same space")),
        })
        .collect()
}

fn reply_rule(v: &Value) -> Result<ReplyRule, Invalid> {
    let r = match v {
        Value::Map(r) => r,
        _ => return Err(Invalid("a reply rule must be an object")),
    };
    match rule_type(r) {
        Some(RULE_MENTION) => Ok(ReplyRule::Mention),
        Some(RULE_FOLLOWING) => Ok(ReplyRule::Following),
        Some(RULE_FOLLOWER) => Ok(ReplyRule::Follower),
        Some(RULE_LIST) => match r.get("list") {
            Some(Value::Text(k)) if is_valid_tid(k) => Ok(ReplyRule::List(k.clone())),
            _ => Err(Invalid(
                "a list rule names the author's own list by TID key",
            )),
        },
        _ => Err(Invalid("unknown reply rule")),
    }
}

fn rule_type(r: &Map) -> Option<&str> {
    match r.get("$type") {
        Some(Value::Text(t)) => Some(t.as_str()),
        _ => None,
    }
}

fn no_hidden(m: &Map) -> Result<(), Invalid> {
    if mentions_space_uri(&Value::Map(m.clone())) {
        Err(Invalid("this record may not name a hidden record"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        validate_record, Record, EVERYONE_SKEY, FOLLOW, FOLLOWERS_SKEY, POSTGATE, PROFILE, SPACE_TYPE,
        THREADGATE,
    };
    use umbrae_core::cid::Cid;

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const GROUP: &str = "3mbbbbbbbbbb2";
    const OTHER: &str = "3mbbbbbbbbbb3";
    const RKEY: &str = "3mbaaaaaaaaa2";
    const NOW: &str = "2026-11-20T10:00:00Z";

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn map(pairs: &[(&str, Value)]) -> Map {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn space(skey: &str) -> SpaceRef {
        SpaceRef::new(ALICE, SPACE_TYPE, skey).unwrap()
    }

    fn at(skey: &str, author: &str, collection: &str, rkey: &str) -> SpaceRecordUri {
        space(skey).record(author, collection, rkey).unwrap()
    }

    fn arr(items: &[String]) -> Value {
        Value::Array(items.iter().map(|s| t(s)).collect())
    }

    fn rule(ty: &str) -> Value {
        Value::Map(map(&[("$type", t(ty))]))
    }

    #[test]
    fn hidden_profile_only_in_the_followers_space() {
        let avatar = Value::Map(map(&[
            ("$type", t("blob")),
            ("ref", Value::Link(Cid::for_drisl(b"img"))),
            ("mimeType", t("image/png")),
            ("size", Value::Integer(10)),
        ]));
        let p = map(&[
            ("$type", t(PROFILE)),
            ("displayName", t("Alice")),
            ("pronouns", t("she/her")),
            ("website", t("https://example.com")),
            ("avatar", avatar),
            ("createdAt", t(NOW)),
        ]);
        assert!(matches!(
            validate_record(&at(FOLLOWERS_SKEY, ALICE, PROFILE, "self"), &p),
            Ok(Some(Record::Profile(pr))) if pr.avatar.is_some()
        ));
        // One copy per audience: followers, a group, everyone, and a
        // member's own copy in a community.
        for uri in [
            at(GROUP, ALICE, PROFILE, "self"),
            at(EVERYONE_SKEY, ALICE, PROFILE, "self"),
            at(COMMUNITY_SKEY, BOB, PROFILE, "self"),
        ] {
            assert!(validate_record(&uri, &p).is_ok(), "{uri}");
        }
        // Not in only-me, not someone else's elsewhere, not at a TID.
        for uri in [
            at("self", ALICE, PROFILE, "self"),
            at(GROUP, BOB, PROFILE, "self"),
            at(EVERYONE_SKEY, BOB, PROFILE, "self"),
            at(FOLLOWERS_SKEY, BOB, PROFILE, "self"),
            at(FOLLOWERS_SKEY, ALICE, PROFILE, RKEY),
        ] {
            assert!(validate_record(&uri, &p).is_err(), "{uri}");
        }
        let at_f = at(FOLLOWERS_SKEY, ALICE, PROFILE, "self");
        for (k, v) in [
            ("website", "http://example.com"),
            ("website", "https://"),
            ("pronouns", "a very long pronoun string indeed"),
        ] {
            let mut bad = p.clone();
            bad.insert(k.into(), t(v));
            assert!(validate_record(&at_f, &bad).is_err(), "{k}={v}");
        }
        let mut leak = p.clone();
        leak.insert(
            "description".into(),
            t(&at(GROUP, ALICE, POST, RKEY).to_string()),
        );
        assert!(validate_record(&at_f, &leak).is_err());
    }

    #[test]
    fn profile_pronoun_sets_links_and_alt_text() {
        let icon = Value::Map(map(&[
            ("$type", t("blob")),
            ("ref", Value::Link(Cid::for_drisl(b"ico"))),
            ("mimeType", t("image/png")),
            ("size", Value::Integer(10)),
        ]));
        let set = |forms: &[&str]| {
            Value::Map(map(&[(
                "forms",
                Value::Array(forms.iter().map(|f| t(f)).collect()),
            )]))
        };
        let link = |url: &str, title: Option<&str>, icon: Option<Value>| {
            let mut l = map(&[("url", t(url))]);
            if let Some(x) = title {
                l.insert("title".into(), t(x));
            }
            if let Some(i) = icon {
                l.insert("icon".into(), i);
            }
            Value::Map(l)
        };
        let p = map(&[
            ("$type", t(PROFILE)),
            ("pronouns", t("she/they")),
            (
                "pronounSets",
                Value::Array(vec![set(&["she", "her"]), set(&["they", "them"])]),
            ),
            ("pronounDisplayMode", t("firstOnly")),
            (
                "links",
                Value::Array(vec![
                    link("https://example.com/a", Some("Shop"), Some(icon)),
                    link("https://example.org", None, None),
                ]),
            ),
            ("avatarAlt", t("A cat on a keyboard")),
            ("bannerAlt", t("Mountains")),
            ("createdAt", t(NOW)),
        ]);
        let at_f = at(FOLLOWERS_SKEY, ALICE, PROFILE, "self");
        let Ok(Some(Record::Profile(pr))) = validate_record(&at_f, &p) else {
            panic!("profile should validate");
        };
        assert_eq!(pr.pronoun_sets.as_ref().map(Vec::len), Some(2));
        assert_eq!(pr.pronoun_sets.unwrap()[1].forms, ["they", "them"]);
        assert_eq!(pr.pronoun_display_mode.as_deref(), Some("firstOnly"));
        assert_eq!(pr.links.len(), 2);
        assert!(pr.links[0].icon.is_some() && pr.links[1].title.is_none());
        assert_eq!(pr.avatar_alt.as_deref(), Some("A cat on a keyboard"));
        assert_eq!(pr.banner_alt.as_deref(), Some("Mountains"));
        // Empty sets are allowed: they show nothing.
        let mut empty = p.clone();
        empty.insert("pronounSets".into(), Value::Array(vec![]));
        assert!(validate_record(&at_f, &empty).is_ok());

        let too_many_links = Value::Array(
            (0..=MAX_PROFILE_LINKS)
                .map(|i| link(&format!("https://example.com/{i}"), None, None))
                .collect(),
        );
        let too_many_sets = Value::Array((0..=MAX_PRONOUN_SETS).map(|_| set(&["xe"])).collect());
        let pdf = Value::Map(map(&[
            ("$type", t("blob")),
            ("ref", Value::Link(Cid::for_drisl(b"pdf"))),
            ("mimeType", t("application/pdf")),
            ("size", Value::Integer(10)),
        ]));
        for (k, v) in [
            (
                "links",
                Value::Array(vec![link("http://example.com", None, None)]),
            ),
            (
                "links",
                Value::Array(vec![link("javascript:alert(1)", None, None)]),
            ),
            (
                "links",
                Value::Array(vec![link(
                    "https://example.com",
                    Some(&"x".repeat(31)),
                    None,
                )]),
            ),
            (
                "links",
                Value::Array(vec![link("https://example.com", None, Some(pdf))]),
            ),
            ("links", Value::Array(vec![Value::Map(map(&[]))])),
            ("links", too_many_links),
            ("pronounSets", too_many_sets),
            ("pronounSets", Value::Array(vec![set(&[])])),
            ("pronounSets", Value::Array(vec![set(&[&"x".repeat(25)])])),
            ("avatarAlt", t("")),
            ("bannerAlt", t(&"x".repeat(2001))),
        ] {
            let mut bad = p.clone();
            bad.insert(k.into(), v.clone());
            assert!(validate_record(&at_f, &bad).is_err(), "{k}={v:?}");
        }
        // A hidden URI is refused in a link too.
        let mut leak = p.clone();
        leak.insert(
            "links".into(),
            Value::Array(vec![link(
                "https://example.com",
                Some(&at(GROUP, ALICE, POST, RKEY).to_string()),
                None,
            )]),
        );
        assert!(validate_record(&at_f, &leak).is_err());
    }

    #[test]
    fn hidden_follows_live_in_only_me() {
        let f = map(&[
            ("$type", t(FOLLOW)),
            ("subject", t(BOB)),
            ("createdAt", t(NOW)),
        ]);
        assert!(matches!(
            validate_record(&at("self", ALICE, FOLLOW, RKEY), &f),
            Ok(Some(Record::Follow(x))) if x.subject == BOB
        ));
        for uri in [
            at(GROUP, ALICE, FOLLOW, RKEY),
            at(FOLLOWERS_SKEY, ALICE, FOLLOW, RKEY),
            at("self", BOB, FOLLOW, RKEY),
            at("self", ALICE, FOLLOW, "self"),
        ] {
            assert!(validate_record(&uri, &f).is_err(), "{uri}");
        }
        let mut not_did = f.clone();
        not_did.insert("subject".into(), t("bob"));
        assert!(validate_record(&at("self", ALICE, FOLLOW, RKEY), &not_did).is_err());
        let mut via = f.clone();
        via.insert("via".into(), t(&at(GROUP, ALICE, POST, RKEY).to_string()));
        assert!(validate_record(&at("self", ALICE, FOLLOW, RKEY), &via).is_err());
    }

    #[test]
    fn threadgates() {
        let gate_at = at(GROUP, BOB, THREADGATE, RKEY);
        let post = at(GROUP, BOB, POST, RKEY).to_string();
        let reply = at(GROUP, ALICE, POST, "3mbaaaaaaaaa3").to_string();
        let g = |extra: &[(&str, Value)]| {
            let mut m = map(&[
                ("$type", t(THREADGATE)),
                ("post", t(&post)),
                ("createdAt", t(NOW)),
            ]);
            m.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
            m
        };
        match validate_record(&gate_at, &g(&[])).unwrap().unwrap() {
            Record::Threadgate(x) => assert!(x.allow.is_none()),
            other => panic!("{other:?}"),
        }
        let rules = Value::Array(vec![
            rule(RULE_MENTION),
            rule(RULE_FOLLOWING),
            rule(RULE_FOLLOWER),
            Value::Map(map(&[("$type", t(RULE_LIST)), ("list", t(RKEY))])),
        ]);
        match validate_record(
            &gate_at,
            &g(&[("allow", rules), ("hiddenReplies", arr(&[reply.clone()]))]),
        )
        .unwrap()
        .unwrap()
        {
            Record::Threadgate(x) => {
                assert_eq!(x.allow.unwrap().len(), 4);
                assert_eq!(x.hidden_replies.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        // Empty allow: nobody.
        match validate_record(&gate_at, &g(&[("allow", Value::Array(vec![]))]))
            .unwrap()
            .unwrap()
        {
            Record::Threadgate(x) => assert_eq!(x.allow, Some(vec![])),
            other => panic!("{other:?}"),
        }
        // The post must be the gate author's, at the gate's key, in this space.
        for p in [
            at(GROUP, ALICE, POST, RKEY).to_string(),
            at(GROUP, BOB, POST, "3mbaaaaaaaaa3").to_string(),
            at(OTHER, BOB, POST, RKEY).to_string(),
            at(GROUP, BOB, crate::LIKE, RKEY).to_string(),
        ] {
            let mut m = g(&[]);
            m.insert("post".into(), t(&p));
            assert!(validate_record(&gate_at, &m).is_err(), "{p}");
        }
        assert!(validate_record(&at(GROUP, BOB, THREADGATE, "self"), &g(&[])).is_err());
        // Hidden replies only in this space; nothing hidden elsewhere.
        let elsewhere = at(OTHER, ALICE, POST, RKEY).to_string();
        assert!(validate_record(
            &gate_at,
            &g(&[("hiddenReplies", arr(&[elsewhere.clone()]))])
        )
        .is_err());
        let public = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";
        assert!(
            validate_record(&gate_at, &g(&[("hiddenReplies", arr(&[public.into()]))])).is_err()
        );
        let sneaky_rule = Value::Array(vec![Value::Map(map(&[
            ("$type", t(RULE_MENTION)),
            ("note", t(&elsewhere)),
        ]))]);
        assert!(validate_record(&gate_at, &g(&[("allow", sneaky_rule)])).is_err());
        assert!(validate_record(&gate_at, &g(&[("via", t(&elsewhere))])).is_err());
        // Unknown rules and malformed list rules refuse.
        let unknown = Value::Array(vec![rule("tools.umbrae.threadgate#other")]);
        assert!(validate_record(&gate_at, &g(&[("allow", unknown)])).is_err());
        let bad_list = Value::Array(vec![Value::Map(map(&[
            ("$type", t(RULE_LIST)),
            ("list", t(&elsewhere)),
        ]))]);
        assert!(validate_record(&gate_at, &g(&[("allow", bad_list)])).is_err());
        let not_tid = Value::Array(vec![Value::Map(map(&[
            ("$type", t(RULE_LIST)),
            ("list", t("mutes")),
        ]))]);
        assert!(validate_record(&gate_at, &g(&[("allow", not_tid)])).is_err());
        // At most five rules, in an array.
        let five = Value::Array(vec![rule(RULE_MENTION); 5]);
        assert!(validate_record(&gate_at, &g(&[("allow", five)])).is_ok());
        let six = Value::Array(vec![rule(RULE_MENTION); 6]);
        assert!(validate_record(&gate_at, &g(&[("allow", six)])).is_err());
        assert!(validate_record(&gate_at, &g(&[("allow", rule(RULE_MENTION))])).is_err());
        // Hidden replies are posts, at most 300, as on Bluesky.
        let like_here = at(GROUP, ALICE, crate::LIKE, "3mbaaaaaaaaa3").to_string();
        assert!(validate_record(&gate_at, &g(&[("hiddenReplies", arr(&[like_here]))])).is_err());
        let most = vec![reply.clone(); 300];
        assert!(validate_record(&gate_at, &g(&[("hiddenReplies", arr(&most))])).is_ok());
        let too_many = vec![reply.clone(); 301];
        assert!(validate_record(&gate_at, &g(&[("hiddenReplies", arr(&too_many))])).is_err());
        // A gate at `self` that names a post at `self` still refuses.
        let mut at_self = g(&[]);
        at_self.insert("post".into(), t(&at(GROUP, BOB, POST, "self").to_string()));
        assert!(validate_record(&at(GROUP, BOB, THREADGATE, "self"), &at_self).is_err());
    }

    #[test]
    fn postgates() {
        let gate_at = at(GROUP, BOB, POSTGATE, RKEY);
        let post = at(GROUP, BOB, POST, RKEY).to_string();
        let quote = at(GROUP, ALICE, POST, "3mbaaaaaaaaa3").to_string();
        let g = |extra: &[(&str, Value)]| {
            let mut m = map(&[
                ("$type", t(POSTGATE)),
                ("post", t(&post)),
                ("createdAt", t(NOW)),
            ]);
            m.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
            m
        };
        match validate_record(
            &gate_at,
            &g(&[
                ("detachedEmbeddingUris", arr(&[quote.clone()])),
                ("embeddingRules", Value::Array(vec![rule(RULE_DISABLE)])),
            ]),
        )
        .unwrap()
        .unwrap()
        {
            Record::Postgate(x) => {
                assert!(x.disable_quotes);
                assert_eq!(x.detached_embedding_uris.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        match validate_record(&gate_at, &g(&[])).unwrap().unwrap() {
            Record::Postgate(x) => assert!(!x.disable_quotes),
            other => panic!("{other:?}"),
        }
        let elsewhere = at(OTHER, ALICE, POST, RKEY).to_string();
        assert!(validate_record(
            &gate_at,
            &g(&[("detachedEmbeddingUris", arr(&[elsewhere.clone()]))])
        )
        .is_err());
        let unknown = Value::Array(vec![rule("tools.umbrae.postgate#other")]);
        assert!(validate_record(&gate_at, &g(&[("embeddingRules", unknown)])).is_err());
        let sneaky = Value::Array(vec![Value::Map(map(&[
            ("$type", t(RULE_DISABLE)),
            ("note", t(&elsewhere)),
        ]))]);
        assert!(validate_record(&gate_at, &g(&[("embeddingRules", sneaky)])).is_err());
        let mut wrong = g(&[]);
        wrong.insert("post".into(), t(&at(GROUP, ALICE, POST, RKEY).to_string()));
        assert!(validate_record(&gate_at, &wrong).is_err());
        // Nothing beside `post` and `detachedEmbeddingUris` names a hidden
        // record: not a top-level field, nor one inside an unknown array.
        assert!(validate_record(&gate_at, &g(&[("via", t(&elsewhere))])).is_err());
        let prose = arr(&[format!("see {elsewhere}")]);
        assert!(validate_record(&gate_at, &g(&[("notes", prose)])).is_err());
        // Detached quotes are posts, at most 50.
        let like_here = at(GROUP, ALICE, crate::LIKE, "3mbaaaaaaaaa3").to_string();
        assert!(validate_record(
            &gate_at,
            &g(&[("detachedEmbeddingUris", arr(&[like_here]))])
        )
        .is_err());
        let most = vec![quote.clone(); 50];
        assert!(validate_record(&gate_at, &g(&[("detachedEmbeddingUris", arr(&most))])).is_ok());
        let too_many = vec![quote.clone(); 51];
        assert!(
            validate_record(&gate_at, &g(&[("detachedEmbeddingUris", arr(&too_many))])).is_err()
        );
        // At most five embedding rules; an empty list leaves quotes on.
        let six = Value::Array(vec![rule(RULE_DISABLE); 6]);
        assert!(validate_record(&gate_at, &g(&[("embeddingRules", six)])).is_err());
        match validate_record(&gate_at, &g(&[("embeddingRules", Value::Array(vec![]))]))
            .unwrap()
            .unwrap()
        {
            Record::Postgate(x) => assert!(!x.disable_quotes),
            other => panic!("{other:?}"),
        }
    }
}
