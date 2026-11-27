//! Record validation for synced Umbrae records.
//!
//! On top of each lexicon's constraints, these rules keep hidden data
//! inside its space:
//! - a hidden reply parent or root must be in the reply's own space;
//! - a public parent needs a public root (a public post can't reply to a
//!   hidden one);
//! - a like's or repost's subject is a hidden post in its own space;
//! - a record embed (a quote) names a public record or a hidden post in
//!   the quoting post's own space; nothing else in an embed points at a
//!   hidden record;
//! - in a community space, "its own space" widens to any space of the same
//!   type and community key: each member writes in their own space, so a
//!   reply, like, repost, quote or feed names records in others' spaces;
//! - a group record is the authority's own, at rkey `self`;
//! - a bookmark is the authority's own, in the only-me space (key `self`),
//!   and its subject is a hidden post (in any Umbrae space). Show it only
//!   while its owner may still see that post;
//! - an in-space label (`com.atproto.label.record`) is checked by
//!   [`crate::validate_space_label`].

use crate::community::{feed, list_subscription, Feed, ListSubscription, MAX_FEEDS_PER_POST};
use crate::list::{exemption, list, listitem, Exemption, List, ListItem};
use crate::social::{follow, postgate, profile, threadgate, Follow, Postgate, Profile, Threadgate};
use crate::space_label::{validate_space_label, SpaceLabel};
use crate::{
    is_community_skey, BOOKMARK, EXEMPTION, FEED, FOLLOW, GROUP, GROUP_RKEY, LIKE, LIST, LISTITEM,
    LIST_SUBSCRIPTION, POST, POSTGATE, PROFILE, REPOST, SELF_RKEY, SPACE_LABEL, SPACE_TYPE,
    THREADGATE,
};
use std::collections::BTreeMap;
use std::fmt;
use umbrae_core::cid::Cid;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{
    contains_space_uri, is_space_uri, is_valid_did, is_valid_nsid, is_valid_record_key,
    is_valid_tid, SpaceRecordUri, SpaceRef,
};
use unicode_segmentation::UnicodeSegmentation;

type Map = BTreeMap<String, Value>;

/// Why a record is dropped. Carries the rule, never the record's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid record: {}", self.0)
    }
}

impl std::error::Error for Invalid {}

/// A public record's `at://did/collection/rkey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicUri {
    pub did: String,
    pub collection: String,
    pub rkey: String,
}

impl PublicUri {
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("at://")?;
        let mut parts = rest.split('/');
        let (did, collection, rkey) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some()
            || !is_valid_did(did)
            || !is_valid_nsid(collection)
            || !is_valid_record_key(rkey)
        {
            return None;
        }
        Some(Self {
            did: did.to_owned(),
            collection: collection.to_owned(),
            rkey: rkey.to_owned(),
        })
    }
}

impl fmt::Display for PublicUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at://{}/{}/{}", self.did, self.collection, self.rkey)
    }
}

/// What a strong ref points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Hidden(SpaceRecordUri),
    Public(PublicUri),
}

impl Target {
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        if is_space_uri(s) {
            SpaceRecordUri::parse(s)
                .map(Target::Hidden)
                .map_err(|_| Invalid("malformed space record URI"))
        } else {
            PublicUri::parse(s)
                .map(Target::Public)
                .ok_or(Invalid("malformed record URI"))
        }
    }

    pub fn hidden(&self) -> Option<&SpaceRecordUri> {
        match self {
            Target::Hidden(u) => Some(u),
            Target::Public(_) => None,
        }
    }
}

/// `com.atproto.repo.strongRef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrongRef {
    pub target: Target,
    pub cid: Cid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub root: StrongRef,
    pub parent: StrongRef,
}

/// The parts of a post that Umbrae's rules use. The full value stays with
/// the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Post {
    pub text: String,
    pub created_at: String,
    pub reply: Option<Reply>,
    pub langs: Vec<String>,
    pub has_embed: bool,
    /// The quoted record, for `app.bsky.embed.record` and
    /// `app.bsky.embed.recordWithMedia`. A hidden one is always a post in
    /// this post's own space, or in a community, in the same community.
    pub quote: Option<StrongRef>,
    /// Community feeds it's sent to: `tools.umbrae.feed` records in this
    /// post's community, in any member's space. At most 3.
    pub feeds: Vec<StrongRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Like {
    pub subject: StrongRef,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

/// A repost of a hidden post, in that post's own space, or in a community,
/// in the reposter's own space for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repost {
    pub subject: StrongRef,
    pub created_at: String,
}

/// A bookmark of a hidden post, kept in the author's only-me space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    pub subject: StrongRef,
    pub created_at: String,
}

/// New record types may be added in a compatible release.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Record {
    Post(Box<Post>),
    Like(Like),
    Group(Group),
    Bookmark(Bookmark),
    Repost(Repost),
    /// A hidden list; its audience is its space's.
    List(List),
    ListItem(ListItem),
    Exemption(Exemption),
    /// A hidden profile, one per audience.
    Profile(Box<Profile>),
    /// A hidden follow, in only-me.
    Follow(Follow),
    Threadgate(Box<Threadgate>),
    Postgate(Box<Postgate>),
    /// A community feed.
    Feed(Box<Feed>),
    /// A list subscription, in only-me.
    ListSubscription(ListSubscription),
    /// An in-space label (`com.atproto.label.record`). Whose count is the
    /// reader's rule.
    SpaceLabel(Box<SpaceLabel>),
}

const EMBEDS: &[&str] = &[
    "app.bsky.embed.images",
    "app.bsky.embed.video",
    "app.bsky.embed.external",
    "app.bsky.embed.record",
    "app.bsky.embed.recordWithMedia",
];

/// Validate a record synced from a space, given its full URI.
///
/// `Ok(None)` for a collection that isn't Umbrae's (the PDS's published
/// policy and member records, or another app's): the caller handles or
/// ignores it.
pub fn validate_record(uri: &SpaceRecordUri, value: &Map) -> Result<Option<Record>, Invalid> {
    let space = uri.space();
    if space.space_type() != SPACE_TYPE {
        return Err(Invalid("not a tools.umbrae.space space"));
    }
    let collection = uri.collection();
    if ![
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
        LIST_SUBSCRIPTION,
        SPACE_LABEL,
    ]
    .contains(&collection)
    {
        return Ok(None);
    }
    if collection == SPACE_LABEL {
        return Ok(Some(Record::SpaceLabel(Box::new(validate_space_label(
            uri, value,
        )?))));
    }
    match value.get("$type") {
        Some(Value::Text(t)) if t == collection => {}
        _ => return Err(Invalid("$type must match the collection")),
    }
    Ok(Some(match collection {
        POST => {
            tid_key(uri)?;
            Record::Post(Box::new(post(value, space)?))
        }
        LIKE => {
            tid_key(uri)?;
            Record::Like(like(value, space)?)
        }
        PROFILE => Record::Profile(Box::new(profile(value, uri)?)),
        FOLLOW => {
            tid_key(uri)?;
            Record::Follow(follow(value, uri)?)
        }
        THREADGATE => Record::Threadgate(Box::new(threadgate(value, uri)?)),
        POSTGATE => Record::Postgate(Box::new(postgate(value, uri)?)),
        FEED => {
            tid_key(uri)?;
            Record::Feed(Box::new(feed(value, uri)?))
        }
        LIST_SUBSCRIPTION => {
            tid_key(uri)?;
            Record::ListSubscription(list_subscription(value, uri)?)
        }
        LIST | LISTITEM => {
            // A list's audience is its space's: only-me (the owner's own),
            // a group, a community or the owner's everyone space. Entries
            // name their list by key, in the same repo and space.
            tid_key(uri)?;
            if space.skey() == SELF_RKEY && uri.author() != space.authority() {
                return Err(Invalid("only-me holds only its owner's lists"));
            }
            match collection {
                LIST => Record::List(list(value)?),
                _ => Record::ListItem(listitem(value, true)?),
            }
        }
        EXEMPTION => {
            tid_key(uri)?;
            if space.skey() != SELF_RKEY || uri.author() != space.authority() {
                return Err(Invalid(
                    "exemptions live only in their owner's only-me space",
                ));
            }
            Record::Exemption(exemption(value, space.authority())?)
        }
        REPOST => {
            tid_key(uri)?;
            Record::Repost(repost(value, space)?)
        }
        BOOKMARK => {
            tid_key(uri)?;
            if space.skey() != GROUP_RKEY || uri.author() != space.authority() {
                return Err(Invalid(
                    "a bookmark lives only in its author's only-me space",
                ));
            }
            Record::Bookmark(bookmark(value)?)
        }
        _ => {
            if uri.author() != space.authority() || uri.rkey() != GROUP_RKEY {
                return Err(Invalid(
                    "group record must be the authority's, at rkey self",
                ));
            }
            Record::Group(group(value)?)
        }
    }))
}

fn tid_key(uri: &SpaceRecordUri) -> Result<(), Invalid> {
    if is_valid_tid(uri.rkey()) {
        Ok(())
    } else {
        Err(Invalid("record key must be a TID"))
    }
}

fn post(m: &Map, space: &SpaceRef) -> Result<Post, Invalid> {
    let text = string(m, "text", 0, 3000, 300)?.ok_or(Invalid("text is required"))?;
    let created_at = datetime(m, "createdAt")?;
    if let Some(f) = m.get("facets") {
        if !matches!(f, Value::Array(_)) {
            return Err(Invalid("facets must be an array"));
        }
    }
    let reply = match m.get("reply") {
        None => None,
        Some(Value::Map(r)) => {
            let root = strong_ref(r.get("root"))?;
            let parent = strong_ref(r.get("parent"))?;
            for t in [&root.target, &parent.target] {
                if let Target::Hidden(u) = t {
                    if !in_reach(space, u.space()) {
                        return Err(Invalid("a hidden reply target must be in the same space"));
                    }
                }
            }
            if matches!(parent.target, Target::Public(_))
                && matches!(root.target, Target::Hidden(_))
            {
                return Err(Invalid("a public parent can't have a hidden root"));
            }
            Some(Reply { root, parent })
        }
        Some(_) => return Err(Invalid("reply must be an object")),
    };
    let (has_embed, quote) = match m.get("embed") {
        None => (false, None),
        Some(Value::Map(e)) => (true, embed(e, space)?),
        Some(_) => return Err(Invalid("embed must be an object")),
    };
    let langs = match m.get("langs") {
        None => Vec::new(),
        Some(Value::Array(a)) if a.len() <= 3 => a
            .iter()
            .map(|l| match l {
                Value::Text(t) if is_language(t) => Ok(t.clone()),
                _ => Err(Invalid("langs entries must be language tags")),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(Invalid("langs must be an array of at most 3")),
    };
    let feeds = match m.get("feeds") {
        None => Vec::new(),
        Some(Value::Array(a)) if a.len() <= MAX_FEEDS_PER_POST => {
            if !is_community_skey(space.skey()) {
                return Err(Invalid("only a post in a community is sent to feeds"));
            }
            a.iter()
                .map(|f| {
                    let r = strong_ref(Some(f))?;
                    match &r.target {
                        Target::Hidden(u)
                            if in_reach(space, u.space()) && u.collection() == FEED =>
                        {
                            Ok(r)
                        }
                        _ => Err(Invalid("a post's feeds are feeds in its own community")),
                    }
                })
                .collect::<Result<_, _>>()?
        }
        Some(_) => return Err(Invalid("feeds must be an array of at most 3")),
    };
    Ok(Post {
        text,
        created_at,
        reply,
        langs,
        has_embed,
        quote,
        feeds,
    })
}

const MEDIA: &[&str] = &[
    "app.bsky.embed.images",
    "app.bsky.embed.video",
    "app.bsky.embed.external",
];

/// Check an embed and return the record it quotes, if any. The quoted
/// strong ref's `uri` is the only place in an embed that may name a hidden
/// record, and then only a post in `space` (or its community).
fn embed(e: &Map, space: &SpaceRef) -> Result<Option<StrongRef>, Invalid> {
    let ty = match e.get("$type") {
        Some(Value::Text(t)) if EMBEDS.contains(&t.as_str()) => t.as_str(),
        _ => return Err(Invalid("unsupported embed type")),
    };
    let mut rest = e.clone();
    let quoted = match ty {
        "app.bsky.embed.record" => Some(take_ref(&mut rest)?),
        "app.bsky.embed.recordWithMedia" => {
            let mut inner = match rest.remove("record") {
                Some(Value::Map(r)) => r,
                _ => return Err(Invalid("recordWithMedia needs a record object")),
            };
            let quoted = take_ref(&mut inner)?;
            match rest.get("media") {
                Some(Value::Map(media)) => match media.get("$type") {
                    Some(Value::Text(t)) if MEDIA.contains(&t.as_str()) => {}
                    _ => return Err(Invalid("unsupported media embed type")),
                },
                _ => return Err(Invalid("recordWithMedia needs a media object")),
            }
            rest.insert("record".to_owned(), Value::Map(inner));
            Some(quoted)
        }
        _ => None,
    };
    if mentions_space_uri(&Value::Map(rest)) {
        return Err(Invalid("an embed can't point at a hidden record"));
    }
    if let Some(q) = &quoted {
        if let Target::Hidden(u) = &q.target {
            if !in_reach(space, u.space()) || u.collection() != POST {
                return Err(Invalid("a quoted hidden post must be in the same space"));
            }
        }
    }
    Ok(quoted)
}

/// Parse `m.record` as a strong ref and remove its `uri` from `m`, so the
/// rest can be checked for hidden URIs.
fn take_ref(m: &mut Map) -> Result<StrongRef, Invalid> {
    let r = strong_ref(m.get("record"))?;
    if let Some(Value::Map(inner)) = m.get_mut("record") {
        inner.remove("uri");
    }
    Ok(r)
}

fn like(m: &Map, space: &SpaceRef) -> Result<Like, Invalid> {
    let subject = strong_ref(m.get("subject"))?;
    match &subject.target {
        Target::Hidden(u) if in_reach(space, u.space()) && u.collection() == POST => {}
        _ => return Err(Invalid("a like's subject must be a post in the same space")),
    }
    only_subject_is_hidden(m)?;
    Ok(Like {
        subject,
        created_at: datetime(m, "createdAt")?,
    })
}

fn repost(m: &Map, space: &SpaceRef) -> Result<Repost, Invalid> {
    let subject = strong_ref(m.get("subject"))?;
    match &subject.target {
        Target::Hidden(u) if in_reach(space, u.space()) && u.collection() == POST => {}
        _ => {
            return Err(Invalid(
                "a repost's subject must be a post in the same space",
            ))
        }
    }
    only_subject_is_hidden(m)?;
    Ok(Repost {
        subject,
        created_at: datetime(m, "createdAt")?,
    })
}

/// Refuse a record that names a hidden record anywhere but `subject.uri`
/// (in an extra field such as `via`): it would tell the space's members
/// that a post elsewhere exists, and where.
fn only_subject_is_hidden(m: &Map) -> Result<(), Invalid> {
    let mut rest = m.clone();
    if let Some(Value::Map(subject)) = rest.get_mut("subject") {
        subject.remove("uri");
    }
    if mentions_space_uri(&Value::Map(rest)) {
        return Err(Invalid("only the subject may name a hidden record"));
    }
    Ok(())
}

fn bookmark(m: &Map) -> Result<Bookmark, Invalid> {
    let subject = strong_ref(m.get("subject"))?;
    match &subject.target {
        Target::Hidden(u) if u.space().space_type() == SPACE_TYPE && u.collection() == POST => {}
        _ => return Err(Invalid("a bookmark's subject must be a hidden post")),
    }
    Ok(Bookmark {
        subject,
        created_at: datetime(m, "createdAt")?,
    })
}

fn group(m: &Map) -> Result<Group, Invalid> {
    let name = string(m, "name", 1, 640, 64)?.ok_or(Invalid("name is required"))?;
    Ok(Group {
        name,
        description: string(m, "description", 0, 3000, 300)?,
        created_at: datetime(m, "createdAt")?,
    })
}

/// Whether a record in `here` may name a hidden record in `target`: the
/// same space, or, in a community space, any space of the same type and
/// community key (another member's space for the same community).
pub(crate) fn in_reach(here: &SpaceRef, target: &SpaceRef) -> bool {
    target == here
        || (is_community_skey(here.skey())
            && target.space_type() == here.space_type()
            && target.skey() == here.skey())
}

pub(crate) fn strong_ref(v: Option<&Value>) -> Result<StrongRef, Invalid> {
    let m = match v {
        Some(Value::Map(m)) => m,
        _ => return Err(Invalid("strong ref must be an object")),
    };
    let (uri, cid) = match (m.get("uri"), m.get("cid")) {
        (Some(Value::Text(u)), Some(Value::Text(c))) => (u, c),
        _ => return Err(Invalid("strong ref needs uri and cid strings")),
    };
    Ok(StrongRef {
        target: Target::parse(uri)?,
        cid: Cid::parse(cid).map_err(|_| Invalid("strong ref cid"))?,
    })
}

pub(crate) fn mentions_space_uri(v: &Value) -> bool {
    match v {
        Value::Text(t) => contains_space_uri(t),
        Value::Array(a) => a.iter().any(mentions_space_uri),
        Value::Map(m) => m.values().any(mentions_space_uri),
        _ => false,
    }
}

/// An optional string field with lexicon `minLength`/`maxLength` (UTF-8
/// bytes) and `maxGraphemes`.
pub(crate) fn string(
    m: &Map,
    key: &str,
    min: usize,
    max_bytes: usize,
    max_graphemes: usize,
) -> Result<Option<String>, Invalid> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => bounded(v, min, max_bytes, max_graphemes).map(Some),
    }
}

/// A string value within byte and grapheme limits.
pub(crate) fn bounded(
    v: &Value,
    min: usize,
    max_bytes: usize,
    max_graphemes: usize,
) -> Result<String, Invalid> {
    match v {
        Value::Text(t) => {
            if t.len() < min || t.len() > max_bytes || t.graphemes(true).count() > max_graphemes {
                Err(Invalid("string length out of range"))
            } else {
                Ok(t.clone())
            }
        }
        _ => Err(Invalid("expected a string")),
    }
}

pub(crate) fn datetime(m: &Map, key: &str) -> Result<String, Invalid> {
    match m.get(key) {
        Some(Value::Text(t)) if is_datetime(t) => Ok(t.clone()),
        _ => Err(Invalid("createdAt must be an atproto datetime")),
    }
}

/// The atproto datetime profile of RFC 3339: `YYYY-MM-DDTHH:MM:SS`, an
/// optional fraction, and `Z` or a numeric offset (not `-00:00`).
pub(crate) fn is_datetime(s: &str) -> bool {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    if b.len() < 20
        || !digits(0..4)
        || b[4] != b'-'
        || !digits(5..7)
        || b[7] != b'-'
        || !digits(8..10)
        || b[10] != b'T'
        || !digits(11..13)
        || b[13] != b':'
        || !digits(14..16)
        || b[16] != b':'
        || !digits(17..19)
    {
        return false;
    }
    let num = |r: std::ops::Range<usize>| s[r].parse::<u32>().unwrap_or(99);
    if !(1..=12).contains(&num(5..7))
        || !(1..=31).contains(&num(8..10))
        || num(11..13) > 23
        || num(14..16) > 59
        || num(17..19) > 60
        || &s[0..4] == "0000"
    {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match &s[i..] {
        "Z" => true,
        off if off.len() == 6 => {
            let o = off.as_bytes();
            (o[0] == b'+' || o[0] == b'-')
                && o[1..3].iter().all(u8::is_ascii_digit)
                && o[3] == b':'
                && o[4..6].iter().all(u8::is_ascii_digit)
                && off != "-00:00"
        }
        _ => false,
    }
}

/// A loose BCP 47 check: alphanumeric subtags joined by `-`, primary
/// subtag 2–3 letters (or `i`/`x`).
pub(crate) fn is_language(s: &str) -> bool {
    let mut parts = s.split('-');
    let first = parts.next().unwrap_or("");
    let first_ok = (first.len() == 1 && (first == "i" || first == "x"))
        || ((2..=3).contains(&first.len()) && first.bytes().all(|c| c.is_ascii_alphabetic()));
    first_ok
        && parts
            .all(|p| !p.is_empty() && p.len() <= 8 && p.bytes().all(|c| c.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const SKEY: &str = "3mbbbbbbbbbb2";
    const OTHER_SKEY: &str = "3mbbbbbbbbbb3";
    const RKEY: &str = "3mbaaaaaaaaa2";
    const NOW: &str = "2026-11-13T10:00:00.000Z";

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

    fn uri(author: &str, collection: &str, rkey: &str) -> SpaceRecordUri {
        space(SKEY).record(author, collection, rkey).unwrap()
    }

    fn sref(uri: &str) -> Value {
        let cid = Cid::for_drisl(b"subject").to_string();
        Value::Map(map(&[("uri", t(uri)), ("cid", t(&cid))]))
    }

    fn hidden_post_uri(skey: &str) -> String {
        space(skey).record(ALICE, POST, RKEY).unwrap().to_string()
    }

    fn post_with(extra: &[(&str, Value)]) -> Map {
        let mut m = map(&[("$type", t(POST)), ("text", t("hi")), ("createdAt", t(NOW))]);
        m.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
        m
    }

    fn check(
        collection: &str,
        author: &str,
        rkey: &str,
        m: &Map,
    ) -> Result<Option<Record>, Invalid> {
        validate_record(&uri(author, collection, rkey), m)
    }

    #[test]
    fn plain_post() {
        let r = check(
            POST,
            BOB,
            RKEY,
            &post_with(&[("langs", Value::Array(vec![t("en")]))]),
        )
        .unwrap()
        .unwrap();
        match r {
            Record::Post(p) => {
                assert_eq!(p.text, "hi");
                assert_eq!(p.langs, ["en"]);
                assert!(p.reply.is_none());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_fields_and_collections() {
        let m = post_with(&[("tags", Value::Array(vec![t("x")]))]);
        assert!(check(POST, BOB, RKEY, &m).unwrap().is_some());
        let member = map(&[("read", Value::Bool(true))]);
        assert_eq!(
            check(
                "com.atproto.memberspace.member",
                ALICE,
                "did:plc:x",
                &member
            ),
            Ok(None)
        );
    }

    #[test]
    fn wrong_space_type_and_type_field() {
        let other = SpaceRef::new(ALICE, "com.example.space", SKEY).unwrap();
        let u = other.record(BOB, POST, RKEY).unwrap();
        assert!(validate_record(&u, &post_with(&[])).is_err());
        let mut m = post_with(&[]);
        m.insert("$type".into(), t(LIKE));
        assert!(check(POST, BOB, RKEY, &m).is_err());
        assert!(check(POST, BOB, "self", &post_with(&[])).is_err());
    }

    #[test]
    fn text_limits() {
        let long = "a".repeat(301);
        assert!(check(POST, BOB, RKEY, &post_with(&[("text", t(&long))])).is_err());
        // 300 graphemes of a 4-byte emoji is 1200 bytes: fine.
        let emoji = "😀".repeat(300);
        assert!(check(POST, BOB, RKEY, &post_with(&[("text", t(&emoji))])).is_ok());
        let m = map(&[("$type", t(POST)), ("createdAt", t(NOW))]);
        assert!(check(POST, BOB, RKEY, &m).is_err());
    }

    #[test]
    fn replies_stay_in_their_space() {
        let here = hidden_post_uri(SKEY);
        let there = hidden_post_uri(OTHER_SKEY);
        let public = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";
        let reply = |root: &str, parent: &str| {
            post_with(&[(
                "reply",
                Value::Map(map(&[("root", sref(root)), ("parent", sref(parent))])),
            )])
        };
        assert!(check(POST, BOB, RKEY, &reply(&here, &here)).is_ok());
        // A hidden reply to a public post, and a hidden reply under it.
        assert!(check(POST, BOB, RKEY, &reply(public, public)).is_ok());
        assert!(check(POST, BOB, RKEY, &reply(public, &here)).is_ok());
        assert_eq!(
            check(POST, BOB, RKEY, &reply(&there, &there)),
            Err(Invalid("a hidden reply target must be in the same space"))
        );
        assert_eq!(
            check(POST, BOB, RKEY, &reply(&here, public)),
            Err(Invalid("a public parent can't have a hidden root"))
        );
        assert!(check(POST, BOB, RKEY, &reply("at://not a uri", &here)).is_err());
        // The old at:// form of a hidden ref is refused, never read as public.
        let (did, rest) = here["at:space/".len()..].split_once('/').unwrap();
        let old = format!("at://{did}/space/{rest}");
        assert_eq!(
            check(POST, BOB, RKEY, &reply(&old, &old)),
            Err(Invalid("malformed space record URI"))
        );
    }

    #[test]
    fn embeds_never_point_at_hidden_records() {
        let quote = |u: &str| {
            post_with(&[(
                "embed",
                Value::Map(map(&[
                    ("$type", t("app.bsky.embed.record")),
                    ("record", sref(u)),
                ])),
            )])
        };
        let public = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";
        assert!(check(POST, BOB, RKEY, &quote(public)).is_ok());
        // Quoting a post in another group, or a hidden non-post, refuses.
        assert!(check(POST, BOB, RKEY, &quote(&hidden_post_uri(OTHER_SKEY))).is_err());
        let like_uri = space(SKEY).record(ALICE, LIKE, RKEY).unwrap().to_string();
        assert!(check(POST, BOB, RKEY, &quote(&like_uri)).is_err());
        // A link card whose URL carries another group's hidden post.
        let card = post_with(&[(
            "embed",
            Value::Map(map(&[
                ("$type", t("app.bsky.embed.external")),
                (
                    "external",
                    Value::Map(map(&[
                        (
                            "uri",
                            t(&format!(
                                "https://app.example/view?uri={}",
                                hidden_post_uri(OTHER_SKEY)
                            )),
                        ),
                        ("title", t("")),
                        ("description", t("")),
                    ])),
                ),
            ])),
        )]);
        assert!(check(POST, BOB, RKEY, &card).is_err());
        let odd = post_with(&[("embed", Value::Map(map(&[("$type", t("app.example.x"))])))]);
        assert!(check(POST, BOB, RKEY, &odd).is_err());
    }

    #[test]
    fn quotes_stay_in_their_space() {
        let same = hidden_post_uri(SKEY);
        let other = hidden_post_uri(OTHER_SKEY);
        let record = |u: &str| {
            post_with(&[(
                "embed",
                Value::Map(map(&[
                    ("$type", t("app.bsky.embed.record")),
                    ("record", sref(u)),
                ])),
            )])
        };
        match check(POST, BOB, RKEY, &record(&same)).unwrap().unwrap() {
            Record::Post(p) => {
                assert_eq!(p.quote.unwrap().target.hidden().unwrap().to_string(), same)
            }
            other => panic!("{other:?}"),
        }
        assert!(check(POST, BOB, RKEY, &record(&other)).is_err());
        // The quoted post's own URI is the only slot that may name it:
        // another hidden URI elsewhere in the strong ref still refuses.
        let mut sneaky = sref(&same);
        if let Value::Map(m) = &mut sneaky {
            m.insert("note".into(), t(&other));
        }
        let sneaky = post_with(&[(
            "embed",
            Value::Map(map(&[
                ("$type", t("app.bsky.embed.record")),
                ("record", sneaky),
            ])),
        )]);
        assert!(check(POST, BOB, RKEY, &sneaky).is_err());
        let images = Value::Map(map(&[
            ("$type", t("app.bsky.embed.images")),
            ("images", Value::Array(vec![])),
        ]));
        let with_media = |u: &str, media: Value| {
            post_with(&[(
                "embed",
                Value::Map(map(&[
                    ("$type", t("app.bsky.embed.recordWithMedia")),
                    ("record", Value::Map(map(&[("record", sref(u))]))),
                    ("media", media),
                ])),
            )])
        };
        assert!(check(POST, BOB, RKEY, &with_media(&same, images.clone())).is_ok());
        assert!(check(POST, BOB, RKEY, &with_media(&other, images.clone())).is_err());
        // In recordWithMedia too, another hidden URI beside the quoted one
        // refuses: in the strong ref, or in the record wrapper around it.
        let mut in_ref = sref(&same);
        if let Value::Map(m) = &mut in_ref {
            m.insert("note".into(), t(&other));
        }
        for wrapper in [
            map(&[("record", in_ref)]),
            map(&[("record", sref(&same)), ("note", t(&other))]),
        ] {
            let m = post_with(&[(
                "embed",
                Value::Map(map(&[
                    ("$type", t("app.bsky.embed.recordWithMedia")),
                    ("record", Value::Map(wrapper)),
                    ("media", images.clone()),
                ])),
            )]);
            assert!(check(POST, BOB, RKEY, &m).is_err());
        }
        // Media that names a hidden post, or that is itself a record embed.
        let card = Value::Map(map(&[
            ("$type", t("app.bsky.embed.external")),
            (
                "external",
                Value::Map(map(&[
                    ("uri", t(&other)),
                    ("title", t("")),
                    ("description", t("")),
                ])),
            ),
        ]));
        assert!(check(POST, BOB, RKEY, &with_media(&same, card)).is_err());
        // The nested record is public, so only the media type check can
        // refuse it.
        let nested = Value::Map(map(&[
            ("$type", t("app.bsky.embed.record")),
            (
                "record",
                sref("at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5"),
            ),
        ]));
        assert!(check(POST, BOB, RKEY, &with_media(&same, nested)).is_err());
        // A malformed quote refuses.
        let bare = post_with(&[(
            "embed",
            Value::Map(map(&[("$type", t("app.bsky.embed.record"))])),
        )]);
        assert!(check(POST, BOB, RKEY, &bare).is_err());
        // recordWithMedia without its record, or without its media.
        for (key, value) in [
            ("media", images.clone()),
            ("record", Value::Map(map(&[("record", sref(&same))]))),
        ] {
            let half = post_with(&[(
                "embed",
                Value::Map(map(&[
                    ("$type", t("app.bsky.embed.recordWithMedia")),
                    (key, value),
                ])),
            )]);
            assert!(check(POST, BOB, RKEY, &half).is_err());
        }
    }

    #[test]
    fn reposts() {
        let repost = |u: &str| {
            map(&[
                ("$type", t(REPOST)),
                ("subject", sref(u)),
                ("createdAt", t(NOW)),
            ])
        };
        assert!(matches!(
            check(REPOST, BOB, RKEY, &repost(&hidden_post_uri(SKEY))),
            Ok(Some(Record::Repost(_)))
        ));
        assert!(check(REPOST, BOB, RKEY, &repost(&hidden_post_uri(OTHER_SKEY))).is_err());
        let public = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";
        assert!(check(REPOST, BOB, RKEY, &repost(public)).is_err());
        let like_uri = space(SKEY).record(ALICE, LIKE, RKEY).unwrap().to_string();
        assert!(check(REPOST, BOB, RKEY, &repost(&like_uri)).is_err());
        assert!(check(REPOST, BOB, "self", &repost(&hidden_post_uri(SKEY))).is_err());
    }

    #[test]
    fn likes_and_reposts_name_no_other_hidden_record() {
        let other = hidden_post_uri(OTHER_SKEY);
        for collection in [LIKE, REPOST] {
            let mut m = map(&[
                ("$type", t(collection)),
                ("subject", sref(&hidden_post_uri(SKEY))),
                ("createdAt", t(NOW)),
            ]);
            assert!(check(collection, BOB, RKEY, &m).is_ok());
            m.insert("via".into(), sref(&other));
            assert!(check(collection, BOB, RKEY, &m).is_err());
            m.remove("via");
            if let Some(Value::Map(s)) = m.get_mut("subject") {
                s.insert("note".into(), t(&format!("see {other}")));
            }
            assert!(check(collection, BOB, RKEY, &m).is_err());
        }
    }

    #[test]
    fn likes() {
        let like = |u: &str| {
            map(&[
                ("$type", t(LIKE)),
                ("subject", sref(u)),
                ("createdAt", t(NOW)),
            ])
        };
        assert!(check(LIKE, BOB, RKEY, &like(&hidden_post_uri(SKEY))).is_ok());
        assert!(check(LIKE, BOB, RKEY, &like(&hidden_post_uri(OTHER_SKEY))).is_err());
        let public = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";
        assert!(check(LIKE, BOB, RKEY, &like(public)).is_err());
    }

    #[test]
    fn bookmarks_live_in_their_authors_only_me_space() {
        let bookmark = |u: &str| {
            map(&[
                ("$type", t(BOOKMARK)),
                ("subject", sref(u)),
                ("createdAt", t(NOW)),
            ])
        };
        let only_me = |author: &str| SpaceRef::new(author, SPACE_TYPE, "self").unwrap();
        let at = |space: &SpaceRef, author: &str, rkey: &str| {
            space.record(author, BOOKMARK, rkey).unwrap()
        };
        // Alice bookmarks a post from a group she reads, and one of her own
        // only-me posts.
        let group_post = hidden_post_uri(SKEY);
        let own = only_me(ALICE)
            .record(ALICE, POST, RKEY)
            .unwrap()
            .to_string();
        for subject in [&group_post, &own] {
            match validate_record(&at(&only_me(ALICE), ALICE, RKEY), &bookmark(subject)) {
                Ok(Some(Record::Bookmark(b))) => assert!(b.subject.target.hidden().is_some()),
                other => panic!("{other:?}"),
            }
        }
        // Not in a group space; not in someone else's only-me; not a TID key.
        assert!(check(BOOKMARK, ALICE, RKEY, &bookmark(&group_post)).is_err());
        assert!(validate_record(&at(&only_me(ALICE), BOB, RKEY), &bookmark(&group_post)).is_err());
        assert!(
            validate_record(&at(&only_me(ALICE), ALICE, "self"), &bookmark(&group_post)).is_err()
        );
        // Only hidden posts: no public posts, likes, or other space types.
        let public = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";
        let like = space(SKEY).record(BOB, LIKE, RKEY).unwrap().to_string();
        let elsewhere = SpaceRef::new(BOB, "com.example.space", "x")
            .unwrap()
            .record(BOB, POST, RKEY)
            .unwrap()
            .to_string();
        for bad in [public, like.as_str(), elsewhere.as_str()] {
            assert!(
                validate_record(&at(&only_me(ALICE), ALICE, RKEY), &bookmark(bad)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn community_records_name_other_members_spaces() {
        let skey = |key: &str| {
            crate::community_skey(
                &crate::CommunityRef::new("did:web:app.example#umbrae_app", key).unwrap(),
            )
        };
        let (art, music) = (skey("art"), skey("music"));
        // Alice's post in her space; Bob writes in his own.
        let alices = SpaceRef::new(ALICE, SPACE_TYPE, &art)
            .unwrap()
            .record(ALICE, POST, RKEY)
            .unwrap()
            .to_string();
        let bobs = SpaceRef::new(BOB, SPACE_TYPE, &art).unwrap();
        let in_bobs = |collection: &str, m: &Map| {
            validate_record(&bobs.record(BOB, collection, RKEY).unwrap(), m)
        };
        let reply = |target: &str| {
            post_with(&[(
                "reply",
                Value::Map(map(&[("root", sref(target)), ("parent", sref(target))])),
            )])
        };
        let quote = |target: &str| {
            post_with(&[(
                "embed",
                Value::Map(map(&[
                    ("$type", t("app.bsky.embed.record")),
                    ("record", sref(target)),
                ])),
            )])
        };
        let subject = |collection: &str, target: &str| {
            map(&[
                ("$type", t(collection)),
                ("subject", sref(target)),
                ("createdAt", t(NOW)),
            ])
        };
        assert!(
            matches!(in_bobs(POST, &reply(&alices)), Ok(Some(Record::Post(p))) if p.reply.is_some())
        );
        assert!(
            matches!(in_bobs(POST, &quote(&alices)), Ok(Some(Record::Post(p))) if p.quote.is_some())
        );
        assert!(in_bobs(LIKE, &subject(LIKE, &alices)).is_ok());
        assert!(in_bobs(REPOST, &subject(REPOST, &alices)).is_ok());
        // Another community's post, or a group's, is out of reach.
        for other in [
            SpaceRef::new(ALICE, SPACE_TYPE, &music).unwrap(),
            space(SKEY),
        ] {
            let there = other.record(ALICE, POST, RKEY).unwrap().to_string();
            assert!(in_bobs(POST, &reply(&there)).is_err(), "{there}");
            assert!(in_bobs(POST, &quote(&there)).is_err(), "{there}");
            assert!(in_bobs(LIKE, &subject(LIKE, &there)).is_err(), "{there}");
            assert!(
                in_bobs(REPOST, &subject(REPOST, &there)).is_err(),
                "{there}"
            );
        }
        // Another type under the same key is out of reach too.
        let list_type = SpaceRef::new(ALICE, crate::LIST_SPACE_TYPE, &art)
            .unwrap()
            .record(ALICE, POST, RKEY)
            .unwrap()
            .to_string();
        assert!(in_bobs(POST, &reply(&list_type)).is_err());
        // Outside community spaces, the same-space rule stands: Bob's group
        // can't name Alice's group of the same key.
        let alices_group = space(SKEY).record(ALICE, POST, RKEY).unwrap().to_string();
        let bobs_group = SpaceRef::new(BOB, SPACE_TYPE, SKEY).unwrap();
        let in_bobs_group =
            |m: &Map| validate_record(&bobs_group.record(BOB, POST, RKEY).unwrap(), m);
        assert!(in_bobs_group(&reply(&alices_group)).is_err());
        assert!(in_bobs_group(&quote(&alices_group)).is_err());
    }

    #[test]
    fn groups_belong_to_the_authority() {
        let g = map(&[
            ("$type", t(GROUP)),
            ("name", t("close friends")),
            ("createdAt", t(NOW)),
        ]);
        match check(GROUP, ALICE, GROUP_RKEY, &g).unwrap().unwrap() {
            Record::Group(g) => assert_eq!(g.name, "close friends"),
            other => panic!("{other:?}"),
        }
        assert!(check(GROUP, BOB, GROUP_RKEY, &g).is_err());
        assert!(check(GROUP, ALICE, RKEY, &g).is_err());
        let empty = map(&[("$type", t(GROUP)), ("name", t("")), ("createdAt", t(NOW))]);
        assert!(check(GROUP, ALICE, GROUP_RKEY, &empty).is_err());
    }

    #[test]
    fn datetimes() {
        for ok in [
            "2026-11-13T10:00:00Z",
            "2026-11-13T10:00:00.123456Z",
            "2026-11-13T10:00:00+05:30",
        ] {
            assert!(is_datetime(ok), "{ok}");
        }
        for bad in [
            "2026-11-13",
            "2026-11-13T10:00:00",
            "2026-13-13T10:00:00Z",
            "2026-11-13T10:00:00.Z",
            "2026-11-13T10:00:00-00:00",
            "2026-11-13 10:00:00Z",
            "0000-01-01T00:00:00Z",
        ] {
            assert!(!is_datetime(bad), "{bad}");
        }
    }

    #[test]
    fn languages() {
        assert!(is_language("en"));
        assert!(is_language("pt-BR"));
        assert!(is_language("zh-Hant-TW"));
        assert!(!is_language("english"));
        assert!(!is_language("en-"));
    }
}
