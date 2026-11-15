//! Record validation for private labeler spaces (`tools.umbrae.labeler`).
//!
//! On top of each lexicon's constraints:
//! - only the authority's records count; any other repo's are refused;
//! - a label's `src` is the authority;
//! - a label's `uri` is a public subject (an `at://` account or record URI,
//!   or a DID), or a hidden post (a `tools.umbrae.post` in a
//!   `tools.umbrae.space` space); nothing else from inside a space;
//! - the profile, policies and reasons records sit at rkey `self`;
//! - a reason's `group`, if set, is one of the record's `groups`.

use crate::validate::{is_datetime, is_language, string, Invalid, PublicUri};
use crate::{
    LABEL, LABELER_POLICIES, LABELER_PROFILE, LABELER_REASONS, LABELER_SPACE_TYPE, POST, SELF_RKEY,
    SPACE_TYPE,
};
use std::collections::BTreeMap;
use umbrae_core::cid::Cid;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{is_space_uri, is_valid_did, is_valid_nsid, is_valid_tid, SpaceRecordUri};

type Map = BTreeMap<String, Value>;

/// A label, as `com.atproto.label.defs#label`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub ver: Option<i64>,
    pub src: String,
    pub uri: String,
    pub cid: Option<Cid>,
    pub val: String,
    pub neg: bool,
    pub cts: String,
    pub exp: Option<String>,
    pub sig: Option<Vec<u8>>,
}

/// The parts of a blob reference a reader needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef {
    pub cid: Cid,
    pub mime_type: String,
    pub size: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelerProfile {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub avatar: Option<BlobRef>,
    pub banner: Option<BlobRef>,
    pub created_at: String,
}

/// The policies record. `policies` keeps its full value (label values and
/// definitions, as `app.bsky.labeler.defs#labelerPolicies`) for the caller;
/// `label_values` is pulled out because readers filter on it.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelerPolicies {
    pub label_values: Vec<String>,
    pub policies: Map,
    pub reason_types: Option<Vec<String>>,
    pub subject_types: Option<Vec<String>>,
    pub subject_collections: Option<Vec<String>>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonStrings {
    pub lang: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    pub reason_type: String,
    /// The id of the group it's shown under, if the labeler groups them.
    pub group: Option<String>,
    pub locales: Vec<ReasonStrings>,
}

/// A heading reasons are grouped under in a report form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonGroup {
    pub id: String,
    pub locales: Vec<ReasonStrings>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelerReasons {
    pub reasons: Vec<Reason>,
    /// Empty when the labeler doesn't group its reasons.
    pub groups: Vec<ReasonGroup>,
    pub created_at: String,
}

/// What a label is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelSubject {
    /// A public account or record.
    Public,
    /// A hidden post. Show the label only to viewers who may see the post.
    HiddenPost(SpaceRecordUri),
}

#[derive(Debug, Clone, PartialEq)]
pub enum LabelerRecord {
    Label(Box<Label>),
    Profile(LabelerProfile),
    Policies(LabelerPolicies),
    Reasons(LabelerReasons),
}

/// Validate a record synced from a labeler space, given its full URI.
///
/// `Ok(None)` for a collection that isn't a labeler record (the PDS's
/// published policy and member records): the caller handles or ignores it.
pub fn validate_labeler_record(
    uri: &SpaceRecordUri,
    value: &Map,
) -> Result<Option<LabelerRecord>, Invalid> {
    let space = uri.space();
    if space.space_type() != LABELER_SPACE_TYPE || space.skey() != SELF_RKEY {
        return Err(Invalid("not a tools.umbrae.labeler space"));
    }
    let collection = uri.collection();
    if ![LABEL, LABELER_PROFILE, LABELER_POLICIES, LABELER_REASONS].contains(&collection) {
        return Ok(None);
    }
    if uri.author() != space.authority() {
        return Err(Invalid("only the labeler's own records count"));
    }
    match value.get("$type") {
        Some(Value::Text(t)) if t == collection => {}
        _ => return Err(Invalid("$type must match the collection")),
    }
    if collection == LABEL {
        if !is_valid_tid(uri.rkey()) {
            return Err(Invalid("record key must be a TID"));
        }
        return Ok(Some(LabelerRecord::Label(Box::new(label(
            value,
            space.authority(),
        )?))));
    }
    if uri.rkey() != SELF_RKEY {
        return Err(Invalid(
            "labeler profile, policies and reasons sit at rkey self",
        ));
    }
    Ok(Some(match collection {
        LABELER_PROFILE => LabelerRecord::Profile(profile(value)?),
        LABELER_POLICIES => LabelerRecord::Policies(policies(value)?),
        _ => LabelerRecord::Reasons(reasons(value)?),
    }))
}

/// Whether `uri` names a public label subject: an account (`at://did` or a
/// bare DID) or a public record.
pub fn is_public_subject(uri: &str) -> bool {
    if is_space_uri(uri) {
        return false;
    }
    if is_valid_did(uri) {
        return true;
    }
    match uri.strip_prefix("at://") {
        Some(did) if is_valid_did(did) => true,
        Some(_) => PublicUri::parse(uri).is_some(),
        None => false,
    }
}

/// What a label's `uri` names, or `None` if it may not be labelled: a
/// public subject, or a hidden post. A like, a group record, a space
/// without a record, or anything in another space type isn't allowed.
pub fn label_subject(uri: &str) -> Option<LabelSubject> {
    if !is_space_uri(uri) {
        return is_public_subject(uri).then_some(LabelSubject::Public);
    }
    let u = SpaceRecordUri::parse(uri).ok()?;
    (u.space().space_type() == SPACE_TYPE && u.collection() == POST)
        .then_some(LabelSubject::HiddenPost(u))
}

fn label(m: &Map, authority: &str) -> Result<Label, Invalid> {
    let src = text(m, "src")?.ok_or(Invalid("label src is required"))?;
    if src != authority {
        return Err(Invalid("label src must be the labeler"));
    }
    let uri = text(m, "uri")?.ok_or(Invalid("label uri is required"))?;
    if label_subject(&uri).is_none() {
        return Err(Invalid(
            "label uri must be a public account or record, or a hidden post",
        ));
    }
    let cid = match text(m, "cid")? {
        None => None,
        Some(c) => Some(Cid::parse(&c).map_err(|_| Invalid("label cid"))?),
    };
    let val = string(m, "val", 1, 128, 128)?.ok_or(Invalid("label val is required"))?;
    let neg = match m.get("neg") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(Invalid("label neg must be a boolean")),
    };
    let cts = datetime(m, "cts")?.ok_or(Invalid("label cts is required"))?;
    let exp = datetime(m, "exp")?;
    let ver = match m.get("ver") {
        None => None,
        Some(Value::Integer(v)) => Some(*v),
        Some(_) => return Err(Invalid("label ver must be an integer")),
    };
    let sig = match m.get("sig") {
        None => None,
        Some(Value::Bytes(b)) => Some(b.clone()),
        Some(_) => return Err(Invalid("label sig must be bytes")),
    };
    Ok(Label {
        ver,
        src,
        uri,
        cid,
        val,
        neg,
        cts,
        exp,
        sig,
    })
}

fn profile(m: &Map) -> Result<LabelerProfile, Invalid> {
    Ok(LabelerProfile {
        display_name: string(m, "displayName", 0, 640, 64)?,
        description: string(m, "description", 0, 2560, 256)?,
        avatar: blob(m.get("avatar"))?,
        banner: blob(m.get("banner"))?,
        created_at: created_at(m)?,
    })
}

const IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg"];
const MAX_IMAGE: i64 = 1_000_000;

fn blob(v: Option<&Value>) -> Result<Option<BlobRef>, Invalid> {
    let m = match v {
        None => return Ok(None),
        Some(Value::Map(m)) => m,
        Some(_) => return Err(Invalid("blob must be an object")),
    };
    match (
        m.get("$type"),
        m.get("ref"),
        m.get("mimeType"),
        m.get("size"),
    ) {
        (
            Some(Value::Text(t)),
            Some(Value::Link(cid)),
            Some(Value::Text(mime)),
            Some(Value::Integer(size)),
        ) if t == "blob" => {
            if !IMAGE_TYPES.contains(&mime.as_str()) || !(0..=MAX_IMAGE).contains(size) {
                return Err(Invalid("image must be png or jpeg, at most 1 MB"));
            }
            Ok(Some(BlobRef {
                cid: *cid,
                mime_type: mime.clone(),
                size: *size,
            }))
        }
        _ => Err(Invalid("malformed blob")),
    }
}

/// `identifier` values: `[a-z-]+`, at most 100. Global values (`!hide`)
/// may appear in `labelValues` but are never defined by a labeler.
fn is_label_identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'-')
}

fn policies(m: &Map) -> Result<LabelerPolicies, Invalid> {
    let p = match m.get("policies") {
        Some(Value::Map(p)) => p,
        _ => return Err(Invalid("policies is required")),
    };
    let label_values = match p.get("labelValues") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| match v {
                Value::Text(t) if !t.is_empty() && t.len() <= 128 => Ok(t.clone()),
                _ => Err(Invalid("labelValues entries must be label values")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(Invalid("policies.labelValues is required")),
    };
    match p.get("labelValueDefinitions") {
        None => {}
        Some(Value::Array(defs)) => {
            for d in defs {
                definition(d)?;
            }
        }
        Some(_) => return Err(Invalid("labelValueDefinitions must be an array")),
    }
    Ok(LabelerPolicies {
        label_values,
        policies: p.clone(),
        reason_types: strings(m, "reasonTypes", |_| true)?,
        subject_types: strings(m, "subjectTypes", |_| true)?,
        subject_collections: strings(m, "subjectCollections", is_valid_nsid)?,
        created_at: created_at(m)?,
    })
}

fn definition(v: &Value) -> Result<(), Invalid> {
    let d = match v {
        Value::Map(d) => d,
        _ => return Err(Invalid("a label definition must be an object")),
    };
    match d.get("identifier") {
        Some(Value::Text(t)) if is_label_identifier(t) => {}
        _ => return Err(Invalid("definition identifier must be [a-z-]+")),
    }
    for key in ["severity", "blurs"] {
        if !matches!(d.get(key), Some(Value::Text(_))) {
            return Err(Invalid("definition severity and blurs are required"));
        }
    }
    if !matches!(d.get("defaultSetting"), None | Some(Value::Text(_)))
        || !matches!(d.get("adultOnly"), None | Some(Value::Bool(_)))
    {
        return Err(Invalid("definition defaultSetting or adultOnly"));
    }
    match d.get("locales") {
        Some(Value::Array(ls)) => {
            for l in ls {
                localized(l, "name", 640, 64)?;
            }
            Ok(())
        }
        _ => Err(Invalid("definition locales is required")),
    }
}

fn reasons(m: &Map) -> Result<LabelerReasons, Invalid> {
    let list = match m.get("reasons") {
        Some(Value::Array(a)) if a.len() <= 500 => a,
        _ => return Err(Invalid("reasons must be an array of at most 500")),
    };
    let groups = match m.get("groups") {
        None => Vec::new(),
        Some(Value::Array(a)) if a.len() <= 100 => a
            .iter()
            .map(|g| {
                let g = match g {
                    Value::Map(g) => g,
                    _ => return Err(Invalid("a reason group must be an object")),
                };
                let id = string(g, "id", 1, 128, 128)?
                    .ok_or(Invalid("a reason group id is required"))?;
                let locales = match g.get("locales") {
                    Some(Value::Array(ls)) => ls
                        .iter()
                        .map(|l| localized(l, "title", 640, 64))
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => return Err(Invalid("reason group locales is required")),
                };
                Ok(ReasonGroup { id, locales })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(Invalid("groups must be an array of at most 100")),
    };
    let ids: std::collections::BTreeSet<&str> = groups.iter().map(|g| g.id.as_str()).collect();
    if ids.len() != groups.len() {
        return Err(Invalid("reason group ids must be unique"));
    }
    let reasons = list
        .iter()
        .map(|r| {
            let r = match r {
                Value::Map(r) => r,
                _ => return Err(Invalid("a reason must be an object")),
            };
            let reason_type = match r.get("type") {
                Some(Value::Text(t)) if !t.is_empty() => t.clone(),
                _ => return Err(Invalid("a reason type is required")),
            };
            let group = string(r, "group", 1, 128, 128)?;
            if group.as_deref().is_some_and(|g| !ids.contains(g)) {
                return Err(Invalid("a reason's group must be defined in groups"));
            }
            let locales = match r.get("locales") {
                Some(Value::Array(ls)) => ls
                    .iter()
                    .map(|l| localized(l, "title", 640, 64))
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(Invalid("reason locales is required")),
            };
            Ok(Reason {
                reason_type,
                group,
                locales,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LabelerReasons {
        reasons,
        groups,
        created_at: created_at(m)?,
    })
}

/// `{lang, <title_key>, description}`, as label definitions and reasons
/// localize their strings.
fn localized(
    v: &Value,
    title_key: &str,
    title_bytes: usize,
    title_graphemes: usize,
) -> Result<ReasonStrings, Invalid> {
    let l = match v {
        Value::Map(l) => l,
        _ => return Err(Invalid("localized strings must be an object")),
    };
    let lang = match l.get("lang") {
        Some(Value::Text(t)) if is_language(t) => t.clone(),
        _ => return Err(Invalid("localized lang must be a language tag")),
    };
    let title = string(l, title_key, 0, title_bytes, title_graphemes)?
        .ok_or(Invalid("localized title is required"))?;
    let description = string(l, "description", 0, 100_000, 10_000)?
        .ok_or(Invalid("localized description is required"))?;
    Ok(ReasonStrings {
        lang,
        title,
        description,
    })
}

fn strings(m: &Map, key: &str, ok: impl Fn(&str) -> bool) -> Result<Option<Vec<String>>, Invalid> {
    match m.get(key) {
        None => Ok(None),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| match v {
                Value::Text(t) if ok(t) => Ok(t.clone()),
                _ => Err(Invalid("expected an array of strings")),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(Invalid("expected an array")),
    }
}

fn text(m: &Map, key: &str) -> Result<Option<String>, Invalid> {
    match m.get(key) {
        None => Ok(None),
        Some(Value::Text(t)) => Ok(Some(t.clone())),
        Some(_) => Err(Invalid("expected a string")),
    }
}

fn datetime(m: &Map, key: &str) -> Result<Option<String>, Invalid> {
    match m.get(key) {
        None => Ok(None),
        Some(Value::Text(t)) if is_datetime(t) => Ok(Some(t.clone())),
        Some(_) => Err(Invalid("expected an atproto datetime")),
    }
}

fn created_at(m: &Map) -> Result<String, Invalid> {
    datetime(m, "createdAt")?.ok_or(Invalid("createdAt is required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbrae_core::uri::SpaceRef;

    const LABELER: &str = "did:plc:labelerllllllllllllllll";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const RKEY: &str = "3mbaaaaaaaaa2";
    const NOW: &str = "2026-11-14T10:00:00.000Z";
    const SUBJECT: &str = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn map(pairs: &[(&str, Value)]) -> Map {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn space() -> SpaceRef {
        SpaceRef::new(LABELER, LABELER_SPACE_TYPE, SELF_RKEY).unwrap()
    }

    fn check(
        collection: &str,
        author: &str,
        rkey: &str,
        m: &Map,
    ) -> Result<Option<LabelerRecord>, Invalid> {
        validate_labeler_record(&space().record(author, collection, rkey).unwrap(), m)
    }

    fn label_with(extra: &[(&str, Value)]) -> Map {
        let mut m = map(&[
            ("$type", t(LABEL)),
            ("ver", Value::Integer(1)),
            ("src", t(LABELER)),
            ("uri", t(SUBJECT)),
            ("val", t("spam")),
            ("cts", t(NOW)),
        ]);
        m.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
        m
    }

    #[test]
    fn labels() {
        match check(LABEL, LABELER, RKEY, &label_with(&[]))
            .unwrap()
            .unwrap()
        {
            LabelerRecord::Label(l) => {
                assert_eq!(l.val, "spam");
                assert!(!l.neg);
                assert_eq!(l.ver, Some(1));
            }
            other => panic!("{other:?}"),
        }
        let neg = label_with(&[("neg", Value::Bool(true)), ("exp", t(NOW))]);
        assert!(check(LABEL, LABELER, RKEY, &neg).is_ok());
        // Someone else's repo, someone else's src, a non-TID key.
        assert!(check(LABEL, BOB, RKEY, &label_with(&[])).is_err());
        assert!(check(LABEL, LABELER, RKEY, &label_with(&[("src", t(BOB))])).is_err());
        assert!(check(LABEL, LABELER, "self", &label_with(&[])).is_err());
        assert!(check(LABEL, LABELER, RKEY, &label_with(&[("val", t(""))])).is_err());
        assert!(check(LABEL, LABELER, RKEY, &label_with(&[("sig", t("x"))])).is_err());
    }

    #[test]
    fn label_subjects_are_public() {
        for ok in [
            SUBJECT,
            "did:plc:carolcccccccccccccccccccc",
            "at://did:plc:carolcccccccccccccccccccc",
        ] {
            assert!(is_public_subject(ok), "{ok}");
        }
        let hidden = SpaceRef::new(BOB, "tools.umbrae.space", "3mbbbbbbbbbb2")
            .unwrap()
            .record(BOB, "tools.umbrae.post", RKEY)
            .unwrap()
            .to_string();
        for bad in [hidden.as_str(), "https://example.com", "at://not a uri", ""] {
            assert!(!is_public_subject(bad), "{bad}");
        }
    }

    #[test]
    fn labels_on_hidden_posts_and_nothing_else_inside_a_space() {
        let group = SpaceRef::new(BOB, "tools.umbrae.space", "3mbbbbbbbbbb2").unwrap();
        let post = group.record(BOB, "tools.umbrae.post", RKEY).unwrap();
        assert_eq!(
            label_subject(&post.to_string()),
            Some(LabelSubject::HiddenPost(post.clone()))
        );
        assert_eq!(label_subject(SUBJECT), Some(LabelSubject::Public));
        assert!(check(
            LABEL,
            LABELER,
            RKEY,
            &label_with(&[("uri", t(&post.to_string()))])
        )
        .is_ok());
        let like = group.record(BOB, "tools.umbrae.like", RKEY).unwrap();
        let group_rec = group.record(BOB, "tools.umbrae.group", "self").unwrap();
        let elsewhere = SpaceRef::new(BOB, "com.example.space", "x")
            .unwrap()
            .record(BOB, "tools.umbrae.post", RKEY)
            .unwrap();
        let labeler_rec = SpaceRef::new(LABELER, LABELER_SPACE_TYPE, "self")
            .unwrap()
            .record(LABELER, "tools.umbrae.post", RKEY)
            .unwrap();
        for bad in [
            like.to_string(),
            group_rec.to_string(),
            elsewhere.to_string(),
            labeler_rec.to_string(),
            group.to_string(),
        ] {
            assert_eq!(label_subject(&bad), None, "{bad}");
            assert!(check(LABEL, LABELER, RKEY, &label_with(&[("uri", t(&bad))])).is_err());
        }
    }

    #[test]
    fn wrong_space_and_unknown_collections() {
        let other = SpaceRef::new(LABELER, "tools.umbrae.space", "3mbbbbbbbbbb2").unwrap();
        let u = other.record(LABELER, LABEL, RKEY).unwrap();
        assert!(validate_labeler_record(&u, &label_with(&[])).is_err());
        let member = map(&[("read", Value::Bool(true))]);
        assert_eq!(
            check(
                "com.atproto.memberspace.member",
                LABELER,
                "did:plc:x",
                &member
            ),
            Ok(None)
        );
    }

    #[test]
    fn profile_and_blobs() {
        let img = |mime: &str, size: i64| {
            Value::Map(map(&[
                ("$type", t("blob")),
                ("ref", Value::Link(Cid::for_drisl(b"img"))),
                ("mimeType", t(mime)),
                ("size", Value::Integer(size)),
            ]))
        };
        let p = |avatar: Value| {
            map(&[
                ("$type", t(LABELER_PROFILE)),
                ("displayName", t("Private mod")),
                ("avatar", avatar),
                ("createdAt", t(NOW)),
            ])
        };
        match check(
            LABELER_PROFILE,
            LABELER,
            SELF_RKEY,
            &p(img("image/png", 10)),
        )
        .unwrap()
        .unwrap()
        {
            LabelerRecord::Profile(p) => assert_eq!(p.avatar.unwrap().size, 10),
            other => panic!("{other:?}"),
        }
        assert!(check(
            LABELER_PROFILE,
            LABELER,
            SELF_RKEY,
            &p(img("image/gif", 10))
        )
        .is_err());
        assert!(check(
            LABELER_PROFILE,
            LABELER,
            SELF_RKEY,
            &p(img("image/png", 2_000_000))
        )
        .is_err());
        assert!(check(LABELER_PROFILE, LABELER, RKEY, &p(img("image/png", 10))).is_err());
        assert!(check(LABELER_PROFILE, BOB, SELF_RKEY, &p(img("image/png", 10))).is_err());
    }

    fn strings_of(lang: &str, key: &str) -> Value {
        Value::Map(map(&[
            ("lang", t(lang)),
            (key, t("Spam")),
            ("description", t("Unwanted")),
        ]))
    }

    #[test]
    fn policies_record() {
        let def = |id: &str| {
            Value::Map(map(&[
                ("identifier", t(id)),
                ("severity", t("alert")),
                ("blurs", t("content")),
                ("defaultSetting", t("warn")),
                ("locales", Value::Array(vec![strings_of("en", "name")])),
            ]))
        };
        let p = |defs: Vec<Value>| {
            map(&[
                ("$type", t(LABELER_POLICIES)),
                (
                    "policies",
                    Value::Map(map(&[
                        ("labelValues", Value::Array(vec![t("spam"), t("!hide")])),
                        ("labelValueDefinitions", Value::Array(defs)),
                    ])),
                ),
                (
                    "reasonTypes",
                    Value::Array(vec![t("com.atproto.moderation.defs#reasonSpam")]),
                ),
                (
                    "subjectCollections",
                    Value::Array(vec![t("app.bsky.feed.post")]),
                ),
                ("createdAt", t(NOW)),
            ])
        };
        match check(LABELER_POLICIES, LABELER, SELF_RKEY, &p(vec![def("spam")]))
            .unwrap()
            .unwrap()
        {
            LabelerRecord::Policies(p) => {
                assert_eq!(p.label_values, ["spam", "!hide"]);
                assert_eq!(p.subject_collections.unwrap(), ["app.bsky.feed.post"]);
                assert!(p.subject_types.is_none());
            }
            other => panic!("{other:?}"),
        }
        assert!(check(LABELER_POLICIES, LABELER, SELF_RKEY, &p(vec![def("Spam")])).is_err());
        assert!(check(LABELER_POLICIES, LABELER, SELF_RKEY, &p(vec![def("!hide")])).is_err());
        let mut no_values = p(vec![]);
        no_values.insert("policies".into(), Value::Map(Map::new()));
        assert!(check(LABELER_POLICIES, LABELER, SELF_RKEY, &no_values).is_err());
    }

    #[test]
    fn reasons_record() {
        let r = |locales: Vec<Value>| {
            map(&[
                ("$type", t(LABELER_REASONS)),
                (
                    "reasons",
                    Value::Array(vec![Value::Map(map(&[
                        ("type", t("com.atproto.moderation.defs#reasonSpam")),
                        ("locales", Value::Array(locales)),
                    ]))]),
                ),
                ("createdAt", t(NOW)),
            ])
        };
        match check(
            LABELER_REASONS,
            LABELER,
            SELF_RKEY,
            &r(vec![strings_of("en", "title")]),
        )
        .unwrap()
        .unwrap()
        {
            LabelerRecord::Reasons(r) => {
                assert_eq!(r.reasons[0].locales[0].title, "Spam");
            }
            other => panic!("{other:?}"),
        }
        assert!(check(
            LABELER_REASONS,
            LABELER,
            SELF_RKEY,
            &r(vec![strings_of("english", "title")])
        )
        .is_err());
        assert!(check(
            LABELER_REASONS,
            LABELER,
            SELF_RKEY,
            &r(vec![strings_of("en", "name")])
        )
        .is_err());
    }

    #[test]
    fn reason_groups() {
        let reason = |group: Option<&str>| {
            let mut m = map(&[
                ("type", t("com.atproto.moderation.defs#reasonSpam")),
                ("locales", Value::Array(vec![strings_of("en", "title")])),
            ]);
            if let Some(g) = group {
                m.insert("group".into(), t(g));
            }
            Value::Map(m)
        };
        let group = |id: &str| {
            Value::Map(map(&[
                ("id", t(id)),
                ("locales", Value::Array(vec![strings_of("en", "title")])),
            ]))
        };
        let rec = |reasons: Vec<Value>, groups: Option<Vec<Value>>| {
            let mut m = map(&[
                ("$type", t(LABELER_REASONS)),
                ("reasons", Value::Array(reasons)),
                ("createdAt", t(NOW)),
            ]);
            if let Some(g) = groups {
                m.insert("groups".into(), Value::Array(g));
            }
            m
        };
        let ok = rec(
            vec![reason(Some("abuse")), reason(None)],
            Some(vec![group("abuse")]),
        );
        match check(LABELER_REASONS, LABELER, SELF_RKEY, &ok)
            .unwrap()
            .unwrap()
        {
            LabelerRecord::Reasons(r) => {
                assert_eq!(r.groups[0].id, "abuse");
                assert_eq!(r.reasons[0].group.as_deref(), Some("abuse"));
                assert_eq!(r.reasons[1].group, None);
            }
            other => panic!("{other:?}"),
        }
        // Ungrouped records still validate, with no groups.
        match check(
            LABELER_REASONS,
            LABELER,
            SELF_RKEY,
            &rec(vec![reason(None)], None),
        )
        .unwrap()
        .unwrap()
        {
            LabelerRecord::Reasons(r) => assert!(r.groups.is_empty()),
            other => panic!("{other:?}"),
        }
        for bad in [
            rec(vec![reason(Some("missing"))], Some(vec![group("abuse")])),
            rec(vec![reason(Some("abuse"))], None),
            rec(
                vec![reason(None)],
                Some(vec![group("abuse"), group("abuse")]),
            ),
            rec(vec![reason(None)], Some(vec![group("")])),
        ] {
            assert!(check(LABELER_REASONS, LABELER, SELF_RKEY, &bad).is_err());
        }
    }
}
