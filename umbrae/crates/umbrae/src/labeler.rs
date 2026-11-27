//! Private labelers.
//!
//! A private labeler is a memberspace of type `tools.umbrae.labeler`, key
//! `self`, whose authority is the labeler's DID. It is never publicly
//! readable or writable; `allowedApps` names the apps that may read; the
//! policy is published so readers can check it. Readers are member accounts
//! with read access and no write access ([`reader_member`]): a credential
//! always needs a delegation token from an account the policy lets read,
//! and an attested client in `allowedApps`.
//!
//! Labels are append-only, as on a label stream. Each apply or negation is
//! a new `tools.umbrae.label` record; [`current_labels`] takes the latest
//! per `(src, uri, cid, val)` by `cts`, then record key, and drops negated
//! and expired ones. A deleted record counts as never written.
//!
//! Labels carry the standard label signature ([`sign_label`],
//! [`verify_label`]), by the key in the labeler's policies record
//! ([`LabelKeys`]) or, failing that, its DID document's `#atproto_label`.
//!
//! Who sees a label ([`can_view_label`]): everyone the serving app shows
//! the labeler to, unless the label names an audience (then only its
//! members, from [`Audiences`]) or is on a hidden post (then only those
//! who may see the post). Both apply when both are set. A label on a
//! hidden repost goes through [`can_view_repost_label`], which also needs
//! the post it reposts.
//!
//! A community's labeler may use a managed labeler space instead: a
//! `tools.umbrae.labeler` space at `self` whose managed policy names the
//! community's app (`check_labeler_policy` accepts it; the app also checks
//! that `managingApp` is its own). One labeler space names one app, so it
//! serves that app's communities only. The app answers `checkAccess` for it
//! as for a community space:
//! - the same service-auth check: `iss` the labeler, `aud` the app, `lxm`
//!   `checkAccess`;
//! - the space maps by `(tools.umbrae.labeler, labeler DID)` to the
//!   communities that name it;
//! - nothing, ever, when `repo` names an account: members get labels
//!   through the app, which applies [`can_view_label`] and
//!   [`can_view_repost_label`], label audiences included;
//! - with `repo` absent, `read` only for its own attested client ID;
//! - no `write`: the labeler writes as authority.
//!
//! The labeler reads community posts through the app, never by syncing
//! members' spaces.
//!
//! **In-space labels.** A label also has a home in the subject's own space,
//! as a `com.atproto.label.record` by a label writer there
//! ([`crate::access::is_label_writer`]). Each label has one home: an
//! unrestricted label on a hidden post or repost in a community or
//! everyone space where the labeler is a label writer goes in-space; every
//! other label stays in the labeler space. [`current_space_labels`] takes
//! the latest per `(writer, uri, cid, val)`; a label is removed by
//! deleting its records. A reader counts one only when the writer's repo is
//! in the writer set when synced, the writer is a label writer, and the
//! reader trusts it as a labeler ([`can_view_space_label`]). A reader
//! merging both homes uses [`merge_label_homes`].
//!
//! **Takedowns** ([`apply_takedowns`]): the authority's `!takedown` on a
//! record in its own space takes it out of every view, its author's
//! included, until the label is deleted. In a community space the named
//! labeler's `!takedown` counts too, as the community's. In Umbrae spaces
//! this always applies; for other space types (`tools.umbrae.private`
//! included) the serving app applies it where its spaces configuration
//! says to, on by default.

use crate::access::{can_view_record, can_view_repost, is_label_writer, SpaceState, ViewContext};
use crate::space::{is_community_space, is_only_me, Misconfigured};
use std::collections::{BTreeMap, BTreeSet};
use umbrae_core::didkey::{self, AnyKey};
use umbrae_core::drisl::{self, Value};
use umbrae_core::policy::{MemberAccess, MemberPolicy, Policy};
use umbrae_core::tokens::Signer;
use umbrae_core::uri::{SpaceRecordUri, SpaceRef, UriError};
use umbrae_lexicons::{
    label_subject, Label, LabelSubject, LabelerAudience, LabelerPolicies, SpaceLabel,
    LABELER_SPACE_TYPE, LIST_SPACE_TYPE, POST, PROFILE_SKEY, REPOST, SELF_RKEY, SPACE_TYPE,
    TAKEDOWN,
};

/// The labeler's space.
pub fn labeler_space(labeler: &str) -> Result<SpaceRef, UriError> {
    SpaceRef::new(labeler, LABELER_SPACE_TYPE, SELF_RKEY)
}

/// The policy a labeler space is created with. `allowed_apps` names the
/// apps that may read it (by attested OAuth client ID) and must not be
/// empty.
pub fn labeler_policy(allowed_apps: Vec<String>) -> Policy {
    Policy::Member(MemberPolicy {
        public_read: false,
        public_write: false,
        allowed_apps: Some(allowed_apps),
        publish_policy: true,
        publish_members: false,
    })
}

/// A reader's member-list entry: read, never write.
pub fn reader_member() -> MemberAccess {
    MemberAccess {
        read: true,
        write: false,
    }
}

/// Check that `policy` is what a labeler space must have. The labeler
/// checks before writing; a reader before showing.
pub fn check_labeler_policy(space: &SpaceRef, policy: &Policy) -> Result<(), Misconfigured> {
    if space.space_type() != LABELER_SPACE_TYPE {
        return Err(Misconfigured::NotUmbrae);
    }
    let p = match policy {
        Policy::Member(p) if space.skey() == SELF_RKEY => p,
        // A community's labeler may leave its readers to the community's
        // app (prism, or a PDS managing its own communities), which reads
        // it with its own attested client and answers nothing for accounts.
        // See the module docs.
        Policy::Managed(m) if space.skey() == SELF_RKEY => {
            return match m.publish_policy {
                true => Ok(()),
                false => Err(Misconfigured::Unpublished),
            }
        }
        _ => return Err(Misconfigured::WrongPolicy),
    };
    if p.public_read {
        return Err(Misconfigured::PublicRead);
    }
    if p.public_write {
        return Err(Misconfigured::PublicWrite);
    }
    if !p.publish_policy {
        return Err(Misconfigured::Unpublished);
    }
    match &p.allowed_apps {
        Some(apps) if !apps.is_empty() => Ok(()),
        _ => Err(Misconfigured::NoAllowedApps),
    }
}

/// The bytes a label signature covers: the DRISL encoding of the label
/// without `sig` or `$type`, with `ver` defaulting to 1 and `neg` omitted
/// unless true (as the reference labeler signs), and `audience` included
/// exactly when set, so a copy can't shed its restriction.
pub fn label_signing_bytes(label: &Label) -> Vec<u8> {
    let mut m = BTreeMap::new();
    m.insert("ver".to_owned(), Value::Integer(label.ver.unwrap_or(1)));
    m.insert("src".to_owned(), Value::Text(label.src.clone()));
    m.insert("uri".to_owned(), Value::Text(label.uri.clone()));
    if let Some(cid) = &label.cid {
        m.insert("cid".to_owned(), Value::Text(cid.to_string()));
    }
    m.insert("val".to_owned(), Value::Text(label.val.clone()));
    if label.neg {
        m.insert("neg".to_owned(), Value::Bool(true));
    }
    m.insert("cts".to_owned(), Value::Text(label.cts.clone()));
    if let Some(exp) = &label.exp {
        m.insert("exp".to_owned(), Value::Text(exp.clone()));
    }
    if let Some(a) = &label.audience {
        m.insert("audience".to_owned(), Value::Text(a.clone()));
    }
    drisl::encode(&Value::Map(m)).expect("a label of strings always encodes")
}

/// Sign a label with the labeler's label key.
pub fn sign_label(label: &Label, key: &Signer) -> Vec<u8> {
    key.sign(&label_signing_bytes(label)).to_vec()
}

/// The hidden post a label is on, if it's on one: look up that post's
/// space state to decide who may see the label.
pub fn hidden_post_of(label: &Label) -> Option<SpaceRecordUri> {
    match label_subject(&label.uri) {
        Some(LabelSubject::HiddenPost(u)) => Some(u),
        _ => None,
    }
}

/// The hidden record a label is on, a post or a repost: look up that
/// record's space state to decide who may see the label.
pub fn hidden_record_of(label: &Label) -> Option<SpaceRecordUri> {
    match label_subject(&label.uri) {
        Some(LabelSubject::HiddenPost(u) | LabelSubject::HiddenRepost(u)) => Some(u),
        _ => None,
    }
}

/// One labeler's audiences, from the `tools.umbrae.labelerAudience` records
/// in its space. Audience ids are only record keys, so another labeler can
/// reuse one: an `Audiences` opens only labels whose `src` is its labeler.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Audiences {
    labeler: String,
    members: BTreeMap<String, BTreeSet<String>>,
}

impl Audiences {
    /// `records` must be the validated audience records from `labeler`'s
    /// space.
    pub fn from_records<'a>(
        labeler: &str,
        records: impl IntoIterator<Item = &'a LabelerAudience>,
    ) -> Self {
        Self {
            labeler: labeler.to_owned(),
            members: records
                .into_iter()
                .map(|a| (a.id.clone(), a.members.clone()))
                .collect(),
        }
    }

    /// Whether `did` is in labeler `src`'s audience `id`. An unknown
    /// audience, or another labeler's, has no one.
    pub fn allows(&self, src: &str, id: &str, did: &str) -> bool {
        !self.labeler.is_empty()
            && self.labeler == src
            && self.members.get(id).is_some_and(|m| m.contains(did))
    }
}

/// Whether `viewer` may see `label`, given that they may see the labeler
/// at all (which the serving app decides).
///
/// - With an audience: only its members, from the label's own labeler's
///   `audiences`; an unknown audience, nobody. That includes the labeler
///   itself unless it lists its own DID.
/// - On an account or a public record: no further condition.
/// - On a hidden post: also only if they may see that post. `post_space` is
///   the state of the post's space; without it, no (fail closed).
/// - On a hidden repost: no. Seeing a repost needs its subject too, which
///   the label doesn't carry; use [`can_view_repost_label`].
/// - On anything else: no.
pub fn can_view_label(
    viewer: Option<&str>,
    label: &Label,
    post_space: Option<&SpaceState>,
    audiences: &Audiences,
    ctx: &impl ViewContext,
) -> bool {
    if !audience_allows(viewer, label, audiences) {
        return false;
    }
    match label_subject(&label.uri) {
        Some(LabelSubject::Account(_) | LabelSubject::Record(_)) => true,
        Some(LabelSubject::HiddenPost(uri)) => {
            post_space.is_some_and(|s| can_view_record(viewer, &uri, s, ctx))
        }
        _ => false,
    }
}

/// Whether `viewer` may see `label`, a label on a hidden repost whose
/// `subject` is the post it reposts (from the repost record). As
/// [`can_view_label`] for the audience, and only if they may see the
/// repost **and** its subject ([`can_view_repost`]), given `repost_space`,
/// the repost's space state ([`hidden_record_of`]), and `subject_space`,
/// the subject's (in a community, another member's space). Without either,
/// no. A label on anything but a hidden repost: no.
#[allow(clippy::too_many_arguments)]
pub fn can_view_repost_label(
    viewer: Option<&str>,
    label: &Label,
    subject: &SpaceRecordUri,
    repost_space: Option<&SpaceState>,
    subject_space: Option<&SpaceState>,
    audiences: &Audiences,
    ctx: &impl ViewContext,
) -> bool {
    if !audience_allows(viewer, label, audiences) {
        return false;
    }
    match (label_subject(&label.uri), repost_space, subject_space) {
        (Some(LabelSubject::HiddenRepost(repost)), Some(r), Some(s)) => {
            can_view_repost(viewer, &repost, r, subject, s, ctx)
        }
        _ => false,
    }
}

/// A label without an audience is open; with one, only its members.
fn audience_allows(viewer: Option<&str>, label: &Label, audiences: &Audiences) -> bool {
    match &label.audience {
        Some(a) => viewer.is_some_and(|v| audiences.allows(&label.src, a, v)),
        None => true,
    }
}

/// Whether the label carries a valid low-S signature by `key`.
pub fn verify_label(label: &Label, key: &AnyKey) -> bool {
    label
        .sig
        .as_ref()
        .is_some_and(|sig| key.verify_low_s(&label_signing_bytes(label), sig))
}

/// The keys a labeler's labels verify against: the current one, and keys
/// retired by routine rotation, each good only for labels created before
/// it was retired.
#[derive(Debug, Clone, Default)]
pub struct LabelKeys {
    current: Option<AnyKey>,
    retired: Vec<(AnyKey, i128)>,
}

impl LabelKeys {
    /// From the policies record. Keys that don't parse are left out (the
    /// lexicon check refuses them first).
    pub fn from_policies(p: &LabelerPolicies) -> Self {
        Self {
            current: p
                .label_key
                .as_deref()
                .and_then(|k| didkey::parse_any(k).ok()),
            retired: p
                .previous_label_keys
                .iter()
                .filter_map(|r| {
                    Some((
                        didkey::parse_any(&r.key).ok()?,
                        parse_datetime_ns(&r.retired_at)?,
                    ))
                })
                .collect(),
        }
    }

    /// Just one key, such as the DID document's `#atproto_label`.
    pub fn single(key: AnyKey) -> Self {
        Self {
            current: Some(key),
            retired: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.current.is_none()
    }
}

/// Whether the label verifies against `keys`: by the current key, or by a
/// retired key if the label's `cts` is before that key's retirement. `cts`
/// is the signer's claim, so a leaked retired key can still backdate; a
/// compromised key must not be listed.
pub fn verify_label_with(label: &Label, keys: &LabelKeys) -> bool {
    if keys
        .current
        .as_ref()
        .is_some_and(|k| verify_label(label, k))
    {
        return true;
    }
    let Some(cts) = parse_datetime_ns(&label.cts) else {
        return false;
    };
    keys.retired
        .iter()
        .any(|(k, retired)| cts < *retired && verify_label(label, k))
}

/// The labels in effect at `now_ms` (Unix milliseconds), from a labeler's
/// label records as `(rkey, label)`. Per `(src, uri, cid, val)` the latest
/// record wins, by `cts` and then by record key; it applies unless it is a
/// negation or has expired. Output is ordered by subject, then value.
///
/// `audience` isn't part of the key: a later restricted record replaces an
/// open one for everyone (those outside its audience then see no label),
/// and a later open record or negation replaces a restricted one.
pub fn current_labels<'a>(
    records: impl IntoIterator<Item = (&'a str, &'a Label)>,
    now_ms: i64,
) -> Vec<&'a Label> {
    type Key<'a> = (&'a str, Option<String>, &'a str, &'a str);
    let mut latest: BTreeMap<Key<'a>, ((i128, &'a str), &'a Label)> = BTreeMap::new();
    for (rkey, label) in records {
        let Some(cts) = parse_datetime_ns(&label.cts) else {
            continue;
        };
        let key = (
            label.uri.as_str(),
            label.cid.as_ref().map(|c| c.to_string()),
            label.val.as_str(),
            label.src.as_str(),
        );
        let order = (cts, rkey);
        match latest.get(&key) {
            Some((seen, _)) if *seen >= order => {}
            _ => {
                latest.insert(key, (order, label));
            }
        }
    }
    let now_ns = i128::from(now_ms) * 1_000_000;
    latest
        .into_values()
        .map(|(_, l)| l)
        .filter(|l| !l.neg)
        .filter(|l| match &l.exp {
            None => true,
            Some(exp) => parse_datetime_ns(exp).is_some_and(|e| e > now_ns),
        })
        .collect()
}

/// The in-space labels in effect at `now_ms` (Unix milliseconds), from one
/// space's `com.atproto.label.record`s as `(record URI, label)`. Per
/// `(writer, uri, cid, val)` the latest record wins, by `cts` and then by
/// record key; expired and ignored ones drop out, and so does a label whose
/// subject isn't in its record's space. A deleted record counts as never
/// written. Output is ordered by writer, then subject, then value.
pub fn current_space_labels<'a>(
    records: impl IntoIterator<Item = (&'a SpaceRecordUri, &'a SpaceLabel)>,
    now_ms: i64,
) -> Vec<(&'a SpaceRecordUri, &'a SpaceLabel)> {
    type Key<'a> = (&'a str, &'a str, Option<String>, &'a str);
    type Seen<'a> = ((i128, &'a str), (&'a SpaceRecordUri, &'a SpaceLabel));
    let mut latest: BTreeMap<Key<'a>, Seen<'a>> = BTreeMap::new();
    for (uri, label) in records {
        let Some(cts) = parse_datetime_ns(&label.cts) else {
            continue;
        };
        if label.record().is_none_or(|s| s.space() != uri.space()) {
            continue;
        }
        let key = (
            uri.author(),
            label.uri.as_str(),
            label.cid.as_ref().map(|c| c.to_string()),
            label.val.as_str(),
        );
        let order = (cts, uri.rkey());
        match latest.get(&key) {
            Some((seen, _)) if *seen >= order => {}
            _ => {
                latest.insert(key, (order, (uri, label)));
            }
        }
    }
    let now_ns = i128::from(now_ms) * 1_000_000;
    latest
        .into_values()
        .map(|(_, l)| l)
        .filter(|(_, l)| match &l.exp {
            None => true,
            Some(exp) => parse_datetime_ns(exp).is_some_and(|e| e > now_ns),
        })
        .collect()
}

/// Fill `state.taken_down` from the space's current in-space labels
/// ([`current_space_labels`]): every `!takedown` by the authority, and in a
/// community space also by the community's named labeler (a label writer
/// there), on a record in this space. Any other writer's `!takedown` is an
/// ordinary label. Ignored in only-me, the profile space, labeler spaces and
/// shared list spaces, where the owner deletes instead. Deleting the label
/// brings the record back at the next call.
pub fn apply_takedowns<'a>(
    state: &mut SpaceState,
    labels: impl IntoIterator<Item = (&'a SpaceRecordUri, &'a SpaceLabel)>,
) {
    let space = &state.space;
    let ignored = match space.space_type() {
        SPACE_TYPE => is_only_me(space) || space.skey() == PROFILE_SKEY,
        t => t == LABELER_SPACE_TYPE || t == LIST_SPACE_TYPE,
    };
    let mut down = BTreeSet::new();
    for (uri, label) in labels {
        let Some(subject) = label.record() else {
            continue;
        };
        let writer = uri.author();
        let counts = writer == space.authority()
            || (is_community_space(space) && is_label_writer(writer, state));
        if !ignored
            && counts
            && label.val == TAKEDOWN
            && uri.space() == space
            && subject.space() == space
        {
            down.insert((
                subject.author().to_owned(),
                subject.collection().to_owned(),
                subject.rkey().to_owned(),
            ));
        }
    }
    state.taken_down = down;
}

/// Whether `viewer` may see `label`, an in-space label by `writer` on a
/// hidden post in `subject_state`'s space: the writer is a label writer
/// there ([`is_label_writer`]), the reader trusts it (`trusted`: the
/// viewer's accepted labelers plus those the serving app applies for
/// everyone), and the viewer may see the post. A label on a repost needs
/// its subject: use [`can_view_space_repost_label`]. Anything else: no.
pub fn can_view_space_label(
    viewer: Option<&str>,
    label: &SpaceLabel,
    writer: &str,
    subject_state: &SpaceState,
    trusted: &BTreeSet<String>,
    ctx: &impl ViewContext,
) -> bool {
    match label.record() {
        Some(post) if post.collection() == POST => {
            counts_in(writer, subject_state, trusted)
                && can_view_record(viewer, post, subject_state, ctx)
        }
        _ => false,
    }
}

/// As [`can_view_space_label`], for a label on a hidden repost in
/// `repost_state`'s space whose `subject` is the post it reposts, in
/// `subject_state`'s space: the viewer may see both ([`can_view_repost`]).
#[allow(clippy::too_many_arguments)]
pub fn can_view_space_repost_label(
    viewer: Option<&str>,
    label: &SpaceLabel,
    writer: &str,
    subject: &SpaceRecordUri,
    repost_state: &SpaceState,
    subject_state: &SpaceState,
    trusted: &BTreeSet<String>,
    ctx: &impl ViewContext,
) -> bool {
    match label.record() {
        Some(repost) if repost.collection() == REPOST => {
            counts_in(writer, repost_state, trusted)
                && can_view_repost(viewer, repost, repost_state, subject, subject_state, ctx)
        }
        _ => false,
    }
}

fn counts_in(writer: &str, state: &SpaceState, trusted: &BTreeSet<String>) -> bool {
    is_label_writer(writer, state) && trusted.contains(writer)
}

/// Both homes as one list: labeler-space labels (from [`current_labels`])
/// and in-space ones (from [`current_space_labels`], as `(record URI,
/// label)`, the writer being the label's `src`). Per `(src, uri, cid, val)`
/// the latest `cts` wins; on a tie the in-space one. Ignored in-space labels
/// are left out. Apply the usual checks to each before showing it.
pub fn merge_label_homes<'a>(
    labeler_space: impl IntoIterator<Item = &'a Label>,
    in_space: impl IntoIterator<Item = (&'a SpaceRecordUri, &'a SpaceLabel)>,
) -> Vec<Label> {
    type Key = (String, String, Option<String>, String);
    let mut out: BTreeMap<Key, (i128, Label)> = BTreeMap::new();
    let moved = in_space.into_iter().filter_map(|(uri, l)| {
        l.record()?;
        Some(Label {
            ver: None,
            src: uri.author().to_owned(),
            uri: l.uri.clone(),
            cid: l.cid,
            val: l.val.clone(),
            neg: false,
            cts: l.cts.clone(),
            exp: l.exp.clone(),
            sig: None,
            audience: None,
        })
    });
    for label in labeler_space.into_iter().cloned().chain(moved) {
        let Some(cts) = parse_datetime_ns(&label.cts) else {
            continue;
        };
        let key = (
            label.src.clone(),
            label.uri.clone(),
            label.cid.as_ref().map(|c| c.to_string()),
            label.val.clone(),
        );
        match out.get(&key) {
            Some((seen, _)) if *seen > cts => {}
            _ => {
                out.insert(key, (cts, label));
            }
        }
    }
    out.into_values().map(|(_, l)| l).collect()
}

/// An atproto datetime as Unix nanoseconds. Assumes the string already
/// passed lexicon validation; returns `None` otherwise.
fn parse_datetime_ns(s: &str) -> Option<i128> {
    let b = s.as_bytes();
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, se) = (n(11..13)?, n(14..16)?, n(17..19)?);
    let mut i = 19;
    let mut frac_ns: i128 = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &s[start..i];
        let mut scaled = String::from(&digits[..digits.len().min(9)]);
        while scaled.len() < 9 {
            scaled.push('0');
        }
        frac_ns = scaled.parse().ok()?;
    }
    let offset_s: i64 = match s.get(i..)? {
        "Z" => 0,
        off if off.len() == 6 => {
            let sign = if off.starts_with('-') { -1 } else { 1 };
            let part = |r: std::ops::Range<usize>| off.get(r)?.parse::<i64>().ok();
            sign * (part(1..3)? * 3600 + part(4..6)? * 60)
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant's algorithm).
    let (y, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + se - offset_s;
    Some(i128::from(secs) * 1_000_000_000 + frac_ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use umbrae_core::cid::Cid;
    use umbrae_core::didkey;

    const LABELER: &str = "did:plc:labelerllllllllllllllll";
    const POST_A: &str = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";
    const POST_B: &str = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa6";
    // 2026-11-14T10:00:00Z
    const NOW_MS: i64 = 1_794_650_400_000;

    fn label(uri: &str, val: &str, cts: &str) -> Label {
        Label {
            ver: Some(1),
            src: LABELER.into(),
            uri: uri.into(),
            cid: None,
            val: val.into(),
            neg: false,
            cts: cts.into(),
            exp: None,
            sig: None,
            audience: None,
        }
    }

    #[test]
    fn datetimes_to_instants() {
        assert_eq!(
            parse_datetime_ns("2026-11-14T10:00:00Z"),
            Some(i128::from(NOW_MS) * 1_000_000)
        );
        assert_eq!(parse_datetime_ns("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_datetime_ns("2026-11-14T15:30:00+05:30"),
            parse_datetime_ns("2026-11-14T10:00:00.000000Z")
        );
        assert_eq!(
            parse_datetime_ns("1970-01-01T00:00:00.5Z"),
            Some(500_000_000)
        );
        assert_eq!(parse_datetime_ns("2026-11-14"), None);
        // A label built without validation: no panic on a split character.
        assert_eq!(parse_datetime_ns("2026-11-14T10:00:00+0é00"), None);
    }

    #[test]
    fn space_and_policy() {
        let s = labeler_space(LABELER).unwrap();
        assert_eq!(
            s.to_string(),
            format!("at:space/{LABELER}/{LABELER_SPACE_TYPE}/self")
        );
        let p = labeler_policy(vec!["https://app.example/client-metadata.json".into()]);
        assert_eq!(Policy::from_map(&p.to_map()).unwrap(), p);
        assert_eq!(check_labeler_policy(&s, &p), Ok(()));
        assert!(p.requires_attestation());
        assert!(p.requires_delegation());
        assert!(reader_member().read && !reader_member().write);
    }

    #[test]
    fn refuses_misconfigured_labeler_spaces() {
        let s = labeler_space(LABELER).unwrap();
        let with = |f: fn(&mut MemberPolicy)| {
            let mut p = match labeler_policy(vec!["https://app.example/c.json".into()]) {
                Policy::Member(p) => p,
                _ => unreachable!(),
            };
            f(&mut p);
            Policy::Member(p)
        };
        assert_eq!(
            check_labeler_policy(&s, &with(|p| p.public_read = true)),
            Err(Misconfigured::PublicRead)
        );
        assert_eq!(
            check_labeler_policy(&s, &with(|p| p.public_write = true)),
            Err(Misconfigured::PublicWrite)
        );
        assert_eq!(
            check_labeler_policy(&s, &with(|p| p.publish_policy = false)),
            Err(Misconfigured::Unpublished)
        );
        assert_eq!(
            check_labeler_policy(&s, &with(|p| p.allowed_apps = None)),
            Err(Misconfigured::NoAllowedApps)
        );
        assert_eq!(
            check_labeler_policy(&s, &with(|p| p.allowed_apps = Some(vec![]))),
            Err(Misconfigured::NoAllowedApps)
        );
        assert_eq!(
            check_labeler_policy(&s, &Policy::Personal),
            Err(Misconfigured::WrongPolicy)
        );
        let wrong_key = SpaceRef::new(LABELER, LABELER_SPACE_TYPE, "3mbbbbbbbbbb2").unwrap();
        assert_eq!(
            check_labeler_policy(&wrong_key, &with(|_| {})),
            Err(Misconfigured::WrongPolicy)
        );
        let posts = SpaceRef::new(LABELER, crate::SPACE_TYPE, "3mbbbbbbbbbb2").unwrap();
        assert_eq!(
            check_labeler_policy(&posts, &with(|_| {})),
            Err(Misconfigured::NotUmbrae)
        );
    }

    #[test]
    fn signatures() {
        for signer in [
            Signer::K256(k256::ecdsa::SigningKey::random(&mut OsRng)),
            Signer::P256(p256::ecdsa::SigningKey::random(&mut OsRng)),
        ] {
            let key = didkey::parse_any(&signer.did_key()).unwrap();
            let mut l = label(POST_A, "spam", "2026-11-14T09:00:00.000Z");
            l.cid = Some(Cid::for_drisl(b"post"));
            l.sig = Some(sign_label(&l, &signer));
            assert!(verify_label(&l, &key));
            // neg: false and an absent ver sign the same as their defaults.
            let mut same = l.clone();
            same.ver = None;
            assert!(verify_label(&same, &key));
            let mut changed = l.clone();
            changed.val = "porn".into();
            assert!(!verify_label(&changed, &key));
            let mut negated = l.clone();
            negated.neg = true;
            assert!(!verify_label(&negated, &key));
            let mut unsigned = l.clone();
            unsigned.sig = None;
            assert!(!verify_label(&unsigned, &key));
        }
    }

    #[test]
    fn signing_bytes_match_the_reference_shape() {
        let l = label(POST_A, "spam", "2026-11-14T09:00:00.000Z");
        let decoded = drisl::decode(&label_signing_bytes(&l)).unwrap();
        let m = decoded.as_map().unwrap();
        let keys: Vec<_> = m.keys().map(String::as_str).collect();
        assert_eq!(keys.len(), 5);
        for k in ["ver", "src", "uri", "val", "cts"] {
            assert!(m.contains_key(k), "{k}");
        }
        assert!(!m.contains_key("neg") && !m.contains_key("sig") && !m.contains_key("$type"));
    }

    #[test]
    fn latest_record_wins() {
        let applied = label(POST_A, "spam", "2026-11-14T08:00:00.000Z");
        let mut negated = label(POST_A, "spam", "2026-11-14T09:00:00.000Z");
        negated.neg = true;
        let reapplied = label(POST_A, "spam", "2026-11-14T09:30:00.000Z");
        let other = label(POST_B, "rude", "2026-11-14T08:00:00.000Z");
        let mut expired = label(POST_B, "spam", "2026-11-14T08:00:00.000Z");
        expired.exp = Some("2026-11-14T09:59:59.999Z".into());
        let mut live = label(POST_B, "nudity", "2026-11-14T08:00:00.000Z");
        live.exp = Some("2026-11-14T11:00:00+01:00".into()); // 10:00Z: expired exactly now
        let mut later = label(POST_B, "graphic-media", "2026-11-14T08:00:00.000Z");
        later.exp = Some("2026-11-14T10:00:00.001Z".into());

        // Negated and not re-applied.
        let current = current_labels(
            [
                ("3mbaaaaaaaaa2", &applied),
                ("3mbaaaaaaaaa3", &negated),
                ("3mbaaaaaaaaa4", &other),
            ],
            NOW_MS,
        );
        assert_eq!(current, [&other]);

        // Re-applied; input order doesn't matter.
        let current = current_labels(
            [
                ("3mbaaaaaaaaa4", &reapplied),
                ("3mbaaaaaaaaa3", &negated),
                ("3mbaaaaaaaaa2", &applied),
            ],
            NOW_MS,
        );
        assert_eq!(current, [&reapplied]);

        let current = current_labels(
            [
                ("3mbaaaaaaaa22", &expired),
                ("3mbaaaaaaaa23", &live),
                ("3mbaaaaaaaa24", &later),
            ],
            NOW_MS,
        );
        assert_eq!(current, [&later]);
    }

    #[test]
    fn same_cts_breaks_ties_by_record_key() {
        let applied = label(POST_A, "spam", "2026-11-14T08:00:00.000Z");
        let mut negated = applied.clone();
        negated.neg = true;
        assert!(current_labels(
            [("3mbaaaaaaaaa2", &applied), ("3mbaaaaaaaaa3", &negated)],
            NOW_MS
        )
        .is_empty());
        assert_eq!(
            current_labels(
                [("3mbaaaaaaaaa3", &applied), ("3mbaaaaaaaaa2", &negated)],
                NOW_MS
            ),
            [&applied]
        );
    }

    #[test]
    fn cid_scoped_labels_are_separate() {
        let whole = label(POST_A, "spam", "2026-11-14T08:00:00.000Z");
        let mut version = whole.clone();
        version.cid = Some(Cid::for_drisl(b"v1"));
        version.neg = true;
        version.cts = "2026-11-14T09:00:00.000Z".into();
        assert_eq!(
            current_labels(
                [("3mbaaaaaaaaa2", &whole), ("3mbaaaaaaaaa3", &version)],
                NOW_MS
            ),
            [&whole]
        );
    }

    struct Everyone;

    impl ViewContext for Everyone {
        fn is_active(&self, _: &str) -> crate::Tri {
            crate::Tri::Yes
        }

        fn blocked(&self, _: &str, _: &str) -> crate::Tri {
            crate::Tri::No
        }
    }

    #[test]
    fn labels_on_hidden_posts_follow_the_post() {
        const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
        const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
        const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
        let space = crate::space::group_space(ALICE, "3mbbbbbbbbbb2").unwrap();
        let mut state = SpaceState::new(space.clone(), Some(crate::space::group_policy(None)));
        state.members.insert(
            BOB,
            MemberAccess {
                read: true,
                write: true,
            },
        );
        let post = space
            .record(ALICE, umbrae_lexicons::POST, "3mbaaaaaaaaa2")
            .unwrap();
        let on_post = label(&post.to_string(), "spam", "2026-11-14T08:00:00.000Z");
        let on_public = label(POST_A, "spam", "2026-11-14T08:00:00.000Z");
        let c = Everyone;
        let none = Audiences::default();

        assert_eq!(hidden_post_of(&on_post), Some(post.clone()));
        assert_eq!(hidden_post_of(&on_public), None);
        // Members of the post's group see the label; others don't.
        assert!(can_view_label(Some(BOB), &on_post, Some(&state), &none, &c));
        assert!(can_view_label(
            Some(ALICE),
            &on_post,
            Some(&state),
            &none,
            &c
        ));
        assert!(!can_view_label(
            Some(CAROL),
            &on_post,
            Some(&state),
            &none,
            &c
        ));
        assert!(!can_view_label(None, &on_post, Some(&state), &none, &c));
        // Without the post's space state, or with the wrong one: hidden.
        assert!(!can_view_label(Some(BOB), &on_post, None, &none, &c));
        let other = SpaceState::new(
            crate::space::group_space(ALICE, "3mbbbbbbbbbb3").unwrap(),
            Some(crate::space::group_policy(None)),
        );
        assert!(!can_view_label(
            Some(BOB),
            &on_post,
            Some(&other),
            &none,
            &c
        ));
        // Public subjects are as visible as the labeler.
        assert!(can_view_label(Some(CAROL), &on_public, None, &none, &c));
        // A label that slipped past validation, on a like: never shown.
        let like = space
            .record(BOB, umbrae_lexicons::LIKE, "3mbaaaaaaaaa3")
            .unwrap();
        let on_like = label(&like.to_string(), "spam", "2026-11-14T08:00:00.000Z");
        assert!(!can_view_label(
            Some(BOB),
            &on_like,
            Some(&state),
            &none,
            &c
        ));
    }

    /// Everyone active; `pairs` block each other.
    struct Blocks(&'static [(&'static str, &'static str)]);

    impl ViewContext for Blocks {
        fn is_active(&self, _: &str) -> crate::Tri {
            crate::Tri::Yes
        }

        fn blocked(&self, a: &str, b: &str) -> crate::Tri {
            if self
                .0
                .iter()
                .any(|&(x, y)| (x == a && y == b) || (x == b && y == a))
            {
                crate::Tri::Yes
            } else {
                crate::Tri::No
            }
        }
    }

    #[test]
    fn labels_on_hidden_reposts_follow_the_repost_and_its_post() {
        const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
        const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
        const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
        const DAVE: &str = "did:plc:davedddddddddddddddddddddd";
        const EVE: &str = "did:plc:eveeeeeeeeeeeeeeeeeeeeeee";
        let rw = MemberAccess {
            read: true,
            write: true,
        };
        let space = crate::space::group_space(ALICE, "3mbbbbbbbbbb2").unwrap();
        let mut state = SpaceState::new(space.clone(), Some(crate::space::group_policy(None)));
        state.members.insert(BOB, rw);
        state.members.insert(DAVE, rw);
        state.members.insert(EVE, rw);
        // Eve posts; Bob reposts it.
        let post = space
            .record(EVE, umbrae_lexicons::POST, "3mbaaaaaaaaa2")
            .unwrap();
        let repost = space
            .record(BOB, umbrae_lexicons::REPOST, "3mbaaaaaaaaa4")
            .unwrap();
        let on_post = label(&post.to_string(), "spam", "2026-11-14T08:00:00.000Z");
        let on_repost = label(&repost.to_string(), "spam", "2026-11-14T08:00:00.000Z");
        let c = Everyone;
        let none = Audiences::default();
        let sees = |viewer: Option<&str>, s: Option<&SpaceState>, ctx: &Blocks| {
            can_view_repost_label(viewer, &on_repost, &post, s, s, &none, ctx)
        };
        let open = Blocks(&[]);

        assert_eq!(hidden_record_of(&on_repost), Some(repost.clone()));
        assert_eq!(hidden_record_of(&on_post), Some(post.clone()));
        assert_eq!(hidden_post_of(&on_repost), None);
        // Members who may see the repost and the post see the label.
        assert!(sees(Some(ALICE), Some(&state), &open));
        assert!(sees(Some(DAVE), Some(&state), &open));
        assert!(!sees(Some(CAROL), Some(&state), &open));
        assert!(!sees(None, Some(&state), &open));
        // Without the repost's space state, or another space's: hidden,
        // even where the viewer and the reposter both belong.
        assert!(!sees(Some(DAVE), None, &open));
        let mut other = SpaceState::new(
            crate::space::group_space(ALICE, "3mbbbbbbbbbb3").unwrap(),
            Some(crate::space::group_policy(None)),
        );
        other.members.insert(BOB, rw);
        other.members.insert(DAVE, rw);
        other.members.insert(EVE, rw);
        assert!(!sees(Some(DAVE), Some(&other), &open));
        // Dave may see Bob's repost but not Eve's post: no label.
        let dave_eve = Blocks(&[(DAVE, EVE)]);
        assert!(can_view_record(Some(DAVE), &repost, &state, &dave_eve));
        assert!(!sees(Some(DAVE), Some(&state), &dave_eve));
        // Nor once Eve leaves: Bob's repost stays, her post drops out.
        let mut eve_left = SpaceState::new(space.clone(), Some(crate::space::group_policy(None)));
        eve_left.members.insert(BOB, rw);
        eve_left.members.insert(DAVE, rw);
        assert!(can_view_record(Some(DAVE), &repost, &eve_left, &open));
        assert!(!sees(Some(DAVE), Some(&eve_left), &open));
        // Nor if Dave blocks Bob, the reposter.
        assert!(!sees(Some(DAVE), Some(&state), &Blocks(&[(DAVE, BOB)])));
        // Once Bob leaves, the label on his repost hides too.
        let mut left = SpaceState::new(space.clone(), Some(crate::space::group_policy(None)));
        left.members.insert(DAVE, rw);
        left.members.insert(EVE, rw);
        assert!(!sees(Some(DAVE), Some(&left), &open));
        // A subject in another space: never.
        let elsewhere = other
            .space
            .record(ALICE, umbrae_lexicons::POST, "3mbaaaaaaaaa2")
            .unwrap();
        assert!(!can_view_repost_label(
            Some(DAVE),
            &on_repost,
            &elsewhere,
            Some(&state),
            Some(&state),
            &none,
            &open
        ));
        assert!(!can_view_repost_label(
            Some(DAVE),
            &on_repost,
            &elsewhere,
            Some(&state),
            Some(&other),
            &none,
            &open
        ));
        // Without the subject's state: hidden.
        assert!(!can_view_repost_label(
            Some(DAVE),
            &on_repost,
            &post,
            Some(&state),
            None,
            &none,
            &open
        ));
        // An audience still applies.
        let mut restricted = on_repost.clone();
        restricted.audience = Some("3mbaaaaaaaaa9".into());
        assert!(!can_view_repost_label(
            Some(DAVE),
            &restricted,
            &post,
            Some(&state),
            Some(&state),
            &none,
            &open
        ));
        // can_view_label can't see the subject, so it never shows a repost
        // label; can_view_repost_label shows nothing else.
        assert!(!can_view_label(
            Some(DAVE),
            &on_repost,
            Some(&state),
            &none,
            &c
        ));
        assert!(!can_view_repost_label(
            Some(DAVE),
            &on_post,
            &post,
            Some(&state),
            Some(&state),
            &none,
            &open
        ));
    }

    #[test]
    fn labels_on_community_reposts_follow_both_members_spaces() {
        use crate::space::{community_space, managed_policy};
        use umbrae_lexicons::CommunityRef;
        const APP: &str = "did:web:app.example#umbrae_app";
        const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
        const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
        const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
        let art = CommunityRef::new(APP, "art").unwrap();
        let space_of = |author: &str, app: &str| {
            let mut s = SpaceState::new(
                community_space(author, &art).unwrap(),
                Some(managed_policy(app)),
            );
            s.community = Some(art.clone());
            for d in [ALICE, BOB] {
                s.members.insert(
                    d,
                    MemberAccess {
                        read: true,
                        write: true,
                    },
                );
            }
            s
        };
        // Alice posts in her space; Bob reposts it from his.
        let (alices, bobs) = (space_of(ALICE, APP), space_of(BOB, APP));
        let post = alices
            .space
            .record(ALICE, umbrae_lexicons::POST, "3mbaaaaaaaaa2")
            .unwrap();
        let repost = bobs
            .space
            .record(BOB, umbrae_lexicons::REPOST, "3mbaaaaaaaaa4")
            .unwrap();
        let on_repost = label(&repost.to_string(), "spam", "2026-11-14T08:00:00.000Z");
        let none = Audiences::default();
        let open = Blocks(&[]);
        let sees = |v: &str, subject_space: &SpaceState| {
            can_view_repost_label(
                Some(v),
                &on_repost,
                &post,
                Some(&bobs),
                Some(subject_space),
                &none,
                &open,
            )
        };
        assert!(sees(ALICE, &alices) && sees(BOB, &alices));
        assert!(!sees(CAROL, &alices));
        // A lookalike: Alice's space under the same key, naming another app.
        let lookalike = space_of(ALICE, "did:web:other.example#umbrae_app");
        assert!(!sees(BOB, &lookalike));
    }

    fn audience(id: &str, members: &[&str]) -> LabelerAudience {
        LabelerAudience {
            id: id.into(),
            name: None,
            members: members.iter().map(|m| m.to_string()).collect(),
            created_at: "2026-11-14T08:00:00.000Z".into(),
        }
    }

    #[test]
    fn restricted_labels_show_only_to_their_audience() {
        const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
        const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
        const MOD: &str = "did:plc:moddddddddddddddddddddddd";
        const AUD: &str = "3mbaaaaaaaab2";
        let c = Everyone;
        let audiences = Audiences::from_records(LABELER, [&audience(AUD, &[MOD])]);
        let mut on_account = label(
            "did:plc:carolcccccccccccccccccccc",
            "spam",
            "2026-11-14T08:00:00.000Z",
        );
        on_account.audience = Some(AUD.into());
        assert!(can_view_label(Some(MOD), &on_account, None, &audiences, &c));
        assert!(!can_view_label(
            Some(BOB),
            &on_account,
            None,
            &audiences,
            &c
        ));
        assert!(!can_view_label(None, &on_account, None, &audiences, &c));
        // An audience that doesn't exist (or was deleted): nobody.
        let gone = Audiences::default();
        assert!(!can_view_label(Some(MOD), &on_account, None, &gone, &c));
        let mut elsewhere = on_account.clone();
        elsewhere.audience = Some("3mbaaaaaaaab3".into());
        assert!(!can_view_label(Some(MOD), &elsewhere, None, &audiences, &c));
        // Another labeler's audience with the same key opens nothing here,
        // and this labeler's audience opens nothing of another labeler's.
        let theirs = Audiences::from_records(
            "did:plc:otherlabeleroooooooooooo",
            [&audience(AUD, &[MOD, BOB])],
        );
        assert!(!can_view_label(Some(MOD), &on_account, None, &theirs, &c));
        assert!(!can_view_label(Some(BOB), &on_account, None, &theirs, &c));
        let mut from_other = on_account.clone();
        from_other.src = "did:plc:otherlabeleroooooooooooo".into();
        assert!(!can_view_label(
            Some(MOD),
            &from_other,
            None,
            &audiences,
            &c
        ));

        // On a hidden post: in the audience AND able to see the post.
        let space = crate::space::group_space(ALICE, "3mbbbbbbbbbb2").unwrap();
        let mut state = SpaceState::new(space.clone(), Some(crate::space::group_policy(None)));
        state.members.insert(
            BOB,
            MemberAccess {
                read: true,
                write: true,
            },
        );
        let post = space
            .record(ALICE, umbrae_lexicons::POST, "3mbaaaaaaaaa2")
            .unwrap();
        let mut on_post = label(&post.to_string(), "spam", "2026-11-14T08:00:00.000Z");
        on_post.audience = Some(AUD.into());
        let both = Audiences::from_records(LABELER, [&audience(AUD, &[MOD, BOB])]);
        assert!(can_view_label(Some(BOB), &on_post, Some(&state), &both, &c));
        // In the audience but not the group.
        assert!(!can_view_label(
            Some(MOD),
            &on_post,
            Some(&state),
            &both,
            &c
        ));
        // In the group but not the audience.
        assert!(!can_view_label(
            Some(BOB),
            &on_post,
            Some(&state),
            &audiences,
            &c
        ));
    }

    #[test]
    fn audience_is_not_part_of_precedence() {
        const MOD: &str = "did:plc:moddddddddddddddddddddddd";
        const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
        const AUD: &str = "3mbaaaaaaaab2";
        let c = Everyone;
        let audiences = Audiences::from_records(LABELER, [&audience(AUD, &[MOD])]);
        let open = label(POST_A, "spam", "2026-11-14T08:00:00.000Z");
        let mut restricted = label(POST_A, "spam", "2026-11-14T09:00:00.000Z");
        restricted.audience = Some(AUD.into());
        // A later restricted record replaces the open one: only MOD sees it.
        let now = current_labels(
            [("3mbaaaaaaaaa2", &open), ("3mbaaaaaaaaa3", &restricted)],
            NOW_MS,
        );
        assert_eq!(now, [&restricted]);
        assert!(can_view_label(Some(MOD), now[0], None, &audiences, &c));
        assert!(!can_view_label(Some(BOB), now[0], None, &audiences, &c));
        // A later open record replaces the restricted one, for everyone.
        let mut reopened = open.clone();
        reopened.cts = "2026-11-14T09:30:00.000Z".into();
        let now = current_labels(
            [
                ("3mbaaaaaaaaa2", &open),
                ("3mbaaaaaaaaa3", &restricted),
                ("3mbaaaaaaaaa4", &reopened),
            ],
            NOW_MS,
        );
        assert_eq!(now, [&reopened]);
        assert!(can_view_label(Some(BOB), now[0], None, &audiences, &c));
    }

    #[test]
    fn the_audience_is_signed_when_set() {
        let signer = Signer::K256(k256::ecdsa::SigningKey::random(&mut OsRng));
        let key = didkey::parse_any(&signer.did_key()).unwrap();
        let plain = label(POST_A, "spam", "2026-11-14T09:00:00.000Z");
        let mut restricted = plain.clone();
        restricted.audience = Some("3mbaaaaaaaab2".into());
        // Without an audience, the bytes are as before.
        let m = drisl::decode(&label_signing_bytes(&plain)).unwrap();
        assert!(!m.as_map().unwrap().contains_key("audience"));
        restricted.sig = Some(sign_label(&restricted, &signer));
        assert!(verify_label(&restricted, &key));
        // Stripping or changing the audience breaks the signature.
        let mut stripped = restricted.clone();
        stripped.audience = None;
        assert!(!verify_label(&stripped, &key));
        let mut moved = restricted.clone();
        moved.audience = Some("3mbaaaaaaaab3".into());
        assert!(!verify_label(&moved, &key));
    }

    mod in_space {
        use super::*;
        use crate::community::{referenced_post, ReferencedPost};
        use crate::space::{
            community_space, everyone_space, followers_space, group_policy, group_space,
            managed_policy, only_me_policy, only_me_space, profile_space,
        };
        use umbrae_lexicons::{validate_space_label, CommunityRef, SPACE_LABEL};

        const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
        const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
        const CAROL: &str = "did:plc:carolcccccccccccccccccccc";
        const OTHER_LABELER: &str = "did:plc:otherlabeleroooooooooooo";
        const APP: &str = "did:web:app.example#umbrae_app";
        const RW: MemberAccess = MemberAccess {
            read: true,
            write: true,
        };

        fn trusted(dids: &[&str]) -> BTreeSet<String> {
            dids.iter().map(|d| d.to_string()).collect()
        }

        /// A label record by `writer` in `subject`'s space, validated.
        fn in_space(
            writer: &str,
            rkey: &str,
            subject: &SpaceRecordUri,
            val: &str,
            cts: &str,
            extra: &[(&str, Value)],
        ) -> (SpaceRecordUri, SpaceLabel) {
            let uri = subject.space().record(writer, SPACE_LABEL, rkey).unwrap();
            let mut m: BTreeMap<String, Value> = [
                ("$type", Value::Text(SPACE_LABEL.into())),
                ("uri", Value::Text(subject.to_string())),
                ("val", Value::Text(val.into())),
                ("cts", Value::Text(cts.into())),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
            m.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
            let label = validate_space_label(&uri, &m).unwrap();
            (uri, label)
        }

        fn refs(v: &[(SpaceRecordUri, SpaceLabel)]) -> Vec<(&SpaceRecordUri, &SpaceLabel)> {
            v.iter().map(|(u, l)| (u, l)).collect()
        }

        fn group() -> SpaceState {
            let mut s = SpaceState::new(
                group_space(ALICE, "3mbbbbbbbbbb2").unwrap(),
                Some(group_policy(None)),
            );
            s.members.insert(BOB, RW);
            s.members.insert(CAROL, RW);
            s
        }

        fn everyone() -> SpaceState {
            let mut s = SpaceState::new(everyone_space(ALICE).unwrap(), Some(managed_policy(APP)));
            s.members.insert(BOB, RW);
            s.members.insert(CAROL, RW);
            s
        }

        fn art() -> CommunityRef {
            CommunityRef::new(APP, "art").unwrap()
        }

        /// Alice's community space as its app holds it, Bob a writer, with
        /// the community's named labeler.
        fn community() -> SpaceState {
            let mut s = SpaceState::new(
                community_space(ALICE, &art()).unwrap(),
                Some(managed_policy(APP)),
            );
            s.community = Some(art());
            s.members.insert(ALICE, RW);
            s.members.insert(BOB, RW);
            s.label_writers.insert(LABELER.to_owned());
            s
        }

        fn post_in(s: &SpaceState, author: &str, rkey: &str) -> SpaceRecordUri {
            s.space.record(author, umbrae_lexicons::POST, rkey).unwrap()
        }

        #[test]
        fn latest_label_record_wins_per_writer() {
            let g = everyone();
            let p = post_in(&g, ALICE, "3mbaaaaaaaaa2");
            let q = post_in(&g, ALICE, "3mbaaaaaaaaa3");
            let early = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &p,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            let late = in_space(
                LABELER,
                "3mbaaaaaaal23",
                &p,
                "spam",
                "2026-11-14T09:00:00Z",
                &[],
            );
            let theirs = in_space(
                OTHER_LABELER,
                "3mbaaaaaaal24",
                &p,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            let expired = in_space(
                LABELER,
                "3mbaaaaaaal25",
                &q,
                "rude",
                "2026-11-14T08:00:00Z",
                &[("exp", Value::Text("2026-11-14T10:00:00Z".into()))],
            );
            let negated = in_space(
                LABELER,
                "3mbaaaaaaal26",
                &p,
                "spam",
                "2026-11-14T09:30:00Z",
                &[("neg", Value::Bool(true))],
            );
            let all = [
                early.clone(),
                late.clone(),
                theirs.clone(),
                expired,
                negated,
            ];
            let now = current_space_labels(refs(&all), NOW_MS);
            // One per writer; the later record wins; expired at exactly
            // now drops; a neg record never replaces anything.
            assert_eq!(now.len(), 2);
            assert!(now.contains(&(&late.0, &late.1)) && now.contains(&(&theirs.0, &theirs.1)));
            // Same cts: the higher record key wins.
            let tie = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &p,
                "spam",
                "2026-11-14T09:00:00Z",
                &[],
            );
            let pair = [tie, late.clone()];
            assert_eq!(
                current_space_labels(refs(&pair), NOW_MS),
                [(&late.0, &late.1)]
            );
            // A deleted record is simply absent: the earlier one applies.
            let left = [early.clone()];
            assert_eq!(
                current_space_labels(refs(&left), NOW_MS),
                [(&early.0, &early.1)]
            );
            // A label filed under another space's record URI never counts.
            let elsewhere = group()
                .space
                .record(LABELER, SPACE_LABEL, "3mbaaaaaaal27")
                .unwrap();
            assert!(current_space_labels([(&elsewhere, &early.1)], NOW_MS).is_empty());
        }

        #[test]
        fn whose_labels_count_where() {
            let c = Everyone;
            let us = trusted(&[LABELER, OTHER_LABELER, BOB, CAROL]);
            // A community: the named labeler's label counts; a writer's
            // doesn't, and nobody's does without label writers.
            let cm = community();
            let p = post_in(&cm, ALICE, "3mbaaaaaaaaa2");
            let named = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &p,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            let bobs = in_space(
                BOB,
                "3mbaaaaaaal23",
                &p,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            assert!(can_view_space_label(
                Some(BOB),
                &named.1,
                LABELER,
                &cm,
                &us,
                &c
            ));
            assert!(!can_view_space_label(Some(BOB), &bobs.1, BOB, &cm, &us, &c));
            let mut none = community();
            none.label_writers.clear();
            assert!(!can_view_space_label(
                Some(BOB),
                &named.1,
                LABELER,
                &none,
                &us,
                &c
            ));
            // Everyone: a listed (writer-set) labeler counts where trusted;
            // a listed replier the reader doesn't trust doesn't.
            let mut e = everyone();
            e.label_writers = trusted(&[LABELER, CAROL]);
            let ep = post_in(&e, ALICE, "3mbaaaaaaaaa2");
            let lab = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &ep,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            let carols = in_space(
                CAROL,
                "3mbaaaaaaal23",
                &ep,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            let only_lab = trusted(&[LABELER]);
            assert!(can_view_space_label(
                Some(BOB),
                &lab.1,
                LABELER,
                &e,
                &only_lab,
                &c
            ));
            assert!(!can_view_space_label(
                Some(BOB),
                &carols.1,
                CAROL,
                &e,
                &only_lab,
                &c
            ));
            // Not in the writer set (not listed): never, trusted or not.
            let out = in_space(
                OTHER_LABELER,
                "3mbaaaaaaal24",
                &ep,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            assert!(!can_view_space_label(
                Some(BOB),
                &out.1,
                OTHER_LABELER,
                &e,
                &us,
                &c
            ));
            e.label_writers.clear();
            assert!(!can_view_space_label(
                Some(BOB),
                &lab.1,
                LABELER,
                &e,
                &us,
                &c
            ));
            // A group: no labeler unless the owner added it as a member;
            // then it's an ordinary member, and counts where trusted.
            let g = group();
            let gp = post_in(&g, ALICE, "3mbaaaaaaaaa2");
            let gl = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &gp,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            assert!(!can_view_space_label(
                Some(BOB),
                &gl.1,
                LABELER,
                &g,
                &us,
                &c
            ));
            let mut added = group();
            added.members.insert(LABELER, RW);
            assert!(can_view_space_label(
                Some(BOB),
                &gl.1,
                LABELER,
                &added,
                &us,
                &c
            ));
            assert!(!can_view_space_label(
                Some(BOB),
                &gl.1,
                LABELER,
                &added,
                &trusted(&[OTHER_LABELER]),
                &c
            ));
            let mut f = SpaceState::new(followers_space(ALICE).unwrap(), Some(group_policy(None)));
            f.members.insert(BOB, RW);
            let fp = post_in(&f, ALICE, "3mbaaaaaaaaa2");
            let fl = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &fp,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            assert!(!can_view_space_label(
                Some(BOB),
                &fl.1,
                LABELER,
                &f,
                &us,
                &c
            ));
            // Only-me and the profile: nobody.
            let mut me = SpaceState::new(only_me_space(ALICE).unwrap(), Some(only_me_policy()));
            me.label_writers.insert(LABELER.into());
            let mp = post_in(&me, ALICE, "3mbaaaaaaaaa2");
            let ml = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &mp,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            assert!(!can_view_space_label(
                Some(ALICE),
                &ml.1,
                LABELER,
                &me,
                &us,
                &c
            ));
            let mut pr = SpaceState::new(profile_space(ALICE).unwrap(), Some(group_policy(None)));
            pr.label_writers.insert(LABELER.into());
            let pp = post_in(&pr, ALICE, "3mbaaaaaaaaa2");
            let pl = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &pp,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            assert!(!can_view_space_label(
                Some(ALICE),
                &pl.1,
                LABELER,
                &pr,
                &us,
                &c
            ));
            // The authority isn't a label writer.
            let own = in_space(
                ALICE,
                "3mbaaaaaaal25",
                &ep,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            let mut e = everyone();
            e.label_writers = trusted(&[ALICE]);
            assert!(!can_view_space_label(
                Some(BOB),
                &own.1,
                ALICE,
                &e,
                &trusted(&[ALICE]),
                &c
            ));
            // A label writer's own post never counts.
            let lab_post = post_in(&cm, LABELER, "3mbaaaaaaaaa4");
            assert!(!crate::access::is_writer(LABELER, &cm));
            assert!(!can_view_record(Some(ALICE), &lab_post, &cm, &c));
        }

        #[test]
        fn in_space_labels_follow_the_post() {
            let c = Everyone;
            let us = trusted(&[LABELER]);
            let cm = community();
            let p = post_in(&cm, ALICE, "3mbaaaaaaaaa2");
            let l = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &p,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            // Members see it, an outsider doesn't, nor anyone signed out.
            assert!(can_view_space_label(
                Some(ALICE),
                &l.1,
                LABELER,
                &cm,
                &us,
                &c
            ));
            assert!(!can_view_space_label(
                Some(CAROL),
                &l.1,
                LABELER,
                &cm,
                &us,
                &c
            ));
            assert!(!can_view_space_label(None, &l.1, LABELER, &cm, &us, &c));
            // Bob blocks Alice: he no longer sees her post or its label.
            let blocks = Blocks(&[(BOB, ALICE)]);
            assert!(!can_view_space_label(
                Some(BOB),
                &l.1,
                LABELER,
                &cm,
                &us,
                &blocks
            ));
            // A label on a repost needs the repost and its subject.
            let bobs = {
                let mut s = SpaceState::new(
                    community_space(BOB, &art()).unwrap(),
                    Some(managed_policy(APP)),
                );
                s.community = Some(art());
                s.members.insert(ALICE, RW);
                s.members.insert(BOB, RW);
                s.label_writers.insert(LABELER.to_owned());
                s
            };
            let rp = bobs
                .space
                .record(BOB, umbrae_lexicons::REPOST, "3mbaaaaaaaaa5")
                .unwrap();
            let rl = in_space(
                LABELER,
                "3mbaaaaaaal23",
                &rp,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            assert!(!can_view_space_label(
                Some(ALICE),
                &rl.1,
                LABELER,
                &bobs,
                &us,
                &c
            ));
            assert!(can_view_space_repost_label(
                Some(ALICE),
                &rl.1,
                LABELER,
                &p,
                &bobs,
                &cm,
                &us,
                &c
            ));
            let mut gone = community();
            gone.members.insert(
                ALICE,
                MemberAccess {
                    read: false,
                    write: false,
                },
            );
            assert!(!can_view_space_repost_label(
                Some(BOB),
                &rl.1,
                LABELER,
                &p,
                &bobs,
                &gone,
                &us,
                &c
            ));
            assert!(!can_view_space_repost_label(
                Some(ALICE),
                &l.1,
                LABELER,
                &p,
                &bobs,
                &cm,
                &us,
                &c
            ));
        }

        #[test]
        fn takedowns() {
            let c = Everyone;
            // Alice's group: Bob replies, Carol replies.
            let mut g = group();
            let root = post_in(&g, ALICE, "3mbaaaaaaaaa2");
            let reply = post_in(&g, BOB, "3mbaaaaaaaaa3");
            let carols = post_in(&g, CAROL, "3mbaaaaaaaaa4");
            let down = in_space(
                ALICE,
                "3mbaaaaaaal22",
                &reply,
                TAKEDOWN,
                "2026-11-14T08:00:00Z",
                &[],
            );
            let by_member = in_space(
                CAROL,
                "3mbaaaaaaal23",
                &carols,
                TAKEDOWN,
                "2026-11-14T08:00:00Z",
                &[],
            );
            let negated = in_space(
                ALICE,
                "3mbaaaaaaal24",
                &root,
                TAKEDOWN,
                "2026-11-14T08:00:00Z",
                &[("neg", Value::Bool(true))],
            );
            let all = [down.clone(), by_member, negated];
            apply_takedowns(&mut g, current_space_labels(refs(&all), NOW_MS));
            // Bob's reply is gone for everyone, Bob included, and shows as
            // unavailable where it's referenced.
            for v in [ALICE, BOB, CAROL] {
                assert!(!can_view_record(Some(v), &reply, &g, &c), "{v}");
            }
            assert_eq!(
                referenced_post(Some(CAROL), &reply, Some(&g), &c),
                ReferencedPost::Unavailable
            );
            // A member's !takedown, and a neg: true one, do nothing.
            assert!(can_view_record(Some(ALICE), &carols, &g, &c));
            assert!(can_view_record(Some(BOB), &root, &g, &c));
            // Deleting the label brings the reply back.
            apply_takedowns(&mut g, []);
            assert!(can_view_record(Some(CAROL), &reply, &g, &c));
            // A takedown naming another space is ignored.
            let other = SpaceState::new(group_space(ALICE, "3mbbbbbbbbbb3").unwrap(), None);
            let there = post_in(&other, BOB, "3mbaaaaaaaaa3");
            let (_, stray) = in_space(
                ALICE,
                "3mbaaaaaaal25",
                &there,
                TAKEDOWN,
                "2026-11-14T08:00:00Z",
                &[],
            );
            apply_takedowns(&mut g, [(&down.0, &stray)]);
            assert!(g.taken_down.is_empty());

            // A community: the named labeler's !takedown counts as the
            // community's, the writer's own counts, another writer's doesn't.
            let mut cm = community();
            let a1 = post_in(&cm, ALICE, "3mbaaaaaaaaa2");
            let a2 = post_in(&cm, ALICE, "3mbaaaaaaaaa3");
            let a3 = post_in(&cm, ALICE, "3mbaaaaaaaaa4");
            let labels = [
                in_space(
                    LABELER,
                    "3mbaaaaaaal22",
                    &a1,
                    TAKEDOWN,
                    "2026-11-14T08:00:00Z",
                    &[],
                ),
                in_space(
                    ALICE,
                    "3mbaaaaaaal23",
                    &a2,
                    TAKEDOWN,
                    "2026-11-14T08:00:00Z",
                    &[],
                ),
                in_space(
                    BOB,
                    "3mbaaaaaaal24",
                    &a3,
                    TAKEDOWN,
                    "2026-11-14T08:00:00Z",
                    &[],
                ),
            ];
            apply_takedowns(&mut cm, current_space_labels(refs(&labels), NOW_MS));
            assert!(!can_view_record(Some(BOB), &a1, &cm, &c));
            assert!(!can_view_record(Some(BOB), &a2, &cm, &c));
            assert!(can_view_record(Some(BOB), &a3, &cm, &c));
            // In an everyone space a labeler's !takedown is an ordinary
            // label, not a takedown.
            let mut e = everyone();
            e.label_writers.insert(LABELER.into());
            let ep = post_in(&e, ALICE, "3mbaaaaaaaaa2");
            let el = [in_space(
                LABELER,
                "3mbaaaaaaal22",
                &ep,
                TAKEDOWN,
                "2026-11-14T08:00:00Z",
                &[],
            )];
            apply_takedowns(&mut e, current_space_labels(refs(&el), NOW_MS));
            assert!(can_view_record(Some(BOB), &ep, &e, &c));
            assert!(can_view_space_label(
                Some(BOB),
                &el[0].1,
                LABELER,
                &e,
                &trusted(&[LABELER]),
                &c
            ));
            // Only-me: ignored.
            let mut me = SpaceState::new(only_me_space(ALICE).unwrap(), Some(only_me_policy()));
            let mp = post_in(&me, ALICE, "3mbaaaaaaaaa2");
            let ml = [in_space(
                ALICE,
                "3mbaaaaaaal22",
                &mp,
                TAKEDOWN,
                "2026-11-14T08:00:00Z",
                &[],
            )];
            apply_takedowns(&mut me, current_space_labels(refs(&ml), NOW_MS));
            assert!(can_view_record(Some(ALICE), &mp, &me, &c));
        }

        #[test]
        fn a_removed_label_writer_keeps_its_last_labels_at_the_managing_app() {
            let c = Everyone;
            // The app synced the named labeler's !takedown and a label, then
            // the writer removed it from the writer set (repoRemoved). The
            // app keeps both, and keeps it in label_writers.
            let mut cm = community();
            let a1 = post_in(&cm, ALICE, "3mbaaaaaaaaa2");
            let a2 = post_in(&cm, ALICE, "3mbaaaaaaaaa3");
            let kept = [
                in_space(
                    LABELER,
                    "3mbaaaaaaal22",
                    &a1,
                    TAKEDOWN,
                    "2026-11-14T08:00:00Z",
                    &[],
                ),
                in_space(
                    LABELER,
                    "3mbaaaaaaal23",
                    &a2,
                    "spam",
                    "2026-11-14T08:00:00Z",
                    &[],
                ),
            ];
            apply_takedowns(&mut cm, current_space_labels(refs(&kept), NOW_MS));
            assert!(!can_view_record(Some(BOB), &a1, &cm, &c));
            assert!(can_view_space_label(
                Some(BOB),
                &kept[1].1,
                LABELER,
                &cm,
                &trusted(&[LABELER]),
                &c
            ));
            // Everyone: the app keeps the removed writer listed too.
            let mut e = everyone();
            e.label_writers.insert(LABELER.into());
            let ep = post_in(&e, ALICE, "3mbaaaaaaaaa2");
            let el = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &ep,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            assert!(can_view_space_label(
                Some(BOB),
                &el.1,
                LABELER,
                &e,
                &trusted(&[LABELER]),
                &c
            ));
            // A reader that drops it from label_writers drops its labels.
            e.label_writers.clear();
            assert!(!can_view_space_label(
                Some(BOB),
                &el.1,
                LABELER,
                &e,
                &trusted(&[LABELER]),
                &c
            ));
        }

        #[test]
        fn both_homes_merge_to_one() {
            let cm = community();
            let p = post_in(&cm, ALICE, "3mbaaaaaaaaa2");
            let mut old = label(&p.to_string(), "spam", "2026-11-14T08:00:00.000Z");
            old.src = LABELER.into();
            let moved = in_space(
                LABELER,
                "3mbaaaaaaal22",
                &p,
                "spam",
                "2026-11-14T08:00:00Z",
                &[],
            );
            let other = in_space(
                LABELER,
                "3mbaaaaaaal23",
                &p,
                "rude",
                "2026-11-14T07:00:00Z",
                &[],
            );
            let ignored = in_space(
                LABELER,
                "3mbaaaaaaal24",
                &p,
                "nudity",
                "2026-11-14T07:00:00Z",
                &[("neg", Value::Bool(true))],
            );
            let merged = merge_label_homes(
                [&old],
                [
                    (&moved.0, &moved.1),
                    (&other.0, &other.1),
                    (&ignored.0, &ignored.1),
                ],
            );
            assert_eq!(merged.len(), 2);
            let spam = merged.iter().find(|l| l.val == "spam").unwrap();
            assert!(spam.sig.is_none() && spam.src == LABELER);
            // A later labeler-space record of the same label wins.
            let mut newer = old.clone();
            newer.cts = "2026-11-14T09:00:00.000Z".into();
            let merged = merge_label_homes([&newer], [(&moved.0, &moved.1)]);
            assert_eq!(merged, [newer.clone()]);
            // Another labeler's label of the same value stays separate.
            let mut theirs = old.clone();
            theirs.src = OTHER_LABELER.into();
            assert_eq!(
                merge_label_homes([&theirs], [(&moved.0, &moved.1)]).len(),
                2
            );
            // The labeler-space home still follows the post for its viewers.
            let none = Audiences::default();
            assert!(can_view_label(Some(BOB), &old, Some(&cm), &none, &Everyone));
            assert!(!can_view_label(
                Some(CAROL),
                &old,
                Some(&cm),
                &none,
                &Everyone
            ));
        }
    }

    #[test]
    fn retired_keys_verify_only_older_labels() {
        let old = Signer::K256(k256::ecdsa::SigningKey::random(&mut OsRng));
        let new = Signer::P256(p256::ecdsa::SigningKey::random(&mut OsRng));
        let policies = umbrae_lexicons::LabelerPolicies {
            label_values: vec![],
            policies: BTreeMap::new(),
            reason_types: None,
            subject_types: None,
            subject_collections: None,
            label_key: Some(new.did_key()),
            previous_label_keys: vec![umbrae_lexicons::RetiredKey {
                key: old.did_key(),
                retired_at: "2026-11-14T09:00:00.000Z".into(),
            }],
            created_at: "2026-11-14T08:00:00.000Z".into(),
        };
        let keys = LabelKeys::from_policies(&policies);
        let signed = |cts: &str, by: &Signer| {
            let mut l = label(POST_A, "spam", cts);
            l.sig = Some(sign_label(&l, by));
            l
        };
        // The current key verifies any label.
        assert!(verify_label_with(
            &signed("2026-11-14T08:00:00.000Z", &new),
            &keys
        ));
        assert!(verify_label_with(
            &signed("2026-11-14T10:00:00.000Z", &new),
            &keys
        ));
        // The retired key only before it was retired.
        assert!(verify_label_with(
            &signed("2026-11-14T08:59:59.999Z", &old),
            &keys
        ));
        assert!(!verify_label_with(
            &signed("2026-11-14T09:00:00.000Z", &old),
            &keys
        ));
        assert!(!verify_label_with(
            &signed("2026-11-14T10:00:00.000Z", &old),
            &keys
        ));
        // Neither key: no.
        let other = Signer::K256(k256::ecdsa::SigningKey::random(&mut OsRng));
        assert!(!verify_label_with(
            &signed("2026-11-14T08:00:00.000Z", &other),
            &keys
        ));
        assert!(!verify_label_with(
            &signed("2026-11-14T08:00:00.000Z", &new),
            &LabelKeys::default()
        ));
        assert!(LabelKeys::default().is_empty());
        assert!(verify_label_with(
            &signed("2026-11-14T08:00:00.000Z", &other),
            &LabelKeys::single(didkey::parse_any(&other.did_key()).unwrap())
        ));
    }
}
