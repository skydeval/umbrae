//! Checking synced records against the Umbrae lexicons.

use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::uri::SpaceRecordUri;
use umbrae_lexicons::{
    validate_labeler_record, validate_private_record, validate_record, validate_space_label,
    Invalid, LabelerRecord, PrivateRecord, Record, SpaceLabel, LABELER_SPACE_TYPE,
    PRIVATE_SPACE_TYPE, SPACE_LABEL, SPACE_TYPE,
};

/// What a record turned out to be.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Checked {
    /// A valid hidden-post record (post, like or group name).
    Hidden(Record),
    /// A valid labeler record (label, profile, policies or reasons).
    Labeler(Box<LabelerRecord>),
    /// A valid record in a private account's space: a native post, repost,
    /// like or gate, or the owner's rules. Another account's shows only
    /// while its author passes the owner's rules.
    Private(Box<PrivateRecord>),
    /// An in-space label (`com.atproto.label.record`) in a
    /// `tools.umbrae.space` or private space. Whose count, and whether it
    /// applies at all, is the reader's rule (the `umbrae` crate).
    SpaceLabel(Box<SpaceLabel>),
    /// Not one of Umbrae's collections, in an Umbrae space: the PDS's own
    /// published policy and member records, or another app's. Handle or
    /// ignore.
    Other,
    /// In a space type Umbrae doesn't know.
    UnknownSpace,
    /// Fails its lexicon or Umbrae's rules: never show it.
    Invalid(Invalid),
}

/// Check one record by its space type.
pub fn check(uri: &SpaceRecordUri, value: &BTreeMap<String, Value>) -> Checked {
    match uri.space().space_type() {
        SPACE_TYPE => match validate_record(uri, value) {
            Ok(Some(Record::SpaceLabel(l))) => Checked::SpaceLabel(l),
            Ok(Some(r)) => Checked::Hidden(r),
            Ok(None) => Checked::Other,
            Err(e) => Checked::Invalid(e),
        },
        LABELER_SPACE_TYPE => match validate_labeler_record(uri, value) {
            Ok(Some(r)) => Checked::Labeler(Box::new(r)),
            Ok(None) => Checked::Other,
            Err(e) => Checked::Invalid(e),
        },
        PRIVATE_SPACE_TYPE if uri.collection() == SPACE_LABEL => {
            match validate_space_label(uri, value) {
                Ok(l) => Checked::SpaceLabel(Box::new(l)),
                Err(e) => Checked::Invalid(e),
            }
        }
        PRIVATE_SPACE_TYPE => match validate_private_record(uri, value) {
            Ok(Some(r)) => Checked::Private(Box::new(r)),
            Ok(None) => Checked::Other,
            Err(e) => Checked::Invalid(e),
        },
        _ => Checked::UnknownSpace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbrae_core::uri::SpaceRef;

    #[test]
    fn dispatches_by_space_type() {
        let t = |s: &str| Value::Text(s.into());
        let post = BTreeMap::from([
            ("$type".to_owned(), t("tools.umbrae.post")),
            ("text".to_owned(), t("hi")),
            ("createdAt".to_owned(), t("2026-11-14T10:00:00Z")),
        ]);
        let group = SpaceRef::new("did:example:a", SPACE_TYPE, "3mbbbbbbbbbb2").unwrap();
        let u = group
            .record("did:example:b", "tools.umbrae.post", "3mbaaaaaaaaa2")
            .unwrap();
        assert!(matches!(check(&u, &post), Checked::Hidden(Record::Post(_))));
        // An in-space label is its own kind, in a group or a private space,
        // and a broken one is invalid.
        let label = BTreeMap::from([
            ("$type".to_owned(), t(SPACE_LABEL)),
            ("uri".to_owned(), t(&u.to_string())),
            ("val".to_owned(), t("spam")),
            ("cts".to_owned(), t("2026-11-27T10:00:00Z")),
        ]);
        let l = group
            .record("did:example:c", SPACE_LABEL, "3mbaaaaaaaal2")
            .unwrap();
        assert!(matches!(check(&l, &label), Checked::SpaceLabel(x) if x.record() == Some(&u)));
        let bad = group.record("did:example:c", SPACE_LABEL, "nope").unwrap();
        assert!(matches!(check(&bad, &label), Checked::Invalid(_)));
        let private = SpaceRef::new("did:example:a", PRIVATE_SPACE_TYPE, "self").unwrap();
        let pl = private
            .record("did:example:c", SPACE_LABEL, "3mbaaaaaaaal2")
            .unwrap();
        assert!(matches!(check(&pl, &label), Checked::SpaceLabel(x) if x.record().is_none()));
        let member = group
            .record(
                "did:example:a",
                "com.atproto.memberspace.member",
                "did:example:b",
            )
            .unwrap();
        assert_eq!(check(&member, &BTreeMap::new()), Checked::Other);
        let other = SpaceRef::new("did:example:a", "com.example.space", "x").unwrap();
        let u = other
            .record("did:example:b", "tools.umbrae.post", "3mbaaaaaaaaa2")
            .unwrap();
        assert_eq!(check(&u, &post), Checked::UnknownSpace);
        let labeler = SpaceRef::new("did:example:a", LABELER_SPACE_TYPE, "self").unwrap();
        let u = labeler
            .record("did:example:a", "tools.umbrae.label", "3mbaaaaaaaaa2")
            .unwrap();
        assert!(matches!(check(&u, &BTreeMap::new()), Checked::Invalid(_)));
    }

    #[test]
    fn checks_private_spaces() {
        let t = |s: &str| Value::Text(s.into());
        let native = BTreeMap::from([
            ("$type".to_owned(), t("app.bsky.feed.post")),
            ("text".to_owned(), t("hi")),
            ("createdAt".to_owned(), t("2026-11-27T10:00:00Z")),
        ]);
        let private = SpaceRef::new("did:example:a", PRIVATE_SPACE_TYPE, "self").unwrap();
        // The owner's top-level post counts; another account's doesn't.
        let own = private
            .record("did:example:a", "app.bsky.feed.post", "3mbaaaaaaaaa2")
            .unwrap();
        assert!(matches!(
            check(&own, &native),
            Checked::Private(r) if matches!(*r, PrivateRecord::Post(_))
        ));
        let theirs = private
            .record("did:example:b", "app.bsky.feed.post", "3mbaaaaaaaaa2")
            .unwrap();
        assert!(matches!(check(&theirs, &native), Checked::Invalid(_)));
        // The published policy is the caller's.
        let policy = private
            .record("did:example:a", "com.atproto.space.policy", "self")
            .unwrap();
        assert_eq!(check(&policy, &BTreeMap::new()), Checked::Other);
        // A native post in a group space isn't Umbrae's there.
        let group = SpaceRef::new("did:example:a", SPACE_TYPE, "3mbbbbbbbbbb2").unwrap();
        let u = group
            .record("did:example:a", "app.bsky.feed.post", "3mbaaaaaaaaa2")
            .unwrap();
        assert_eq!(check(&u, &native), Checked::Other);
    }
}
