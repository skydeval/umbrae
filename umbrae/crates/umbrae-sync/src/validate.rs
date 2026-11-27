//! Checking synced records against the Umbrae lexicons.

use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::uri::SpaceRecordUri;
use umbrae_lexicons::{
    validate_labeler_record, validate_private_record, validate_record, Invalid, LabelerRecord,
    PrivateRecord, Record, LABELER_SPACE_TYPE, PRIVATE_SPACE_TYPE, SPACE_TYPE,
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
            Ok(Some(r)) => Checked::Hidden(r),
            Ok(None) => Checked::Other,
            Err(e) => Checked::Invalid(e),
        },
        LABELER_SPACE_TYPE => match validate_labeler_record(uri, value) {
            Ok(Some(r)) => Checked::Labeler(Box::new(r)),
            Ok(None) => Checked::Other,
            Err(e) => Checked::Invalid(e),
        },
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
