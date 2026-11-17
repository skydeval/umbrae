//! Checking synced records against the Umbrae lexicons.

use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::uri::SpaceRecordUri;
use umbrae_lexicons::{
    validate_labeler_record, validate_record, Invalid, LabelerRecord, Record, LABELER_SPACE_TYPE,
    SPACE_TYPE,
};

/// What a record turned out to be.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Checked {
    /// A valid hidden-post record (post, like or group name).
    Hidden(Record),
    /// A valid labeler record (label, profile, policies or reasons).
    Labeler(Box<LabelerRecord>),
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
}
