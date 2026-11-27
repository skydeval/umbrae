//! In-space labels: `com.atproto.label.record`, written into a space by a
//! labeler, in the same space as the record it labels.
//!
//! - The lexicon: a TID key, `uri` and `val` (1 to 128 bytes) required,
//!   `cid` optional, `cts` and an optional `exp` as datetimes. Unknown
//!   fields are allowed.
//! - The subject must be a record in the label's own space. A label naming
//!   another space, a public record, an account or a space is ignored.
//! - A record with `neg: true` is ignored: the lexicon has no `neg`, so it
//!   never applies. Removing a label is deleting its record.
//! - The repo it's in authenticates it; there's no `src` or signature.
//!   Whose labels count is the reader's rule (the `umbrae` crate).

use crate::labeler::{datetime, text};
use crate::validate::{string, Invalid};
use crate::SPACE_LABEL;
use std::collections::BTreeMap;
use umbrae_core::cid::Cid;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{is_space_uri, is_valid_tid, SpaceRecordUri};

type Map = BTreeMap<String, Value>;

/// What an in-space label is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceLabelSubject {
    /// A record in the label's own space.
    Record(SpaceRecordUri),
    /// Anything else, or a record with `neg: true`: the label never applies.
    Ignored,
}

/// A `com.atproto.label.record`. Its writer is the record URI's author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceLabel {
    pub uri: String,
    pub subject: SpaceLabelSubject,
    pub cid: Option<Cid>,
    pub val: String,
    pub cts: String,
    pub exp: Option<String>,
}

impl SpaceLabel {
    /// The record it applies to, unless it's ignored.
    pub fn record(&self) -> Option<&SpaceRecordUri> {
        match &self.subject {
            SpaceLabelSubject::Record(u) => Some(u),
            SpaceLabelSubject::Ignored => None,
        }
    }
}

/// Validate a `com.atproto.label.record` synced from a space, given its
/// full URI. `Err` for a record failing the lexicon; a label that doesn't
/// apply comes back with [`SpaceLabelSubject::Ignored`].
pub fn validate_space_label(uri: &SpaceRecordUri, value: &Map) -> Result<SpaceLabel, Invalid> {
    if uri.collection() != SPACE_LABEL {
        return Err(Invalid("not a com.atproto.label.record"));
    }
    match value.get("$type") {
        Some(Value::Text(t)) if t == SPACE_LABEL => {}
        _ => return Err(Invalid("$type must match the collection")),
    }
    if !is_valid_tid(uri.rkey()) {
        return Err(Invalid("record key must be a TID"));
    }
    let target = text(value, "uri")?.ok_or(Invalid("label uri is required"))?;
    let cid = match text(value, "cid")? {
        None => None,
        Some(c) => Some(Cid::parse(&c).map_err(|_| Invalid("label cid"))?),
    };
    let val = string(value, "val", 1, 128, 128)?.ok_or(Invalid("label val is required"))?;
    let cts = datetime(value, "cts")?.ok_or(Invalid("label cts is required"))?;
    let exp = datetime(value, "exp")?;
    let negated = matches!(value.get("neg"), Some(Value::Bool(true)));
    let subject = match SpaceRecordUri::parse(&target) {
        Ok(u) if is_space_uri(&target) && u.space() == uri.space() && !negated => {
            SpaceLabelSubject::Record(u)
        }
        _ => SpaceLabelSubject::Ignored,
    };
    Ok(SpaceLabel {
        uri: target,
        subject,
        cid,
        val,
        cts,
        exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{POST, SPACE_TYPE};
    use umbrae_core::uri::SpaceRef;

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const LABELER: &str = "did:plc:labelerllllllllllllllll";
    const RKEY: &str = "3mbaaaaaaaal2";
    const NOW: &str = "2026-11-27T10:00:00.000Z";

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn space(skey: &str) -> SpaceRef {
        SpaceRef::new(ALICE, SPACE_TYPE, skey).unwrap()
    }

    fn post() -> SpaceRecordUri {
        space("everyone")
            .record(ALICE, POST, "3mbaaaaaaaaa2")
            .unwrap()
    }

    fn at(rkey: &str) -> SpaceRecordUri {
        space("everyone")
            .record(LABELER, SPACE_LABEL, rkey)
            .unwrap()
    }

    fn label(subject: &str, extra: &[(&str, Value)]) -> Map {
        let mut m: Map = [
            ("$type", t(SPACE_LABEL)),
            ("uri", t(subject)),
            ("val", t("spam")),
            ("cts", t(NOW)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        m.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
        m
    }

    #[test]
    fn a_label_on_a_record_in_its_own_space() {
        let cid = Cid::for_drisl(b"post").to_string();
        let l = validate_space_label(
            &at(RKEY),
            &label(
                &post().to_string(),
                &[("cid", t(&cid)), ("exp", t("2026-12-01T00:00:00Z"))],
            ),
        )
        .unwrap();
        assert_eq!(l.record(), Some(&post()));
        assert_eq!(l.cid.map(|c| c.to_string()), Some(cid));
        assert_eq!((l.val.as_str(), l.cts.as_str()), ("spam", NOW));
        assert_eq!(l.exp.as_deref(), Some("2026-12-01T00:00:00Z"));
        // Any collection, and extra fields such as src.
        let like = space("everyone")
            .record(ALICE, "tools.umbrae.like", "3mbaaaaaaaaa3")
            .unwrap();
        let l = validate_space_label(&at(RKEY), &label(&like.to_string(), &[("src", t(LABELER))]))
            .unwrap();
        assert_eq!(l.record(), Some(&like));
    }

    #[test]
    fn the_lexicon_is_enforced() {
        let p = post().to_string();
        let bad = |rkey: &str, m: Map| validate_space_label(&at(rkey), &m).is_err();
        assert!(bad("notatid", label(&p, &[])));
        assert!(bad(RKEY, label(&p, &[("val", t(""))])));
        assert!(bad(RKEY, label(&p, &[("val", t(&"x".repeat(129)))])));
        // 128 bytes pass; 65 two-byte characters (130 bytes) don't.
        assert!(!bad(RKEY, label(&p, &[("val", t(&"x".repeat(128)))])));
        assert!(bad(RKEY, label(&p, &[("val", t(&"é".repeat(65)))])));
        assert!(bad(RKEY, label(&p, &[("cts", t("yesterday"))])));
        assert!(bad(RKEY, label(&p, &[("exp", t("2026-12-01"))])));
        assert!(bad(RKEY, label(&p, &[("cid", t("not a cid"))])));
        assert!(bad(RKEY, label(&p, &[("$type", t("tools.umbrae.label"))])));
        let mut no_cts = label(&p, &[]);
        no_cts.remove("cts");
        assert!(bad(RKEY, no_cts));
        let mut no_uri = label(&p, &[]);
        no_uri.remove("uri");
        assert!(bad(RKEY, no_uri));
        // Another collection's URI isn't a label record.
        let other = space("everyone").record(LABELER, POST, RKEY).unwrap();
        assert!(validate_space_label(&other, &label(&p, &[])).is_err());
    }

    #[test]
    fn labels_that_never_apply() {
        let ignored = |subject: &str, extra: &[(&str, Value)]| {
            validate_space_label(&at(RKEY), &label(subject, extra))
                .unwrap()
                .subject
                == SpaceLabelSubject::Ignored
        };
        let elsewhere = space("3mbbbbbbbbbb2")
            .record(ALICE, POST, "3mbaaaaaaaaa2")
            .unwrap();
        assert!(ignored(&elsewhere.to_string(), &[]));
        assert!(ignored(
            &format!("at://{ALICE}/app.bsky.feed.post/3mbaaaaaaaaa2"),
            &[]
        ));
        assert!(ignored(ALICE, &[]));
        assert!(ignored(&format!("at://{ALICE}"), &[]));
        assert!(ignored(&space("everyone").to_string(), &[]));
        assert!(ignored("not a uri", &[]));
        // neg: true never applies; neg: false is as if absent.
        let p = post().to_string();
        assert!(ignored(&p, &[("neg", Value::Bool(true))]));
        assert!(!ignored(&p, &[("neg", Value::Bool(false))]));
    }

    #[test]
    fn umbrae_spaces_check_their_label_records() {
        use crate::{validate_record, Record};
        let p = post().to_string();
        assert!(matches!(
            validate_record(&at(RKEY), &label(&p, &[])),
            Ok(Some(Record::SpaceLabel(l))) if l.record() == Some(&post())
        ));
        assert!(validate_record(&at("notatid"), &label(&p, &[])).is_err());
    }
}
