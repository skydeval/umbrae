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
//! [`verify_label`]) with the labeler's `#atproto_label` key.

use crate::space::Misconfigured;
use std::collections::BTreeMap;
use umbrae_core::didkey::AnyKey;
use umbrae_core::drisl::{self, Value};
use umbrae_core::policy::{MemberAccess, MemberPolicy, Policy};
use umbrae_core::tokens::Signer;
use umbrae_core::uri::{SpaceRef, UriError};
use umbrae_lexicons::{Label, LABELER_SPACE_TYPE, SELF_RKEY};

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
/// unless true (as the reference labeler signs).
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
    drisl::encode(&Value::Map(m)).expect("a label of strings always encodes")
}

/// Sign a label with the labeler's `#atproto_label` key.
pub fn sign_label(label: &Label, key: &Signer) -> Vec<u8> {
    key.sign(&label_signing_bytes(label)).to_vec()
}

/// Whether the label carries a valid low-S signature by `key`.
pub fn verify_label(label: &Label, key: &AnyKey) -> bool {
    label
        .sig
        .as_ref()
        .is_some_and(|sig| key.verify_low_s(&label_signing_bytes(label), sig))
}

/// The labels in effect at `now_ms` (Unix milliseconds), from a labeler's
/// label records as `(rkey, label)`. Per `(src, uri, cid, val)` the latest
/// record wins, by `cts` and then by record key; it applies unless it is a
/// negation or has expired. Output is ordered by subject, then value.
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
            sign * (off[1..3].parse::<i64>().ok()? * 3600 + off[4..6].parse::<i64>().ok()? * 60)
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
    }

    #[test]
    fn space_and_policy() {
        let s = labeler_space(LABELER).unwrap();
        assert_eq!(
            s.to_string(),
            format!("at://{LABELER}/space/{LABELER_SPACE_TYPE}/self")
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
}
