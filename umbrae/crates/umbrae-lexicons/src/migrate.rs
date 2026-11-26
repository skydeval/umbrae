//! Moving stored records to the `at:space/` URI form.
//!
//! The PDS migrates its own internal space URIs, but not URIs stored inside
//! record values. A record written before the change holds old-form refs
//! (`at://{did}/space/...`), which no longer parse, so validation drops it.
//! [`upgrade_space_uris`] rewrites them. The record's author then writes the
//! result back with `com.atproto.space.putRecord` at the same key.
//!
//! - **Whole strings only:** a string value that is exactly an old-form space
//!   or space-record URI is rewritten, wherever it sits in the record.
//!   Nothing inside prose is touched. Validation already refuses hidden URIs
//!   in text, so a record that has one stays refused.
//! - **New CIDs:** a rewritten record has a new CID, so a strong ref to it
//!   from someone else's record (a reply's parent, a like's subject) names
//!   the old version. Strong refs whose `uri` is rewritten keep their `cid`,
//!   which still names the version they were made against.

use umbrae_core::drisl::Value;
use umbrae_core::uri::upgrade_legacy;

/// Rewrite every old-form space URI string in `value` to the new form, in
/// place. Returns how many strings changed; 0 means the record needs no
/// rewrite.
pub fn upgrade_space_uris(value: &mut Value) -> usize {
    match value {
        Value::Text(t) => match upgrade_legacy(t) {
            Some(new) => {
                *t = new;
                1
            }
            None => 0,
        },
        Value::Array(a) => a.iter_mut().map(upgrade_space_uris).sum(),
        Value::Map(m) => m.values_mut().map(upgrade_space_uris).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const OLD: &str = "at://did:plc:alice/space/tools.umbrae.space/3mbbbbbbbbbb2/did:plc:bob/tools.umbrae.post/3mbaaaaaaaaa5";
    const NEW: &str = "at:space/did:plc:alice/tools.umbrae.space/3mbbbbbbbbbb2/did:plc:bob/tools.umbrae.post/3mbaaaaaaaaa5";

    fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    fn map(pairs: &[(&str, Value)]) -> Value {
        Value::Map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    #[test]
    fn rewrites_nested_refs_and_leaves_the_rest() {
        let public = "at://did:plc:carol/app.bsky.feed.post/3mbaaaaaaaaa5";
        let prose = format!("see {OLD}");
        let mut v = map(&[
            ("text", text(&prose)),
            (
                "reply",
                map(&[
                    ("parent", map(&[("uri", text(OLD)), ("cid", text("bafy"))])),
                    ("root", map(&[("uri", text(public))])),
                ]),
            ),
            ("list", Value::Array(vec![text(OLD), text(NEW)])),
        ]);
        assert_eq!(upgrade_space_uris(&mut v), 2);
        let want = map(&[
            ("text", text(&prose)),
            (
                "reply",
                map(&[
                    ("parent", map(&[("uri", text(NEW)), ("cid", text("bafy"))])),
                    ("root", map(&[("uri", text(public))])),
                ]),
            ),
            ("list", Value::Array(vec![text(NEW), text(NEW)])),
        ]);
        assert_eq!(v, want);
        assert_eq!(upgrade_space_uris(&mut v), 0);
    }
}
