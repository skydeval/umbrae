//! Where records go.
//!
//! - A reply to a hidden post goes into that post's space, in the replier's
//!   own repo there, so its audience is exactly the parent's.
//! - A hidden reply to a public post goes into whichever space the author
//!   picks, like a new post.
//! - A like goes into the liked post's space.
//! - A public record never points at a hidden one: a space URI has no
//!   public meaning, and naming one in public leaks that it exists.

use umbrae_core::drisl::Value;
use umbrae_core::uri::{contains_space_uri, SpaceRecordUri, SpaceRef};
use umbrae_lexicons::Target;

/// The space a reply must go into, or `None` when the parent is public and
/// the author chooses.
pub fn reply_space(parent: &Target) -> Option<SpaceRef> {
    parent.hidden().map(|u| u.space().clone())
}

pub fn like_space(subject: &SpaceRecordUri) -> SpaceRef {
    subject.space().clone()
}

/// Whether a record headed for a **public** repo names a hidden record
/// anywhere in its value, including inside its text or another URL. A
/// client refuses to write one that does.
pub fn leaks_hidden(value: &Value) -> bool {
    match value {
        Value::Text(t) => contains_space_uri(t),
        Value::Array(a) => a.iter().any(leaks_hidden),
        Value::Map(m) => m.values().any(leaks_hidden),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use umbrae_lexicons::{POST, SPACE_TYPE};

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";

    fn hidden() -> SpaceRecordUri {
        SpaceRef::new(ALICE, SPACE_TYPE, "3mbbbbbbbbbb2")
            .unwrap()
            .record(ALICE, POST, "3mbaaaaaaaaa2")
            .unwrap()
    }

    #[test]
    fn replies_and_likes_follow_the_parent() {
        let h = hidden();
        assert_eq!(
            reply_space(&Target::Hidden(h.clone())).as_ref(),
            Some(h.space())
        );
        let public =
            Target::parse(&format!("at://{BOB}/app.bsky.feed.post/3mbaaaaaaaaa5")).unwrap();
        assert_eq!(reply_space(&public), None);
        assert_eq!(&like_space(&h), h.space());
    }

    #[test]
    fn public_records_never_name_hidden_ones() {
        let quote = |uri: String| {
            let r = BTreeMap::from([("uri".to_string(), Value::Text(uri))]);
            Value::Map(BTreeMap::from([(
                "embed".to_string(),
                Value::Map(BTreeMap::from([("record".to_string(), Value::Map(r))])),
            )]))
        };
        assert!(leaks_hidden(&quote(hidden().to_string())));
        assert!(!leaks_hidden(&quote(format!(
            "at://{BOB}/app.bsky.feed.post/3mbaaaaaaaaa5"
        ))));
        assert!(leaks_hidden(&Value::Array(vec![Value::Text(
            hidden().space().to_string()
        )])));
        // Pasted into the text, or wrapped in another URL.
        let text = |t: String| Value::Map(BTreeMap::from([("text".to_string(), Value::Text(t))]));
        assert!(leaks_hidden(&text(format!("look: {}", hidden()))));
        assert!(leaks_hidden(&text(format!(
            "https://app.example/view?uri={}",
            hidden()
        ))));
        assert!(!leaks_hidden(&text(format!(
            "look: at://{BOB}/app.bsky.feed.post/3mbaaaaaaaaa5"
        ))));
    }
}
