//! Where records go.
//!
//! - A reply to a hidden post goes into that post's space, in the replier's
//!   own repo there, so its audience is exactly the parent's.
//! - A hidden reply to a public post goes into whichever space the author
//!   picks, like a new post.
//! - A like or a repost goes into its subject's space.
//! - A quote of a hidden post goes into that post's space; a quote of a
//!   public record goes wherever the author picks. A quote that is also a
//!   reply to a hidden post needs both in the same space.
//! - **In a community**, everyone writes only into their own space: a
//!   reply, like, repost or quote of a post in a community space goes into
//!   the actor's own space for the same community (same type and key). A
//!   reply that also quotes goes there too.
//! - A public record never points at a hidden one: a space URI has no
//!   public meaning, and naming one in public leaks that it exists.

use crate::space::is_community_space;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{contains_space_uri, SpaceRecordUri, SpaceRef, UriError};
use umbrae_lexicons::Target;

/// The space `actor` writes into when acting on a hidden record in
/// `subject`: the subject's own space, or in a community, the actor's own
/// space for it.
fn acting_space(actor: &str, subject: &SpaceRef) -> Result<SpaceRef, UriError> {
    if is_community_space(subject) {
        SpaceRef::new(actor, subject.space_type(), subject.skey())
    } else {
        Ok(subject.clone())
    }
}

/// The space `actor`'s reply must go into, or `None` when the parent is
/// public and the author chooses.
pub fn reply_space(actor: &str, parent: &Target) -> Result<Option<SpaceRef>, UriError> {
    parent
        .hidden()
        .map(|u| acting_space(actor, u.space()))
        .transpose()
}

pub fn like_space(actor: &str, subject: &SpaceRecordUri) -> Result<SpaceRef, UriError> {
    acting_space(actor, subject.space())
}

pub fn repost_space(actor: &str, subject: &SpaceRecordUri) -> Result<SpaceRef, UriError> {
    acting_space(actor, subject.space())
}

/// The space `actor`'s quote must go into, or `None` when the quoted
/// record is public and the author chooses.
pub fn quote_space(actor: &str, quoted: &Target) -> Result<Option<SpaceRef>, UriError> {
    quoted
        .hidden()
        .map(|u| acting_space(actor, u.space()))
        .transpose()
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
    use crate::space::{community_space, followers_space};
    use std::collections::BTreeMap;
    use umbrae_lexicons::{CommunityRef, POST, SPACE_TYPE};

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
            reply_space(BOB, &Target::Hidden(h.clone()))
                .unwrap()
                .as_ref(),
            Some(h.space())
        );
        let public =
            Target::parse(&format!("at://{BOB}/app.bsky.feed.post/3mbaaaaaaaaa5")).unwrap();
        assert_eq!(reply_space(BOB, &public), Ok(None));
        assert_eq!(&like_space(BOB, &h).unwrap(), h.space());
    }

    #[test]
    fn reposts_and_quotes_follow_a_hidden_subject() {
        let h = hidden();
        assert_eq!(&repost_space(BOB, &h).unwrap(), h.space());
        assert_eq!(
            quote_space(BOB, &Target::Hidden(h.clone()))
                .unwrap()
                .as_ref(),
            Some(h.space())
        );
        // A quote of a public record goes wherever the author picks.
        let public =
            Target::parse(&format!("at://{BOB}/app.bsky.feed.post/3mbaaaaaaaaa5")).unwrap();
        assert_eq!(quote_space(BOB, &public), Ok(None));
        // The followers space is a group: same space too.
        let f = followers_space(ALICE)
            .unwrap()
            .record(ALICE, POST, "3mbaaaaaaaaa2")
            .unwrap();
        assert_eq!(&like_space(BOB, &f).unwrap(), f.space());
    }

    #[test]
    fn in_a_community_actors_write_in_their_own_space() {
        let art = CommunityRef::new("did:web:app.example#umbrae_app", "art").unwrap();
        let post = community_space(ALICE, &art)
            .unwrap()
            .record(ALICE, POST, "3mbaaaaaaaaa2")
            .unwrap();
        let bobs = community_space(BOB, &art).unwrap();
        let t = Target::Hidden(post.clone());
        assert_eq!(reply_space(BOB, &t), Ok(Some(bobs.clone())));
        assert_eq!(quote_space(BOB, &t), Ok(Some(bobs.clone())));
        assert_eq!(like_space(BOB, &post), Ok(bobs.clone()));
        assert_eq!(repost_space(BOB, &post), Ok(bobs));
        // The author acting on their own post stays in their own space.
        assert_eq!(&like_space(ALICE, &post).unwrap(), post.space());
        assert!(like_space("not a did", &post).is_err());
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
