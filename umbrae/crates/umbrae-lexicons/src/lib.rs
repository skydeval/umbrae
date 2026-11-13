//! Lexicons for Umbrae hidden posts, and the checks a reader applies to
//! records it syncs from a space.
//!
//! | NSID | What |
//! |---|---|
//! | `tools.umbrae.space` | the space type: one author's hidden posts for one group |
//! | `tools.umbrae.post` | a hidden post (the fields of `app.bsky.feed.post`) |
//! | `tools.umbrae.like` | a like of a hidden post |
//! | `tools.umbrae.group` | the group's name, written by the authority |
//!
//! Validation works on decoded DRISL maps, as they come out of a space
//! repo (STAR archive, `listRepoOps` or `getRecord`). Unknown fields are
//! allowed, as Lexicon evolution allows. A record that fails is dropped
//! from views; it is never an error for the space as a whole.

mod validate;

pub use validate::{
    validate_record, Group, Invalid, Like, Post, PublicUri, Record, Reply, StrongRef, Target,
};

pub const SPACE_TYPE: &str = "tools.umbrae.space";
pub const POST: &str = "tools.umbrae.post";
pub const LIKE: &str = "tools.umbrae.like";
pub const GROUP: &str = "tools.umbrae.group";
/// The group record's only record key.
pub const GROUP_RKEY: &str = "self";

/// Every Umbrae lexicon document, by NSID.
pub const LEXICONS: &[(&str, &str)] = &[
    (
        SPACE_TYPE,
        include_str!("../lexicons/tools/umbrae/space.json"),
    ),
    (POST, include_str!("../lexicons/tools/umbrae/post.json")),
    (LIKE, include_str!("../lexicons/tools/umbrae/like.json")),
    (GROUP, include_str!("../lexicons/tools/umbrae/group.json")),
];

/// A lexicon document by NSID.
pub fn get(nsid: &str) -> Option<&'static str> {
    LEXICONS.iter().find(|(n, _)| *n == nsid).map(|(_, d)| *d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn documents_parse_and_carry_their_ids() {
        for (nsid, doc) in LEXICONS {
            let v: Value = serde_json::from_str(doc).unwrap();
            assert_eq!(v["lexicon"], 1, "{nsid}");
            assert_eq!(v["id"], *nsid);
            assert!(v["defs"]["main"].is_object(), "{nsid}");
        }
        assert!(get(POST).is_some());
        assert!(get("tools.umbrae.nope").is_none());
    }

    #[test]
    fn space_type_declares_its_collections() {
        let v: Value = serde_json::from_str(get(SPACE_TYPE).unwrap()).unwrap();
        let main = &v["defs"]["main"];
        assert_eq!(main["type"], "space");
        assert_eq!(main["key"], "any");
        let cols: Vec<_> = main["collections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(cols, [POST, LIKE, GROUP]);
    }
}
