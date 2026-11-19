//! Hidden lists and exemptions.
//!
//! - A **personal** list (`tools.umbrae.list`, TID key), its entries
//!   (`tools.umbrae.listitem`, naming the list by its record key) and
//!   exemptions (`tools.umbrae.exemption`) live in the owner's only-me
//!   space, written by the owner.
//! - A **shared** list is its own space (`tools.umbrae.listSpace`, TID
//!   key): the list record at `self`, entries with TID keys and no `list`
//!   field, all written by the authority. Subscribers are read-only members
//!   and the member list is unpublished, so no app serves these spaces:
//!   clients read them from the owner's PDS.
//! - Entries and exemptions name accounts by DID. Nothing names a hidden
//!   record, except an exemption's `kind.list`: a public
//!   `app.bsky.graph.list`, one of the owner's own personal lists, or a
//!   shared list's `self` record.

use crate::validate::{datetime, mentions_space_uri, string, Invalid, PublicUri};
use crate::{LIST, LISTITEM, LIST_SPACE_TYPE, SELF_RKEY, SPACE_TYPE};
use std::collections::BTreeMap;
use umbrae_core::drisl::Value;
use umbrae_core::uri::{is_space_uri, is_valid_did, is_valid_tid, SpaceRecordUri};

type Map = BTreeMap<String, Value>;

pub const EXEMPTION_LABEL: &str = "tools.umbrae.exemption#label";
pub const EXEMPTION_LABELER: &str = "tools.umbrae.exemption#labeler";
pub const EXEMPTION_LIST: &str = "tools.umbrae.exemption#list";
const PUBLIC_LIST: &str = "app.bsky.graph.list";

/// What a list is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Purpose {
    Block,
    Mute,
    Curate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    pub purpose: Purpose,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

/// One account on a list. `list` is the personal list's record key; a
/// shared list's entries have none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub subject: String,
    pub list: Option<String>,
    pub created_at: String,
}

/// The list an exemption names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListRef {
    Public(PublicUri),
    Hidden(SpaceRecordUri),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExemptionKind {
    /// Ignore one label value from one labeler on the subject.
    Label { labeler: String, val: String },
    /// Ignore every label from one labeler on the subject.
    Labeler { labeler: String },
    /// Don't apply one mute or block list to the subject.
    List(ListRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exemption {
    pub subject: String,
    pub kind: ExemptionKind,
    pub created_at: String,
}

/// A record from a shared list space.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListRecord {
    List(List),
    Item(ListItem),
}

/// Validate a record synced from a shared list space, given its full URI.
///
/// `Ok(None)` for a collection that isn't Umbrae's (the PDS's published
/// policy record).
pub fn validate_list_record(
    uri: &SpaceRecordUri,
    value: &Map,
) -> Result<Option<ListRecord>, Invalid> {
    let space = uri.space();
    if space.space_type() != LIST_SPACE_TYPE || !is_valid_tid(space.skey()) {
        return Err(Invalid("not a tools.umbrae.listSpace space"));
    }
    let collection = uri.collection();
    if collection.starts_with("tools.umbrae.") && collection != LIST && collection != LISTITEM {
        return Err(Invalid("only lists and list items belong in a list space"));
    }
    if collection != LIST && collection != LISTITEM {
        return Ok(None);
    }
    if uri.author() != space.authority() {
        return Err(Invalid("only the list owner's records count"));
    }
    type_matches(value, collection)?;
    if collection == LIST {
        if uri.rkey() != SELF_RKEY {
            return Err(Invalid("a shared list's record sits at rkey self"));
        }
        return Ok(Some(ListRecord::List(list(value)?)));
    }
    if !is_valid_tid(uri.rkey()) {
        return Err(Invalid("record key must be a TID"));
    }
    if value.contains_key("list") {
        return Err(Invalid("a shared list's entries name no list"));
    }
    Ok(Some(ListRecord::Item(listitem(value, false)?)))
}

fn type_matches(m: &Map, collection: &str) -> Result<(), Invalid> {
    match m.get("$type") {
        Some(Value::Text(t)) if t == collection => Ok(()),
        _ => Err(Invalid("$type must match the collection")),
    }
}

pub(crate) fn list(m: &Map) -> Result<List, Invalid> {
    no_hidden(m)?;
    let purpose = match m.get("purpose") {
        Some(Value::Text(t)) => match t.as_str() {
            "block" => Purpose::Block,
            "mute" => Purpose::Mute,
            "curate" => Purpose::Curate,
            _ => return Err(Invalid("list purpose must be block, mute or curate")),
        },
        _ => return Err(Invalid("list purpose is required")),
    };
    Ok(List {
        purpose,
        name: string(m, "name", 1, 640, 64)?.ok_or(Invalid("name is required"))?,
        description: string(m, "description", 0, 3000, 300)?,
        created_at: datetime(m, "createdAt")?,
    })
}

/// `personal`: in only-me, where `list` is required.
pub(crate) fn listitem(m: &Map, personal: bool) -> Result<ListItem, Invalid> {
    no_hidden(m)?;
    let list = match m.get("list") {
        None if !personal => None,
        Some(Value::Text(k)) if personal && is_valid_tid(k) => Some(k.clone()),
        _ => return Err(Invalid("a personal list item names its list's TID key")),
    };
    Ok(ListItem {
        subject: did(m, "subject")?,
        list,
        created_at: datetime(m, "createdAt")?,
    })
}

/// `owner`: the only-me space's authority.
pub(crate) fn exemption(m: &Map, owner: &str) -> Result<Exemption, Invalid> {
    let kind = match m.get("kind") {
        Some(Value::Map(k)) => k,
        _ => return Err(Invalid("exemption kind must be an object")),
    };
    let mut rest = m.clone();
    if let Some(Value::Map(k)) = rest.get_mut("kind") {
        if matches!(k.get("$type"), Some(Value::Text(t)) if t == EXEMPTION_LIST) {
            k.remove("list");
        }
    }
    no_hidden(&rest)?;
    let kind = match kind.get("$type") {
        Some(Value::Text(t)) if t == EXEMPTION_LABEL => ExemptionKind::Label {
            labeler: did(kind, "labeler")?,
            val: string(kind, "val", 1, 128, 128)?.ok_or(Invalid("label val is required"))?,
        },
        Some(Value::Text(t)) if t == EXEMPTION_LABELER => ExemptionKind::Labeler {
            labeler: did(kind, "labeler")?,
        },
        Some(Value::Text(t)) if t == EXEMPTION_LIST => {
            ExemptionKind::List(list_ref(kind.get("list"), owner)?)
        }
        _ => return Err(Invalid("unknown exemption kind")),
    };
    Ok(Exemption {
        subject: did(m, "subject")?,
        kind,
        created_at: datetime(m, "createdAt")?,
    })
}

fn list_ref(v: Option<&Value>, owner: &str) -> Result<ListRef, Invalid> {
    let s = match v {
        Some(Value::Text(s)) => s,
        _ => return Err(Invalid("an exemption's list must be a URI")),
    };
    if !is_space_uri(s) {
        return match PublicUri::parse(s) {
            Some(u) if u.collection == PUBLIC_LIST => Ok(ListRef::Public(u)),
            _ => Err(Invalid("a public list must be an app.bsky.graph.list")),
        };
    }
    let u = SpaceRecordUri::parse(s).map_err(|_| Invalid("malformed space record URI"))?;
    let sp = u.space();
    let personal = sp.space_type() == SPACE_TYPE
        && sp.skey() == SELF_RKEY
        && sp.authority() == owner
        && u.author() == owner
        && is_valid_tid(u.rkey());
    let shared = sp.space_type() == LIST_SPACE_TYPE
        && is_valid_tid(sp.skey())
        && u.author() == sp.authority()
        && u.rkey() == SELF_RKEY;
    if u.collection() == LIST && (personal || shared) {
        Ok(ListRef::Hidden(u))
    } else {
        Err(Invalid(
            "a hidden list must be the owner's own or a shared list",
        ))
    }
}

fn no_hidden(m: &Map) -> Result<(), Invalid> {
    if mentions_space_uri(&Value::Map(m.clone())) {
        Err(Invalid("this record may not name a hidden record"))
    } else {
        Ok(())
    }
}

fn did(m: &Map, key: &str) -> Result<String, Invalid> {
    match m.get(key) {
        Some(Value::Text(d)) if is_valid_did(d) => Ok(d.clone()),
        _ => Err(Invalid("expected a DID")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{validate_record, Record, EXEMPTION, POST};
    use umbrae_core::uri::SpaceRef;

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobbbbbbbbbbbbbbbbbbbbbb";
    const LABELER: &str = "did:plc:labelerlllllllllllllllll";
    const SKEY: &str = "3mbbbbbbbbbb2";
    const RKEY: &str = "3mbaaaaaaaaa2";
    const NOW: &str = "2026-11-19T10:00:00Z";

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn map(pairs: &[(&str, Value)]) -> Map {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn only_me(author: &str, collection: &str, rkey: &str) -> SpaceRecordUri {
        SpaceRef::new(ALICE, SPACE_TYPE, SELF_RKEY)
            .unwrap()
            .record(author, collection, rkey)
            .unwrap()
    }

    fn shared(author: &str, collection: &str, rkey: &str) -> SpaceRecordUri {
        SpaceRef::new(ALICE, LIST_SPACE_TYPE, SKEY)
            .unwrap()
            .record(author, collection, rkey)
            .unwrap()
    }

    fn a_list(purpose: &str) -> Map {
        map(&[
            ("$type", t(LIST)),
            ("purpose", t(purpose)),
            ("name", t("spam")),
            ("createdAt", t(NOW)),
        ])
    }

    fn item(list: Option<&str>) -> Map {
        let mut m = map(&[
            ("$type", t(LISTITEM)),
            ("subject", t(BOB)),
            ("createdAt", t(NOW)),
        ]);
        if let Some(l) = list {
            m.insert("list".into(), t(l));
        }
        m
    }

    fn exempt(kind: Map) -> Map {
        map(&[
            ("$type", t(EXEMPTION)),
            ("subject", t(BOB)),
            ("kind", Value::Map(kind)),
            ("createdAt", t(NOW)),
        ])
    }

    fn list_kind(uri: &str) -> Map {
        map(&[("$type", t(EXEMPTION_LIST)), ("list", t(uri))])
    }

    #[test]
    fn personal_lists_live_in_only_me() {
        for p in ["block", "mute", "curate"] {
            assert!(matches!(
                validate_record(&only_me(ALICE, LIST, RKEY), &a_list(p)),
                Ok(Some(Record::List(_)))
            ));
        }
        assert!(validate_record(&only_me(ALICE, LIST, RKEY), &a_list("other")).is_err());
        assert!(matches!(
            validate_record(&only_me(ALICE, LISTITEM, RKEY), &item(Some(RKEY))),
            Ok(Some(Record::ListItem(i))) if i.list.as_deref() == Some(RKEY)
        ));
        // A personal item must name its list by TID.
        assert!(validate_record(&only_me(ALICE, LISTITEM, RKEY), &item(None)).is_err());
        assert!(validate_record(&only_me(ALICE, LISTITEM, RKEY), &item(Some("self"))).is_err());
        // Not in a group, not by someone else, not at a non-TID key.
        let group = SpaceRef::new(ALICE, SPACE_TYPE, SKEY)
            .unwrap()
            .record(ALICE, LIST, RKEY)
            .unwrap();
        assert!(validate_record(&group, &a_list("mute")).is_err());
        assert!(validate_record(&only_me(BOB, LIST, RKEY), &a_list("mute")).is_err());
        assert!(validate_record(&only_me(ALICE, LIST, "self"), &a_list("mute")).is_err());
    }

    #[test]
    fn shared_list_spaces() {
        assert!(matches!(
            validate_list_record(&shared(ALICE, LIST, "self"), &a_list("curate")),
            Ok(Some(ListRecord::List(_)))
        ));
        assert!(matches!(
            validate_list_record(&shared(ALICE, LISTITEM, RKEY), &item(None)),
            Ok(Some(ListRecord::Item(_)))
        ));
        // A shared item names no list; the list sits at self.
        assert!(validate_list_record(&shared(ALICE, LISTITEM, RKEY), &item(Some(RKEY))).is_err());
        assert!(validate_list_record(&shared(ALICE, LIST, RKEY), &a_list("mute")).is_err());
        // Only the owner's records count.
        assert!(validate_list_record(&shared(BOB, LISTITEM, RKEY), &item(None)).is_err());
        // No other Umbrae records; the PDS's own are left to the caller.
        assert!(validate_list_record(&shared(ALICE, POST, RKEY), &map(&[])).is_err());
        assert_eq!(
            validate_list_record(
                &shared(ALICE, "com.atproto.memberspace.policy", "self"),
                &map(&[])
            ),
            Ok(None)
        );
        // Not a list space.
        assert!(validate_list_record(&only_me(ALICE, LIST, RKEY), &a_list("mute")).is_err());
    }

    #[test]
    fn lists_and_items_name_no_hidden_record() {
        let hidden = shared(ALICE, LIST, "self").to_string();
        let mut l = a_list("mute");
        l.insert("description".into(), t(&format!("see {hidden}")));
        assert!(validate_list_record(&shared(ALICE, LIST, "self"), &l).is_err());
        let mut i = item(None);
        i.insert("via".into(), t(&hidden));
        assert!(validate_list_record(&shared(ALICE, LISTITEM, RKEY), &i).is_err());
        let mut i = item(None);
        i.insert("subject".into(), t(&hidden));
        assert!(validate_list_record(&shared(ALICE, LISTITEM, RKEY), &i).is_err());
    }

    #[test]
    fn exemptions() {
        let at = only_me(ALICE, EXEMPTION, RKEY);
        let label = map(&[
            ("$type", t(EXEMPTION_LABEL)),
            ("labeler", t(LABELER)),
            ("val", t("rude")),
        ]);
        assert!(matches!(
            validate_record(&at, &exempt(label)),
            Ok(Some(Record::Exemption(Exemption {
                kind: ExemptionKind::Label { .. },
                ..
            })))
        ));
        let labeler = map(&[("$type", t(EXEMPTION_LABELER)), ("labeler", t(LABELER))]);
        assert!(validate_record(&at, &exempt(labeler)).is_ok());
        let not_did = map(&[("$type", t(EXEMPTION_LABELER)), ("labeler", t("bob"))]);
        assert!(validate_record(&at, &exempt(not_did)).is_err());
        let unknown = map(&[("$type", t("tools.umbrae.exemption#other"))]);
        assert!(validate_record(&at, &exempt(unknown)).is_err());

        // Lists: a public list, the owner's own, or a shared list's self.
        let public = "at://did:plc:carolcccccccccccccccccccc/app.bsky.graph.list/3mbaaaaaaaaa5";
        let own = only_me(ALICE, LIST, RKEY).to_string();
        let subscribed = SpaceRef::new(BOB, LIST_SPACE_TYPE, SKEY)
            .unwrap()
            .record(BOB, LIST, "self")
            .unwrap()
            .to_string();
        for ok in [public, own.as_str(), subscribed.as_str()] {
            assert!(validate_record(&at, &exempt(list_kind(ok))).is_ok(), "{ok}");
        }
        let public_post = "at://did:plc:carolcccccccccccccccccccc/app.bsky.feed.post/3mbaaaaaaaaa5";
        let bobs_only_me = SpaceRef::new(BOB, SPACE_TYPE, SELF_RKEY)
            .unwrap()
            .record(BOB, LIST, RKEY)
            .unwrap()
            .to_string();
        let a_post = only_me(ALICE, POST, RKEY).to_string();
        let not_self = SpaceRef::new(BOB, LIST_SPACE_TYPE, SKEY)
            .unwrap()
            .record(BOB, LIST, RKEY)
            .unwrap()
            .to_string();
        let not_owners = SpaceRef::new(BOB, LIST_SPACE_TYPE, SKEY)
            .unwrap()
            .record(ALICE, LIST, "self")
            .unwrap()
            .to_string();
        for bad in [public_post, &bobs_only_me, &a_post, &not_self, &not_owners] {
            assert!(
                validate_record(&at, &exempt(list_kind(bad))).is_err(),
                "{bad}"
            );
        }
        // Only kind.list may name a hidden record, and only in a #list.
        let mut sneaky = exempt(list_kind(&own));
        sneaky.insert("via".into(), t(&subscribed));
        assert!(validate_record(&at, &sneaky).is_err());
        let mut k = list_kind(&own);
        k.insert("note".into(), t(&subscribed));
        assert!(validate_record(&at, &exempt(k)).is_err());
        let label_with_list = map(&[
            ("$type", t(EXEMPTION_LABEL)),
            ("labeler", t(LABELER)),
            ("val", t("rude")),
            ("list", t(&own)),
        ]);
        assert!(validate_record(&at, &exempt(label_with_list)).is_err());
        // Only in the owner's only-me.
        assert!(
            validate_record(&only_me(BOB, EXEMPTION, RKEY), &exempt(list_kind(public))).is_err()
        );
    }
}
