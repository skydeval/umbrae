//! `space:` OAuth scopes (spec: "OAuth scopes").
//!
//! ```text
//! space:<spaceType>[?authority=<did>][&skey=<skey>][&collection=<nsid>...][&action=<action>...][&manage=<op>...]
//! ```
//!
//! `authority` defaults to `self` (the granting user, resolved at grant
//! time; unresolved it matches nothing), `skey` to `*`, `action` to
//! `read create update delete`, and `manage` to none. An omitted
//! `collection` means the space type declaration's `collections`, which
//! the caller materializes with [`SpacePermission::with_default_collections`];
//! until then the grant has no write targets.
//!
//! Parsing and formatting follow the reference implementation, so a
//! formatted scope is canonical: defaults omitted, values deduplicated and
//! ordered, and `:` `/` `+` `,` `@` `%` left unencoded.

use crate::uri::{is_valid_did, is_valid_nsid, is_valid_record_key};
use std::fmt;

/// A record action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    ReadSelf,
    Read,
    Create,
    Update,
    Delete,
}

impl Action {
    const ALL: [Action; 5] = [
        Action::ReadSelf,
        Action::Read,
        Action::Create,
        Action::Update,
        Action::Delete,
    ];
    /// `read_self` is left out since `read` implies it.
    const DEFAULT: [Action; 4] = [Action::Read, Action::Create, Action::Update, Action::Delete];

    pub fn as_str(self) -> &'static str {
        match self {
            Action::ReadSelf => "read_self",
            Action::Read => "read",
            Action::Create => "create",
            Action::Update => "update",
            Action::Delete => "delete",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }
}

/// A space management operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManageOp {
    Create,
    Update,
    Delete,
}

impl ManageOp {
    const ALL: [ManageOp; 3] = [ManageOp::Create, ManageOp::Update, ManageOp::Delete];

    pub fn as_str(self) -> &'static str {
        match self {
            ManageOp::Create => "create",
            ManageOp::Update => "update",
            ManageOp::Delete => "delete",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }
}

/// What a grant's authority names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Authority {
    Any,
    /// The granting user; resolve with [`SpacePermission::with_resolved_authority`].
    SelfUser,
    Did(String),
}

/// A wildcard or a concrete value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Pattern {
    Any,
    Is(String),
}

impl Pattern {
    fn matches(&self, v: &str) -> bool {
        match self {
            Pattern::Any => true,
            Pattern::Is(s) => s == v,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Pattern::Any => "*",
            Pattern::Is(s) => s,
        }
    }
}

/// A parsed `space:` permission.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpacePermission {
    pub space_type: Pattern,
    pub authority: Authority,
    pub skey: Pattern,
    /// `None` when omitted: no write targets until defaults are applied.
    /// Otherwise sorted and deduplicated, or just `[Any]`.
    pub collection: Option<Vec<Pattern>>,
    /// Non-empty, in canonical order.
    pub action: Vec<Action>,
    /// `None` when omitted; otherwise non-empty, in canonical order.
    pub manage: Option<Vec<ManageOp>>,
}

/// The space a check is about.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub space_type: &'a str,
    pub authority: &'a str,
    pub skey: &'a str,
}

/// The operation a check is about.
#[derive(Debug, Clone, Copy)]
pub enum Operation<'a> {
    Read,
    ReadSelf,
    Write(Action, &'a str),
    Manage(ManageOp),
}

const PREFIX: &str = "space";

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode; `+` is a space when `form` is set (query values).
fn decode(s: &str, form: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                out.push(hex_val(b[i + 1])? << 4 | hex_val(b[i + 2])?);
                i += 3;
            }
            b'%' => return None,
            b'+' if form => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Encode as the reference does: form-encoding (alphanumerics and `*-._`
/// kept), then `:` `/` `+` `,` `@` `%` restored.
fn encode(s: &str) -> String {
    let mut out = String::new();
    for &c in s.as_bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(c as char)
            }
            b':' | b'/' | b',' | b'@' | b'%' => out.push(c as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

fn parse_pattern(v: &str, valid: fn(&str) -> bool) -> Option<Pattern> {
    if v == "*" {
        Some(Pattern::Any)
    } else if valid(v) {
        Some(Pattern::Is(v.to_owned()))
    } else {
        None
    }
}

impl SpacePermission {
    /// Parse a scope string; `None` if it isn't a valid `space:` scope.
    pub fn parse(scope: &str) -> Option<Self> {
        let rest = scope.strip_prefix(PREFIX)?;
        let (positional, query) = match rest.as_bytes().first() {
            None => (None, None),
            Some(b':') => {
                let rest = &rest[1..];
                match rest.split_once('?') {
                    Some((p, q)) => (Some(decode(p, false)?), Some(q)),
                    None => (Some(decode(rest, false)?), None),
                }
            }
            Some(b'?') => (None, Some(&rest[1..])),
            _ => return None,
        };

        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            for pair in q.split('&').filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                params.push((decode(k, true)?, decode(v, true)?));
            }
        }
        let all = |k: &str| -> Vec<&str> {
            params
                .iter()
                .filter(|(pk, _)| pk == k)
                .map(|(_, v)| v.as_str())
                .collect()
        };
        let single = |k: &str| -> Result<Option<&str>, ()> {
            match all(k)[..] {
                [] => Ok(None),
                [v] => Ok(Some(v)),
                _ => Err(()),
            }
        };
        const KEYS: [&str; 6] = [
            "spaceType",
            "authority",
            "skey",
            "collection",
            "action",
            "manage",
        ];
        if params.iter().any(|(k, _)| !KEYS.contains(&k.as_str())) {
            return None;
        }

        let named_type = single("spaceType").ok()?;
        let space_type = match (positional.as_deref(), named_type) {
            (Some(_), Some(_)) => return None,
            (Some(t), None) | (None, Some(t)) => parse_pattern(t, is_valid_nsid)?,
            (None, None) => return None,
        };
        let authority = match single("authority").ok()? {
            None | Some("self") => Authority::SelfUser,
            Some("*") => Authority::Any,
            Some(d) if is_valid_did(d) => Authority::Did(d.to_owned()),
            Some(_) => return None,
        };
        let skey = match single("skey").ok()? {
            None => Pattern::Any,
            Some(s) => parse_pattern(s, is_valid_record_key)?,
        };
        let collections = all("collection");
        let collection = if collections.is_empty() {
            None
        } else {
            let mut c = collections
                .iter()
                .map(|v| parse_pattern(v, is_valid_nsid))
                .collect::<Option<Vec<_>>>()?;
            if c.contains(&Pattern::Any) {
                c = vec![Pattern::Any];
            } else {
                c.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                c.dedup();
            }
            Some(c)
        };
        let actions = all("action");
        let action = if actions.is_empty() {
            Action::DEFAULT.to_vec()
        } else {
            let parsed = actions
                .iter()
                .map(|a| Action::parse(a))
                .collect::<Option<Vec<_>>>()?;
            Action::ALL
                .into_iter()
                .filter(|a| parsed.contains(a))
                .collect()
        };
        let manages = all("manage");
        let manage = if manages.is_empty() {
            None
        } else {
            let parsed = manages
                .iter()
                .map(|m| ManageOp::parse(m))
                .collect::<Option<Vec<_>>>()?;
            Some(
                ManageOp::ALL
                    .into_iter()
                    .filter(|m| parsed.contains(m))
                    .collect(),
            )
        };
        Some(Self {
            space_type,
            authority,
            skey,
            collection,
            action,
            manage,
        })
    }

    /// Whether this grant authorizes `op` on `target`.
    pub fn matches(&self, target: &Target<'_>, op: &Operation<'_>) -> bool {
        if !self.space_type.matches(target.space_type) || !self.skey.matches(target.skey) {
            return false;
        }
        match &self.authority {
            Authority::Any => {}
            Authority::Did(d) if d == target.authority => {}
            // An unresolved `self` matches nothing: fail closed.
            _ => return false,
        }
        match op {
            Operation::Manage(m) => self.manage.as_ref().is_some_and(|ms| ms.contains(m)),
            Operation::Read => self.action.contains(&Action::Read),
            Operation::ReadSelf => {
                self.action.contains(&Action::Read) || self.action.contains(&Action::ReadSelf)
            }
            Operation::Write(a, collection) => {
                matches!(a, Action::Create | Action::Update | Action::Delete)
                    && self.action.contains(a)
                    && self
                        .collection
                        .as_ref()
                        .is_some_and(|cs| cs.iter().any(|c| c.matches(collection)))
            }
        }
    }

    /// Fill an omitted `collection` from the space type declaration's
    /// `collections`, as resolved when the grant is evaluated.
    pub fn with_default_collections(&self, collections: &[&str]) -> Self {
        if self.collection.is_some() || collections.is_empty() {
            return self.clone();
        }
        let mut c: Vec<Pattern> = collections
            .iter()
            .map(|s| Pattern::Is((*s).to_owned()))
            .collect();
        c.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        c.dedup();
        Self {
            collection: Some(c),
            ..self.clone()
        }
    }

    /// Resolve an `authority` of `self` to the granting user's DID.
    pub fn with_resolved_authority(&self, user: &str) -> Self {
        match self.authority {
            Authority::SelfUser => Self {
                authority: Authority::Did(user.to_owned()),
                ..self.clone()
            },
            _ => self.clone(),
        }
    }

    /// Whether this grant asks for any authority and any type: the consent
    /// screen should warn prominently.
    pub fn is_wildcard_authority_and_type(&self) -> bool {
        self.authority == Authority::Any && self.space_type == Pattern::Any
    }

    /// The narrowest scope covering `op` on `target`, for error messages.
    pub fn needed_for(target: &Target<'_>, op: &Operation<'_>) -> Self {
        let (collection, action, manage) = match op {
            Operation::Read => (None, vec![Action::Read], None),
            Operation::ReadSelf => (None, vec![Action::ReadSelf], None),
            Operation::Write(a, c) => (Some(vec![Pattern::Is((*c).to_owned())]), vec![*a], None),
            Operation::Manage(m) => (None, vec![Action::ReadSelf], Some(vec![*m])),
        };
        Self {
            space_type: Pattern::Is(target.space_type.to_owned()),
            authority: Authority::Did(target.authority.to_owned()),
            skey: Pattern::Is(target.skey.to_owned()),
            collection,
            action,
            manage,
        }
    }
}

impl fmt::Display for SpacePermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut params: Vec<(&str, String)> = Vec::new();
        match &self.authority {
            Authority::SelfUser => {}
            Authority::Any => params.push(("authority", "*".into())),
            Authority::Did(d) => params.push(("authority", d.clone())),
        }
        if self.skey != Pattern::Any {
            params.push(("skey", self.skey.as_str().to_owned()));
        }
        for c in self.collection.iter().flatten() {
            params.push(("collection", c.as_str().to_owned()));
        }
        let default = self.action.len() == Action::DEFAULT.len()
            && Action::DEFAULT.iter().all(|a| self.action.contains(a));
        if !default {
            for a in &self.action {
                params.push(("action", a.as_str().to_owned()));
            }
        }
        for m in self.manage.iter().flatten() {
            params.push(("manage", m.as_str().to_owned()));
        }
        // The positional value goes through encodeURIComponent, which keeps
        // `*`; an NSID needs no encoding.
        write!(f, "{PREFIX}:{}", self.space_type.as_str())?;
        for (i, (k, v)) in params.iter().enumerate() {
            write!(f, "{}{k}={}", if i == 0 { '?' } else { '&' }, encode(v))?;
        }
        Ok(())
    }
}

/// A `space` permission inside a permission set. Its `spaceType` may not
/// be a wildcard.
pub fn permission_from_set_entry(
    space_type: &str,
    authority: Option<&str>,
    skey: Option<&str>,
    collection: &[&str],
    action: &[&str],
    manage: &[&str],
) -> Option<SpacePermission> {
    if space_type == "*" {
        return None;
    }
    let mut s = format!("{PREFIX}:{space_type}");
    let mut params: Vec<String> = Vec::new();
    if let Some(a) = authority {
        params.push(format!("authority={}", encode(a)));
    }
    if let Some(k) = skey {
        params.push(format!("skey={}", encode(k)));
    }
    for (name, values) in [
        ("collection", collection),
        ("action", action),
        ("manage", manage),
    ] {
        for v in values {
            params.push(format!("{name}={}", encode(v)));
        }
    }
    if !params.is_empty() {
        s.push('?');
        s.push_str(&params.join("&"));
    }
    SpacePermission::parse(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: [Action; 4] = Action::DEFAULT;

    fn p(s: &str) -> SpacePermission {
        SpacePermission::parse(s).unwrap_or_else(|| panic!("{s}"))
    }

    const T: Target<'static> = Target {
        space_type: "com.atmoboards.forum",
        authority: "did:plc:abc",
        skey: "default",
    };

    #[test]
    fn parses_with_defaults() {
        let s = p("space:com.atmoboards.forum");
        assert_eq!(s.space_type, Pattern::Is("com.atmoboards.forum".into()));
        assert_eq!(s.authority, Authority::SelfUser);
        assert_eq!(s.skey, Pattern::Any);
        assert_eq!(s.collection, None);
        assert_eq!(s.action, DEFAULT);
        assert_eq!(s.manage, None);
        assert_eq!(s.to_string(), "space:com.atmoboards.forum");
    }

    #[test]
    fn named_space_type_but_not_both_or_type() {
        assert_eq!(
            p("space?spaceType=com.atmoboards.forum").space_type,
            Pattern::Is("com.atmoboards.forum".into())
        );
        assert!(SpacePermission::parse("space?type=com.atmoboards.forum").is_none());
        assert!(SpacePermission::parse("space:com.a.b?spaceType=com.a.b").is_none());
        assert!(SpacePermission::parse("space").is_none());
    }

    #[test]
    fn parses_full_scope_and_round_trips() {
        let input = "space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default&collection=com.atmoboards.thread&action=create";
        let s = p(input);
        assert_eq!(s.authority, Authority::Did("did:plc:abc123xyz".into()));
        assert_eq!(s.skey, Pattern::Is("default".into()));
        assert_eq!(
            s.collection,
            Some(vec![Pattern::Is("com.atmoboards.thread".into())])
        );
        assert_eq!(s.action, [Action::Create]);
        assert_eq!(s.to_string(), input);
        assert_eq!(
            p("space:com.atmoboards.forum?action=read").to_string(),
            "space:com.atmoboards.forum?action=read"
        );
        let m = p("space:com.atmoboards.forum?manage=delete&manage=update");
        assert_eq!(m.manage, Some(vec![ManageOp::Update, ManageOp::Delete]));
        assert_eq!(
            m.to_string(),
            "space:com.atmoboards.forum?manage=update&manage=delete"
        );
    }

    #[test]
    fn normalizes_collections() {
        let s = p("space:com.a.b?collection=com.z.y&collection=com.a.c&collection=com.z.y");
        assert_eq!(
            s.to_string(),
            "space:com.a.b?collection=com.a.c&collection=com.z.y"
        );
        assert_eq!(
            p("space:com.a.b?collection=com.z.y&collection=*").collection,
            Some(vec![Pattern::Any])
        );
    }

    #[test]
    fn rejections() {
        for bad in [
            "space:foo bar",
            "space:short",
            "space:*?authority=not-a-did",
            "space:*?authority=did:",
            "space:com.example.x?action=bogus",
            "space:com.example.x?manage=bogus",
            "space:com.example.x?collection=not_an_nsid",
            "space:com.example.x?skey=",
            "space:com.example.x?authority=*&authority=self",
            "space:com.example.x?unknown=1",
            "repo:com.example.x",
            "whatever",
            "spacex:com.example.x",
        ] {
            assert!(SpacePermission::parse(bad).is_none(), "{bad}");
        }
        for skey in ["hello%20world", ".", "..", "a%2Fb", "a%23b"] {
            let s = format!("space:com.example.x?skey={skey}");
            assert!(SpacePermission::parse(&s).is_none(), "{s}");
        }
        assert!(
            SpacePermission::parse(&format!("space:com.example.x?skey={}", "x".repeat(513)))
                .is_none()
        );
    }

    #[test]
    fn accepts_rkey_shaped_skeys() {
        for skey in ["self", "3jui7kd54zh2y", "a.b-c_d~e:f", &"x".repeat(512)] {
            let s = p(&format!("space:com.example.x?skey={skey}"));
            assert_eq!(s.skey, Pattern::Is(skey.to_string()));
        }
        // `~` is percent-encoded on output, as the reference does.
        assert_eq!(
            p("space:com.example.x?skey=a~b").to_string(),
            "space:com.example.x?skey=a%7Eb"
        );
        assert_eq!(
            p("space:com.example.x?skey=a%7Eb").skey,
            Pattern::Is("a~b".into())
        );
    }

    fn any(rest: &str) -> SpacePermission {
        p(&format!("space:com.atmoboards.forum?authority=*{rest}"))
    }

    #[test]
    fn read_matching() {
        assert!(any("").matches(&T, &Operation::Read));
        assert!(!any("&action=create").matches(&T, &Operation::Read));
        assert!(any("&action=read").matches(&T, &Operation::ReadSelf));
        let rs = any("&action=read_self");
        assert!(rs.matches(&T, &Operation::ReadSelf));
        assert!(!rs.matches(&T, &Operation::Read));
        assert!(any("&action=read_self&collection=com.atmoboards.thread")
            .matches(&T, &Operation::ReadSelf));
    }

    #[test]
    fn write_matching() {
        let thread = Operation::Write(Action::Create, "com.atmoboards.thread");
        // No collection, no write targets.
        assert!(!any("").matches(&T, &thread));
        assert!(!any("&action=read").matches(&T, &thread));
        assert!(any("&collection=*")
            .matches(&T, &Operation::Write(Action::Update, "any.collection.name")));
        let one = any("&collection=com.atmoboards.thread&action=create");
        assert!(one.matches(&T, &thread));
        assert!(!one.matches(
            &T,
            &Operation::Write(Action::Create, "com.atmoboards.reply")
        ));
        assert!(!one.matches(
            &T,
            &Operation::Write(Action::Delete, "com.atmoboards.thread")
        ));
        // A read action is not a write.
        assert!(!any("&collection=*").matches(&T, &Operation::Write(Action::Read, "com.a.b")));
    }

    #[test]
    fn manage_matching() {
        let s = any("&action=read&manage=update");
        assert!(s.matches(&T, &Operation::Manage(ManageOp::Update)));
        assert!(!s.matches(&T, &Operation::Manage(ManageOp::Delete)));
        assert!(!any("&action=read").matches(&T, &Operation::Manage(ManageOp::Update)));
        assert!(!any("").matches(&T, &Operation::Manage(ManageOp::Update)));
    }

    #[test]
    fn target_matching() {
        let wild = p("space:*?authority=did:plc:abc");
        assert!(wild.matches(&T, &Operation::Read));
        assert!(wild.matches(
            &Target {
                space_type: "com.example.different",
                ..T
            },
            &Operation::Read
        ));
        let exact = p("space:com.atmoboards.forum?authority=did:plc:abc&skey=default");
        assert!(exact.matches(&T, &Operation::Read));
        assert!(!exact.matches(
            &Target {
                authority: "did:plc:other",
                ..T
            },
            &Operation::Read
        ));
        assert!(!exact.matches(&Target { skey: "other", ..T }, &Operation::Read));
    }

    #[test]
    fn self_authority() {
        let s = p("space:com.atmoboards.forum?action=read");
        assert!(
            !s.matches(&T, &Operation::Read),
            "unresolved self fails closed"
        );
        let r = s.with_resolved_authority("did:plc:abc");
        assert!(r.matches(&T, &Operation::Read));
        assert!(!r.matches(
            &Target {
                authority: "did:plc:other",
                ..T
            },
            &Operation::Read
        ));
        let concrete = p("space:com.atmoboards.forum?authority=did:plc:xyz");
        assert_eq!(concrete.with_resolved_authority("did:plc:abc"), concrete);
        assert_eq!(any("").with_resolved_authority("did:plc:abc"), any(""));
    }

    #[test]
    fn default_collections() {
        let s = any("");
        let e = s.with_default_collections(&["com.atmoboards.thread", "com.atmoboards.reply"]);
        assert_eq!(
            e.collection,
            Some(vec![
                Pattern::Is("com.atmoboards.reply".into()),
                Pattern::Is("com.atmoboards.thread".into())
            ])
        );
        assert!(e.matches(
            &T,
            &Operation::Write(Action::Create, "com.atmoboards.thread")
        ));
        let named = p("space:com.atmoboards.forum?collection=com.atmoboards.thread");
        assert_eq!(
            named.with_default_collections(&["com.atmoboards.reply"]),
            named
        );
        let star = p("space:com.atmoboards.forum?collection=*");
        assert_eq!(
            star.with_default_collections(&["com.atmoboards.thread"]),
            star
        );
        assert_eq!(s.with_default_collections(&[]), s);
    }

    #[test]
    fn needed_for_round_trips_without_widening() {
        assert_eq!(
            SpacePermission::needed_for(&T, &Operation::Read).to_string(),
            "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read"
        );
        assert_eq!(
            SpacePermission::needed_for(&T, &Operation::Write(Action::Create, "com.atmoboards.thread")).to_string(),
            "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&collection=com.atmoboards.thread&action=create"
        );
        assert_eq!(
            SpacePermission::needed_for(&T, &Operation::Manage(ManageOp::Update)).to_string(),
            "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read_self&manage=update"
        );
        let thread = Operation::Write(Action::Create, "com.atmoboards.thread");
        for op in [
            Operation::Read,
            Operation::ReadSelf,
            thread,
            Operation::Manage(ManageOp::Delete),
        ] {
            let again = p(&SpacePermission::needed_for(&T, &op).to_string());
            assert!(again.matches(&T, &op));
            if !matches!(op, Operation::Write(..)) {
                assert!(!again.matches(&T, &thread));
            }
        }
    }

    #[test]
    fn wildcard_warning_and_permission_sets() {
        assert!(p("space:*?authority=*").is_wildcard_authority_and_type());
        assert!(!any("").is_wildcard_authority_and_type());
        let s = permission_from_set_entry(
            "com.atmoboards.forum",
            Some("*"),
            None,
            &["com.atmoboards.thread", "com.atmoboards.reply"],
            &["read", "create"],
            &[],
        )
        .unwrap();
        assert_eq!(s.action, [Action::Read, Action::Create]);
        assert!(s.matches(
            &T,
            &Operation::Write(Action::Create, "com.atmoboards.reply")
        ));
        assert!(permission_from_set_entry("*", Some("*"), None, &[], &[], &[]).is_none());
    }
}
