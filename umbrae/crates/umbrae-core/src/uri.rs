//! Space addressing (spec: "Addressing", proposal 0016 as merged 2026-11-25).
//!
//! ```text
//! Space:  at:space/{spaceDid}/{spaceType}/{skey}
//! Record: at:space/{spaceDid}/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}
//! ```
//!
//! Every string form is produced and parsed here and nowhere else.
//!
//! Parsing is strict, as in the reference implementation:
//! - the prefix is exactly `at:space/`, lowercase;
//! - only the 3- and 6-segment forms;
//! - no query, no fragment, no trailing slash, no empty segment;
//! - the authority and the author are DIDs, never handles.
//!
//! The old `at://{spaceDid}/space/...` form is not a space URI any more
//! ("There is no `at://` form of a space URI"). [`SpaceRef::parse`] refuses
//! it with [`UriError::LegacyForm`]. Records written before the change can be
//! read with [`SpaceRef::parse_legacy`] / [`SpaceRecordUri::parse_legacy`]
//! and rewritten with [`upgrade_legacy`]. The leak guards
//! ([`is_space_uri`], [`contains_space_uri`]) still treat the old form as a
//! space URI, because it still names hidden data.

use std::fmt;

/// The fixed prefix of every space URI.
pub const SPACE_URI_PREFIX: &str = "at:space/";
const SCHEME_MARKER: &str = "at:space";
const LEGACY_PREFIX: &str = "at://";
const LEGACY_MARKER: &str = "space";

/// A reference to a space: `(authority, type, skey)`. Its string form is the
/// lexicon `space-ref` format.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpaceRef {
    authority: String,
    space_type: String,
    skey: String,
}

/// A record within a space.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpaceRecordUri {
    space: SpaceRef,
    author: String,
    collection: String,
    rkey: String,
}

/// Why a string isn't a valid space URI or component.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UriError {
    /// Doesn't start with `at:space/`.
    NotSpaceUri,
    /// The old `at://{did}/space/...` form, no longer valid. Read it with
    /// `parse_legacy` and rewrite it with [`upgrade_legacy`].
    LegacyForm,
    /// Wrong number of path segments, an empty segment, or a trailing slash.
    BadShape,
    /// A query or fragment is present.
    QueryOrFragment,
    InvalidAuthority,
    InvalidSpaceType,
    InvalidSkey,
    InvalidAuthor,
    InvalidCollection,
    InvalidRkey,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            UriError::NotSpaceUri => "not a space URI",
            UriError::LegacyForm => "old at:// space URI form; space URIs start at:space/",
            UriError::BadShape => "space URI does not match expected format",
            UriError::QueryOrFragment => "space URI may not have a query or fragment",
            UriError::InvalidAuthority => "space URI authority must be a DID",
            UriError::InvalidSpaceType => "space URI has invalid space type",
            UriError::InvalidSkey => "space URI has invalid space key",
            UriError::InvalidAuthor => "space URI author must be a DID",
            UriError::InvalidCollection => "space URI has invalid collection",
            UriError::InvalidRkey => "space URI has invalid record key",
        };
        f.write_str(s)
    }
}

impl std::error::Error for UriError {}

impl SpaceRef {
    /// Build from validated components.
    pub fn new(authority: &str, space_type: &str, skey: &str) -> Result<Self, UriError> {
        if !is_valid_did(authority) {
            return Err(UriError::InvalidAuthority);
        }
        if !is_valid_nsid(space_type) {
            return Err(UriError::InvalidSpaceType);
        }
        if !is_valid_record_key(skey) {
            return Err(UriError::InvalidSkey);
        }
        Ok(Self {
            authority: authority.to_owned(),
            space_type: space_type.to_owned(),
            skey: skey.to_owned(),
        })
    }

    /// Parse the three-part `at:space/` form only. A record URI is not a
    /// space ref.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        match parse_segments(input)? {
            Parsed::Space(s) => Ok(s),
            Parsed::Record(_) => Err(UriError::BadShape),
        }
    }

    /// Parse the old `at://{did}/space/{type}/{skey}` form only, for reading
    /// records written before the change.
    pub fn parse_legacy(input: &str) -> Result<Self, UriError> {
        match parse_legacy_segments(input)? {
            Parsed::Space(s) => Ok(s),
            Parsed::Record(_) => Err(UriError::BadShape),
        }
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn space_type(&self) -> &str {
        &self.space_type
    }

    pub fn skey(&self) -> &str {
        &self.skey
    }

    /// The URI of a record in this space.
    pub fn record(
        &self,
        author: &str,
        collection: &str,
        rkey: &str,
    ) -> Result<SpaceRecordUri, UriError> {
        SpaceRecordUri::new(self.clone(), author, collection, rkey)
    }
}

impl fmt::Display for SpaceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{SPACE_URI_PREFIX}{}/{}/{}",
            self.authority, self.space_type, self.skey
        )
    }
}

impl std::str::FromStr for SpaceRef {
    type Err = UriError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl SpaceRecordUri {
    /// Build from a space and validated record components.
    pub fn new(
        space: SpaceRef,
        author: &str,
        collection: &str,
        rkey: &str,
    ) -> Result<Self, UriError> {
        if !is_valid_did(author) {
            return Err(UriError::InvalidAuthor);
        }
        if !is_valid_nsid(collection) {
            return Err(UriError::InvalidCollection);
        }
        if !is_valid_record_key(rkey) {
            return Err(UriError::InvalidRkey);
        }
        Ok(Self {
            space,
            author: author.to_owned(),
            collection: collection.to_owned(),
            rkey: rkey.to_owned(),
        })
    }

    /// Parse the six-part `at:space/` record form only.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        match parse_segments(input)? {
            Parsed::Record(r) => Ok(r),
            Parsed::Space(_) => Err(UriError::BadShape),
        }
    }

    /// Parse the old `at://{did}/space/...` record form only, for reading
    /// records written before the change.
    pub fn parse_legacy(input: &str) -> Result<Self, UriError> {
        match parse_legacy_segments(input)? {
            Parsed::Record(r) => Ok(r),
            Parsed::Space(_) => Err(UriError::BadShape),
        }
    }

    pub fn space(&self) -> &SpaceRef {
        &self.space
    }

    pub fn author(&self) -> &str {
        &self.author
    }

    pub fn collection(&self) -> &str {
        &self.collection
    }

    pub fn rkey(&self) -> &str {
        &self.rkey
    }
}

impl fmt::Display for SpaceRecordUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.space, self.author, self.collection, self.rkey
        )
    }
}

impl std::str::FromStr for SpaceRecordUri {
    type Err = UriError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// The new form of an old-form space or space-record URI, or `None` if
/// `input` isn't a valid old-form one. A new-form URI isn't changed (`None`).
pub fn upgrade_legacy(input: &str) -> Option<String> {
    match parse_legacy_segments(input).ok()? {
        Parsed::Space(s) => Some(s.to_string()),
        Parsed::Record(r) => Some(r.to_string()),
    }
}

/// True if `input` is in the space-URI family: it starts with `at:space`
/// (any case), or it's the old `at://{authority}/space...` form. Says nothing
/// about validity. Errs towards yes, so a hidden reference is never taken
/// for a public one.
pub fn is_space_uri(input: &str) -> bool {
    let b = input.as_bytes();
    let new = b.len() >= SCHEME_MARKER.len()
        && b[..SCHEME_MARKER.len()].eq_ignore_ascii_case(SCHEME_MARKER.as_bytes())
        && marker_ends(&b[SCHEME_MARKER.len()..]);
    new || is_legacy_space_uri(input)
}

/// True if `input` has the old `at://{authority}/space` shape.
pub fn is_legacy_space_uri(input: &str) -> bool {
    let Some(rest) = input.strip_prefix(LEGACY_PREFIX) else {
        return false;
    };
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let path = &rest[slash + 1..];
    path == LEGACY_MARKER || path.starts_with("space/")
}

/// True if a space URI, in either form, appears anywhere in `text`: as the
/// whole string, or inside prose or another URL. Errs towards yes: anything
/// that could be a space URI, cut off by punctuation, a quote or whitespace,
/// counts.
pub fn contains_space_uri(text: &str) -> bool {
    // ASCII lowercasing keeps byte offsets.
    let lower = text.to_ascii_lowercase();
    let new = lower
        .match_indices(SCHEME_MARKER)
        .any(|(i, _)| marker_ends(&lower.as_bytes()[i + SCHEME_MARKER.len()..]));
    new || contains_legacy(text)
}

fn contains_legacy(text: &str) -> bool {
    text.match_indices(LEGACY_PREFIX).any(|(i, _)| {
        let rest = &text[i + LEGACY_PREFIX.len()..];
        let Some(slash) = rest.find('/') else {
            return false;
        };
        // The authority is one unbroken word; a later `/space` in the
        // prose isn't part of this URI.
        if rest[..slash].contains(char::is_whitespace) {
            return false;
        }
        let Some(after) = rest[slash + 1..].strip_prefix(LEGACY_MARKER) else {
            return false;
        };
        marker_ends(after.as_bytes())
    })
}

/// Whether the bytes after a `space` marker end it as a whole word, rather
/// than continuing it into a longer name such as `spaces.example.x` or
/// `space.example.x`.
fn marker_ends(after: &[u8]) -> bool {
    let nsid_char = |c: u8| c.is_ascii_alphanumeric() || c == b'-' || c == b'_';
    match after.first() {
        None => true,
        Some(&c) if nsid_char(c) => false,
        Some(b'.') => !after.get(1).is_some_and(|&c| nsid_char(c)),
        Some(_) => true,
    }
}

enum Parsed {
    Space(SpaceRef),
    Record(SpaceRecordUri),
}

fn check_chars(input: &str) -> Result<(), UriError> {
    if input.contains(['?', '#']) {
        return Err(UriError::QueryOrFragment);
    }
    if input
        .bytes()
        .any(|b| b.is_ascii_whitespace() || !b.is_ascii())
    {
        return Err(UriError::BadShape);
    }
    Ok(())
}

fn build(segs: &[&str]) -> Result<Parsed, UriError> {
    if segs.iter().any(|s| s.is_empty()) {
        return Err(UriError::BadShape);
    }
    match segs.len() {
        3 => Ok(Parsed::Space(SpaceRef::new(segs[0], segs[1], segs[2])?)),
        6 => {
            let space = SpaceRef::new(segs[0], segs[1], segs[2])?;
            Ok(Parsed::Record(SpaceRecordUri::new(
                space, segs[3], segs[4], segs[5],
            )?))
        }
        _ => Err(UriError::BadShape),
    }
}

fn parse_segments(input: &str) -> Result<Parsed, UriError> {
    let Some(rest) = input.strip_prefix(SPACE_URI_PREFIX) else {
        if is_legacy_space_uri(input) {
            return Err(UriError::LegacyForm);
        }
        return Err(UriError::NotSpaceUri);
    };
    check_chars(input)?;
    let segs: Vec<&str> = rest.split('/').collect();
    build(&segs)
}

fn parse_legacy_segments(input: &str) -> Result<Parsed, UriError> {
    if !is_legacy_space_uri(input) {
        return Err(UriError::NotSpaceUri);
    }
    check_chars(input)?;
    let segs: Vec<&str> = input[LEGACY_PREFIX.len()..].split('/').collect();
    // segs[1] is the `space` marker, checked by is_legacy_space_uri.
    let mut rest = vec![segs[0]];
    rest.extend_from_slice(&segs[2..]);
    build(&rest)
}

/// atproto DID syntax: `did:{method}:{id}`, at most 2048 characters.
pub fn is_valid_did(s: &str) -> bool {
    if s.len() > 2048 {
        return false;
    }
    let Some(rest) = s.strip_prefix("did:") else {
        return false;
    };
    let Some((method, id)) = rest.split_once(':') else {
        return false;
    };
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    if id.is_empty() {
        return false;
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'%' | b'-'))
    {
        return false;
    }
    !matches!(id.as_bytes().last(), Some(b':') | Some(b'%'))
}

/// atproto NSID syntax: a reversed domain authority plus a name segment.
pub fn is_valid_nsid(s: &str) -> bool {
    if s.len() > 317 || !s.is_ascii() {
        return false;
    }
    let segs: Vec<&str> = s.split('.').collect();
    if segs.len() < 3 {
        return false;
    }
    let (name, domain) = segs.split_last().expect("at least three segments");
    for (i, seg) in domain.iter().enumerate() {
        let b = seg.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return false;
        }
        if !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-') {
            return false;
        }
        if b[0] == b'-' || b[b.len() - 1] == b'-' {
            return false;
        }
        if i == 0 && b[0].is_ascii_digit() {
            return false;
        }
    }
    let n = name.as_bytes();
    !n.is_empty()
        && n.len() <= 63
        && n[0].is_ascii_alphabetic()
        && n.iter().all(|c| c.is_ascii_alphanumeric())
}

/// atproto record-key syntax, which space keys share: 1–512 characters of
/// `A-Za-z0-9 . - _ : ~`, and not `.` or `..`.
pub fn is_valid_record_key(s: &str) -> bool {
    if s.is_empty() || s.len() > 512 || s == "." || s == ".." {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'~'))
}

/// atproto TID syntax: 13 characters of sortable base32
/// (`234567abcdefghijklmnopqrstuvwxyz`), the first limited to `234567a-j`
/// so the top bit is zero.
pub fn is_valid_tid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 13
        && matches!(b[0], b'2'..=b'7' | b'a'..=b'j')
        && b.iter().all(|c| matches!(c, b'2'..=b'7' | b'a'..=b'z'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tid_syntax() {
        assert!(is_valid_tid("3mwcj3b6uak2f"));
        assert!(is_valid_tid("3kbcq3p7ad422"));
        assert!(is_valid_tid("2222222222222"));
        assert!(is_valid_tid("jzzzzzzzzzzzz"));
        assert!(!is_valid_tid("kzzzzzzzzzzzz"));
        assert!(!is_valid_tid("3mwcj3b6uak2"));
        assert!(!is_valid_tid("3mwcj3b6uak2ff"));
        assert!(!is_valid_tid("3MWCJ3B6UAK2F"));
        // 0 and 1 aren't in the alphabet. The reference tests use
        // `3kbcq3p7ad400` as a rev, which is not a valid TID.
        assert!(!is_valid_tid("3kbcq3p7ad400"));
        assert!(!is_valid_tid("3kbcq3p7ad411"));
    }

    const SPACE: &str = "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default";
    const RECORD: &str = "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default/did:plc:44ybard66vv44zksje25o7dz/app.bsky.feed.post/3jui7kd54zh2y";
    const OLD_SPACE: &str = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/space/app.bsky.group/default";
    const OLD_RECORD: &str = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/space/app.bsky.group/default/did:plc:44ybard66vv44zksje25o7dz/app.bsky.feed.post/3jui7kd54zh2y";

    #[test]
    fn parses_and_formats_space_ref() {
        let s = SpaceRef::parse(SPACE).unwrap();
        assert_eq!(s.authority(), "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
        assert_eq!(s.space_type(), "app.bsky.group");
        assert_eq!(s.skey(), "default");
        assert_eq!(s.to_string(), SPACE);
    }

    #[test]
    fn parses_and_formats_record() {
        let r = SpaceRecordUri::parse(RECORD).unwrap();
        assert_eq!(r.space().to_string(), SPACE);
        assert_eq!(r.author(), "did:plc:44ybard66vv44zksje25o7dz");
        assert_eq!(r.collection(), "app.bsky.feed.post");
        assert_eq!(r.rkey(), "3jui7kd54zh2y");
        assert_eq!(r.to_string(), RECORD);
    }

    #[test]
    fn space_ref_and_record_forms_are_distinct() {
        assert_eq!(SpaceRef::parse(RECORD), Err(UriError::BadShape));
        assert_eq!(
            SpaceRecordUri::parse(SPACE).unwrap_err(),
            UriError::BadShape
        );
    }

    #[test]
    fn old_form_is_refused_but_readable_on_request() {
        assert_eq!(SpaceRef::parse(OLD_SPACE), Err(UriError::LegacyForm));
        assert_eq!(
            SpaceRecordUri::parse(OLD_RECORD).unwrap_err(),
            UriError::LegacyForm
        );
        assert_eq!(
            SpaceRef::parse_legacy(OLD_SPACE).unwrap(),
            SpaceRef::parse(SPACE).unwrap()
        );
        assert_eq!(
            SpaceRecordUri::parse_legacy(OLD_RECORD).unwrap(),
            SpaceRecordUri::parse(RECORD).unwrap()
        );
        assert_eq!(SpaceRef::parse_legacy(SPACE), Err(UriError::NotSpaceUri));
        assert_eq!(upgrade_legacy(OLD_SPACE).as_deref(), Some(SPACE));
        assert_eq!(upgrade_legacy(OLD_RECORD).as_deref(), Some(RECORD));
        assert_eq!(upgrade_legacy(RECORD), None);
        assert_eq!(
            upgrade_legacy("at://did:plc:abc/app.bsky.feed.post/k"),
            None
        );
        assert_eq!(
            upgrade_legacy("at://alice.example.com/space/app.bsky.group/default"),
            None
        );
    }

    #[test]
    fn public_uris_are_not_space_uris() {
        let public = "at://did:plc:abc/app.bsky.feed.post/3jui7kd54zh2y";
        assert!(!is_space_uri(public));
        assert_eq!(SpaceRef::parse(public), Err(UriError::NotSpaceUri));
        assert!(is_space_uri(SPACE));
        assert!(is_space_uri(RECORD));
        assert!(is_space_uri("at:space"));
        assert!(is_space_uri("AT:Space/x"));
        assert!(!is_space_uri("at:spacecraft/x"));
        // The old form still counts, so it's never taken for public.
        assert!(is_space_uri(OLD_SPACE));
        assert!(is_space_uri("at://did:plc:abc/space"));
    }

    #[test]
    fn mixed_case_prefix_does_not_parse() {
        assert_eq!(
            SpaceRef::parse(&SPACE.replacen("at:space", "AT:space", 1)),
            Err(UriError::NotSpaceUri)
        );
    }

    #[test]
    fn space_uris_inside_text() {
        for text in [
            SPACE.to_owned(),
            RECORD.to_owned(),
            OLD_RECORD.to_owned(),
            format!("see {RECORD} for details"),
            format!("({RECORD})."),
            format!("https://app.example/view?uri={RECORD}"),
            "at:space".to_owned(),
            "at:space/".to_owned(),
            "at:space.".to_owned(),
            "AT:SPACE/did:plc:abc".to_owned(),
            "at://did:plc:abc/space".to_owned(),
            "at://did:plc:abc/space.".to_owned(),
            "at://did:plc:abc/space, then".to_owned(),
            format!("at://did:plc:abc/app.bsky.feed.post/3jui7kd54zh2y and {SPACE}"),
            format!("at://did:plc:abc/app.bsky.feed.post/3jui7kd54zh2y and {OLD_SPACE}"),
        ] {
            assert!(contains_space_uri(&text), "{text}");
        }
        for text in [
            "",
            "plain words about space",
            "at:spacecraft",
            "at:space.example.thing",
            "at://did:plc:abc/app.bsky.feed.post/3jui7kd54zh2y",
            "at://did:plc:abc/spaces.example.thing/3jui7kd54zh2y",
            "at://did:plc:abc/space.example.thing/3jui7kd54zh2y",
            "at://did:plc:abc",
            "at:/did:plc:abc/space/x",
            "at://did:plc:abc is me, see /space for more",
        ] {
            assert!(!contains_space_uri(text), "{text}");
        }
    }

    #[test]
    fn authority_and_author_must_be_dids() {
        assert_eq!(
            SpaceRef::parse("at:space/alice.example.com/app.bsky.group/default"),
            Err(UriError::InvalidAuthority)
        );
        let bad_author =
            "at:space/did:plc:abc/app.bsky.group/default/alice.example.com/app.bsky.feed.post/k";
        assert_eq!(
            SpaceRecordUri::parse(bad_author).unwrap_err(),
            UriError::InvalidAuthor
        );
    }

    #[test]
    fn rejects_bad_components() {
        assert_eq!(
            SpaceRef::parse("at:space/did:plc:abc/notansid/default"),
            Err(UriError::InvalidSpaceType)
        );
        assert_eq!(
            SpaceRef::parse("at:space/did:plc:abc/app.bsky.group/.."),
            Err(UriError::InvalidSkey)
        );
        let bad_coll = "at:space/did:plc:abc/app.bsky.group/default/did:plc:def/post/k";
        assert_eq!(
            SpaceRecordUri::parse(bad_coll).unwrap_err(),
            UriError::InvalidCollection
        );
        let bad_rkey =
            "at:space/did:plc:abc/app.bsky.group/default/did:plc:def/app.bsky.feed.post/a$b";
        assert_eq!(
            SpaceRecordUri::parse(bad_rkey).unwrap_err(),
            UriError::InvalidRkey
        );
    }

    #[test]
    fn strict_shape() {
        for bad in [
            "at:space/did:plc:abc/app.bsky.group/default/",
            "at:space/did:plc:abc/app.bsky.group",
            "at:space/did:plc:abc",
            "at:space/",
            "at:space/did:plc:abc/app.bsky.group//default",
            "at:space//did:plc:abc/app.bsky.group/default",
            "at:space/did:plc:abc/app.bsky.group/default/did:plc:def",
            "at:space/did:plc:abc/app.bsky.group/default/did:plc:def/app.bsky.feed.post",
            "at:space/did:plc:abc/app.bsky.group/default/did:plc:def/app.bsky.feed.post/k/x",
        ] {
            assert_eq!(SpaceRef::parse(bad), Err(UriError::BadShape), "{bad}");
        }
        assert_eq!(
            SpaceRef::parse("at:space/did:plc:abc/app.bsky.group/default?x=1"),
            Err(UriError::QueryOrFragment)
        );
        assert_eq!(
            SpaceRef::parse("at:space/did:plc:abc/app.bsky.group/default#/a"),
            Err(UriError::QueryOrFragment)
        );
        assert_eq!(
            SpaceRef::parse("at:space/did:plc:abc/app.bsky.group/def ault"),
            Err(UriError::BadShape)
        );
    }

    #[test]
    fn did_syntax() {
        assert!(is_valid_did("did:plc:ewvi7nxzyoun6zhxrhs64oiz"));
        assert!(is_valid_did("did:web:example.com"));
        assert!(is_valid_did("did:web:localhost%3A1234"));
        assert!(!is_valid_did("did:PLC:abc"));
        assert!(!is_valid_did("did:plc:"));
        assert!(!is_valid_did("did:plc:abc:"));
        assert!(!is_valid_did("did:plc:abc%"));
        assert!(!is_valid_did("dad:plc:abc"));
        assert!(!is_valid_did("did:plc"));
    }

    #[test]
    fn nsid_syntax() {
        assert!(is_valid_nsid("com.atproto.space.getRecord"));
        assert!(is_valid_nsid("tools.umbrae.post"));
        assert!(is_valid_nsid("com.example-1.foo"));
        assert!(!is_valid_nsid("com.example"));
        assert!(!is_valid_nsid("1com.example.foo"));
        assert!(!is_valid_nsid("com.-example.foo"));
        assert!(!is_valid_nsid("com.example.1foo"));
        assert!(!is_valid_nsid("com..foo"));
        assert!(!is_valid_nsid("com.example.foo-bar"));
    }

    #[test]
    fn record_key_syntax() {
        assert!(is_valid_record_key("self"));
        assert!(is_valid_record_key("3jui7kd54zh2y"));
        assert!(is_valid_record_key("a:b~c_d-e.f"));
        assert!(is_valid_record_key(&"a".repeat(512)));
        assert!(!is_valid_record_key(&"a".repeat(513)));
        assert!(!is_valid_record_key(""));
        assert!(!is_valid_record_key("."));
        assert!(!is_valid_record_key(".."));
        assert!(!is_valid_record_key("a/b"));
    }

    #[test]
    fn builders_validate() {
        assert_eq!(
            SpaceRef::new("did:plc:abc", "app.bsky.group", "").unwrap_err(),
            UriError::InvalidSkey
        );
        let s = SpaceRef::new("did:plc:abc", "app.bsky.group", "default").unwrap();
        let r = s.record("did:plc:def", "app.bsky.feed.post", "k").unwrap();
        assert_eq!(
            r.to_string(),
            "at:space/did:plc:abc/app.bsky.group/default/did:plc:def/app.bsky.feed.post/k"
        );
        assert_eq!(SpaceRecordUri::parse(&r.to_string()).unwrap(), r);
    }
}
