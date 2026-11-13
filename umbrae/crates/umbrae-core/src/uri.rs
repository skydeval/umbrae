//! Space addressing (spec: "Addressing").
//!
//! ```text
//! Space:  at://{spaceDid}/space/{spaceType}/{skey}
//! Record: at://{spaceDid}/space/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}
//! ```
//!
//! The URI syntax may still change before the spec settles (an `at:space/`
//! form is under discussion), so every string form is produced and parsed
//! here and nowhere else.
//!
//! Parsing is strict: no query, no fragment, no trailing slash. The
//! authority and the author must be DIDs, never handles.

use std::fmt;

const PREFIX: &str = "at://";
const MARKER: &str = "space";

/// A reference to a space: `(authority, type, skey)`.
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
pub enum UriError {
    /// Doesn't start with `at://` followed by an authority and the `space` marker.
    NotSpaceUri,
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

    /// Parse the three-part form only. A record URI is not a space ref.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        match parse_segments(input)? {
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
            "{PREFIX}{}/{MARKER}/{}/{}",
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

    /// Parse the six-part record form only.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        match parse_segments(input)? {
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

/// True if `input` is in the space-URI family (has the `space` marker as
/// its first path segment). Says nothing about validity.
pub fn is_space_uri(input: &str) -> bool {
    let Some(rest) = input.strip_prefix(PREFIX) else {
        return false;
    };
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let path = &rest[slash + 1..];
    path == MARKER || path.starts_with("space/")
}

enum Parsed {
    Space(SpaceRef),
    Record(SpaceRecordUri),
}

fn parse_segments(input: &str) -> Result<Parsed, UriError> {
    if !is_space_uri(input) {
        return Err(UriError::NotSpaceUri);
    }
    if input.contains(['?', '#']) {
        return Err(UriError::QueryOrFragment);
    }
    if input
        .bytes()
        .any(|b| b.is_ascii_whitespace() || !b.is_ascii())
    {
        return Err(UriError::BadShape);
    }
    let rest = &input[PREFIX.len()..];
    let segs: Vec<&str> = rest.split('/').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return Err(UriError::BadShape);
    }
    // segs[1] is the marker, checked by is_space_uri.
    match segs.len() {
        4 => Ok(Parsed::Space(SpaceRef::new(segs[0], segs[2], segs[3])?)),
        7 => {
            let space = SpaceRef::new(segs[0], segs[2], segs[3])?;
            Ok(Parsed::Record(SpaceRecordUri::new(
                space, segs[4], segs[5], segs[6],
            )?))
        }
        _ => Err(UriError::BadShape),
    }
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

    const SPACE: &str = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/space/app.bsky.group/default";
    const RECORD: &str = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/space/app.bsky.group/default/did:plc:44ybard66vv44zksje25o7dz/app.bsky.feed.post/3jui7kd54zh2y";

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
    fn public_uris_are_not_space_uris() {
        let public = "at://did:plc:abc/app.bsky.feed.post/3jui7kd54zh2y";
        assert!(!is_space_uri(public));
        assert_eq!(SpaceRef::parse(public), Err(UriError::NotSpaceUri));
        assert!(is_space_uri(SPACE));
        assert!(is_space_uri("at://did:plc:abc/space"));
    }

    #[test]
    fn authority_and_author_must_be_dids() {
        assert_eq!(
            SpaceRef::parse("at://alice.example.com/space/app.bsky.group/default"),
            Err(UriError::InvalidAuthority)
        );
        let bad_author =
            "at://did:plc:abc/space/app.bsky.group/default/alice.example.com/app.bsky.feed.post/k";
        assert_eq!(
            SpaceRecordUri::parse(bad_author).unwrap_err(),
            UriError::InvalidAuthor
        );
    }

    #[test]
    fn rejects_bad_components() {
        assert_eq!(
            SpaceRef::parse("at://did:plc:abc/space/notansid/default"),
            Err(UriError::InvalidSpaceType)
        );
        assert_eq!(
            SpaceRef::parse("at://did:plc:abc/space/app.bsky.group/.."),
            Err(UriError::InvalidSkey)
        );
        let bad_coll = "at://did:plc:abc/space/app.bsky.group/default/did:plc:def/post/k";
        assert_eq!(
            SpaceRecordUri::parse(bad_coll).unwrap_err(),
            UriError::InvalidCollection
        );
        let bad_rkey =
            "at://did:plc:abc/space/app.bsky.group/default/did:plc:def/app.bsky.feed.post/a$b";
        assert_eq!(
            SpaceRecordUri::parse(bad_rkey).unwrap_err(),
            UriError::InvalidRkey
        );
    }

    #[test]
    fn strict_shape() {
        for bad in [
            "at://did:plc:abc/space/app.bsky.group/default/",
            "at://did:plc:abc/space/app.bsky.group",
            "at://did:plc:abc/space/app.bsky.group//default",
            "at://did:plc:abc/space/app.bsky.group/default/did:plc:def",
        ] {
            assert_eq!(SpaceRef::parse(bad), Err(UriError::BadShape), "{bad}");
        }
        assert_eq!(
            SpaceRef::parse("at://did:plc:abc/space/app.bsky.group/default?x=1"),
            Err(UriError::QueryOrFragment)
        );
        assert_eq!(
            SpaceRef::parse("at://did:plc:abc/space/app.bsky.group/default#/a"),
            Err(UriError::QueryOrFragment)
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
            "at://did:plc:abc/space/app.bsky.group/default/did:plc:def/app.bsky.feed.post/k"
        );
        assert_eq!(SpaceRecordUri::parse(&r.to_string()).unwrap(), r);
    }
}
