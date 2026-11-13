//! STAR archives (<https://dasl.ing/star.html>).
//!
//! ```text
//! [ magic | len | meta ] [ 1 | len | key | len | val ] ... [ 0 ]
//! ```
//!
//! The magic is `2A 6C 01 00`. Each `len` is an unsigned varint in its
//! shortest form, at most 9 bytes. The metadata is a canonical DRISL map
//! with a text `$type`, naming the profile. Pairs are ordered but not
//! sorted, and may repeat; profiles add their own rules. Nothing may follow
//! the end byte, and any error is fatal for the whole archive.
//!
//! The decoder does no I/O: callers push bytes as they arrive and pull
//! events out, so it serves blocking and async readers alike. Lengths are
//! checked against the limits before a frame is buffered, so an oversized
//! frame is rejected from its length alone.

use crate::drisl::{self, DrislError, Value};
use std::collections::BTreeMap;
use std::fmt;

/// The four magic bytes: `*l`, version 1, NUL.
pub const MAGIC: [u8; 4] = [0x2a, 0x6c, 0x01, 0x00];
const CONTROL_PAIR: u8 = 0x01;
const CONTROL_END: u8 = 0x00;
const MAX_VARINT_BYTES: usize = 9;

/// Per-frame length caps. STAR has none of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StarLimits {
    pub meta: u64,
    pub key: u64,
    pub value: u64,
}

impl StarLimits {
    /// No limits beyond what fits in memory.
    pub const UNLIMITED: StarLimits = StarLimits {
        meta: u64::MAX,
        key: u64::MAX,
        value: u64::MAX,
    };

    /// The spaces profiles' archive limits: 64 KiB metadata, 4 KiB keys,
    /// 1 MiB values.
    pub const SPACES: StarLimits = StarLimits {
        meta: 64 * 1024,
        key: 4 * 1024,
        value: 1024 * 1024,
    };
}

/// Which frame a length belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    Meta,
    Key,
    Value,
}

/// Why bytes aren't a valid STAR archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StarError {
    Magic,
    /// The input ended before the archive did.
    Truncated,
    /// A varint with a trailing zero byte.
    NonCanonicalVarint,
    /// A varint longer than 9 bytes.
    VarintTooLong,
    /// A frame longer than its limit.
    TooLong {
        frame: Frame,
        length: u64,
        limit: u64,
    },
    /// A control byte other than `0x00` or `0x01`.
    Control(u8),
    /// Bytes after the end byte.
    TrailingBytes,
    /// The metadata isn't canonical DRISL.
    Meta(DrislError),
    /// The metadata isn't a map with a text `$type`.
    MetaShape,
}

impl fmt::Display for StarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StarError::Magic => f.write_str("invalid STAR magic bytes"),
            StarError::Truncated => f.write_str("unexpected end of STAR archive"),
            StarError::NonCanonicalVarint => f.write_str("non-canonical varint"),
            StarError::VarintTooLong => f.write_str("varint too long"),
            StarError::TooLong {
                frame,
                length,
                limit,
            } => write!(f, "{frame:?} length {length} exceeds limit of {limit}"),
            StarError::Control(b) => write!(f, "invalid control byte: {b}"),
            StarError::TrailingBytes => f.write_str("unexpected bytes after end of archive"),
            StarError::Meta(e) => write!(f, "invalid metadata: {e}"),
            StarError::MetaShape => f.write_str("metadata must be a map with a text $type"),
        }
    }
}

impl std::error::Error for StarError {}

/// What the decoder found next.
#[derive(Debug, Clone, PartialEq)]
pub enum StarEvent {
    /// The metadata, always first. Its `$type` is a text value.
    Meta(BTreeMap<String, Value>),
    Pair {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    /// The end byte, with nothing after it so far.
    End,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Magic,
    MetaLen,
    Meta(usize),
    Control,
    KeyLen,
    Key(usize),
    ValueLen,
    Value(usize),
    Done,
    Failed,
}

/// An incremental STAR decoder.
#[derive(Debug)]
pub struct StarDecoder {
    limits: StarLimits,
    buf: Vec<u8>,
    pos: usize,
    state: State,
    eof: bool,
    key: Vec<u8>,
    error: Option<StarError>,
}

impl StarDecoder {
    pub fn new(limits: StarLimits) -> Self {
        Self {
            limits,
            buf: Vec::new(),
            pos: 0,
            state: State::Magic,
            eof: false,
            key: Vec::new(),
            error: None,
        }
    }

    /// Add input. Bytes after the end byte are an error.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), StarError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if bytes.is_empty() {
            return Ok(());
        }
        if matches!(self.state, State::Done) {
            return Err(self.fail(StarError::TrailingBytes));
        }
        if self.pos > 0 && self.pos >= self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Mark the end of input. Afterwards, an unfinished archive is an error
    /// rather than a request for more bytes.
    pub fn finish(&mut self) {
        self.eof = true;
    }

    /// The next event, or `None` if more input is needed (or the archive
    /// has ended and its `End` was already returned).
    pub fn next_event(&mut self) -> Result<Option<StarEvent>, StarError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        match self.step() {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) if self.eof && !matches!(self.state, State::Done) => {
                Err(self.fail(StarError::Truncated))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(self.fail(e)),
        }
    }

    fn fail(&mut self, e: StarError) -> StarError {
        self.state = State::Failed;
        self.error = Some(e.clone());
        e
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.available().len() < n {
            return None;
        }
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(out)
    }

    /// Read a varint and check it against `limit`. `None` means more input.
    fn length(&mut self, frame: Frame, limit: u64) -> Result<Option<usize>, StarError> {
        let avail = self.available();
        let mut value: u64 = 0;
        for i in 0..MAX_VARINT_BYTES {
            let Some(&byte) = avail.get(i) else {
                return Ok(None);
            };
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte < 0x80 {
                if byte == 0 && i > 0 {
                    return Err(StarError::NonCanonicalVarint);
                }
                self.pos += i + 1;
                if value > limit {
                    return Err(StarError::TooLong {
                        frame,
                        length: value,
                        limit,
                    });
                }
                // On a 32-bit target a length past usize can't be buffered.
                return usize::try_from(value)
                    .map(Some)
                    .map_err(|_| StarError::TooLong {
                        frame,
                        length: value,
                        limit: usize::MAX as u64,
                    });
            }
        }
        Err(StarError::VarintTooLong)
    }

    fn step(&mut self) -> Result<Option<StarEvent>, StarError> {
        loop {
            match self.state {
                State::Magic => {
                    let avail = self.available();
                    let n = avail.len().min(MAGIC.len());
                    if avail[..n] != MAGIC[..n] {
                        return Err(StarError::Magic);
                    }
                    if n < MAGIC.len() {
                        return Ok(None);
                    }
                    self.pos += MAGIC.len();
                    self.state = State::MetaLen;
                }
                State::MetaLen => match self.length(Frame::Meta, self.limits.meta)? {
                    Some(n) => self.state = State::Meta(n),
                    None => return Ok(None),
                },
                State::Meta(n) => {
                    let Some(bytes) = self.take(n) else {
                        return Ok(None);
                    };
                    self.state = State::Control;
                    return parse_meta(&bytes).map(|m| Some(StarEvent::Meta(m)));
                }
                State::Control => {
                    let Some(&c) = self.available().first() else {
                        return Ok(None);
                    };
                    self.pos += 1;
                    match c {
                        CONTROL_PAIR => self.state = State::KeyLen,
                        CONTROL_END => {
                            self.state = State::Done;
                            if !self.available().is_empty() {
                                return Err(StarError::TrailingBytes);
                            }
                            return Ok(Some(StarEvent::End));
                        }
                        other => return Err(StarError::Control(other)),
                    }
                }
                State::KeyLen => match self.length(Frame::Key, self.limits.key)? {
                    Some(n) => self.state = State::Key(n),
                    None => return Ok(None),
                },
                State::Key(n) => {
                    let Some(bytes) = self.take(n) else {
                        return Ok(None);
                    };
                    self.key = bytes;
                    self.state = State::ValueLen;
                }
                State::ValueLen => match self.length(Frame::Value, self.limits.value)? {
                    Some(n) => self.state = State::Value(n),
                    None => return Ok(None),
                },
                State::Value(n) => {
                    let Some(value) = self.take(n) else {
                        return Ok(None);
                    };
                    self.state = State::Control;
                    let key = std::mem::take(&mut self.key);
                    return Ok(Some(StarEvent::Pair { key, value }));
                }
                State::Done | State::Failed => return Ok(None),
            }
        }
    }
}

fn parse_meta(bytes: &[u8]) -> Result<BTreeMap<String, Value>, StarError> {
    // The DRISL decoder is strict, so a decoded map is already canonical.
    let value = drisl::decode(bytes).map_err(StarError::Meta)?;
    match value {
        Value::Map(m) if matches!(m.get("$type"), Some(Value::Text(_))) => Ok(m),
        _ => Err(StarError::MetaShape),
    }
}

/// A whole archive in memory: its metadata and pairs, in order.
pub type StarContents = (BTreeMap<String, Value>, Vec<(Vec<u8>, Vec<u8>)>);

/// Decode a complete archive held in memory.
pub fn read_star(bytes: &[u8], limits: StarLimits) -> Result<StarContents, StarError> {
    let mut d = StarDecoder::new(limits);
    d.push(bytes)?;
    d.finish();
    let mut meta = None;
    let mut pairs = Vec::new();
    while let Some(ev) = d.next_event()? {
        match ev {
            StarEvent::Meta(m) => meta = Some(m),
            StarEvent::Pair { key, value } => pairs.push((key, value)),
            StarEvent::End => break,
        }
    }
    Ok((meta.expect("metadata precedes the end"), pairs))
}

fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// The magic and metadata frame. The metadata must be a map with a text
/// `$type`.
pub fn encode_header(meta: &BTreeMap<String, Value>) -> Result<Vec<u8>, StarError> {
    if !matches!(meta.get("$type"), Some(Value::Text(_))) {
        return Err(StarError::MetaShape);
    }
    let body = drisl::encode(&Value::Map(meta.clone())).map_err(StarError::Meta)?;
    let mut out = MAGIC.to_vec();
    write_varint(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    Ok(out)
}

/// One pair frame, control byte included.
pub fn encode_pair(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + value.len() + 7);
    out.push(CONTROL_PAIR);
    write_varint(&mut out, key.len() as u64);
    out.extend_from_slice(key);
    write_varint(&mut out, value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// The end byte.
pub const END: [u8; 1] = [CONTROL_END];

/// Encode a complete archive.
pub fn write_star<'a>(
    meta: &BTreeMap<String, Value>,
    pairs: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Vec<u8>, StarError> {
    let mut out = encode_header(meta)?;
    for (k, v) in pairs {
        out.extend_from_slice(&encode_pair(k, v));
    }
    out.extend_from_slice(&END);
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Decode feeding one byte at a time, to exercise frames that span
    /// pushes.
    fn read_bytewise(bytes: &[u8]) -> Result<StarContents, StarError> {
        let mut d = StarDecoder::new(StarLimits::UNLIMITED);
        let mut meta = None;
        let mut pairs = Vec::new();
        let mut ended = false;
        let mut drain = |d: &mut StarDecoder| -> Result<(), StarError> {
            while let Some(ev) = d.next_event()? {
                match ev {
                    StarEvent::Meta(m) => meta = Some(m),
                    StarEvent::Pair { key, value } => pairs.push((key, value)),
                    StarEvent::End => ended = true,
                }
            }
            Ok(())
        };
        for b in bytes {
            d.push(std::slice::from_ref(b))?;
            drain(&mut d)?;
        }
        d.finish();
        drain(&mut d)?;
        assert!(ended);
        Ok((meta.unwrap(), pairs))
    }

    // A minimal JSON reader for the fixture files: objects, arrays,
    // strings (with \" \\ \uXXXX escapes) and non-negative integers.
    #[derive(Debug, Clone, PartialEq)]
    enum Json {
        Obj(Vec<(String, Json)>),
        Arr(Vec<Json>),
        Str(String),
        Num(i64),
    }

    impl Json {
        fn get(&self, k: &str) -> &Json {
            match self {
                Json::Obj(m) => &m.iter().find(|(key, _)| key == k).unwrap().1,
                _ => panic!("not an object"),
            }
        }
        fn str(&self) -> &str {
            match self {
                Json::Str(s) => s,
                _ => panic!("not a string"),
            }
        }
        fn arr(&self) -> &[Json] {
            match self {
                Json::Arr(a) => a,
                _ => panic!("not an array"),
            }
        }
        fn to_drisl(&self) -> Value {
            match self {
                Json::Obj(m) => Value::map(m.iter().map(|(k, v)| (k.clone(), v.to_drisl()))),
                Json::Arr(a) => Value::Array(a.iter().map(Json::to_drisl).collect()),
                Json::Str(s) => Value::Text(s.clone()),
                Json::Num(n) => Value::Integer(*n),
            }
        }
    }

    fn parse_json(s: &str) -> Json {
        fn ws(b: &[char], i: &mut usize) {
            while b[*i].is_whitespace() {
                *i += 1;
            }
        }
        fn val(b: &[char], i: &mut usize) -> Json {
            ws(b, i);
            match b[*i] {
                '{' => {
                    *i += 1;
                    let mut m = Vec::new();
                    loop {
                        ws(b, i);
                        if b[*i] == '}' {
                            *i += 1;
                            return Json::Obj(m);
                        }
                        let Json::Str(k) = val(b, i) else { panic!() };
                        ws(b, i);
                        assert_eq!(b[*i], ':');
                        *i += 1;
                        m.push((k, val(b, i)));
                        ws(b, i);
                        if b[*i] == ',' {
                            *i += 1;
                        }
                    }
                }
                '[' => {
                    *i += 1;
                    let mut a = Vec::new();
                    loop {
                        ws(b, i);
                        if b[*i] == ']' {
                            *i += 1;
                            return Json::Arr(a);
                        }
                        a.push(val(b, i));
                        ws(b, i);
                        if b[*i] == ',' {
                            *i += 1;
                        }
                    }
                }
                '"' => {
                    *i += 1;
                    let mut s = String::new();
                    while b[*i] != '"' {
                        if b[*i] == '\\' {
                            *i += 1;
                            match b[*i] {
                                'u' => {
                                    let hex: String = b[*i + 1..*i + 5].iter().collect();
                                    let c = u32::from_str_radix(&hex, 16).unwrap();
                                    s.push(char::from_u32(c).unwrap());
                                    *i += 4;
                                }
                                c => s.push(c),
                            }
                        } else {
                            s.push(b[*i]);
                        }
                        *i += 1;
                    }
                    *i += 1;
                    Json::Str(s)
                }
                _ => {
                    let start = *i;
                    while b[*i].is_ascii_digit() {
                        *i += 1;
                    }
                    let n: String = b[start..*i].iter().collect();
                    Json::Num(n.parse().unwrap())
                }
            }
        }
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        val(&chars, &mut i)
    }

    const VALID: &str = include_str!("../tests/fixtures/star/valid-star-fixtures.json");
    const INVALID: &str = include_str!("../tests/fixtures/star/invalid-star-fixtures.json");

    #[test]
    fn valid_fixtures_read_and_write() {
        let fixtures = parse_json(VALID);
        assert!(fixtures.arr().len() >= 18);
        for f in fixtures.arr() {
            let comment = f.get("comment").str();
            let star = from_hex(f.get("star_hex").str());
            let decoded = f.get("decoded");
            let Value::Map(meta) = decoded.get("meta").to_drisl() else {
                panic!()
            };
            let pairs: Vec<(Vec<u8>, Vec<u8>)> = decoded
                .get("pairs")
                .arr()
                .iter()
                .map(|p| {
                    (
                        from_hex(p.get("key_hex").str()),
                        from_hex(p.get("value_hex").str()),
                    )
                })
                .collect();
            let whole = read_star(&star, StarLimits::UNLIMITED)
                .unwrap_or_else(|e| panic!("{comment}: {e}"));
            assert_eq!(whole, (meta.clone(), pairs.clone()), "{comment}");
            let bytewise = read_bytewise(&star).unwrap_or_else(|e| panic!("{comment}: {e}"));
            assert_eq!(bytewise, (meta.clone(), pairs.clone()), "{comment}");
            let written = write_star(
                &meta,
                pairs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
            )
            .unwrap();
            assert_eq!(written, star, "{comment}: writes the same bytes");
        }
    }

    #[test]
    fn invalid_fixtures_are_rejected() {
        let fixtures = parse_json(INVALID);
        assert!(fixtures.arr().len() >= 37);
        for f in fixtures.arr() {
            let comment = f.get("comment").str();
            let star = from_hex(f.get("star_hex").str());
            assert!(
                read_star(&star, StarLimits::UNLIMITED).is_err(),
                "{comment}: accepted whole"
            );
            assert!(
                read_bytewise(&star).is_err(),
                "{comment}: accepted bytewise"
            );
        }
    }

    #[test]
    fn limits_reject_from_the_length_alone() {
        let meta = BTreeMap::from([("$type".to_owned(), Value::Text("t".into()))]);
        let mut star = encode_header(&meta).unwrap();
        star.push(CONTROL_PAIR);
        star.push(1);
        star.push(b'k');
        // A 2 MiB value length, with no value bytes following.
        write_varint(&mut star, 2 * 1024 * 1024);
        let mut d = StarDecoder::new(StarLimits::SPACES);
        d.push(&star).unwrap();
        assert!(matches!(d.next_event(), Ok(Some(StarEvent::Meta(_)))));
        assert_eq!(
            d.next_event(),
            Err(StarError::TooLong {
                frame: Frame::Value,
                length: 2 * 1024 * 1024,
                limit: 1024 * 1024
            })
        );
        // The error sticks.
        assert!(d.next_event().is_err());
        assert!(d.push(b"x").is_err());
    }

    #[test]
    fn pushing_after_the_end_is_an_error() {
        let meta = BTreeMap::from([("$type".to_owned(), Value::Text("t".into()))]);
        let star = write_star(&meta, []).unwrap();
        let mut d = StarDecoder::new(StarLimits::UNLIMITED);
        d.push(&star).unwrap();
        assert!(matches!(d.next_event(), Ok(Some(StarEvent::Meta(_)))));
        assert_eq!(d.next_event(), Ok(Some(StarEvent::End)));
        assert_eq!(d.next_event(), Ok(None));
        assert_eq!(d.push(&[0]), Err(StarError::TrailingBytes));
    }

    #[test]
    fn needs_more_input_until_finished() {
        let mut d = StarDecoder::new(StarLimits::UNLIMITED);
        d.push(&MAGIC[..2]).unwrap();
        assert_eq!(d.next_event(), Ok(None));
        d.finish();
        assert_eq!(d.next_event(), Err(StarError::Truncated));
    }

    #[test]
    fn header_requires_text_type() {
        let meta = BTreeMap::from([("$type".to_owned(), Value::Integer(1))]);
        assert_eq!(encode_header(&meta), Err(StarError::MetaShape));
        assert_eq!(encode_header(&BTreeMap::new()), Err(StarError::MetaShape));
    }

    #[test]
    fn varints() {
        for (n, enc) in [
            (0u64, &[0x00][..]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
        ] {
            let mut out = Vec::new();
            write_varint(&mut out, n);
            assert_eq!(out, enc);
        }
        let mut max = Vec::new();
        write_varint(&mut max, (1 << 63) - 1);
        assert_eq!(max.len(), 9);
    }
}
