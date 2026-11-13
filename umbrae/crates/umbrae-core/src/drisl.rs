//! DRISL, the deterministic CBOR profile used for records and archive
//! metadata (<https://dasl.ing/drisl.html>).
//!
//! The rules enforced here, on both encode and decode:
//! - definite lengths only; integers and lengths in their shortest form;
//! - integers in the `i64` range (the atproto data model's range);
//! - floats only as 64-bit, never NaN, infinite or negative zero;
//! - map keys are text, unique, and sorted by encoded bytes (shorter keys
//!   first, then bytewise), as in CBOR/c;
//! - the only tag is 42, holding a DASL CID behind a leading `0x00`;
//! - the only simple values are `false`, `true` and `null`;
//! - text is valid UTF-8, and nothing trails the top-level value.
//!
//! A decoder that accepted a second encoding of the same value would give
//! that value a second CID, so decoding is strict: whatever decodes,
//! re-encodes to the same bytes.

use crate::cid::{Cid, CidError};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

/// Maximum nesting of arrays and maps a decoder accepts.
pub const MAX_DEPTH: usize = 128;

/// The largest record a repo accepts, as encoded bytes.
pub const MAX_RECORD_SIZE: usize = 1024 * 1024;

const TAG_CID: u64 = 42;

/// A DRISL value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Encoded in DRISL key order whatever the map's own order.
    Map(BTreeMap<String, Value>),
    Link(Cid),
}

/// Why a value can't be encoded, or bytes aren't canonical DRISL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrislError {
    /// Input ended mid-value.
    Truncated,
    /// Bytes follow the top-level value.
    TrailingBytes,
    /// An integer or length not in its shortest form.
    NonCanonicalLength,
    /// Indefinite-length item or break code.
    Indefinite,
    /// Reserved additional-information value (28–30).
    Reserved,
    /// Integer outside the `i64` range.
    IntegerRange,
    /// Float not 64-bit, or NaN, infinite or negative zero.
    Float,
    /// Simple value other than `false`, `true`, `null`.
    SimpleValue,
    /// Tag other than 42.
    Tag(u64),
    /// Tag 42 content not a byte string with a `0x00` prefix.
    LinkEncoding,
    /// Tag 42 content not a DASL CID.
    Cid(CidError),
    /// Map key not text.
    MapKeyType,
    /// Map keys duplicated or out of order.
    MapKeyOrder,
    /// Text not valid UTF-8.
    Utf8,
    /// Nesting deeper than [`MAX_DEPTH`].
    Depth,
    /// Encoded value larger than allowed.
    TooLarge,
    /// A record that isn't a map.
    NotAMap,
}

impl fmt::Display for DrislError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DrislError::Truncated => f.write_str("DRISL input is truncated"),
            DrislError::TrailingBytes => f.write_str("bytes follow the DRISL value"),
            DrislError::NonCanonicalLength => {
                f.write_str("DRISL integer or length is not in shortest form")
            }
            DrislError::Indefinite => f.write_str("DRISL does not allow indefinite lengths"),
            DrislError::Reserved => f.write_str("reserved CBOR additional information"),
            DrislError::IntegerRange => f.write_str("integer outside the 64-bit signed range"),
            DrislError::Float => {
                f.write_str("floats must be finite, non-negative-zero 64-bit values")
            }
            DrislError::SimpleValue => f.write_str("only false, true and null are allowed"),
            DrislError::Tag(t) => write!(f, "CBOR tag {t} is not allowed"),
            DrislError::LinkEncoding => {
                f.write_str("tag 42 must hold a byte string with a 0x00 prefix")
            }
            DrislError::Cid(e) => write!(f, "tag 42: {e}"),
            DrislError::MapKeyType => f.write_str("map keys must be text"),
            DrislError::MapKeyOrder => f.write_str("map keys are duplicated or out of order"),
            DrislError::Utf8 => f.write_str("text is not valid UTF-8"),
            DrislError::Depth => f.write_str("DRISL value nested too deeply"),
            DrislError::TooLarge => f.write_str("DRISL value is too large"),
            DrislError::NotAMap => f.write_str("a record must be a map"),
        }
    }
}

impl std::error::Error for DrislError {}

/// DRISL key order: shorter first, then bytewise. Equal to comparing the
/// keys' encoded bytes, since the length is in the header.
pub fn key_order(a: &str, b: &str) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

impl Value {
    /// Shorthand for a map from `(key, value)` pairs.
    pub fn map<K: Into<String>>(entries: impl IntoIterator<Item = (K, Value)>) -> Value {
        Value::Map(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

/// Encode a value. Fails only on a float DRISL forbids.
pub fn encode(value: &Value) -> Result<Vec<u8>, DrislError> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn float_allowed(f: f64) -> bool {
    f.is_finite() && !(f == 0.0 && f.is_sign_negative())
}

fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), DrislError> {
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Integer(i) if *i >= 0 => write_head(out, 0, *i as u64),
        // -1 - n for n >= 0, i.e. the bitwise complement.
        Value::Integer(i) => write_head(out, 1, !(*i) as u64),
        Value::Float(f) => {
            if !float_allowed(*f) {
                return Err(DrislError::Float);
            }
            out.push(0xfb);
            out.extend_from_slice(&f.to_be_bytes());
        }
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out)?;
            }
        }
        Value::Map(map) => {
            write_head(out, 5, map.len() as u64);
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| key_order(a.0, b.0));
            for (k, v) in entries {
                write_head(out, 3, k.len() as u64);
                out.extend_from_slice(k.as_bytes());
                encode_into(v, out)?;
            }
        }
        Value::Link(cid) => {
            write_head(out, 6, TAG_CID);
            let bytes = cid.to_bytes();
            write_head(out, 2, bytes.len() as u64 + 1);
            out.push(0x00);
            out.extend_from_slice(&bytes);
        }
    }
    Ok(())
}

/// Decode one canonical DRISL value occupying all of `bytes`.
pub fn decode(bytes: &[u8]) -> Result<Value, DrislError> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    let v = d.value(0)?;
    if d.pos != bytes.len() {
        return Err(DrislError::TrailingBytes);
    }
    Ok(v)
}

/// Check that `bytes` is a canonical DRISL record (a map, at most
/// [`MAX_RECORD_SIZE`]) and return its CID.
pub fn record_cid(bytes: &[u8]) -> Result<Cid, DrislError> {
    if bytes.len() > MAX_RECORD_SIZE {
        return Err(DrislError::TooLarge);
    }
    match decode(bytes)? {
        Value::Map(_) => Ok(Cid::for_drisl(bytes)),
        _ => Err(DrislError::NotAMap),
    }
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], DrislError> {
        let end = self.pos.checked_add(n).ok_or(DrislError::Truncated)?;
        if end > self.buf.len() {
            return Err(DrislError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Read a head: (major type, argument). Rejects non-shortest forms,
    /// indefinite lengths and reserved values. Major type 7 is returned
    /// with its raw additional information as the argument.
    fn head(&mut self) -> Result<(u8, u64), DrislError> {
        let ib = self.take(1)?[0];
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major == 7 {
            return Ok((7, u64::from(ai)));
        }
        let n = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let n = u64::from(self.take(1)?[0]);
                if n < 24 {
                    return Err(DrislError::NonCanonicalLength);
                }
                n
            }
            25 => {
                let b = self.take(2)?;
                let n = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if n <= 0xff {
                    return Err(DrislError::NonCanonicalLength);
                }
                n
            }
            26 => {
                let b = self.take(4)?;
                let n = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if n <= 0xffff {
                    return Err(DrislError::NonCanonicalLength);
                }
                n
            }
            27 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                let n = u64::from_be_bytes(a);
                if n <= 0xffff_ffff {
                    return Err(DrislError::NonCanonicalLength);
                }
                n
            }
            31 => return Err(DrislError::Indefinite),
            _ => return Err(DrislError::Reserved),
        };
        Ok((major, n))
    }

    /// A length that must fit in what's left of the input (each element
    /// takes at least one byte), so a hostile length can't force a huge
    /// allocation.
    fn length(&self, n: u64) -> Result<usize, DrislError> {
        let n = usize::try_from(n).map_err(|_| DrislError::Truncated)?;
        if n > self.remaining() {
            return Err(DrislError::Truncated);
        }
        Ok(n)
    }

    fn text(&mut self, n: u64) -> Result<String, DrislError> {
        let len = self.length(n)?;
        let b = self.take(len)?;
        String::from_utf8(b.to_vec()).map_err(|_| DrislError::Utf8)
    }

    fn value(&mut self, depth: usize) -> Result<Value, DrislError> {
        let (major, n) = self.head()?;
        match major {
            0 => i64::try_from(n)
                .map(Value::Integer)
                .map_err(|_| DrislError::IntegerRange),
            1 => {
                // -1 - n must be >= i64::MIN, i.e. n <= i64::MAX.
                let n = i64::try_from(n).map_err(|_| DrislError::IntegerRange)?;
                Ok(Value::Integer(-1 - n))
            }
            2 => {
                let len = self.length(n)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => Ok(Value::Text(self.text(n)?)),
            4 => {
                if depth >= MAX_DEPTH {
                    return Err(DrislError::Depth);
                }
                let len = self.length(n)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                if depth >= MAX_DEPTH {
                    return Err(DrislError::Depth);
                }
                let len = self.length(n)?;
                let mut map = BTreeMap::new();
                let mut prev: Option<String> = None;
                for _ in 0..len {
                    let (kmajor, kn) = self.head()?;
                    if kmajor != 3 {
                        return Err(DrislError::MapKeyType);
                    }
                    let key = self.text(kn)?;
                    if let Some(p) = &prev {
                        if key_order(p, &key) != Ordering::Less {
                            return Err(DrislError::MapKeyOrder);
                        }
                    }
                    let v = self.value(depth + 1)?;
                    map.insert(key.clone(), v);
                    prev = Some(key);
                }
                Ok(Value::Map(map))
            }
            6 => {
                if n != TAG_CID {
                    return Err(DrislError::Tag(n));
                }
                let (bmajor, bn) = self.head()?;
                if bmajor != 2 {
                    return Err(DrislError::LinkEncoding);
                }
                let len = self.length(bn)?;
                let b = self.take(len)?;
                match b.split_first() {
                    Some((&0x00, cid)) => Cid::from_bytes(cid)
                        .map(Value::Link)
                        .map_err(DrislError::Cid),
                    _ => Err(DrislError::LinkEncoding),
                }
            }
            7 => match n {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                27 => {
                    let b = self.take(8)?;
                    let mut a = [0u8; 8];
                    a.copy_from_slice(b);
                    let f = f64::from_be_bytes(a);
                    if !float_allowed(f) {
                        return Err(DrislError::Float);
                    }
                    Ok(Value::Float(f))
                }
                25 | 26 => Err(DrislError::Float),
                31 => Err(DrislError::Indefinite),
                _ => Err(DrislError::SimpleValue),
            },
            _ => unreachable!("major type is three bits"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(v: Value) -> Vec<u8> {
        let bytes = encode(&v).unwrap();
        assert_eq!(decode(&bytes).unwrap(), v, "round trip of {bytes:02x?}");
        bytes
    }

    #[test]
    fn reference_record_cid() {
        // The reference implementation's CID for `{ text: 'hello' }`.
        let bytes = rt(Value::map([("text", Value::Text("hello".into()))]));
        assert_eq!(bytes, b"\xa1\x64text\x65hello");
        assert_eq!(
            record_cid(&bytes).unwrap().to_string(),
            "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"
        );
        let world = encode(&Value::map([("text", Value::Text("world".into()))])).unwrap();
        assert_eq!(
            record_cid(&world).unwrap().to_string(),
            "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a"
        );
    }

    #[test]
    fn integers_shortest_form() {
        assert_eq!(rt(Value::Integer(0)), [0x00]);
        assert_eq!(rt(Value::Integer(23)), [0x17]);
        assert_eq!(rt(Value::Integer(24)), [0x18, 24]);
        assert_eq!(rt(Value::Integer(256)), [0x19, 1, 0]);
        assert_eq!(rt(Value::Integer(65536)), [0x1a, 0, 1, 0, 0]);
        assert_eq!(rt(Value::Integer(1 << 32)), [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(rt(Value::Integer(-1)), [0x20]);
        assert_eq!(rt(Value::Integer(-25)), [0x38, 24]);
        rt(Value::Integer(i64::MAX));
        rt(Value::Integer(i64::MIN));
        for bad in [
            &[0x18, 23][..],
            &[0x19, 0, 0xff],
            &[0x1a, 0, 0, 0xff, 0xff],
            &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            &[0x38, 0],
        ] {
            assert_eq!(
                decode(bad),
                Err(DrislError::NonCanonicalLength),
                "{bad:02x?}"
            );
        }
        // u64 beyond i64::MAX, and below i64::MIN.
        assert_eq!(
            decode(&[0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            Err(DrislError::IntegerRange)
        );
        assert_eq!(
            decode(&[0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            Err(DrislError::IntegerRange)
        );
    }

    #[test]
    fn map_key_order() {
        let v = Value::map([
            ("bb", Value::Integer(1)),
            ("a", Value::Integer(2)),
            ("aa", Value::Integer(3)),
            ("b", Value::Integer(4)),
        ]);
        let bytes = rt(v);
        // a, b, aa, bb
        assert_eq!(
            bytes,
            [0xa4, 0x61, b'a', 2, 0x61, b'b', 4, 0x62, b'a', b'a', 3, 0x62, b'b', b'b', 1]
        );
        // Out of order, and duplicated.
        assert_eq!(
            decode(&[0xa2, 0x62, b'a', b'a', 1, 0x61, b'b', 2]),
            Err(DrislError::MapKeyOrder)
        );
        assert_eq!(
            decode(&[0xa2, 0x61, b'a', 1, 0x61, b'a', 2]),
            Err(DrislError::MapKeyOrder)
        );
        // Non-text key.
        assert_eq!(decode(&[0xa1, 0x01, 0x02]), Err(DrislError::MapKeyType));
    }

    #[test]
    fn floats() {
        assert_eq!(rt(Value::Float(1.5)), [0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]);
        for f in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.0] {
            assert_eq!(encode(&Value::Float(f)), Err(DrislError::Float));
            let mut b = vec![0xfb];
            b.extend_from_slice(&f.to_be_bytes());
            assert_eq!(decode(&b), Err(DrislError::Float));
        }
        // Half and single precision.
        assert_eq!(decode(&[0xf9, 0x3e, 0x00]), Err(DrislError::Float));
        assert_eq!(decode(&[0xfa, 0x3f, 0xc0, 0, 0]), Err(DrislError::Float));
    }

    #[test]
    fn simple_values_and_tags() {
        assert_eq!(rt(Value::Null), [0xf6]);
        assert_eq!(rt(Value::Bool(true)), [0xf5]);
        assert_eq!(rt(Value::Bool(false)), [0xf4]);
        assert_eq!(decode(&[0xf7]), Err(DrislError::SimpleValue)); // undefined
        assert_eq!(decode(&[0xf8, 0x20]), Err(DrislError::SimpleValue));
        assert_eq!(decode(&[0xc1, 0x00]), Err(DrislError::Tag(1)));
        assert_eq!(decode(&[0xdc]), Err(DrislError::Reserved));
    }

    #[test]
    fn links() {
        let cid = Cid::for_raw(b"x");
        let bytes = rt(Value::Link(cid));
        assert_eq!(&bytes[..4], &[0xd8, 42, 0x58, 37]);
        assert_eq!(bytes[4], 0x00);
        // Missing the 0x00 prefix.
        let mut no_prefix = vec![0xd8, 42, 0x58, 36];
        no_prefix.extend_from_slice(&cid.to_bytes());
        assert_eq!(decode(&no_prefix), Err(DrislError::LinkEncoding));
        // Tag 42 around text.
        assert_eq!(decode(&[0xd8, 42, 0x60]), Err(DrislError::LinkEncoding));
        // A non-DASL CID inside.
        let mut bad = bytes.clone();
        bad[6] = 0x70;
        assert!(matches!(decode(&bad), Err(DrislError::Cid(_))));
    }

    #[test]
    fn rejects_indefinite_truncated_trailing() {
        assert_eq!(decode(&[0x9f, 0xff]), Err(DrislError::Indefinite));
        assert_eq!(decode(&[0x5f]), Err(DrislError::Indefinite));
        assert_eq!(decode(&[0xff]), Err(DrislError::Indefinite));
        assert_eq!(decode(&[0x62, b'a']), Err(DrislError::Truncated));
        assert_eq!(decode(&[]), Err(DrislError::Truncated));
        assert_eq!(decode(&[0x00, 0x00]), Err(DrislError::TrailingBytes));
        // A huge declared length doesn't allocate.
        assert_eq!(
            decode(&[0x9b, 0, 0, 0, 1, 0, 0, 0, 0]),
            Err(DrislError::Truncated)
        );
    }

    #[test]
    fn rejects_bad_utf8() {
        assert_eq!(decode(&[0x62, 0xc3, 0x28]), Err(DrislError::Utf8));
    }

    #[test]
    fn depth_limit() {
        let mut ok = vec![0x81; MAX_DEPTH];
        ok.push(0x00);
        assert!(decode(&ok).is_ok());
        let mut deep = vec![0x81; MAX_DEPTH + 1];
        deep.push(0x00);
        assert_eq!(decode(&deep), Err(DrislError::Depth));
    }

    #[test]
    fn record_cid_requires_a_map_within_size() {
        assert_eq!(record_cid(&[0x01]), Err(DrislError::NotAMap));
        let big = Value::map([("b", Value::Bytes(vec![0; MAX_RECORD_SIZE]))]);
        assert_eq!(
            record_cid(&encode(&big).unwrap()),
            Err(DrislError::TooLarge)
        );
    }

    #[test]
    fn nested_round_trip() {
        rt(Value::map([
            ("$type", Value::Text("app.example.post".into())),
            (
                "tags",
                Value::Array(vec![Value::Text("a".into()), Value::Null]),
            ),
            ("data", Value::Bytes(vec![1, 2, 3])),
            ("n", Value::Integer(-1000)),
            ("ref", Value::Link(Cid::for_drisl(b"\xa0"))),
            (
                "inner",
                Value::map([("z", Value::Bool(true)), ("y", Value::Float(0.25))]),
            ),
        ]));
    }
}
