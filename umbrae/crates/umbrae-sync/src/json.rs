//! Lexicon JSON to DRISL, for the values XRPC returns as JSON: `{"$bytes":
//! base64}` is a byte string and `{"$link": cid}` a CID link.

use crate::error::SyncError;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use serde_json::Value;
use std::collections::BTreeMap;
use umbrae_core::cid::Cid;
use umbrae_core::commit::Commit;
use umbrae_core::drisl::Value as D;
use umbrae_core::uri::SpaceRef;

const B64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Nesting deeper than this is refused, as DRISL refuses it.
const MAX_DEPTH: usize = 64;

/// The bytes of a `{"$bytes": …}` value.
pub fn bytes(v: &Value) -> Option<Vec<u8>> {
    let o = v.as_object()?;
    if o.len() != 1 {
        return None;
    }
    B64.decode(o.get("$bytes")?.as_str()?).ok()
}

/// A lexicon JSON value as DRISL.
pub fn to_drisl(v: &Value) -> Result<D, SyncError> {
    convert(v, 0)
}

/// A lexicon JSON object as a DRISL map.
pub fn to_map(v: &Value) -> Result<BTreeMap<String, D>, SyncError> {
    match to_drisl(v)? {
        D::Map(m) => Ok(m),
        _ => Err(SyncError::Malformed("expected an object")),
    }
}

fn convert(v: &Value, depth: usize) -> Result<D, SyncError> {
    if depth > MAX_DEPTH {
        return Err(SyncError::Malformed("value nested too deeply"));
    }
    Ok(match v {
        Value::Null => D::Null,
        Value::Bool(b) => D::Bool(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => D::Integer(i),
            None => D::Float(
                n.as_f64()
                    .ok_or(SyncError::Malformed("number out of range"))?,
            ),
        },
        Value::String(s) => D::Text(s.clone()),
        Value::Array(a) => D::Array(
            a.iter()
                .map(|x| convert(x, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(o) => {
            if o.len() == 1 {
                if let Some(b) = bytes(v) {
                    return Ok(D::Bytes(b));
                }
                if let Some(link) = o.get("$link").and_then(Value::as_str) {
                    return Cid::parse(link)
                        .map(D::Link)
                        .map_err(|_| SyncError::Malformed("bad $link"));
                }
            }
            D::Map(
                o.iter()
                    .map(|(k, x)| Ok((k.clone(), convert(x, depth + 1)?)))
                    .collect::<Result<_, SyncError>>()?,
            )
        }
    })
}

/// A `com.atproto.space.defs#commit` from its JSON form.
pub fn commit(v: &Value) -> Result<Commit, SyncError> {
    let bad = SyncError::Malformed("commit");
    let space =
        SpaceRef::parse(v["space"].as_str().ok_or(bad.clone())?).map_err(|_| bad.clone())?;
    let data: [u8; 32] = bytes(&v["data"])
        .ok_or(bad.clone())?
        .try_into()
        .map_err(|_| bad.clone())?;
    Commit::from_parts(
        v["ver"].as_i64().ok_or(bad.clone())?,
        v["repo"].as_str().ok_or(bad.clone())?,
        space,
        v["rev"].as_str().ok_or(bad)?,
        data,
    )
    .map_err(SyncError::Commit)
}

/// A 32-byte `$bytes` digest.
pub fn digest(v: &Value) -> Option<[u8; 32]> {
    bytes(v)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bytes_links_and_maps() {
        let cid = Cid::for_drisl(b"x");
        let v = json!({ "a": { "$bytes": "AAEC" }, "b": { "$link": cid.to_string() }, "c": [1, 2.5, null] });
        let m = to_map(&v).unwrap();
        assert_eq!(m["a"], D::Bytes(vec![0, 1, 2]));
        assert_eq!(m["b"], D::Link(cid));
        assert_eq!(
            m["c"],
            D::Array(vec![D::Integer(1), D::Float(2.5), D::Null])
        );
        // A `$bytes` beside other keys is just a map.
        assert!(matches!(
            to_drisl(&json!({ "$bytes": "AA", "x": 1 })).unwrap(),
            D::Map(_)
        ));
        assert!(to_map(&json!([1])).is_err());
    }

    #[test]
    fn deep_nesting_is_refused() {
        let mut v = json!(1);
        for _ in 0..100 {
            v = json!([v]);
        }
        assert_eq!(
            to_drisl(&v),
            Err(SyncError::Malformed("value nested too deeply"))
        );
    }
}
