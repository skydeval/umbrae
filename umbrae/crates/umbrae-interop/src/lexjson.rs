//! Lexicon JSON ↔ DRISL, for the values XRPC returns as JSON: `{"$bytes":
//! base64}` is a byte string and `{"$link": cid}` a CID link.

use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use serde_json::Value;
use umbrae_core::cid::Cid;
use umbrae_core::commit::Commit;
use umbrae_core::drisl::Value as D;
use umbrae_core::uri::SpaceRef;

const B64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The bytes of a `{"$bytes": …}` value.
pub fn bytes(v: &Value) -> Option<Vec<u8>> {
    let o = v.as_object()?;
    if o.len() != 1 {
        return None;
    }
    B64.decode(o.get("$bytes")?.as_str()?).ok()
}

/// Convert a lexicon JSON value to DRISL.
pub fn to_drisl(v: &Value) -> Result<D, String> {
    Ok(match v {
        Value::Null => D::Null,
        Value::Bool(b) => D::Bool(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => D::Integer(i),
            None => D::Float(n.as_f64().ok_or("number out of range")?),
        },
        Value::String(s) => D::Text(s.clone()),
        Value::Array(a) => D::Array(a.iter().map(to_drisl).collect::<Result<_, _>>()?),
        Value::Object(o) => {
            if o.len() == 1 {
                if let Some(b) = bytes(v) {
                    return Ok(D::Bytes(b));
                }
                if let Some(link) = o.get("$link").and_then(Value::as_str) {
                    return Cid::parse(link).map(D::Link).map_err(|e| e.to_string());
                }
            }
            D::Map(
                o.iter()
                    .map(|(k, v)| Ok((k.clone(), to_drisl(v)?)))
                    .collect::<Result<_, String>>()?,
            )
        }
    })
}

/// Convert DRISL to lexicon JSON, the reverse of [`to_drisl`].
pub fn to_json(v: &D) -> Value {
    match v {
        D::Null => Value::Null,
        D::Bool(b) => Value::Bool(*b),
        D::Integer(i) => Value::from(*i),
        D::Float(f) => Value::from(*f),
        D::Bytes(b) => serde_json::json!({ "$bytes": B64.encode(b) }),
        D::Text(s) => Value::String(s.clone()),
        D::Array(a) => Value::Array(a.iter().map(to_json).collect()),
        D::Map(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), to_json(v))).collect()),
        D::Link(c) => serde_json::json!({ "$link": c.to_string() }),
    }
}

/// A `com.atproto.space.defs#commit` from its JSON form.
pub fn commit(v: &Value) -> Result<Commit, String> {
    let space = v["space"].as_str().ok_or("commit has no space")?;
    let data: [u8; 32] = bytes(&v["data"])
        .ok_or("commit data is not $bytes")?
        .try_into()
        .map_err(|_| "commit data is not 32 bytes")?;
    Commit::from_parts(
        v["ver"].as_i64().ok_or("commit has no ver")?,
        v["repo"].as_str().ok_or("commit has no repo")?,
        SpaceRef::parse(space).map_err(|e| e.to_string())?,
        v["rev"].as_str().ok_or("commit has no rev")?,
        data,
    )
    .map_err(|e| e.to_string())
}
