//! A minimal in-memory PLC directory, so the harness never touches the
//! public one. It accepts whatever operation the PDS posts (no signature or
//! chain checks: this is a fixture, not a directory) and serves DID
//! documents built from the latest operation.

use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};

/// The latest operation per DID.
#[derive(Clone, Default)]
pub struct Directory {
    ops: Arc<Mutex<HashMap<String, Value>>>,
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The DID document for an operation, as a PLC directory renders it.
pub fn did_document(did: &str, op: &Value) -> Value {
    let empty = Map::new();
    let methods = op
        .get("verificationMethods")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let services = op
        .get("services")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": op.get("alsoKnownAs").cloned().unwrap_or(json!([])),
        "verificationMethod": methods.iter().map(|(id, key)| json!({
            "id": format!("{did}#{id}"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": key.as_str().unwrap_or("").trim_start_matches("did:key:"),
        })).collect::<Vec<_>>(),
        "service": services.iter().map(|(id, s)| json!({
            "id": format!("#{id}"),
            "type": s.get("type").cloned().unwrap_or(Value::Null),
            "serviceEndpoint": s.get("endpoint").cloned().unwrap_or(Value::Null),
        })).collect::<Vec<_>>(),
    })
}

impl Directory {
    /// The latest operation for a DID.
    pub fn op(&self, did: &str) -> Option<Value> {
        self.ops.lock().unwrap().get(did).cloned()
    }

    /// A `did:key` from the DID's `verificationMethods`.
    pub fn key(&self, did: &str, id: &str) -> Option<String> {
        self.op(did)?
            .get("verificationMethods")?
            .get(id)?
            .as_str()
            .map(str::to_owned)
    }

    /// Serve until the process exits.
    pub fn serve(&self, bind: &str) {
        let server = Server::http(bind).unwrap_or_else(|e| panic!("bind {bind}: {e}"));
        let ops = self.ops.clone();
        std::thread::spawn(move || {
            for mut req in server.incoming_requests() {
                let path = percent_decode(req.url().trim_start_matches('/'));
                let json_header =
                    Header::from_bytes(&b"content-type"[..], &b"application/json"[..]).unwrap();
                let (status, body) = match (req.method(), path.as_str()) {
                    (_, "_health") => (200, json!({"version": "mock"})),
                    (Method::Post, did) if did.starts_with("did:plc:") => {
                        let mut s = String::new();
                        let _ = req.as_reader().read_to_string(&mut s);
                        match serde_json::from_str::<Value>(&s) {
                            Ok(op) => {
                                ops.lock().unwrap().insert(did.to_owned(), op);
                                (200, json!({}))
                            }
                            Err(_) => (400, json!({"message": "bad op"})),
                        }
                    }
                    (Method::Get, p) => {
                        let (did, suffix) = match p.split_once('/') {
                            Some((d, s)) => (d, s),
                            None => (p, ""),
                        };
                        let op = ops.lock().unwrap().get(did).cloned();
                        match (op, suffix) {
                            (None, _) => (404, json!({"message": "DID not registered"})),
                            (Some(op), "") => (200, did_document(did, &op)),
                            (Some(op), "data") => (
                                200,
                                json!({
                                    "did": did,
                                    "verificationMethods": op.get("verificationMethods"),
                                    "rotationKeys": op.get("rotationKeys"),
                                    "alsoKnownAs": op.get("alsoKnownAs"),
                                    "services": op.get("services"),
                                }),
                            ),
                            (Some(op), "log/last") => (200, op),
                            (Some(op), "log") => (200, json!([op])),
                            (Some(op), "log/audit") => (
                                200,
                                json!([{ "did": did, "operation": op, "cid": "", "nullified": false, "createdAt": "2026-01-01T00:00:00.000Z" }]),
                            ),
                            _ => (404, json!({"message": "not found"})),
                        }
                    }
                    _ => (404, json!({"message": "not found"})),
                };
                let _ = req.respond(
                    Response::from_string(body.to_string())
                        .with_status_code(status)
                        .with_header(json_header),
                );
            }
        });
    }
}
