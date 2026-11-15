//! What the caller supplies: an HTTP transport and DID resolution.
//!
//! The crate never opens a connection or resolves a name itself, so the
//! caller's own client (address filtering, timeouts, size caps) handles
//! every byte that crosses the network.

use std::fmt;
use std::future::Future;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// One XRPC call. The caller sends `method` to [`Request::url`] with the
/// query pairs URL-encoded, the headers as given, and `body` as JSON.
///
/// The headers carry the space credential and a signature that can be
/// replayed until it expires, and a body can carry a delegation or a
/// registration token, so `Debug` shows header names only, and no body.
#[derive(Clone, PartialEq)]
pub struct Request {
    pub method: Method,
    /// The host's base URL, from the DID document (`#atproto_pds`).
    pub base: String,
    pub nsid: &'static str,
    pub query: Vec<(&'static str, String)>,
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<serde_json::Value>,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(k, _)| *k).collect();
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("nsid", &self.nsid)
            .field("headers", &names)
            .field("body", &self.body.is_some())
            .finish_non_exhaustive()
    }
}

impl Request {
    /// `{base}/xrpc/{nsid}`, without the query.
    pub fn url(&self) -> String {
        format!("{}/xrpc/{}", self.base.trim_end_matches('/'), self.nsid)
    }
}

/// The host's answer, whatever its status. `Debug` leaves out the body,
/// which can hold a credential or records.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Response {
    /// A header by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Why a request got no response. Carries no detail, so it can't carry
/// anything sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Unreachable,
    Timeout,
    TooLarge,
    Refused,
    Other,
}

/// Sends requests. Implement it with the application's guarded client.
pub trait Transport: Send + Sync {
    fn send(&self, req: Request) -> impl Future<Output = Result<Response, TransportError>> + Send;
}

/// What sync needs from an account's DID document. Keys are `did:key`s.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    /// The `#atproto_pds` service endpoint.
    pub pds: String,
    /// `#atproto`: verifies space credentials.
    pub signing_key: Option<String>,
    /// `#atproto_kem`: response MACs.
    pub kem_key: Option<String>,
    /// `#atproto_label`: label signatures, for labelers.
    pub label_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    Unreachable,
    Invalid,
}

/// Resolves DIDs. `refresh` asks for a fresh document, past any cache, and
/// is used once when a cached key fails to verify (it may have rotated):
/// the authority's `#atproto` key for a credential, or an account's
/// `#atproto_kem` key for a MAC.
pub trait Directory: Send + Sync {
    fn resolve(
        &self,
        did: &str,
        refresh: bool,
    ) -> impl Future<Output = Result<Identity, ResolveError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_no_credential_or_body() {
        let req = Request {
            method: Method::Post,
            base: "https://pds.example".into(),
            nsid: "com.atproto.space.authorizeSpaceSync",
            query: vec![],
            headers: vec![
                (
                    "Authorization",
                    "Atproto-Space-Credential secret-jwt".into(),
                ),
                ("Signature", "sig=:c2VjcmV0LXNpZw==:".into()),
            ],
            body: Some(serde_json::json!({ "delegationToken": "secret-delegation" })),
        };
        let res = Response {
            status: 200,
            headers: vec![],
            body: br#"{"credential":"secret-credential"}"#.to_vec(),
        };
        let shown = format!("{req:?} {res:?}");
        assert!(shown.contains("Authorization") && shown.contains("200"));
        for secret in [
            "secret-jwt",
            "c2VjcmV0LXNpZw",
            "secret-delegation",
            "115, 101",
        ] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
    }
}
