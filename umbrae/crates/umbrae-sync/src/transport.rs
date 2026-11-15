//! What the caller supplies: an HTTP transport and DID resolution.
//!
//! The crate never opens a connection or resolves a name itself, so the
//! caller's own client (address filtering, timeouts, size caps) handles
//! every byte that crosses the network.

use std::future::Future;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// One XRPC call. The caller sends `method` to [`Request::url`] with the
/// query pairs URL-encoded, the headers as given, and `body` as JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub method: Method,
    /// The host's base URL, from the DID document (`#atproto_pds`).
    pub base: String,
    pub nsid: &'static str,
    pub query: Vec<(&'static str, String)>,
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<serde_json::Value>,
}

impl Request {
    /// `{base}/xrpc/{nsid}`, without the query.
    pub fn url(&self) -> String {
        format!("{}/xrpc/{}", self.base.trim_end_matches('/'), self.nsid)
    }
}

/// The host's answer, whatever its status.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
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
/// is used once when a cached key fails to verify (it may have rotated).
pub trait Directory: Send + Sync {
    fn resolve(
        &self,
        did: &str,
        refresh: bool,
    ) -> impl Future<Output = Result<Identity, ResolveError>> + Send;
}
