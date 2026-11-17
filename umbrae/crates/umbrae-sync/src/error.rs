//! Errors. None carries record content, URIs, DIDs or tokens, so they're
//! safe to count and to log at any level.

use crate::transport::{ResolveError, TransportError};
use std::fmt;
use umbrae_core::commit::{CommitError, OpError};
use umbrae_core::httpsig::SignatureError;
use umbrae_core::repo_archive::RepoArchiveError;
use umbrae_core::tokens::TokenError;

/// An XRPC error name from the host, kept only if it looks like one
/// (ASCII letters and digits, at most 64), so a hostile host can't put
/// arbitrary text into our errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrpcName(String);

impl XrpcName {
    pub fn new(name: &str) -> Self {
        if !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric()) {
            Self(name.to_owned())
        } else {
            Self(String::new())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SyncError {
    Transport(TransportError),
    Resolve(ResolveError),
    /// The host refused, with its HTTP status and XRPC error name.
    Xrpc {
        status: u16,
        error: XrpcName,
    },
    /// A response or notification didn't have the expected shape.
    Malformed(&'static str),
    /// A DID document lacks a key sync needs.
    MissingKey(&'static str),
    Token(TokenError),
    /// The credential the host returned isn't bound to our key or space.
    CredentialMismatch,
    /// The credential has expired; authorize again.
    CredentialExpired,
    Mac(SignatureError),
    Commit(CommitError),
    Archive(RepoArchiveError),
    Op(OpError),
    /// The op log doesn't reproduce the host's commit: fetch the whole repo.
    DigestMismatch,
    /// The op log can't be applied to the cursor (out of order, or an op's
    /// `prev` isn't what we hold), or the repo is older than the cursor.
    Gap(&'static str),
    /// A record value doesn't hash to its CID.
    RecordMismatch,
}

impl SyncError {
    /// Whether the host said the space doesn't exist (or, equivalently, that
    /// we may not see it).
    pub fn is_space_not_found(&self) -> bool {
        self.is_xrpc("SpaceNotFound")
    }

    /// Whether the host has no repo for the account in this space (never
    /// written, cleared, or the account is gone).
    pub fn is_repo_not_found(&self) -> bool {
        self.is_xrpc("RepoNotFound")
    }

    fn is_xrpc(&self, name: &str) -> bool {
        matches!(self, SyncError::Xrpc { error, .. } if error.as_str() == name)
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::Transport(e) => write!(f, "transport: {e:?}"),
            SyncError::Resolve(e) => write!(f, "resolve: {e:?}"),
            SyncError::Xrpc { status, error } => {
                write!(f, "host: HTTP {status} {}", error.as_str())
            }
            SyncError::Malformed(what) => write!(f, "malformed: {what}"),
            SyncError::MissingKey(which) => write!(f, "DID document has no {which}"),
            SyncError::Token(e) => write!(f, "credential: {e}"),
            SyncError::CredentialMismatch => {
                f.write_str("credential not bound to our key or space")
            }
            SyncError::CredentialExpired => f.write_str("credential expired"),
            SyncError::Mac(e) => write!(f, "MAC: {e}"),
            SyncError::Commit(e) => write!(f, "commit: {e}"),
            SyncError::Archive(e) => write!(f, "archive: {e}"),
            SyncError::Op(e) => write!(f, "op log: {e}"),
            SyncError::DigestMismatch => f.write_str("op log doesn't reproduce the commit"),
            SyncError::Gap(why) => write!(f, "op log gap: {why}"),
            SyncError::RecordMismatch => f.write_str("record doesn't match its CID"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<TransportError> for SyncError {
    fn from(e: TransportError) -> Self {
        SyncError::Transport(e)
    }
}

impl From<ResolveError> for SyncError {
    fn from(e: ResolveError) -> Self {
        SyncError::Resolve(e)
    }
}
