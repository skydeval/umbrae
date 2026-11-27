//! Sync for apps that read atproto spaces: credentials, the writer set,
//! repos, op logs and notifications, checked end to end with `umbrae-core`
//! and, for Umbrae spaces, `umbrae-lexicons`.
//!
//! No I/O of its own: the caller supplies a [`Transport`] (its own HTTP
//! client, with its own address filtering, timeouts and size limits) and a
//! [`Directory`] (DID resolution). Nothing here logs, and errors carry no
//! record content, URIs, DIDs or tokens.
//!
//! The usual loop for one space:
//! 1. [`authorize`] with a reader's delegation (plus a client attestation
//!    when the space limits apps, and a [`Notify`] registration).
//! 2. [`sync_space`] from a [`SpaceCursor`] (empty the first time), with a
//!    lookup of the CIDs held for each record. It returns what changed per
//!    repo and the new cursor; persist the cursor with the records.
//! 3. On a notification ([`notify::parse_notification`], token checked with
//!    [`notify::token_matches`]), sync again. Renew the credential before
//!    [`Credential::expires_at`] with a fresh delegation.
//! 4. At least once a day, drop every repo's cursor before syncing, so each
//!    repo is fetched whole; on an `#identity` event that moves an account,
//!    call [`host_changed`], and on a `SpaceNotFound` after it,
//!    [`missing_space`]. A [`RepoChange::TakenDown`] keeps only what the
//!    host still lists.
//!
//! Who may see what is the `umbrae` crate's job, from the records synced
//! here.

mod credential;
mod error;
pub mod json;
pub mod notify;
mod sync;
mod transport;
mod validate;

pub use credential::{authorize, Authorize, Credential, Notify};
pub use error::{SyncError, XrpcName};
pub use sync::{
    fetch_ops, fetch_repo, host_changed, list_records, list_writers, missing_space, sync_space,
    MissingSpace, Op, RepoChange, RepoCursor, SpaceCursor, SyncedRecord, Writer, Writers,
    MISSING_AFTER_MOVE,
};
pub use transport::{
    Directory, Identity, Method, Request, ResolveError, Response, Transport, TransportError,
};
pub use validate::{check, Checked};
