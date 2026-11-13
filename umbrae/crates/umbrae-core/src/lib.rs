//! Protocol primitives for atproto spaces.
//!
//! Pure code: no I/O, no storage, no HTTP server. Hosts (a PDS acting as
//! repo host and space host) and applications (syncers, managing apps) build
//! on these pieces.
//!
//! Tracks the atproto spaces proposal (0016) as of the 2026-11-12 release.
//! The proposal is still an alpha; anything that may still move, such as
//! the URI syntax, is kept inside a single module.

pub mod cid;
pub mod commit;
pub mod drisl;
pub mod lthash;
pub mod uri;

pub use cid::{Cid, CidError, Codec};
pub use commit::{Commit, CommitError, OpError, RepoOp, COMMIT_HEADER, COMMIT_VERSION};
pub use drisl::{DrislError, Value};
pub use lthash::LtHash;
pub use uri::{SpaceRecordUri, SpaceRef, UriError};
