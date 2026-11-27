//! Umbrae: hidden posts and private labelers on atproto spaces.
//!
//! A hidden post is a `tools.umbrae.post` record in a space whose authority
//! is the author. A group is a memberspace with its member list published to
//! members only; only-me is a personalspace. The author's PDS (any host
//! that speaks spaces) stores the spaces, holds the member list and mints credentials.
//! Nothing here is a service: these are the rules every consumer applies.
//!
//! - [`space`]: the space and policy to create, and the check that a space
//!   is configured as Umbrae expects.
//! - [`placement`]: which space a reply or like goes into, and the check that
//!   a public record never points at a hidden one.
//! - [`access`]: who may see a space, its member list and its records.
//! - [`community`]: communities, feeds, placeholders, legacy profile copies
//!   and list subscriptions.
//! - [`profile`]: the one hidden profile and the audiences it lists.
//! - [`labeler`]: private labelers: the space, its policy and readers,
//!   label signatures, and which labels are in effect, in the labeler
//!   space or in the subject's own space; and `!takedown`.
//! - [`private`]: private accounts: who passes the owner's rules, which
//!   interactions count, and what stays inside when going public.
//!
//! Record validation lives in `umbrae-lexicons`; protocol primitives in
//! `umbrae-core`.

pub mod access;
pub mod community;
pub mod labeler;
pub mod placement;
pub mod private;
pub mod profile;
pub mod space;

pub use access::{Members, SpaceState, Tri, ViewContext};
pub use umbrae_lexicons::{LABELER_SPACE_TYPE, PRIVATE_SPACE_TYPE, SPACE_TYPE};
