//! Umbrae: hidden posts on atproto spaces.
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
//!
//! Record validation lives in `umbrae-lexicons`; protocol primitives in
//! `umbrae-core`.

pub mod access;
pub mod placement;
pub mod space;

pub use access::{Members, SpaceState, Tri, ViewContext};
pub use umbrae_lexicons::SPACE_TYPE;
