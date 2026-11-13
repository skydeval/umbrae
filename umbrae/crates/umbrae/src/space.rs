//! The spaces Umbrae creates.
//!
//! | Audience | skey | Policy |
//! |---|---|---|
//! | a group | a TID | memberspace, not public, policy and members published |
//! | only me | `self` | personalspace |
//!
//! Publishing the member list puts it in the authority's repo inside the
//! space, so only people who can read the space see it. That is also how an
//! app serving the posts learns who may see them.

use umbrae_core::policy::{MemberPolicy, Policy};
use umbrae_core::uri::{is_valid_tid, SpaceRef, UriError};
use umbrae_lexicons::SPACE_TYPE;

/// The only-me space's key.
pub const ONLY_ME_SKEY: &str = "self";

/// A group's space. The key must be a TID.
pub fn group_space(author: &str, skey: &str) -> Result<SpaceRef, UriError> {
    if !is_valid_tid(skey) {
        return Err(UriError::InvalidSkey);
    }
    SpaceRef::new(author, SPACE_TYPE, skey)
}

pub fn only_me_space(author: &str) -> Result<SpaceRef, UriError> {
    SpaceRef::new(author, SPACE_TYPE, ONLY_ME_SKEY)
}

pub fn is_only_me(space: &SpaceRef) -> bool {
    space.skey() == ONLY_ME_SKEY
}

/// The policy a group is created with. `allowed_apps` limits which apps
/// may read (by attested client ID); `None` allows any app a member uses.
pub fn group_policy(allowed_apps: Option<Vec<String>>) -> Policy {
    Policy::Member(MemberPolicy {
        public_read: false,
        public_write: false,
        allowed_apps,
        publish_policy: true,
        publish_members: true,
    })
}

pub fn only_me_policy() -> Policy {
    Policy::Personal
}

/// Why a space isn't one Umbrae will post into or show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misconfigured {
    NotUmbrae,
    /// Anyone could read it: posts there wouldn't be hidden.
    PublicRead,
    PublicWrite,
    /// A group must publish its policy and member list to its members.
    Unpublished,
    WrongPolicy,
}

/// Check that `policy` is what Umbrae expects for `space`. A client checks
/// before writing; a reader before showing.
pub fn check_policy(space: &SpaceRef, policy: &Policy) -> Result<(), Misconfigured> {
    if space.space_type() != SPACE_TYPE {
        return Err(Misconfigured::NotUmbrae);
    }
    match (is_only_me(space), policy) {
        (true, Policy::Personal) => Ok(()),
        (false, Policy::Member(p)) if p.public_read => Err(Misconfigured::PublicRead),
        (false, Policy::Member(p)) if p.public_write => Err(Misconfigured::PublicWrite),
        (false, Policy::Member(p)) if !(p.publish_policy && p.publish_members) => {
            Err(Misconfigured::Unpublished)
        }
        (false, Policy::Member(_)) if is_valid_tid(space.skey()) => Ok(()),
        _ => Err(Misconfigured::WrongPolicy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
    const SKEY: &str = "3mbbbbbbbbbb2";

    #[test]
    fn spaces() {
        let g = group_space(ALICE, SKEY).unwrap();
        assert_eq!(
            g.to_string(),
            format!("at://{ALICE}/space/{SPACE_TYPE}/{SKEY}")
        );
        assert!(group_space(ALICE, "friends").is_err());
        assert!(group_space(ALICE, ONLY_ME_SKEY).is_err());
        assert!(is_only_me(&only_me_space(ALICE).unwrap()));
    }

    #[test]
    fn policies_round_trip_and_check() {
        let g = group_space(ALICE, SKEY).unwrap();
        let p = group_policy(None);
        assert_eq!(Policy::from_map(&p.to_map()).unwrap(), p);
        assert_eq!(check_policy(&g, &p), Ok(()));
        let me = only_me_space(ALICE).unwrap();
        assert_eq!(check_policy(&me, &only_me_policy()), Ok(()));
        assert_eq!(check_policy(&me, &p), Err(Misconfigured::WrongPolicy));
        assert_eq!(
            check_policy(&g, &only_me_policy()),
            Err(Misconfigured::WrongPolicy)
        );
    }

    #[test]
    fn refuses_public_or_unpublished_groups() {
        let g = group_space(ALICE, SKEY).unwrap();
        let with = |f: fn(&mut MemberPolicy)| {
            let mut p = match group_policy(None) {
                Policy::Member(p) => p,
                _ => unreachable!(),
            };
            f(&mut p);
            Policy::Member(p)
        };
        assert_eq!(
            check_policy(&g, &with(|p| p.public_read = true)),
            Err(Misconfigured::PublicRead)
        );
        assert_eq!(
            check_policy(&g, &with(|p| p.public_write = true)),
            Err(Misconfigured::PublicWrite)
        );
        assert_eq!(
            check_policy(&g, &with(|p| p.publish_members = false)),
            Err(Misconfigured::Unpublished)
        );
        let other = SpaceRef::new(ALICE, "com.example.space", SKEY).unwrap();
        assert_eq!(
            check_policy(&other, &group_policy(None)),
            Err(Misconfigured::NotUmbrae)
        );
    }
}
