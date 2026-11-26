# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor bump is a breaking change and a patch is compatible, as Cargo treats them.

## [Unreleased]

## [0.7.0] - 2026-11-26

### Added
- Communities:
  - a `tools.umbrae.space` space with the key `community`, whose authority is the community's own account;
  - its policy is a published `managedspace` (`community_space`, `managed_policy`, accepted by `check_policy`);
  - membership is held by the managing app through `checkAccess`: a serving app, or a PDS that manages its own communities;
  - `SpaceState.members` takes the managing app's answers for managed spaces.
- The "everyone with Umbrae" audience: an account's `everyone` space, also managed (`everyone_space`).
- `tools.umbrae.feed`: an author-driven feed in a community, with up to 5000 authors. `Post.feeds` names up to 3 feeds in the post's own community. `can_view_feed_post` shows a post only while its author is on the feed's current author list.
- `tools.umbrae.listSubscription`, in only-me, naming a list in any Umbrae space. Shown by `can_view_list_subscription`.
- `profile_for_viewer` and `ProfileCopy`: the profile copy a viewer sees is the narrowest audience they're in. `tools.umbrae.profile` gains `updatedAt`.
- `check_labeler_policy` accepts a published managed labeler space.
- `is_managed`, `COMMUNITY_SKEY`, `EVERYONE_SKEY`, `FEED`, `LIST_SUBSCRIPTION`, `MAX_FEED_AUTHORS` and `MAX_FEEDS_PER_POST`.
- Interop coverage of a managed community on the reference PDS, against a stand-in managing app. It checks: member writes tracked, a non-member refused, service auth on every check, removal, and failing closed when the app is down.

### Changed
- **Breaking:** `tools.umbrae.profile` may live at `self` in any audience space: followers, a group or everyone (by the owner), or a community (by the member). It never lives in only-me.
- **Breaking:** lists and list items may live in any audience space, not only in only-me. Exemptions stay in only-me.
- **Breaking:** `Post` is `#[non_exhaustive]` and gains `feeds`. `Record` gains `Feed` and `ListSubscription`.

## [0.6.0] - 2026-11-26

### Added
- `tools.umbrae.profile` matches the public profile:
  - `pronounSets` (up to 10 sets of 1 to 12 forms, as in `app.nearhorizon.actor.pronouns`) and `pronounDisplayMode` (`all` or `firstOnly`), next to the short `pronouns`;
  - `links`: up to 10, each an https `url` with an optional `title` (30 graphemes) and `icon` (png or jpeg, at most 1 MB). Readers hide duplicates and general-purpose shorteners when showing them;
  - `avatarAlt` and `bannerAlt`.
- `PronounSet`, `ProfileLink`, `MAX_PROFILE_LINKS`, `MAX_LINK_TITLE`, `MAX_PRONOUN_SETS` and `MAX_PRONOUN_FORMS`.

### Changed
- **Breaking:** `Profile` gains fields and is `#[non_exhaustive]`, so later fields can arrive in a patch.

## [0.5.0] - 2026-11-25

### Changed
- **Breaking:** space URIs use the `at:space/` form from the spaces spec (proposal 0016, merged 2026-11-25):
  - a space is `at:space/{spaceDid}/{spaceType}/{skey}`;
  - a record is `at:space/{spaceDid}/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}`.
  `SpaceRef` and `SpaceRecordUri` format and parse only this form. The old `at://{did}/space/...` form fails with `UriError::LegacyForm`.
- **Breaking:** `UriError` gains `LegacyForm` and is `#[non_exhaustive]`.
- `is_space_uri` and `contains_space_uri` also match the new form (any case), and still match the old one, so neither form is ever taken for a public URI or let through into public text.
- Commits, MACs, credential subjects and notifications carry the new form, as the reference PDS now does.

### Added
- `SPACE_URI_PREFIX`, `SpaceRef::parse_legacy`, `SpaceRecordUri::parse_legacy`, `is_legacy_space_uri` and `upgrade_legacy`, for reading and rewriting old-form URIs.
- `upgrade_space_uris`, which rewrites the old-form space URIs stored in a record value, so the author can put the record back. The PDS doesn't rewrite record values itself.

## [0.4.3] - 2026-11-23

### Added
- Labels on hidden reposts: `LabelSubject::HiddenRepost`, accepted by `label_subject` and `validate_labeler_record`. `can_view_repost_label` shows them only to people who may see the repost and the post it reposts; `can_view_label`, which can't see that post, never shows them.
- `hidden_record_of`, which returns the hidden post or repost a label is on.

## [0.4.2] - 2026-11-20

### Added
- Private accounts: a `tools.umbrae.space` space with the key `followers` holds a private account's approved followers. It uses the group policy (`followers_space`, accepted by `check_policy`).
- `tools.umbrae.profile`: the hidden profile, written by the authority at `self` in its followers space. It has display name, bio, pronouns, website, avatar and banner. The avatar and banner are served only through space `getBlob`.
- `tools.umbrae.follow`: a hidden follow, a DID, kept in its owner's only-me space.
- `tools.umbrae.threadgate`: reply rules (mention, following, follower, own list) and up to 300 hidden replies.
- `tools.umbrae.postgate`: detached quotes, and turning quoting off. Both gates are written by the post's author, in the post's space, at the post's key.
- Interop coverage of a followers space, the hidden profile and its blob, and both gates on the reference PDS.
- Public design docs in `docs/design/`.

### Changed
- README brought up to date.

## [0.4.1] - 2026-11-19

### Added
- Hidden lists:
  - `tools.umbrae.list` (purpose `block`, `mute` or `curate`) and `tools.umbrae.listitem`.
  - **Personal lists** live in the owner's only-me space; entries name their list by record key.
  - **Shared lists** are their own space type, `tools.umbrae.listSpace`: the owner writes the list at `self` and its entries, and subscribers are read-only members. The member list is unpublished, so subscribers can't see each other and no app serves the list.
- `tools.umbrae.exemption`, in only-me: don't apply one label value, one labeler's labels, or one list, to one account.
- `validate_list_record`, `list_space`, `list_policy`, `check_list_policy` and `subscriber`.
- `Record::List`, `Record::ListItem` and `Record::Exemption`.
- Interop coverage of a shared list on the reference PDS.

### Changed
- `tools.umbrae.space` now declares the list, listitem and exemption collections. Records in them are validated instead of ignored.

## [0.4.0] - 2026-11-17

### Added
- `tools.umbrae.repost`: a repost of a hidden post, written into that post's own space.
- Quotes:
  - a hidden post may quote a public record, or a hidden post in its own space;
  - `Post.quote` carries the quoted strong ref;
  - the quoted URI is the only place in an embed that may name a hidden record.
- `repost_space`, `quote_space` and `can_view_repost`.

### Changed
- **Breaking:** `Record`, `LabelerRecord`, `LabelSubject`, `Checked`, `RepoChange`, `Update` and `SyncError` are `#[non_exhaustive]`. A `match` on them needs a wildcard arm.
- **Breaking:** `Post` gains a public `quote` field.
- **Breaking:** `tools.umbrae.repost` records validate as `Record::Repost` instead of being ignored.
- Validation now refuses:
  - malformed record embeds;
  - `recordWithMedia` media other than images, video or external;
  - likes and reposts that name a hidden record anywhere but `subject.uri`.

## [0.3.0] - 2026-11-14

### Added
- `tools.umbrae.bookmark`: a bookmark of a hidden post, kept in its owner's only-me space and shown only while the owner may still see the post.
- `can_view_bookmark`.

### Changed
- **Breaking:** `Record` gains `Bookmark`.

## [0.2.0] - 2026-11-14

### Added
- **Private labelers:** the `tools.umbrae.labeler` space type, and the records:
  - `label`;
  - `labelerProfile`, `labelerPolicies`, `labelerReasons`;
  - `labelerAudience`.
- **Labels on:** accounts, public records and hidden posts. A label on a hidden post shows only to people who may see the post.
- **Restricted labels:** a label may name an audience, a permitted list. It then shows only to that list's members, bound to the label's own labeler.
- **Label keys:**
  - signing and verification;
  - the key kept in the labeler's policies;
  - retired keys that still verify older labels.
- `umbrae-sync`: space sync as an admitted app over a caller-supplied transport. It covers credentials, writer listing, full and incremental repo sync bound to the records held, update notifications, and validation by space type.

### Fixed
- A credential's issuer is bound to the space authority.
- Hidden URIs inside public text are caught.
- DRISL decoding caps how much it preallocates.
- Op-log replay is bound to the records held.
- Hosts sending hostile responses are handled.

## [0.1.0] - 2026-11-14

### Added
- Rebuilt on atproto spaces: hidden posts live in space repos on each author's own PDS.
- `umbrae-core`:
  - space URIs;
  - DRISL and DASL CIDs;
  - commits and the LtHash digest;
  - STAR archives;
  - KEM shared secrets;
  - RFC 9421 credential signatures and MACs;
  - credentials, delegation tokens and client attestations;
  - `space:` OAuth scopes;
  - the baseline policies.
- `umbrae-lexicons`: the `tools.umbrae.space` space type, plus `post`, `like` and `group`, with validation.
- `umbrae`:
  - placement of replies and likes;
  - `can_view` rules;
  - group and only-me policies;
  - the public-leak guard.
- The interop harness against the reference spaces PDS.

[Unreleased]: https://github.com/skydeval/umbrae/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/skydeval/umbrae/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/skydeval/umbrae/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/skydeval/umbrae/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/skydeval/umbrae/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/skydeval/umbrae/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/skydeval/umbrae/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/skydeval/umbrae/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/skydeval/umbrae/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/skydeval/umbrae/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/skydeval/umbrae/releases/tag/v0.1.0
