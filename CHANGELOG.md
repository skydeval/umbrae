# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor bump is a breaking change and a patch is compatible, as Cargo treats them.

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/skydeval/umbrae/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/skydeval/umbrae/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/skydeval/umbrae/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/skydeval/umbrae/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/skydeval/umbrae/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/skydeval/umbrae/releases/tag/v0.1.0
