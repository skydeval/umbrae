# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor bump is a breaking change and a patch is compatible, as Cargo treats them.

## [Unreleased]

## [0.9.0] - 2026-11-27

Spaces compatibility: Umbrae reads and writes the spec's in-space labels, honors `!takedown`, and runs its interop suite against a second PDS.

### Changed
- **Breaking:** `SpaceState` gains `label_writers`, the accounts whose in-space labels may count (never members), and `taken_down`, the records a `!takedown` hides. Its fields are public, so code building it literally needs both; `SpaceState::new` fills them empty.
- **Breaking:** `can_view_record` refuses a record in `taken_down`, for every viewer, its author included. Everything built on it follows: reposts, bookmarks, feeds, labels and `referenced_post`, which shows a taken-down post as unavailable.
- `tools.umbrae.space` declares `com.atproto.label.record` among its collections, and its description says whose labels count. Lexicons are republished with this release.
- `validate_record` checks a `com.atproto.label.record` in a `tools.umbrae.space` space, as `Record::SpaceLabel`.
- `umbrae-sync` retries a `RepoDeactivated` once with the account's DID document resolved afresh, as it does a failed MAC.
- Docs: a community app's `checkAccess` is asked for each write or delete notification from a repo other than the authority, not "never for writes"; it answers from memory. An everyone space's managing app answers `read` and `write` for the accounts it admits, whose replies, likes and reposts go into the post's space.

### Added
- In-space labels: `SPACE_LABEL`, `validate_space_label`, `SpaceLabel` and `SpaceLabelSubject`. The lexicon's constraints apply (`val` 1 to 128 bytes, datetimes, a TID key); a label naming anything but a record in its own space, or with `neg: true`, is ignored.
- `current_space_labels`: per `(writer, uri, cid, val)`, the latest by `cts`, then record key; expired and ignored labels drop, and a deleted record counts as never written.
- `is_label_writer`: a community's named labeler; an everyone space's writer set minus the authority; a group's or followers space's members with `write` (labelers are never listed there automatically, and one the owner adds is an ordinary member); in a private space, the accounts its app lists; nobody elsewhere. `can_view_space_label` and `can_view_space_repost_label` also need the reader's trust in that labeler and the viewer's right to see the post.
- `merge_label_homes`: labeler-space and in-space labels as one list, de-duplicated by `(src, uri, cid, val)`.
- `TAKEDOWN` and `apply_takedowns`: the authority's `!takedown` on a record in its space, and in a community space the named labeler's as the community's. Ignored in only-me, the profile, labeler spaces and shared lists. For other space types, `tools.umbrae.private` included, the serving app applies it per its spaces configuration, on by default.
- Rule 4a for community apps: `checkAccess` answers `{read: false, write: true}` for the community's named labeler with no `clientId`, so its labels enter the writer set; a managing app keeps a removed label writer's last-synced labels.
- `umbrae-sync`: `Checked::SpaceLabel`; `RepoChange::TakenDown`, with the keys `listRecords` still lists, when a host refuses a repo with `RecordsTakendown` (the cursor is kept); `list_records`; `host_changed` for an account that moved hosts; `missing_space`, `MissingSpace` and `MISSING_AFTER_MOVE` for a space answering `SpaceNotFound` after a move; `SyncError::is_space_deleted`, `is_records_takendown` and `is_repo_deactivated`. The daily resync drops cursors so every repo is fetched whole.
- Docs: labels in the subject's space and whose count; takedowns for spaces in general and for Umbrae spaces; blobs; moving to another PDS, the hidden profile's sticky copy fallback included; the community's takedown; the labeler's scope.
- The interop harness runs against atproto-crates' `atproto-pds` with `PDS_IMPL=crates`, built from a pinned commit by `scripts/build-atproto-pds.sh`, behind a TLS front. One table in `umbrae-interop` lists where the two PDSes answer differently: error names for an unauthenticated space read, a label record failing the lexicon or its key, another account's repo and `listWriters` with a session; a repo outside the writer set, which only the reference serves directly; and a legacy blob ref written with `validate: false`, which only atproto-pds accepts.
- Interop coverage, on both PDSes, against a stand-in managing app: rule 4a (the labeler's label write is asked about and answered write, it syncs and counts; its own credential request is refused); another writer's label write stays outside the writer set; the named labeler's `!takedown` hides a post with a placeholder; after `removeWriter` the app's kept labels still apply and the labeler's next write brings its repo back whole; deleting label records removes them; in an everyone space, a configured labeler's label counts where trusted and an untrusted replier's doesn't, and an admitted reply is tracked; a group owner's `!takedown` hides a member's reply and deleting it brings it back. On atproto-pds only: a host record takedown answers `RecordsTakendown`, the syncer drops only that record, and op replay from an older cursor still carries it (a known limit).

## [0.8.1] - 2026-11-27

### Added
- Private accounts: one switch makes a whole account permissioned, old posts included, with the boundary enforced by spaces. See [Private accounts](docs/design/private-accounts.md).
  - The private space: `tools.umbrae.private` at `self` (`private_space`, `PRIVATE_SPACE_TYPE`), with a published managed policy naming the owner's serving app, its only reader (`check_private_policy`). It holds native `app.bsky.feed.*` posts, reposts, likes, threadgates and postgates, so a move is an exact copy at the same key, and the owner's `tools.umbrae.private.rules`.
  - `validate_private_record`, `PrivateRecord` and `PrivatePost`: the owner's records may name public records and records in the space; another account's count only on the owner's thread; a space URI of any other space doesn't count. `umbrae-sync` returns them as `Checked::Private`.
  - The rules: `Rules` and `Rule` (`#approvedFollowers`, `#following`, `#mutuals`, `#list`), and `can_view_private` over a `PrivateInputs` trait, checked live and failing closed. `interaction_counts` hides others' interactions once their author stops passing.
  - Two forms of one record's URI: `private_uri` and `public_uri`.
  - Placement: interactions on a private-space record go into that space, and a private account's own writes into its own (`private_actor_space`).
  - Going public: `stays_private`, the records that stay, computed to a fixpoint, and `going_public_value`, which rewrites the owner's own references to the public form.
  - `tools.umbrae.private.declaration`, in the public repo, naming the serving app.
  - Methods at the serving app: `register`, `unregister`, `requestFollow`, `withdrawRequest`, `listRequests`, `getAccess`, and the read surface `listRecords`, `getRecords`, `listInteractions` and `getBlob`. `tools.umbrae.private.move`, an optional native move a PDS may serve. The `PRIVATE_*` constants, `PRIVATE_COLLECTIONS` and the `BSKY_*` collection names.
  - The private audience for the hidden profile: `#privateAudience` (`AUDIENCE_PRIVATE`, `Audience::Private`), served only by the private space's serving app through `AudienceSource::private_viewer`, which answers false by default.
  - OAuth scopes for the owner's private space, for acting in others', and for the serving app's followers-space access.
  - The serving app's moderators may see private accounts through its moderation paths.
- Interop coverage on the reference PDS against a stand-in serving app: a post with an image moves in one batch at the same rkey with the same CID; public `getRecord` and `sync.getBlob` refuse it once the last public use moves, and `listBlobs` leaves the blob out; the owner and the app read the post and blob; resuming looks up first and sends only creates and updates; a legacy blob ref is rewritten before the write; allowed and outside accounts' own delegations are refused; an allowed account's reply is tracked and an outsider's isn't, and after a loss of access the app filters it; going public restores the records and blob and keeps the space; with the app down the PDS fails closed; every `checkAccess` carries the owner as `iss`.

## [0.8.0] - 2026-11-27

### Changed
- **Breaking:** a community is a membership kept by a managing app, not an account. It's named by `CommunityRef {app, key}` (`tools.umbrae.community.defs#communityRef`): the app's `did#serviceId` and a key unique within it. There's no community account, repo or declaration. The 0.7 community switches were never turned on, so nothing migrates.
- **Breaking:** each writer keeps their community records in their own space: `community_space(author, &ref)`, a `tools.umbrae.space` keyed `community_skey(ref)` (`c-` and 32 base32 characters of a SHA-256 over the ref), with a published managed policy naming the app. Only the authority's records count there.
- **Breaking:** the app is the only reader of community spaces. It answers `checkAccess` with nothing for any account, and with `read` only for its own attested client while the space's authority is a writer. Members read through the app, so a removal takes effect at its next request.
- **Breaking:** `SpaceState` gains `community`, the ref the app maps a community space to. A community space shows only with it set, a policy passing `check_community_policy`, and a writer authority. `is_writer` is authority-only there.
- **Breaking:** `reply_space`, `like_space`, `repost_space` and `quote_space` take the actor, return a `Result`, and send a reply, like, repost or quote of a community post into the actor's own space for that community.
- **Breaking:** validation accepts, in a community space, references to any space of the same type and key: reply roots and parents, like and repost subjects, quoted posts, `Post.feeds`, threadgate `hiddenReplies` and postgate `detachedEmbeddingUris`. Elsewhere the same-space rules stand.
- **Breaking:** `can_view_repost` and `can_view_repost_label` take the repost's and the subject's space states; `can_view_feed_post` takes the post's and the feed's. In a community, both spaces must be one community (`in_same_community`), so a lookalike naming another app fails.
- **Breaking:** `Audience::Community` holds a `CommunityRef`, and `#communityAudience` is `{community}`. Only the community's app serves it, through `AudienceSource::community_member`, which answers `None` by default and for communities an app doesn't keep.
- **Breaking:** `tools.umbrae.community.*` methods take `key` in place of the community DID. `getCommunity` returns the ref, `listed`, `labeler`, `appClientId` and `viewer.moderator`; roles are `reader` and `writer`; `invite` takes an optional `role`.
- `check_policy` and `is_managed` treat `c-` keys as managed.
- The managed labeler space names the community's app, which answers nothing for accounts and serves labels through its own views.

### Added
- `CommunityRef`, `community_skey`, `is_community_skey`, `is_community_space`, `check_community_policy` and `in_same_community`.
- `tools.umbrae.community.listMyCommunities`, `registerSpace` (the app syncs a writer's new space at once) and `registerProfile {key, delegationToken}` (the app syncs the caller's profile space for its community audiences). `COMMUNITY_LIST_MINE`, `COMMUNITY_REGISTER_SPACE`, `COMMUNITY_REGISTER_PROFILE` and `COMMUNITY_DEFS`.
- Placeholders: `tools.umbrae.community.defs#unavailablePost` (`UNAVAILABLE_POST`) and `referenced_post`, which answers `Visible`, `Blocked` or `Unavailable` for a post a thread refers to. A reply stays visible when its parent doesn't, and a removal looks like a deletion.
- `Role`, a member's role in a community.
- Rules for gates and reply rules in communities, records outside a community that name records in it, and handing a profile to a community app, in the design docs. The profile scope gains `manage=update`, for adding a community app to `allowedApps`.
- Interop coverage on the reference PDS against a stand-in app: writes in one's own space ask the app nothing; the app's attested sync and notifications; refused unattested, foreign, forged and replayed attestations; no credential for any member's, reader's or outsider's delegation; removal withdrawing the app's registration and leaving placeholders; a lookalike failing the policy check; a profile space limited by `allowedApps`; and failing closed.

### Removed
- **Breaking:** `COMMUNITY_SKEY`, `tools.umbrae.community.declaration`, `CommunityDeclaration`, `validate_community_declaration` and `COMMUNITY_DECLARATION`.
- **Breaking:** the legacy profile copy by a member in a community space. Legacy copies are the owner's own, in its followers, group or everyone space, and `profile_for_viewer` no longer ranks community copies.

## [0.7.4] - 2026-11-27

### Fixed
- `can_view_profile` showed a profile whose profile space failed `check_policy`: one with an unpublished member list (a member the reader can't see reads it directly), public read, or a managed policy. Now such a space shows the profile to nobody, the owner included.

### Added
- `tools.umbrae.actor.getProfile` and `tools.umbrae.actor.getProfileBlob`: how a viewer reads a hidden profile and its blobs through their serving app, with service auth and `atproto-proxy`. `ProfileNotFound` answers alike for none, not allowed and not held. `ACTOR_GET_PROFILE` and `ACTOR_GET_PROFILE_BLOB`.
- Keeping the serving app current: after every write to the profile space, the owner's client hands the serving app a fresh delegation, or the app fetches its own with read scope on the profile space.
- Hidden profiles reach moderation the same way as hidden posts, with the audiences they're shown to.
- OAuth scopes for writing the profile and for a serving app that fetches profile delegations itself.
- Interop coverage: a non-owner's delegation for a profile space is refused as `SpaceNotFound`; deleting a legacy copy keeps the shared avatar in the profile space and off the public side; profile spaces with an unpublished member list, or public read, show to nobody.

### Changed
- Migration from copies: list only the audiences whose copy matches the newest content, carry nothing over from a copy that differs, and let the owner confirm before the copies are deleted. 0.7.3 merged pictures across copies, which could show one audience's face to another.
- Readers ignore legacy copies once the owner has, or has deleted, a profile space, not just while a record exists, so deleting the record doesn't bring the copies back.
- Clients editing a profile keep audience entries they don't know.

## [0.7.3] - 2026-11-27

### Added
- One hidden profile for every audience. Per-audience copies drifted apart, because an edit only reached the copy being edited. Now:
  - `tools.umbrae.profile` lives at `self` in the owner's profile space: the key `profile` (`profile_space`, `PROFILE_SKEY`), the group policy, and no members;
  - the record lists its `audiences`: followers, one of the owner's groups, a community the owner is in, or everyone the serving app admits;
  - the serving app reads it on the owner's delegation, and shows it and its blobs to anyone in a listed audience (`can_view_profile`, `can_view_profile_blob`, `AudienceSource`). A profile space with members shows the profile to nobody.
- `Audience`, `Profile::audiences`, `Profile::blobs`, `MAX_PROFILE_AUDIENCES`, and the `AUDIENCE_*` types.
- Interop coverage of a profile space on the reference PDS: only the owner's delegation reads it, and a follower sees the profile and its avatar.

### Deprecated
- Per-audience profile copies (0.7.0 to 0.7.2) are legacy. Read them with `profile_for_viewer` only while the owner has no profile-space record. On the next save a client writes the one record and deletes the copies.

## [0.7.2] - 2026-11-26

### Added
- `tools.umbrae.community.declaration`: a community's public record, at `self` in the community account's public repo, naming its `managingApp`. A client that has only the community's DID reads it with `com.atproto.repo.getRecord` to learn where to call `tools.umbrae.community.*`, since the space policy isn't readable before joining. A community without one is unlisted, and invites carry the managing app instead.
- `validate_community_declaration`, `CommunityDeclaration` and `COMMUNITY_DECLARATION`.

## [0.7.1] - 2026-11-26

### Added
- Community membership methods, `tools.umbrae.community.*`: `getCommunity`, `join`, `leave`, `listMembers`, `decide`, `invite` and `remove`.
  - Any managing app serves them, at the `#umbrae_app` endpoint the space policy names, with atproto service auth. Clients call through their PDS with `atproto-proxy`.
  - They're manager-neutral, so a serving app and a PDS that manages its own communities answer the same calls.
- `COMMUNITY_GET`, `COMMUNITY_JOIN`, `COMMUNITY_LEAVE`, `COMMUNITY_LIST_MEMBERS`, `COMMUNITY_DECIDE`, `COMMUNITY_INVITE` and `COMMUNITY_REMOVE`.

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

[Unreleased]: https://github.com/skydeval/umbrae/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/skydeval/umbrae/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/skydeval/umbrae/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/skydeval/umbrae/compare/v0.7.4...v0.8.0
[0.7.4]: https://github.com/skydeval/umbrae/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/skydeval/umbrae/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/skydeval/umbrae/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/skydeval/umbrae/compare/v0.7.0...v0.7.1
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
