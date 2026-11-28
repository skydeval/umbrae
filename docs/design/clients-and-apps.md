# Clients and apps

## OAuth scopes

`space:` scopes default the authority to `self`: the signing-in user's own spaces. Acting in other people's spaces needs `authority=*`. The `action` parameter defaults to `read create update delete`; `action=read` limits a grant to reads.

| Use | Scope |
|---|---|
| post, reply, like and repost in groups, including other people's | `space:tools.umbrae.space?authority=*&collection=tools.umbrae.post&collection=tools.umbrae.like&collection=tools.umbrae.repost` |
| the user's own groups and only-me (create, members, delete) | `space:tools.umbrae.space?collection=tools.umbrae.group&collection=tools.umbrae.bookmark&collection=tools.umbrae.list&collection=tools.umbrae.listitem&collection=tools.umbrae.exemption&manage=create&manage=update&manage=delete` |
| own shared lists | `space:tools.umbrae.listSpace?collection=tools.umbrae.list&collection=tools.umbrae.listitem&manage=create&manage=update&manage=delete` |
| reading lists the user subscribes to | `space:tools.umbrae.listSpace?authority=*&action=read` |
| the user's own community spaces (create one, then post, reply, like, repost, feed and gate there) | `space:tools.umbrae.space?collection=tools.umbrae.post&collection=tools.umbrae.like&collection=tools.umbrae.repost&collection=tools.umbrae.feed&collection=tools.umbrae.threadgate&collection=tools.umbrae.postgate&manage=create` |
| the user's hidden profile (create the profile space, write the record, add a community app to `allowedApps`) | `space:tools.umbrae.space?skey=profile&collection=tools.umbrae.profile&manage=create&manage=update` |
| a serving app that fetches the owner's profile delegations itself | `space:tools.umbrae.space?skey=profile&action=read` |
| a private account's own private space (create it, move records in and out, write the rules, approve and remove followers, change serving app) | `space:tools.umbrae.private?collection=app.bsky.feed.post&collection=app.bsky.feed.repost&collection=app.bsky.feed.like&collection=app.bsky.feed.threadgate&collection=app.bsky.feed.postgate&collection=tools.umbrae.private.rules&collection=tools.umbrae.private.approval&manage=create&manage=update&manage=delete` |
| replying, liking, reposting and quoting in others' private spaces | `space:tools.umbrae.private?authority=*&collection=app.bsky.feed.post&collection=app.bsky.feed.repost&collection=app.bsky.feed.like&collection=app.bsky.feed.postgate` |
| a labeler writing and deleting in-space labels in others' spaces (not yet checked against a PDS) | `space:tools.umbrae.space?authority=*&collection=com.atproto.label.record&action=create&action=delete` |

`manage=create` covers `createSpace`, `manage=update` covers `putMembers`, `removeMembers` and `updateSpace`, and `manage=delete` covers `deleteSpace`.

A community space is only ever read by its author and the community's app, so no client asks for `authority=*` on one: members read communities through the app.

A private space is read only by its owner and its serving app. `authority=*` there is for writing interactions into the owner's space; viewers read through the app's `tools.umbrae.private.*` methods.

## Reading another account's space

The only way to a space credential is `authorizeSpaceSync`. Clients and serving apps both use it.

1. **On the reader's own PDS:** call `com.atproto.space.getDelegationToken {space}`.
   - It needs a full-access OAuth session (no app passwords) with a scope that allows reading the space.
   - The token is single-use, valid for 60 seconds, and not bound to a client, so treat it as a bearer secret.
2. **On the space authority's PDS:** call `com.atproto.space.authorizeSpaceSync {space, credentialKey, delegationToken}`.
   - `credentialKey` is a fresh P-256 did:key.
   - Add a client attestation if the space restricts apps with `allowedApps`.
   - The result is a space credential: 600 seconds by default, 3600 at most.
3. **Read** with the credential, plus an RFC 9421 signature from the credential key, using any of these:
   - `com.atproto.space.listWriters`;
   - `getRepo` (a STAR archive with a commit MAC);
   - `listRecords {space, repo, collection?}`, which returns `{records: [{collection, rkey, cid, value?}], cursor?}`;
   - `getRecord`, `listRepoOps` or `getBlob`.

   Space `getBlob` carries no MAC, so check the blob's CID.

A community's app reads members' community spaces without a delegation: step 2 alone, with its own client attestation and no `delegationToken`. The space's policy names the app, which answers `read` for its own attested client while the space's authority is a writer, and nothing for any account.

`umbrae-sync` does all of this for an admitted serving app, over a transport the caller supplies:
- authorization and credentials;
- writer listing;
- full and incremental repo sync, bound to the records it already holds;
- update notifications (`notifySpaceUpdate`);
- validation by space type.

A space type it doesn't handle, such as a list space, comes back as unknown and is never served. A `com.atproto.label.record` in an Umbrae or private space comes back as its own kind (`Checked::SpaceLabel`); whose count is the `umbrae` crate's rule.

### Keeping a copy honest

- **A daily full fetch.** Op replay never learns that a host took a record down, so at least once a day the app drops each repo's cursor before `sync_space`, and every repo is fetched with `getRepo`.
- **`RecordsTakendown`** (atproto-pds): while any record in a repo is taken down at its host, `getRepo` refuses the whole repo. `sync_space` reports `RepoChange::TakenDown`: the cursor is kept, and the app serves only the held records whose `(collection, rkey, cid)` `listRecords` still lists, dropping the rest. That listing isn't verified, so it only ever removes. A record `listRepoOps` returns but `listRecords` doesn't list is never served.
- **Known limit:** atproto-pds still returns a taken-down record's value in `listRepoOps`, so op replay can serve it for up to a day, until the next full fetch.

## Blobs

- **Write the record right after the upload.** atproto-pds deletes a blob nothing references after a grace period (24 hours by default). Clients write the record referencing a blob in the same flow as its `uploadBlob`; if that write didn't happen, upload again. This covers post images and video, profile avatars, banners and link icons, and labeler profile images.
- **Drafts** keep a blob's bytes locally, never just its CID.
- **Replacing a blob** drops the old one once nothing references it: at once on the reference PDS, after the grace on atproto-pds. `BlobNotFound` for a blob no current record names is normal; for one a current record names, the blob is unavailable, not an error.

## Moving to another PDS

Space URIs name DIDs, never hosts, so no record is rewritten when an account moves. Notification registrations, credential revocations and deleted-space tombstones don't carry over, and the new host has its own `#atproto_kem` key and an empty op log.

- **Syncing apps** watch `#identity` events for every authority and writer whose spaces they sync. When an account's `#atproto_pds` changes, `host_changed` drops its repo's cursor, so its repos are fetched in full once; the app drops its cached endpoint and KEM key, and for an authority authorizes again at the new host, registering for notifications again. A `RepoDeactivated` from a host is retried once with the DID document resolved afresh.
- **Already handled:** a failed MAC is retried with the KEM key re-resolved, and an op log that can't bridge the cursor falls back to a full fetch.
- **A space deleted before the move** answers `SpaceNotFound` at the new host. After a host change, `missing_space` says to stop serving it at once and drop its copy after 72 hours unless it answers again. Before any host change, only `SpaceDeleted` drops data.
- **Lost revocations:** for up to 60 minutes the new host may accept a credential the old one revoked, within the existing bound of an hour.
- **Community spaces** keep their policy, `managingApp` included, and the new host asks the same `checkAccess`. After migrating, the writer's client calls `registerSpace` at each community app where it's a writer.
- **Groups:** policy and members move with the space. Members' repos don't move.
- **The hidden profile:** see [Moving to another PDS](accounts.md#moving-to-another-pds).
- **A labeler** moves its in-space labels with its repos, one space at a time. They aren't signed, so nothing is re-signed. Its labeler space moves as any authority's space, and its `labelKey` is in its policies record.

## Detecting spaces support

A PDS supports spaces if either:
- `describeServer` reports `spacesAlpha: true` (the alpha only); or
- an unauthenticated `com.atproto.space.getSpace` probe answers `401 AuthMissing`.

## Lexicon resolution

A PDS resolves the space type's lexicon when a user grants `space:` scopes. The `tools.umbrae.*` lexicons are published as `com.atproto.lexicon.schema` records, with record key = NSID, on the account that `_lexicon.umbrae.tools` points to. They're republished with every release.

## Versioning

Umbrae uses semver, with Cargo's pre-1.0 rule:
- a minor bump (0.x.0) is breaking;
- a patch (0.x.y) is compatible.

Since 0.4.0 the public record and change enums are `#[non_exhaustive]`:
- **For consumers:** match them with a wildcard arm that fails closed (refuse, hide or report).
- **What it allows:** new record types can arrive in a patch.

See the [changelog](../../CHANGELOG.md).
