# Clients and apps

## OAuth scopes

`space:` scopes default the authority to `self`: the signing-in user's own spaces. Acting in other people's spaces needs `authority=*`. The `action` parameter defaults to `read create update delete`; `action=read` limits a grant to reads.

| Use | Scope |
|---|---|
| post, reply, like and repost in groups, including other people's | `space:tools.umbrae.space?authority=*&collection=tools.umbrae.post&collection=tools.umbrae.like&collection=tools.umbrae.repost` |
| the user's own groups and only-me (create, members, delete) | `space:tools.umbrae.space?collection=tools.umbrae.group&collection=tools.umbrae.bookmark&collection=tools.umbrae.list&collection=tools.umbrae.listitem&collection=tools.umbrae.exemption&manage=create&manage=update&manage=delete` |
| own shared lists | `space:tools.umbrae.listSpace?collection=tools.umbrae.list&collection=tools.umbrae.listitem&manage=create&manage=update&manage=delete` |
| reading lists the user subscribes to | `space:tools.umbrae.listSpace?authority=*&action=read` |
| the user's hidden profile (create the profile space, write the record) | `space:tools.umbrae.space?skey=profile&collection=tools.umbrae.profile&manage=create` |
| a serving app that fetches the owner's profile delegations itself | `space:tools.umbrae.space?skey=profile&action=read` |

`manage=create` covers `createSpace`, `manage=update` covers `putMembers` and `removeMembers`, and `manage=delete` covers `deleteSpace`.

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

`umbrae-sync` does all of this for an admitted serving app, over a transport the caller supplies:
- authorization and credentials;
- writer listing;
- full and incremental repo sync, bound to the records it already holds;
- update notifications (`notifySpaceUpdate`);
- validation by space type.

A space type it doesn't handle, such as a list space, comes back as unknown and is never served.

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
