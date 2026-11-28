# Private accounts

Turning on "private account" makes the whole account permissioned, old posts included. It's a real boundary enforced by spaces, not just "require sign-in".

- **What moves:** posts, reposts and likes, with each post's threadgate and postgate.
- **What stays public:** follows, blocks and lists.
- **Who sees:** people who pass the owner's rules, checked live like a block, so a rule change applies to every post at once.
- **"Followers" means approved followers:** people request and the owner approves. A plain public follow grants nothing.
- **Reversible:** turning it off moves everything back to public.

There's no Umbrae service. The records live in the owner's PDS, and a serving app (prism, or a PDS such as Aurora-Locus) is the private space's only reader.

## The private space

One per account: `private_space(owner)`, a space of type **`tools.umbrae.private`** at key **`self`**, with the owner as authority.

- **Policy:** `managed_policy(app)`, a published `com.atproto.managedspace.policy` naming the owner's serving app. The app checks it with `check_private_policy(space, app, policy)` before syncing or serving.
- **Collections:** `app.bsky.feed.post`, `app.bsky.feed.repost`, `app.bsky.feed.like`, `app.bsky.feed.threadgate`, `app.bsky.feed.postgate`, `tools.umbrae.private.rules` and `tools.umbrae.private.approval`. The posts, reposts, likes and gates are native, so a move is an exact copy and clients reuse their renderers. `PRIVATE_COLLECTIONS` lists the first six; approvals are `PRIVATE_APPROVAL`, apart, since no public alias names one.
- **The type's lexicon** (`type: space`, `key: literal:self`) is published with the others. A PDS resolves it when a client asks for a `space:tools.umbrae.private` scope, and the grant fails if it can't.
- **Readers:** the serving app alone, as in communities. Its `checkAccess` answers:
  - nothing unless the service auth's `iss` is the space authority, `aud` the app and `lxm` `checkAccess`, and the space is a `tools.umbrae.private` at `self` whose owner has registered there;
  - with `repo` absent: `read` for the app's own attested client only;
  - with `repo` set: `read` never, and `write` only while that account passes the owner's rules. The PDS asks only when the account's PDS reports a write into the space, and `write` only adds it to the writer set the app syncs, so it grants nothing else.
- **The owner** reads as authority: its session reads its own repo, and a credential from its own delegation reads the whole space. Nobody else's delegation gets a credential.

### Validation

`validate_private_record(uri, value)` checks what the rules use. The PDS validates the native schemas on ordinary writes.

- **Collections:** one of the six or an approval, with `$type` matching. Anything else (the PDS's policy record) is the caller's.
- **Keys:** TIDs, except the gates, which sit at their post's key, and `rules`, at `self`.
- **The owner's records** may name public records by `at://` (moved replies, likes, reposts and quotes of public posts), and records in this space by either form.
- **Another account's record** counts only if it acts on the owner's thread:
  - a reply whose root is the owner's post and whose parent is in this space;
  - a like, repost or quote of a record in this space;
  - a postgate on its own post here.

  A top-level post, or a threadgate, by anyone else doesn't count.
- **`rules`:** the owner's only.
- **Approvals:** the owner's only, at a TID, with `subject` a DID other than the owner's and a `createdAt` (`PrivateRecord::Approval`). An approval by anyone else doesn't count, even though a writer who passes the rules can put one there and the app's sync will hold it.
- **References:** a record in this space is named by its `at:space` URI, or, for the owner's records, by their public `at://` alias. A space URI of any other space, anywhere in the record, doesn't count.

`umbrae-sync` checks the type with it and returns `Checked::Private`.

## The rules

`tools.umbrae.private.rules` at `self` in the private space, by the owner. Only the owner and the app read it.

```
{ allow: [ #approvedFollowers | #following | #mutuals | #list {list} ], createdAt, updatedAt?, approvalsInSpace? }
```

| Rule | Who passes |
|---|---|
| `#approvedFollowers` | accounts the owner approved: at least one of the owner's approvals names them |
| `#following` | accounts the owner follows publicly |
| `#mutuals` | accounts that follow each other publicly with the owner |
| `#list` | members of one of the owner's own public `app.bsky.graph.list`s; any other list grants nothing |

`can_view_private(viewer, owner, rules, inputs, ctx)` admits the owner, or an account that:
- passes **any** rule;
- has no block with the owner either way: blocks, and list blocks (`app.bsky.graph.listblock`) either one subscribes to;
- is active.

It fails closed:
- an empty `allow` means the owner alone;
- an unknown rule type grants nothing;
- with no rules record, `#approvedFollowers` alone applies;
- an input the app can't answer right now (`Tri::Unknown`) grants nothing.

The app answers each input through `PrivateInputs`:

| Input | Source |
|---|---|
| the rules | the private space, which the app syncs with its own attestation and registers notifications for |
| approved followers | the owner's approvals in the private space, from the same sync (`approved_followers`) |
| the owner's follows, lists and blocks | the owner's public repo |
| the viewer's follows, blocks and list blocks | an index the app keeps, or a public AppView |
| active | the viewer's account status |

### Approvals

`tools.umbrae.private.approval` sits in the owner's private space, `{subject: did, createdAt}` at a TID key. The key isn't the DID, since a `did:web` with a port holds `%`, which a record key can't.

- **Approving** a request creates an approval; **removing** a follower deletes their approvals; **refusing** dismisses the request. Several approvals of one account are harmless: it stays approved until the last goes.
- **`approved_followers(space, records)`** gives the set: the subjects of the owner's valid approvals. Others' approvals, invalid ones and records of any other space count for nothing.
- **Written like the rules,** with `validate` unset (or `false`). A PDS that doesn't know the lexicon refuses `validate: true`.
- **Live without the owner:** the app syncs the private space with its own attestation and holds a notification registration, renewing both itself. An approval or a removal reaches it at the next notification, whether or not the owner is online. Notifications are best-effort; the app resyncs when it renews, before 10 minutes, so a lost one delays a change by at most that. No followers-space grant or delegation is involved.
- **Private:** only the owner and the app read them, and the read surface never serves them, so approved followers don't see each other.
- A blocked, list-blocked or inactive account sees nothing whatever its approvals say, since blocks are checked first. Clients needn't delete approvals on a block.
- **Moderators** are never approvals.

### Accounts made private before approvals

Under 0.8.1, `#approvedFollowers` read the owner's followers space. The rules' `approvalsInSpace` marks the change:
- **The serving app upgrades first.** A client copies and switches to approvals only once its serving app reads them. An old app reads the followers space, so a removal made only in approvals would leave the follower admitted there.
- **Without the marker,** the app may also count followers-space members it holds from a sync less than 24 hours old, and the owner's client runs the copy once at its next start. It re-authorizes first, since the old grant lacks the approval collection.
- **The copy:** for each member of the followers space with no approval, create one; then rewrite the rules with `approvalsInSpace: true` in the same `applyWrites` as the last batch (at most 199 approvals beside it). Interrupted, it runs again safely. Finished, it never runs again, so a follower removed later isn't approved again from the followers space, which the copy leaves as it is.
- **With the marker** (`Rules::approvals_in_space`), approved followers are the approvals only. Accounts going private now write it in their first rules record. Absent and `false` read the same; anything else refuses the record, which then shows the account to the owner alone.

The followers space stays for the hidden profile's `#followersAudience` and the followers audience of hidden posts. It's a separate list from the approvals now.

## Interactions

- **Placement:** a reply, like, repost or quote of a record in a private space goes into **that** space, in the actor's own repo, whoever the actor is (`reply_space`, `like_space`, `repost_space`, `quote_space`). Anything else a private account writes goes into **its own** private space: its posts, and its interactions on public subjects (`private_actor_space`).
- **A private account acting in another owner's space** is shown under that owner's rules, not its own. Its client says so.
- **A quote that is also a reply** goes where both point. If they point into different private spaces, the client refuses it.
- **Shown** only to viewers who pass the rules, and only while the actor passes too (`interaction_counts`). The PDS keeps listing an actor who lost access as a writer, and the app's credential still reads their repo, so the app filters. The owner may also call `removeWriter`.
- **Replies from outside the boundary:** a public reply naming a private post, in either form, can't be prevented. The app shows it only alongside the post, to allowed viewers; to everyone else its parent is a placeholder.
- **Old public interactions,** made before the move, stay in the actors' public repos. The app resolves them through the alias.
- **Notifications** about in-boundary interactions come from the owner's app.

## Addresses

A moved record keeps its collection and rkey. `private_uri` maps `at://{did}/{coll}/{rkey}` to `at:space/{did}/tools.umbrae.private/self/{did}/{coll}/{rkey}`, and `public_uri` maps back.

- Any reference to a private owner's record may use either form, in public records and in the space alike. The app maps both to wherever the record lives now.
- Moved records keep their `at://` references; new writes name the record's current location.
- The app matches the owner's records by URI and ignores a CID mismatch, since a move may rewrite a record.
- A lookup by URI answers the same for "doesn't exist" and "not allowed".

## Moving

### Going private

1. **The gate:** add the self-label `!no-unauthenticated` to `app.bsky.actor.profile`, make the profile a stub (without `pinnedPost`), and write `tools.umbrae.private.declaration`.
2. Create the private space with the policy, and write `rules` with `approvalsInSpace: true`.
3. Call `tools.umbrae.private.register` at the serving app.
4. **Move,** in batches of up to 200 records. For each batch:
   - look up each record's space copy: none, **create** it with the same rkey and value; the same CID, no write; a different CID, **update** it;
   - write with `validate: false`, since the PDS already accepted these records;
   - check the space write succeeded, **then** delete the public copies with `com.atproto.repo.applyWrites`.
5. New records go straight to the private space.

Notes on the move:
- **Blobs** need no upload: the account holds them and the space write links them. A blob stays public until the last public record using it moves.
- **Legacy blob refs** (`{cid, mimeType}`) are refused even with validation off. The mover rewrites each to `{$type: blob, ref, mimeType, size}`, with the size from `sync.getBlob`'s `content-length`.
- **A record still refused** is left out and listed to the owner, who may delete it. It's never left public silently.
- **Order:** posts first, newest first, each with its threadgate and postgate in the same batch; then reposts, then likes.
- **Pacing:** a space create costs 3 of the PDS's 5000 points an hour and 35000 a day, so about 1,666 records an hour and 11,666 a day. The mover follows the rate-limit headers, backs off on 429, leaves room for the owner's own writes, and shows the expected time and progress. Until a post moves, the gate hides it only from signed-out viewers.
- **Resumable:** progress is read from both sides, so a stopped move resumes, and running it twice is harmless. A repeated create would fail the whole batch, which is why each copy is looked up first.
- **Deletes during the move** remove both copies.

### Going public

1. Move the owner's records back by the same steps, sides swapped:
   - **what stays** (`stays_private`): the rules and approvals, every record by another account, and any owner's record that names a record that stays, applied until nothing more changes. The client works this out before moving anything, so no public record names, or reveals, a record that stays inside;
   - **everything else** goes public, with the owner's own `at:space` references rewritten to the public form (`going_public_value`).
2. Remove the gate and the declaration, and restore the full public profile if the owner wants it.
3. **Keep the space, the rules and the approvals.** The app goes on serving in-boundary interactions, and the records kept there, to whoever passes the rules. Nobody else's words become public.
4. Deleting the space is a separate, explicit act. The client warns that it drops every in-boundary interaction for good.

### Native move

A PDS may serve `tools.umbrae.private.move {direction: "private"|"public"}` for the authenticated account, doing the move server-side by the same rules and without the rate limits. Clients try it first and fall back to batches on `MethodNotImplemented`. Aurora-Locus is expected to serve it.

## The serving app

- **`tools.umbrae.private.register`** (the owner): the app records that the account is private here and syncs the private space with its own attestation, registering for notifications. That sync carries the rules and the approvals; the app renews it itself, so it needs nothing more from the owner.
- **`tools.umbrae.private.unregister`** (the owner): the app discards everything it holds for the account and stops answering for its space.
- **With no current private-space state,** `#approvedFollowers` admits nobody.
- **Follow requests:** `requestFollow {actor}` (refused for blocked accounts), `withdrawRequest {actor}`, `listRequests` (the owner only) and `getAccess {actor}`, which returns `owner`, `allowed`, `requested` or `none`. The owner approves with an approval record and refuses by dismissing. The app drops a request once it sees an approval.
- **The profile:** the private space's app is the owner's serving app, which already reads the profile space. If an owner ever splits the two, the profile-delegation grant applies, and `allowedApps` must list the app.

### Changing serving app

1. `updateSpace` the private space to a policy naming the new app. Until step 2, nobody but the owner reads.
2. Register at the new app, and add its client ID to a profile space limited by `allowedApps`. The approvals are already in the space, so the new app reads them with no further grant. The new app retries a `SpaceNotFound` once, briefly, in case the policy write and its sync race.
3. Rewrite the declaration.
4. Call `unregister` at the old app. An old app that has gone away fails closed anyway, since the policy no longer names it.

### Reading

Called at the serving app with `atproto-proxy` and service auth (`iss` the viewer, `lxm` the method). Each applies the rules for the viewer, and shows `tools.umbrae.community.defs#unavailablePost` where a referenced post isn't visible.

| Method | Params | Returns |
|---|---|---|
| `tools.umbrae.private.listRecords` | `actor`, `collection`, `cursor?` | the owner's records in one collection, newest first |
| `tools.umbrae.private.getRecords` | `uris` (either form, up to 25) | the records, or `notFound` for each one missing or not allowed |
| `tools.umbrae.private.listInteractions` | `subject`, `collection?`, `cursor?` | replies, likes, reposts and quotes of one record, in-boundary and public |
| `tools.umbrae.private.getBlob` | `actor`, `cid` | a blob that a record the viewer may see refers to |

Records come raw, as `{uri, cid, author, value}`, for the viewer's own app or client to render. The surface serves the five native collections only. Rules and approvals go to the owner alone, through its own reads, and `getRecords` answers `notFound` for them.

## Public face

- **Declaration:** `tools.umbrae.private.declaration` at `self` in the owner's public repo, `{servingApp, createdAt}`. Others' clients learn the account is private and where to call the methods above.
- **Public profile:** a stub the owner chooses (a display name and avatar, or nothing), plus `!no-unauthenticated`.
- **The full profile** is the one hidden profile, with the audience `#privateAudience`: whoever passes the rules. Only the private space's serving app serves it (`AudienceSource::private_viewer`, false by default).
- **What the public sees:** the stub, the declaration, the public follows, blocks and lists, and no posts.

## Moderation

The serving app's moderators may see private accounts through its moderation paths. They don't count as passing the rules: they get no `checkAccess` write, and never show as followers, in `getAccess` or in requests.

### Labels and takedowns

The private space isn't a `tools.umbrae.space`, so the rules for spaces in general apply (see [Takedowns](overview.md#takedowns)):
- **The owner's `!takedown`** on a record here, an interactor's reply for instance, hides it where the serving app's spaces configuration honors it for `tools.umbrae.private`, which it does by default (`apply_takedowns`).
- **In-space labels** count only from accounts the app lists in `SpaceState.label_writers`, the writer set minus the owner, and only where the reader trusts them as labelers. Interactors are in the writer set too, so trust is what decides. Labels on the native collections are ordinary in-space labels; `neg: true` and a subject outside the space never apply.
- **After a `removeWriter`,** the app keeps a label writer's last-synced labels, as in communities, and `RecordsTakendown` is handled as for any space ([Clients and apps](clients-and-apps.md#keeping-a-copy-honest)).

## Known limits

- Copies public services already hold aren't recalled: AppView caches, image and video CDNs, firehose consumers and archives.
- Until a post moves, signed-in viewers elsewhere can still see it.
- After going public, in-boundary interactions still show only under the rules, so the public thread is thinner than the owner's view of it.
- A follower removed from an account not yet migrated to approvals may keep access for up to 24 hours, while the app still counts its held copy of the followers space.
- An older client that rewrites the rules may drop `approvalsInSpace`. Keep every client up to date.

## Scopes

| Use | Scope |
|---|---|
| the owner's private space | `space:tools.umbrae.private?collection=app.bsky.feed.post&collection=app.bsky.feed.repost&collection=app.bsky.feed.like&collection=app.bsky.feed.threadgate&collection=app.bsky.feed.postgate&collection=tools.umbrae.private.rules&collection=tools.umbrae.private.approval&manage=create&manage=update&manage=delete` |
| acting in others' private spaces | `space:tools.umbrae.private?authority=*&collection=app.bsky.feed.post&collection=app.bsky.feed.repost&collection=app.bsky.feed.like&collection=app.bsky.feed.postgate` |

The space type's lexicon, with the approval collection, is published before any client asks for the owner's scope. The serving app needs no followers-space grant for private accounts.
