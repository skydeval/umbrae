# Communities, feeds and audiences

A community is an audience with its own membership: its posts are hidden from the world but open to every member, whether or not they follow each other. It's built to scale to large communities.

A community is a **membership kept by a managing app**, not an account. It has no account, PDS, repo, sign-in or record of its own. The managing app can be a separate service such as the serving app, or a PDS that manages its own communities, such as [Aurora-Locus](https://github.com/dollspace-gay/Aurora-Locus). Umbrae doesn't care which, and it isn't a server: these are the rules every client and app applies.

## The community ref

A community is `{app, key}` (`CommunityRef`, `tools.umbrae.community.defs#communityRef`):
- **`app`:** the managing app's service ref, a DID plus a non-empty fragment (`did#serviceId`). It's where `tools.umbrae.community.*` is served, and the `atproto-proxy` target for calling it.
- **`key`:** unique within that app, `[a-z0-9][a-z0-9-]{0,62}`.

Two refs are the same community exactly when both parts are equal, byte for byte. Another spelling of the same DID is another community: it gets another space key, which the app doesn't know, so it answers nothing.

A community has a name, a description, members (each a **reader** or a **writer**), moderators, an optional labeler, and is listed or unlisted. The operator adds and removes members in the app's admin; join modes (open, request, invite) are optional.

## Each writer's community space

Posts don't live in a shared space. Each writer keeps their records for the community in **their own** space (`community_space(author, &ref)`):
- **Type and authority:** `tools.umbrae.space`, with the author as authority.
- **Key:** `community_skey(ref)`: `c-` and the first 32 characters of base32lower-nopad(sha256(`"tools.umbrae.community\n" + app + "\n" + key`)), 34 characters in all. It's deterministic, a valid record key, never TID-shaped, and different for every app and key.
- **Shape:** `is_community_skey` and `is_community_space` accept exactly `c-` plus 32 characters of `[a-z2-7]`. Validation, which sees no ref, uses the shape. The app, which knows the ref, uses the full check.
- **Policy:** `com.atproto.managedspace.policy {managingApp: app, publishPolicy: true}` (`managed_policy`). `check_community_policy(space, ref, policy)` requires the type, `skey == community_skey(ref)`, a managed policy whose `managingApp` is the ref's app, and a published policy. `check_policy` treats a `c-` key as managed, as it does `everyone`.
- **Only its authority writes in it.** A record by anyone else in a community space is ignored. The PDS always lets the authority write, so the app is never asked about writes.
- **Creating it:** a writer's client creates its space before its first write there, then calls `registerSpace`.

### What the app answers

The PDS asks the app through `com.atproto.managedspace.checkAccess {space, repo?, clientId?}`. "Nothing" means `{read: false, write: false}`.

1. **Service auth:** `iss` must be the space's authority, `aud` the app's own ref, and `lxm` `checkAccess`. Otherwise nothing.
2. **Mapping:** the app maps `(space type, key)` to one of its communities by computing `community_skey` for each. An unknown type or key gets nothing.
3. **The authority** must be a **writer**. Otherwise nothing.
4. **`repo` names an account: nothing, always.** Nobody but the authority reads or writes a community space directly. Members read through the app, and nobody writes into another's space. So `checkAccess` reveals nobody's membership, and no member ever holds a credential that outlives a removal.
5. **`repo` absent** (a sync with no delegation): `read` only when `clientId` is the app's own client ID, and never `write`. The client ID is the URL of the app's OAuth client metadata, which publishes a JWKS; a PDS acting as the managing app needs one too. The PDS verifies the attestation (signature, `aud`, single-use `jti`) before asking, so `clientId` is never a bare claim.

The authority's own reads, writes, `getRecord` and `getBlob` never ask the app, and notification registration rides on the app's own credential request.

### Visibility

These rules are for community spaces only. The `everyone` space is managed too, but keeps the usual rules.
- **The state:** a community space's `SpaceState` carries `community: Some(ref)`, set by the app from its own mapping, and `members` from the app's own table: the authority's role and the viewers' (a reader reads; a writer reads and writes).
- **The policy:** the space shows only if `check_community_policy` passes for that ref. With no ref, nobody but the authority sees it.
- **The space:** shown only while the authority is a writer, cached copies included.
- **A record:** counts only if its author is the authority, and the authority is a writer. In a community space, `is_writer`'s "the authority is always a writer" shortcut doesn't apply.
- **Current role:** visibility follows the current role, so an account's records show again if it becomes a writer again.
- **Fail closed:** with no answer for an account, it isn't a member.
- **Viewers:** the app shows community content to members only, readers and writers, by its own table, at request time.

## Timeline and reading

- **The app:**
  - syncs each writer's space with its own client attestation and no delegation;
  - registers for update notifications with that same request, renewing it with each credential. A refused request withdraws the registration;
  - assembles the community timeline;
  - tries a writer's space when they become a writer, and again on `registerSpace`. `SpaceNotFound` without a `checkAccess` call means the space doesn't exist yet;
  - checks the published policy with `check_community_policy` before it syncs or serves any community space, so a lookalike never enters the timeline.
- **Clients read only through the app.** No member's client can get a credential for another member's space. Its own space it reads as authority.
- **Reading the community's posts, feeds and threads** is the app's own API. Umbrae defines the visibility rules, the placeholder and the lookup by URI, not the view shapes.
- **Notifications** to members (replies, likes, reposts, quotes, mentions) come only from the app, which applies the same rules.

## Removal

When a member is removed, demoted to reader, or leaves:
- **instant at the app:** the next request no longer shows the community to them, or their posts to it. No credential is left to expire, because only the app holds credentials;
- **their own space:** the app stops serving it. Its records stay in their repo, where they can always read them;
- **others' records stay:** replies, likes and reposts by others live in the others' own spaces. Where they point at the removed member's post, the app shows a placeholder;
- **their gates still apply** (see Gates).

## Scale

- **Spaces:** one per writer, on the writer's own PDS.
- **The app:** one credential per writer space, renewed each credential lifetime (10 minutes by default, 1 hour at most), with one notification registration riding on it. Load grows with the number of writers, not readers.
- **`checkAccess`:** called once per credential the app requests, and never for writes. The app should answer from memory.

## Where records go

Every record goes in its author's own space for the community: posts, replies, likes, reposts, quotes, feeds, lists shared with the community, and threadgates and postgates (in the gated post's author's space, as usual).
- **Who writes:** writers only. A reader's space is never synced, so a reader can't post, reply, like or repost.
- **Placement:** `reply_space`, `like_space`, `repost_space` and `quote_space` take the actor. For a subject in a community space, they return the actor's own space for the same community (same type and key). A post that is both a reply and a quote goes where the reply goes, which is the same space. Groups and only-me keep same-space placement.
- **Validation:** in a community space, these may name records in any space of the same type and key: `reply.root` and `reply.parent`, like and repost subjects, a quoted hidden post, `post.feeds`, threadgate `hiddenReplies` and postgate `detachedEmbeddingUris`. Outside community spaces, the same-space rules stand.
- **Matching across spaces:** whenever the app matches two spaces as one community, for a reply, like, repost, quote, feed or gate, it checks both spaces' policies against the ref (`in_same_community`). A lookalike space naming another app fails, and its records are treated as unavailable.
- **Reposts:** `can_view_repost` takes the repost's and the subject's states. Outside communities both must be the same space. In a community, the two spaces must be one community, and both records visible. `can_view_repost_label` takes both states too.
- **Counts:** likes and reposts count only while both the actor's record and the subject are visible.

## Gates and reply rules

- **A threadgate** in the root author's space governs replies wherever they live. The app enforces it at display time, and `hiddenReplies` may name replies in other members' spaces.
- **A gate outlives its post's visibility.** A gate applies while the app holds it, whether or not its post is visible. When the app stops serving a space, it keeps the last copy of each gate it synced from there and goes on applying it, without showing it. A gate stops applying when the app syncs its deletion.
- **Reply rules in a community:** the app holds only community spaces and public data.
  - It evaluates `#mentionRule`, and `#followingRule` against the author's public follows. For a root it no longer serves, it keeps the root's mention list with the gate.
  - `#followerRule`, `#listRule` and hidden follows need spaces the app doesn't read, so in a community space they admit nobody (fail closed). Clients don't offer them for community posts.
- **A postgate's** `disableQuotes` and `detachedEmbeddingUris` apply to quotes in any member's space.

## Feeds

Feeds are author-driven: there's no algorithm.
- **The feed record:** `tools.umbrae.feed {name, description?, avatar?, authors: [did], createdAt}`, with a TID key, in its builder's own community space. There are at most 5000 authors.
- **Sending a post:** a post names the feeds it's sent to in `feeds`, as strong refs: at most 3, each a feed in the same community. A post goes to one space only, so it can't go to a feed and a group at once.
- **Who sees what:** `can_view_feed_post` takes the post's and the feed's states. It shows a post in a feed when both spaces are one community, the post names the feed, its author is on the feed's **current** author list, and both records are visible. Taking someone off the list takes their posts out of the feed. The posts stay in the community.
- **Readers:** the whole community can read any feed in it, through the app. Feeds don't span communities.

## Placeholders

- **A reply's visibility doesn't depend on its parent or root.** A visible reply stays visible when the post it answers isn't.
- **Where a referenced post isn't visible**, as a reply's parent, root or ancestor, or as a quoted post, the app shows `tools.umbrae.community.defs#unavailablePost` in its place (`referenced_post`). A post is unavailable when it was deleted, its author was removed, demoted or left, its space fails `check_community_policy`, or the app doesn't hold it.
- **The placeholder** has no author, no text and no reason. A deleted post and a removed member's post look the same, so removals aren't announced.
- **Raw references:** a reply's own record names its parent's URI, which includes the parent's author DID. The app doesn't pass on a reply's raw `reply` refs, or a quote's raw embed, when the target is unavailable.
- **Blocks** keep the usual handling: a placeholder never replaces a block notice.
- Likes and reposts of an unavailable post aren't shown.

## Records outside the community

A bookmark of a community post, or a subscription to a list shared with a community, lives in its owner's only-me space, as usual. The owner's client reads it there and resolves the post or list **through the community's app**, which applies the rules above for that viewer and answers the record, a placeholder, or not found. The app's read API offers that lookup by URI; its shape is the app's.

The URI shows only the space's `c-` key, so the client finds the app by computing `community_skey` for each ref `listMyCommunities` returns. A post from a community the viewer has left resolves nowhere.

## Membership methods

A community's app serves `tools.umbrae.community.*` at the service its ref's `app` names:

| Method | Params | Who | What |
|---|---|---|---|
| `getCommunity` | `key` | anyone admitted; an unlisted community answers `CommunityNotFound` to non-members | the ref, name, description, join mode, listed, labeler, `appClientId`, and the caller's state, role and moderator flag |
| `listMyCommunities` | `cursor?` | the caller | their communities and roles at this app |
| `join` | `key` | the caller, within the join mode | join, ask to, or accept an invitation |
| `leave` | `key` | the caller | leave, withdraw a request, or decline an invitation |
| `registerSpace` | `key` | writers | the caller's community space exists: the app syncs it at once and registers for notifications |
| `registerProfile` | `key`, `delegationToken` | members | the app syncs the caller's profile space (see below) |
| `listMembers` | `key`, `state?`, `cursor?` | moderators | members, requests, invitations or removals, paged |
| `decide` | `key`, `did`, `accept` | moderators | accept or refuse a request |
| `invite` | `key`, `did`, `role?` | moderators | invite an account; one that already asked becomes a member |
| `remove` | `key`, `did` | moderators | remove a member |

- **Auth:** atproto service auth. The client calls through its PDS with `atproto-proxy` set to the ref's `app`, and the app checks `iss`, `aud` and `lxm`.
- **Roles:** `reader` or `writer`; moderators are named in the app.
- **`registerSpace`** takes no other input. It answers `SpaceNotFound` if the space doesn't exist or fails `check_community_policy`, and is rate-limited per caller.
- **Common errors:** `CommunityNotFound`, `NotAllowed`, `NotAdmitted`.
- **Finding a listed community:** the app shows it on `getCommunity` to anyone it admits, and invite links carry the ref. A directory query is left for later.
- **Same calls everywhere:** a serving app and a PDS that manages its own communities answer the same methods, so clients don't depend on which one runs the community.

## One profile, many audiences

An account has **one** hidden profile, so an edit reaches every audience at once:
- **Where it lives:** `tools.umbrae.profile` at `self` in the owner's profile space, `tools.umbrae.space` with the key `profile` (`profile_space`).
  - The space is created with `group_policy`, whose `allowed_apps` may limit which apps read it.
  - It has **no members**: the owner reads it as authority, and a client never calls `putMembers` on it.
  - Only the profile belongs there. Readers ignore any other record in it.
- **Who reads the record:** the owner, and the apps the owner delegates to: its serving app, and the app of each community audience. Anyone else's delegation is refused as `SpaceNotFound`. An app returns the audience list only to the owner and to moderation.
- **Who sees the profile:** the record lists its `audiences`. An app shows the profile, and serves its blobs, to anyone in one of them it serves (`can_view_profile`, `can_view_profile_blob`):

| Audience | `$type` | Who's in it |
|---|---|---|
| followers | `#followersAudience` | members of the owner's `followers` space |
| a group | `#groupAudience {space}` | members of one of the owner's own groups |
| a community | `#communityAudience {community}` | the community's members, readers and writers, while the owner is still one; served only by the community's app |
| everyone with Umbrae | `#everyoneAudience` | anyone the serving app admits |

- **Rules:**
  - an empty list shows the profile to the owner alone, and deleting the record turns it off;
  - turning an audience off is an edit to the list;
  - blocks cut either way;
  - an audience type a reader doesn't know grants nothing, and a client editing the record writes such entries back unchanged;
  - **a sound profile space:** its policy must pass `check_policy` (members published, not public) and its published member list must be empty. Otherwise the profile shows to nobody, the owner included, so the owner's client notices and repairs it. Members, seen or not, could read the list and get past it.

A profile never lives in only-me, because nobody else can read only-me, the serving app included.

### Community audiences

- **The community's own app serves them.** It alone knows the membership: `AudienceSource::community_member(ref, did)` answers a role from its table, and `None` for a community it doesn't keep, so at any other app a community audience grants nothing. A viewer browsing a community is at that community's app, and reads the profile there with `tools.umbrae.actor.getProfile`.
- **Handing the profile to a community app:**
  - The owner's client calls `registerProfile {key, delegationToken}` at each community app, with a fresh delegation for the profile space. The app syncs the profile space at once, with that token and its own attestation. `key` is a community the caller belongs to at that app. The app answers `ProfileNotFound` if it can't sync (no space, a refused token, or its client not in `allowedApps`), and `NotAllowed` to a non-member.
  - The client does this after every write to the profile space (create, edit, delete), for every community app named in the audiences **before or after** the write, so an app whose community was just dropped, or whose profile was deleted, learns it.
  - A profile space limited by `allowedApps` must list each such app's `appClientId` (from `getCommunity`). The client adds it with `updateSpace` before the first `registerProfile`, and removes it only after the app has synced the edit that dropped its community.
- **The app keeps a profile only for a current member.** It discards its copy when the owner is a member of none of its communities, and holds none until the next `registerProfile`. So the owner's client calls `registerProfile` again after rejoining a community its profile lists. An audience dropped while the owner was out never comes back with them. If the operator re-adds the owner in the admin, the client doesn't know to re-register, so the app holds no profile until the owner's next write (fail closed).
- **Other audiences at a community app:** an `#everyoneAudience` profile shows to anyone the app admits, as at any serving app. Followers and group audiences grant nothing there, since the app holds neither space.
- **Known limit:** a credential reads the whole profile space, so every community app named in the audiences reads the whole record, audience list included: the owner's other communities, on any app and listed or not, and their groups' keys. The owner's client says so before the first community audience is added.

### Reading someone's profile

An app answers two queries, with the same service auth and `atproto-proxy` routing as `tools.umbrae.community.*`:

| Method | Params | Answer |
|---|---|---|
| `tools.umbrae.actor.getProfile` | `actor` | the profile, with its blob refs, without `audiences` |
| `tools.umbrae.actor.getProfileBlob` | `actor`, `cid` | the blob's bytes |

- **Errors:** `ProfileNotFound` is the same answer for no profile, not allowed, and a profile the app doesn't hold. `BlobNotFound` is for a blob, on the same terms.
- **Which app:** the viewer's own serving app, or for a community audience, the community's app. A profile reaches the viewers whose app the owner delegates to. There's no discovery record.
- **Group members:** a group member's client can't read the profile space, so this is the only way it sees the profile.

### Keeping the serving app current

- **No standing access:** a delegation token is single-use and lasts 60 seconds, and a space credential lasts 10 minutes by default. Only the owner's delegation works for the profile space, so an app holds whatever it last synced.
- **After every write** to the profile space (create, edit, delete), the owner's client hands each serving app it uses a fresh delegation for the profile space, plus the followers space and listed groups if the app lacks them, and calls `registerProfile` at each community app (above). The app re-syncs before answering for that profile again.
- **Or the app fetches them itself:** a serving app holding the owner's OAuth session, with read scope on the profile space, fetches delegations on its own.
- **Otherwise:** a write reaches the app only at its next sync. Blocks, account state and audience membership are checked live, so they're never delayed.

### Moderation

Hidden means hidden from the public and outsiders, not from moderators. An app makes a profile available to moderation the same way as hidden posts:
- to a community's moderation service, for each community the profile is currently shown to;
- to its own moderation for every other audience.

Moderators get the profile, its blobs and the audiences it's shown to. They're never members of the profile space.

### Moving from copies

0.7.0 to 0.7.2 kept one copy per audience. Those copies drifted apart, because an edit reached only the copy being edited. They're now legacy.

- **Readers:**
  - Once the owner **has, or has deleted, a profile space**, ignore every copy, whether or not the record exists. A deleted space leaves a tombstone (`authorizeSpaceSync` answers `SpaceDeleted`), so deleting it doesn't bring copies back.
  - Before that, fall back to `profile_for_viewer` over the copies in the owner's followers, group and everyone spaces. A community copy from 0.7 is never shown.
- **Clients:** migration never shows anyone something they couldn't see before.
  1. Take the newest copy's content (by `updatedAt`, else `createdAt`).
  2. List only the audiences whose copy has the same content: every field equal except `createdAt` and `updatedAt`. Carry nothing over from a copy with different content, blobs included.
  3. Create the profile space, write the record, and hand the serving app a delegation.
  4. Show the owner which audiences no longer see a profile, and let them add those audiences explicitly.
  5. Once the owner confirms, delete every copy, retrying until all are gone. A blob a copy shares with the new record stays.
- **Validation:** copies still validate, without `audiences`, and only by the space's authority. A record outside the profile space that lists audiences is refused.

## Shareable lists

- **Where a list lives:** a `tools.umbrae.list` and its `listitem`s may live in any audience space: only-me, a group, the owner's own space for a community, or the owner's everyone space. Its audience is that space's audience. Entries name their list by record key, in the same repo.
- **Subscribing:** a subscription is `tools.umbrae.listSubscription {list, createdAt}` in the subscriber's only-me space. `can_view_list_subscription` shows it only to its owner, and only while they may still see the list. A list shared with a community resolves through the community's app.
  - A subscribed mod list applies like the subscriber's own lists.
  - A subscribed curate list reads as a feed.
- **Named sharing:** `tools.umbrae.listSpace` (named subscribers who can't see each other) stays for private sharing.

## Moderation

- **A community's labeler:** a `tools.umbrae.labeler` space at `self` with a managed policy whose `managingApp` is the community's app. `getCommunity.labeler` is its DID. One labeler space names one app, so a labeler serves that app's communities only.
- **What the app answers for it:** the same service-auth check; the space maps by `(tools.umbrae.labeler, labeler DID)` to the communities that name it; **nothing for an account**, since members get labels through the app, which applies `can_view_label` and `can_view_repost_label`, label audiences included; with `repo` absent, `read` only for the app's own client ID; no `write`, since the labeler is the authority.
- `check_labeler_policy` accepts this policy. The app also checks that the labeler space's `managingApp` is its own.
- **The labeler reads community posts through the app**, never by syncing members' spaces.
- Moderators are named in the app. Takedowns stay with the labeler service.

## Known limits

- The app sees everything in the community, as any serving app does.
- If the app is down, the community can't be read.
- A member can always copy their own posts elsewhere, including into a lookalike space naming another app. That leaks nothing that isn't theirs.
- A PDS can send `checkAccess` with no account and a claimed client ID for a space its own account holds, and so learn whether that account is a writer. It already sees that account's writes there.
- When a member is removed, all their posts turn into placeholders at once, which hints at a removal more than one deletion does.
- Others' replies to a removed member's post stay under a placeholder, and each names the parent's URI. Only the app sees it, and it doesn't pass it on.
