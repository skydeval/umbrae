# Communities, feeds and audiences

A community is an audience with its own identity and membership: its posts are hidden from the world but open to every member, whether or not they follow each other. It's built to scale to large communities.

## The community space

A community is a `tools.umbrae.space` space with the key `community` (`community_space`):
- **Authority:** the community's own atproto account. Its operator holds it.
- **Policy:** `com.atproto.managedspace.policy`, with `publishPolicy: true` (`managed_policy`, accepted by `check_policy`).
- **Membership:** held by the managing app named in the policy. The PDS asks it through `com.atproto.managedspace.checkAccess` who may read (whether to issue a credential) and who may write (whether to track them as a writer).
  - The managing app can be a separate service such as the serving app, or a PDS that manages its own communities, such as [Aurora-Locus](https://github.com/dollspace-gay/Aurora-Locus). Umbrae doesn't care which.
  - No member records exist anywhere.
- **Failing closed:** if the managing app doesn't answer, the PDS refuses. It never grants access by default.

Every rule for groups applies unchanged inside a community: posts, replies, likes, reposts, quotes, gates and labels on hidden posts. Each member writes into their own repo in the community space, so their posts move with their account.

## Finding a community's managing app

A space's policy is readable only with a space credential, so someone who isn't a member yet can't read it. Instead:
- **Listed communities:** the community account writes `tools.umbrae.community.declaration` at `self` in its **public** repo, with `{managingApp, name?, description?, avatar?, createdAt}`. Anyone reads it with `com.atproto.repo.getRecord`, then calls `tools.umbrae.community.*` through their PDS with `atproto-proxy: <managingApp>`. It says the community exists and who manages it, never who its members are or what they post.
- **Unlisted communities:** they have no declaration. The invite link carries the managing app.
- **Trust:** only the community account can write its declaration. A managing app answers `CommunityNotFound` for a community whose space policy doesn't name it, so a wrong pointer fails closed.

## Membership methods

A community's managing app serves `tools.umbrae.community.*` at the `#umbrae_app` endpoint its space policy names:

| Method | Kind | Who | What |
|---|---|---|---|
| `getCommunity` | query | anyone admitted | name, description, join mode (`open`, `request` or `invite`), and the caller's state and role |
| `join` | procedure | the caller | join, ask to, or accept an invitation |
| `leave` | procedure | the caller | leave, withdraw a request, or decline an invitation |
| `listMembers` | query | moderators | members, requests, invitations or removals, paged |
| `decide` | procedure | moderators | accept or refuse a request |
| `invite` | procedure | moderators | invite an account; one that already asked becomes a member |
| `remove` | procedure | moderators | end access at once and remove them as a writer |

- **Auth:** atproto service auth. The client calls through its PDS with `atproto-proxy` set to the policy's `managingApp`, and the managing app checks `iss`, `aud` and `lxm`.
- **Moderators:** the community account, plus the accounts the managing app names.
- **Common errors:** `CommunityNotFound`, `NotAllowed`, `NotAdmitted`.
- **Same calls everywhere:** a serving app and a PDS that manages its own communities answer the same methods, so clients don't depend on which one runs the community.

## Scale

- **Membership:** the managing app keeps it, so no member list sits in a repo.
- **Sync:** the serving app syncs each writer's repo once and serves members from its own copy. Sync load grows with the number of apps syncing, not with the number of readers.
- **Reader state:** a reader's `SpaceState` takes its `members` from the managing app's answers. It needs only the accounts in question, such as the viewer, the authors on screen and the owner of a profile shown there, not the whole membership.

## Removal

When the managing app stops answering `write` for someone, and the community calls `com.atproto.space.removeWriter`:
- they're no longer a writer, so their posts, earlier ones included, leave the community;
- their records stay in their own repo, where they can always read them;
- the space is fixed in each record's URI, so they can't move those posts to another audience.

## Feeds

Feeds are author-driven: there's no algorithm.
- **The feed record:** `tools.umbrae.feed {name, description?, avatar?, authors: [did], createdAt}`, with a TID key. Any member writes it into their own repo in the community space. There are at most 5000 authors.
- **Sending a post:** a post names the feeds it's sent to in `feeds`, as strong refs. There are at most 3, and each must be a feed in the post's own community space. A post goes to one space only, so it can't go to a feed and a group at once.
- **Who sees what:** `can_view_feed_post` shows a post in a feed when it names the feed, its author is on the feed's **current** author list, and the viewer may see both. Taking someone off the list takes their posts out of the feed. The posts stay in the community.
- **Readers:** the whole community can read any feed in it. Feeds don't span communities.

## One profile, many audiences

An account has **one** hidden profile, so an edit reaches every audience at once:
- **Where it lives:** `tools.umbrae.profile` at `self` in the owner's profile space, `tools.umbrae.space` with the key `profile` (`profile_space`).
  - The space is created with `group_policy`, whose `allowed_apps` may limit which serving apps read it.
  - It has **no members**: the owner reads it as authority, and a client never calls `putMembers` on it.
  - Only the profile belongs there. Readers ignore any other record in it.
- **Who reads the record:** the owner, and the serving apps the owner delegates to. Anyone else's delegation is refused as `SpaceNotFound`. So nobody else sees the audience list, and a serving app returns it only to the owner and to moderation.
- **Who sees the profile:** the record lists its `audiences`. The serving app shows the profile, and serves its blobs, to anyone in one of them (`can_view_profile`, `can_view_profile_blob`):

| Audience | `$type` | Who's in it |
|---|---|---|
| followers | `#followersAudience` | members of the owner's `followers` space |
| a group | `#groupAudience {space}` | members of one of the owner's own groups |
| a community | `#communityAudience {space}` | members of the community, while the owner is still one |
| everyone with Umbrae | `#everyoneAudience` | anyone the serving app admits |

- **Rules:**
  - an empty list shows the profile to the owner alone, and deleting the record turns it off;
  - turning an audience off is an edit to the list;
  - blocks cut either way;
  - an audience type a reader doesn't know grants nothing, and a client editing the record writes such entries back unchanged;
  - a community audience needs the managing app's answer for the owner as well as the viewer;
  - **a sound profile space:** its policy must pass `check_policy` (members published, not public) and its published member list must be empty. Otherwise the profile shows to nobody, the owner included, so the owner's client notices and repairs it. Members, seen or not, could read the list and get past it.

A profile never lives in only-me, because nobody else can read only-me, the serving app included.

### Reading someone's profile

A serving app answers two queries, with the same service auth and `atproto-proxy` routing as `tools.umbrae.community.*`:

| Method | Params | Answer |
|---|---|---|
| `tools.umbrae.actor.getProfile` | `actor` | the profile, with its blob refs, without `audiences` |
| `tools.umbrae.actor.getProfileBlob` | `actor`, `cid` | the blob's bytes |

- **Errors:** `ProfileNotFound` is the same answer for no profile, not allowed, and a profile the app doesn't hold. `BlobNotFound` is for a blob, on the same terms.
- **Which app:** the viewer's own serving app. A profile reaches the viewers whose app the owner delegates to. There's no discovery record.
- **Group members:** a group member's client can't read the profile space, so this is the only way it sees the profile.

### Keeping the serving app current

- **No standing access:** a delegation token is single-use and lasts 60 seconds, and a space credential lasts 10 minutes by default. Only the owner's delegation works for the profile space, so a serving app holds whatever it last synced.
- **After every write** to the profile space (create, edit, delete), the owner's client hands each serving app it uses a fresh delegation for the profile space, plus the followers space and listed groups if the app lacks them. The app re-syncs before answering for that profile again.
- **Or the app fetches them itself:** a serving app holding the owner's OAuth session, with read scope on the profile space, fetches delegations on its own.
- **Otherwise:** a write reaches the app only at its next sync. Blocks, account state and audience membership are checked live, so they're never delayed.

### Moderation

Hidden means hidden from the public and outsiders, not from moderators. The serving app makes a profile available to moderation the same way as hidden posts:
- to a community's moderation service, for each community the profile is currently shown to;
- to its own moderation for every other audience.

Moderators get the profile, its blobs and the audiences it's shown to. They're never members of the profile space.

### Moving from copies

0.7.0 to 0.7.2 kept one copy per audience. Those copies drifted apart, because an edit reached only the copy being edited. They're now legacy.

- **Readers:**
  - Once the owner **has, or has deleted, a profile space**, ignore every copy, whether or not the record exists. A deleted space leaves a tombstone (`authorizeSpaceSync` answers `SpaceDeleted`), so deleting it doesn't bring copies back.
  - Before that, fall back to `profile_for_viewer` over the copies.
- **Clients:** migration never shows anyone something they couldn't see before.
  1. Take the newest copy's content (by `updatedAt`, else `createdAt`).
  2. List only the audiences whose copy has the same content: every field equal except `createdAt` and `updatedAt`. Carry nothing over from a copy with different content, blobs included.
  3. Create the profile space, write the record, and hand the serving app a delegation.
  4. Show the owner which audiences no longer see a profile, and let them add those audiences explicitly.
  5. Once the owner confirms, delete every copy, retrying until all are gone. A blob a copy shares with the new record stays.
- **Validation:** copies still validate, without `audiences`. A record outside the profile space that lists audiences is refused.

## Shareable lists

- **Where a list lives:** a `tools.umbrae.list` and its `listitem`s may live in any audience space: only-me, a group, a community, or the owner's everyone space. Its audience is that space's audience. Entries name their list by record key, in the same repo.
- **Subscribing:** a subscription is `tools.umbrae.listSubscription {list, createdAt}` in the subscriber's only-me space. `can_view_list_subscription` shows it only to its owner, and only while they may still see the list.
  - A subscribed mod list applies like the subscriber's own lists.
  - A subscribed curate list reads as a feed.
- **Named sharing:** `tools.umbrae.listSpace` (named subscribers who can't see each other) stays for private sharing.

## Moderation

A community's labeler may use a managed labeler space too. `check_labeler_policy` accepts a published `managedspace` at `self`. Its managing app must answer read only, and write only for the labeler.
