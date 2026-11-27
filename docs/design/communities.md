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
- **Reader state:** a reader's `SpaceState` takes its `members` from the managing app's answers. It needs only the accounts in question, such as the viewer and the authors on screen, not the whole membership.

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
- **Where it lives:** `tools.umbrae.profile` at `self` in the owner's profile space, `tools.umbrae.space` with the key `profile` (`profile_space`). The space takes the group policy and has **no members**.
- **Who reads the record:** the owner, and the serving app the owner delegates to. Nobody else can read the space, so nobody else sees the audience list, and a serving app never returns it to anyone but the owner.
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
  - an audience type a reader doesn't know grants nothing;
  - a profile space with any members shows the profile to nobody, because members could read the list and get past it.
- **Without a serving app:** a group member's client can't read the profile space, so it asks the serving app for the profile.

A profile never lives in only-me, because nobody else can read only-me, the serving app included.

### Moving from copies

0.7.0 to 0.7.2 kept one copy per audience. Those copies drifted apart, because an edit reached only the copy being edited. They're now legacy:
- **Readers:** use the profile-space record when there is one, and ignore the copies. Until then, fall back to `profile_for_viewer` over the copies.
- **Clients:** on the next save, write the one record from the newest copy, keep any avatar or banner (and its alt text) that only an older copy has, list the audiences the copies were in, then delete the copies.
- **Validation:** copies still validate, without `audiences`. A record outside the profile space that lists audiences is refused.

## Shareable lists

- **Where a list lives:** a `tools.umbrae.list` and its `listitem`s may live in any audience space: only-me, a group, a community, or the owner's everyone space. Its audience is that space's audience. Entries name their list by record key, in the same repo.
- **Subscribing:** a subscription is `tools.umbrae.listSubscription {list, createdAt}` in the subscriber's only-me space. `can_view_list_subscription` shows it only to its owner, and only while they may still see the list.
  - A subscribed mod list applies like the subscriber's own lists.
  - A subscribed curate list reads as a feed.
- **Named sharing:** `tools.umbrae.listSpace` (named subscribers who can't see each other) stays for private sharing.

## Moderation

A community's labeler may use a managed labeler space too. `check_labeler_policy` accepts a published `managedspace` at `self`. Its managing app must answer read only, and write only for the labeler.
