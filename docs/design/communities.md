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

## One profile per audience

A hidden profile has one copy per audience, each at `self`:

| Audience | Space | Written by |
|---|---|---|
| a group | the group's space | the owner |
| approved followers | the owner's `followers` space | the owner |
| a community | the community space | the member, in their own repo |
| everyone with Umbrae | the owner's `everyone` space (`everyone_space`), a managedspace whose app answers read for any admitted account and write for the owner | the owner |

A profile never lives in only-me, because nobody else can read only-me, the managing app included. `profile_for_viewer` picks the copy a viewer sees:
- the narrowest audience they may see wins, in the order group, followers, community, everyone;
- ties go to the latest `updatedAt` (or `createdAt`).

A different face per group comes out of this directly.

## Shareable lists

- **Where a list lives:** a `tools.umbrae.list` and its `listitem`s may live in any audience space: only-me, a group, a community, or the owner's everyone space. Its audience is that space's audience. Entries name their list by record key, in the same repo.
- **Subscribing:** a subscription is `tools.umbrae.listSubscription {list, createdAt}` in the subscriber's only-me space. `can_view_list_subscription` shows it only to its owner, and only while they may still see the list.
  - A subscribed mod list applies like the subscriber's own lists.
  - A subscribed curate list reads as a feed.
- **Named sharing:** `tools.umbrae.listSpace` (named subscribers who can't see each other) stays for private sharing.

## Moderation

A community's labeler may use a managed labeler space too. `check_labeler_policy` accepts a published `managedspace` at `self`. Its managing app must answer read only, and write only for the labeler.
