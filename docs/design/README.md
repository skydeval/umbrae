# Umbrae design

How Umbrae uses [atproto spaces](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data), and the rules every client, PDS and serving app follows. The code in `umbrae/` is the reference for these rules, and these docs explain them.

| Doc | What |
|---|---|
| [Overview](overview.md) | the model, who does what, and what spaces do and don't protect |
| [Hidden posts](hidden-posts.md) | groups and only-me, posts, replies, likes, reposts, quotes, bookmarks; where each goes and who sees it |
| [Private labelers](labelers.md) | hidden labels, labels on hidden posts, restricted labels, label keys |
| [Lists and exemptions](lists.md) | personal and shared hidden lists, and exemptions |
| [Private accounts, profiles, follows and gates](accounts.md) | the followers audience, the hidden profile, hidden follows, reply and quote gates |
| [Communities, feeds and audiences](communities.md) | managed community spaces, feeds, one profile per audience, shareable lists and subscriptions |
| [Clients and apps](clients-and-apps.md) | OAuth scopes, reading and syncing spaces, lexicon resolution, versioning |

Spaces are still in development upstream. Where the spec changes, Umbrae follows it.
