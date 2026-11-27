# Private accounts, profiles, follows and gates

## Private accounts

A private account's **approved followers** are a `tools.umbrae.space` space with the key **`followers`**. It works exactly like a group:
- the group policy (`followers_space`, `check_policy`);
- followers are members with `read` and `write`;
- the member list is published, so approved followers see each other;
- every post, reply, like, repost and quote rule applies unchanged.

Follow requests are the app's business and never public. Approving a request is `putMembers`, and removing a follower is `removeMembers`.

## Hidden profile

`tools.umbrae.profile` is one record at `self` in the owner's profile space, listing the audiences that see it (see [One profile, many audiences](communities.md#one-profile-many-audiences)). Approved followers see it when `followers` is listed. Fields: `{displayName?, description?, pronouns?, pronounSets?, pronounDisplayMode?, website?, links?, avatar?, avatarAlt?, banner?, bannerAlt?, audiences, createdAt, updatedAt?}`, with `app.bsky.actor.profile`'s limits. `website` and every link `url` are https URLs. There are at most 10 links, each with an optional 30-grapheme `title` and an `icon` image. The pronoun sets follow `app.nearhorizon.actor.pronouns`.

The avatar, banner and link icons are blobs referenced only from the profile space:
- the owner fetches them with space `getBlob` and its own session; the serving app, with its credential for the profile space. Both check the CID;
- everyone else gets them through `tools.umbrae.actor.getProfileBlob` from their serving app, which serves a blob only to someone who may see the profile and only if the profile refers to it;
- the public `sync.getBlob` doesn't serve them.

## Hidden follows

`tools.umbrae.follow {subject: did, createdAt}` lives in the follower's own only-me space, with a TID key. It feeds a hidden Following timeline. It's separate from approval into a private account: membership is the access, and the follow is the follower's own list.

## Gates

Both gates are written by a post's author, in the post's space, at the post's own record key. That's the same placement Bluesky uses.

- **`tools.umbrae.threadgate`:**
  - `allow` rules: `#mentionRule`, `#followingRule` (the author's public or hidden follows), `#followerRule` (approved followers) and `#listRule` (one of the author's own personal lists).
  - An absent `allow` means everyone who can see the post may reply; an empty one means nobody may.
  - `hiddenReplies` holds up to 300 replies, hidden for everyone but their authors.
- **`tools.umbrae.postgate`:** `detachedEmbeddingUris` lists quotes shown without the post, and `#disableRule` turns quoting off.
- **Hidden URIs:** a gate names hidden records only as posts in its own space.

Gates are enforced where posts are shown. Every member writes into their own repo, so nothing can stop a reply from being written.

Enforcing in views has a side effect: the replies that do show reveal who a rule allows. A `#followingRule` hints at the author's hidden follows. A `#followerRule` shows group members who are approved followers. A `#listRule` shows who's on the list.
