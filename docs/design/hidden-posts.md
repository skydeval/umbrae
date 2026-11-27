# Hidden posts

## Spaces

Space type `tools.umbrae.space`. The author's DID is the authority.

| Audience | skey | Policy |
|---|---|---|
| a group | a TID | memberspace: not public, policy published, member list published |
| only me | `self` | personalspace: only the authority |

Other audiences have their own keys: a private account's `followers`, the `everyone` space, the `profile` space, and each writer's own space for a community, keyed `c-` plus 32 base32 characters (see [Communities](communities.md)).

- **Groups:**
  - The group's name is a `tools.umbrae.group` record at rkey `self`, written by the authority.
  - Members are added with `putMembers` and get `read` and `write`.
  - The member list is published to members only, so a serving app can learn who may see the posts. Members see who else is in their own groups, never the members of groups they aren't in.
- **Policy checks:** `check_policy` refuses any group that is publicly readable or writable, or that doesn't publish its policy and members. Clients check before writing, and readers check before showing.

## Records

| NSID | Key | What | Where |
|---|---|---|---|
| `tools.umbrae.post` | TID | a post: the fields of `app.bsky.feed.post` | the chosen space |
| `tools.umbrae.like` | TID | `{subject: strongRef, createdAt}` | the liked post's space |
| `tools.umbrae.repost` | TID | `{subject: strongRef, createdAt}` | the reposted post's space |
| `tools.umbrae.group` | `self` | `{name, description?, createdAt}` | a group, by its authority |
| `tools.umbrae.bookmark` | TID | `{subject: strongRef, createdAt}` | the owner's only-me space |

Each person writes into **their own repo** in the space. A member's reply, like or repost lives in their repo inside the author's space.

## Placement

| Record | Goes into |
|---|---|
| a reply to a hidden post | the parent's space (`reply_space`) |
| a hidden reply to a public post | whichever space the author picks |
| a like | the liked post's space (`like_space`) |
| a repost | the reposted post's space (`repost_space`) |
| a quote of a hidden post | the quoted post's space (`quote_space`) |
| a quote of a public record | whichever space the author picks |
| a bookmark | the owner's only-me space |

So a reply, like, repost or quote of a hidden post never reaches anyone outside that post's audience.

The placement helpers take the actor. **In a community**, everyone writes only into their own space: a reply, like, repost or quote of a post in a community space goes into the actor's own space for the same community (same type and key), whose audience is the same community. A reply that also quotes goes there too.

## Validation

`validate_record(uri, value)` applies the lexicon's constraints plus these rules. A record that fails is dropped. In a community space, "its own space" below means any space of the same type and key, so a record may name posts in other members' spaces for the same community, never another community's.

- **Replies:**
  - a hidden reply parent or root must be in the reply's own space;
  - a public parent needs a public root.
- **Likes and reposts:**
  - the subject is a `tools.umbrae.post` in the record's own space;
  - nothing else in the record may name a hidden record.
- **Embeds:**
  - **Allowed types:** images, video, external, record and recordWithMedia.
  - **Record embeds (quotes):** a record embed names either a public record or a `tools.umbrae.post` in the quoting post's own space. The quoted URI is the only field in an embed that may name a hidden record.
  - **recordWithMedia:** its media must be images, video or external.
- **Groups:** a group record is the authority's own, at `self`.
- **Bookmarks:**
  - the authority's own, in only-me;
  - its subject is a hidden post.
- **Everything else:** unknown fields are allowed, as Lexicon evolution allows. Collections that aren't Umbrae's are left to the caller.

## Who sees what

`can_view_record(viewer, uri, space state, context)`:

- **Allowed:** the space's authority always sees it. Otherwise the viewer must be a member with `read`.
- **Denied:**
  - a block between the viewer and the author or authority;
  - an inactive author or authority;
  - anything unknown.
- **Records drop out:** records from repos that aren't current writers are hidden, so a removed member's replies and likes disappear with them.
- **The rest:**
  - `can_view_repost`: the viewer may see both the repost and its subject, given both spaces' states: the same space, or in a community, two spaces of it.
  - `can_view_bookmark`: only its owner, and only while they may still see the bookmarked post.
  - A quoted hidden post is looked up in its own space's state. If the viewer can't see it, it shows as unavailable, while the quoting post still shows.
