# Overview

## The model

**The space is the audience.**
- An author keeps one space for each group of people they post to, such as "close friends", plus one **only-me** space for themselves.
- A post goes into exactly one space, and whoever may read that space may read the post. Nobody else can.

| Piece | Role |
|---|---|
| The author's PDS | stores the space repos and the member list; issues credentials; enforces reads |
| Each member's PDS | stores that member's own records in the space (their replies, likes, reposts) |
| A serving app | an app the space admits: it syncs spaces, builds views, and applies Umbrae's view rules |
| A client, such as [Horizon](https://github.com/skydeval/horizon-ts) | composes posts, manages groups and members, shows views |
| The `umbrae` crates | the rules all of these share |

Umbrae has **no server of its own**. Everything lives in standard space repos under standard wire names. So hidden posts work on any PDS that implements spaces: the reference PDS, or [Aurora-Locus](https://github.com/dollspace-gay/Aurora-Locus). They also move with the account between PDSes.

## What spaces protect, and what they don't

Spaces are **access control, not encryption**:
- **Who can read, and how it's enforced:** the PDS checks every read. Readers need a short-lived signed credential, issued only to members, through apps the space admits. Knowing a space's address gets you nothing.
- **Who sees plaintext:** the PDS operator and every admitted app see what they handle.
- **Removed members:** removing a member stops future reads. Anything they already fetched stays with them, and a credential they already hold lasts until it expires (at most an hour).

## Moderation

Hidden means hidden from the public and from people outside the audience, **not from the community's moderators**:
- A hidden-post protocol mustn't become a place where anything can be posted unseen.
- The serving app makes hidden posts available to the community's moderation service.
- Moderators never appear in a space's member list. Authors can't opt out, and the community's terms cover it.

## Space URIs

Space URIs follow the spaces spec:

| What | Form |
|---|---|
| A space (the lexicon `space-ref` format) | `at:space/{spaceDid}/{spaceType}/{skey}` |
| A record in a space | `at:space/{spaceDid}/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}` |

- **Strict parsing:** only these two lengths, a lowercase `at:space/` prefix, DIDs (never handles) in both DID slots, and no query, fragment, empty segment or trailing slash.
- **The old form:** `at://{spaceDid}/space/...` is no longer a space URI, and parsing refuses it. The leak checks still treat it as one, since it still names hidden data.
- **Migration:** the PDS doesn't rewrite URIs stored inside record values, so records written before the change are dropped by validation until their authors rewrite them. `upgrade_space_uris` rewrites a record value in place, and the author puts it back at the same key.

## Hidden URIs never go public

A space URI has no public meaning, and naming one in public reveals that the record exists. So:
- **Public records:** no public record ever names a hidden one. Clients check every public write with `leaks_hidden` before sending it.
- **Inside a space:** a record names a hidden record only in the places the rules allow, such as a reply's parent or a like's subject. Those places always point within the same audience.

## Rules fail closed

- When a reader lacks the state needed to decide (a space's policy, its members, the post a label or bookmark points at), the answer is no.
- A record that fails validation is dropped from views. It's never an error for the whole space.
- "Unreadable" and "missing" look the same to the reader.
