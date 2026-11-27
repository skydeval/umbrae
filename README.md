# umbrae

Hidden posts for the Horizon ecosystem, built on [atproto spaces](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data).

[Horizon](https://github.com/skydeval/horizon-ts) has three kinds of post:

| Kind | Where it lives |
|---|---|
| Public | the account's public repo, on the firehose |
| [Kryphocron](https://github.com/skydeval/kryphocron) | encoded posts |
| **Umbrae** | hidden posts, in atproto spaces |

Umbrae posts live in a space repo on the author's own PDS. They never go into the public repo, the firehose or a relay. Only the people the author chose, and the apps the space admits, can read them. They're the account's own space data, so they move with it when it migrates to another PDS.

Spaces give access control, not confidentiality: the PDS and the apps a space admits can read what they handle. That's what lets a community's moderators see hidden posts. A hidden post protocol shouldn't be a place where anything goes.

Umbrae isn't a server. It's lexicons, rules and protocol code that clients, PDSes and serving apps share.

## What's in it

- **Hidden posts:** posts, replies, likes, reposts and same-group quotes. One space per audience (a group, or only-me).
- **Bookmarks** of hidden posts, kept in only-me.
- **Private labelers:** labels readable only by admitted accounts, labels on hidden posts and accounts, and labels restricted to a permitted list.
- **Private accounts:** an approved-followers audience, a hidden profile, hidden follows, and reply and quote gates.
- **Communities:** a community's own managed space, with membership held by its managing app (a serving app, or a PDS that manages its own communities), author-driven feeds, one profile shown to the audiences it lists, and shareable lists with subscriptions.
- **Hidden lists:** block, mute and curate lists, personal (in only-me) or shared (subscribers can't see each other). Also exemptions from labels, labelers and lists.

The design is documented in [`docs/design/`](docs/design/README.md).

## Layout

The Rust workspace lives in `umbrae/`.

| Crate | What |
|---|---|
| `umbrae-core` | atproto spaces primitives, no I/O: space URIs, DRISL and CIDs, commits and LtHash, STAR archives, KEM secrets, HTTP message signatures and MACs, credentials and delegation tokens, `space:` OAuth scopes, the baseline policies |
| `umbrae-lexicons` | the `tools.umbrae.*` lexicons and record validation |
| `umbrae` | the rules: which space a record goes into, who may see what, and the policy each space must have |
| `umbrae-sync` | syncing spaces as an admitted app, over a transport the caller supplies |
| `umbrae-interop` | an interop harness against the reference spaces PDS |

Wire names follow the spaces spec exactly (`com.atproto.space.*` and the rest), so Umbrae data stays readable by any spaces-aware app and portable between any PDSes that implement spaces. [Aurora-Locus](https://github.com/dollspace-gay/Aurora-Locus) will host spaces using `umbrae-core`.

The lexicons are published for [Lexicon resolution](https://atproto.com/specs/lexicon) under `umbrae.tools`.

## Building

From `umbrae/`:

- `sh scripts/ci.sh`: formatting, clippy and tests.
- `sh scripts/interop.sh`: the interop run against the reference spaces PDS. It needs Docker.

## Versioning

[Semantic versioning](https://semver.org/), with Cargo's pre-1.0 rule: a minor bump (0.x.0) is a breaking change, and a patch (0.x.y) is compatible. The public record and change enums are `#[non_exhaustive]`, so new record types can arrive in a patch. See [CHANGELOG.md](CHANGELOG.md).

## License

[MPL-2.0](LICENSE)
