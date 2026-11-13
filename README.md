# umbrae

Hidden posts for the Horizon ecosystem, built on [atproto spaces](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data).

Horizon has three kinds of post:

| Kind | Where it lives |
|---|---|
| Public | the account's public repo, on the firehose |
| Kryphocron | encoded posts |
| **Umbrae** | hidden posts, in atproto spaces |

Umbrae posts live in a space repo on the member's own PDS. They never go into the public repo, the firehose or a relay. Only authorised apps can read them, with a space credential. Because the posts are the member's own space data, they move with the account when it migrates to another PDS.

Spaces give access control, not confidentiality: the PDS and authorised apps can read what they handle, which is what server-side moderation needs.

Status: early. The standalone design that came before spaces is kept at the `standalone-final` tag.

## Layout

The Rust workspace lives in `umbrae/`.

- `umbrae/crates/umbrae-core`: atproto spaces protocol primitives (no I/O):
  - space URIs;
  - the LtHash set-hash commit digest.

  Still to come: commits, STAR archives, KEM shared secrets, HTTP message signatures and MACs, credentials and delegation tokens, `space:` OAuth scopes, the baseline policies.

Wire names follow the spaces spec exactly (`com.atproto.space.*` and the rest), so Umbrae data stays readable by any spaces-aware app and portable between any PDSes that implement spaces. Locus, the Horizon PDS, will host spaces using `umbrae-core`.

## Building

On the build machine, from `umbrae/`, run `sh scripts/ci.sh`.

## License

[MPL-2.0](LICENSE)
