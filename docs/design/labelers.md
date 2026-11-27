# Private labelers

A private labeler's labels are readable only by the accounts it admits, never publicly.

## Records

| NSID | Key | What |
|---|---|---|
| `tools.umbrae.label` | TID | a label: the fields of `com.atproto.label.defs#label`, plus an optional `audience` |
| `tools.umbrae.labelerProfile` | `self` | name, description, images |
| `tools.umbrae.labelerPolicies` | `self` | label values and definitions, report scope, the label key and retired keys |
| `tools.umbrae.labelerReasons` | `self` | report reasons, localized, in groups |
| `tools.umbrae.labelerAudience` | TID | a permitted list: `{name, members: [did], createdAt}`, at most 5000 accounts |

`validate_labeler_record(uri, value)` checks them. Only the labeler's own records count, and a label's `src` must be the labeler.

## Where they live

A labeler is either of these. The records and rules are the same either way.

- **A space:** type `tools.umbrae.labeler`, key `self`, with the labeler's DID as authority.
  - The space must be a memberspace that isn't publicly readable or writable, with `allowedApps` set and its policy published (`check_labeler_policy`).
  - Readers are members with `read` only (`reader_member`).
- **No network presence:** the labeler and the apps it serves exchange the same records directly, over an authenticated channel. Validate each record against a stand-in record URI in the labeler space type, built from a stable DID-shaped id the two sides share. No sync is involved, so the channel's authentication carries the trust.

## What a label may be on

`label_subject`:

| Subject | Who sees the label |
|---|---|
| an account (a DID) | everyone who may see the labeler |
| a public record | everyone who may see the labeler |
| a hidden post (`tools.umbrae.post` in a `tools.umbrae.space` space) | only people who may also see that post |
| a hidden repost (`tools.umbrae.repost` in a `tools.umbrae.space` space) | only people who may also see that repost and the post it reposts (`can_view_repost_label`) |

A label on anything else refuses. The serving app decides who may see the labeler at all.

## Restricted labels

A label with an `audience` names one of its labeler's `labelerAudience` records. The label is shown only to that list's members (`Audiences`, `can_view_label`). Rules:
- **Unknown audiences:** an audience that doesn't exist shows the label to nobody.
- **Labeler binding:** an audience opens only labels from its own labeler. Audience ids are record keys, so another labeler reusing a key opens nothing.
- **The labeler itself:** it isn't in an audience unless it lists its own DID.

## Signing and keys

- **How labels are signed:** the same way as the reference labeler (`label_signing_bytes`, `sign_label`):
  - the DRISL bytes of the label without `sig` and `$type`;
  - `ver` defaults to 1;
  - `neg` is included only when true;
  - `audience` is included when set.
- **Which key:** the labeler's policies record holds `labelKey`. Without one, the key is the `#atproto_label` key in the labeler's DID document.
- **Key rotation:** the policies record also holds up to 10 retired keys, each with a `retiredAt` time. `verify_label_with` accepts a retired key only for labels created before it retired.
- **Optional:** when labels arrive over an authenticated channel instead of a synced space, signing is optional.

## Labels in effect

`current_labels`:
- For each `(src, uri, cid, val)`, the latest label wins by `cts`, with ties broken by record key.
- Labels are append-only, as on a label stream: applying a label and negating it are each a new record.
- Negated and expired labels drop out.
- A deleted label record counts as never written.
- `audience` is not part of the key.

## Labels in the subject's space

Spaces define their own label records: a `com.atproto.label.record` (`SPACE_LABEL`) written into the subject's own space by a labeler whose repo is in that space's writer set. Other spaces apps read them; Umbrae reads theirs.

### One home per label

A label lives in exactly one place, never both.

| Label | Home |
|---|---|
| unrestricted, on a hidden post or repost in a community or everyone space where the labeler is a label writer | `com.atproto.label.record` in the subject's space, in the labeler's repo |
| any other label on a hidden post or repost, including every label on group and followers posts | `tools.umbrae.label` in the labeler space |
| any label with an `audience` | `tools.umbrae.label` in the labeler space |
| on an account or a public record | `tools.umbrae.label` in the labeler space |

The labeler space keeps everything the standard has no place for: the profile, policies, reasons and audiences.

- **Readers accept both homes**, so a labeler may move a label: it writes the in-space record first, then deletes the labeler-space one. `merge_label_homes` de-duplicates by `(src, uri, cid, val)` and takes the latest `cts`.
- **Writing elsewhere:** a write into a space where the labeler isn't a label writer is still answered 200 by its own PDS, and the record syncs if its repo is ever in that space's writer set. A labeler checks before writing, and deletes any record it finds it wrote elsewhere.
- **Not public:** labels on hidden content never go on `subscribeLabels`.

### The record

`validate_space_label(uri, value)` checks it (`SpaceLabel`):

- **Fields:** `uri` and `val` (1 to 128 bytes) are required, `cid` optional, `cts` and an optional `exp` are datetimes, and the key is a TID. There's no `src`, `sig` or `ver`: the repo the record is in authenticates it, and the writer is the record's author.
- **The subject** must be a record in the label's own space. A label naming another space, a public record, an account (a DID or `at://did`) or a space is ignored. Account and space labels stay in the labeler space.
- **`neg`:** the lexicon has none. A record with `neg: true` is ignored: it never applies, `!takedown` included. Other unknown fields are ignored.
- **Removing a label:** delete its records. A deleted record counts as never written. An expired record isn't a removal, and neither is `neg`.

`current_space_labels` takes, per `(writer, uri, cid, val)`, the latest by `cts`, with ties broken by record key, and drops expired and ignored ones.

### Whose labels count

A reader counts an in-space label only when all three hold:

1. **The writer's repo is in the space's writer set** when the label is synced. A reader never syncs a repo outside it.
2. **The writer is a label writer for the space** (`is_label_writer`). Anyone else's label records are ignored.
3. **The reader trusts that labeler**, as for public labels: the viewer's accepted labelers (`atproto-accept-labelers`), plus the labelers the serving app applies for everyone.

`can_view_space_label` checks all three, and that the viewer may see the post. A label on a repost needs the post it reposts too (`can_view_space_repost_label`).

| Space | Label writers | How they get write access |
|---|---|---|
| everyone | any non-authority repo in its writer set; trust selects whose labels count | the managing app answers `{read: false, write: true}` for its configured labelers |
| a community space | the community's named labeler (`getCommunity.labeler`) | rule 4a (see [Communities](communities.md#what-the-app-answers)) |
| a group, followers | members with `write`, other than the owner | as any member |
| only-me, the profile, a labeler space, a shared list | none | n/a |

- **Not members:** a reader carries label writers in `SpaceState.label_writers`, never in `members`, and a label writer's other records, such as a post or a like, never count.
- **Who fills it:** a community's app, with the named labeler; any reader of an everyone space, with the writer set minus the authority. A group's and a followers space's come from their published members. With none, no label counts.
- **Groups and followers:** labelers are never listed as members of a group or followers space automatically. A labeler the owner adds by hand is an ordinary member. Umbrae's own labelers keep group and followers labels in the labeler space.
- **After a `removeWriter`:** a managing app keeps applying a removed label writer's last-synced labels, `!takedown` included, until it syncs their deletion, without reading the repo outside the writer set. The writer's next write there brings its repo back, whole. Other readers may drop them.

### What outside apps see

- **Everyone spaces:** any app the managing app admits for read sees the label records, and finds the label writers in the writer set.
- **Community spaces:** no outside app reads them. Labels reach members through the managing app.
- **Groups and followers:** Umbrae's labels on them are in the labeler space.
- **Restricted and account labels:** never outside the labeler space.

### What a labeler needs

- a DID on a spaces PDS, and a session whose scope covers `com.atproto.label.record` in `tools.umbrae.space` spaces of any authority, with create and delete (see [Clients and apps](clients-and-apps.md#oauth-scopes));
- to know where it's a label writer: `getCommunity.labeler` for communities, its configuration at an everyone space's managing app;
- outside labels: the serving app syncs every writer-set repo in the spaces it serves, and hands labels to the moderation service as `{space, writer, uri, cid?, val, cts, exp?, isLabelWriter}`. The serving app's verified sync is the authentication.
