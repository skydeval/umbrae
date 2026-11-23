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
| a hidden repost (`tools.umbrae.repost` in a `tools.umbrae.space` space) | only people who may also see that repost |

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
