# Lists and exemptions

The permissioned counterpart of `app.bsky.graph.list`.

## Records

| NSID | What |
|---|---|
| `tools.umbrae.list` | `{purpose: "block" \| "mute" \| "curate", name, description?, createdAt}` |
| `tools.umbrae.listitem` | `{subject: did, list?: <TID rkey>, createdAt}` |
| `tools.umbrae.exemption` | `{subject: did, kind, createdAt}` |

`name` is 1–64 graphemes and `description` at most 300, as in `app.bsky.graph.list`.

## Personal lists

These live in the owner's **only-me** space, written by the owner with TID keys:
- A list is a `tools.umbrae.list` at a TID rkey.
- Each entry is a `tools.umbrae.listitem` whose `list` field is that list's rkey.
- Only the owner, and the apps they delegate to, can read them.

## Shared lists

A shared list is its own space, type `tools.umbrae.listSpace`, key a TID, with the owner as authority.

- **Records:**
  - the list record at rkey `self`;
  - entries with TID keys and no `list` field;
  - only the owner's records count (`validate_list_record`).
- **Policy (`list_policy`, `check_list_policy`):** a memberspace, not public, with the policy published and the **member list unpublished**.
- **Subscribers:**
  - they're read-only members (`subscriber()`), so they can't see each other;
  - only the owner can list them (`com.atproto.memberspace.listMembers` is authority-only).
- **Who can join:** shared lists are **invite-only**, because only the owner can add members. A request to subscribe is the app's business. It must never appear in a public record or post, because that would name the list's space.
- **No app serves list spaces,** because the member list isn't published. A subscriber's client reads the list straight from the owner's PDS with the subscriber's own credential.
- **Writes by subscribers:** a subscriber's own PDS still accepts a write into their repo in the list space. The owner's PDS never counts them as a writer, so nobody reading the list sees that write.

## Exemptions

These live in the owner's only-me space. `kind` is one of:

| `$type` | Meaning |
|---|---|
| `tools.umbrae.exemption#label` `{labeler: did, val}` | ignore one label value from one labeler on this account |
| `tools.umbrae.exemption#labeler` `{labeler: did}` | ignore every label from that labeler on this account |
| `tools.umbrae.exemption#list` `{list: uri}` | don't apply one list to this account |

A `#list` exemption names one of these:
- a public `app.bsky.graph.list`;
- one of the owner's own personal lists;
- the `self` record of any shared list space, including lists the owner subscribes to. That reveals nothing, because only-me is readable only by its owner.

## Hidden URIs

- `subject` and `labeler` are DIDs.
- A list or entry never names a hidden record.
- An exemption names one only in `kind.list`.

## Applying them

The client applies exemptions in its own moderation step. Enforcing hidden block lists on the serving side is a separate design.
