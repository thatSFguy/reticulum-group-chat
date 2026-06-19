# Reaction attribution across a re-originating relay

**Status:** app-layer interop convention (not part of `SPEC.md`).
**Applies to:** any LXMF client that displays tap-back reactions in a
relayed/group context — Sideband, MeshChatX, Columba, ratspeak, and
relays such as `reticulum-forwarding-service` (fwdsvc).
**Wire impact:** purely additive. Spec-compliant clients that ignore it
keep working; they just fall back to source-based attribution.

---

## The problem

A tap-back reaction is `FIELD_REACTION` (`0x40`), per LXMF 1.0.0 /
`SPEC.md` §5.9.8:

```
fields[0x40] = {
  0x00: <raw 32-byte target message_id>,   # REACTION_TO
  0x01: <UTF-8 reaction content>,          # REACTION_CONTENT (e.g. an emoji)
}
```

Per spec, a reaction carries **no reactor identity** — attribution is
"the carrying LXMF's own `source_hash` / signing identity." That is
correct point-to-point.

A group relay does not work point-to-point. fwdsvc (and any relay like
it) **re-originates** each message: it unpacks the inbound LXMF, applies
group policy, and **re-signs as itself**, so the outbound
`source_hash` is the *relay's* identity, not the original author's.

- For a **text** message, authorship survives because the relay prepends
  a `[Nick] ` prefix to the body.
- A **reaction has no body.** Once it is re-originated, the reactor is
  gone and *every* relayed reaction collapses onto the relay's identity.
  All reactions appear to come from one sender.

(Historically this worked because the pre-1.0.0 reaction shape carried
an explicit `sender` field. Clients migrated to the upstream `0x40`
form, which deliberately dropped it — so the relay must carry it
out-of-band.)

## The convention

On **every re-originated reaction**, the relay stamps the original
reactor's **RNS identity hash** into the upstream app-convention custom
fields (`SPEC.md` §5.9.1; `FIELD_CUSTOM_TYPE`/`FIELD_CUSTOM_DATA` in
`LXMF/LXMF.py`):

```
fields[0xFB]  FIELD_CUSTOM_TYPE  = "originator-identity"   # UTF-8 string, EXACT
fields[0xFC]  FIELD_CUSTOM_DATA  = <reactor identity hash, raw 16 bytes>
```

Full field map of a re-originated reaction:

```
{
  0x40: { 0x00: <32B target message_id>, 0x01: <emoji> },
  0xFB: "originator-identity",
  0xFC: <16B reactor identity hash>,
}
# carrying LXMF: empty content, empty title, source_hash = relay
```

### Rules

1. **`fields[0xFB]` MUST be the exact UTF-8 string `originator-identity`.**
   A receiver that doesn't match it byte-for-byte MUST fall back to
   source-based attribution (i.e. it will mis-attribute to the relay —
   the unfixed behaviour). There is no versioning or fuzzy match.

2. **`fields[0xFC]` is the reactor's RNS _identity hash_, raw 16 bytes** —
   `SHA-256(public_key)[:16]`, where `public_key` is the 64-byte
   announced key (X25519 pub ‖ Ed25519 pub).
   - ⚠️ **It is the identity hash, NOT the `lxmf.delivery` destination
     hash.** Destination hash = `SHA-256(name_hash ‖ identity_hash)[:16]`
     — a *different* value. Clients aggregate reactions by identity, so
     stamping the destination hash mis-attributes exactly as
     `source_hash` does. This is the same dest-vs-identity gotcha that
     bites `source_hash`.
   - The relay already holds the reactor's public key — it verified the
     inbound reaction's signature with it — and derives the identity
     hash from that.

3. **Reactions only.** Only stamp messages whose fields contain `0x40`.
   Replies (`0x30`/`0x31`), comments (`0x41`), and continuations
   (`0x42`) carry a body and ride the relay's `[Nick]` prefix, so they
   need no stamp.

### Sender (relay) behaviour

- For each re-originated reaction, set `0xFB`/`0xFC` as above before
  fan-out, deriving `0xFC` from the **verified** inbound signing
  identity (never from a client-supplied field — see Security).

### Receiver (client) behaviour

When you receive a reaction (`fields[0x40]` present):

- If `fields[0xFB] == "originator-identity"` and `fields[0xFC]` is
  present, **attribute/aggregate the reaction to the identity hash in
  `0xFC`**, not to the carrying message's `source_hash`.
- Otherwise, attribute by `source_hash` as today.

Aggregate by `(reactor-identity, REACTION_CONTENT)` per §5.9.8, where
`reactor-identity` is the `0xFC` hash when present.

## Security

The relay MUST set `0xFC` from the identity it cryptographically
verified on the inbound reaction, and MUST ignore any `0xFB`/`0xFC` a
client included on the inbound message (fwdsvc does this by keeping
`0xFB`/`0xFC`/`0xFD` out of its forward allowlist, so client-supplied
values are stripped before the relay stamps its own). Otherwise a client
could forge reactions attributed to someone else.

## Backward compatibility

Purely additive. A spec-compliant client that threads only `0x40`
ignores `0xFB`/`0xFC` and falls back to source-based attribution — no
client breaks. Cooperating clients gain correct per-reactor attribution.

## Decoding reactions: the nested integer-keyed map pitfall

`FIELD_REACTION` (`0x40`), `FIELD_COMMENT` (`0x41`), and
`FIELD_CONTINUATION` (`0x42`) all carry a **nested map with integer
keys** (`0x00`, `0x01`). This trips a common msgpack-library default:
when decoding a map *value* into a generic type, many libraries produce
a **string-keyed** map and choke on the integer keys.

- **Go (`vmihailenco/msgpack`):** a nested map value decodes into
  `map[string]interface{}` by default and fails on inner key `0x00` with
  `msgpack: invalid code=0 decoding string/bytes length` — which aborts
  the decode of the **entire** LXMF message. The reaction is dropped
  before any reaction logic runs, and over a Link the sender gets no
  delivery proof and **retries indefinitely** — so it presents as "the
  link is failing," not as a reaction bug. Fix: decode the fields
  element with `Decoder.SetMapDecoder(func(d){ return d.DecodeUntypedMap() })`
  so every nesting level decodes into `map[interface{}]interface{}`.
- **Other runtimes** have the analogous switch — decode into an untyped
  / `Map<Any, Any>` map rather than `Map<String, Any>`.

Two more tolerances when reading the inner dict:

- **Integer key width.** Inner keys may decode as any integer type
  (`int8`/`int64`/`uint8`/…). Compare keys by integer *value*, not exact
  type.
- **bytes vs str.** Per §5.9.8 the `REACTION_TO` hash and
  `REACTION_CONTENT` may arrive as msgpack `bin` or `str`; accept both.

**Symptom to recognise:** reply-to (`0x30`, raw bytes at the *top*
level) works but reactions/comments/continuations vanish. Top-level
fields decode fine; only the nested integer-keyed dicts break. That's
this pitfall, not a routing problem.

## Routing: why reactions reach a re-originating relay

Because the relay **re-originates** (re-signs as itself), the relayed
message's `source_hash` is the relay's destination. A client reacting to
that message naturally addresses the reaction to the relay, so it comes
back to the relay for fan-out with **no special egress handling**. This
is specific to the re-originating model. A relay that instead *preserves*
the original `source_hash` would have reactions addressed to the
original author, bypassing the relay — that is the case SPEC §5.9.8 /
§6.7.6 LINKIDENTIFY egress-routing addresses, and it does not apply here.

## Out of scope: target resolution

Attribution (this document) and **target resolution** are separate
concerns. `0x40.0x00` (reaction target) points at a message by its
`message_id = SHA-256(dest_hash ‖ source_hash ‖ msgpack_payload)`
(§5.5). Because a re-originated message has a different `message_id` per
recipient, a relay must rewrite the target id per recipient as it fans
out (fwdsvc's id-cache does this). That mechanism is unchanged by this
convention; if reactions were landing on the right message before, they
still do.

## Reference implementation

fwdsvc stamps this on relay in
[`internal/service/inbox.go`](../internal/service/inbox.go) /
[`internal/service/rewrite.go`](../internal/service/rewrite.go)
(`stampReactorIdentity`), deriving the identity hash via
`KnownIdentity.IdentityHash()` (`SHA-256(public_key)[:16]`).
