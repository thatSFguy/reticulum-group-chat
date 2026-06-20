# Reaction attribution across a re-originating relay

**Status:** app-layer interop convention (not part of `SPEC.md`).
**Applies to:** any LXMF client that displays tap-back reactions in a
relayed/group context — Sideband, MeshChatX, Columba, ratspeak, and
relays such as `reticulum-group-chat` (fwdsvc).
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
reactor's **`source_hash`** into the upstream app-convention custom
fields (`SPEC.md` §5.9.1; `FIELD_CUSTOM_TYPE`/`FIELD_CUSTOM_DATA` in
`LXMF/LXMF.py`):

```
fields[0xFB]  FIELD_CUSTOM_TYPE  = "originator-identity"   # UTF-8 string, EXACT
fields[0xFC]  FIELD_CUSTOM_DATA  = <reactor source_hash, raw 16 bytes>
```

Full field map of a re-originated reaction:

```
{
  0x40: { 0x00: <32B target message_id>, 0x01: <emoji> },
  0xFB: "originator-identity",
  0xFC: <16B reactor source_hash>,
}
# carrying LXMF: empty content, empty title, source_hash = relay
```

### Rules

1. **`fields[0xFB]` MUST be the exact UTF-8 string `originator-identity`.**
   A receiver that doesn't match it byte-for-byte MUST fall back to
   source-based attribution (i.e. it will mis-attribute to the relay —
   the unfixed behaviour). There is no versioning or fuzzy match. (The
   tag string keeps this exact wording for wire compatibility even though
   the value it labels is a source_hash, not an identity hash.)

2. **`fields[0xFC]` is the reactor's `source_hash`, raw 16 bytes** — i.e.
   the reactor's **`lxmf.delivery` destination hash**
   (`SHA-256(name_hash ‖ identity_hash)[:16]`), which is exactly the
   value a *direct* reaction carries in its LXMF `source_hash`. The relay
   just copies the inbound reaction's `source_hash` here.
   - ⚠️ **It is the destination hash, NOT the raw RNS identity hash**
     (`SHA-256(public_key)[:16]`). Per `SPEC.md` §5.9.8, reaction
     attribution rides on `source_hash`; per §9.1, an LXMF `source_hash`
     is the **destination** hash and receivers key their contacts by it —
     *"sending the identity hash here means the recipient can't look you
     up in their contacts … and the conversation gets orphaned."* Using
     the destination hash keeps direct and relayed reactions one
     consistent key that resolves to a contact.

3. **Reactions only.** Only stamp messages whose fields contain `0x40`.
   Replies (`0x30`/`0x31`), comments (`0x41`), and continuations
   (`0x42`) carry a body and ride the relay's `[Nick]` prefix, so they
   need no stamp.

### Sender (relay) behaviour

- For each re-originated reaction, set `0xFB`/`0xFC` as above before
  fan-out, copying `0xFC` from the **verified** inbound reaction's
  `source_hash` (never from a client-supplied field — see Security).

### Receiver (client) behaviour

When you receive a reaction (`fields[0x40]` present), honor the stamp
only when **all** of these hold; otherwise attribute by the carrying
message's `source_hash` as today:

1. `fields[0xFB] == "originator-identity"` (exact UTF-8), and
2. `fields[0xFC]` is a **well-formed** reactor `source_hash` — exactly a
   16-byte value (32 hex chars after the serializer's hex-encoding).
   Reject blank / wrong-length / non-hex values (don't let them become an
   unresolvable attribution key), and
3. **the reaction provably arrived via a trusted relay** — see Security.
   Concretely: the carrying message's `source_hash` is the relay/group
   source that delivered the message being reacted to.

When honored, attribute/aggregate by the `0xFC` `source_hash`. It's in
the same hash space as a direct reaction's `source_hash`, so it resolves
against your contacts (keyed by destination hash, §9.1) with no special
handling. Aggregate by `(reactor-identity, REACTION_CONTENT)` per §5.9.8,
where `reactor-identity` is the `0xFC` value when honored, else the
carrying `source_hash`.

## Security

The stamp is an **unauthenticated assertion** — there is no signature
binding `0xFC` to the reactor. Its trust comes entirely from the relay:
a re-originating relay verifies the reactor's LXMF signature on the
inbound reaction before stamping, so a member trusts the relay's
attribution the same way it already trusts the relay's `[Nick]` prefix on
relayed text.

Two MUSTs follow, one per side:

- **Relay (sender):** MUST set `0xFC` from the `source_hash` it
  cryptographically verified on the inbound reaction, and MUST ignore any
  `0xFB`/`0xFC` a client put on the inbound message (fwdsvc keeps
  `0xFB`/`0xFC`/`0xFD` out of its forward allowlist, so client-supplied
  values are stripped before it stamps its own).

- **Receiver (client):** MUST NOT honor the stamp on a reaction that did
  **not** arrive via a trusted relay. Because the stamp is unsigned, a
  *direct* peer can set `0xFB`/`0xFC` to attribute a reaction to an
  arbitrary third party; honoring it unconditionally lets any peer forge
  reactions as anyone (e.g. spoofing "Charlie reacted" by direct-sending
  a stamped reaction targeting a message Charlie can see). Gate the
  override on the carrying `source_hash` being a trusted relay — e.g. the
  same source that delivered the reacted-to message, or an operator/
  user-confirmed relay. A stamp from any other source MUST be discarded
  and attribution MUST fall back to `source_hash`. (This is no weaker
  than relayed text, where authorship is likewise relay-asserted.)

## Backward compatibility

Purely additive. A spec-compliant client that threads only `0x40`
ignores `0xFB`/`0xFC` and falls back to source-based attribution — no
client breaks. Cooperating clients gain correct per-reactor attribution.

## Decoding reactions: the nested integer-keyed map pitfall

`FIELD_REACTION` (`0x40`), `FIELD_COMMENT` (`0x41`), and
`FIELD_CONTINUATION` (`0x42`) all carry a **nested map with integer
keys** (`0x00`, `0x01`). `SPEC.md` §5.9.8 makes this a normative receiver
requirement ("Inner-map decode tolerance … Receivers MUST tolerate this
via a runtime cast that does not depend on the outer map's static key
type. A silent type-assertion failure produces a no-log no-error drop").
This trips a common msgpack-library default: when decoding a map *value*
into a generic type, many libraries produce a **string-keyed** map and
choke on the integer keys.

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
(`stampReactorIdentity`), copying `0xFC` straight from the inbound
reaction's verified `source_hash` (`msg.SourceHash`).

## Spec basis

| Concern | Spec |
|---|---|
| `FIELD_REACTION 0x40` shape (`REACTION_TO` raw bytes, `REACTION_CONTENT` UTF-8), bytes/str + inner-map decode tolerance, attribution rides on `source_hash` | `SPEC.md` §5.9.8 |
| `FIELD_CUSTOM_TYPE 0xFB` / `FIELD_CUSTOM_DATA 0xFC` (app-defined type + opaque data) | §5.9.1 |
| `source_hash` is the destination hash, contacts keyed by it (why `0xFC` is the destination hash, not the identity hash) | §9.1 |
| Reply-to `0x30` / `0x31` (untouched) | §5.9.9 |
| `message_id` over raw wire bytes (target resolution) | §5.5 / §5.7 |

The `"originator-identity"` stamp convention itself is **not** part of
`SPEC.md` — it is an app-layer interop convention built on those
spec-defined primitives, kept out of the spec by design.
