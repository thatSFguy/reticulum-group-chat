# Draft issue for liamcottle/reticulum-meshchat

Submit at: https://github.com/liamcottle/reticulum-meshchat/issues/new

---

**Title:** Spurious incoming-call notification from a peer that has no `call.audio` destination

---

## Summary

A MeshChat user receives an "incoming call" UI notification attributed to a peer that has only an `lxmf.delivery` destination — no `call.audio` destination at all. The notification fires shortly after the peer's announce reaches the user's MeshChat, presents briefly with a codec-mismatch / failed-call message, and ends. This is reproducible against any text-only LXMF peer; we hit it consistently against [`reticulum-forwarding-service`](https://github.com/thatSFguy/reticulum-forwarding-service), a Go LXMF group-chat relay that registers only `lxmf.delivery` and never opens links to anything other than other peers' `lxmf.delivery` destinations.

## What we expect

The text-only peer never derives, never announces, and never opens a link to `call.audio` on anyone. So the only way `AudioCallReceiver.client_connected` should fire is if a remote peer establishes a link to *the local user's* `call.audio` destination — which a peer that doesn't even know that aspect exists shouldn't be able to do.

## What actually happens

The incoming-call UI appears, attributed to the text-only peer. We've audited the relay end:

- It never computes the `call.audio` name_hash, so it cannot produce that destination's hash.
- Its only outbound link path (`acquireLinkTo`) targets the recipient's `lxmf.delivery` dest_hash — pulled either from `roster.ActiveHashes()` or from the `source_hash` field of an inbound LXMF body. Both are `lxmf.delivery` hashes, not `call.audio`.
- It does not call `link.identify`, so even if a link reached MeshChat for unrelated reasons, we wouldn't be advertising our identity over it.

## Suspected mechanisms (need help confirming)

One of the following must be true. We can't pin which without MeshChat-side diagnostics:

1. **Misrouted link callback.** RNS dispatches the link-established callback on the destination the LINKREQUEST is addressed to. If anything in MeshChat installs a global / identity-level link callback that fires for *any* destination on the identity, an inbound LXMF link (addressed to `lxmf.delivery` on the user's identity) would be misrouted to `AudioCallReceiver.client_connected`. Worth checking whether `set_link_established_callback` is installed anywhere outside `AudioCallReceiver.__init__`, and whether anything wraps RNS's per-destination dispatch.

2. **Frontend or unrelated subsystem opens the call.audio link.** Something other than `AudioCallManager.initiate()` — possibly a Vue frontend handler, a presence/keepalive job, or a contact-online auto-action — opens a link to a peer's `call.audio` destination on announce-received. We didn't find such a path in `audio_call_manager.py` or `announce_handler.py` but haven't read the frontend.

3. **Misattribution.** An unrelated peer is actually opening links to the user's `call.audio` and the admin is attributing it to whichever peer most recently announced. Less likely given how reproducibly it correlates with fwdsvc startup, but possible.

## Diagnostic that would settle it

When the bogus notification fires, MeshChat's log line for the incoming call (and the link-established callback that fired) should include the dest_hash the link was addressed to and the initiator's identity hash if it identified. Specifically:

- If the destination shows the user's `call.audio` dest_hash AND the initiator hash matches the text-only peer's identity → that peer really did open a call.audio link, and the bug is on the peer's side or in some shared library both ends use.
- If the destination shows the user's `lxmf.delivery` dest_hash (not call.audio) → MeshChat is misrouting the callback (mechanism #1 above).
- If the initiator hash doesn't match the displayed peer → misattribution (#3).

We're happy to capture this on our side too if MeshChat exposes the link-established attribution.

## Why this matters

Text-only LXMF peers (group-chat relays, command bots, automation endpoints) are a real and growing class of useful destinations. They announce normally, respond to LXMF, and have no voice surface. Today's UX surfaces them as "broken voice peers that keep failing to connect" — which is wrong on both axes (they're not voice peers, and they're not calling anyone).

cc @ynosgr — reporting this from the affected-user side (running into it via fwdsvc).
