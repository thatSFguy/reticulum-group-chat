#!/usr/bin/env python3
"""Live coverage for the v1.14.0 inbound-parsing changes.

Two things nothing else in the harness exercises, both against bytes
produced by the REAL upstream encoder rather than our own:

1. Integer-keyed field maps (FIELD_REACTION 0x40, FIELD_IMAGE 0x06,
   FIELD_REPLY_TO 0x30). v1.14.0 added structural msgpack pre-validation
   in front of every inbound decode; this proves the guard does not
   reject the nested arrays and int-keyed maps real clients send.

2. A message carrying a STAMP (the optional 5th payload element).
   SPEC 5.6 lets a stamp be added without invalidating the signature, so
   the receiver must re-verify against a stamp-stripped payload. Until
   v1.14.0 that path re-encoded through a decoder that cannot represent
   integer-keyed maps, so every stamped message carrying reactions,
   replies or images failed verification and was SILENTLY DROPPED.

The assertion is fan-out to a second peer, not service liveness: a
dropped message leaves the service perfectly healthy, so only observing
the message arrive at another member proves it was accepted, verified
and forwarded. Each payload carries a random tag so a stale or
duplicated message cannot produce a false pass.
"""

from __future__ import annotations
import os
import sys
import threading
import time

import LXMF
import RNS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402


def main() -> int:
    args = _common.parse_args()

    cfg_dir = _common._write_rns_config(args.rnsd)
    RNS.Reticulum(cfg_dir, loglevel=int(os.environ.get("INTEROP_LOGLEVEL", "4")))

    sender_id = RNS.Identity()
    watcher_id = RNS.Identity()
    storage = os.path.join(cfg_dir, "storage")
    os.makedirs(storage, exist_ok=True)

    sender_router = LXMF.LXMRouter(identity=sender_id, storagepath=storage)
    watcher_router = LXMF.LXMRouter(identity=watcher_id, storagepath=storage)

    watcher_inbox: list[LXMF.LXMessage] = []
    watcher_lock = threading.Lock()

    def on_watcher(message: LXMF.LXMessage) -> None:
        with watcher_lock:
            watcher_inbox.append(message)

    sender_dst = sender_router.register_delivery_identity(sender_id, display_name="stamp-sender")
    watcher_dst = watcher_router.register_delivery_identity(watcher_id, display_name="stamp-watcher")
    watcher_router.register_delivery_callback(on_watcher)
    sender_dst.announce()
    watcher_dst.announce()
    print(f"[case] sender  = {sender_dst.hash.hex()}")
    print(f"[case] watcher = {watcher_dst.hash.hex()}")

    deadline = time.time() + args.timeout
    last_request = 0.0
    while time.time() < deadline:
        if RNS.Identity.recall(args.fwdsvc_hash) is not None:
            break
        now = time.time()
        if now - last_request > 3:
            RNS.Transport.request_path(args.fwdsvc_hash)
            last_request = now
        time.sleep(0.3)
    else:
        print("[case] FAIL: fwdsvc never announced", file=sys.stderr)
        return 1
    time.sleep(3.0)  # let both announces reach fwdsvc

    fwdsvc_id = RNS.Identity.recall(args.fwdsvc_hash)
    fwdsvc_dst = RNS.Destination(
        fwdsvc_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "lxmf", "delivery",
    )

    def send_from(router, src, content: str, *, fields=None, stamp_cost=None) -> None:
        msg = LXMF.LXMessage(
            destination=fwdsvc_dst, source=src,
            content=content.encode("utf-8"), title=b"",
            desired_method=LXMF.LXMessage.DIRECT,
            stamp_cost=stamp_cost,
        )
        if fields:
            msg.fields = fields
        msg.try_propagation_on_fail = False
        router.handle_outbound(msg)

    print("[case] both peers /join")
    send_from(sender_router, sender_dst, "/join")
    time.sleep(2.0)
    send_from(watcher_router, watcher_dst, "/join")
    time.sleep(2.0)

    def expect_fanout(label: str, fields, stamp_cost) -> bool:
        tag = os.urandom(4).hex()
        payload = f"{label} {tag}"
        print(f"[case] sending: {label} (stamp_cost={stamp_cost})")
        send_from(sender_router, sender_dst, payload, fields=fields, stamp_cost=stamp_cost)

        end = time.time() + args.timeout
        while time.time() < end:
            with watcher_lock:
                for m in watcher_inbox:
                    if tag in m.content.decode("utf-8", errors="replace"):
                        print(f"[case]   OK — watcher received it (tag {tag})")
                        return True
            time.sleep(0.3)
        print(f"[case] FAIL: watcher never received {label!r} (tag {tag}) — "
              f"message was dropped, not forwarded", file=sys.stderr)
        return False

    reaction_target = bytes(32)
    # Image payloads use RANDOM bytes: real images are already
    # compressed, and RNS only bz2-compresses a Resource when it helps.
    # Zero-filled test data would compress and hit fwdsvc's deliberate
    # rejection of compressed Resources (see docs/resource-security-audit.md),
    # which would be testing that policy rather than these changes.
    cases = [
        ("int-keyed-reaction-and-reply",
         {LXMF.FIELD_REACTION: {0x00: reaction_target, 0x01: "👍".encode("utf-8")},
          LXMF.FIELD_REPLY_TO: reaction_target},
         None),
        ("nested-array-image-field",
         {LXMF.FIELD_IMAGE: ["png", os.urandom(400)]},
         None),
        ("STAMPED-with-int-keyed-fields",
         {LXMF.FIELD_REACTION: {0x00: reaction_target, 0x01: "🎉".encode("utf-8")},
          LXMF.FIELD_IMAGE: ["png", os.urandom(200)]},
         8),
        ("STAMPED-plain-text",
         None,
         8),
    ]

    for label, fields, stamp_cost in cases:
        if not expect_fanout(label, fields, stamp_cost):
            return 1

    print("[case] PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[case] FAIL: {e!r}", file=sys.stderr)
        sys.exit(1)
