#!/usr/bin/env python3
"""Does a long-but-allowed chat message from a real client survive?

`max_inbound_chars` defaults to 500, so a ~450-character message is
explicitly within policy. But a message that size exceeds the Link MDU
and is therefore sent as an RNS Resource — and RNS bz2-compresses a
Resource whenever that shrinks it, which ordinary prose does by roughly
30%. fwdsvc deliberately rejects compressed (c=1) Resources as a
decompression-bomb defense (docs/resource-security-audit.md F1).

This case establishes whether those two policies collide in practice,
i.e. whether messages the config permits are silently dropped on the
wire. Assertion is fan-out to a second peer, so a drop fails the test.
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

# Ordinary English prose, the compressible case that matters. Varied
# enough to be realistic rather than a pathological repeat.
PROSE = (
    "Heading out to the north ridge repeater this afternoon to swap the "
    "failing solar controller and re-seat the antenna feedline. Weather "
    "looks marginal after four so I want to be off the hill by then. If "
    "anyone needs a test transmission while I am up there, say so now "
    "and I will keep the handheld monitoring. "
)


def main() -> int:
    args = _common.parse_args()
    cfg_dir = _common._write_rns_config(args.rnsd)
    RNS.Reticulum(cfg_dir, loglevel=int(os.environ.get("INTEROP_LOGLEVEL", "4")))

    sender_id, watcher_id = RNS.Identity(), RNS.Identity()
    storage = os.path.join(cfg_dir, "storage")
    os.makedirs(storage, exist_ok=True)
    sender_router = LXMF.LXMRouter(identity=sender_id, storagepath=storage)
    watcher_router = LXMF.LXMRouter(identity=watcher_id, storagepath=storage)

    inbox: list[LXMF.LXMessage] = []
    lock = threading.Lock()
    watcher_router.register_delivery_callback(
        lambda m: (lock.acquire(), inbox.append(m), lock.release()) and None)

    sender_dst = sender_router.register_delivery_identity(sender_id, display_name="longtext-sender")
    watcher_dst = watcher_router.register_delivery_identity(watcher_id, display_name="longtext-watcher")
    sender_dst.announce()
    watcher_dst.announce()

    deadline = time.time() + args.timeout
    last = 0.0
    while time.time() < deadline:
        if RNS.Identity.recall(args.fwdsvc_hash) is not None:
            break
        if time.time() - last > 3:
            RNS.Transport.request_path(args.fwdsvc_hash)
            last = time.time()
        time.sleep(0.3)
    else:
        print("[case] FAIL: fwdsvc never announced", file=sys.stderr)
        return 1
    time.sleep(3.0)

    fwdsvc_dst = RNS.Destination(
        RNS.Identity.recall(args.fwdsvc_hash), RNS.Destination.OUT,
        RNS.Destination.SINGLE, "lxmf", "delivery")

    def send(router, src, content):
        msg = LXMF.LXMessage(destination=fwdsvc_dst, source=src,
                             content=content.encode("utf-8"), title=b"",
                             desired_method=LXMF.LXMessage.DIRECT)
        msg.try_propagation_on_fail = False
        router.handle_outbound(msg)

    send(sender_router, sender_dst, "/join")
    time.sleep(2.0)
    send(watcher_router, watcher_dst, "/join")
    time.sleep(2.0)

    ok = True
    for nchars in (200, 450):
        tag = os.urandom(4).hex()
        body = (PROSE * 3)[:nchars - 9] + " " + tag
        print(f"[case] sending {len(body)}-char prose message (tag {tag})")
        send(sender_router, sender_dst, body)

        end = time.time() + args.timeout
        got = False
        while time.time() < end and not got:
            with lock:
                got = any(tag in m.content.decode("utf-8", errors="replace") for m in inbox)
            if not got:
                time.sleep(0.3)
        if got:
            print(f"[case]   OK — {len(body)}-char message forwarded")
        else:
            print(f"[case]   DROPPED — {len(body)}-char message never arrived "
                  f"(within max_inbound_chars=500)", file=sys.stderr)
            ok = False

    print("[case] PASS" if ok else "[case] FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[case] FAIL: {e!r}", file=sys.stderr)
        sys.exit(1)
