#!/usr/bin/env python3
"""Spawns two Python LXMF peers that both /join, has alice send a chat
message, and asserts bob receives it via fwdsvc fanout.

Today this case stresses the same code path as a regular group-chat
broadcast: alice -> fwdsvc inbound, fwdsvc fans out to every member of
the roster (including bob), bob's LXMF callback fires.

Both peers run inside this single Python process. Two LXMRouter
instances on one Reticulum stack share the same announce table but
have distinct identities, dest_hashes, and inboxes — exactly what we
need to prove fanout.
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

    # Bring up RNS once for both peers.
    cfg_dir = _common._write_rns_config(args.rnsd)
    RNS.Reticulum(cfg_dir, loglevel=int(os.environ.get("INTEROP_LOGLEVEL", "4")))

    alice_id = RNS.Identity()
    bob_id = RNS.Identity()
    storage = os.path.join(cfg_dir, "storage")
    os.makedirs(storage, exist_ok=True)

    alice_router = LXMF.LXMRouter(identity=alice_id, storagepath=storage)
    bob_router = LXMF.LXMRouter(identity=bob_id, storagepath=storage)

    bob_inbox: list[LXMF.LXMessage] = []
    bob_lock = threading.Lock()

    def on_bob(message: LXMF.LXMessage) -> None:
        with bob_lock:
            bob_inbox.append(message)

    alice_dst = alice_router.register_delivery_identity(alice_id, display_name="alice-fanout")
    bob_dst = bob_router.register_delivery_identity(bob_id, display_name="bob-fanout")
    bob_router.register_delivery_callback(on_bob)
    alice_dst.announce()
    bob_dst.announce()
    print(f"[case] alice = {alice_dst.hash.hex()}")
    print(f"[case] bob   = {bob_dst.hash.hex()}")

    # Wait for fwdsvc identity AND for our two announces to settle on
    # fwdsvc's side. Without the settle, the first /join would race fwdsvc's
    # path? -> announce roundtrip and get dropped silently.
    #
    # Force a fresh path? every 3s — has_path() can return True before
    # Identity.recall() is populated (rnsd may know the route via its
    # path table without yet having relayed the announce body to us),
    # so we can't gate path? on has_path.
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
    time.sleep(3.0)  # let alice + bob's announces propagate to fwdsvc

    fwdsvc_id = RNS.Identity.recall(args.fwdsvc_hash)
    fwdsvc_dst = RNS.Destination(
        fwdsvc_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "lxmf", "delivery",
    )

    def send_from(router: LXMF.LXMRouter, src: RNS.Destination, content: str) -> None:
        msg = LXMF.LXMessage(
            destination=fwdsvc_dst, source=src,
            content=content.encode("utf-8"), title=b"",
            desired_method=LXMF.LXMessage.DIRECT,
        )
        msg.try_propagation_on_fail = False
        router.handle_outbound(msg)

    print("[case] both peers /join")
    send_from(alice_router, alice_dst, "/join")
    time.sleep(2.0)
    send_from(bob_router, bob_dst, "/join")
    time.sleep(2.0)

    print("[case] alice sends a chat message")
    payload = "hello from alice — " + os.urandom(4).hex()
    send_from(alice_router, alice_dst, payload)

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        with bob_lock:
            for m in bob_inbox:
                text = m.content.decode("utf-8", errors="replace")
                if payload in text:
                    print(f"[case] bob got fanout: {text!r}")
                    print("[case] PASS")
                    return 0
        time.sleep(0.3)

    print(f"[case] FAIL: bob never received alice's message within {args.timeout}s",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[case] FAIL: {e!r}", file=sys.stderr)
        sys.exit(1)
