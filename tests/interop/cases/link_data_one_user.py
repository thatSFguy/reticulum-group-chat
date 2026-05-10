#!/usr/bin/env python3
"""Joins the chat (becoming the sole member), then sends /users and
expects the reply to come back over a Reticulum Link as a single
in-MTU link DATA packet.

Why DIRECT (not OPPORTUNISTIC) for /users: the reply is ~30 bytes for
a one-user roster, but fwdsvc serializes its commands to use the link
path whenever the caller's outbound LXMF was DIRECT. This case exercises
the LRREQ -> LRPROOF -> link DATA path that the operator's deployment
relies on for /users replies.
"""

from __future__ import annotations
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402
import LXMF  # noqa: E402


def main() -> int:
    args, peer = _common.setup(display_name="link-data-one-user")
    peer.wait_for_fwdsvc()

    print("[case] sending /join (DIRECT)")
    peer.send_cmd("/join", method=LXMF.LXMessage.DIRECT)
    join_text = peer.wait_for_reply(
        match=lambda t: "joined" in t.lower() or "already" in t.lower(),
    )
    print(f"[case] join reply: {join_text!r}")

    # Small settle so the join's roster persistence can flush before
    # we ask for /users — racing the persist write with the read could
    # give a 0-user list back even though our /join just succeeded.
    time.sleep(0.5)

    print("[case] sending /users (DIRECT)")
    peer.send_cmd("/users", method=LXMF.LXMessage.DIRECT)
    users_text = peer.wait_for_reply(
        match=lambda t: t.startswith("Users (") or t.startswith("No users"),
    )
    print(f"[case] users reply: {users_text!r}")

    if "Users (1)" not in users_text:
        print(f"[case] FAIL: expected 'Users (1)' header in reply, got {users_text!r}",
              file=sys.stderr)
        return 1
    print("[case] PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[case] FAIL: {e!r}", file=sys.stderr)
        sys.exit(1)
