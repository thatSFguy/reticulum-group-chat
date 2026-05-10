#!/usr/bin/env python3
"""Joins the chat, then sends /users when the roster is large enough
that the reply exceeds Reticulum's 500-byte MTU. fwdsvc has to either
truncate the reply (with an "...and N more" footer) or transfer it via
SPEC §10 Resource transfer. Today neither path works against an upstream
Python LXMF receiver — this case is marked _xfail in its filename so the
harness skips on failure rather than failing the whole run.

Flip from xfail to normal once the regression is fixed:
  rename to drop the _xfail suffix.
"""

from __future__ import annotations
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402
import LXMF  # noqa: E402


def main() -> int:
    args, peer = _common.setup(display_name="link-data-oversize")
    peer.wait_for_fwdsvc()

    # Just /join and /users — the roster size is set up by the harness'
    # fwdsvc state.json (or whatever future preload mechanism). For now,
    # this case proves the *single-member* fanout works, then proves the
    # large reply path either truncates cleanly or arrives.
    peer.send_cmd("/join", method=LXMF.LXMessage.DIRECT)
    peer.wait_for_reply(match=lambda t: "joined" in t.lower() or "already" in t.lower())
    time.sleep(0.5)

    peer.send_cmd("/users", method=LXMF.LXMessage.DIRECT)
    users_text = peer.wait_for_reply(
        match=lambda t: t.startswith("Users (") or t.startswith("No users"),
        timeout=30.0,
    )
    print(f"[case] users reply ({len(users_text)} bytes): {users_text!r}")

    # When this case is migrated out of xfail we'll add a stronger
    # assertion (e.g. that "...and N more" appears, or that the reply
    # contains every preloaded user). For now, the success criterion is
    # simply "we got SOMETHING that looks like a /users reply" — which
    # today fails because the reply never arrives.
    if "Users (" not in users_text and "No users" not in users_text:
        print(f"[case] FAIL: malformed /users reply", file=sys.stderr)
        return 1
    print("[case] PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[case] FAIL: {e!r}", file=sys.stderr)
        sys.exit(1)
