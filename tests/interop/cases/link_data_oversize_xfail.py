#!/usr/bin/env python3
"""Sends /users when fwdsvc has a 50-user roster preloaded (sidecar:
link_data_oversize_xfail.preload.state.json). The reply is ~1.4 KB
plaintext — well over Reticulum's 500-byte MTU and the 431-byte
LinkMDU — so it can't fit in a single link DATA packet.

Today this case fails: the v1.3.1 daemon emits one oversize link DATA
packet, the receiver (or some hop's MTU-enforcing code) drops it, no
proof comes back, the case times out. Marked _xfail so the harness
skips on failure rather than failing CI.

When the underlying fix lands (either MaxReplyContentBytes cap so the
reply truncates with '...and N more', or working Resource transfer),
rename this file to drop the _xfail suffix and the harness will start
treating failure as a real test failure.
"""

from __future__ import annotations
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402
import LXMF  # noqa: E402


def main() -> int:
    args, peer = _common.setup(display_name="users-oversize")
    peer.wait_for_fwdsvc()

    # /join so the case peer becomes user 51 (preload has 50, we add one).
    print("[case] sending /join")
    peer.send_cmd("/join", method=LXMF.LXMessage.DIRECT)
    peer.wait_for_reply(match=lambda t: "joined" in t.lower() or "already" in t.lower())
    time.sleep(0.5)

    print("[case] sending /users (expects 51-user reply, ~1.4KB plaintext)")
    peer.send_cmd("/users", method=LXMF.LXMessage.DIRECT)
    text = peer.wait_for_reply(
        match=lambda t: t.startswith("Users (") or t.startswith("No users"),
        timeout=30.0,
    )
    print(f"[case] users reply ({len(text)} bytes): {text[:200]!r}...")

    # Two possible "fix landed" outcomes:
    #   (a) Full reply: header says "Users (51)" and at least 51 lines arrived.
    #   (b) Truncated cleanly: header says "Users (51)" and reply ends with
    #       "...and N more (see operator log)" — short list but not an error.
    # Either way, the case PASSES once we get a syntactically-correct reply
    # whose header matches the actual roster size.
    if "Users (51)" not in text:
        print(f"[case] FAIL: expected 'Users (51)' header, got: {text!r}",
              file=sys.stderr)
        return 1

    truncation_ok = "...and" in text and "more" in text
    full_ok = text.count("\n  ") >= 51

    if not (truncation_ok or full_ok):
        print(f"[case] FAIL: reply has wrong header but neither full list "
              f"nor truncation footer: {text!r}", file=sys.stderr)
        return 1

    print("[case] PASS — reply arrived and structure is valid")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[case] FAIL: {e!r}", file=sys.stderr)
        sys.exit(1)
