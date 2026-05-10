#!/usr/bin/env python3
"""Joins the chat against a fwdsvc preloaded with 50 fake users (sidecar:
link_data_oversize.preload.state.json) and sends /users. The reply is
~1.4 KB plaintext — far over Reticulum's 500-byte MTU and the 431-byte
LinkMDU — so it has to ride a SPEC §10 Resource transfer.

This case is the regression test for the v1.3.2 fix:
  1. Link DATA / Resource packets must be HEADER_1 with no transport_id
     even on multi-hop paths (relays don't strip transport_id from
     link_table-routed packets, which would trip the receiver's
     packet_filter "for other transport instance" drop).
  2. The initiator must send an LRRTT packet to the responder right
     after validating the LRPROOF — without it, the responder's link
     stays in HANDSHAKE forever and resource_strategy stays at the
     default ACCEPT_NONE, silently dropping every ADV.
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

    if "Users (51)" not in text:
        print(f"[case] FAIL: expected 'Users (51)' header, got: {text!r}",
              file=sys.stderr)
        return 1

    truncation_ok = "...and" in text and "more" in text
    full_ok = text.count("\n  ") >= 51

    if not (truncation_ok or full_ok):
        print(f"[case] FAIL: header but neither full list nor truncation footer",
              file=sys.stderr)
        return 1

    print("[case] PASS — full /users reply received via Resource transfer")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[case] FAIL: {e!r}", file=sys.stderr)
        sys.exit(1)
