#!/usr/bin/env python3
"""Sends /version, expects a single-packet opportunistic LXMF reply with
the running fwdsvc version + repo URL. Reply is ~80 bytes, well under
the 295-byte opportunistic msgpack cap, so it never opens a Link.

Pinned regression: this exercises the simplest path. If this case fails,
something fundamental is broken (announce / encrypt / Token decrypt).
"""

from __future__ import annotations
import sys

# Add cases/ to the import path so _common is importable regardless of
# whether `python` was invoked from the repo root or the cases dir.
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402
import LXMF  # noqa: E402


def main() -> int:
    args, peer = _common.setup(display_name="opportunistic-short")
    print(f"[case] waiting for fwdsvc {args.fwdsvc_hash.hex()} announce...")
    peer.wait_for_fwdsvc()

    print("[case] sending /version")
    peer.send_cmd("/version", method=LXMF.LXMessage.OPPORTUNISTIC)

    text = peer.wait_for_reply(
        match=lambda t: "fwdsvc" in t.lower() and "github.com" in t.lower(),
    )
    print(f"[case] got reply: {text!r}")
    print("[case] PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[case] FAIL: {e!r}", file=sys.stderr)
        sys.exit(1)
