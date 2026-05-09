#!/usr/bin/env python
"""
Live command tester. Brings up a minimal RNS+LXMF client that connects
to the same TCP entry node our running fwdsvc connects to, then sends
each LXMF command against the service's delivery destination and
records whether a reply arrives.

Purpose: definitively isolate whether broken commands are bugs in our
service vs flakiness in a specific peer (e.g. Sideband on someone's
device). Upstream Python LXMF is the authoritative client; if it
can't get a reply either, the bug is on our side.

Usage:
    python tests/interop/live_command_test.py \
        --entry rns.michmesh.net:7822 \
        --service e00caf0cbe412b3a3ee3e5f2c1fa9344

Each command is sent once, with a 90 s wait for reply. Output is one
line per command: PASS / FAIL / NO_REPLY plus a snippet of the reply
content when one arrives.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import threading
import time

import RNS
import LXMF


COMMANDS = [
    "/?",
    "/users",
    "/mods",
    "/admin",
    "/join",
    "/nick livetest",
    "/leave",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--entry", default="rns.michmesh.net:7822",
                    help="TCP entry node host:port (must match the service's interface)")
    ap.add_argument("--service", required=True,
                    help="Service delivery destination hash (32 hex chars)")
    ap.add_argument("--service-identity-file", default=None,
                    help="Path to the service's binary identity file. If set, the test loads it directly instead of waiting for an announce — useful when the test runs on the same machine as the service.")
    ap.add_argument("--reply-timeout", type=float, default=90.0,
                    help="Seconds to wait for each command's reply (default 90)")
    ap.add_argument("--service-announce-timeout", type=float, default=60.0,
                    help="Seconds to wait for the service's announce on startup")
    args = ap.parse_args()

    service_hash = bytes.fromhex(args.service)
    if len(service_hash) != 16:
        print(f"--service must be 32 hex chars, got {len(args.service)}", file=sys.stderr)
        return 2
    host, port = args.entry.split(":")

    # Fresh RNS state per run so we don't reuse a stale identity that the
    # service may have learned about already.
    state_dir = tempfile.mkdtemp(prefix="livetest-rns-")
    config = (
        "[reticulum]\n"
        "enable_transport = no\n"
        "share_instance = no\n"
        "[interfaces]\n"
        "[[live entry]]\n"
        "type = TCPClientInterface\n"
        f"target_host = {host}\n"
        f"target_port = {port}\n"
    )
    with open(os.path.join(state_dir, "config"), "w") as f:
        f.write(config)
    print(f"# state_dir = {state_dir}")

    reticulum = RNS.Reticulum(configdir=state_dir, loglevel=RNS.LOG_NOTICE)

    identity = RNS.Identity()
    print(f"# tester identity hash = {RNS.prettyhexrep(identity.hash)}")

    storagepath = os.path.join(state_dir, "lxmf")
    os.makedirs(storagepath, exist_ok=True)
    router = LXMF.LXMRouter(identity=identity, storagepath=storagepath)

    local_delivery = router.register_delivery_identity(identity, display_name="livetest")
    local_delivery.announce()
    print(f"# tester delivery_dest = {RNS.prettyhexrep(local_delivery.hash)}")

    # Reply rendezvous: callback drops every received LXMessage onto the
    # current 'pending_reply' single-slot queue. Cleared between
    # commands so a stray late reply for command N+1 doesn't corrupt
    # command N+2.
    state = {"reply": None, "lock": threading.Lock(), "event": threading.Event()}

    def on_inbound(lxm: "LXMF.LXMessage") -> None:
        with state["lock"]:
            state["reply"] = {
                "source": lxm.source_hash,
                "title": (lxm.title_as_string() if lxm.title else ""),
                "content": lxm.content_as_string() if lxm.content else "",
                "method": lxm.method,
            }
            state["event"].set()

    router.register_delivery_callback(on_inbound)

    # Resolve the service identity. Two paths:
    #   - --service-identity-file: read the binary identity directly. Fast.
    #   - default: wait for the service's announce (or path-response).
    service_identity = None
    if args.service_identity_file:
        with open(args.service_identity_file, "rb") as f:
            priv = f.read()
        if len(priv) != 64:
            print(f"identity file must be 64 bytes, got {len(priv)}", file=sys.stderr)
            return 2
        service_identity = RNS.Identity(create_keys=False)
        service_identity.load_private_key(priv)
        derived_dest = RNS.Destination.hash_from_name_and_identity(
            "lxmf.delivery", service_identity)
        if derived_dest != service_hash:
            print(f"identity file's lxmf.delivery dest = {derived_dest.hex()}, "
                  f"but --service = {args.service}. Mismatch.", file=sys.stderr)
            return 2
        # Seed RNS.Identity.known_destinations directly so Packet.send can
        # encrypt opportunistically without waiting for an announce. The
        # tuple shape matches RNS internals: (timestamp, packet_hash,
        # public_key, app_data). We don't have a real packet_hash so use
        # a placeholder; RNS only checks it for dedup, not correctness.
        RNS.Identity.known_destinations[service_hash] = (
            time.time(), bytes(16), service_identity.get_public_key(), b"")
        print(f"# service identity loaded from {args.service_identity_file} and seeded into known_destinations")
        # Also fire an explicit path? request so we get a path table entry.
        RNS.Transport.request_path(service_hash)
        path_deadline = time.time() + 30.0
        while time.time() < path_deadline:
            if RNS.Transport.has_path(service_hash):
                break
            time.sleep(1.0)
        if RNS.Transport.has_path(service_hash):
            print("# path to service known")
        else:
            print("# WARNING: no path to service yet; sends may queue or drop")
    else:
        print(f"# waiting up to {args.service_announce_timeout}s for service announce …")
        deadline = time.time() + args.service_announce_timeout
        while time.time() < deadline:
            service_identity = RNS.Identity.recall(service_hash)
            if service_identity is not None:
                break
            time.sleep(1.0)
        if service_identity is None:
            print("# no announce yet, requesting path")
            RNS.Transport.request_path(service_hash)
            deadline = time.time() + 30.0
            while time.time() < deadline:
                service_identity = RNS.Identity.recall(service_hash)
                if service_identity is not None:
                    break
                time.sleep(1.0)
        if service_identity is None:
            print(f"FAIL: never learned service identity for {args.service} within timeout", file=sys.stderr)
            return 1

    print(f"# service identity hash: {RNS.prettyhexrep(service_identity.hash)}")
    service_dest = RNS.Destination(
        service_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery",
    )

    summary: list[tuple[str, str, str]] = []
    for cmd in COMMANDS:
        print(f"\n=== {cmd} ===")
        with state["lock"]:
            state["reply"] = None
            state["event"].clear()

        lxm = LXMF.LXMessage(
            destination=service_dest,
            source=local_delivery,
            content=cmd,
            title="",
            desired_method=LXMF.LXMessage.OPPORTUNISTIC,
        )
        # The router will auto-downgrade large bodies from OPPORTUNISTIC
        # to DIRECT at pack time per LXMessage.pack:394-398.
        router.handle_outbound(lxm)
        send_t = time.time()

        got = state["event"].wait(timeout=args.reply_timeout)
        elapsed = time.time() - send_t
        if not got:
            print(f"NO_REPLY after {elapsed:.1f}s")
            summary.append((cmd, "NO_REPLY", f"{elapsed:.1f}s"))
            continue

        with state["lock"]:
            r = state["reply"]
        method_name = {
            LXMF.LXMessage.OPPORTUNISTIC: "OPPORTUNISTIC",
            LXMF.LXMessage.DIRECT: "DIRECT",
            LXMF.LXMessage.PROPAGATED: "PROPAGATED",
        }.get(r["method"], f"unknown({r['method']})")
        snippet = r["content"][:120].replace("\n", " ⏎ ")
        print(f"PASS in {elapsed:.1f}s via {method_name} ({len(r['content'])} bytes): {snippet}")
        summary.append((cmd, "PASS", f"{elapsed:.1f}s {method_name} {len(r['content'])}b"))

    print("\n=== Summary ===")
    for cmd, result, info in summary:
        print(f"  {result:<8} {cmd:<20} {info}")

    fails = [s for s in summary if s[1] != "PASS"]
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
