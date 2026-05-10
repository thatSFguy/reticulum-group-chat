#!/usr/bin/env python3
"""Minimal upstream-LXMF receiver that joins fwdsvc, sends /users, and
verifies the Resource-transfer reply lands intact. Pinned diagnostic
for the resource-transfer branch — if THIS receiver doesn't get the
Resource, the bug is in fwdsvc; if it does, it's Sideband-side.

Usage:
  python python_lxmf_receiver.py <fwdsvc-delivery-hash-hex> [--rnsd rns.chicagonomad.net:4242]

The script will:
  1. Bring up RNS with a TCP client interface to the named transport.
  2. Create a fresh identity, register an lxmf.delivery destination,
     announce it.
  3. Wait until the fwdsvc delivery destination is known (announce
     received).
  4. Send /join, then /users.
  5. Print every Resource event + the final reply body.

Pins what's broken: if step 5 sees the full /users reply, fwdsvc's
Resource sender works against upstream RNS — the bug then would be
Sideband-specific. If step 5 hangs / no reply, the bug is in our
sender code path.
"""

from __future__ import annotations
import argparse, sys, time, threading

import RNS
import LXMF


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("fwdsvc_hash", help="hex of the fwdsvc lxmf.delivery destination")
    ap.add_argument("--rnsd", default="rns.chicagonomad.net:4242",
                    help="TCP transport peer (host:port)")
    ap.add_argument("--config-dir", default=None,
                    help="Reticulum config dir; default = ephemeral tempdir")
    ap.add_argument("--timeout", type=int, default=180,
                    help="seconds to wait for /users reply before giving up")
    args = ap.parse_args()

    fwdsvc_hash = bytes.fromhex(args.fwdsvc_hash)
    if len(fwdsvc_hash) != 16:
        print(f"fwdsvc hash must be 16 bytes (got {len(fwdsvc_hash)})", file=sys.stderr)
        return 2

    # Bring up RNS with explicit config so we don't pollute the user's
    # default. tempdir keeps it ephemeral.
    import tempfile, os
    cfg_dir = args.config_dir or tempfile.mkdtemp(prefix="lxmf-recv-")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, "config")
    if not os.path.exists(cfg_path):
        host, port = args.rnsd.split(":")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(f"""[reticulum]
enable_transport = no
share_instance = no

[interfaces]

  [[Default Interface]]
    type = AutoInterface
    enabled = no

  [[chicagonomad]]
    type = TCPClientInterface
    enabled = yes
    target_host = {host}
    target_port = {port}
""")
    # LOG_EXTREME = 7 in RNS — we want every resource decoding step
    # so we can see whether our ADV decrypts and parses or fails silently.
    RNS.Reticulum(cfg_dir, loglevel=7)

    # Identity + LXMF router + delivery destination.
    id_path = os.path.join(cfg_dir, "identity")
    if os.path.exists(id_path):
        identity = RNS.Identity.from_file(id_path)
    else:
        identity = RNS.Identity()
        identity.to_file(id_path)
    print(f"[recv] my identity hash = {identity.hash.hex()}")

    storage_path = os.path.join(cfg_dir, "storage")
    os.makedirs(storage_path, exist_ok=True)
    lxmrouter = LXMF.LXMRouter(identity=identity, storagepath=storage_path)

    received: dict = {"messages": []}
    received_lock = threading.Lock()

    def on_delivery(message: LXMF.LXMessage) -> None:
        try:
            content = message.content.decode("utf-8", errors="replace")
        except Exception:
            content = repr(message.content)
        print(f"[recv] LXMF delivered: src={message.source_hash.hex()} bytes={len(message.content)}")
        print("--- BEGIN BODY ---")
        print(content)
        print("--- END BODY ---", flush=True)
        with received_lock:
            received["messages"].append(content)

    delivery_dst = lxmrouter.register_delivery_identity(identity, display_name="lxmf-recv-test")
    lxmrouter.register_delivery_callback(on_delivery)
    delivery_dst.announce()
    print(f"[recv] my lxmf.delivery hash = {delivery_dst.hash.hex()}")

    # Wait until fwdsvc destination is known (we received their
    # announce). Then we have the public keys to LXMF-send to them.
    print(f"[recv] waiting for fwdsvc {fwdsvc_hash.hex()} to become known...")
    deadline = time.time() + 60
    while time.time() < deadline:
        if RNS.Identity.recall(fwdsvc_hash):
            print(f"[recv] fwdsvc identity recalled.")
            break
        if not RNS.Transport.has_path(fwdsvc_hash):
            RNS.Transport.request_path(fwdsvc_hash)
        time.sleep(2)
    else:
        print("[recv] timed out waiting for fwdsvc identity", file=sys.stderr)
        return 3

    fwdsvc_identity = RNS.Identity.recall(fwdsvc_hash)
    fwdsvc_dst = RNS.Destination(
        fwdsvc_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "lxmf", "delivery",
    )

    def send_cmd(cmd: str) -> None:
        print(f"[recv] sending {cmd!r} -> fwdsvc")
        msg = LXMF.LXMessage(
            destination=fwdsvc_dst,
            source=delivery_dst,
            content=cmd.encode("utf-8"),
            title=b"",
            desired_method=LXMF.LXMessage.DIRECT,
        )
        msg.try_propagation_on_fail = False
        lxmrouter.handle_outbound(msg)

    # Get into the chat so /users responds with the user list.
    send_cmd("/join")
    time.sleep(2)
    send_cmd("/users")

    print(f"[recv] waiting up to {args.timeout}s for /users reply...")
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        with received_lock:
            for m in received["messages"]:
                if "Users (" in m:
                    print("[recv] SUCCESS — /users reply received")
                    return 0
        time.sleep(1)

    print("[recv] FAILED — no /users reply within timeout", file=sys.stderr)
    return 4


if __name__ == "__main__":
    sys.exit(main())
