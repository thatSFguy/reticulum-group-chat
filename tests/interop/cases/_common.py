"""Shared scaffolding for interop case scripts.

Each case is a Python subprocess that:
  1. Brings up RNS with a TCPClientInterface to the harness rnsd
  2. Creates a fresh identity + registers an lxmf.delivery destination
  3. Waits until fwdsvc has announced (so we have its pubkey for encrypt)
  4. Sends commands and waits for replies
  5. Exits 0 on success, non-zero on failure

Cases import `setup()` and the `Peer` class below to avoid 100 lines of
RNS boilerplate per file.
"""

from __future__ import annotations
import argparse
import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import RNS
import LXMF


@dataclass
class Args:
    rnsd: str
    fwdsvc_hash: bytes
    timeout: float


def parse_args() -> Args:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rnsd", required=True, help="harness rnsd as host:port")
    ap.add_argument("--fwdsvc", required=True, help="fwdsvc delivery hash hex (32 chars)")
    ap.add_argument("--timeout", type=float, default=45.0,
                    help="overall case timeout in seconds")
    a = ap.parse_args()
    h = bytes.fromhex(a.fwdsvc)
    if len(h) != 16:
        print(f"--fwdsvc must be 16-byte hex (got {len(h)} bytes)", file=sys.stderr)
        sys.exit(2)
    return Args(rnsd=a.rnsd, fwdsvc_hash=h, timeout=a.timeout)


class Peer:
    """Thin LXMF peer: identity + delivery destination + send/recv hooks."""

    def __init__(self, args: Args, *, display_name: str = "interop-peer") -> None:
        self.args = args
        self.cfg_dir = _write_rns_config(args.rnsd)
        # LOG_INFO (4) is enough to see what's happening without flooding;
        # bump to 7 (LOG_EXTREME) when investigating a failed case.
        loglevel = int(os.environ.get("INTEROP_LOGLEVEL", "4"))
        RNS.Reticulum(self.cfg_dir, loglevel=loglevel)

        self.identity = RNS.Identity()
        storage = os.path.join(self.cfg_dir, "lxmf-storage")
        os.makedirs(storage, exist_ok=True)
        self.router = LXMF.LXMRouter(identity=self.identity, storagepath=storage)

        self._inbox: list[LXMF.LXMessage] = []
        self._inbox_lock = threading.Lock()

        self.delivery = self.router.register_delivery_identity(
            self.identity, display_name=display_name
        )
        self.router.register_delivery_callback(self._on_delivery)
        self.delivery.announce()

        # State.json for the current case run; useful when the harness
        # forwards stderr/stdout — caller knows which delivery hash is ours.
        print(f"[{display_name}] my delivery hash = {self.delivery.hash.hex()}",
              flush=True)

    def _on_delivery(self, message: LXMF.LXMessage) -> None:
        with self._inbox_lock:
            self._inbox.append(message)

    # ---- Public API used by case scripts ----

    def wait_for_fwdsvc(self) -> None:
        """Block until we know fwdsvc and fwdsvc almost certainly knows us.

        Two-way handshake:
          1. Wait until RNS.Identity.recall returns fwdsvc — proves we got
             their announce.
          2. Sleep `settle_secs` so our own announce, fired in __init__,
             has time to reach fwdsvc and be cached. Without this delay,
             our first command races fwdsvc's path? + retry path and gets
             dropped silently for OPPORTUNISTIC sends (which don't retry).

        Bounded by self.args.timeout.
        """
        h = self.args.fwdsvc_hash
        deadline = time.time() + self.args.timeout
        last_request = 0.0
        while time.time() < deadline:
            if RNS.Identity.recall(h) is not None:
                # Known on our side. Now give our announce ~3s to settle on
                # fwdsvc's side. This matches what a real client experiences
                # — the first command after a fresh start tends to race the
                # announce and our case shouldn't be more flaky than reality.
                time.sleep(3.0)
                return
            now = time.time()
            if now - last_request > 4:
                if not RNS.Transport.has_path(h):
                    RNS.Transport.request_path(h)
                last_request = now
            time.sleep(0.2)
        raise TimeoutError(f"fwdsvc {h.hex()} never announced within "
                           f"{self.args.timeout}s")

    def fwdsvc_destination(self) -> RNS.Destination:
        identity = RNS.Identity.recall(self.args.fwdsvc_hash)
        if identity is None:
            raise RuntimeError("call wait_for_fwdsvc() first")
        return RNS.Destination(
            identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
            "lxmf", "delivery",
        )

    def send_cmd(self, cmd: str, *, method: int = LXMF.LXMessage.DIRECT) -> None:
        """Send a single fwdsvc command (e.g. '/users') as an LXMF message."""
        msg = LXMF.LXMessage(
            destination=self.fwdsvc_destination(),
            source=self.delivery,
            content=cmd.encode("utf-8"),
            title=b"",
            desired_method=method,
        )
        msg.try_propagation_on_fail = False
        self.router.handle_outbound(msg)

    def wait_for_reply(self,
                       *,
                       match: Callable[[str], bool],
                       timeout: Optional[float] = None) -> str:
        """Block until an inbound LXMF whose decoded content satisfies match.

        Returns the matched content. Raises TimeoutError on overall budget.
        """
        deadline = time.time() + (timeout or self.args.timeout)
        seen = 0
        while time.time() < deadline:
            with self._inbox_lock:
                while seen < len(self._inbox):
                    m = self._inbox[seen]
                    seen += 1
                    text = m.content.decode("utf-8", errors="replace")
                    if match(text):
                        return text
            time.sleep(0.2)
        raise TimeoutError("no matching LXMF reply received")

    def shutdown(self) -> None:
        # LXMRouter spawns a background thread for delivery; RNS.Reticulum
        # has its own threads. There's no clean .stop() on the public API,
        # so let process exit handle it. This method is a placeholder for
        # cases that want to force-flush before exit.
        pass


def setup(*, display_name: str = "interop-peer") -> tuple[Args, Peer]:
    args = parse_args()
    peer = Peer(args, display_name=display_name)
    return args, peer


def _write_rns_config(rnsd: str) -> str:
    host, port = rnsd.rsplit(":", 1)
    cfg_dir = tempfile.mkdtemp(prefix="interop-rns-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(f"""[reticulum]
enable_transport = no
share_instance = no

[interfaces]

  [[Default Interface]]
    type = AutoInterface
    enabled = no

  [[harness]]
    type = TCPClientInterface
    enabled = yes
    target_host = {host}
    target_port = {port}
""")
    return cfg_dir
