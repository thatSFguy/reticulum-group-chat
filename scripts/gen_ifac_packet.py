"""IFAC-sealed packet helper.

Two modes:

  default (no args)
    Print one JSON blob to stdout containing:
      {
        "unsealed_hex":    "<hex of unsealed packet>",
        "ifac_sealed_hex": "<hex of same packet after IFAC sealing>",
        "ifac_size":       16
      }
    Used by internal/rns/packet_ifac_interop_test.go for byte-level
    interop testing (build tag: interop_python).

  --serve PORT
    Bind 127.0.0.1:PORT, accept one inbound TCP connection, and ship a
    single HDLC-framed IFAC-sealed Reticulum packet down the wire. Stays
    alive after sending so the peer's read loop has time to process the
    frame before the connection drops. Used by scripts/live_ifac_test.sh
    to drive the forwarding service end-to-end.

The IFAC sealing logic in both modes is verbatim from upstream
RNS/Transport.py:993-1024 (RNS 1.2.0).
"""
import argparse
import json
import os
import socket
import sys
import tempfile
import time

import RNS


HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_ESC_MASK = 0x20


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-ifac-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def build_unsealed_packet():
    # Hand-built HEADER_1 DATA packet: flags(1) hops(1) dest(16) ctx(1) data.
    flag = (RNS.Packet.HEADER_1 << 6) | (RNS.Destination.SINGLE << 2) | RNS.Packet.DATA
    dest_hash = bytes(range(16))
    return bytes([flag, 0]) + dest_hash + b"\x00" + b"hello-from-python-ifac-test"


def ifac_seal(raw, ifac_size=16):
    """Apply upstream RNS Transport.transmit IFAC sealing (lines 993-1024).

    Returns the sealed wire bytes. The IFAC flag (bit 7 of byte 0) is
    forced ON even after masking, per line 1013 — that's the bit our
    parser checks.
    """
    ifac_identity = RNS.Identity()
    ifac_key = os.urandom(32)

    ifac = ifac_identity.sign(raw)[-ifac_size:]
    mask = RNS.Cryptography.hkdf(
        length=len(raw) + ifac_size,
        derive_from=ifac,
        salt=ifac_key,
        context=None,
    )
    new_header = bytes([raw[0] | 0x80, raw[1]])
    new_raw = new_header + ifac + raw[2:]

    out = bytearray()
    for i, byte in enumerate(new_raw):
        if i == 0:
            out.append((byte ^ mask[i]) | 0x80)  # IFAC flag stays set
        elif i == 1 or i > ifac_size + 1:
            out.append(byte ^ mask[i])
        else:
            out.append(byte)  # IFAC bytes themselves are not masked
    return bytes(out)


def hdlc_frame(packet):
    out = bytearray([HDLC_FLAG])
    for b in packet:
        if b == HDLC_FLAG or b == HDLC_ESC:
            out.append(HDLC_ESC)
            out.append(b ^ HDLC_ESC_MASK)
        else:
            out.append(b)
    out.append(HDLC_FLAG)
    return bytes(out)


def emit_json():
    raw = build_unsealed_packet()
    sealed = ifac_seal(raw)

    if not (sealed[0] & 0x80):
        print("BUG: sealed[0] has no IFAC bit", file=sys.stderr)
        sys.exit(2)
    if raw[0] & 0x80:
        print("BUG: unsealed[0] has IFAC bit", file=sys.stderr)
        sys.exit(2)

    print(json.dumps({
        "unsealed_hex": raw.hex(),
        "ifac_sealed_hex": sealed.hex(),
        "ifac_size": 16,
    }))


def serve(port):
    raw = build_unsealed_packet()
    sealed = ifac_seal(raw)
    framed = hdlc_frame(sealed)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    print(f"ifac emitter: listening on 127.0.0.1:{port}", flush=True)

    conn, addr = sock.accept()
    print(f"ifac emitter: peer connected from {addr}", flush=True)
    print(f"ifac emitter: sending {len(framed)} HDLC bytes (sealed packet first byte 0x{sealed[0]:02x}, IFAC bit={'1' if sealed[0]&0x80 else '0'})", flush=True)
    conn.sendall(framed)
    print("ifac emitter: packet sent, idling for 30s", flush=True)
    # Idle so the peer has time to read and log before the connection
    # drops. The peer can close at will; we treat that as success.
    conn.settimeout(30.0)
    try:
        conn.recv(1)
    except (socket.timeout, ConnectionResetError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        sock.close()
    print("ifac emitter: done", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", type=int, metavar="PORT",
                        help="serve mode: bind 127.0.0.1:PORT, ship one IFAC-sealed HDLC frame on connect")
    args = parser.parse_args()

    init_minimal_rns()

    if args.serve is not None:
        serve(args.serve)
    else:
        emit_json()


if __name__ == "__main__":
    main()
