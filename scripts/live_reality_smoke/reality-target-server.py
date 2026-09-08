#!/usr/bin/env python3
"""Deterministic loopback TLS 1.3 ServerHello source for REALITY live smoke.

REALITY observes only the target's TLS 1.3 server-flight shape before constructing
its own accepted-path handshake.  This helper supplies a bounded local source for
that observation so the smoke harness does not depend on an Internet destination.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import struct
import sys
import threading


TLS_AES_256_GCM_SHA384 = 0x1302
TLS13_VERSION = b"\x03\x04"
NAMED_GROUP_X25519 = 0x001D


def u16(value: int) -> bytes:
    return struct.pack("!H", value)


def build_server_hello() -> bytes:
    key_share = (
        u16(NAMED_GROUP_X25519)
        + u16(32)
        + bytes([0x22] * 32)
    )
    extensions = (
        u16(0x002B) + u16(len(TLS13_VERSION)) + TLS13_VERSION
        + u16(0x0033) + u16(len(key_share)) + key_share
    )
    body = (
        b"\x03\x03"
        + bytes([0x11] * 32)
        + b"\x00"
        + u16(TLS_AES_256_GCM_SHA384)
        + b"\x00"
        + u16(len(extensions))
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + u16(len(handshake)) + handshake


def serve_connection(conn: socket.socket, context: ssl.SSLContext) -> None:
    with conn:
        conn.settimeout(2.0)
        try:
            with context.wrap_socket(conn, server_side=True):
                pass
        except (OSError, ssl.SSLError):
            # REALITY observes the server flight and then closes its target socket.
            pass


def recv_exact(conn: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    while length:
        chunk = conn.recv(length)
        if not chunk:
            break
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def serve_minimal_connection(conn: socket.socket) -> None:
    with conn:
        try:
            header = recv_exact(conn, 5)
            if len(header) == 5 and header[0] == 0x16:
                recv_exact(conn, int.from_bytes(header[3:5], "big"))
                conn.sendall(build_server_hello())
        except OSError:
            pass


def serve(port: int, mode: str, cert: str | None, key: str | None) -> None:
    context: ssl.SSLContext | None = None
    if mode == "full":
        if not cert or not key:
            raise ValueError("full target mode requires --cert and --key")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certfile=cert, keyfile=key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(64)
        print(f"REALITY target listening on 127.0.0.1:{port}", flush=True)
        while True:
            conn, _ = listener.accept()
            if context is None:
                threading.Thread(
                    target=serve_minimal_connection, args=(conn,), daemon=True
                ).start()
                continue
            threading.Thread(
                target=serve_connection, args=(conn, context), daemon=True
            ).start()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--mode", choices=("minimal", "full"), default="minimal")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    args = parser.parse_args()
    serve(args.port, args.mode, args.cert, args.key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
