#!/usr/bin/env python3
"""Local REALITY dest servers that force a single TLS 1.3 cipher suite each.

Each listener accepts the forwarded ClientHello and replies with a minimal TLS 1.3
ServerHello containing X25519 key_share so rust-xray can observe the cipher suite.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
from typing import Iterable

EXTENSION_SUPPORTED_VERSIONS = 0x002B
EXTENSION_KEY_SHARE = 0x0033
NAMED_GROUP_X25519 = 0x001D
TLS13_VERSION = b"\x03\x04"
X25519_KEY_LEN = 32

TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303

SERVERS = [
    (19601, TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"),
    (19602, TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"),
    (19603, TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"),
]


def u16(value: int) -> bytes:
    return struct.pack("!H", value)


def u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def build_extension(extension_type: int, body: bytes) -> bytes:
    return u16(extension_type) + u16(len(body)) + body


def x25519_key_share(key_exchange: bytes) -> bytes:
    return u16(NAMED_GROUP_X25519) + u16(len(key_exchange)) + key_exchange


def build_server_hello_handshake(cipher_suite: int) -> bytes:
    random = bytes([0x11] * 32)
    key_exchange = bytes([0x22] * X25519_KEY_LEN)
    extensions = b"".join(
        [
            build_extension(EXTENSION_SUPPORTED_VERSIONS, TLS13_VERSION),
            build_extension(EXTENSION_KEY_SHARE, x25519_key_share(key_exchange)),
        ]
    )

    body = (
        b"\x03\x03"
        + random
        + b"\x00"
        + u16(cipher_suite)
        + b"\x00"
        + u16(len(extensions))
        + extensions
    )
    return b"\x02" + u24(len(body)) + body


def build_tls_handshake_record(handshake_message: bytes) -> bytes:
    return b"\x16\x03\x03" + u16(len(handshake_message)) + handshake_message


def read_client_hello_record(conn: socket.socket) -> None:
    header = _recv_exact(conn, 5)
    if len(header) != 5:
        return
    content_type, _legacy_version, payload_len = struct.unpack("!B2sH", header)
    if content_type != 0x16:
        return
    _recv_exact(conn, payload_len)


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve(port: int, cipher_suite: int, suite_name: str) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(64)
    print(
        f"started cipher dest {suite_name} on 127.0.0.1:{port}",
        flush=True,
    )

    while True:
        conn, _addr = listener.accept()
        with conn:
            try:
                read_client_hello_record(conn)
                record = build_tls_handshake_record(
                    build_server_hello_handshake(cipher_suite)
                )
                conn.sendall(record)
            except OSError as err:
                print(f"port {port}: connection error: {err}", file=sys.stderr, flush=True)


def start_servers(specs: Iterable[tuple[int, int, str]]) -> None:
    for port, cipher_suite, suite_name in specs:
        thread = threading.Thread(
            target=serve,
            args=(port, cipher_suite, suite_name),
            daemon=True,
        )
        thread.start()


def main() -> int:
    start_servers(SERVERS)
    print("cipher TLS dest servers listening on 19601-19603", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
