#!/usr/bin/env python3
"""Capture exactly one TLS handshake record from a single TCP connection.

Stdlib only. The captor is not a TLS server; it saves raw bytes and exits.
"""

from __future__ import annotations

import argparse
import socket
import sys

TLS_CONTENT_TYPE_HANDSHAKE = 0x16
RECORD_HEADER_LEN = 5
MAX_RECORD_PAYLOAD = 16_384


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Listen for one TCP connection, read one complete TLS record, "
            "validate content type 0x16 (handshake), and write it to --out."
        )
    )
    parser.add_argument(
        "--listen",
        required=True,
        help="Listen address, e.g. 127.0.0.1:24443",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output file path for the captured TLS record bytes",
    )
    return parser.parse_args()


def parse_listen(listen: str) -> tuple[str, int]:
    if listen.count(":") != 1:
        raise ValueError(f"invalid --listen address (expected host:port): {listen!r}")
    host, port_str = listen.split(":", 1)
    return host, int(port_str, 10)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    received = 0
    while received < size:
        chunk = sock.recv(size - received)
        if not chunk:
            raise EOFError(
                f"connection closed after {received} bytes, expected {size}"
            )
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def read_one_tls_record(sock: socket.socket) -> bytes:
    header = recv_exact(sock, RECORD_HEADER_LEN)
    content_type = header[0]
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE:
        raise ValueError(
            "expected TLS handshake record (content_type=0x16), "
            f"got 0x{content_type:02x}"
        )

    payload_len = int.from_bytes(header[3:5], "big")
    if payload_len > MAX_RECORD_PAYLOAD:
        raise ValueError(f"TLS record payload too large: {payload_len}")

    payload = recv_exact(sock, payload_len)
    return header + payload


def main() -> int:
    args = parse_args()

    try:
        host, port = parse_listen(args.listen)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(1)
            print(
                f"listening on {host}:{port}, waiting for one connection...",
                file=sys.stderr,
            )

            conn, addr = server.accept()
            with conn:
                print(
                    f"accepted connection from {addr[0]}:{addr[1]}",
                    file=sys.stderr,
                )
                record = read_one_tls_record(conn)
    except OSError as err:
        print(f"error: socket failure: {err}", file=sys.stderr)
        return 1
    except (EOFError, ValueError) as err:
        print(f"error: failed to capture TLS record: {err}", file=sys.stderr)
        return 1

    try:
        with open(args.out, "wb") as out_file:
            out_file.write(record)
    except OSError as err:
        print(f"error: failed to write {args.out}: {err}", file=sys.stderr)
        return 1

    print(f"wrote {len(record)} bytes to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
