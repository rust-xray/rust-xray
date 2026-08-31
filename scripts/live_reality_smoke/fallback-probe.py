#!/usr/bin/env python3
"""Probe rust-xray VLESS fallback selection over TLS and return backend marker."""

from __future__ import annotations

import socket
import ssl
import sys


def probe_http_path(port: int, path: str = "/smoke-path") -> str:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        request = f"GET {path} HTTP/1.1\r\nHost: smoke.local\r\n\r\n"
        sock.sendall(request.encode("ascii"))
        data = b""
        sock.settimeout(3.0)
        while len(data) < 4096:
            chunk = sock.recv(256)
            if not chunk:
                break
            data += chunk
            if b"FB-" in data:
                break
    except (TimeoutError, OSError):
        pass
    finally:
        sock.close()

    payload = data.decode("utf-8", errors="ignore")
    for line in payload.replace("\r", "\n").split("\n"):
        line = line.strip()
        if line.startswith("FB-"):
            return line
    return payload.strip().split("\n")[0] if payload.strip() else ""


def probe(server_name: str, port: int, alpn: str | None = None) -> str:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols([part.strip() for part in alpn.split(",") if part.strip()])

    tls = ctx.wrap_socket(
        sock,
        server_hostname=server_name,
        do_handshake_on_connect=False,
    )
    try:
        tls.do_handshake()
    except ssl.SSLError:
        pass

    data = b""
    try:
        tls.settimeout(3.0)
        while len(data) < 4096:
            chunk = tls.recv(256)
            if not chunk:
                break
            data += chunk
            if b"FB-" in data:
                break
    except (TimeoutError, ssl.SSLError, OSError):
        pass

    payload = data.decode("utf-8", errors="ignore")
    for line in payload.replace("\r", "\n").split("\n"):
        line = line.strip()
        if line.startswith("FB-"):
            return line
    return payload.strip().split("\n")[0] if payload.strip() else ""


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "http":
        if len(sys.argv) not in (3, 4):
            print(
                "usage: fallback-probe.py http <port> [path]",
                file=sys.stderr,
            )
            return 2
        path = sys.argv[3] if len(sys.argv) == 4 else "/smoke-path"
        print(probe_http_path(int(sys.argv[2]), path))
        return 0

    if len(sys.argv) not in (3, 4):
        print(
            "usage: fallback-probe.py <server_name> <port> [alpn]\n"
            "       fallback-probe.py http <port> [path]",
            file=sys.stderr,
        )
        return 2
    alpn = sys.argv[3] if len(sys.argv) == 4 else None
    print(probe(sys.argv[1], int(sys.argv[2]), alpn))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
