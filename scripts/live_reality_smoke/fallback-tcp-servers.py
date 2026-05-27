#!/usr/bin/env python3
"""Local TCP listeners for VLESS fallback live smoke phases."""

from __future__ import annotations

import os
import socket
import sys
import threading
from pathlib import Path

PROXY_V2_SIGNATURE = bytes(
    [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]
)


def write_hit(port: int, suffix: str = "") -> None:
    hit_dir = os.environ.get("SMOKE_FALLBACK_HIT_DIR")
    if not hit_dir:
        print("error: SMOKE_FALLBACK_HIT_DIR is not set", file=sys.stderr)
        raise SystemExit(1)
    path = Path(hit_dir) / f"{port}{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("ok\n", encoding="utf-8")


def serve(port: int, expect_proxy: str | None = None) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", port))
    except OSError as err:
        print(f"port {port}: bind failed: {err}", file=sys.stderr, flush=True)
        raise
    listener.listen(32)
    print(f"started fallback dest on 127.0.0.1:{port}", flush=True)

    while True:
        conn, _addr = listener.accept()
        with conn:
            data = conn.recv(4096)
            if expect_proxy == "v1":
                if not data.startswith(b"PROXY TCP"):
                    print(
                        f"port {port}: expected PROXY v1 header, got {data[:32]!r}",
                        file=sys.stderr,
                    )
                    conn.sendall(b"FB-PROXY-FAIL\n")
                    continue
                write_hit(port, ".proxy")
                conn.sendall(b"FB-PROXY\n")
                write_hit(port)
                continue

            if expect_proxy == "v2":
                if not data.startswith(PROXY_V2_SIGNATURE):
                    print(
                        f"port {port}: expected PROXY v2 signature, got {data[:32]!r}",
                        file=sys.stderr,
                    )
                    conn.sendall(b"FB-PROXY-V2-FAIL\n")
                    continue
                write_hit(port, ".proxyv2")
                conn.sendall(b"FB-PROXY-V2\n")
                write_hit(port)
                continue

            marker = {
                19501: b"FB-DEFAULT\n",
                19502: b"FB-NAME\n",
                19503: b"FB-PATH\n",
                19505: b"FB-ALPN-H1\n",
                19506: b"FB-ALPN-H2\n",
            }.get(port, b"FB-UNKNOWN\n")
            conn.sendall(marker)
            write_hit(port)


def main() -> int:
    specs = [
        (19501, None),
        (19502, None),
        (19503, None),
        (19504, "v1"),
        (19505, None),
        (19506, None),
        (19507, "v2"),
    ]
    for port, expect_proxy in specs:
        thread = threading.Thread(
            target=serve, args=(port, expect_proxy), daemon=True
        )
        thread.start()
    print("fallback tcp servers listening on 19501-19507", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
