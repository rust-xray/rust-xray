#!/usr/bin/env python3
"""Local TCP listeners for VLESS fallback live smoke phases."""

from __future__ import annotations

import os
import socket
import sys
import threading
from pathlib import Path


def write_hit(port: int, suffix: str = "") -> None:
    hit_dir = os.environ.get("SMOKE_FALLBACK_HIT_DIR")
    if not hit_dir:
        return
    path = Path(hit_dir) / f"{port}{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("ok\n", encoding="utf-8")


def serve(port: int, expect_proxy: bool = False) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(32)

    while True:
        conn, _addr = listener.accept()
        with conn:
            data = conn.recv(4096)
            if expect_proxy:
                if not data.startswith(b"PROXY TCP"):
                    print(
                        f"port {port}: expected PROXY header, got {data[:32]!r}",
                        file=sys.stderr,
                    )
                    conn.sendall(b"FB-PROXY-FAIL\n")
                    continue
                write_hit(port, ".proxy")
                conn.sendall(b"FB-PROXY\n")
                write_hit(port)
                continue

            marker = {
                19501: b"FB-DEFAULT\n",
                19502: b"FB-NAME\n",
                19503: b"FB-PATH\n",
            }.get(port, b"FB-UNKNOWN\n")
            conn.sendall(marker)
            write_hit(port)


def main() -> int:
    specs = [
        (19501, False),
        (19502, False),
        (19503, False),
        (19504, True),
    ]
    for port, expect_proxy in specs:
        thread = threading.Thread(
            target=serve, args=(port, expect_proxy), daemon=True
        )
        thread.start()
    print("fallback tcp servers listening on 19501-19504", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
