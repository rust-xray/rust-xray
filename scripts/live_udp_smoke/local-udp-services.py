#!/usr/bin/env python3
"""Deterministic loopback UDP services for live UDP interoperability smoke."""

from __future__ import annotations

import argparse
import socket
import struct
import threading
import time


def _serve_echo(host: str, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except TimeoutError:
            continue
        sock.sendto(data, addr)
    sock.close()


def _serve_multi_response(host: str, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except TimeoutError:
            continue
        if not data:
            continue
        for idx in range(3):
            sock.sendto(bytes([idx]) + data, addr)
            time.sleep(0.05)
    sock.close()


def _encode_name(label: str) -> bytes:
    parts = label.split(".")
    out = b""
    for part in parts:
        encoded = part.encode("ascii")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def _dns_response(query: bytes) -> bytes | None:
    if len(query) < 12:
        return None
    tx_id = query[0:2]
    flags = b"\x81\x80"
    counts = query[4:6] + b"\x00\x01" + b"\x00\x00" + b"\x00\x00"
    question = query[12:]
    # Minimal A answer for any query: 127.0.0.1
    answer = question + b"\x00\x01\x00\x01" + struct.pack("!IH", 60, 4) + socket.inet_aton(
        "127.0.0.1"
    )
    return tx_id + flags + counts + question + answer


def _serve_dns(host: str, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except TimeoutError:
            continue
        response = _dns_response(data)
        if response:
            sock.sendto(response, addr)
    sock.close()


def _serve_stun(host: str, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except TimeoutError:
            continue
        if len(data) < 20:
            continue
        # Binding request: type 0x0001, copy transaction id + minimal XOR-MAPPED-ADDRESS
        if data[0:2] != b"\x00\x01":
            continue
        tx_id = data[8:20]
        attr = b"\x00\x01\x00\x08" + b"\x00\x01" + struct.pack("!H", port) + socket.inet_aton(
            addr[0]
        )
        response = b"\x01\x01" + b"\x00\x00" + struct.pack("!I", len(attr)) + tx_id + attr
        sock.sendto(response, addr)
    sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--echo-port", type=int, default=37001)
    parser.add_argument("--multi-port", type=int, default=37002)
    parser.add_argument("--dns-port", type=int, default=37053)
    parser.add_argument("--stun-port", type=int, default=37047)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    stop = threading.Event()
    threads = [
        threading.Thread(
            target=_serve_echo, args=(args.host, args.echo_port, stop), daemon=True
        ),
        threading.Thread(
            target=_serve_multi_response,
            args=(args.host, args.multi_port, stop),
            daemon=True,
        ),
        threading.Thread(
            target=_serve_dns, args=(args.host, args.dns_port, stop), daemon=True
        ),
        threading.Thread(
            target=_serve_stun, args=(args.host, args.stun_port, stop), daemon=True
        ),
    ]
    for thread in threads:
        thread.start()
    print(
        f"local-udp-services echo={args.echo_port} multi={args.multi_port} "
        f"dns={args.dns_port} stun={args.stun_port}",
        flush=True,
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        for thread in threads:
            thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
