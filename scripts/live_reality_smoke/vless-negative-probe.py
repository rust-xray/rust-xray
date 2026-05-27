#!/usr/bin/env python3
"""Trigger unsupported VLESS command paths via Xray SOCKS client."""

from __future__ import annotations

import socket
import struct
import sys


def socks5_udp_send(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    payload: bytes,
    timeout: float = 5.0,
) -> None:
    control = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    control.settimeout(timeout)
    try:
        control.sendall(b"\x05\x01\x00")
        greeting = control.recv(2)
        if greeting != b"\x05\x00":
            raise RuntimeError(f"unexpected SOCKS greeting: {greeting!r}")

        control.sendall(
            b"\x05\x03\x00\x01"
            + socket.inet_aton("0.0.0.0")
            + struct.pack("!H", 0)
        )
        reply = control.recv(4)
        if len(reply) < 4 or reply[1] != 0x00:
            raise RuntimeError(f"SOCKS UDP ASSOCIATE failed: {reply!r}")

        atyp = reply[3]
        if atyp == 0x01:
            bound = control.recv(4 + 2)
        elif atyp == 0x04:
            bound = control.recv(16 + 2)
        elif atyp == 0x03:
            length = control.recv(1)[0]
            bound = control.recv(length + 2)
        else:
            raise RuntimeError(f"unsupported SOCKS bound ATYP: {atyp}")

        if len(bound) < 2:
            raise RuntimeError("truncated SOCKS UDP ASSOCIATE response")

        relay_host = proxy_host
        relay_port = struct.unpack("!H", bound[-2:])[0]
        if relay_port == 0:
            relay_port = proxy_port

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        try:
            header = b"\x00\x00\x00\x01" + socket.inet_aton(dest_host) + struct.pack(
                "!H", dest_port
            )
            udp.sendto(header + payload, (relay_host, relay_port))
            try:
                udp.recvfrom(4096)
            except TimeoutError:
                pass
        finally:
            udp.close()
    finally:
        control.close()


def socks5_tcp_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    payload: bytes = b"",
    timeout: float = 5.0,
) -> None:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        reply = sock.recv(2)
        if reply != b"\x05\x00":
            raise RuntimeError(f"unexpected SOCKS greeting: {reply!r}")

        host_bytes = dest_host.encode("ascii")
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", dest_port)
        )
        reply = sock.recv(256)
        if len(reply) < 2 or reply[1] != 0x00:
            raise RuntimeError(f"SOCKS CONNECT failed: {reply!r}")

        if payload:
            sock.sendall(payload)

        sock.settimeout(2)
        try:
            sock.recv(1024)
        except TimeoutError:
            pass
    finally:
        sock.close()


def minimal_dns_query() -> bytes:
    # Query A example.com IN
    return (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: vless-negative-probe.py <mode> <socks_port>\n"
            "modes: udp-dns udp-quic mux-cool",
            file=sys.stderr,
        )
        return 2

    mode = sys.argv[1]
    port = int(sys.argv[2])

    if mode == "udp-dns":
        socks5_udp_send("127.0.0.1", port, "8.8.8.8", 53, minimal_dns_query())
        return 0
    if mode == "udp-quic":
        socks5_udp_send("127.0.0.1", port, "1.1.1.1", 443, b"\x00")
        return 0
    if mode == "mux-cool":
        # Xray maps v1.mux.cool to VLESS command Mux (0x03).
        socks5_tcp_connect("127.0.0.1", port, "v1.mux.cool", 666, b"\x00")
        return 0

    print(f"unknown mode: {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
