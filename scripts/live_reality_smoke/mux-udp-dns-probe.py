#!/usr/bin/env python3
"""Send SOCKS5 UDP DNS query via Xray mux client to a numeric :53 target."""

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
    timeout: float = 10.0,
) -> bytes:
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
            data, _ = udp.recvfrom(4096)
            if len(data) <= len(header):
                raise RuntimeError("truncated SOCKS UDP response")
            return data[len(header) :]
        finally:
            udp.close()
    finally:
        control.close()


def minimal_dns_query() -> bytes:
    # Query A example.com IN
    return (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    )


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: mux-udp-dns-probe.py <socks_port> <dest_host> <dest_port>",
            file=sys.stderr,
        )
        return 2

    port = int(sys.argv[1])
    dest_host = sys.argv[2]
    dest_port = int(sys.argv[3])

    response = socks5_udp_send(
        "127.0.0.1", port, dest_host, dest_port, minimal_dns_query()
    )
    if len(response) < 12:
        raise RuntimeError(f"DNS response too short: {len(response)} bytes")
    if response[0:2] != b"\x12\x34":
        raise RuntimeError(f"unexpected DNS transaction id: {response[0:2]!r}")
    if (response[2] & 0x80) == 0:
        raise RuntimeError("DNS response is not a reply")

    print(f"dns response bytes={len(response)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
