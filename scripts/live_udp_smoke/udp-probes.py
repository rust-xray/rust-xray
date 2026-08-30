#!/usr/bin/env python3
"""SOCKS5 UDP probes for live rust-xray UDP interoperability smoke."""

from __future__ import annotations

import socket
import struct
import sys
import time


def socks5_udp_exchange(
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    payload: bytes,
    timeout: float = 15.0,
    expect_response: bool = True,
) -> bytes | None:
    control = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    control.settimeout(timeout)
    try:
        control.sendall(b"\x05\x01\x00")
        greeting = control.recv(2)
        if greeting != b"\x05\x00":
            raise RuntimeError(f"unexpected SOCKS greeting: {greeting!r}")

        control.sendall(
            b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
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

        relay_port = struct.unpack("!H", bound[-2:])[0] or proxy_port

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        try:
            if ":" in dest_host and not dest_host.startswith("["):
                # IPv6 literal without brackets is invalid here.
                pass
            if dest_host.startswith("[") and dest_host.endswith("]"):
                host = dest_host[1:-1]
                header = (
                    b"\x00\x00\x00\x04"
                    + socket.inet_pton(socket.AF_INET6, host)
                    + struct.pack("!H", dest_port)
                )
            elif dest_host.replace(".", "").isdigit():
                header = (
                    b"\x00\x00\x00\x01"
                    + socket.inet_aton(dest_host)
                    + struct.pack("!H", dest_port)
                )
            else:
                host_bytes = dest_host.encode("ascii")
                header = (
                    b"\x00\x00\x00\x03"
                    + bytes([len(host_bytes)])
                    + host_bytes
                    + struct.pack("!H", dest_port)
                )
            udp.sendto(header + payload, ("127.0.0.1", relay_port))
            if not expect_response:
                return None
            data, _ = udp.recvfrom(65535)
            if len(data) <= len(header):
                raise RuntimeError("truncated SOCKS UDP response")
            return data[len(header) :]
        finally:
            udp.close()
    finally:
        control.close()


def socks5_tcp_connect(proxy_port: int, dest_host: str, dest_port: int, payload: bytes = b"") -> None:
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
    sock.settimeout(5.0)
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


def dns_query(qname: str, qtype: int, tx_id: int = 0xABCD) -> bytes:
    name = b""
    for label in qname.split("."):
        encoded = label.encode("ascii")
        name += bytes([len(encoded)]) + encoded
    name += b"\x00"
    return (
        struct.pack("!H", tx_id)
        + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + name
        + struct.pack("!HH", qtype, 1)
    )


def stun_binding_request() -> bytes:
    return b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12


def probe_echo(proxy_port: int, host: str, port: int, rounds: int = 3) -> None:
    control = socket.create_connection(("127.0.0.1", proxy_port), timeout=15.0)
    control.settimeout(15.0)
    try:
        control.sendall(b"\x05\x01\x00")
        if control.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting failed")
        control.sendall(
            b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
        )
        reply = control.recv(4)
        if len(reply) < 4 or reply[1] != 0x00:
            raise RuntimeError("UDP ASSOCIATE failed")
        atyp = reply[3]
        if atyp == 0x01:
            bound = control.recv(4 + 2)
        elif atyp == 0x03:
            length = control.recv(1)[0]
            bound = control.recv(length + 2)
        else:
            raise RuntimeError(f"unexpected ATYP {atyp}")
        relay_port = struct.unpack("!H", bound[-2:])[0] or proxy_port
        if host.replace(".", "").isdigit():
            header = (
                b"\x00\x00\x00\x01"
                + socket.inet_aton(host)
                + struct.pack("!H", port)
            )
        else:
            host_bytes = host.encode("ascii")
            header = (
                b"\x00\x00\x00\x03"
                + bytes([len(host_bytes)])
                + host_bytes
                + struct.pack("!H", port)
            )
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(15.0)
        try:
            for idx in range(rounds):
                payload = f"echo-{idx}".encode()
                udp.sendto(header + payload, ("127.0.0.1", relay_port))
                data, _ = udp.recvfrom(65535)
                response = data[len(header) :]
                if response != payload:
                    raise RuntimeError(f"echo mismatch round={idx}: {response!r}")
        finally:
            udp.close()
    finally:
        control.close()


def probe_multi_response(proxy_port: int, host: str, port: int) -> int:
    payload = b"multi"
    count = 0
    control = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
    control.settimeout(5.0)
    try:
        control.sendall(b"\x05\x01\x00")
        if control.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting failed")
        control.sendall(
            b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
        )
        reply = control.recv(4)
        if len(reply) < 4 or reply[1] != 0x00:
            raise RuntimeError("UDP ASSOCIATE failed")
        atyp = reply[3]
        if atyp == 0x01:
            bound = control.recv(4 + 2)
        else:
            raise RuntimeError(f"unexpected ATYP {atyp}")
        relay_port = struct.unpack("!H", bound[-2:])[0] or proxy_port
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(2.0)
        try:
            header = (
                b"\x00\x00\x00\x01"
                + socket.inet_aton(host)
                + struct.pack("!H", port)
            )
            udp.sendto(header + payload, ("127.0.0.1", relay_port))
            deadline = time.time() + 5.0
            while time.time() < deadline and count < 3:
                try:
                    data, _ = udp.recvfrom(65535)
                except TimeoutError:
                    break
                body = data[len(header) :]
                if len(body) >= 1 and body[1:] == payload:
                    count += 1
        finally:
            udp.close()
    finally:
        control.close()
    if count < 3:
        raise RuntimeError(f"expected 3 multi responses, got {count}")
    return count


def probe_dns(proxy_port: int, host: str, port: int, qname: str, qtype: int) -> None:
    response = socks5_udp_exchange(
        proxy_port, host, port, dns_query(qname, qtype), timeout=8.0
    )
    if response is None or len(response) < 12:
        raise RuntimeError("dns response too short")
    if (response[2] & 0x80) == 0:
        raise RuntimeError("dns response is not a reply")


def probe_stun(proxy_port: int, host: str, port: int) -> None:
    response = socks5_udp_exchange(proxy_port, host, port, stun_binding_request())
    if response is None or len(response) < 20:
        raise RuntimeError("stun response too short")
    if response[0:2] != b"\x01\x01":
        raise RuntimeError(f"unexpected stun response type: {response[0:2]!r}")


def probe_quic_smoke(proxy_port: int, host: str = "1.1.1.1", port: int = 443) -> None:
    # Initial QUIC long header-ish prefix; smoke only checks bidirectional UDP survives.
    initial = bytes.fromhex("c0ff0000010800abcdef0900000001")
    first = socks5_udp_exchange(proxy_port, host, port, initial, timeout=8.0)
    if first is None:
        raise RuntimeError("no QUIC/UDP443 response")
    second = socks5_udp_exchange(proxy_port, host, port, initial, timeout=8.0)
    if second is None:
        raise RuntimeError("second QUIC/UDP443 exchange failed")


def probe_blackhole(proxy_port: int, host: str, port: int) -> None:
    try:
        socks5_udp_exchange(
            proxy_port,
            host,
            port,
            b"blocked",
            timeout=2.0,
            expect_response=True,
        )
    except TimeoutError:
        return
    except socket.timeout:
        return
    raise RuntimeError("blackhole target unexpectedly returned UDP response")


def prime_mux(proxy_port: int) -> None:
    socks5_tcp_connect(proxy_port, "v1.mux.cool", 666, b"\x00")


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: udp-probes.py <mode> <socks_port> [args...]\n"
            "modes: echo multi dns stun quic blackhole prime-mux",
            file=sys.stderr,
        )
        return 2
    mode = sys.argv[1]
    port = int(sys.argv[2])
    if mode == "echo":
        host = sys.argv[3]
        dport = int(sys.argv[4])
        rounds = int(sys.argv[5]) if len(sys.argv) > 5 else 3
        probe_echo(port, host, dport, rounds)
        print(f"echo ok rounds={rounds}")
        return 0
    if mode == "multi":
        host = sys.argv[3]
        dport = int(sys.argv[4])
        count = probe_multi_response(port, host, dport)
        print(f"multi-response ok count={count}")
        return 0
    if mode == "dns":
        host = sys.argv[3]
        dport = int(sys.argv[4])
        qname = sys.argv[5]
        qtype = int(sys.argv[6])
        probe_dns(port, host, dport, qname, qtype)
        print(f"dns ok qname={qname} qtype={qtype}")
        return 0
    if mode == "stun":
        host = sys.argv[3]
        dport = int(sys.argv[4])
        probe_stun(port, host, dport)
        print("stun ok")
        return 0
    if mode == "quic":
        host = sys.argv[3] if len(sys.argv) > 3 else "1.1.1.1"
        dport = int(sys.argv[4]) if len(sys.argv) > 4 else 443
        probe_quic_smoke(port, host, dport)
        print(f"quic smoke ok target={host}:{dport}")
        return 0
    if mode == "blackhole":
        host = sys.argv[3]
        dport = int(sys.argv[4])
        probe_blackhole(port, host, dport)
        print("blackhole ok (no response)")
        return 0
    if mode == "prime-mux":
        prime_mux(port)
        print("mux primed")
        return 0
    print(f"unknown mode: {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
