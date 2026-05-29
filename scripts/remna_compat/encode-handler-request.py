#!/usr/bin/env python3
"""Encode HandlerService AlterInbound requests (stdlib-only protobuf wire format)."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from typing import Iterable


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _key(field_number: int, wire_type: int) -> bytes:
    return _varint((field_number << 3) | wire_type)


def _encode_string(field_number: int, value: str) -> bytes:
    data = value.encode("utf-8")
    return _key(field_number, 2) + _varint(len(data)) + data


def _encode_bytes(field_number: int, value: bytes) -> bytes:
    return _key(field_number, 2) + _varint(len(value)) + value


def _encode_message(field_number: int, value: bytes) -> bytes:
    return _key(field_number, 2) + _varint(len(value)) + value


def _encode_uint32(field_number: int, value: int) -> bytes:
    return _key(field_number, 0) + _varint(value)


def encode_vless_account(account_id: str, flow: str) -> bytes:
    parts: list[bytes] = [_encode_string(1, account_id)]
    if flow:
        parts.append(_encode_string(2, flow))
    return b"".join(parts)


def encode_typed_message(type_name: str, value: bytes) -> bytes:
    return _encode_string(1, type_name) + _encode_bytes(2, value)


def encode_user(email: str, account_id: str, flow: str, level: int = 0) -> bytes:
    account = encode_vless_account(account_id, flow)
    typed = encode_typed_message("xray.proxy.vless.Account", account)
    parts = [_encode_uint32(1, level), _encode_string(2, email), _encode_message(3, typed)]
    return b"".join(parts)


def encode_add_user_operation(email: str, account_id: str, flow: str) -> bytes:
    user = encode_user(email, account_id, flow)
    return _encode_message(1, user)


def encode_remove_user_operation(email: str) -> bytes:
    return _encode_string(1, email)


def encode_alter_inbound(tag: str, operation_type: str, operation_value: bytes) -> bytes:
    operation = encode_typed_message(operation_type, operation_value)
    return _encode_string(1, tag) + _encode_message(2, operation)


def alter_inbound_json(tag: str, operation_type: str, operation_value: bytes) -> dict:
    return {
        "tag": tag,
        "operation": {
            "type": operation_type,
            "value": base64.b64encode(operation_value).decode("ascii"),
        },
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add-user")
    add.add_argument("--tag", default="vless-reality-in")
    add.add_argument("--email", required=True)
    add.add_argument("--id", required=True)
    add.add_argument("--flow", default="xtls-rprx-vision")

    remove = sub.add_parser("remove-user")
    remove.add_argument("--tag", default="vless-reality-in")
    remove.add_argument("--email", required=True)

    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "add-user":
        op = encode_add_user_operation(args.email, args.id, args.flow)
        op_type = "xray.app.proxyman.command.AddUserOperation"
    else:
        op = encode_remove_user_operation(args.email)
        op_type = "xray.app.proxyman.command.RemoveUserOperation"

    payload = alter_inbound_json(args.tag, op_type, op)
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
