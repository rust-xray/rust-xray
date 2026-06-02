#!/usr/bin/env python3
"""Extract #[cfg(test)] mod blocks from src/ into tests/unit/ and wire via #[path]."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
UNIT = ROOT / "tests" / "unit"


def rel_depth(src_file: Path) -> int:
    rel = src_file.relative_to(SRC)
    return rel.as_posix().count("/") + 1


def path_to_unit_test(src_file: Path, mod_name: str) -> str:
    rel = src_file.relative_to(SRC)
    prefix = "../" * rel_depth(src_file)
    stem = rel.with_suffix("")
    if mod_name == "tests":
        target = UNIT / stem.with_suffix(".rs")
    else:
        target = UNIT / stem.parent / f"{stem.name}_{mod_name}.rs"
    return f"{prefix}tests/unit/{target.relative_to(UNIT)}"


def skip_raw_string(src: str, i: int) -> int:
    j = i
    if src.startswith("b", j):
        j += 1
    if j >= len(src) or src[j] != "r":
        return i
    j += 1
    hashes = 0
    while j < len(src) and src[j] == "#":
        hashes += 1
        j += 1
    if j >= len(src) or src[j] != '"':
        return i
    j += 1
    end_marker = '"' + ("#" * hashes)
    end = src.find(end_marker, j)
    return len(src) if end == -1 else end + len(end_marker)


def skip_lifetime_or_char(src: str, i: int) -> int:
    if src[i] != "'":
        return i
    j = i + 1
    while j < len(src):
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == "'":
            return j + 1
        if src[j] in ",)>]{}`:; \t\n":
            return j
        j += 1
    return len(src)


def skip_string_or_comment(src: str, i: int) -> int:
    if src.startswith("//", i):
        nl = src.find("\n", i)
        return len(src) if nl == -1 else nl + 1
    if src.startswith("/*", i):
        end = src.find("*/", i + 2)
        return len(src) if end == -1 else end + 2
    raw_end = skip_raw_string(src, i)
    if raw_end > i:
        return raw_end
    if src[i] == "'":
        return skip_lifetime_or_char(src, i)
    if src[i] == '"':
        quote = src[i]
        i += 1
        while i < len(src):
            if src[i] == "\\":
                i += 2
                continue
            if src[i] == quote:
                return i + 1
            i += 1
        return len(src)
    return i


def find_matching_brace(src: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    while i < len(src):
        skipped = skip_string_or_comment(src, i)
        if skipped > i:
            i = skipped
            continue
        if src[i] in "rb" and skip_raw_string(src, i) > i:
            i = skip_raw_string(src, i)
            continue
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError(f"unmatched brace at {open_idx}")


def find_test_mod_blocks(content: str) -> list[tuple[int, int, str, str]]:
    """Return (start, end_exclusive, mod_name, mod_body_without_outer_braces)."""
    blocks: list[tuple[int, int, str, str]] = []
    pattern = re.compile(r"#\[cfg\(test\)\]\s*\n(?:#\[path[^\]]*\]\s*\n)?mod\s+(\w+)\s*\{")
    for match in pattern.finditer(content):
        mod_name = match.group(1)
        open_brace = match.end() - 1
        close_brace = find_matching_brace(content, open_brace)
        body = content[open_brace + 1 : close_brace]
        end = close_brace + 1
        while end < len(content) and content[end] in " \t":
            end += 1
        if end < len(content) and content[end] == "\n":
            end += 1
        blocks.append((match.start(), end, mod_name, body))
    return blocks


def unit_target(src_file: Path, mod_name: str) -> Path:
    rel = src_file.relative_to(SRC)
    stem = rel.with_suffix("")
    if mod_name == "tests":
        return UNIT / stem.with_suffix(".rs")
    return UNIT / stem.parent / f"{stem.name}_{mod_name}.rs"


def process_file(src_file: Path, dry_run: bool = False) -> int:
    content = src_file.read_text()
    blocks = find_test_mod_blocks(content)
    if not blocks:
        return 0

    new_content = content
    extracted = 0
    for start, end, mod_name, body in reversed(blocks):
        target = unit_target(src_file, mod_name)
        rel_path = path_to_unit_test(src_file, mod_name)
        module_src = f"#[cfg(test)]\n#[path = \"{rel_path}\"]\nmod {mod_name};\n"
        new_content = new_content[:start] + module_src + new_content[end:]
        file_body = body
        if not file_body.startswith("\n"):
            file_body = "\n" + file_body
        if not file_body.endswith("\n"):
            file_body += "\n"
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(file_body)
        extracted += 1

    if not dry_run and new_content != content:
        src_file.write_text(new_content)
    return extracted


def move_existing_xray_tests() -> None:
    old = SRC / "config" / "xray" / "tests.rs"
    new = UNIT / "config" / "xray.rs"
    if old.exists() and not new.exists():
        new.parent.mkdir(parents=True, exist_ok=True)
        new.write_text(old.read_text())
        old.unlink()
    mod_rs = SRC / "config" / "xray" / "mod.rs"
    text = mod_rs.read_text()
    replacement = (
        "#[cfg(test)]\n"
        '#[path = "../../../tests/unit/config/xray.rs"]\n'
        "mod tests;\n"
    )
    text = re.sub(
        r"#\[cfg\(test\)\]\s*\nmod tests;\s*\n?",
        replacement,
        text,
        count=1,
    )
    mod_rs.write_text(text)


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    total = 0
    rust_files = sorted(SRC.rglob("*.rs"))
    for path in rust_files:
        if path.name == "tests.rs":
            continue
        count = process_file(path, dry_run=dry_run)
        if count:
            print(f"{path.relative_to(ROOT)}: {count} module(s)")
            total += count
    if not dry_run:
        move_existing_xray_tests()
    print(f"Total extracted modules: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
