#!/usr/bin/env python3
"""
best_effort_braces.py

Best-effort fixer for simple brace-less C control statements.

It handles common patterns like:

    if (x)
        do_thing();

    while (x)
        do_thing();

    for (...)
        do_thing();

    else
        do_thing();

It intentionally skips lines where the body is already a block, a preprocessor
directive, a blank line, or an obvious multi-line construct.

After running this, run clang-format.

Usage:

    python3 scripts/best_effort_braces.py src include
    find src include \( -name '*.c' -o -name '*.h' \) -print0 | xargs -0 clang-format -i
"""

from __future__ import annotations

import argparse
from pathlib import Path


CONTROL_PREFIXES = (
    "if ",
    "if(",
    "for ",
    "for(",
    "while ",
    "while(",
    "else",
    "else if(",
    "else if (",
)


def leading_ws(s: str) -> str:
    return s[: len(s) - len(s.lstrip(" \t"))]


def is_control_header(stripped: str) -> bool:
    if stripped.startswith("else if"):
        return False

    if stripped.startswith("else"):
        return stripped in ("else", "else\n") or stripped.startswith("else ")

    return stripped.startswith(("if ", "if(", "for ", "for(", "while ", "while("))


def header_is_single_line(stripped: str) -> bool:
    if stripped.startswith("else"):
        return True

    depth = 0
    in_str = False
    in_chr = False
    esc = False

    for ch in stripped:
        if esc:
            esc = False
            continue

        if ch == "\\":
            esc = True
            continue

        if in_str:
            if ch == '"':
                in_str = False
            continue

        if in_chr:
            if ch == "'":
                in_chr = False
            continue

        if ch == '"':
            in_str = True
        elif ch == "'":
            in_chr = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1

    return depth == 0


def should_skip_body(body: str) -> bool:
    stripped = body.strip()

    if not stripped:
        return True

    if stripped.startswith("{"):
        return True

    if stripped.startswith("#"):
        return True

    if stripped.startswith("case ") or stripped.startswith("default:"):
        return True

    # Avoid changing labels.
    if stripped.endswith(":") and not stripped.startswith("goto "):
        return True

    return False


def body_is_simple_statement(body: str) -> bool:
    stripped = body.strip()

    if stripped.endswith(";"):
        return True

    if stripped.startswith(("return ", "break;", "continue;", "goto ")):
        return True

    return False


def fix_file(path: Path) -> bool:
    lines = path.read_text(errors="replace").splitlines(keepends=True)
    out: list[str] = []
    changed = False
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not is_control_header(stripped) or not header_is_single_line(stripped):
            out.append(line)
            i += 1
            continue

        if i + 1 >= len(lines):
            out.append(line)
            i += 1
            continue

        body = lines[i + 1]

        if should_skip_body(body):
            out.append(line)
            i += 1
            continue

        if not body_is_simple_statement(body):
            out.append(line)
            i += 1
            continue

        hdr_indent = leading_ws(line)
        body_indent = leading_ws(body)

        out.append(line)
        out.append(f"{hdr_indent}{{\n")
        out.append(body)
        out.append(f"{hdr_indent}}}\n")

        changed = True
        i += 2

    if changed:
        path.write_text("".join(out))

    return changed


def iter_files(paths: list[Path]):
    for p in paths:
        if p.is_file() and p.suffix in {".c", ".h"}:
            yield p
        elif p.is_dir():
            yield from p.rglob("*.c")
            yield from p.rglob("*.h")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args()

    changed_count = 0

    for path in sorted(set(iter_files(args.paths))):
        if fix_file(path):
            print(f"[fixed] {path}")
            changed_count += 1

    print(f"[done] files changed: {changed_count}")
    print("[next] run clang-format")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
