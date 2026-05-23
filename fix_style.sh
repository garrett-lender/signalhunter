#!/usr/bin/env bash
set -euo pipefail

python3 scripts/best_effort_braces.py src include

find src include \( -name '*.c' -o -name '*.h' \) -print0 | \
    xargs -0 clang-format -i

echo "[ok] braces/style pass complete"
