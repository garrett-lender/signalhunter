#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")"/ && pwd)"

echo $ROOT

find "$ROOT/src" "$ROOT/include" \
    \( -name '*.c' -o -name '*.h' \) \
    -print0 | xargs -0 clang-format -i

echo "[ok] formatting complete"
