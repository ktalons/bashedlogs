#!/usr/bin/env bash
# build.sh - bundle bin/bashedlogs + lib/ into the single-file release artifact
# dist/bashedlogs, preserving the "curl one file onto a triage box" story.
# Usage: tools/build.sh [--version X.Y.Z]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_OVERRIDE=""

if [ "${1:-}" = "--version" ]; then
  if [ -z "${2:-}" ]; then
    echo "build.sh: --version needs a value" >&2
    exit 1
  fi
  VERSION_OVERRIDE=$2
fi

ENTRY="$ROOT/bin/bashedlogs"
OUT_DIR="$ROOT/dist"
OUT="$OUT_DIR/bashedlogs"

mkdir -p "$OUT_DIR"

# Everything before the skip region (shebang, version, bash guard), the
# inlined libs in the same order bin/ sources them, then the tail (main call).
{
  sed -n '1,/@BUNDLE-SKIP-START/p' "$ENTRY" | sed '$d'
  echo "# --- inlined from lib/ by tools/build.sh; edit the repo, not this file ---"
  for f in "$ROOT"/lib/core/*.sh "$ROOT"/lib/formats/*.sh; do
    echo
    echo "# ==== ${f##"$ROOT"/} ===="
    sed '/^# shellcheck shell=bash$/d' "$f"
  done
  sed -n '/@BUNDLE-SKIP-END/,$p' "$ENTRY" | sed '1d'
} > "$OUT"

if [ -n "$VERSION_OVERRIDE" ]; then
  sed -i.bak "s/^BASHEDLOGS_VERSION=.*/BASHEDLOGS_VERSION=\"$VERSION_OVERRIDE\"/" "$OUT"
  rm -f "$OUT.bak"
fi

chmod +x "$OUT"
bash -n "$OUT"
echo "built $OUT ($(wc -l < "$OUT" | tr -d ' ') lines)"
