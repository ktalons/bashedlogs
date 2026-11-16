#!/usr/bin/env bash
# ******************************************************************************
# *Title: Release Bundle Builder*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Inlines lib/ into bin/bashedlogs to build dist/bashedlogs.*
# ******************************************************************************
# Usage: tools/build.sh [--version X.Y.Z]
set -euo pipefail

# *--- Configuration ---*

ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_OVERRIDE=""

if [ "$#" -gt 0 ]; then
  if [ "$#" -ne 2 ] || [ "$1" != "--version" ] ||
      [[ ! $2 =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?(\+[A-Za-z0-9.-]+)?$ ]]; then
    printf 'Usage: tools/build.sh [--version X.Y.Z]\n' >&2
    exit 1
  fi
  VERSION_OVERRIDE=$2
fi

ENTRY="$ROOT/bin/bashedlogs"
OUT_DIR="$ROOT/dist"
OUT="$OUT_DIR/bashedlogs"

mkdir -p "$OUT_DIR"
temp=$(mktemp "$OUT_DIR/.bashedlogs.XXXXXX")
trap 'rm -f -- "$temp" "$temp.bak"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# *--- Bundle Assembly ---*

# NOTE: everything before the skip region (shebang, version, bash guard), the
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
} > "$temp"

# *--- Version Override ---*

if [ -n "$VERSION_OVERRIDE" ]; then
  sed -i.bak "s/^BASHEDLOGS_VERSION=.*/BASHEDLOGS_VERSION=\"$VERSION_OVERRIDE\"/" "$temp"
  rm -f -- "$temp.bak"
fi

# *--- Verify and Publish ---*

bash -n "$temp"
chmod 755 "$temp"
mv -f -- "$temp" "$OUT"
echo "built $OUT ($(wc -l < "$OUT" | tr -d ' ') lines)"
