#!/usr/bin/env bats
# ******************************************************************************
# *Title: Hostile Input Handling*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Tests that hostile log content is never executed or expanded.*
# ******************************************************************************

# SECURITY: log content is untrusted attacker-controlled input. These assert
# output stays parseable and nothing in a log line is ever executed,
# expanded, or treated as a printf format.

load test_helper

setup() {
  export BASHEDLOGS_ASSUME_YEAR=2025
  if ! command -v jq >/dev/null 2>&1; then
    echo "tests require jq" >&2
    return 1
  fi
}

# *--- Injection Safety ---*

@test "hostile content still produces valid JSON" {
  run bash -c "\"$BL\" --iocs -o json \"$FIXTURES/hostile/injection.log\" | jq -e . >/dev/null"
  [ "$status" -eq 0 ]
}

@test "hostile content produces valid JSON on every ndjson line" {
  run bash -c "
    bad=0
    while IFS= read -r l; do
      printf '%s' \"\$l\" | jq -e . >/dev/null 2>&1 || bad=1
    done < <(\"$BL\" --iocs -o ndjson \"$FIXTURES/hostile/injection.log\")
    exit \$bad
  "
  [ "$status" -eq 0 ]
}

@test "command substitution in a log line is not executed" {
  run "$BL" --no-color --iocs "$FIXTURES/hostile/injection.log"
  [ "$status" -eq 0 ]
  # `id`/`whoami` output would look like these; the literal text is fine.
  [[ "$output" != *"uid="*"gid="* ]]
  [[ "$output" != *"root:x:0:0"* ]]
}

@test "printf specifiers in a log line are not interpreted" {
  run "$BL" --no-color "$FIXTURES/hostile/injection.log"
  [ "$status" -eq 0 ]
  # A mishandled %s would swallow the literal text or emit stray numbers.
  [[ "$output" == *"%s%s%n%d"* ]]
}

@test "glob characters in a username are not expanded" {
  run bash -c "cd \"$REPO_ROOT\" && \"$BL\" -o json \"$FIXTURES/hostile/injection.log\" | jq -r .metrics.targeted_users"
  [ "$status" -eq 0 ]
  [[ "$output" != *README* ]]
  [[ "$output" != *lib* ]]
}

@test "hostile log still detects the real brute force underneath" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/hostile/injection.log\" | jq -r '[.findings[] | select(.category==\"brute-force\")][0].data.ip'"
  [ "$status" -eq 0 ]
  [ "$output" = "203.0.113.66" ]
}

# *--- Malformed Input ---*

@test "a filename containing a quote does not break JSON" {
  cp "$FIXTURES/generic/clean.log" "$BATS_TEST_TMPDIR/we\"ird'name.log"
  run bash -c "\"$BL\" -o json \"\$1\" | jq -e .file >/dev/null" _ "$BATS_TEST_TMPDIR/we\"ird'name.log"
  [ "$status" -eq 0 ]
}

@test "a log with CRLF line endings is handled" {
  printf 'Jun  1 10:00:00 h sshd[1]: Failed password for root from 203.0.113.66 port 1 ssh2\r\n' \
    > "$BATS_TEST_TMPDIR/crlf.log"
  run bash -c "\"$BL\" -o json \"$BATS_TEST_TMPDIR/crlf.log\" | jq -e . >/dev/null"
  [ "$status" -eq 0 ]
}

@test "an empty file is analyzed without crashing" {
  : > "$BATS_TEST_TMPDIR/empty.log"
  run bash -c "\"$BL\" -o json \"$BATS_TEST_TMPDIR/empty.log\" | jq -r '.format, (.findings | length)'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "generic" ]
  [ "${lines[1]}" = "0" ]
}

@test "a file with no trailing newline is fully counted" {
  printf 'Jun  1 10:00:00 h sshd[1]: Failed password for root from 203.0.113.66 port 1 ssh2' \
    > "$BATS_TEST_TMPDIR/nonewline.log"
  run bash -c "\"$BL\" -o json \"$BATS_TEST_TMPDIR/nonewline.log\" | jq -r .metrics.total_lines"
  [ "$status" -eq 0 ]
  [ "$output" = "1" ]
}

# *--- Terminal Control Sequences ---*

# SECURITY: pretty output goes to the analyst's terminal. These logs carry
# CSI cursor-up and erase-line, OSC 52 (clipboard write), OSC 8 (hyperlink),
# BEL, and a UTF-8 encoded C1 CSI. The logs are built here rather than kept as
# fixtures so no raw control byte is committed to the repo.
HOSTILE_SEQ=$'\033[3A\033[2K\033]52;c;ZWNobyBwd25lZA==\007\033]8;;http://evil.example/\033\\'
HOSTILE_SEQ_SHOWN='\x1b[3A\x1b[2K\x1b]52;c;ZWNobyBwd25lZA==\x07\x1b]8;;http://evil.example/\x1b\'

# One token with no spaces or quotes, so every analyzer keeps it whole.
HOSTILE_USER="x${HOSTILE_SEQ}y"$'\302\2332J'

# 12 fast failures then a success for the same hostile username: trips the
# brute-force and possible-compromise findings, which quote the username.
write_hostile_auth() {
  local s
  : > "$BATS_TEST_TMPDIR/auth.log"
  for s in 00 01 02 03 04 05 06 07 08 09 10 11; do
    printf 'Jun  1 10:00:%s bastion sshd[100]: Failed password for invalid user %s from 203.0.113.66 port 40%s ssh2\n' \
      "$s" "$HOSTILE_USER" "$s" >> "$BATS_TEST_TMPDIR/auth.log"
  done
  printf 'Jun  1 10:00:40 bastion sshd[101]: Accepted password for %s from 203.0.113.66 port 5000 ssh2\n' \
    "$HOSTILE_USER" >> "$BATS_TEST_TMPDIR/auth.log"
}

# SQL injection requests on a hostile path: the path lands in top_paths and
# in the finding's example= field.
write_hostile_web() {
  local s
  : > "$BATS_TEST_TMPDIR/web.log"
  for s in 1 2 3; do
    printf '203.0.113.66 - - [01/Jun/2025:10:00:0%s +0000] "GET /p%sq?id=1+union+select+1 HTTP/1.1" 200 12 "-" "curl/8.0"\n' \
      "$s" "$HOSTILE_SEQ" >> "$BATS_TEST_TMPDIR/web.log"
  done
}

# NOTE: the IOC URL pattern stops at "]", so an OSC sequence cannot ride
# inside a URL; this one carries CSI, BEL, and the UTF-8 C1 CSI instead.
write_hostile_url() {
  printf '2025-06-01T10:00:01Z appsvc INFO fetch url=http://evil.example/a%sb\007c\302\2332J status=200\n' \
    $'\033[3A\033[2K' > "$BATS_TEST_TMPDIR/url.log"
}

# run_on_tty <args...>: runs the tool on a pseudo-terminal so it turns color
# on. util-linux script(1) takes the command with -c; BSD script(1) takes it
# as trailing arguments.
run_on_tty() {
  if script -qc true /dev/null >/dev/null 2>&1; then
    run script -qc "$(printf '%q ' "$BL" "$@")" /dev/null < /dev/null
  elif script -q /dev/null true >/dev/null 2>&1 < /dev/null; then
    run script -q /dev/null "$BL" "$@" < /dev/null
  else
    skip "no script(1) available to provide a terminal"
  fi
}

# find_locale <name>: prints the installed locale matching <name>, ignoring
# case (glibc lists ja_JP.SJIS as ja_JP.sjis), or nothing when it is absent.
find_locale() {
  command -v locale >/dev/null 2>&1 || return 0
  locale -a 2>/dev/null | grep -i -x -F "$1" | head -n 1 || true
}

# write_legacy_web <path>: two plain requests for <path>, so it shows in
# top_paths as "<path> (2)".
write_legacy_web() {
  local s
  : > "$BATS_TEST_TMPDIR/legacy-web.log"
  for s in 1 2; do
    printf '203.0.113.66 - - [01/Jun/2025:10:00:0%s +0000] "GET %s HTTP/1.1" 200 12 "-" "curl/8.0"\n' \
      "$s" "$1" >> "$BATS_TEST_TMPDIR/legacy-web.log"
  done
}

@test "pretty output shows control bytes in an SSH username as visible escapes" {
  write_hostile_auth
  run "$BL" --no-color "$BATS_TEST_TMPDIR/auth.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" != *$'\302\233'* ]]
  [[ "$output" == *"targeted_users"*"x${HOSTILE_SEQ_SHOWN}y"'\xc2\x9b2J (12)'* ]]
  [[ "$output" == *"possible-compromise"*"successful login for 'x${HOSTILE_SEQ_SHOWN}y"* ]]
  [[ "$output" == *"user=x${HOSTILE_SEQ_SHOWN}y"'\xc2\x9b2J'* ]]
}

@test "pretty output shows control bytes in a web request path as visible escapes" {
  write_hostile_web
  run "$BL" --no-color "$BATS_TEST_TMPDIR/web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" == *"top_paths"*"/p${HOSTILE_SEQ_SHOWN}q?id=1+union+select+1 (3)"* ]]
  [[ "$output" == *"example=/p${HOSTILE_SEQ_SHOWN}q?id=1+union+select+1"* ]]
}

@test "pretty output shows control bytes in a URL IOC as visible escapes" {
  write_hostile_url
  run "$BL" --no-color --iocs "$BATS_TEST_TMPDIR/url.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" != *$'\302\233'* ]]
  [[ "$output" == *'http://evil.example/a\x1b[3A\x1b[2Kb\x07c\xc2\x9b2J'* ]]
}

@test "pretty output shows control bytes in the file name as visible escapes" {
  local f="$BATS_TEST_TMPDIR/evil"$'\033[2J\033]0;title\007'".log"
  cp "$FIXTURES/generic/clean.log" "$f"
  run "$BL" --no-color "$f"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" == *'evil\x1b[2J\x1b]0;title\x07.log'* ]]
}

@test "pretty output shows control bytes in enrichment text as visible escapes" {
  local mock="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$mock" "$BATS_TEST_TMPDIR/mmdb"
  : > "$BATS_TEST_TMPDIR/mmdb/GeoLite2-ASN.mmdb"
  # A lookup source is untrusted too: this mock returns a hostile org name.
  cat > "$mock/mmdblookup" <<'MOCK'
#!/usr/bin/env bash
for arg in "$@"; do last=$arg; done
case "$last" in
  autonomous_system_organization) printf '  "Evil\033[2J\033]0;x\007Org" <utf8_string>\n' ;;
  *) exit 1 ;;
esac
MOCK
  chmod +x "$mock/mmdblookup"
  run env PATH="$mock:$PATH" "$BL" --no-color --iocs --mmdb-dir "$BATS_TEST_TMPDIR/mmdb" \
    "$FIXTURES/iocs/sample.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" == *'Evil\x1b[2J\x1b]0;x\x07Org'* ]]
}

@test "color output carries no escape bytes except the tool's own colors" {
  local code rest
  write_hostile_auth
  write_hostile_web
  run_on_tty --iocs "$BATS_TEST_TMPDIR/auth.log"
  rest=$output
  run_on_tty "$BATS_TEST_TMPDIR/web.log"
  rest=$rest$output
  # Color must really be on, or the checks below prove nothing.
  [[ "$rest" == *$'\033[0m'* ]]
  for code in $'\033[0;31m' $'\033[0;32m' $'\033[1;33m' $'\033[0;36m' \
    $'\033[0;35m' $'\033[1m' $'\033[2m' $'\033[0m'; do
    rest=${rest//"$code"/}
  done
  [[ "$rest" != *$'\033'* ]]
  [[ "$rest" != *$'\007'* ]]
  [[ "$rest" != *$'\302\233'* ]]
  [[ "$rest" == *"$HOSTILE_SEQ_SHOWN"* ]]
}

@test "json output keeps its own control-byte handling for hostile values" {
  write_hostile_auth
  run bash -c "\"$BL\" -o json \"$BATS_TEST_TMPDIR/auth.log\" | jq -r '.metrics.targeted_users, (.findings[] | select(.category == \"possible-compromise\") | .data.user)'"
  [ "$status" -eq 0 ]
  # json_escape drops C0 bytes outright; no display escape leaks into JSON.
  local stripped=$'x[3A[2K]52;c;ZWNobyBwd25lZA==]8;;http://evil.example/\\y\302\2332J'
  [ "${lines[0]}" = "$stripped (12)" ]
  [ "${lines[1]}" = "$stripped" ]
}

@test "legitimate UTF-8 text displays unchanged in pretty output" {
  local s user=$'j\303\266s\303\251' path=$'/caf\303\251/\302\251\302\240\342\202\254/\346\227\245\346\234\254'
  : > "$BATS_TEST_TMPDIR/utf8-auth.log"
  for s in 00 01 02; do
    printf 'Jun  1 10:00:%s bastion sshd[100]: Failed password for %s from 203.0.113.66 port 40%s ssh2\n' \
      "$s" "$user" "$s" >> "$BATS_TEST_TMPDIR/utf8-auth.log"
  done
  run "$BL" --no-color "$BATS_TEST_TMPDIR/utf8-auth.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"targeted_users"*"$user (3)"* ]]
  [[ "$output" != *'\x'* ]]

  : > "$BATS_TEST_TMPDIR/utf8-web.log"
  for s in 1 2; do
    printf '203.0.113.66 - - [01/Jun/2025:10:00:0%s +0000] "GET %s HTTP/1.1" 200 12 "-" "curl/8.0"\n' \
      "$s" "$path" >> "$BATS_TEST_TMPDIR/utf8-web.log"
  done
  run "$BL" --no-color --iocs "$BATS_TEST_TMPDIR/utf8-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"top_paths"*"$path (2)"* ]]
  [[ "$output" != *'\x'* ]]
}

@test "pretty output shows control bytes as visible escapes under a Shift-JIS locale" {
  local loc
  loc=$(find_locale ja_JP.SJIS)
  if [ -z "$loc" ]; then
    skip "ja_JP.SJIS is not installed (locale -a does not list it)"
  fi
  # ASCII-only input under a multibyte locale, where bash would match by
  # character if pretty_safe did not set LC_ALL=C.
  write_hostile_web
  run env LC_ALL="$loc" "$BL" --no-color "$BATS_TEST_TMPDIR/web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" == *"top_paths"*"/p${HOSTILE_SEQ_SHOWN}q?id=1+union+select+1 (3)"* ]]
}

@test "legitimate GBK text displays unchanged under its own locale" {
  local loc path=$'/\302\200\302\233'
  loc=$(find_locale zh_CN.GBK)
  if [ -z "$loc" ]; then
    skip "zh_CN.GBK is not installed (locale -a does not list it)"
  fi
  # Two GBK ideographs whose bytes are exactly the UTF-8 form of two C1
  # controls. In a GBK locale they are text and must print as they are.
  write_legacy_web "$path"
  run env LC_ALL="$loc" "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"top_paths"*"$path (2)"* ]]
  [[ "$output" != *'\x'* ]]
}

@test "legitimate Shift-JIS text displays unchanged under its own locale" {
  local loc path=$'/\202\302\202\242'
  loc=$(find_locale ja_JP.SJIS)
  if [ -z "$loc" ]; then
    skip "ja_JP.SJIS is not installed (locale -a does not list it)"
  fi
  # Two kana; the trail byte of the first and the lead byte of the second
  # read as a UTF-8 C1 control (\302\202) if taken out of context.
  write_legacy_web "$path"
  run env LC_ALL="$loc" "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"top_paths"*"$path (2)"* ]]
  [[ "$output" != *'\x'* ]]
}

@test "pretty output shows UTF-8 C1 controls as visible escapes when no C0 byte is present" {
  local LC_ALL=C path=$'/a\302\2332Jb\302\23552;c;QQ==\302\234c\302\220d\302\237e\302\215f'
  # CSI, OSC 52 with its ST terminator, DCS, APC, and reverse index from the
  # \302\200-\302\217 half, all in UTF-8 form and with no C0 byte beside them,
  # so only the \302 check sends the value to the rewrite.
  write_legacy_web "$path"
  run env LC_ALL=C "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\302'* ]]
  [[ "$output" == *"top_paths"*'/a\xc2\x9b2Jb\xc2\x9d52;c;QQ==\xc2\x9cc\xc2\x90d\xc2\x9fe\xc2\x8df (2)'* ]]
}

@test "pretty output shows every C0 control and DEL as a visible escape with no ESC present" {
  local i ch hex raw="" shown="" n=0
  # Every C0 byte but ESC, then DEL. With no ESC to trip it, the value reaches
  # the rewrite only if each of these bytes is in the control set. A file name
  # carries them because no log parser splits it on VT, FF or CR first.
  for ((i = 1; i < 32; i++)); do
    if [ "$i" -eq 27 ]; then continue; fi
    printf -v hex '%02x' "$i"
    printf -v ch '%b' "\\x$hex"
    raw+=$ch
    shown+="\\x$hex"
  done
  raw+=$'\177'
  shown+='\x7f'
  cp "$FIXTURES/generic/clean.log" "$BATS_TEST_TMPDIR/c${raw}z.log"
  run "$BL" --no-color "$BATS_TEST_TMPDIR/c${raw}z.log"
  [ "$status" -eq 0 ]
  for ((i = 0; i < ${#raw}; i++)); do
    ch=${raw:i:1}
    if [ "$ch" != $'\n' ] && [[ "$output" == *"$ch"* ]]; then n=$((n + 1)); fi
  done
  [ "$n" -eq 0 ]
  [[ "$output" == *"c${shown}z.log"* ]]
}

@test "each control character on its own is shown as a visible escape" {
  # One control per value, so each must be in the control set by itself to
  # reach the rewrite: every C0 byte, DEL, and every UTF-8 C1 pair. Any
  # value that comes back wrong prints its byte in hex.
  run env LC_ALL=C bash -c '
    source "$1"
    for ((i = 1; i < 160; i++)); do
      if [ "$i" -ge 32 ] && [ "$i" -lt 127 ]; then continue; fi
      printf -v hex "%02x" "$i"
      if [ "$i" -lt 128 ]; then
        printf -v ch "%b" "\\x$hex"
        want="a\\x${hex}b"
      else
        printf -v ch "%b" "\\xc2\\x$hex"
        want="a\\xc2\\x${hex}b"
      fi
      pretty_safe "a${ch}b"
      if [ "$PRETTY_SAFE" != "$want" ]; then printf "%s " "$hex"; fi
    done
  ' _ "$REPO_ROOT/lib/core/output.sh"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "UTF-8 C1 controls are escaped under a locale named without its charset" {
  local LC_ALL=C
  # macOS en_US is UTF-8 under a bare name; where en_US is missing or is
  # glibc's ISO-8859-1, CSI must still come out as text. No raw \233 survives.
  write_legacy_web $'/a\302\2332Jb'
  run env -u LC_ALL -u LC_CTYPE LANG=en_US "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\233'* ]]
  [[ "$output" == *"top_paths"*'\x9b2Jb (2)'* ]]
}

@test "raw C1 bytes show as visible escapes under an ISO-8859 locale" {
  local LC_ALL=C loc path=$'/caf\351/a\233b\302\233c'
  loc=$(find_locale en_US.ISO8859-1)
  if [ -z "$loc" ]; then loc=$(find_locale en_US.iso88591); fi
  if [ -z "$loc" ]; then
    skip "no en_US ISO-8859-1 locale is installed (locale -a lists none)"
  fi
  # Latin-1 has no text at \200-\237, only C1 controls, and \233 is CSI. The
  # e acute (\351) and A circumflex (\302) beside them are text and stay.
  write_legacy_web "$path"
  run env LC_ALL="$loc" "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\233'* ]]
  [[ "$output" == *"top_paths"*$'/caf\351/a''\x9b'$'b\302''\x9bc (2)'* ]]
}

@test "raw C1 bytes are escaped under an EUC locale, and EUC text stays" {
  local LC_ALL=C loc
  loc=$(find_locale ja_JP.eucJP)
  if [ -z "$loc" ]; then
    skip "ja_JP.eucJP is not installed (locale -a does not list it)"
  fi
  # EUC keeps \200-\237 for C1 controls, so raw CSI (\233) is shown as text.
  # SS2 (\216) is in that range but opens a half-width kana, here \216\261,
  # so it stays, as does the hiragana \244\242. pretty_safe is called
  # directly, so the value reaches it whatever a log parser makes of the line.
  printf '/\244\242/a\233b\216\261c\n' > "$BATS_TEST_TMPDIR/euc.txt"
  run env LC_ALL="$loc" bash -c '
    source "$1"
    IFS= read -r v < "$2"
    pretty_safe "$v"
    LC_ALL=C
    printf "%s" "$PRETTY_SAFE"
  ' _ "$REPO_ROOT/lib/core/output.sh" "$BATS_TEST_TMPDIR/euc.txt"
  [ "$status" -eq 0 ]
  [ "$output" = $'/\244\242/a''\x9b'$'b\216\261c' ]
}

@test "a long run of one control byte is rewritten in full" {
  local k esc="" shown=""
  # od folds repeated 16-byte lines into a single "*" line unless given -v,
  # and 64 ESC bytes in a row fill several identical lines.
  for ((k = 0; k < 64; k++)); do
    esc+=$'\033'
    shown+='\x1b'
  done
  write_legacy_web "/e${esc}z"
  run "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" == *"top_paths"*"/e${shown}z (2)"* ]]
}

@test "pretty output adds no locale warnings when LC_ALL names a missing locale" {
  local l n=0
  # Bash warns once at startup about an LC_ALL it cannot load, and again each
  # time a function's local LC_ALL is unwound; the second kind must not leak.
  write_hostile_web
  run env LC_ALL=xx_YY.UTF-8 "$BL" --no-color "$BATS_TEST_TMPDIR/web.log"
  [ "$status" -eq 0 ]
  for l in "${lines[@]}"; do
    case $l in *setlocale*) n=$((n + 1)) ;; esac
  done
  [ "$n" -le 1 ]
}

@test "pretty output fails closed when the control-byte rewrite cannot run" {
  local mock="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$mock"
  # An od that fails leaves the rewrite with nothing to work from; the value
  # must be replaced, never printed raw.
  printf '#!/bin/sh\nexit 1\n' > "$mock/od"
  chmod +x "$mock/od"
  write_hostile_web
  run env PATH="$mock:$PATH" "$BL" --no-color "$BATS_TEST_TMPDIR/web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" == *"top_paths"*"[unprintable]"* ]]
}

@test "ESC-dense request paths render in bounded time" {
  local s k p="" start
  # SECURITY: five request paths of 2,600 CSI sequences each (7.8 KB, inside
  # the usual 8 KB request-line limit). A per-byte ${v//x/y} rewrite took
  # over a minute on this under bash 4.0; one linear pass takes well under 1s.
  for ((k = 0; k < 2600; k++)); do p+=$'\033[A'; done
  : > "$BATS_TEST_TMPDIR/dense.log"
  for s in 1 2 3 4 5; do
    printf '203.0.113.66 - - [01/Jun/2025:10:00:0%s +0000] "GET /%s%s HTTP/1.1" 404 0 "-" "curl/8.0"\n' \
      "$s" "$s" "$p" >> "$BATS_TEST_TMPDIR/dense.log"
  done
  start=$SECONDS
  run "$BL" --no-color "$BATS_TEST_TMPDIR/dense.log"
  [ "$status" -eq 0 ]
  [ $((SECONDS - start)) -lt 20 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" == *"top_paths"*'/1\x1b[A\x1b[A'* ]]
}

@test "stderr shows control bytes in an unreadable file name as visible escapes" {
  run "$BL" "$BATS_TEST_TMPDIR/gone"$'\033[2J\033]0;x\007'".log"
  [ "$status" -eq 2 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" == *"cannot read"*'gone\x1b[2J\x1b]0;x\x07.log'* ]]
}

@test "stderr shows control bytes in a file name as visible escapes on a --strict failure" {
  local f="$BATS_TEST_TMPDIR/mixed"$'\033[2J\033]0;x\007'".log"
  cp "$FIXTURES/generic/mixed.log" "$f"
  run "$BL" --strict "$f"
  [ "$status" -eq 2 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" == *"--strict"* ]]
  [[ "$output" == *'mixed\x1b[2J\x1b]0;x\x07.log'* ]]
}

@test "stderr shows control bytes in an unknown option as visible escapes" {
  # A file name that starts with a dash is parsed as an option and quoted.
  run "$BL" $'-\033[2J\033]0;x\007.log'
  [ "$status" -eq 1 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\007'* ]]
  [[ "$output" == *"unknown option"*'-\x1b[2J\x1b]0;x\x07.log'* ]]
}

@test "raw C1 bytes in a log show as visible escapes under an EUC locale" {
  local LC_ALL=C loc path=$'/\244\242/a\233b\216\261c'
  loc=$(find_locale ja_JP.eucJP)
  if [ -z "$loc" ]; then
    skip "ja_JP.eucJP is not installed (locale -a does not list it)"
  fi
  # EUC keeps \200-\237 for C1 controls, so raw CSI (\233) is shown as text.
  # SS2 (\216) is in that range but opens a half-width kana, here \216\261,
  # so it stays, as does the hiragana \244\242.
  write_legacy_web "$path"
  run env LC_ALL="$loc" "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\233'* ]]
  [[ "$output" == *"top_paths"*$'/\244\242/a''\x9b'$'b\216\261c (2)'* ]]
}

@test "a stray EUC lead byte reaches the report unchanged" {
  local LC_ALL=C loc
  loc=$(find_locale ja_JP.eucJP)
  if [ -z "$loc" ]; then
    skip "ja_JP.eucJP is not installed (locale -a does not list it)"
  fi
  # SS3 (\217) opens a three-byte character. Followed by ASCII instead, it
  # stopped BSD awk under EUC, and bash expansion there added a \001 after it.
  write_legacy_web $'/a\217b'
  run env LC_ALL="$loc" "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\001'* ]]
  [[ "$output" == *"top_paths"*$'/a\217b (2)'* ]]
}

@test "an invalid UTF-8 byte next to a control byte neither stops the run nor leaks" {
  local LC_ALL=C l loc=""
  for l in en_US.UTF-8 en_US.utf8 C.UTF-8 C.utf8; do
    loc=$(find_locale "$l")
    if [ -n "$loc" ]; then break; fi
  done
  if [ -z "$loc" ]; then
    skip "no UTF-8 locale is installed (locale -a lists none)"
  fi
  # SECURITY: BSD awk under a UTF-8 locale stopped at \377 with "illegal byte
  # sequence" and printed the raw line, ESC included, to stderr.
  write_legacy_web $'/a\377\033[2Jb'
  run env LC_ALL="$loc" "$BL" --no-color "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" == *"top_paths"*$'/a\377''\x1b[2Jb (2)'* ]]
  run env LC_ALL="$loc" "$BL" -o json "$BATS_TEST_TMPDIR/legacy-web.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
}
