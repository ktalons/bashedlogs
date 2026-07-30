#!/usr/bin/env bats
# hostile.bats - log content is untrusted attacker-controlled input.
# These assert output stays parseable and nothing in a log line is ever
# executed, expanded, or treated as a printf format.

load test_helper

setup() {
  export BASHEDLOGS_ASSUME_YEAR=2025
  if ! command -v jq >/dev/null 2>&1; then
    echo "tests require jq" >&2
    return 1
  fi
}

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
