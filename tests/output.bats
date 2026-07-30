#!/usr/bin/env bats
# output.bats - JSON/NDJSON validity and pretty-mode basics

load test_helper

@test "json output parses and has the expected shape" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/generic/mixed.log\" | jq -e '.tool, .format, .metrics, .findings, .threat' >/dev/null"
  [ "$status" -eq 0 ]
}

@test "json reports generic format and correct core metrics" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/generic/mixed.log\" | jq -r '.format, .metrics.total_lines, .metrics.unique_source_ips, (.findings | length)'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "generic" ]
  [ "${lines[1]}" = "15" ]
  [ "${lines[2]}" = "3" ]
  [ "${lines[3]}" = "4" ]
}

@test "json escapes are valid for jq on every finding" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/generic/mixed.log\" | jq -e '.findings[].message' >/dev/null"
  [ "$status" -eq 0 ]
}

@test "ndjson emits one parseable object per line, summary last" {
  run bash -c "\"$BL\" -o ndjson \"$FIXTURES/generic/mixed.log\" | jq -r .type"
  [ "$status" -eq 0 ]
  [ "${lines[${#lines[@]}-1]}" = "summary" ]
  for l in "${lines[@]}"; do
    [[ "$l" == "finding" || "$l" == "summary" ]]
  done
}

@test "pretty output with --no-color has no escape bytes" {
  run "$BL" --no-color "$FIXTURES/generic/mixed.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Threat score"* ]]
  [[ "$output" != *$'\033'* ]]
}

@test "stdin input via - reports (stdin) as the file" {
  run bash -c "cat \"$FIXTURES/generic/mixed.log\" | \"$BL\" -o json - | jq -r .file"
  [ "$status" -eq 0 ]
  [ "$output" = "(stdin)" ]
}

@test "NO_COLOR env disables colors even on pretty" {
  run bash -c "NO_COLOR=1 \"$BL\" \"$FIXTURES/generic/clean.log\""
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
}
