#!/usr/bin/env bats
# exitcodes.bats - the pipeline/cron half of the exit-code contract

load test_helper

@test "findings at --fail-level exit 3" {
  run "$BL" -o json --fail-level high "$FIXTURES/generic/mixed.log"
  [ "$status" -eq 3 ]
}

@test "--fail-level above the worst finding exits 0" {
  # mixed.log tops out at high; critical must not trip
  run "$BL" -o json --fail-level critical "$FIXTURES/generic/mixed.log"
  [ "$status" -eq 0 ]
}

@test "clean log with --fail-level low exits 0" {
  run "$BL" -o json --fail-level low "$FIXTURES/generic/clean.log"
  [ "$status" -eq 0 ]
}

@test "clean log produces zero findings and threat none" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/generic/clean.log\" | jq -r '(.findings | length), .threat.level'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "0" ]
  [ "${lines[1]}" = "none" ]
}

@test "no --fail-level never exits 3 even with findings" {
  run "$BL" -o json "$FIXTURES/generic/mixed.log"
  [ "$status" -eq 0 ]
}
