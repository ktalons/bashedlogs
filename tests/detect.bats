#!/usr/bin/env bats
# detect.bats - detection engine behavior and the --strict contract

load test_helper

@test "unrecognized content falls back to generic" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/generic/mixed.log\" | jq -r .format"
  [ "$status" -eq 0 ]
  [ "$output" = "generic" ]
}

@test "--strict exits 2 when only the generic fallback matches" {
  run "$BL" --strict -o json "$FIXTURES/generic/mixed.log"
  [ "$status" -eq 2 ]
}

@test "--format generic forces the generic analyzer" {
  run bash -c "\"$BL\" --format generic -o json \"$FIXTURES/generic/clean.log\" | jq -r .format"
  [ "$status" -eq 0 ]
  [ "$output" = "generic" ]
}

@test "--format bypasses --strict detection failure" {
  run "$BL" --strict --format generic -o json "$FIXTURES/generic/mixed.log"
  [ "$status" -eq 0 ]
}
