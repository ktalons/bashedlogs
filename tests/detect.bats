#!/usr/bin/env bats
# ******************************************************************************
# *Title: Detection Engine*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Tests format detection fallback and the --strict contract.*
# ******************************************************************************

load test_helper

# *--- Generic Fallback ---*

@test "unrecognized content falls back to generic" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/generic/mixed.log\" | jq -r .format"
  [ "$status" -eq 0 ]
  [ "$output" = "generic" ]
}

@test "--strict exits 2 when only the generic fallback matches" {
  run "$BL" --strict -o json "$FIXTURES/generic/mixed.log"
  [ "$status" -eq 2 ]
}

# *--- Format Override ---*

@test "--format generic forces the generic analyzer" {
  run bash -c "\"$BL\" --format generic -o json \"$FIXTURES/generic/clean.log\" | jq -r .format"
  [ "$status" -eq 0 ]
  [ "$output" = "generic" ]
}

@test "--format bypasses --strict detection failure" {
  run "$BL" --strict --format generic -o json "$FIXTURES/generic/mixed.log"
  [ "$status" -eq 0 ]
}
