#!/usr/bin/env bats
# cli.bats - argument handling and the usage half of the exit-code contract

load test_helper

@test "--version prints the version" {
  run "$BL" --version
  [ "$status" -eq 0 ]
  [[ "$output" == bashedlogs\ 2* ]]
}

@test "--help exits 0 and shows usage" {
  run "$BL" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage:"* ]]
  [[ "$output" == *"--fail-level"* ]]
}

@test "no arguments is a usage error (exit 1)" {
  run "$BL"
  [ "$status" -eq 1 ]
}

@test "unknown option is a usage error (exit 1)" {
  run "$BL" --frobnicate x.log
  [ "$status" -eq 1 ]
  [[ "$output" == *"unknown option"* ]]
}

@test "bad output mode is a usage error (exit 1)" {
  run "$BL" -o yaml "$FIXTURES/generic/clean.log"
  [ "$status" -eq 1 ]
}

@test "unknown --format is a usage error (exit 1)" {
  run "$BL" --format nosuch "$FIXTURES/generic/clean.log"
  [ "$status" -eq 1 ]
}

@test "missing input file exits 2" {
  run "$BL" /no/such/file.log
  [ "$status" -eq 2 ]
}

@test "--list-formats includes generic" {
  run "$BL" --list-formats
  [ "$status" -eq 0 ]
  [[ "$output" == *generic* ]]
}

@test "help does not advertise unimplemented flags" {
  run "$BL" --help
  [[ "$output" != *"--iocs"* ]]
  [[ "$output" != *"--bf-threshold"* ]]
  [[ "$output" != *"--enrich-online"* ]]
}
