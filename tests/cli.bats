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

@test "help documents every implemented flag" {
  run "$BL" --help
  [ "$status" -eq 0 ]
  for flag in --output --format --list-formats --strict --fail-level \
              --bf-threshold --bf-window --iocs --defang --mmdb-dir \
              --enrich-online --no-color --version; do
    [[ "$output" == *"$flag"* ]] || {
      echo "help is missing $flag" >&2
      return 1
    }
  done
}

@test "help states that online lookups are opt-in" {
  run "$BL" --help
  [[ "$output" == *"no network call is ever made"* ]]
}

@test "every documented flag is accepted by the parser" {
  run "$BL" --iocs --defang --enrich-online --bf-threshold 5 --bf-window 30 \
      --mmdb-dir /nonexistent --no-color -o json "$FIXTURES/generic/clean.log"
  [ "$status" -eq 0 ]
}

@test "zero and non-numeric brute-force values are rejected" {
  run "$BL" --bf-threshold 0 "$FIXTURES/generic/clean.log"
  [ "$status" -eq 1 ]
  run "$BL" --bf-window abc "$FIXTURES/generic/clean.log"
  [ "$status" -eq 1 ]
}
