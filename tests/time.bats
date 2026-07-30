#!/usr/bin/env bats
# time.bats - the awk time library against independently known epochs

load test_helper

epoch_of() {
  bash -c "source \"$REPO_ROOT/lib/core/time.sh\" && bl_epoch_of \"$1\""
}

@test "unix epoch zero" {
  run epoch_of "1970-01-01T00:00:00"
  [ "$output" = "0" ]
}

@test "y2k constant" {
  run epoch_of "2000-01-01T00:00:00"
  [ "$output" = "946684800" ]
}

@test "2025 new year constant" {
  run epoch_of "2025-01-01T00:00:00"
  [ "$output" = "1735689600" ]
}

@test "post-leap-day 2024 (leap year handled)" {
  run epoch_of "2024-03-01T00:00:00"
  [ "$output" = "1709251200" ]
}

@test "fixture-era timestamp with time of day" {
  run epoch_of "2025-06-01T10:00:01"
  [ "$output" = "1748772001" ]
}

@test "space-separated and timezone-suffixed forms parse the same" {
  a=$(bash -c "source \"$REPO_ROOT/lib/core/time.sh\" && bl_epoch_of '2025-06-01 10:00:01'")
  b=$(bash -c "source \"$REPO_ROOT/lib/core/time.sh\" && bl_epoch_of '2025-06-01T10:00:01-0700'")
  [ "$a" = "1748772001" ]
  [ "$b" = "1748772001" ]
}
