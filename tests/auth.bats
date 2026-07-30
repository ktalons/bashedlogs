#!/usr/bin/env bats
# auth.bats - auth_ssh analyzer: windowed brute force + compromise heuristic
# The scenario pair here is the M2 contract: a burst MUST alert, a slow drip
# over the same total count MUST NOT.

load test_helper

setup() {
  export BASHEDLOGS_ASSUME_YEAR=2025
}

@test "auth log is detected as auth_ssh" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/auth/bruteforce.log\" | jq -r .format"
  [ "$status" -eq 0 ]
  [ "$output" = "auth_ssh" ]
}

@test "burst of 12 failures in 40s trips the default window" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/auth/bruteforce.log\" | jq -r '[.findings[] | select(.category==\"brute-force\")][0] | .severity, .data.ip, .data.count'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "high" ]
  [ "${lines[1]}" = "203.0.113.66" ]
  [ "${lines[2]}" = "12" ]
}

@test "success shortly after a burst is flagged as possible compromise" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/auth/bruteforce.log\" | jq -r '[.findings[] | select(.category==\"possible-compromise\")][0] | .severity, .data.ip, .data.user'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "critical" ]
  [ "${lines[1]}" = "203.0.113.66" ]
  [ "${lines[2]}" = "admin" ]
}

@test "invalid-user preambles are not double-counted as failures" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/auth/bruteforce.log\" | jq -r '.metrics.failed_auth, .metrics.invalid_user_lines'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "12" ]
  [ "${lines[1]}" = "3" ]
}

@test "10 failures spread over 24h do NOT trip the default window" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/auth/slowdrip.log\" | jq -r '[.findings[] | select(.category==\"brute-force\")] | length'"
  [ "$status" -eq 0 ]
  [ "$output" = "0" ]
}

@test "slow drip exits 0 even with --fail-level high" {
  run "$BL" -o json --fail-level high "$FIXTURES/auth/slowdrip.log"
  [ "$status" -eq 0 ]
}

@test "--bf-threshold and --bf-window change the verdict" {
  run bash -c "\"$BL\" -o json --bf-threshold 5 --bf-window 86400 \"$FIXTURES/auth/slowdrip.log\" | jq -r '[.findings[] | select(.category==\"brute-force\")][0].data.count'"
  [ "$status" -eq 0 ]
  [ "$output" = "10" ]
}

@test "root attempts get their own finding" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/auth/bruteforce.log\" | jq -r '[.findings[] | select(.category==\"root-attempts\")][0].data.count'"
  [ "$status" -eq 0 ]
  [ "$output" = "3" ]
}

@test "top attacker metric is field-exact, not substring-inflated" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/auth/bruteforce.log\" | jq -r .metrics.top_attacking_ips"
  [ "$status" -eq 0 ]
  [ "$output" = "203.0.113.66 (12)" ]
}

@test "sliding window is exact at its boundary" {
  # 7 failures: six at 10s intervals (span 50s), then one at +65s from the first.
  log="$BATS_TEST_TMPDIR/boundary.log"
  for s in 00 10 20 30 40 50; do
    printf 'Jun  1 10:00:%s h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2\n' "$s"
  done > "$log"
  printf 'Jun  1 10:01:05 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2\n' >> "$log"

  # Six DO fit in a 60s window.
  run bash -c "\"$BL\" -o json --bf-threshold 6 --bf-window 60 \"$log\" | jq -r '[.findings[]|select(.category==\"brute-force\")][0].data.count'"
  [ "$output" = "6" ]

  # Seven never do, because the last one is 65s after the first.
  run bash -c "\"$BL\" -o json --bf-threshold 7 --bf-window 60 \"$log\" | jq -r '[.findings[]|select(.category==\"brute-force\")]|length'"
  [ "$output" = "0" ]
}

@test "healthy auth log yields zero findings" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/auth/normal.log\" | jq -r '(.findings | length), .threat.level'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "0" ]
  [ "${lines[1]}" = "none" ]
}
