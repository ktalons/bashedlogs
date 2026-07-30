#!/usr/bin/env bats
# formats.bats - syslog, journald, and web_access analyzers

load test_helper

@test "syslog: detected and flags oom, segfault, sudo failures" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/syslog/system.log\" | jq -r '.format, ([.findings[].category] | sort | join(\",\"))'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "syslog" ]
  [ "${lines[1]}" = "oom-killer,segfault,sudo-failures" ]
}

@test "journald short-iso: detected with oom finding" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/journald/short-iso.log\" | jq -r '.format, .metrics.input_mode, ([.findings[].category] | join(\",\"))'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "journald" ]
  [ "${lines[1]}" = "iso" ]
  [ "${lines[2]}" = "oom-killer" ]
}

@test "journald json export: priority histogram drives findings" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/journald/export.json\" | jq -r '.format, .metrics.input_mode, ([.findings[].category] | sort | join(\",\"))'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "journald" ]
  [ "${lines[1]}" = "json" ]
  [ "${lines[2]}" = "journal-critical,oom-killer,segfault" ]
}

@test "web_access: detected with correct status accounting" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/web/access.log\" | jq -r '.format, .metrics.total_requests, .metrics.status_2xx, .metrics.status_3xx, .metrics.status_4xx, .metrics.status_5xx'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "web_access" ]
  [ "${lines[1]}" = "22" ]
  [ "${lines[2]}" = "7" ]
  [ "${lines[3]}" = "1" ]
  [ "${lines[4]}" = "13" ]
  [ "${lines[5]}" = "1" ]
}

@test "web_access: scanner, probes, sqli, traversal all flagged" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/web/access.log\" | jq -r '[.findings[].category] | sort | join(\",\")'"
  [ "$status" -eq 0 ]
  [ "$output" = "injection-sqli,path-traversal,scanning,sensitive-paths" ]
}

@test "web_access: scanner finding names the right IP" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/web/access.log\" | jq -r '[.findings[] | select(.category==\"scanning\")][0].data.ip'"
  [ "$status" -eq 0 ]
  [ "$output" = "203.0.113.99" ]
}

@test "web_access: quiet traffic yields zero findings" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/web/quiet.log\" | jq -r '(.findings | length), .threat.level'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "0" ]
  [ "${lines[1]}" = "none" ]
}

@test "generic fixtures still route to generic (no new-format claim-jumping)" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/generic/mixed.log\" | jq -r .format"
  [ "$status" -eq 0 ]
  [ "$output" = "generic" ]
}
