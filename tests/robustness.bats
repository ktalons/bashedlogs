#!/usr/bin/env bats
# robustness.bats - an analyzer must never abort or emit broken JSON, even when
# pointed at a log it was not written for. Forcing all 8 analyzers over every
# fixture is the cheapest way to catch an unguarded grep or an unbound array.

load test_helper

ALL_FORMATS="generic auth_ssh syslog journald web_access wazuh_alerts dns_route53 firewall"

setup() {
  export BASHEDLOGS_ASSUME_YEAR=2025
  if ! command -v jq >/dev/null 2>&1; then
    echo "tests require jq" >&2
    return 1
  fi
}

@test "every analyzer emits valid JSON for every fixture" {
  local bad=0
  for fx in "$FIXTURES"/*/*; do
    for f in $ALL_FORMATS; do
      if ! "$BL" --format "$f" --iocs -o json "$fx" 2>/dev/null | jq -e . >/dev/null 2>&1; then
        echo "invalid JSON: --format $f on $fx" >&2
        bad=1
      fi
    done
  done
  [ "$bad" -eq 0 ]
}

@test "every analyzer exits 0 on an empty file" {
  for f in $ALL_FORMATS; do
    : > "$BATS_TEST_TMPDIR/empty.log"
    run "$BL" --format "$f" --iocs -o json "$BATS_TEST_TMPDIR/empty.log"
    [ "$status" -eq 0 ] || {
      echo "--format $f exited $status on an empty file" >&2
      return 1
    }
  done
}

@test "every analyzer exits 0 on a single junk line" {
  echo "not a log line at all" > "$BATS_TEST_TMPDIR/junk.log"
  for f in $ALL_FORMATS; do
    run "$BL" --format "$f" --iocs -o json "$BATS_TEST_TMPDIR/junk.log"
    [ "$status" -eq 0 ] || {
      echo "--format $f exited $status on junk" >&2
      return 1
    }
  done
}

@test "octet validation rejects impossible addresses" {
  cat > "$BATS_TEST_TMPDIR/badip.log" <<'EOF'
999.999.999.999 - - [10/Jun/2025:10:00:00 -0700] "GET /a HTTP/1.1" 404 0 "-" "x"
256.1.1.1 - - [10/Jun/2025:10:00:01 -0700] "GET /b HTTP/1.1" 404 0 "-" "x"
203.0.113.5 - - [10/Jun/2025:10:00:02 -0700] "GET /c HTTP/1.1" 404 0 "-" "x"
EOF
  run bash -c "\"$BL\" --format web_access -o json \"$BATS_TEST_TMPDIR/badip.log\" | jq -r .metrics.top_clients"
  [ "$output" = "203.0.113.5 (1)" ]
}

@test "an awk injection attempt in a log field stays inert data" {
  cat > "$BATS_TEST_TMPDIR/inject.log" <<'EOF'
1.2.3.4"; system("id"); " - - [10/Jun/2025:10:00:00 -0700] "GET /a HTTP/1.1" 404 0 "-" "x"
EOF
  run "$BL" --format web_access --no-color "$BATS_TEST_TMPDIR/inject.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *"uid="*"gid="* ]]
}

@test "IOC output is valid with no IOCs present in any mode" {
  echo "nothing here at all" > "$BATS_TEST_TMPDIR/bare.log"
  run bash -c "\"$BL\" --iocs --defang -o json \"$BATS_TEST_TMPDIR/bare.log\" | jq -e '.iocs.ips == [] and .iocs.hashes.md5 == []' >/dev/null"
  [ "$status" -eq 0 ]
  run bash -c "\"$BL\" --iocs -o ndjson \"$BATS_TEST_TMPDIR/bare.log\" | tail -1 | jq -r .type"
  [ "$output" = "summary" ]
  run "$BL" --iocs --no-color "$BATS_TEST_TMPDIR/bare.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"IOCs (0)"* ]]
}
