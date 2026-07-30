#!/usr/bin/env bats
# regressions.bats - one test per defect found in the pre-release audit.
# Each of these failed before its fix; the comment records what the tool
# reported at the time so a regression is unambiguous.

load test_helper

setup() {
  export BASHEDLOGS_ASSUME_YEAR=2025
  if ! command -v jq >/dev/null 2>&1; then
    echo "tests require jq" >&2
    return 1
  fi
}

# --- Debian dual logging: reported 6 failures for 3 real attempts -------------

@test "dual-logged sshd+PAM counts each attempt once" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/pam-dual.log\" | jq -r '.metrics.failed_auth, .metrics.failure_source, .metrics.top_attacking_ips'"
  [ "${lines[0]}" = "3" ]
  [ "${lines[1]}" = "sshd" ]
  [ "${lines[2]}" = "203.0.113.5 (3)" ]
}

@test "dual logging does not halve the brute-force threshold" {
  # 3 real attempts must not raise an alert at a threshold of 6.
  run bash -c "\"$BL\" -o json --bf-threshold 6 \"$FIXTURES/regressions/pam-dual.log\" | jq -r '[.findings[]|select(.category==\"brute-force\")]|length'"
  [ "$output" = "0" ]
}

@test "duplicate PAM lines are disclosed, not silently dropped" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/pam-dual.log\" | jq -r '.metrics.pam_duplicate_lines'"
  [[ "$output" == "3 (not counted)" ]]
}

@test "a PAM-only export still yields failures" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/pam-only.log\" | jq -r '.metrics.failed_auth, .metrics.failure_source'"
  [ "${lines[0]}" = "3" ]
  [ "${lines[1]}" = "pam" ]
}

# --- IPv6: counted failures but produced zero findings ------------------------

@test "an IPv6 brute force is detected, not silently ignored" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/ipv6-brute.log\" | jq -r '.metrics.failed_auth, .metrics.top_attacking_ips, [.findings[]|select(.category==\"brute-force\")][0].data.ip'"
  [ "${lines[0]}" = "12" ]
  [ "${lines[1]}" = "2001:db8::dead:beef (12)" ]
  [ "${lines[2]}" = "2001:db8::dead:beef" ]
}

@test "IPv6 sources are counted by the firewall analyzer" {
  run bash -c "\"$BL\" --format firewall -o json \"$FIXTURES/regressions/firewall-icmp.log\" | jq -r .metrics.top_blocked_sources"
  [[ "$output" == *"2001:db8::99"* ]]
}

@test "address validation accepts real IPv6 and rejects malformed" {
  run bash -c "
    source \"$REPO_ROOT/lib/core/awklib.sh\"
    awk \"\$AWK_IP_LIB\"'
      BEGIN {
        split(\"2001:db8::dead:beef|::1|fe80::1%eth0|::ffff:192.0.2.1|203.0.113.5\", g, \"|\")
        split(\"2001:db8:::1|gggg::1|2001:db8::dead::beef|1:2:3:4:5:6:7:8:9|999.1.1.1|12345::1|:\", b, \"|\")
        for (i in g) if (!bl_valid_ip(bl_clean_ip(g[i]))) { print \"FALSE NEGATIVE: \" g[i]; bad=1 }
        for (i in b) if (bl_valid_ip(bl_clean_ip(b[i])))  { print \"FALSE POSITIVE: \" b[i]; bad=1 }
        exit bad
      }' </dev/null
  "
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

# --- pfSense/iptables ICMP: type and code were reported as ports --------------

@test "ICMP events contribute no ports" {
  run bash -c "\"$BL\" --format firewall -o json \"$FIXTURES/regressions/firewall-icmp.log\" | jq -r .metrics.top_target_ports"
  # Only the three real tcp ports; no port 0 and no icmp type/code.
  [ "$output" = "22 (1), 443 (1), 8443 (1)" ]
}

@test "ICMP blocks are still counted as blocked events" {
  run bash -c "\"$BL\" --format firewall -o json \"$FIXTURES/regressions/firewall-icmp.log\" | jq -r '.metrics.total_events, .metrics.blocked_events'"
  [ "${lines[0]}" = "6" ]
  [ "${lines[1]}" = "6" ]
}

# --- Wazuh: manager.name shadowed agent.name on every alert ------------------

@test "wazuh attributes alerts to agent.name, not manager.name" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/wazuh-nested.json\" | jq -r .metrics.top_agents"
  [ "$output" = "db-01 (1), web-01 (1)" ]
  [[ "$output" != *"wazuh-mgr"* ]]
}

@test "wazuh reads level and description from the rule object" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/wazuh-nested.json\" | jq -r '.metrics.max_level, .metrics.level_12_plus'"
  [ "${lines[0]}" = "12" ]
  [ "${lines[1]}" = "1" ]
}

@test "an escaped quote in a description is not truncated" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/wazuh-nested.json\" | jq -r .metrics.top_rules"
  [[ "$output" == *'user said "hi" then failed'* ]]
}

@test "wazuh handles an IPv6 srcip" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/wazuh-nested.json\" | jq -e . >/dev/null"
  [ "$status" -eq 0 ]
}

# --- Realistic fixture shape: the clean fixture hid the bug above -------------

@test "the main wazuh fixture carries manager and decoder names" {
  # If this fixture ever loses its sibling name fields, the misattribution bug
  # becomes invisible again.
  run grep -c '"manager":{"name":"wazuh-mgr"}' "$FIXTURES/wazuh/alerts.json"
  [ "$output" = "15" ]
  run bash -c "\"$BL\" -o json \"$FIXTURES/wazuh/alerts.json\" | jq -r .metrics.top_agents"
  [[ "$output" != *"wazuh-mgr"* ]]
  [[ "$output" == "bastion (11)"* ]]
}

# --- Free-text values carrying a raw tab used to split the internal row -------

@test "a raw tab in a rule description is folded, not truncated" {
  printf '{"manager":{"name":"m"},"agent":{"id":"1","name":"web-01"},"rule":{"level":12,"description":"tab\there and more"},"data":{"srcip":"203.0.113.9"}}\n' \
    > "$BATS_TEST_TMPDIR/tab.json"
  run bash -c "\"$BL\" -o json \"$BATS_TEST_TMPDIR/tab.json\" | jq -r .metrics.top_rules"
  [ "$output" = "tab here and more (1)" ]
}

# --- Confirmed non-defects, pinned so they are not "fixed" by accident -------

@test "concatenated rotated logs still detect a burst" {
  # An out-of-order Dec line ahead of June traffic must not suppress the burst.
  {
    printf 'Dec 31 23:59:00 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2\n'
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
      printf 'Jun  1 10:00:%02d h sshd[%d]: Failed password for root from 203.0.113.7 port %d ssh2\n' "$i" "$i" "$i"
    done
  } > "$BATS_TEST_TMPDIR/rotated.log"
  run bash -c "\"$BL\" -o json \"$BATS_TEST_TMPDIR/rotated.log\" | jq -r '[.findings[]|select(.category==\"brute-force\")][0].data.count'"
  [ "$output" = "12" ]
}

@test "leading-zero numeric flags are accepted as decimal" {
  run "$BL" --bf-threshold 010 --bf-window 060 -o json "$FIXTURES/generic/clean.log"
  [ "$status" -eq 0 ]
}
