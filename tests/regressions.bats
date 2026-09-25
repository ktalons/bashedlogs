#!/usr/bin/env bats
# ******************************************************************************
# *Title: Regression Tests*
# *Author: Kyle Versluis (@ktalons)*
# *Description: One test per defect found in the pre-release audit.*
# ******************************************************************************

# NOTE: each test failed before its fix; the note above every group below
# records what the tool reported at the time so a regression is unambiguous.

load test_helper

setup() {
  export BASHEDLOGS_ASSUME_YEAR=2025
  if ! command -v jq >/dev/null 2>&1; then
    echo "tests require jq" >&2
    return 1
  fi
}

# *--- Debian Dual Logging ---*
# NOTE: dual-logged sshd+PAM reported 6 failures for 3 real attempts.

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

# *--- IPv6 Handling ---*
# NOTE: IPv6 addresses were counted as failures but produced zero findings.

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

# *--- ICMP Port Reporting ---*
# NOTE: pfSense/iptables ICMP type and code were reported as ports.

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

# *--- Wazuh Agent Attribution ---*
# NOTE: manager.name shadowed agent.name on every alert.

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

# *--- Fixture Shape Guard ---*
# NOTE: the clean wazuh fixture hid the manager/agent shadowing bug above
# because it carried no sibling name fields to conflict.

@test "the main wazuh fixture carries manager and decoder names" {
  # If this fixture ever loses its sibling name fields, the misattribution bug
  # becomes invisible again.
  run grep -c '"manager":{"name":"wazuh-mgr"}' "$FIXTURES/wazuh/alerts.json"
  [ "$output" = "15" ]
  run bash -c "\"$BL\" -o json \"$FIXTURES/wazuh/alerts.json\" | jq -r .metrics.top_agents"
  [[ "$output" != *"wazuh-mgr"* ]]
  [[ "$output" == "bastion (11)"* ]]
}

# *--- Tab-Delimited Field Safety ---*
# NOTE: a raw tab in a free-text value used to split the internal row.

@test "a raw tab in a rule description is folded, not truncated" {
  printf '{"manager":{"name":"m"},"agent":{"id":"1","name":"web-01"},"rule":{"level":12,"description":"tab\there and more"},"data":{"srcip":"203.0.113.9"}}\n' \
    > "$BATS_TEST_TMPDIR/tab.json"
  run bash -c "\"$BL\" -o json \"$BATS_TEST_TMPDIR/tab.json\" | jq -r .metrics.top_rules"
  [ "$output" = "tab here and more (1)" ]
}

# *--- Access Log Escaped Quotes ---*
# NOTE: Apache logs a quote in a field as \"; splitting on every quote hid SQLi
# and XSS and read the status from attacker text. The last three tests pass
# before the fix too: they pin parsing the fix must not move.

@test "an escaped quote in the request does not hide SQL injection" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/web-escaped-quote.log\" | jq -r '.format, [.findings[]|select(.category==\"injection-sqli\")][0].data.example'"
  [ "${lines[0]}" = "web_access" ]
  [ "${lines[1]}" = '/products.php?a=\"&id=1+union+select+password+from+users' ]
}

@test "an escaped quote in the request does not hide an XSS probe" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/web-escaped-quote.log\" | jq -r '[.findings[]|select(.category==\"injection-xss\")][0].data.example'"
  [ "$output" = '/search?q=\"><script>alert(1)</script>' ]
}

@test "an escaped quote cannot spoof the status or hide a 404 scan" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/web-escaped-quote.log\" | jq -r '.metrics.status_2xx, .metrics.status_4xx, .metrics.status_5xx'"
  [ "${lines[0]}" = "3" ]
  [ "${lines[1]}" = "12" ]
  [ "${lines[2]}" = "1" ]
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/web-escaped-quote.log\" | jq -r '[.findings[]|select(.category==\"scanning\")][0].data | .ip, .status_404'"
  [ "${lines[0]}" = "203.0.113.99" ]
  [ "${lines[1]}" = "12" ]
}

@test "an escaped quote in the user field does not hide SQL injection" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/web-escaped-user.log\" | jq -r '.format, .metrics.status_4xx, [.findings[]|select(.category==\"injection-sqli\")][0].data.example'"
  [ "${lines[0]}" = "web_access" ]
  [ "${lines[1]}" = "1" ]
  [ "${lines[2]}" = "/p?id=1+union+select+pw" ]
}

@test "an escaped backslash before the closing quote still ends the request" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/web-escaped-fields.log\" | jq -r '.metrics.status_4xx, .metrics.top_paths'"
  [ "${lines[0]}" = "2" ]
  [ "${lines[1]}" = '/a\\ (1), /b\\\\ (1), /r (1)' ]
}

@test "an escaped quote in the referer or user agent does not move the status" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/web-escaped-fields.log\" | jq -r '.metrics.status_2xx, .metrics.status_3xx, .metrics.status_5xx'"
  [ "${lines[0]}" = "0" ]
  [ "${lines[1]}" = "1" ]
  [ "${lines[2]}" = "0" ]
}

@test "a CRLF log with the status last still buckets every status" {
  # Built here, not in mkfixtures: a committed CRLF file risks line-ending
  # normalization. The \\ lines take the escape-aware split, the rest do not.
  {
    for i in 1 2 3 4 5 6; do
      printf '203.0.113.99 - - [10/Jun/2025:10:05:%02d -0700] "GET /probe%d HTTP/1.1" 404\r\n' "$i" "$i"
      printf '203.0.113.99 - - [10/Jun/2025:10:05:%02d -0700] "GET /scripts/..\\\\..\\\\cmd%d.exe HTTP/1.1" 404\r\n' "$((i + 6))" "$i"
    done
    printf '198.51.100.23 - - [10/Jun/2025:10:06:00 -0700] "GET / HTTP/1.1" 200\r\n'
  } > "$BATS_TEST_TMPDIR/crlf.log"
  [ "$(grep -c $'\r$' "$BATS_TEST_TMPDIR/crlf.log")" = "13" ]
  run bash -c "\"$BL\" -o json \"$BATS_TEST_TMPDIR/crlf.log\" | jq -r '.metrics.status_2xx, .metrics.status_4xx, [.findings[]|select(.category==\"scanning\")][0].data.status_404'"
  [ "${lines[0]}" = "1" ]
  [ "${lines[1]}" = "12" ]
  [ "${lines[2]}" = "12" ]
}

# *--- SSH Source Attribution ---*
# NOTE: a username of `x from 198.51.100.7` put that address on the brute force,
# cleared the real source, and turned a later login from it into a critical
# possible-compromise naming a real user.

@test "a username carrying an address does not steal the brute force" {
  run bash -c "\"$BL\" -o json --bf-threshold 5 --bf-window 300 \"$FIXTURES/regressions/ssh-framed-user.log\" | jq -r '.metrics.failed_auth, .metrics.top_attacking_ips, [.findings[]|select(.category==\"brute-force\")][0].data.ip'"
  [ "${lines[0]}" = "12" ]
  [ "${lines[1]}" = "203.0.113.66 (12)" ]
  [ "${lines[2]}" = "203.0.113.66" ]
}

@test "an address only a client supplied appears nowhere in the report" {
  run "$BL" --no-color --bf-threshold 5 --bf-window 300 "$FIXTURES/regressions/ssh-framed-user.log"
  [ "$status" -eq 0 ]
  [[ "$output" != *"198.51.100.7"* ]]
  run "$BL" -o json --bf-threshold 5 --bf-window 300 "$FIXTURES/regressions/ssh-framed-user.log"
  [[ "$output" != *"198.51.100.7"* ]]
}

@test "the compromise names the burst source, not the next login" {
  # alice logs in from the framed address 10 minutes later, innocently. The
  # accept that follows the burst is 'deploy', whose line carries a certificate
  # key ID holding the framed address after sshd's own `from`.
  run bash -c "\"$BL\" -o json --bf-threshold 5 --bf-window 300 \"$FIXTURES/regressions/ssh-framed-user.log\" | jq -r '[.findings[]|select(.category==\"possible-compromise\")]|length, .[0].data.ip, .[0].data.user'"
  [ "${lines[0]}" = "1" ]
  [ "${lines[1]}" = "203.0.113.66" ]
  [ "${lines[2]}" = "deploy" ]
}

@test "PAM reads rhost, not an address inside user=" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/ssh-framed-pam.log\" | jq -r '.metrics.failed_auth, .metrics.failure_source, .metrics.top_attacking_ips'"
  [ "${lines[0]}" = "3" ]
  [ "${lines[1]}" = "pam" ]
  [ "${lines[2]}" = "203.0.113.77 (3)" ]
}

@test "another program's message cannot forge an sshd tag" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/regressions/ssh-framed-tag.log\" | jq -r '.metrics.failed_auth, .metrics.top_attacking_ips, [.findings[]|select(.category==\"root-attempts\")][0].data.count'"
  [ "${lines[0]}" = "1" ]
  [ "${lines[1]}" = "203.0.113.77 (1)" ]
  [ "${lines[2]}" = "1" ]
}

@test "a rewritten program tag does not hide a real brute force" {
  # Requiring the tag to name ssh made a containerized sshd report 0 failures.
  run bash -c "\"$BL\" -o json --bf-threshold 5 --bf-window 300 \"$FIXTURES/regressions/ssh-rewritten-tag.log\" | jq -r '.metrics.failed_auth, .metrics.top_attacking_ips, [.findings[]|select(.category==\"brute-force\")][0].data.ip'"
  [ "${lines[0]}" = "6" ]
  [ "${lines[1]}" = "203.0.113.88 (6)" ]
  [ "${lines[2]}" = "203.0.113.88" ]
}

@test "stacked message prefixes do not swallow a failure" {
  # A relay re-stamps a Solaris id onto a line that has one, and a repeat
  # wrapper sits on either side of it. Stripping one of each left the second in
  # front of the event words, so 6 failures counted as 1 and no burst alerted.
  run bash -c "\"$BL\" -o json --bf-threshold 5 --bf-window 300 \"$FIXTURES/regressions/ssh-stacked-prefix.log\" | jq -r '.metrics.failed_auth, .metrics.top_attacking_ips, [.findings[]|select(.category==\"brute-force\")][0].data.ip'"
  [ "${lines[0]}" = "6" ]
  [ "${lines[1]}" = "203.0.113.99 (6)" ]
  [ "${lines[2]}" = "203.0.113.99" ]
}

@test "every log shape reads the same source from the same event" {
  # One event, six times, in the shapes that move the message start: journald
  # export, one-line json, RFC 5424 with a BOM, and `journalctl -o cat`, which
  # has no tag at all. --format is explicit so this tests framing, not
  # detection. The cat shape has no timestamp, so it has metrics, not findings.
  msg='Failed password for invalid user x from 198.51.100.7 from 203.0.113.66 port 40001 ssh2'
  bom=$(printf '\357\273\277')
  : > "$BATS_TEST_TMPDIR/export.log"
  : > "$BATS_TEST_TMPDIR/json.log"
  : > "$BATS_TEST_TMPDIR/rfc5424.log"
  : > "$BATS_TEST_TMPDIR/cat.log"
  for i in 1 2 3 4 5 6; do
    printf '__REALTIME_TIMESTAMP=174877200%d000000\nSYSLOG_IDENTIFIER=sshd\nMESSAGE=%s\n\n' \
      "$i" "$msg" >> "$BATS_TEST_TMPDIR/export.log"
    printf '{"__REALTIME_TIMESTAMP":"174877200%d000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"%s"}\n' \
      "$i" "$msg" >> "$BATS_TEST_TMPDIR/json.log"
    printf '<38>1 2025-06-01T10:00:0%d.000000-07:00 h sshd 20%d - - %s%s\n' \
      "$i" "$i" "$bom" "$msg" >> "$BATS_TEST_TMPDIR/rfc5424.log"
    printf '%s\n' "$msg" >> "$BATS_TEST_TMPDIR/cat.log"
  done
  for shape in export json rfc5424 cat; do
    run bash -c "\"$BL\" --format auth_ssh -o json \"$BATS_TEST_TMPDIR/$shape.log\" | jq -r '.metrics.failed_auth, .metrics.top_attacking_ips'"
    [ "${lines[0]}" = "6" ] || {
      echo "$shape: failed_auth ${lines[0]}" >&2
      return 1
    }
    [ "${lines[1]}" = "203.0.113.66 (6)" ] || {
      echo "$shape: top_attacking_ips ${lines[1]}" >&2
      return 1
    }
  done
}

# *--- Confirmed Non-Defects ---*
# NOTE: pinned so these behaviors are not "fixed" by accident.

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
