#!/usr/bin/env bats
# ******************************************************************************
# *Title: Repository Audit Regressions*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Verifies input safety, typed records, and correlation accuracy.*
# ******************************************************************************

load test_helper

# *--- Helpers ---*

check_report() {
  [ "$status" -eq 0 ]
  printf '%s\n' "$output" | jq -e "$1"
}

# *--- CLI and Output ---*

@test "relative paths with equals and leading dash are read as files" {
  cd "$BATS_TEST_TMPDIR"
  printf 'access denied\n' > 'RS=.'
  cp 'RS=.' ./-auth
  run "$BL" --format generic -o json 'RS=.' < /dev/null
  check_report '.file == "RS=." and .metrics.total_lines == "1" and .findings[0].category == "auth-failures"'
  run "$BL" -o json -- -auth
  check_report '.file == "-auth" and .metrics.total_lines == "1"'
}

@test "zero-padded zero and overflowing settings are usage errors" {
  run "$BL" --bf-threshold 000 "$FIXTURES/auth/normal.log"
  [ "$status" -eq 1 ]
  run "$BL" --bf-window 2147483648 "$FIXTURES/auth/normal.log"
  [ "$status" -eq 1 ]
  run "$BL" --format "" "$FIXTURES/auth/normal.log"
  [ "$status" -eq 1 ]
}

@test "invalid UTF-8 cannot leak into JSON while valid Unicode survives" {
  local log="$BATS_TEST_TMPDIR/web.log"
  printf '192.0.2.1 - - [10/Jun/2025:10:00:00 +0000] "GET /caf\303\251/\377/.env HTTP/1.1" 404 0\n' > "$log"
  for mode in json ndjson; do
    run "$BL" -o "$mode" "$log"
    [ "$status" -eq 0 ]
    printf '%s\n' "$output" | iconv -f UTF-8 -t UTF-8 >/dev/null
    printf '%s\n' "$output" | jq -s -e 'last.metrics.top_paths == "/café/\ufffd/.env (1)"'
  done
}

@test "finding data cannot glob against local filenames" {
  cd "$BATS_TEST_TMPDIR"
  touch user=expanded
  printf 'Jun  1 10:00:00 h sshd[1]: Failed password for * from 192.0.2.5 port 1 ssh2\nJun  1 10:00:01 h sshd[1]: Accepted password for * from 192.0.2.5 port 1 ssh2\n' > auth.log
  run "$BL" --bf-threshold 1 -o json auth.log
  check_report 'any(.findings[]; .category == "possible-compromise" and .data.user == "*")'
}

# *--- SSH Attribution and Correlation ---*

@test "offsets, IPv6 aliases and record order are applied to SSH windows" {
  cat > "$BATS_TEST_TMPDIR/iso.log" <<'LOG'
2025-06-01T10:00:00.125Z h sshd-session[12]: Accepted password for earlier from 2001:db8::1 port 22 ssh2
2025-06-01T03:00:00.125-07:00 h sshd-session[12]: Failed password for alice from 2001:0DB8:0:0:0:0:0:1 port 22 ssh2
2025-06-01T12:00:00.625+0200 h sshd-session[13]: Failed password for alice from 2001:db8::1 port 23 ssh2
2025-06-01T10:00:00.625Z h sshd-session[13]: Accepted publickey for later from 2001:db8::1 port 23 ssh2
LOG
  run "$BL" --strict --bf-threshold 2 --bf-window 1 -o json "$BATS_TEST_TMPDIR/iso.log"
  check_report '.findings[0].data.user == "later" and .findings[1].data.ip == "2001:db8::1" and .findings[1].data.burst_seconds == "0.5"'
}

@test "a success earlier in the same second cannot become a compromise" {
  printf 'Jun  1 10:00:00 h sshd[1]: Accepted password for earlier from 192.0.2.7 port 22 ssh2\nJun  1 10:00:00 h sshd[2]: Failed password for alice from 192.0.2.7 port 22 ssh2\n' > "$BATS_TEST_TMPDIR/auth.log"
  run "$BL" --bf-threshold 1 -o json "$BATS_TEST_TMPDIR/auth.log"
  check_report '[.findings[].category] == ["brute-force"]'
}

@test "PAM fallback and SSH correlation are scoped to the destination host" {
  cat > "$BATS_TEST_TMPDIR/hosts.log" <<'LOG'
Jun  1 10:00:00 first sshd[1]: Failed password for alice from 192.0.2.44 port 22 ssh2
Jun  1 10:00:01 second sshd[2]: pam_unix(sshd:auth): authentication failure; uid=0 rhost=192.0.2.44 user=alice
Jun  1 10:00:02 first sshd[3]: Accepted password for alice from 192.0.2.44 port 22 ssh2
LOG
  run "$BL" --bf-threshold 2 -o json "$BATS_TEST_TMPDIR/hosts.log"
  check_report '.metrics.failed_auth == "2" and .metrics.failure_source == "mixed" and .findings == []'
}

@test "position-only SSH lines are disclosed and cannot escalate an accepted login" {
  cat > "$BATS_TEST_TMPDIR/relay.log" <<'LOG'
<38>1 2025-06-01T10:00:01Z h relay 12 - [meta@42 value="fake \] Failed password"][meta2@42 v="yes"] Failed password for alice from 192.0.2.7 port 22 ssh2
<38>1 2025-06-01T10:00:02Z h sshd 12 - - Accepted password for alice from 192.0.2.7 port 22 ssh2
<38>1 2025-06-01T10:00:03Z h logger 1 - - Accepted password for root from 192.0.2.7 port 22 ssh2
LOG
  run "$BL" --strict --bf-threshold 1 -o json "$BATS_TEST_TMPDIR/relay.log"
  check_report '.format == "auth_ssh" and .metrics.position_only_ssh_events == "2" and [.findings[].category] == ["brute-force"] and .findings[0].data.named_events == "0"'
  run "$BL" --ssh-named-only --bf-threshold 1 -o json "$BATS_TEST_TMPDIR/relay.log"
  check_report '.metrics.failed_auth == "0" and .findings == []'
}

@test "a position-only failure cannot extend a named SSH compromise window" {
  cat > "$BATS_TEST_TMPDIR/relay.log" <<'LOG'
Jun  1 10:00:00 h sshd[1]: Failed password for alice from 192.0.2.7 port 22 ssh2
Jun  1 10:00:30 h relay[1]: Failed password for alice from 192.0.2.7 port 22 ssh2
Jun  1 10:10:01 h sshd[1]: Accepted password for alice from 192.0.2.7 port 22 ssh2
LOG
  run "$BL" --bf-threshold 1 -o json "$BATS_TEST_TMPDIR/relay.log"
  check_report '[.findings[].category] == ["brute-force"] and .findings[0].data.count == "2"'
}

@test "an ambiguous accepted peer cannot turn a genuine SSH burst into a compromise" {
  cat > "$BATS_TEST_TMPDIR/peer.log" <<'LOG'
Jun  1 10:00:00 h sshd[1]: Failed password for alice from 192.0.2.7 port 22 ssh2
Jun  1 10:00:01 h sshd[1]: Accepted password for fake from 192.0.2.7 port 22 ssh2 from 192.0.2.8 port 22 ssh2
LOG
  run "$BL" --bf-threshold 1 -o json "$BATS_TEST_TMPDIR/peer.log"
  check_report '[.findings[].category] == ["brute-force"] and .metrics.ssh_events_without_peer == "1"'
}

@test "journal SSH correlation reads timestamps and rejects contradictory producer metadata" {
  cat > "$BATS_TEST_TMPDIR/journal.log" <<'LOG'
{"__REALTIME_TIMESTAMP":"1748772001000000","_HOSTNAME":"host","_COMM":"sshd-session","MESSAGE":"Failed password for alice from 192.0.2.7 port 22 ssh2"}
{"__REALTIME_TIMESTAMP":"1748772002000000","_HOSTNAME":"host","_COMM":"other","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for root from 192.0.2.7 port 22 ssh2"}
LOG
  run "$BL" --format auth_ssh --bf-threshold 1 -o json "$BATS_TEST_TMPDIR/journal.log"
  check_report '.metrics.failed_auth == "1" and .metrics.accepted_logins == "0" and [.findings[].category] == ["brute-force"]'
}

# *--- Structured and Network Records ---*

@test "Wazuh ignores nested decoys, arbitrary MITRE text and duplicate JSON keys" {
  cat > "$BATS_TEST_TMPDIR/alerts.json" <<'LOG'

  {"data": {"rule": {"level": 15}, "agent": {"name": "fake"}}, "agent": {"name": "caf\u00e9 \ud83d\ude00"}, "rule": {"level": 5, "description": "test", "mitre": {"id": ["T1110", 100, "T1000.002"]}}, "full_log": "T9999"}
{"rule":{"level":5,"level":15}}
{"data":{"rule":{"level":16}}}
LOG
  run "$BL" --strict -o json "$BATS_TEST_TMPDIR/alerts.json"
  check_report '.format == "wazuh_alerts" and .metrics.total_alerts == "1" and .metrics.unparsed_lines == "3" and .metrics.top_agents == "café 😀 (1)" and .metrics.mitre_techniques == "T1000.002,T1110" and .findings == []'
}

@test "journald reads escaped messages and counts only valid priorities" {
  cat > "$BATS_TEST_TMPDIR/journal.json" <<'LOG'

  {"__REALTIME_TIMESTAMP": "1748772001000000", "PRIORITY": "broken", "data": {"PRIORITY":"0"}, "MESSAGE": "\"quoted\" then segfault"}
  {"__REALTIME_TIMESTAMP": "1748772002000000", "PRIORITY": "2", "MESSAGE": ["ignored"]}
LOG
  run "$BL" --strict -o json "$BATS_TEST_TMPDIR/journal.json"
  check_report '.format == "journald" and .metrics.error_entries == "1" and [.findings[].category] == ["journal-critical","segfault"]'
}

@test "short-iso journal identifies tags without a process ID" {
  printf '2025-06-01T10:00:01Z failover kernel: Out of memory: killed process 42\n' > "$BATS_TEST_TMPDIR/journal.log"
  run "$BL" --strict -o json "$BATS_TEST_TMPDIR/journal.log"
  check_report '.format == "journald" and .metrics.error_entries == "0" and [.findings[].category] == ["oom-killer"]'
}

@test "AWS fractional public query timestamps are detected and malformed rows are excluded" {
  cat > "$BATS_TEST_TMPDIR/dns.log" <<'LOG'
1.0 2017-12-13T08:16:05.744Z Z123412341234 txt.example.com TXT NOERROR UDP IAD 192.0.2.1 -
1.0 2017-12-13T08:16:06.744Z Z123412341234 bad.example.com A NXDomain TCP IAD 2001:db8::1 -
1.0 2017-02-30T08:16:07.744Z Z123412341234 bad.example.com A NXDOMAIN UDP IAD 192.0.2.1 -
LOG
  run "$BL" --strict -o json "$BATS_TEST_TMPDIR/dns.log"
  check_report '.format == "dns_route53" and .metrics.total_queries == "2" and .metrics.nxdomain == "1" and .metrics.unparsed_lines == "1"'
}

@test "pfSense IPv6 uses fixed fields and rejects invalid port numbers" {
  cat > "$BATS_TEST_TMPDIR/fw.log" <<'LOG'
Jun 12 18:30:00 gw filterlog: 5,,,1000000103,igb0,match,block,in,6,0x0,0x0,64,tcp,6,60,2001:0DB8::1,2001:db8::2,55001,00443,0
Jun 12 18:30:01 gw filterlog: 6,,,1000000104,igb0,match,pass,in,6,0x0,0x0,64,tcp,6,60,2001:db8::1,2001:db8::2,55001,65536,0
Jun 12 18:30:02 gw kernel: IN=eth0 OUT= SRC=192.0.2.1 DST=192.0.2.2 PROTO=TCP DPT=22 LABEL=unblocked
LOG
  run "$BL" --strict -o json "$BATS_TEST_TMPDIR/fw.log"
  check_report '.metrics.total_events == "3" and .metrics.blocked_events == "1" and .metrics.top_blocked_sources == "2001:db8::1 (1)" and .metrics.top_target_ports == "22 (1), 443 (1)"'
}

@test "one IPv6 access record can detect a web log and malformed statuses do not count" {
  cat > "$BATS_TEST_TMPDIR/web.log" <<'LOG'
2001:0DB8::1 - - [10/Jun/2025:10:00:00 +0000] "GET / HTTP/1.1" 101 0
2001:db8::1 - - [10/Jun/2025:10:00:00 +0000] "GET /.env HTTP/1.1" 999 0
LOG
  run "$BL" --strict -o json "$BATS_TEST_TMPDIR/web.log"
  check_report '.format == "web_access" and .metrics.total_requests == "1" and .metrics.status_1xx == "1" and .metrics.unparsed_lines == "1" and .findings == []'
}

@test "syslog requires the expected producer for kernel and sudo findings" {
  printf 'Jun  1 10:00:00 host app[1]: test kernel panic and sudo incorrect password\n' > "$BATS_TEST_TMPDIR/sys.log"
  run "$BL" --strict -o json "$BATS_TEST_TMPDIR/sys.log"
  check_report '.format == "syslog" and .findings == []'
}

@test "IOC extraction normalizes IPv6 aliases and defangs uppercase URLs" {
  printf 'HTTPS://[2001:0DB8::1]:8443/path 2001:db8:0:0:0:0:0:1 192.0.2.6:22 ::ffff:c000:0206\n' > "$BATS_TEST_TMPDIR/ioc.log"
  run "$BL" --iocs --defang -o json "$BATS_TEST_TMPDIR/ioc.log"
  check_report '.iocs.ips == ["192[.]0[.]2[.]6","2001[:]db8[:][:]1","[:][:]ffff[:]192[.]0[.]2[.]6"] and .iocs.urls == ["hxxps://[2001:0DB8::1]:8443/path"]'
}

@test "offline enrichment caps attempts even when every IP misses" {
  local mock
  mock="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$mock"
  touch "$BATS_TEST_TMPDIR/GeoLite2-ASN.mmdb"
  cat > "$mock/mmdblookup" <<'MOCK'
#!/usr/bin/env bash
echo miss >> "$BASHEDLOGS_TEST_CALLS"
exit 1
MOCK
  chmod +x "$mock/mmdblookup"
  for ((i = 1; i <= 30; i++)); do
    printf '192.0.2.%s\n' "$i"
  done > "$BATS_TEST_TMPDIR/ip.log"
  run env PATH="$mock:$PATH" BASHEDLOGS_TEST_CALLS="$BATS_TEST_TMPDIR/calls" \
    "$BL" --iocs --mmdb-dir "$BATS_TEST_TMPDIR" -o ndjson "$BATS_TEST_TMPDIR/ip.log"
  [ "$status" -eq 0 ]
  [ "$(wc -l < "$BATS_TEST_TMPDIR/calls" | tr -d ' ')" -eq 50 ]
  printf '%s\n' "$output" | jq -s -e 'last.enrichment_status == "mmdb (0 of 30 IPs resolved, cap 25)"'
}
