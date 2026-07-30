#!/usr/bin/env bats
# soc_formats.bats - wazuh_alerts, dns_route53, firewall

load test_helper

@test "wazuh: detected from alerts.json shape" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/wazuh/alerts.json\" | jq -r .format"
  [ "$output" = "wazuh_alerts" ]
}

@test "wazuh: level histogram is accurate" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/wazuh/alerts.json\" | jq -r '.metrics.total_alerts, .metrics.level_12_plus, .metrics.level_8_to_11, .metrics.max_level'"
  [ "${lines[0]}" = "15" ]
  [ "${lines[1]}" = "1" ]
  [ "${lines[2]}" = "2" ]
  [ "${lines[3]}" = "12" ]
}

@test "wazuh: critical alert and source-IP cluster are flagged" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/wazuh/alerts.json\" | jq -r '[.findings[].category] | sort | join(\",\")'"
  [ "$output" = "alert-cluster,wazuh-critical,wazuh-high" ]
}

@test "wazuh: MITRE techniques are surfaced" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/wazuh/alerts.json\" | jq -r .metrics.mitre_techniques"
  [[ "$output" == *T1110* ]]
  [[ "$output" == *T1565.001* ]]
}

@test "wazuh: agent names are counted, not paths" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/wazuh/alerts.json\" | jq -r .metrics.top_agents"
  [[ "$output" == "bastion (11)"* ]]
}

@test "dns: detected and long-name tunneling flagged" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/dns/route53.log\" | jq -r '.format, [.findings[] | select(.category==\"dns-tunneling-length\")][0].data.count'"
  [ "${lines[0]}" = "dns_route53" ]
  [ "${lines[1]}" = "1" ]
}

@test "dns: query metrics are accurate" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/dns/route53.log\" | jq -r '.metrics.total_queries, .metrics.nxdomain, .metrics.unique_resolvers'"
  [ "${lines[0]}" = "10" ]
  [ "${lines[1]}" = "2" ]
  [ "${lines[2]}" = "2" ]
}

@test "firewall: detected across iptables and pfSense in one file" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/firewall/mixed.log\" | jq -r '.format, .metrics.total_events, .metrics.blocked_events'"
  [ "${lines[0]}" = "firewall" ]
  [ "${lines[1]}" = "15" ]
  [ "${lines[2]}" = "14" ]
}

@test "firewall: port scan across 12 ports is flagged" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/firewall/mixed.log\" | jq -r '[.findings[] | select(.category==\"port-scan\")][0] | .data.ip, .data.distinct_ports'"
  [ "${lines[0]}" = "203.0.113.77" ]
  [ "${lines[1]}" = "12" ]
}

@test "firewall: pfSense passed traffic is not counted as blocked" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/firewall/mixed.log\" | jq -r .metrics.top_blocked_sources"
  [[ "$output" != *"198.51.100.23"* ]]
}

@test "--list-formats shows all eight analyzers" {
  run bash -c "\"$BL\" --list-formats | grep -cE '^  [a-z]'"
  [ "$output" = "8" ]
}
