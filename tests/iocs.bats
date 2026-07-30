#!/usr/bin/env bats
# iocs.bats - IOC extraction, defanging, and the enrichment tiers
# Enrichment is tested against a mock mmdblookup on PATH, so no GeoLite2
# database (and no network) is needed to prove the offline tier works.

load test_helper

@test "extracts the exact expected IOC set" {
  run bash -c "\"$BL\" --iocs -o json \"$FIXTURES/iocs/sample.log\" | jq -c '.iocs.ips, .iocs.domains, .iocs.urls, .iocs.hashes'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = '["192.0.2.44","198.51.100.23","203.0.113.66"]' ]
  [ "${lines[1]}" = '["c2.badhost.example.org","cdn.example.com","malware.example.net"]' ]
  [ "${lines[2]}" = '["http://malware.example.net/payload.bin","https://cdn.example.com/app.js"]' ]
  [ "${lines[3]}" = '{"md5":["d41d8cd98f00b204e9800998ecf8427e"],"sha1":["da39a3ee5e6b4b0d3255bfef95601890afd80709"],"sha256":["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]}' ]
}

@test "--defang rewrites dots and scheme" {
  run bash -c "\"$BL\" --iocs --defang -o json \"$FIXTURES/iocs/sample.log\" | jq -r '.iocs.ips[0], .iocs.urls[0]'"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "192[.]0[.]2[.]44" ]
  [ "${lines[1]}" = "hxxp://malware[.]example[.]net/payload[.]bin" ]
}

@test "hashes are never defanged" {
  run bash -c "\"$BL\" --iocs --defang -o json \"$FIXTURES/iocs/sample.log\" | jq -r '.iocs.hashes.md5[0]'"
  [ "$output" = "d41d8cd98f00b204e9800998ecf8427e" ]
}

@test "no --iocs means no iocs key in json" {
  run bash -c "\"$BL\" -o json \"$FIXTURES/iocs/sample.log\" | jq -r 'has(\"iocs\")'"
  [ "$output" = "false" ]
}

@test "ndjson emits one line per IOC" {
  run bash -c "\"$BL\" --iocs -o ndjson \"$FIXTURES/iocs/sample.log\" | jq -r 'select(.type==\"ioc\") | .kind' | sort | uniq -c | tr -s ' '"
  [ "$status" -eq 0 ]
  [[ "$output" == *"3 domain"* ]]
  [[ "$output" == *"3 ip"* ]]
  [[ "$output" == *"2 url"* ]]
}

@test "enrichment degrades gracefully with nothing available" {
  run bash -c "\"$BL\" --iocs -o json \"$FIXTURES/iocs/sample.log\" | jq -r '.iocs.enrichment.status, (.iocs.enrichment.results | length)'"
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" == skipped* ]]
  [ "${lines[1]}" = "0" ]
}

@test "offline mmdb tier enriches when mmdblookup and a db are present" {
  mock="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$mock" "$BATS_TEST_TMPDIR/mmdb"
  : > "$BATS_TEST_TMPDIR/mmdb/GeoLite2-ASN.mmdb"
  : > "$BATS_TEST_TMPDIR/mmdb/GeoLite2-Country.mmdb"
  cat > "$mock/mmdblookup" <<'MOCK'
#!/usr/bin/env bash
# Mimics mmdblookup's value output shape for the three fields we ask for.
for arg in "$@"; do last=$arg; done
case "$last" in
  autonomous_system_number) echo '  64500 <uint32>' ;;
  autonomous_system_organization) echo '  "Example Networks" <utf8_string>' ;;
  iso_code) echo '  "US" <utf8_string>' ;;
  *) exit 1 ;;
esac
MOCK
  chmod +x "$mock/mmdblookup"

  run bash -c "PATH=\"$mock:\$PATH\" \"$BL\" --iocs --mmdb-dir \"$BATS_TEST_TMPDIR/mmdb\" -o json \"$FIXTURES/iocs/sample.log\" | jq -r '.iocs.enrichment.status, .iocs.enrichment.results[\"203.0.113.66\"]'"
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" == mmdb* ]]
  [ "${lines[1]}" = "AS64500 Example Networks (US)" ]
}

@test "BASHEDLOGS_MMDB_DIR env is equivalent to --mmdb-dir" {
  mock="$BATS_TEST_TMPDIR/bin2"
  mkdir -p "$mock" "$BATS_TEST_TMPDIR/mmdb2"
  : > "$BATS_TEST_TMPDIR/mmdb2/GeoLite2-ASN.mmdb"
  cat > "$mock/mmdblookup" <<'MOCK'
#!/usr/bin/env bash
for arg in "$@"; do last=$arg; done
case "$last" in
  autonomous_system_number) echo '  64500 <uint32>' ;;
  autonomous_system_organization) echo '  "Example Networks" <utf8_string>' ;;
  *) exit 1 ;;
esac
MOCK
  chmod +x "$mock/mmdblookup"

  run bash -c "PATH=\"$mock:\$PATH\" BASHEDLOGS_MMDB_DIR=\"$BATS_TEST_TMPDIR/mmdb2\" \"$BL\" --iocs -o json \"$FIXTURES/iocs/sample.log\" | jq -r '.iocs.enrichment.status'"
  [ "$status" -eq 0 ]
  [[ "$output" == mmdb* ]]
}

@test "default run makes no network call even with --iocs" {
  # A stub resolver/whois that would fail loudly if enrichment reached out.
  mock="$BATS_TEST_TMPDIR/bin3"
  mkdir -p "$mock"
  for tool in whois dig host; do
    printf '#!/usr/bin/env bash\necho NETWORK_CALL_MADE >&2\nexit 99\n' > "$mock/$tool"
    chmod +x "$mock/$tool"
  done
  run bash -c "PATH=\"$mock:\$PATH\" \"$BL\" --iocs -o json \"$FIXTURES/iocs/sample.log\" 2>&1"
  [ "$status" -eq 0 ]
  [[ "$output" != *NETWORK_CALL_MADE* ]]
}
