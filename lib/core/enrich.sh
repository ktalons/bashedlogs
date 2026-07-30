# shellcheck shell=bash
# shellcheck disable=SC2034  # ENRICH_STATUS/E_* are read by lib/core/output.sh
# enrich.sh - tiered GeoIP/ASN/PTR enrichment for extracted IOC IPs
#
# Tier 1 (offline): mmdblookup + user-supplied GeoLite2 databases (--mmdb-dir
#   or BASHEDLOGS_MMDB_DIR). No network.
# Tier 2 (explicit): --enrich-online allows Team Cymru ASN lookups via whois
#   and PTR via dig/host. Never used without the flag.
# Tier 3: everything still works; enrichment reports itself as skipped.
#
# Default behavior makes zero network calls - triage tooling should not phone
# home unless told to.

ENRICH_STATUS="skipped (no MMDB dir; online lookups not enabled)"
E_IP=()
E_TXT=()

enrich_available_mmdb() {
  command -v mmdblookup >/dev/null 2>&1 || return 1
  [ -n "$MMDB_DIR" ] || return 1
  [ -f "$MMDB_DIR/GeoLite2-ASN.mmdb" ] || [ -f "$MMDB_DIR/GeoLite2-City.mmdb" ] \
    || [ -f "$MMDB_DIR/GeoLite2-Country.mmdb" ]
}

# mmdblookup output values look like:  "Example Org" <utf8_string>  /  64500 <uint32>
mmdb_value() {
  sed -n 's/^ *"\{0,1\}\([^"<]*[^"< ]\)"\{0,1\} *<[a-z0-9_]*>.*$/\1/p' | head -1
}

enrich_tier_mmdb() {
  local ip asn org cc txt
  local asn_db="$MMDB_DIR/GeoLite2-ASN.mmdb"
  local cdb=""
  if [ -f "$MMDB_DIR/GeoLite2-City.mmdb" ]; then
    cdb="$MMDB_DIR/GeoLite2-City.mmdb"
  elif [ -f "$MMDB_DIR/GeoLite2-Country.mmdb" ]; then
    cdb="$MMDB_DIR/GeoLite2-Country.mmdb"
  fi
  for ip in ${IOC_IPS[@]+"${IOC_IPS[@]}"}; do
    if [ "${#E_IP[@]}" -ge 25 ]; then break; fi
    asn=""; org=""; cc=""
    if [ -f "$asn_db" ]; then
      asn=$(mmdblookup --file "$asn_db" --ip "$ip" autonomous_system_number 2>/dev/null | mmdb_value || true)
      org=$(mmdblookup --file "$asn_db" --ip "$ip" autonomous_system_organization 2>/dev/null | mmdb_value || true)
    fi
    if [ -n "$cdb" ]; then
      cc=$(mmdblookup --file "$cdb" --ip "$ip" country iso_code 2>/dev/null | mmdb_value || true)
    fi
    txt=""
    if [ -n "$asn" ]; then txt="AS$asn"; fi
    if [ -n "$org" ]; then txt="${txt:+$txt }$org"; fi
    if [ -n "$cc" ]; then txt="${txt:+$txt }($cc)"; fi
    if [ -n "$txt" ]; then
      E_IP+=("$ip")
      E_TXT+=("$txt")
    fi
  done
  ENRICH_STATUS="mmdb (${#E_IP[@]} of ${#IOC_IPS[@]} IPs resolved)"
}

enrich_tier_online() {
  local ip line asn cc name ptr txt count=0
  for ip in ${IOC_IPS[@]+"${IOC_IPS[@]}"}; do
    if [ "$count" -ge 10 ]; then break; fi
    count=$((count + 1))
    txt=""
    if command -v whois >/dev/null 2>&1; then
      line=$(whois -h whois.cymru.com " -v -f $ip" 2>/dev/null | tail -1 || true)
      # "64500 | 203.0.113.66 | 203.0.113.0/24 | US | ripe | ... | EXAMPLE-NET"
      if printf '%s' "$line" | grep -q '|'; then
        asn=$(printf '%s' "$line" | awk -F'|' '{gsub(/ /,"",$1); print $1}')
        cc=$(printf '%s' "$line" | awk -F'|' '{gsub(/ /,"",$4); print $4}')
        name=$(printf '%s' "$line" | awk -F'|' '{sub(/^ */,"",$NF); sub(/ *$/,"",$NF); print $NF}')
        if [ -n "$asn" ] && [ "$asn" != "NA" ]; then
          txt="AS$asn $name ($cc)"
        fi
      fi
    fi
    ptr=""
    if command -v dig >/dev/null 2>&1; then
      ptr=$(dig +short -x "$ip" 2>/dev/null | head -1 || true)
    elif command -v host >/dev/null 2>&1; then
      ptr=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ { print $NF; exit }' || true)
    fi
    if [ -n "$ptr" ]; then
      txt="${txt:+$txt }ptr=$ptr"
    fi
    if [ -n "$txt" ]; then
      E_IP+=("$ip")
      E_TXT+=("$txt")
    fi
  done
  ENRICH_STATUS="online (${#E_IP[@]} of ${#IOC_IPS[@]} IPs resolved, cap 10)"
}

enrich_iocs() {
  if [ "${#IOC_IPS[@]}" -eq 0 ]; then
    ENRICH_STATUS="skipped (no IPs extracted)"
    return 0
  fi
  if enrich_available_mmdb; then
    enrich_tier_mmdb
  elif [ "$ENRICH_ONLINE" -eq 1 ]; then
    enrich_tier_online
  fi
  return 0
}
