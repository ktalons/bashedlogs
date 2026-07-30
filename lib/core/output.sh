# shellcheck shell=bash
# output.sh - color handling, JSON escaping, pretty/json/ndjson emitters

C_RED="" C_GREEN="" C_YELLOW="" C_CYAN="" C_MAGENTA="" C_BOLD="" C_DIM="" C_RESET=""

# init_colors: enable ANSI colors only for pretty output on a TTY, unless
# disabled by --no-color or the NO_COLOR convention (https://no-color.org).
init_colors() {
  if [ "$OUTPUT_MODE" != "pretty" ]; then return 0; fi
  if [ "$COLOR_MODE" = "off" ] || [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    return 0
  fi
  C_RED=$'\033[0;31m'
  C_GREEN=$'\033[0;32m'
  C_YELLOW=$'\033[1;33m'
  C_CYAN=$'\033[0;36m'
  C_MAGENTA=$'\033[0;35m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RESET=$'\033[0m'
}

sev_color() {
  case "$1" in
    critical) printf '%s' "$C_MAGENTA" ;;
    high) printf '%s' "$C_RED" ;;
    medium) printf '%s' "$C_YELLOW" ;;
    low) printf '%s' "$C_CYAN" ;;
    *) printf '%s' "$C_DIM" ;;
  esac
}

# json_escape <string>: prints a JSON-safe version (no surrounding quotes).
json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  # Rare path: strip any remaining control characters.
  if [[ $s == *[$'\001'-$'\037']* ]]; then
    s=$(printf '%s' "$s" | tr -d '\000-\037')
  fi
  printf '%s' "$s"
}

# kv_to_json <tab-separated k=v pairs>: prints a JSON object.
kv_to_json() {
  local kv=$1 out="" pair k v
  if [ -z "$kv" ]; then
    printf '{}'
    return 0
  fi
  local IFS=$'\t'
  for pair in $kv; do
    k=${pair%%=*}
    v=${pair#*=}
    if [ -n "$out" ]; then out="$out,"; fi
    out="$out\"$(json_escape "$k")\":\"$(json_escape "$v")\""
  done
  printf '{%s}' "$out"
}

finding_to_json() {
  local i=$1
  printf '{"severity":"%s","category":"%s","message":"%s","data":%s}' \
    "${R_SEV[$i]}" \
    "$(json_escape "${R_CAT[$i]}")" \
    "$(json_escape "${R_MSG[$i]}")" \
    "$(kv_to_json "${R_KV[$i]}")"
}

metrics_to_json() {
  local out="" i
  if [ "${#M_KEY[@]}" -gt 0 ]; then
    for i in "${!M_KEY[@]}"; do
      if [ -n "$out" ]; then out="$out,"; fi
      out="$out\"$(json_escape "${M_KEY[$i]}")\":\"$(json_escape "${M_VAL[$i]}")\""
    done
  fi
  printf '{%s}' "$out"
}

# json_str_array [values...]: JSON array of defanged, escaped strings.
json_str_array() {
  local out="" v
  for v in "$@"; do
    if [ -n "$out" ]; then out="$out,"; fi
    out="$out\"$(json_escape "$(maybe_defang "$v")")\""
  done
  printf '[%s]' "$out"
}

iocs_to_json() {
  printf '{"ips":%s,"domains":%s,"urls":%s,"hashes":{"md5":%s,"sha1":%s,"sha256":%s},"enrichment":{"status":"%s","results":%s}}' \
    "$(json_str_array ${IOC_IPS[@]+"${IOC_IPS[@]}"})" \
    "$(json_str_array ${IOC_DOMAINS[@]+"${IOC_DOMAINS[@]}"})" \
    "$(json_str_array ${IOC_URLS[@]+"${IOC_URLS[@]}"})" \
    "$(json_str_array ${IOC_MD5[@]+"${IOC_MD5[@]}"})" \
    "$(json_str_array ${IOC_SHA1[@]+"${IOC_SHA1[@]}"})" \
    "$(json_str_array ${IOC_SHA256[@]+"${IOC_SHA256[@]}"})" \
    "$(json_escape "$ENRICH_STATUS")" \
    "$(enrichment_results_json)"
}

enrichment_results_json() {
  local out="" i
  if [ "${#E_IP[@]}" -gt 0 ]; then
    for i in "${!E_IP[@]}"; do
      if [ -n "$out" ]; then out="$out,"; fi
      out="$out\"$(json_escape "$(maybe_defang "${E_IP[$i]}")")\":\"$(json_escape "${E_TXT[$i]}")\""
    done
  fi
  printf '{%s}' "$out"
}

emit_json() {
  local file=$1 fmt=$2 score level findings="" iocs="" i
  score=$(threat_score)
  level=$(threat_level "$score")
  if [ "${#R_SEV[@]}" -gt 0 ]; then
    for i in "${!R_SEV[@]}"; do
      if [ -n "$findings" ]; then findings="$findings,"; fi
      findings="$findings$(finding_to_json "$i")"
    done
  fi
  if [ "$DO_IOCS" -eq 1 ]; then
    iocs=",\"iocs\":$(iocs_to_json)"
  fi
  printf '{"tool":"bashedlogs","version":"%s","file":"%s","format":"%s","metrics":%s,"findings":[%s],"threat":{"score":%s,"level":"%s"}%s}\n' \
    "$BASHEDLOGS_VERSION" \
    "$(json_escape "$file")" \
    "$fmt" \
    "$(metrics_to_json)" \
    "$findings" \
    "$score" "$level" \
    "$iocs"
}

ndjson_ioc_lines() {
  local v
  for v in ${IOC_IPS[@]+"${IOC_IPS[@]}"}; do
    printf '{"type":"ioc","kind":"ip","value":"%s"}\n' "$(json_escape "$(maybe_defang "$v")")"
  done
  for v in ${IOC_DOMAINS[@]+"${IOC_DOMAINS[@]}"}; do
    printf '{"type":"ioc","kind":"domain","value":"%s"}\n' "$(json_escape "$(maybe_defang "$v")")"
  done
  for v in ${IOC_URLS[@]+"${IOC_URLS[@]}"}; do
    printf '{"type":"ioc","kind":"url","value":"%s"}\n' "$(json_escape "$(maybe_defang "$v")")"
  done
  for v in ${IOC_MD5[@]+"${IOC_MD5[@]}"}; do
    printf '{"type":"ioc","kind":"md5","value":"%s"}\n' "$(json_escape "$v")"
  done
  for v in ${IOC_SHA1[@]+"${IOC_SHA1[@]}"}; do
    printf '{"type":"ioc","kind":"sha1","value":"%s"}\n' "$(json_escape "$v")"
  done
  for v in ${IOC_SHA256[@]+"${IOC_SHA256[@]}"}; do
    printf '{"type":"ioc","kind":"sha256","value":"%s"}\n' "$(json_escape "$v")"
  done
}

emit_ndjson() {
  local file=$1 fmt=$2 score level i
  score=$(threat_score)
  level=$(threat_level "$score")
  if [ "${#R_SEV[@]}" -gt 0 ]; then
    for i in "${!R_SEV[@]}"; do
      printf '{"type":"finding","file":"%s","format":"%s",' \
        "$(json_escape "$file")" "$fmt"
      printf '"severity":"%s","category":"%s","message":"%s","data":%s}\n' \
        "${R_SEV[$i]}" \
        "$(json_escape "${R_CAT[$i]}")" \
        "$(json_escape "${R_MSG[$i]}")" \
        "$(kv_to_json "${R_KV[$i]}")"
    done
  fi
  if [ "$DO_IOCS" -eq 1 ]; then
    ndjson_ioc_lines
  fi
  printf '{"type":"summary","tool":"bashedlogs","version":"%s","file":"%s","format":"%s","metrics":%s,"findings":%s,"threat":{"score":%s,"level":"%s"}}\n' \
    "$BASHEDLOGS_VERSION" \
    "$(json_escape "$file")" \
    "$fmt" \
    "$(metrics_to_json)" \
    "${#R_SEV[@]}" \
    "$score" "$level"
}

emit_pretty() {
  local file=$1 fmt=$2 score level i
  score=$(threat_score)
  level=$(threat_level "$score")

  printf '%s\n' "${C_CYAN}${C_BOLD}bashedlogs${C_RESET}${C_DIM} v${BASHEDLOGS_VERSION}${C_RESET}"
  printf '  %sfile%s    %s\n' "$C_DIM" "$C_RESET" "$file"
  printf '  %sformat%s  %s\n' "$C_DIM" "$C_RESET" "$fmt"
  echo

  if [ "${#M_KEY[@]}" -gt 0 ]; then
    printf '%s\n' "${C_BOLD}Metrics${C_RESET}"
    for i in "${!M_KEY[@]}"; do
      printf '  %-28s %s\n' "${M_KEY[$i]}" "${M_VAL[$i]}"
    done
    echo
  fi

  printf '%s\n' "${C_BOLD}Findings (${#R_SEV[@]})${C_RESET}"
  if [ "${#R_SEV[@]}" -eq 0 ]; then
    printf '  %snothing flagged%s\n' "$C_GREEN" "$C_RESET"
  else
    for i in "${!R_SEV[@]}"; do
      printf '  %s%-8s%s %-16s %s\n' \
        "$(sev_color "${R_SEV[$i]}")" "${R_SEV[$i]}" "$C_RESET" \
        "${R_CAT[$i]}" "${R_MSG[$i]}"
      if [ -n "${R_KV[$i]}" ]; then
        printf '           %s%s%s\n' "$C_DIM" "${R_KV[$i]//$'\t'/  }" "$C_RESET"
      fi
    done
  fi
  echo

  if [ "$DO_IOCS" -eq 1 ]; then
    printf '%s\n' "${C_BOLD}IOCs ($(ioc_total))${C_RESET}"
    pretty_ioc_kind "ips" ${IOC_IPS[@]+"${IOC_IPS[@]}"}
    pretty_ioc_kind "domains" ${IOC_DOMAINS[@]+"${IOC_DOMAINS[@]}"}
    pretty_ioc_kind "urls" ${IOC_URLS[@]+"${IOC_URLS[@]}"}
    pretty_ioc_kind "md5" ${IOC_MD5[@]+"${IOC_MD5[@]}"}
    pretty_ioc_kind "sha1" ${IOC_SHA1[@]+"${IOC_SHA1[@]}"}
    pretty_ioc_kind "sha256" ${IOC_SHA256[@]+"${IOC_SHA256[@]}"}
    printf '  %-10s %s%s%s\n' "enrich" "$C_DIM" "$ENRICH_STATUS" "$C_RESET"
    if [ "${#E_IP[@]}" -gt 0 ]; then
      for i in "${!E_IP[@]}"; do
        printf '    %-18s %s\n' "$(maybe_defang "${E_IP[$i]}")" "${E_TXT[$i]}"
      done
    fi
    echo
  fi

  local lvl_color
  lvl_color=$(sev_color "$level")
  printf '%s\n' "${C_BOLD}Threat score${C_RESET}  ${lvl_color}${score}/100 (${level})${C_RESET}"
}

# pretty_ioc_kind <label> [values...]: one wrapped line per kind, capped.
pretty_ioc_kind() {
  local label=$1
  shift
  if [ "$#" -eq 0 ]; then return 0; fi
  local shown=0 line="" v
  for v in "$@"; do
    shown=$((shown + 1))
    if [ "$shown" -gt 25 ]; then
      line="$line +$(($# - 25)) more"
      break
    fi
    if [ -n "$line" ]; then line="$line "; fi
    line="$line$(maybe_defang "$v")"
  done
  printf '  %-10s %s\n' "$label" "$line"
}

emit_output() {
  local file=$1 fmt=$2
  case "$OUTPUT_MODE" in
    json) emit_json "$file" "$fmt" ;;
    ndjson) emit_ndjson "$file" "$fmt" ;;
    *) emit_pretty "$file" "$fmt" ;;
  esac
}
