# shellcheck shell=bash
# ******************************************************************************
# *Title: Output Formatting*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Handles color, JSON escaping, and the three output emitters.*
# ******************************************************************************

# *--- Color State ---*

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

# *--- JSON Helpers ---*

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

# *--- JSON / NDJSON Emitters ---*

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

# *--- Pretty Sanitizing ---*

# SECURITY: pretty output goes to a terminal, and much of it is text copied
# from the log (paths, usernames, URLs), which is attacker-controlled. A raw
# ESC or BEL there would let a log line run CSI/OSC sequences that erase or
# rewrite findings already on screen, so each such value is printed with its
# control characters shown as visible \xHH text. JSON output is not affected.

# The locale the report is shown in. Read at load time: pretty_safe shadows
# LC_ALL, so pretty_ctrl_init cannot see the caller's value itself.
PRETTY_LOCALE=${LC_ALL:-${LC_CTYPE:-${LANG:-}}}

# Set on first use. PRETTY_CTRL_SET holds C0 (\001-\037) and DEL, and then,
# by PRETTY_C1: 1 adds \302, the lead byte of the UTF-8 form of every C1
# control (U+0080-U+009F, bytes \302\200-\302\237); 2 adds the raw C1 bytes
# \200-\237 other than SS2 and SS3 (\216, \217), for charsets that keep that
# range for controls. EUC puts SS2 and SS3 inside characters, and all they
# do is pick the set the next character comes from, so they stay.
# NOTE: under 0 and 1, raw \200-\237 bytes are left alone. In UTF-8 they are
# continuation bytes of ordinary characters, and a lone one is invalid UTF-8
# that a UTF-8 terminal draws as a replacement character instead of acting
# on. In GBK, Shift-JIS and Big5 they are bytes of double-byte characters.
PRETTY_CTRL_SET=""
PRETTY_C1=0
PRETTY_SAFE=""

# Rewrites od's hex dump of one value as a printf %b argument: \0ooo for a
# byte kept as it is, \\xHH for a control byte shown as text, a \302 pair
# shown as \\xc2\\xHH when c1 is 1, and a raw C1 byte other than SS2 and SS3
# shown as \\xHH when c1 is 2. awk only ever sees ASCII hex here, so every
# awk treats the input the same whatever bytes the value holds.
# shellcheck disable=SC2016  # an awk program; its $i is awk's, not the shell's
PRETTY_AWK='
BEGIN { H = "0123456789abcdef" }
{
  for (i = 1; i <= NF; i++) {
    t = tolower($i)
    if (pend) {
      pend = 0
      if (t ~ /^[89]/) { printf "\\\\xc2\\\\x%s", t; continue }
      printf "\\0302"
    }
    if (c1 == 1 && t == "c2") { pend = 1; continue }
    v = (index(H, substr(t, 1, 1)) - 1) * 16 + index(H, substr(t, 2, 1)) - 1
    if (v < 32 || v == 127 || (c1 == 2 && v >= 128 && v < 160 && v != 142 && v != 143))
      printf "\\\\x%s", t
    else printf "\\0%03o", v
  }
}
END { if (pend) printf "\\0302" }
'

pretty_ctrl_init() {
  local i oct ch cs
  # The policy follows the charset the locale really uses, as locale charmap
  # reports it. Where that prints nothing (macOS bare names such as en_US,
  # which are UTF-8) or locale is missing (busybox), the charset part of the
  # name stands in, and a name without one gets the default.
  # The default covers UTF-8, C, POSIX, and any charset not listed below: C0,
  # DEL and the \302 pairs. In C the pair is never printable text either: it
  # is a UTF-8 C1 control, or a Latin-1 A with circumflex followed by one.
  # ISO-8859 and EUC charsets keep \200-\237 for C1 controls, so there those
  # bytes are escaped one by one, SS2 and SS3 aside.
  # GBK, Shift-JIS, Big5, KOI8 and the numbered code pages put \200-\237
  # bytes inside ordinary characters, so they get C0 and DEL only; none of
  # them uses a C0 or DEL byte inside a character.
  # NOTE: an unlisted charset therefore costs, at worst, a legitimate byte
  # pair shown as \xHH text, never a control left live.
  cs=$(LC_ALL=$PRETTY_LOCALE locale charmap 2>/dev/null) || cs=""
  if [ -z "$cs" ]; then
    case $PRETTY_LOCALE in
      *.*)
        cs=${PRETTY_LOCALE#*.}
        cs=${cs%%@*}
        ;;
    esac
  fi
  case $cs in
    [Ii][Ss][Oo]8859* | [Ii][Ss][Oo][-_]8859* | [Ee][Uu][Cc]*) PRETTY_C1=2 ;;
    [Gg][Bb]* | [Ss][Jj][Ii][Ss]* | [Ss][Hh][Ii][Ff][Tt]* | [Bb][Ii][Gg]5* | \
      [Kk][Oo][Ii]8* | [Cc][Pp][0-9]* | [Ww][Ii][Nn][Dd][Oo][Ww][Ss]-*)
      PRETTY_C1=0
      ;;
    *) PRETTY_C1=1 ;;
  esac
  for ((i = 1; i < 160; i++)); do
    if [ "$i" -ge 32 ] && [ "$i" -lt 127 ]; then continue; fi
    if [ "$i" -ge 128 ] && [ "$PRETTY_C1" -ne 2 ]; then break; fi
    if [ "$i" -eq 142 ] || [ "$i" -eq 143 ]; then continue; fi
    printf -v oct '%03o' "$i"
    printf -v ch '%b' "\\0$oct"
    PRETTY_CTRL_SET=$PRETTY_CTRL_SET$ch
  done
  if [ "$PRETTY_C1" -eq 1 ]; then PRETTY_CTRL_SET=$PRETTY_CTRL_SET$'\302'; fi
}

# pretty_safe <value>: sets PRETTY_SAFE to <value> with every control
# character replaced by \xHH. Returns through a variable, not stdout, so a
# clean value costs no subshell.
# SECURITY: LC_ALL=C makes the pattern below, od and awk all work on single
# bytes. In a multibyte locale bash matches by character, and how it reads an
# invalid sequence next to a control byte varies by bash and libc version;
# the C locale takes that question away.
# SECURITY: a value that holds a control byte is rewritten in one od | awk
# pass, linear in its length. A ${v//x/y} per control byte is not: bash 4.0
# tries every match from the end of the string, so ESC-dense log text would
# stall the report. Most values come from capped lists. The uncapped case is
# one possible-compromise finding per source IP, which quotes the username:
# one pass per finding, so the cost still grows linearly with the log.
# NOTE: callers add 2>/dev/null. When LC_ALL names a locale that is not
# installed, bash repeats its startup warning about it every time this local
# LC_ALL is unwound.
pretty_safe() {
  local LC_ALL=C fmt
  if [ -z "$PRETTY_CTRL_SET" ]; then pretty_ctrl_init; fi
  PRETTY_SAFE=$1
  # Fast path: nearly every value has no control character.
  case $PRETTY_SAFE in
    *["$PRETTY_CTRL_SET"]*) ;;
    *) return 0 ;;
  esac
  fmt=$(printf '%s' "$1" | LC_ALL=C od -An -v -tx1 |
    LC_ALL=C awk -v c1="$PRETTY_C1" "$PRETTY_AWK") || fmt=""
  if [ -n "$fmt" ]; then
    printf -v PRETTY_SAFE '%b' "$fmt"
  else
    # Fail closed: a value that could not be rewritten is never shown raw.
    PRETTY_SAFE="[unprintable]"
  fi
}

# *--- Pretty Emitter ---*

# SECURITY: every value that can carry log, file-name, or lookup text goes
# through pretty_safe before it is printed or wrapped in color.
emit_pretty() {
  local file=$1 fmt=$2 score level i cell
  score=$(threat_score)
  level=$(threat_level "$score")

  printf '%s\n' "${C_CYAN}${C_BOLD}bashedlogs${C_RESET}${C_DIM} v${BASHEDLOGS_VERSION}${C_RESET}"
  pretty_safe "$file" 2>/dev/null
  printf '  %sfile%s    %s\n' "$C_DIM" "$C_RESET" "$PRETTY_SAFE"
  printf '  %sformat%s  %s\n' "$C_DIM" "$C_RESET" "$fmt"
  echo

  if [ "${#M_KEY[@]}" -gt 0 ]; then
    printf '%s\n' "${C_BOLD}Metrics${C_RESET}"
    for i in "${!M_KEY[@]}"; do
      pretty_safe "${M_KEY[$i]}" 2>/dev/null
      cell=$PRETTY_SAFE
      pretty_safe "${M_VAL[$i]}" 2>/dev/null
      printf '  %-28s %s\n' "$cell" "$PRETTY_SAFE"
    done
    echo
  fi

  printf '%s\n' "${C_BOLD}Findings (${#R_SEV[@]})${C_RESET}"
  if [ "${#R_SEV[@]}" -eq 0 ]; then
    printf '  %snothing flagged%s\n' "$C_GREEN" "$C_RESET"
  else
    for i in "${!R_SEV[@]}"; do
      pretty_safe "${R_CAT[$i]}" 2>/dev/null
      cell=$PRETTY_SAFE
      pretty_safe "${R_MSG[$i]}" 2>/dev/null
      printf '  %s%-8s%s %-16s %s\n' \
        "$(sev_color "${R_SEV[$i]}")" "${R_SEV[$i]}" "$C_RESET" \
        "$cell" "$PRETTY_SAFE"
      if [ -n "${R_KV[$i]}" ]; then
        pretty_safe "${R_KV[$i]//$'\t'/  }" 2>/dev/null
        printf '           %s%s%s\n' "$C_DIM" "$PRETTY_SAFE" "$C_RESET"
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
        pretty_safe "$(maybe_defang "${E_IP[$i]}")" 2>/dev/null
        cell=$PRETTY_SAFE
        pretty_safe "${E_TXT[$i]}" 2>/dev/null
        printf '    %-18s %s\n' "$cell" "$PRETTY_SAFE"
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
    pretty_safe "$(maybe_defang "$v")" 2>/dev/null
    line="$line$PRETTY_SAFE"
  done
  printf '  %-10s %s\n' "$label" "$line"
}

# *--- Dispatch ---*

emit_output() {
  local file=$1 fmt=$2
  case "$OUTPUT_MODE" in
    json) emit_json "$file" "$fmt" ;;
    ndjson) emit_ndjson "$file" "$fmt" ;;
    *) emit_pretty "$file" "$fmt" ;;
  esac
}
