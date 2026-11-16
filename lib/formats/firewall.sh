# shellcheck shell=bash
# ******************************************************************************
# *Title: Firewall Log Analyzer*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Analyzes iptables and pfSense logs for blocks and port scans.*
# ******************************************************************************

# NOTE: iptables (kernel SRC=/DST= lines) and pfSense filterlog shapes can
# coexist in one file; each line is classified on its own.

# *--- Registration ---*

register_format firewall "iptables + pfSense filterlog (blocks, port scans, repeat offenders)"

# *--- Record Parsing ---*

# shellcheck disable=SC2016  # awk fields are evaluated by awk
FIREWALL_RECORD_AWK='
function port(s) {
  return s ~ /^[0-9]{1,5}$/ && s + 0 <= 65535 ? sprintf("%d", s) : ""
}

function firewall_record(    f, i, offset, prefix) {
  sub(/\r$/, "")
  src = ""; dst = ""; dpt = ""; proto = ""; action = ""
  if (match($0, /(^|[ \t])filterlog(\[[0-9]+\])?:[ \t]*/)) {
    split(substr($0, RSTART + RLENGTH), f, ",")
    if (f[9] == "4") { proto = f[17]; offset = 19 }
    else if (f[9] == "6") { proto = f[13]; offset = 16 }
    else return 0
    proto = tolower(proto)
    action = f[7]
    src = bl_normal_ip(f[offset])
    dst = bl_normal_ip(f[offset + 1])
    dpt = f[offset + 3]
  } else {
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^SRC=/) src = bl_normal_ip(substr($i, 5))
      else if ($i ~ /^DST=/) dst = bl_normal_ip(substr($i, 5))
      else if ($i ~ /^DPT=/) dpt = substr($i, 5)
      else if ($i ~ /^PROTO=/) proto = tolower(substr($i, 7))
    }
    # Common rule prefixes and a bare trailing verdict occur in
    # iptables exports. A substring inside a field is not a verdict.
    prefix = tolower($0)
    sub(/[ \t](in|out|src)=.*/, "", prefix)
    if (prefix ~ /(^|[^a-z0-9])(drop|reject|denied|block)([^a-z0-9]|$)/ ||
        tolower($NF) ~ /^(drop|reject|denied|block)$/) action = "block"
  }
  return src != "" && dst != "" && proto ~ /^[a-z0-9-]+$/
}
'

# *--- Detection ---*

firewall_detect() {
  printf '%s\n' "$SAMPLE" | awk "$AWK_IP_LIB$FIREWALL_RECORD_AWK"'
    firewall_record() { hits++ }
    END { print (hits >= 2 ? 90 : hits ? 60 : 0) }
  '
}

# *--- Analysis ---*

firewall_analyze() {
  local file=$1
  local raw kind a b c

  raw=$(awk_log "$file" "$AWK_IP_LIB$FIREWALL_RECORD_AWK"'
    {
      if (!firewall_record()) { skipped++; next }
      total++
      if (proto == "tcp" || proto == "udp") dpt = port(dpt)
      else dpt = ""
      if (dpt != "") dports[dpt]++
      if (action != "block") next
      blocked++
      bsrcs[src]++
      if (dpt == "") next
      if (!((src SUBSEP dpt) in pair_count)) ports_per_src[src]++
      pair_count[src, dpt]++
      if (pair_count[src, dpt] > max_pair_n[src] ||
          (pair_count[src, dpt] == max_pair_n[src] && dpt + 0 < max_pair_p[src] + 0)) {
        max_pair_n[src] = pair_count[src, dpt]
        max_pair_p[src] = dpt
      }
    }
    END {
      printf "TOTAL\t%d\t-\n", total
      printf "SKIPPED\t%d\t-\n", skipped
      printf "BLOCKED\t%d\t-\n", blocked
      for (s in bsrcs) printf "BSRC\t%d\t%s\n", bsrcs[s], s
      for (p in dports) printf "DPORT\t%d\t%s\n", dports[p], p
      for (s in ports_per_src) printf "SCAN\t%d\t%s\n", ports_per_src[s], s
      for (s in max_pair_n) printf "REPEAT\t%d\t%s\t%s\n", max_pair_n[s], s, max_pair_p[s]
    }
  ')

  local total=0 skipped=0 blocked=0
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      SKIPPED) skipped=$a ;;
      BLOCKED) blocked=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -Ev '^(SRC|BSRC|DPORT|SCAN|REPEAT)' || true)

  report_metric "total_events" "$total"
  if [ "$skipped" -gt 0 ]; then report_metric "unparsed_lines" "$skipped"; fi
  report_metric "blocked_events" "$blocked"

  local list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^BSRC' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_blocked_sources" "$list"
  fi

  list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^DPORT' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_target_ports" "$list"
  fi

  # Port scan: one source blocked on many distinct destination ports.
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ "$a" -ge 10 ]; then
      report_add high port-scan \
        "$b was blocked on $a distinct ports (port scan)" \
        "ip=$b" "distinct_ports=$a"
    fi
  done < <(printf '%s\n' "$raw" | grep '^SCAN' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -3 || true)

  # Repeat offender: one source hammering a single port.
  while IFS=$'\t' read -r kind a b c; do
    if [ -z "$kind" ]; then continue; fi
    if [ "$a" -ge 20 ]; then
      report_add medium repeat-offender \
        "$b blocked $a times against port $c" \
        "ip=$b" "port=$c" "count=$a"
    fi
  done < <(printf '%s\n' "$raw" | grep '^REPEAT' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -3 || true)
}
