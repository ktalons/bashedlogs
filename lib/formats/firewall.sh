# shellcheck shell=bash
# firewall.sh - iptables (kernel SRC=/DST= lines) and pfSense filterlog
# Both shapes can coexist in one file; each line is classified on its own.

register_format firewall "iptables + pfSense filterlog (blocks, port scans, repeat offenders)"

firewall_detect() {
  local ipt pf
  ipt=$(printf '%s\n' "$SAMPLE" | grep -c 'SRC=.*DST=.*PROTO=' || true)
  pf=$(printf '%s\n' "$SAMPLE" | grep -c 'filterlog' || true)
  if [ $((ipt + pf)) -ge 2 ]; then
    echo 90
  elif [ $((ipt + pf)) -ge 1 ]; then
    echo 60
  else
    echo 0
  fi
}

firewall_analyze() {
  local file=$1
  local raw kind a b c

  raw=$(awk '
    function valid_ip(tok,    parts, j) {
      if (tok !~ /^([0-9]+\.){3}[0-9]+$/) return 0
      split(tok, parts, ".")
      for (j = 1; j <= 4; j++) {
        if (length(parts[j]) > 3 || parts[j] + 0 > 255) return 0
      }
      return 1
    }
    # iptables kernel line: KEY=VALUE tokens
    /SRC=.*DST=.*PROTO=/ {
      total++
      src = ""; dpt = ""; action = "log"
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^SRC=/) src = substr($i, 5)
        else if ($i ~ /^DPT=/) dpt = substr($i, 5)
      }
      if (tolower($0) ~ /drop|reject|denied|block/) { action = "block"; blocked++ }
      if (valid_ip(src)) {
        srcs[src]++
        if (action == "block") {
          bsrcs[src]++
          if (dpt != "") {
            if (!((src SUBSEP dpt) in seen_pair)) { seen_pair[src, dpt] = 1; ports_per_src[src]++ }
            pair_count[src, dpt]++
            if (pair_count[src, dpt] > max_pair_n[src]) { max_pair_n[src] = pair_count[src, dpt]; max_pair_p[src] = dpt }
          }
        }
      }
      if (dpt != "") dports[dpt]++
      next
    }
    # pfSense filterlog CSV: action at a fixed early position, then the first
    # two dotted quads are src/dst, the next two numeric fields the ports
    /filterlog/ {
      total++
      csv = $0
      sub(/^.*filterlog(\[[0-9]+\])?: */, "", csv)
      n = split(csv, f, ",")
      action = ""
      src = ""; dst = ""; sport = ""; dport = ""
      for (i = 1; i <= n; i++) {
        if (f[i] == "block" || f[i] == "pass" || f[i] == "rdr") { if (action == "") action = f[i] }
        if (src == "" && valid_ip(f[i])) { src = f[i]; continue }
        if (src != "" && dst == "" && valid_ip(f[i])) { dst = f[i]; continue }
        if (dst != "" && sport == "" && f[i] ~ /^[0-9]+$/) { sport = f[i]; continue }
        if (sport != "" && dport == "" && f[i] ~ /^[0-9]+$/) { dport = f[i]; continue }
      }
      if (action == "block") blocked++
      if (src != "") {
        srcs[src]++
        if (action == "block") {
          bsrcs[src]++
          if (dport != "") {
            if (!((src SUBSEP dport) in seen_pair)) { seen_pair[src, dport] = 1; ports_per_src[src]++ }
            pair_count[src, dport]++
            if (pair_count[src, dport] > max_pair_n[src]) { max_pair_n[src] = pair_count[src, dport]; max_pair_p[src] = dport }
          }
        }
      }
      if (dport != "") dports[dport]++
      next
    }
    END {
      printf "TOTAL\t%d\t-\n", total
      printf "BLOCKED\t%d\t-\n", blocked
      for (s in srcs) printf "SRC\t%d\t%s\n", srcs[s], s
      for (s in bsrcs) printf "BSRC\t%d\t%s\n", bsrcs[s], s
      for (p in dports) printf "DPORT\t%d\t%s\n", dports[p], p
      for (s in ports_per_src) printf "SCAN\t%d\t%s\n", ports_per_src[s], s
      for (s in max_pair_n) printf "REPEAT\t%d\t%s\t%s\n", max_pair_n[s], s, max_pair_p[s]
    }
  ' "$file")

  local total=0 blocked=0
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      BLOCKED) blocked=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -Ev '^(SRC|BSRC|DPORT|SCAN|REPEAT)' || true)

  report_metric "total_events" "$total"
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
