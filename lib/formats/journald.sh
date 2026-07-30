# shellcheck shell=bash
# journald.sh - systemd journal exports
# Handles both `journalctl -o short-iso` text and `journalctl -o json` (one
# JSON object per line). JSON fields are extracted with awk string matching -
# enough for triage counts without breaking the zero-dependency rule.

register_format journald "journald exports (-o short-iso or -o json)"

journald_detect() {
  local first hits
  first=$(printf '%s\n' "$SAMPLE" | head -1)
  case "$first" in
    '{'*'"__REALTIME_TIMESTAMP"'*)
      echo 95
      return 0
      ;;
  esac
  hits=$(printf '%s\n' "$SAMPLE" \
    | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[^ ]* [^ ]+ [^ ]+\[[0-9]+\]:' || true)
  if [ "$hits" -ge 3 ]; then
    echo 75
  elif [ "$hits" -ge 1 ]; then
    echo 45
  else
    echo 0
  fi
}

journald_analyze() {
  local file=$1
  local first raw kind a b mode

  first=$(head -1 -- "$file")
  case "$first" in
    '{'*) mode=json ;;
    *) mode=iso ;;
  esac

  raw=$(awk -v MODE="$mode" "$AWK_IP_LIB"'
    # crude JSON field getter: "KEY":"value" (first occurrence, no nested escapes)
    function jfield(line, key,    pat, rest, v) {
      pat = "\"" key "\":\""
      rest = index(line, pat)
      if (rest == 0) return ""
      v = substr(line, rest + length(pat))
      sub(/".*$/, "", v)
      return v
    }
    {
      total++
      if (MODE == "json") {
        msg = tolower(jfield($0, "MESSAGE"))
        ident = jfield($0, "SYSLOG_IDENTIFIER")
        if (ident == "") ident = jfield($0, "_COMM")
        prio = jfield($0, "PRIORITY")
        if (prio != "") prios[prio]++
        if (prio != "" && prio + 0 <= 2) sev_crit++
        if (prio == "3") sev_err++
      } else {
        if (first_ts == "") first_ts = $1
        last_ts = $1
        msg = tolower($0)
        ident = $3
        sub(/\[[0-9]+\]:?$/, "", ident)
        sub(/:$/, "", ident)
        if (msg ~ /error|fail|critical/) sev_err++
      }
      if (ident != "") idents[ident]++
      if (msg ~ /out of memory|oom-killer|oom_kill/) oom++
      if (msg ~ /segfault/) segv++
      if (msg ~ /authentication failure|failed password/) authfail++
    }
    END {
      printf "TOTAL\t%d\n", total
      printf "CRIT\t%d\n", sev_crit
      printf "ERR\t%d\n", sev_err
      printf "OOM\t%d\n", oom
      printf "SEGV\t%d\n", segv
      printf "AUTHFAIL\t%d\n", authfail
      if (first_ts != "") printf "FIRSTTS\t%s\n", first_ts
      if (last_ts != "") printf "LASTTS\t%s\n", last_ts
      for (i in idents) printf "IDENT\t%d\t%s\n", idents[i], bl_tsv(i)
    }
  ' "$file")

  local total=0 crit=0 err=0 oom=0 segv=0 authfail=0 first_ts="" last_ts=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      CRIT) crit=$a ;;
      ERR) err=$a ;;
      OOM) oom=$a ;;
      SEGV) segv=$a ;;
      AUTHFAIL) authfail=$a ;;
      FIRSTTS) first_ts=$a ;;
      LASTTS) last_ts=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -v '^IDENT' || true)

  report_metric "total_entries" "$total"
  report_metric "input_mode" "$mode"
  report_metric "error_entries" "$err"
  if [ -n "$first_ts" ]; then
    report_metric "time_span" "$first_ts -> $last_ts"
  fi

  local list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^IDENT' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_units" "$list"
  fi

  if [ "$crit" -gt 0 ]; then
    report_add high journal-critical \
      "$crit entr(ies) at priority crit or worse" "count=$crit"
  fi
  if [ "$oom" -gt 0 ]; then
    report_add high oom-killer "out-of-memory killer fired on $oom entr(ies)" "count=$oom"
  fi
  if [ "$segv" -gt 0 ]; then
    report_add medium segfault "$segv segfault(s) logged" "count=$segv"
  fi
  if [ "$authfail" -gt 0 ]; then
    report_add medium auth-failures \
      "authentication failures on $authfail entr(ies)" "count=$authfail"
  fi
  if [ "$total" -ge 20 ] && [ "$err" -gt 0 ] && [ $((err * 5)) -ge "$total" ]; then
    report_add low error-rate "elevated error rate: $err of $total entries" \
      "errors=$err" "total=$total"
  fi
}
