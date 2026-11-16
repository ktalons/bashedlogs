# shellcheck shell=bash
# ******************************************************************************
# *Title: Journald Export Analyzer*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Triages systemd journal exports in short-iso or JSON format.*
# ******************************************************************************

# Supports journalctl short-iso text and one JSON object per line.

# *--- Registration ---*

register_format journald "journald exports (-o short-iso or -o json)"

# *--- Record Parsing ---*

# shellcheck disable=SC2016  # awk fields are evaluated by awk
JOURNAL_RECORD_AWK='
function journal_iso(    start) {
  if ($1 !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ || bl_iso_epoch($1) < 0) return 0
  if (!match($0, /^[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+:[ \t]*/)) return 0
  start = RLENGTH + 1
  timestamp = $1
  ident = $3
  sub(/(\[[0-9]+\])?:$/, "", ident)
  msg = tolower(substr($0, start))
  return 1
}

function journal_json(    root) {
  root = bl_json($0)
  return bl_jstr(root, "__REALTIME_TIMESTAMP") ~ /^[0-9]+$/ ? root : 0
}
'

# *--- Detection ---*

journald_detect() {
  printf '%s\n' "$SAMPLE" | awk "$AWK_JSON_LIB$AWK_TIME_LIB$JOURNAL_RECORD_AWK"'
    /^[ \t]*\{/ { if (journal_json()) { json = 1; exit }; next }
    journal_iso() { hits++ }
    END { print (json ? 95 : hits >= 3 ? 75 : hits ? 55 : 0) }
  '
}

# *--- Analysis ---*

journald_analyze() {
  local file=$1
  local raw kind a b mode=iso

  # shellcheck disable=SC2016  # quoted awk program
  raw=$(awk_log "$file" "$AWK_IP_LIB$AWK_JSON_LIB$AWK_TIME_LIB$JOURNAL_RECORD_AWK"'
    /^[ \t\r]*$/ { next }
    {
      if (/^[ \t]*\{/) {
        root = journal_json()
        if (!root) { skipped++; next }
        json_entries++
        msg = tolower(bl_jstr(root, "MESSAGE"))
        ident = bl_jstr(root, "SYSLOG_IDENTIFIER")
        if (ident == "") ident = bl_jstr(root, "_COMM")
        prio = bl_jstr(root, "PRIORITY")
        if (prio ~ /^[0-2]$/) sev_crit++
        if (prio ~ /^[0-3]$/) sev_err++
      } else {
        if (!journal_iso()) { skipped++; next }
        iso_entries++
        if (first_ts == "") first_ts = timestamp
        last_ts = timestamp
        if (msg ~ /error|fail|critical/) sev_err++
      }
      total++
      if (ident != "") idents[ident]++
      if (msg ~ /out of memory|oom-killer|oom_kill/) oom++
      if (msg ~ /segfault/) segv++
      if (msg ~ /authentication failure|failed password/) authfail++
    }
    END {
      printf "TOTAL\t%d\n", total
      mode = json_entries ? (iso_entries ? "mixed" : "json") : "iso"
      printf "MODE\t%s\n", mode
      printf "SKIPPED\t%d\n", skipped
      printf "CRIT\t%d\n", sev_crit
      printf "ERR\t%d\n", sev_err
      printf "OOM\t%d\n", oom
      printf "SEGV\t%d\n", segv
      printf "AUTHFAIL\t%d\n", authfail
      if (first_ts != "") printf "FIRSTTS\t%s\n", first_ts
      if (last_ts != "") printf "LASTTS\t%s\n", last_ts
      for (i in idents) printf "IDENT\t%d\t%s\n", idents[i], bl_tsv(i)
    }
  ')

  local total=0 skipped=0 crit=0 err=0 oom=0 segv=0 authfail=0 first_ts="" last_ts=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      MODE) mode=${a:-iso} ;;
      SKIPPED) skipped=$a ;;
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
  if [ "$skipped" -gt 0 ]; then report_metric "unparsed_lines" "$skipped"; fi
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
