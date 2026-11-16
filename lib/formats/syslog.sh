# shellcheck shell=bash
# ******************************************************************************
# *Title: Classic Syslog Analyzer*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Analyzes BSD syslog for kernel, sudo, and error-rate signals.*
# ******************************************************************************

# NOTE: Targets classic BSD syslog ("Mon DD HH:MM:SS host prog[pid]: msg").
# General system triage: who is logging, what is failing, kernel red flags.

# *--- Registration ---*

register_format syslog "classic syslog (system triage: oom, segfaults, sudo, error rates)"

# *--- Record Parsing ---*

# shellcheck disable=SC2016  # awk fields are evaluated by awk
SYSLOG_RECORD_AWK='
function syslog_record(    line, header, n) {
  line = $0
  sub(/^<[0-9]{1,3}>/, "", line)
  if (!match(line, /^[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ [^ ]+:/)) return 0
  n = RLENGTH
  split(substr(line, 1, n), header, " ")
  if (bl_syslog_epoch(header[1], header[2], header[3], 2000) < 0) return 0
  timestamp = header[1] " " header[2] " " header[3]
  prog = header[5]
  sub(/(\[[0-9]+\])?:$/, "", prog)
  msg = substr(line, n + 1)
  return 1
}
'

# *--- Detection ---*

syslog_detect() {
  printf '%s\n' "$SAMPLE" | awk "$AWK_TIME_LIB$SYSLOG_RECORD_AWK"'
    syslog_record() { hits++ }
    END { print (hits >= 5 ? 60 : hits ? 50 : 0) }
  '
}

# *--- Analysis ---*

syslog_analyze() {
  local file=$1
  local raw kind a b

  raw=$(awk_log "$file" "$AWK_IP_LIB$AWK_TIME_LIB$SYSLOG_RECORD_AWK"'
    {
      if (!syslog_record()) { skipped++; next }
      total++
      if (first_ts == "") first_ts = timestamp
      last_ts = timestamp
      progs[prog]++
      low = tolower(msg)
      if (low ~ /error|fail|critical/) errors++
      if (prog == "kernel" && low ~ /out of memory|oom-killer|oom_kill/) oom++
      if (prog == "kernel" && low ~ /segfault/) segv++
      if (prog == "kernel" && low ~ /kernel panic/) panic++
      if (prog == "sudo" && low ~ /incorrect password|authentication failure|not in the sudoers/) sudo_fail++
      else if (prog == "sudo" && msg ~ /COMMAND=/) sudo_cmd++
    }
    END {
      printf "TOTAL\t%d\n", total
      printf "SKIPPED\t%d\n", skipped
      printf "ERRORS\t%d\n", errors
      printf "OOM\t%d\n", oom
      printf "SEGV\t%d\n", segv
      printf "PANIC\t%d\n", panic
      printf "SUDOFAIL\t%d\n", sudo_fail
      printf "SUDOCMD\t%d\n", sudo_cmd
      printf "FIRSTTS\t%s\n", first_ts
      printf "LASTTS\t%s\n", last_ts
      for (p in progs) printf "PROG\t%d\t%s\n", progs[p], bl_tsv(p)
    }
  ')

  local total=0 skipped=0 errors=0 oom=0 segv=0 panic=0 sudo_fail=0 sudo_cmd=0
  local first_ts="" last_ts=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      SKIPPED) skipped=$a ;;
      ERRORS) errors=$a ;;
      OOM) oom=$a ;;
      SEGV) segv=$a ;;
      PANIC) panic=$a ;;
      SUDOFAIL) sudo_fail=$a ;;
      SUDOCMD) sudo_cmd=$a ;;
      FIRSTTS) first_ts=$a ;;
      LASTTS) last_ts=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -v '^PROG' || true)

  report_metric "total_lines" "$total"
  if [ "$skipped" -gt 0 ]; then report_metric "unparsed_lines" "$skipped"; fi
  report_metric "error_lines" "$errors"
  report_metric "sudo_commands" "$sudo_cmd"
  if [ -n "$first_ts" ]; then
    report_metric "time_span" "$first_ts -> $last_ts"
  fi

  local list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^PROG' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_programs" "$list"
  fi

  if [ "$panic" -gt 0 ]; then
    report_add critical kernel-panic "kernel panic logged $panic time(s)" "count=$panic"
  fi
  if [ "$oom" -gt 0 ]; then
    report_add high oom-killer "out-of-memory killer fired on $oom line(s)" "count=$oom"
  fi
  if [ "$segv" -gt 0 ]; then
    report_add medium segfault "$segv segfault(s) logged" "count=$segv"
  fi
  if [ "$sudo_fail" -gt 0 ]; then
    report_add medium sudo-failures "$sudo_fail failed sudo attempt(s)" "count=$sudo_fail"
  fi
  if [ "$total" -ge 20 ] && [ "$errors" -gt 0 ] && [ $((errors * 5)) -ge "$total" ]; then
    report_add low error-rate "elevated error rate: $errors of $total lines" \
      "errors=$errors" "total=$total"
  fi
}
