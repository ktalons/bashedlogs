# shellcheck shell=bash
# syslog.sh - classic BSD syslog ("Mon DD HH:MM:SS host prog[pid]: msg")
# General system triage: who is logging, what is failing, kernel red flags.

register_format syslog "classic syslog (system triage: oom, segfaults, sudo, error rates)"

syslog_detect() {
  local hits
  hits=$(printf '%s\n' "$SAMPLE" \
    | grep -cE '^[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ [^ ]+(\[[0-9]+\])?:' || true)
  if [ "$hits" -ge 5 ]; then
    echo 60
  elif [ "$hits" -ge 2 ]; then
    echo 40
  else
    echo 0
  fi
}

syslog_analyze() {
  local file=$1
  local raw kind a b

  raw=$(awk "$AWK_IP_LIB"'
    {
      total++
      if (first_ts == "") first_ts = $1 " " $2 " " $3
      last_ts = $1 " " $2 " " $3
      host[$4]++
      prog = $5
      sub(/\[[0-9]+\]:?$/, "", prog)
      sub(/:$/, "", prog)
      progs[prog]++
      low = tolower($0)
      if (low ~ /error|fail|critical/) errors++
      if (low ~ /out of memory|oom-killer|oom_kill/) oom++
      if (low ~ /segfault/) segv++
      if (low ~ /kernel panic/) panic++
      if ($0 ~ /sudo/ && low ~ /incorrect password|authentication failure|not in the sudoers/) sudo_fail++
      else if ($0 ~ /sudo:/ && $0 ~ /COMMAND=/) sudo_cmd++
    }
    END {
      printf "TOTAL\t%d\n", total
      printf "ERRORS\t%d\n", errors
      printf "OOM\t%d\n", oom
      printf "SEGV\t%d\n", segv
      printf "PANIC\t%d\n", panic
      printf "SUDOFAIL\t%d\n", sudo_fail
      printf "SUDOCMD\t%d\n", sudo_cmd
      printf "FIRSTTS\t%s\n", first_ts
      printf "LASTTS\t%s\n", last_ts
      for (h in host) printf "HOST\t%d\t%s\n", host[h], bl_tsv(h)
      for (p in progs) printf "PROG\t%d\t%s\n", progs[p], bl_tsv(p)
    }
  ' "$file")

  local total=0 errors=0 oom=0 segv=0 panic=0 sudo_fail=0 sudo_cmd=0
  local first_ts="" last_ts=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      ERRORS) errors=$a ;;
      OOM) oom=$a ;;
      SEGV) segv=$a ;;
      PANIC) panic=$a ;;
      SUDOFAIL) sudo_fail=$a ;;
      SUDOCMD) sudo_cmd=$a ;;
      FIRSTTS) first_ts=$a ;;
      LASTTS) last_ts=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -Ev '^(HOST|PROG)' || true)

  report_metric "total_lines" "$total"
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
