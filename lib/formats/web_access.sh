# shellcheck shell=bash
# ******************************************************************************
# *Title: Apache/NGINX Access Log Analyzer*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Flags scanners and injection probes in Apache and NGINX logs.*
# ******************************************************************************

# NOTE: One analyzer for both servers; v1 shipped an apache analyzer plus an
# unreachable duplicate - this replaces that pair.

# *--- Registration ---*

register_format web_access "Apache/NGINX access logs (status mix, scanners, injection probes)"

# *--- Record Parsing ---*

# Mask escaped backslashes and quotes without moving the field boundaries.
# This works for Apache and NGINX escape=json fields in common/combined logs.
# shellcheck disable=SC2016  # awk fields are evaluated by awk
WEB_RECORD_AWK='
function web_record(    line, mask, q, f, i, pos, pre, req, post) {
  line = $0
  sub(/\r$/, "", line)
  mask = line
  gsub(/\\\\/, "__", mask)
  gsub(/\\"/, "__", mask)
  if (split(mask, q, "\"") < 3) return 0

  pos = 1
  for (i = 1; i <= 3; i++) {
    f[i] = substr(line, pos, length(q[i]))
    pos += length(q[i]) + 1
  }
  if (!match(f[1], /\[[0-9]{1,2}\/[A-Z][a-z]{2}\/[0-9]{4}:[^]]+\][ \t]+$/)) return 0
  timestamp = substr(f[1], RSTART + 1, RLENGTH - 1)
  sub(/\][ \t]+$/, "", timestamp)
  split(f[1], pre, " ")
  ip = bl_normal_ip(pre[1])
  if (ip == "" && pre[1] !~ /^([A-Za-z0-9][A-Za-z0-9.-]*|-)$/) return 0

  split(f[3], post, " ")
  if (post[1] !~ /^[1-5][0-9]{2}$/) return 0
  status = post[1] + 0
  request = f[2]
  split(request, req, " ")
  path = req[2]
  return 1
}
'

# *--- Detection ---*

web_access_detect() {
  printf '%s\n' "$SAMPLE" | awk "$AWK_IP_LIB$WEB_RECORD_AWK"'
    web_record() { hits++ }
    END { print (hits >= 2 ? 90 : hits ? 60 : 0) }
  '
}

# *--- Analysis ---*

web_access_analyze() {
  local file=$1
  local raw kind a b c

  raw=$(awk_log "$file" "$AWK_IP_LIB$WEB_RECORD_AWK"'
    {
      if (!web_record()) { skipped++; next }
      total++
      if (ip != "") ips[ip]++
      if (first_ts == "") first_ts = timestamp
      last_ts = timestamp
      if (path != "") paths[path]++

      if (status < 200) s1xx++
      else if (status < 300) s2xx++
      else if (status < 400) s3xx++
      else if (status < 500) { s4xx++; if (status == 404 && ip != "") nf[ip]++ }
      else s5xx++

      low = tolower(request)
      if (low ~ /union[^a-z0-9]+select|union\+select|union%20select|information_schema|sleep\(|benchmark\(/) {
        sqli++; if (sqli_ex == "") sqli_ex = path
      }
      if (low ~ /<script|%3cscript/) { xss++; if (xss_ex == "") xss_ex = path }
      if (low ~ /\.\.\/|\.\.%2f|%2e%2e/) { trav++; if (trav_ex == "") trav_ex = path }
      if (low ~ /wp-login\.php|xmlrpc\.php|\/\.env|phpmyadmin|\/\.git|\/etc\/passwd/) {
        probe++
        if (ip != "") probe_ips[ip] = 1
      }
    }
    END {
      printf "TOTAL\t%d\t-\n", total
      printf "SKIPPED\t%d\t-\n", skipped
      printf "S1XX\t%d\t-\n", s1xx
      printf "S2XX\t%d\t-\n", s2xx
      printf "S3XX\t%d\t-\n", s3xx
      printf "S4XX\t%d\t-\n", s4xx
      printf "S5XX\t%d\t-\n", s5xx
      printf "SQLI\t%d\t%s\n", sqli, bl_tsv(sqli_ex)
      printf "XSS\t%d\t%s\n", xss, bl_tsv(xss_ex)
      printf "TRAV\t%d\t%s\n", trav, bl_tsv(trav_ex)
      np = 0; for (p in probe_ips) np++
      printf "PROBE\t%d\t%d\n", probe, np
      if (first_ts != "") printf "FIRSTTS\t%s\t-\n", first_ts
      if (last_ts != "") printf "LASTTS\t%s\t-\n", last_ts
      for (i in ips) printf "IP\t%d\t%s\n", ips[i], i
      for (p in paths) printf "PATH\t%d\t%s\n", paths[p], bl_tsv(p)
      for (i in nf) {
        if (nf[i] >= 20 || (ips[i] >= 10 && nf[i] * 2 >= ips[i]))
          printf "NF\t%d\t%s\t%d\n", nf[i], i, ips[i]
      }
    }
  ')

  local total=0 skipped=0 s1=0 s2=0 s3=0 s4=0 s5=0 sqli=0 xss=0 trav=0 probe=0 probe_ips=0
  local sqli_ex="" xss_ex="" trav_ex="" first_ts="" last_ts=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      SKIPPED) skipped=$a ;;
      S1XX) s1=$a ;;
      S2XX) s2=$a ;;
      S3XX) s3=$a ;;
      S4XX) s4=$a ;;
      S5XX) s5=$a ;;
      SQLI) sqli=$a; sqli_ex=$b ;;
      XSS) xss=$a; xss_ex=$b ;;
      TRAV) trav=$a; trav_ex=$b ;;
      PROBE) probe=$a; probe_ips=$b ;;
      FIRSTTS) first_ts=$a ;;
      LASTTS) last_ts=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -Ev '^(IP|PATH|NF)' || true)

  report_metric "total_requests" "$total"
  if [ "$skipped" -gt 0 ]; then report_metric "unparsed_lines" "$skipped"; fi
  if [ "$s1" -gt 0 ]; then report_metric "status_1xx" "$s1"; fi
  report_metric "status_2xx" "$s2"
  report_metric "status_3xx" "$s3"
  report_metric "status_4xx" "$s4"
  report_metric "status_5xx" "$s5"
  if [ -n "$first_ts" ]; then
    report_metric "time_span" "$first_ts -> $last_ts"
  fi

  local list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^IP' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_clients" "$list"
  fi

  list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^PATH' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_paths" "$list"
  fi

  if [ "$sqli" -gt 0 ]; then
    report_add high injection-sqli \
      "SQL injection patterns in $sqli request(s)" "count=$sqli" "example=$sqli_ex"
  fi
  if [ "$xss" -gt 0 ]; then
    report_add high injection-xss \
      "cross-site scripting patterns in $xss request(s)" "count=$xss" "example=$xss_ex"
  fi
  if [ "$trav" -gt 0 ]; then
    report_add high path-traversal \
      "path traversal patterns in $trav request(s)" "count=$trav" "example=$trav_ex"
  fi

  # Scanner: an IP whose 404 volume is high in absolute or relative terms.
  while IFS=$'\t' read -r kind a b c; do
    if [ -z "$kind" ]; then continue; fi
    report_add medium scanning \
      "$a not-found responses to $b across $c request(s)" \
      "ip=$b" "status_404=$a" "requests=$c"
  done < <(printf '%s\n' "$raw" | grep '^NF' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)

  if [ "$probe" -gt 0 ]; then
    report_add medium sensitive-paths \
      "$probe request(s) probing sensitive paths from $probe_ips IP(s)" \
      "count=$probe" "unique_ips=$probe_ips"
  fi
  if [ "$total" -ge 20 ] && [ "$s5" -gt 0 ] && [ $((s5 * 10)) -ge "$total" ]; then
    report_add low server-errors "elevated 5xx rate: $s5 of $total requests" \
      "errors=$s5" "total=$total"
  fi
}
