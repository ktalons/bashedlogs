# shellcheck shell=bash
# web_access.sh - Apache/NGINX access logs (common and combined formats)
# One analyzer for both servers; v1 shipped an apache analyzer plus an
# unreachable duplicate - this replaces that pair.

register_format web_access "Apache/NGINX access logs (status mix, scanners, injection probes)"

web_access_detect() {
  local hits
  hits=$(printf '%s\n' "$SAMPLE" \
    | grep -cE '^[0-9]{1,3}(\.[0-9]{1,3}){3} [^ ]+ [^ ]+ \[[^]]+\] "[A-Z]+ ' || true)
  if [ "$hits" -ge 2 ]; then
    echo 90
  elif [ "$hits" -ge 1 ]; then
    echo 60
  else
    echo 0
  fi
}

web_access_analyze() {
  local file=$1
  local raw kind a b

  # FS='"' gives: $1 = 'ip - user [ts] ', $2 = request, $3 = ' status size '
  raw=$(awk -F'"' '
    function valid_ip(tok,    parts, j) {
      if (tok !~ /^([0-9]+\.){3}[0-9]+$/) return 0
      split(tok, parts, ".")
      for (j = 1; j <= 4; j++) {
        if (length(parts[j]) > 3 || parts[j] + 0 > 255) return 0
      }
      return 1
    }
    {
      total++
      n = split($1, pre, " ")
      ip = (n >= 1 && valid_ip(pre[1])) ? pre[1] : ""
      if (ip != "") ips[ip]++
      if (first_ts == "" && match($1, /\[[^]]+\]/)) first_ts = substr($1, RSTART + 1, RLENGTH - 2)
      if (match($1, /\[[^]]+\]/)) last_ts = substr($1, RSTART + 1, RLENGTH - 2)

      split($2, req, " ")
      path = req[2]
      if (path != "") paths[path]++

      split($3, post, " ")
      status = post[1] + 0
      if (status >= 200 && status < 300) s2xx++
      else if (status >= 300 && status < 400) s3xx++
      else if (status >= 400 && status < 500) { s4xx++; if (status == 404 && ip != "") nf[ip]++ }
      else if (status >= 500) s5xx++

      low = tolower($2)
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
      printf "S2XX\t%d\t-\n", s2xx
      printf "S3XX\t%d\t-\n", s3xx
      printf "S4XX\t%d\t-\n", s4xx
      printf "S5XX\t%d\t-\n", s5xx
      printf "SQLI\t%d\t%s\n", sqli, sqli_ex
      printf "XSS\t%d\t%s\n", xss, xss_ex
      printf "TRAV\t%d\t%s\n", trav, trav_ex
      np = 0; for (p in probe_ips) np++
      printf "PROBE\t%d\t%d\n", probe, np
      if (first_ts != "") printf "FIRSTTS\t%s\t-\n", first_ts
      if (last_ts != "") printf "LASTTS\t%s\t-\n", last_ts
      for (i in ips) printf "IP\t%d\t%s\n", ips[i], i
      for (p in paths) printf "PATH\t%d\t%s\n", paths[p], p
      for (i in nf) printf "NF\t%d\t%s\n", nf[i], i
    }
  ' "$file")

  local total=0 s2=0 s3=0 s4=0 s5=0 sqli=0 xss=0 trav=0 probe=0 probe_ips=0
  local sqli_ex="" xss_ex="" trav_ex="" first_ts="" last_ts=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
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
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    local reqs
    reqs=$(printf '%s\n' "$raw" | awk -F'\t' -v ip="$b" '$1 == "IP" && $3 == ip { print $2 }')
    reqs=${reqs:-0}
    if [ "$a" -ge 20 ] || { [ "$reqs" -ge 10 ] && [ $((a * 2)) -ge "$reqs" ]; }; then
      report_add medium scanning \
        "$a not-found responses to $b across $reqs request(s)" \
        "ip=$b" "status_404=$a" "requests=$reqs"
    fi
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
