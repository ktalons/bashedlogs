# shellcheck shell=bash
# generic.sh - fallback analyzer for logs with no dedicated format module
# Honest about what it is: keyword heuristics + IP frequency, labeled generic.

register_format generic "generic security heuristics (fallback for unrecognized formats)"

generic_detect() {
  # Never competes in detection; it is the explicit fallback.
  echo 0
}

generic_analyze() {
  local file=$1
  local total=0 errors=0 warns=0 authfail=0 sqli=0 xss=0 trav=0
  local raw kind count value
  local top_ips="" unique_ips=0 shown=0

  # Single awk pass. IPs are token-validated (each octet 0-255) instead of
  # substring-matched, so counts cannot be inflated by lookalike text.
  raw=$(awk '
    function count_ips(line,   n, toks, i, parts, ok, j) {
      n = split(line, toks, /[^0-9.]+/)
      for (i = 1; i <= n; i++) {
        if (toks[i] !~ /^([0-9]+\.){3}[0-9]+$/) continue
        ok = 1
        split(toks[i], parts, ".")
        for (j = 1; j <= 4; j++) {
          if (length(parts[j]) > 3 || parts[j] + 0 > 255) { ok = 0; break }
        }
        if (ok) ips[toks[i]]++
      }
    }
    {
      total++
      low = tolower($0)
      if (low ~ /error|fatal|critical/) errors++
      if (low ~ /warn/) warns++
      if (low ~ /failed (password|login)|authentication fail|invalid user|login fail|access denied/) authfail++
      if (low ~ /union[^a-z0-9]+select|information_schema|sleep\(|benchmark\(/) sqli++
      if (low ~ /<script|%3cscript/) xss++
      if (low ~ /\.\.\/|\.\.%2f|%2e%2e/) trav++
      count_ips($0)
    }
    END {
      printf "TOTAL\t%d\t-\n", total
      printf "ERRORS\t%d\t-\n", errors
      printf "WARNS\t%d\t-\n", warns
      printf "AUTHFAIL\t%d\t-\n", authfail
      printf "SQLI\t%d\t-\n", sqli
      printf "XSS\t%d\t-\n", xss
      printf "TRAV\t%d\t-\n", trav
      for (ip in ips) printf "IPROW\t%d\t%s\n", ips[ip], ip
    }
  ' "$file")

  while IFS=$'\t' read -r kind count value; do
    case "$kind" in
      TOTAL) total=$count ;;
      ERRORS) errors=$count ;;
      WARNS) warns=$count ;;
      AUTHFAIL) authfail=$count ;;
      SQLI) sqli=$count ;;
      XSS) xss=$count ;;
      TRAV) trav=$count ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -v '^IPROW' || true)

  unique_ips=$(printf '%s\n' "$raw" | grep -c '^IPROW' || true)

  # Top talkers: count desc, then IP asc for deterministic ties.
  while IFS=$'\t' read -r kind count value; do
    if [ -z "$kind" ]; then continue; fi
    shown=$((shown + 1))
    if [ -n "$top_ips" ]; then top_ips="$top_ips, "; fi
    top_ips="$top_ips$value ($count)"
  done < <(printf '%s\n' "$raw" | grep '^IPROW' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)

  report_metric "total_lines" "$total"
  report_metric "error_lines" "$errors"
  report_metric "warning_lines" "$warns"
  report_metric "unique_source_ips" "$unique_ips"
  if [ -n "$top_ips" ]; then
    report_metric "top_source_ips" "$top_ips"
  fi

  if [ "$authfail" -gt 0 ]; then
    report_add medium auth-failures \
      "authentication failure keywords on $authfail line(s)" "count=$authfail"
  fi
  if [ "$sqli" -gt 0 ]; then
    report_add high injection-sqli \
      "SQL injection patterns on $sqli line(s)" "count=$sqli"
  fi
  if [ "$xss" -gt 0 ]; then
    report_add high injection-xss \
      "cross-site scripting patterns on $xss line(s)" "count=$xss"
  fi
  if [ "$trav" -gt 0 ]; then
    report_add high path-traversal \
      "path traversal patterns on $trav line(s)" "count=$trav"
  fi
  if [ "$total" -ge 20 ] && [ "$errors" -gt 0 ] && [ $((errors * 5)) -ge "$total" ]; then
    report_add low error-rate \
      "elevated error rate: $errors of $total lines" "errors=$errors" "total=$total"
  fi
}
