# shellcheck shell=bash
# auth_ssh.sh - SSH/PAM authentication log analyzer
#
# Replaces v1's total-keyword-count "brute force detection" with a real
# per-source sliding window, and only counts "Failed password"/"authentication
# failure" lines as failure events ("Invalid user" preambles are tracked as
# enumeration signal instead of double-counting the same attempt).

register_format auth_ssh "SSH/PAM auth logs (sshd, brute force windows, compromise heuristic)"

auth_ssh_detect() {
  local hits
  hits=$(printf '%s\n' "$SAMPLE" | grep -cE 'sshd\[[0-9]+\]:|pam_unix\(sshd' || true)
  if [ "$hits" -ge 3 ]; then
    echo 95
  elif [ "$hits" -ge 1 ]; then
    echo 70
  else
    echo 0
  fi
}

auth_ssh_analyze() {
  local file=$1
  local assume_year="${BASHEDLOGS_ASSUME_YEAR:-$(date +%Y)}"
  local raw events kind a b c

  # Pass 1: classify events, extract validated IPs/users, stamp epochs.
  raw=$(awk -v YEAR="$assume_year" "$AWK_TIME_LIB"'
    function valid_ip(tok,    parts, j) {
      if (tok !~ /^([0-9]+\.){3}[0-9]+$/) return 0
      split(tok, parts, ".")
      for (j = 1; j <= 4; j++) {
        if (length(parts[j]) > 3 || parts[j] + 0 > 255) return 0
      }
      return 1
    }
    # IP after a "from" token, or rhost=IP
    function line_ip(   i, tok) {
      for (i = 1; i < NF; i++) {
        if ($i == "from" && valid_ip($(i + 1))) return $(i + 1)
      }
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^rhost=/) {
          tok = substr($i, 7)
          if (valid_ip(tok)) return tok
        }
      }
      return ""
    }
    function line_user(   i) {
      for (i = 1; i < NF; i++) {
        if ($i == "for" && $(i + 1) == "invalid" && $(i + 2) == "user") return $(i + 3)
        if ($i == "for" && $(i + 1) != "invalid") return $(i + 1)
        if ($i == "user" && $(i - 1) == "Invalid") return $(i + 1)
      }
      return ""
    }
    function line_epoch(    e) {
      e = bl_syslog_epoch($1, $2, $3, YEAR + year_wrap)
      if (e < 0) {
        # journald short-iso exports of sshd logs carry ISO timestamps
        e = bl_iso_epoch($1)
        if (e > 0) prev_e = e
        return e
      }
      # year rollover inside one file: a >180-day backwards jump means Jan
      if (prev_e > 0 && e + 15552000 < prev_e) {
        year_wrap++
        e = bl_syslog_epoch($1, $2, $3, YEAR + year_wrap)
      }
      if (e > 0) prev_e = e
      return e
    }
    {
      total++
      if (first_ts == "") first_ts = $1 " " $2 " " $3
      last_ts = $1 " " $2 " " $3
      ip = line_ip()
      e = line_epoch()

      if ($0 ~ /Failed password|pam_unix\(sshd:auth\): authentication failure/) {
        failed++
        if ($0 ~ /for root |user=root($| )/) root_attempts++
        if (ip != "") {
          fail_ip[ip]++
          user = line_user()
          if (user != "" && user != "invalid") fail_user[user]++
          if (e > 0) printf "EV\t%d\tfail\t%s\n", e, ip
        }
        next
      }
      if ($0 ~ /Invalid user /) {
        invalid++
        user = line_user()
        if (user != "") enum_user[user] = 1
        next
      }
      if ($0 ~ /Accepted (password|publickey|keyboard-interactive)/) {
        accepted++
        user = line_user()
        if ($0 ~ /Accepted password for root /) root_pw_login++
        if (ip != "" && e > 0) printf "EV\t%d\taccept\t%s\t%s\n", e, ip, user
        next
      }
      if ($0 ~ /Did not receive identification|Connection (closed|reset) by .*preauth|Received disconnect/) {
        probes++
        next
      }
      if ($0 ~ /session opened/) { sess_open++; next }
      if ($0 ~ /session closed/) { sess_close++; next }
    }
    END {
      printf "TOTAL\t%d\n", total
      printf "FAILED\t%d\n", failed
      printf "INVALID\t%d\n", invalid
      printf "ACCEPTED\t%d\n", accepted
      printf "ROOTATT\t%d\n", root_attempts
      printf "ROOTPW\t%d\n", root_pw_login
      printf "PROBES\t%d\n", probes
      printf "SESSOPEN\t%d\n", sess_open
      printf "SESSCLOSE\t%d\n", sess_close
      printf "FIRSTTS\t%s\n", first_ts
      printf "LASTTS\t%s\n", last_ts
      n = 0; for (u in enum_user) n++
      printf "ENUMUSERS\t%d\n", n
      for (ipx in fail_ip) printf "FIP\t%d\t%s\n", fail_ip[ipx], ipx
      for (u in fail_user) printf "FUSER\t%d\t%s\n", fail_user[u], u
    }
  ' "$file")

  local total=0 failed=0 invalid=0 accepted=0 root_attempts=0 root_pw=0
  local probes=0 sess_open=0 sess_close=0 enum_users=0 first_ts="" last_ts=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      FAILED) failed=$a ;;
      INVALID) invalid=$a ;;
      ACCEPTED) accepted=$a ;;
      ROOTATT) root_attempts=$a ;;
      ROOTPW) root_pw=$a ;;
      PROBES) probes=$a ;;
      SESSOPEN) sess_open=$a ;;
      SESSCLOSE) sess_close=$a ;;
      ENUMUSERS) enum_users=$a ;;
      FIRSTTS) first_ts=$a ;;
      LASTTS) last_ts=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -Ev '^(EV|FIP|FUSER)' || true)

  # Pass 2: per-IP sliding window over the time-sorted failure stream, plus
  # the compromise heuristic (an accept from the same IP soon after a burst).
  events=$(printf '%s\n' "$raw" | grep '^EV' | sort -t "$(printf '\t')" -k2,2n || true)
  local windows=""
  if [ -n "$events" ]; then
    windows=$(printf '%s\n' "$events" | awk -F'\t' \
      -v W="$BF_WINDOW" -v T="$BF_THRESHOLD" '
      $3 == "fail" {
        t = $2 + 0; ip = $4
        q[ip, ++tail[ip]] = t
        while (head[ip] < tail[ip] && q[ip, head[ip] + 1] <= t - W) head[ip]++
        size = tail[ip] - head[ip]
        if (size >= T) {
          if (size > burst_n[ip]) {
            burst_n[ip] = size
            burst_start[ip] = q[ip, head[ip] + 1]
            burst_end[ip] = t
          }
          last_burst[ip] = t
        }
      }
      $3 == "accept" {
        t = $2 + 0; ip = $4; user = $5
        if ((ip in last_burst) && t >= last_burst[ip] && t - last_burst[ip] <= 600) {
          comp_user[ip] = user
          comp_t[ip] = t
        }
      }
      END {
        for (ip in burst_n)
          printf "BURST\t%d\t%s\t%d\n", burst_n[ip], ip, burst_end[ip] - burst_start[ip]
        for (ip in comp_user)
          printf "COMPROMISE\t%s\t%s\n", ip, comp_user[ip]
      }
    ' | sort -t "$(printf '\t')" -k1,1r -k2,2rn -k3,3)
  fi

  report_metric "total_lines" "$total"
  report_metric "failed_auth" "$failed"
  report_metric "invalid_user_lines" "$invalid"
  report_metric "accepted_logins" "$accepted"
  report_metric "sessions_opened" "$sess_open"
  report_metric "sessions_closed" "$sess_close"
  report_metric "probes_preauth" "$probes"
  if [ -n "$first_ts" ]; then
    report_metric "time_span" "$first_ts -> $last_ts"
  fi

  # Top attacking IPs (count desc, IP asc), max 5, from validated counts.
  local top=""
  local shown=0
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    shown=$((shown + 1))
    if [ -n "$top" ]; then top="$top, "; fi
    top="$top$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^FIP' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$top" ]; then
    report_metric "top_attacking_ips" "$top"
  fi

  local tusers=""
  shown=0
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$tusers" ]; then tusers="$tusers, "; fi
    tusers="$tusers$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^FUSER' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$tusers" ]; then
    report_metric "targeted_users" "$tusers"
  fi

  # Findings, worst first: compromise heuristic, bursts, root activity, noise.
  if [ -n "$windows" ]; then
    while IFS=$'\t' read -r kind a b c; do
      case "$kind" in
        COMPROMISE)
          report_add critical possible-compromise \
            "successful login for '$b' from $a shortly after a brute-force burst from the same IP" \
            "ip=$a" "user=$b"
          ;;
        BURST)
          report_add high brute-force \
            "$a failed logins from $b within ${c}s (threshold: $BF_THRESHOLD in ${BF_WINDOW}s)" \
            "ip=$b" "count=$a" "burst_seconds=$c"
          ;;
      esac
    done < <(printf '%s\n' "$windows")
  fi
  if [ "$root_pw" -gt 0 ]; then
    report_add high root-password-login \
      "root logged in with a password $root_pw time(s)" "count=$root_pw"
  fi
  if [ "$root_attempts" -gt 0 ]; then
    report_add medium root-attempts \
      "$root_attempts failed login attempt(s) targeting root" "count=$root_attempts"
  fi
  if [ "$enum_users" -ge 5 ]; then
    report_add low user-enumeration \
      "$invalid invalid-user attempts across $enum_users unique names" \
      "unique_names=$enum_users"
  fi
  if [ "$probes" -ge 10 ]; then
    report_add info scanning \
      "$probes pre-auth probes/disconnects (scanners knocking)" "count=$probes"
  fi
}
