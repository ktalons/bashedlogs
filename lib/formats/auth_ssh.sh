# shellcheck shell=bash
# auth_ssh.sh - SSH/PAM authentication log analyzer
#
# Replaces v1's total-keyword-count "brute force detection" with a real
# per-source sliding window.
#
# Counting one attempt exactly once is the whole ballgame here:
#   - Debian/Ubuntu sshd logs BOTH `pam_unix(sshd:auth): authentication
#     failure` and `Failed password` for a single failed attempt. Counting both
#     doubled every figure and halved the effective --bf-threshold, so three
#     attempts could raise a "12 failures" alert. sshd's own `Failed <method>`
#     line is authoritative; the PAM line is only used as the failure stream
#     when a log contains no sshd failure lines at all (filtered exports).
#   - `Invalid user` preambles are enumeration signal, not separate failures.
#   - `Failed publickey`/`Failed none` are routine negotiation noise, counted
#     as probes rather than credential attempts.

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
  raw=$(awk -v YEAR="$assume_year" "$AWK_IP_LIB$AWK_TIME_LIB"'
    # IP after a "from" token, or rhost=IP. Handles IPv4 and IPv6.
    function line_ip(   i, tok) {
      for (i = 1; i < NF; i++) {
        if ($i == "from") {
          tok = bl_clean_ip($(i + 1))
          if (bl_valid_ip(tok)) return tok
        }
      }
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^rhost=/) {
          tok = bl_clean_ip(substr($i, 7))
          if (bl_valid_ip(tok)) return tok
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

      # sshd credential failures: authoritative, one line per real attempt.
      if ($0 ~ /Failed (password|keyboard-interactive)/) {
        sshd_fail++
        if ($0 ~ /for root |for invalid user root /) sshd_root++
        if (ip != "") {
          sshd_fail_ip[ip]++
          user = line_user()
          if (user != "" && user != "invalid") sshd_fail_user[user]++
          if (e > 0) printf "EV\tsshd\t%d\tfail\t%s\n", e, ip
        }
        next
      }
      # PAM view of the same attempt. Tracked separately and only promoted to
      # the failure stream when the log has no sshd failure lines at all.
      if ($0 ~ /pam_unix\(sshd:auth\): authentication failure/) {
        pam_fail++
        if ($0 ~ /user=root($| )/) pam_root++
        if (ip != "") {
          pam_fail_ip[ip]++
          user = line_user()
          if (user != "" && user != "invalid") pam_fail_user[user]++
          if (e > 0) printf "EV\tpam\t%d\tfail\t%s\n", e, ip
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
        if (ip != "" && e > 0) printf "EV\tboth\t%d\taccept\t%s\t%s\n", e, ip, user
        next
      }
      if ($0 ~ /Failed (publickey|none)/) { probes++; next }
      if ($0 ~ /Did not receive identification|Connection (closed|reset) by .*preauth|Received disconnect/) {
        probes++
        next
      }
      if ($0 ~ /session opened/) { sess_open++; next }
      if ($0 ~ /session closed/) { sess_close++; next }
    }
    END {
      # sshd lines win when present; PAM lines are the fallback stream.
      use_pam = (sshd_fail == 0 && pam_fail > 0)
      printf "SOURCE\t%s\n", (use_pam ? "pam" : "sshd")
      printf "TOTAL\t%d\n", total
      printf "FAILED\t%d\n", (use_pam ? pam_fail : sshd_fail)
      printf "PAMDUPES\t%d\n", (use_pam ? 0 : pam_fail)
      printf "INVALID\t%d\n", invalid
      printf "ACCEPTED\t%d\n", accepted
      printf "ROOTATT\t%d\n", (use_pam ? pam_root : sshd_root)
      printf "ROOTPW\t%d\n", root_pw_login
      printf "PROBES\t%d\n", probes
      printf "SESSOPEN\t%d\n", sess_open
      printf "SESSCLOSE\t%d\n", sess_close
      printf "FIRSTTS\t%s\n", first_ts
      printf "LASTTS\t%s\n", last_ts
      n = 0; for (u in enum_user) n++
      printf "ENUMUSERS\t%d\n", n
      if (use_pam) {
        for (ipx in pam_fail_ip) printf "FIP\t%d\t%s\n", pam_fail_ip[ipx], ipx
        for (u in pam_fail_user) printf "FUSER\t%d\t%s\n", pam_fail_user[u], bl_tsv(u)
      } else {
        for (ipx in sshd_fail_ip) printf "FIP\t%d\t%s\n", sshd_fail_ip[ipx], ipx
        for (u in sshd_fail_user) printf "FUSER\t%d\t%s\n", sshd_fail_user[u], bl_tsv(u)
      }
    }
  ' "$file")

  local total=0 failed=0 invalid=0 accepted=0 root_attempts=0 root_pw=0
  local probes=0 sess_open=0 sess_close=0 enum_users=0 first_ts="" last_ts=""
  local source="sshd" pam_dupes=0
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      SOURCE) source=$a ;;
      PAMDUPES) pam_dupes=$a ;;
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
  # Only events from the authoritative source feed the window, so a log that
  # carries both sshd and PAM lines for one attempt cannot double-count.
  # Fields: EV <source> <epoch> <kind> <ip> [user]
  events=$(printf '%s\n' "$raw" | grep '^EV' \
    | awk -F'\t' -v src="$source" '$2 == src || $2 == "both"' \
    | sort -t "$(printf '\t')" -k3,3n || true)
  local windows=""
  if [ -n "$events" ]; then
    windows=$(printf '%s\n' "$events" | awk -F'\t' \
      -v W="$BF_WINDOW" -v T="$BF_THRESHOLD" '
      $4 == "fail" {
        t = $3 + 0; ip = $5
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
      $4 == "accept" {
        t = $3 + 0; ip = $5; user = $6
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
  report_metric "failure_source" "$source"
  if [ "$pam_dupes" -gt 0 ]; then
    report_metric "pam_duplicate_lines" "$pam_dupes (not counted)"
  fi
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
