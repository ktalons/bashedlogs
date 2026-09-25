# shellcheck shell=bash
# ******************************************************************************
# *Title: SSH/PAM Authentication Log Analyzer*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Flags SSH/PAM brute force and possible compromise in auth logs.*
# ******************************************************************************

# Replaces v1's total-keyword-count "brute force detection" with a real
# per-source sliding window.

# *--- Registration ---*

register_format auth_ssh "SSH/PAM auth logs (sshd, brute force windows, compromise heuristic)"

# *--- Detection ---*

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

# *--- Analysis ---*

# NOTE: Counting one attempt exactly once is the whole ballgame here.
#   - Debian/Ubuntu sshd logs BOTH `pam_unix(sshd:auth): authentication
#     failure` and `Failed password` for a single failed attempt. Counting both
#     doubled every figure and halved the effective --bf-threshold, so three
#     attempts could raise a "12 failures" alert. sshd's own `Failed <method>`
#     line is authoritative; the PAM line is only used as the failure stream
#     when a log contains no sshd failure lines at all (filtered exports).
#   - `Invalid user` preambles are enumeration signal, not separate failures.
#   - `Failed publickey`/`Failed none` are routine negotiation noise, counted
#     as probes rather than credential attempts.
#
# SECURITY: sshd logs the username a client sends, and the text of a client
# disconnect, verbatim and with spaces. A username of `x from 198.51.100.7`
# used to put that address on the brute force, and a later real login from it
# read as a possible compromise. Failures, accepts, and their addresses are
# now read only from sshd's own message, which starts after the program tag
# (or the journald MESSAGE key) and must start with the event's words:
#   - A failure takes the address after the LAST `from`. The username comes
#     before sshd's own `from <ip> port <n>`, so it cannot follow it.
#   - An accept takes the FIRST `from`. A certificate key ID comes after it.
#   - PAM takes `rhost=` only, which precedes `user=`.
#   - Event words quoted inside another message are not sshd's. The test is
#     position, not the name: a tag with other text between it and the words
#     means the words belong to that other program, while a tag that reads
#     differently but is followed straight by the words is still sshd. Relays,
#     rsyslog templates and container runtimes all rewrite the tag, and
#     requiring it to name ssh made a containerized sshd report no failures.
# With no tag (journalctl -o cat, RFC 5424, Windows), the message starts at the
# earliest word sshd opens a message with. Every message that carries client
# text opens with one of those words, so client text always comes after it.
#
# WARN: attribution is trusted, not proved. Reading by position rather than by
# name means any program whose message opens with sshd words is read as sshd,
# so an app that logs attacker text at the start of its own message, into the
# same file, can invent a burst against a machine that never connected. The
# reverse rule hides a real burst behind a rewritten tag, which is worse for a
# detector, and no text-only rule separates the two: once the tag is rewritten
# the line no longer carries what wrote it. Three more cases are open. A
# journald `MESSAGE=` record is read whatever its SYSLOG_IDENTIFIER says; a tag
# holding a character outside the TAG class is not seen as a tag at all, so the
# line falls through untested; and an accept takes the first `from`, so an
# account that exists and whose name contains ` from <ip> port <n>`
# re-attributes its own login. Closing them needs the report to disclose how
# each line was attributed instead of assuming it.
auth_ssh_analyze() {
  local file=$1
  local assume_year="${BASHEDLOGS_ASSUME_YEAR:-$(date +%Y)}"
  local raw events kind a b c

  # Pass 1: classify events, extract validated IPs/users, stamp epochs.
  # NOTE: an RFC 5424 message may start with a UTF-8 BOM, which glues it to
  # the first word. It is passed in as bytes; awk %c is not portable past 127.
  raw=$(awk -v YEAR="$assume_year" -v BOM=$'\357\273\277' "$AWK_IP_LIB$AWK_TIME_LIB"'
    BEGIN {
      # Words sshd opens a message with, after a boundary. The last two catch
      # other message shapes that carry client text: foo_bar: and sftp verbs.
      OPENER = "([ \t\"=:]|\\[)(Failed |Accepted |Invalid user |Illegal user " \
        "|Postponed |Partial |pam_[a-z_]+\\(|PAM [0-9]|Connection |Disconnected " \
        "|Disconnecting |Received |Did not receive|User |error: |fatal: " \
        "|banner exchange|Bad protocol|Protocol major|Unable to negotiate" \
        "|reverse mapping|Address |Nasty PTR|refused connect|message repeated " \
        "|Starting session|Close session|Timeout before|drop connection" \
        "|subsystem request|debug[0-9]: |[a-z][a-z0-9]*_[a-z0-9_]*: " \
        "|[a-z][a-z-]* ((name|old) )?\")"
      # A program tag: sshd[123]:, sshd:, or the macOS compact sshd[123:456].
      # Only the [pid] forms are unambiguous on their own; a bare name: needs
      # whitespace after it, or a timestamp such as 2025-06-01T10: reads as one.
      TAG = "[ \t][A-Za-z0-9_./-]+(\\[[0-9]+\\]:|(\\[[0-9]+:[0-9]+\\]|:)[ \t])"
    }
    # A JSON string value up to its closing quote, stepping over \\ and \"
    # the way web_access does.
    function json_value(s,    m, k) {
      m = s
      gsub(/\\\\/, "__", m)
      gsub(/\\"/, "__", m)
      k = index(m, "\"")
      return (k > 0) ? substr(s, 1, k - 1) : s
    }
    # Solaris message IDs and rsyslog repeat wrappers sit before the event.
    function strip_prefix(b) {
      sub(/^[ \t]+/, "", b)
      sub(/^\[ID [0-9]+ [a-z0-9]+\.[a-z]+\] /, "", b)
      sub(/^message repeated [0-9]+ times: \[ /, "", b)
      return b
    }
    # sshd message text of the current line, or "" when it is not sshd.
    # Strings are padded with a space so a boundary never needs ^ or $.
    function msg_body(    s, k, p, pre, e, gap) {
      s = $0
      if (s ~ /^[ \t]*MESSAGE=/) {
        sub(/^[ \t]*MESSAGE=/, "", s)
        return strip_prefix(s)
      }
      if (s ~ /^[ \t]*"MESSAGE" : "/) {
        sub(/^[ \t]*"MESSAGE" : "/, "", s)
        return strip_prefix(json_value(s))
      }
      # Only on a JSON line: sshd writes a username quote as a raw quote.
      if (s ~ /^[ \t]*\{/ && match(s, /[{,]"MESSAGE":"/))
        return strip_prefix(json_value(substr(s, RSTART + RLENGTH)))
      if (s ~ /^<[0-9]+>[0-9]+ / && $4 != "-" && tolower($4) !~ /ssh/) return ""
      if (BOM != "" && (k = index(s, BOM)) > 0)
        s = substr(s, 1, k - 1) " " substr(s, k + length(BOM))
      if (!match(" " s, OPENER)) return ""
      p = RSTART
      pre = substr(s, 1, p - 1)
      if (match(" " pre " ", TAG)) {
        e = RSTART + RLENGTH - 1
        # What sits between the tag and the first word of the event decides.
        # Nothing there means the message came from sshd however the tag reads,
        # because relays, container runtimes and rsyslog templates all rewrite
        # the tag (the Docker syslog driver uses the container id). Other text
        # there means the words are quoted inside some other message.
        gap = (p > e) ? substr(s, e, p - e) : ""
        if (tolower(substr(" " pre " ", RSTART, RLENGTH)) !~ /ssh/ &&
            gap !~ /^[ \t]*(\[ID [0-9]+ [a-z0-9]+\.[a-z]+\] )?(message repeated [0-9]+ times: \[ )?$/)
          return ""
        return strip_prefix(substr(s, (e < p) ? e : p))
      }
      return strip_prefix(substr(s, p))
    }
    # Address after the last (or first) "from" token of the message.
    function from_ip(last,    i, tok) {
      tok = ""
      for (i = 1; i < bn; i++) {
        if (bt[i] == "from") {
          tok = bt[i + 1]
          if (!last) break
        }
      }
      tok = bl_clean_ip(tok)
      return bl_valid_ip(tok) ? tok : ""
    }
    function rhost_ip(    i, tok) {
      for (i = 1; i <= bn; i++) {
        if (bt[i] ~ /^rhost=/) {
          tok = bl_clean_ip(substr(bt[i], 7))
          return bl_valid_ip(tok) ? tok : ""
        }
      }
      return ""
    }
    function body_user(    i) {
      for (i = 1; i < bn; i++) {
        if (bt[i] == "for" && bt[i + 1] == "invalid" && bt[i + 2] == "user") return bt[i + 3]
        if (bt[i] == "for" && bt[i + 1] != "invalid") return bt[i + 1]
        if (bt[i] == "user" && bt[i - 1] == "Invalid") return bt[i + 1]
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
      e = line_epoch()
      body = msg_body()
      bn = split(body, bt, " ")

      # sshd credential failures: authoritative, one line per real attempt.
      if (body ~ /^Failed (password|keyboard-interactive)/) {
        sshd_fail++
        if (body ~ /^Failed [^ ]+ for (invalid user )?root /) sshd_root++
        ip = from_ip(1)
        if (ip != "") {
          sshd_fail_ip[ip]++
          user = body_user()
          if (user != "" && user != "invalid") sshd_fail_user[user]++
          if (e > 0) printf "EV\tsshd\t%d\tfail\t%s\n", e, ip
        }
        next
      }
      # PAM view of the same attempt. Tracked separately and only promoted to
      # the failure stream when the log has no sshd failure lines at all.
      if (body ~ /^pam_unix\(sshd:auth\): authentication failure/) {
        pam_fail++
        if (body ~ /user=root($| )/) pam_root++
        ip = rhost_ip()
        if (ip != "") {
          pam_fail_ip[ip]++
          user = body_user()
          if (user != "" && user != "invalid") pam_fail_user[user]++
          if (e > 0) printf "EV\tpam\t%d\tfail\t%s\n", e, ip
        }
        next
      }
      if (body ~ /^Invalid user /) {
        invalid++
        user = body_user()
        if (user != "") enum_user[user] = 1
        next
      }
      if (body ~ /^Accepted (password|publickey|keyboard-interactive)/) {
        accepted++
        user = body_user()
        if (body ~ /^Accepted password for root /) root_pw_login++
        ip = from_ip(0)
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
