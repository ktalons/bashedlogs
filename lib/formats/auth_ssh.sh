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

# *--- Shared Record Parsing ---*

# shellcheck disable=SC2034  # interpolated into the analyzer and detector
SSH_RECORD_AWK='
function ssh_name(s) { return s ~ /^(sshd(-session|-auth)?|openssh-server)$/ }

function ssh_prefix(s,    size) {
  while (length(s) != size) {
    size = length(s)
    sub(/^[ \t]+/, "", s)
    sub(/^\[ID [0-9]+ [a-z0-9]+\.[a-z]+\] /, "", s)
    sub(/^message repeated [0-9]+ times: \[ /, "", s)
  }
  if (index(s, BOM) == 1) s = substr(s, length(BOM) + 1)
  return s
}

# Escaped quotes and brackets within an RFC 5424 parameter cannot end the
# structured data or begin the message.
function ssh_rfc5424_msg(s,    i, c, quoted) {
  if (s ~ /^- /) return substr(s, 3)
  if (substr(s, 1, 1) != "[") return ""
  for (i = 2; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (quoted && c == "\\") { i++; continue }
    if (c == "\"") quoted = !quoted
    if (!quoted && c == "]") {
      if (substr(s, i + 1, 1) == " ") return substr(s, i + 2)
      if (substr(s, i + 1, 1) != "[") return ""
      i++
    }
  }
  return ""
}

function ssh_record(line,    s, h, tag, ts, root, ident, e) {
  ssh_host = ""; ssh_named = 0; ssh_epoch = -1; ssh_ts = ""
  sub(/\r$/, "", line)
  s = line
  if (s ~ /^[ \t]*\{/) {
    root = bl_json(s)
    if (!root) return ""
    ident = bl_jstr(root, "_COMM")
    if (ident == "") ident = bl_jstr(root, "SYSLOG_IDENTIFIER")
    if (ident != "" && !ssh_name(ident)) return ""
    ssh_named = ssh_name(ident)
    ssh_host = bl_jstr(root, "_HOSTNAME")
    ts = bl_jstr(root, "__REALTIME_TIMESTAMP")
    if (ts ~ /^[0-9]{1,16}$/) ssh_epoch = ts / 1000000
    ssh_ts = ssh_epoch >= 0 ? sprintf("%.6f", ssh_epoch) : ""
    return ssh_prefix(bl_jstr(root, "MESSAGE"))
  }
  if (s ~ /^[ \t]*MESSAGE=/) {
    sub(/^[ \t]*MESSAGE=/, "", s)
    return ssh_prefix(s)
  }
  if (match(s, /^<[0-9]{1,3}>[1-9][0-9]{0,2} [^ ]+ [^ ]+ [^ ]+ [^ ]+ [^ ]+ /)) {
    split(substr(s, 1, RLENGTH), h, " ")
    s = substr(s, RLENGTH + 1)
    ssh_named = ssh_name(h[4])
    ssh_host = h[3] == "-" ? "" : h[3]
    ssh_ts = h[2] == "-" ? "" : h[2]
    ssh_epoch = bl_iso_epoch(h[2])
    return ssh_prefix(ssh_rfc5424_msg(s))
  }
  sub(/^<[0-9]{1,3}>/, "", s)
  if (match(s, /^[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}[ \t]+/)) {
    ssh_ts = substr(s, 1, RLENGTH - 1)
    split(ssh_ts, h, " ")
    s = substr(s, RLENGTH + 1)
    e = bl_syslog_epoch(h[1], h[2], h[3], YEAR + year_wrap)
    if (e >= 0 && prev_e > 0 && e + 15552000 < prev_e) {
      year_wrap++
      e = bl_syslog_epoch(h[1], h[2], h[3], YEAR + year_wrap)
    }
    if (e >= 0) prev_e = e
    ssh_epoch = e
  } else if (match(s, /^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][^ \t]+[ \t]+/)) {
    ssh_ts = substr(s, 1, RLENGTH - 1)
    sub(/[ \t]+$/, "", ssh_ts)
    s = substr(s, RLENGTH + 1)
    ssh_epoch = bl_iso_epoch(ssh_ts)
  } else return ssh_prefix(s)

  # A syslog exporter can omit the hostname. Use the tag after the timestamp
  # or after the hostname, then keep the full message at that boundary.
  if (s !~ /^[^ \t]+(\]:|:[ \t])/ && match(s, /^[^ \t]+[ \t]+/)) {
    ssh_host = substr(s, 1, RLENGTH)
    sub(/[ \t]+$/, "", ssh_host)
    s = substr(s, RLENGTH + 1)
  }
  if (match(s, /^[^ \t:\[]+(\[[0-9]+(:[0-9]+)?\]:?|:)/)) {
    tag = substr(s, 1, RLENGTH)
    # NOTE: (\[|:), not [\[:]. In a bracket expression "[:" opens a class
    # name, and busybox awk rejects the pattern outright.
    sub(/(\[|:).*$/, "", tag)
    ssh_named = ssh_name(tag)
    s = substr(s, RLENGTH + 1)
  } else return ""
  return ssh_prefix(s)
}

function ssh_event(s) {
  return s ~ /^(Failed |Accepted |Invalid user |pam_unix\(sshd(-session|-auth)?:)/
}
'

# *--- Detection ---*

auth_ssh_detect() {
  # Journal JSON gets its own analyzer. For SSH correlation on that export,
  # select the auth analyzer explicitly.
  printf '%s\n' "$SAMPLE" | awk -v YEAR=2000 -v BOM=$'\357\273\277' \
    "$AWK_TIME_LIB$AWK_JSON_LIB$SSH_RECORD_AWK"'
    /^[ \t]*\{/ { next }
    {
      if (ssh_event(ssh_record($0))) hits++
      if (ssh_named) {
        named++
        if ($0 !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/) named_non_iso++
      }
    }
    END { print (named >= 3 ? 95 : named_non_iso ? 80 : hits >= 3 ? 85 : hits ? 65 : 0) }
  '
}

# *--- Analysis ---*

# Text logs can lose the original program name in a relay. Position-based
# events still contribute to metrics and brute-force findings. A successful
# login warning requires a recognized producer and an unambiguous peer.
auth_ssh_analyze() {
  local file=$1
  local assume_year raw events kind a b c
  assume_year=$(date +%Y)
  assume_year=${BASHEDLOGS_ASSUME_YEAR:-$assume_year}
  if [[ ! $assume_year =~ ^[0-9]{4}$ ]] || (( 10#$assume_year < 1970 )); then
    die_usage "BASHEDLOGS_ASSUME_YEAR needs a year from 1970 to 9999"
  fi

  # shellcheck disable=SC2016  # quoted awk program
  raw=$(awk_log "$file" -v YEAR="$assume_year" -v BOM=$'\357\273\277' \
    -v NAMED_ONLY="$SSH_NAMED_ONLY" "$AWK_IP_LIB$AWK_TIME_LIB$AWK_JSON_LIB$SSH_RECORD_AWK"'
    # An accepted login with two valid peer clauses is ambiguous. A username
    # or certificate key ID can contain an entire lookalike clause.
    function peer(s, last,    rest, fields, tok, count, pos, len, chosen) {
      rest = s
      peer_user = ""
      # NOTE: "]" leads the set. A backslash is literal inside brackets in
      # POSIX, so busybox read [: \t\]] as a set and then a required "]".
      while (match(rest, / from [^ \t]+ port [0-9]+ ssh[12]([]: \t]|$)/)) {
        pos = RSTART; len = RLENGTH
        split(substr(rest, pos + 1, len - 1), fields, " ")
        tok = bl_normal_ip(fields[2])
        if (tok != "" && fields[4] + 0 <= 65535) {
          count++
          chosen = tok
          if (count == 1 || last) {
            peer_user = substr(s, 1, length(s) - length(rest) + pos - 1)
            sub(/^[^ ]+ [^ ]+ for (invalid user )?/, "", peer_user)
          }
        }
        rest = substr(rest, pos + len - 1)
      }
      return count && (last || count == 1) ? chosen : ""
    }

    function ssh_ev(kind, stream, user) {
      if (ssh_epoch < 0) { unparsed_time++; return }
      printf "EV\t%s\t%.6f\t%d\t%s\t%s\t%s\t%d\t%s\n",
        stream, ssh_epoch, NR, kind, ip, host, ssh_named, bl_tsv(user)
    }

    {
      total++
      body = ssh_record($0)
      if (ssh_ts != "") {
        if (first_ts == "") first_ts = bl_tsv(ssh_ts)
        last_ts = bl_tsv(ssh_ts)
      }
      if (NAMED_ONLY && !ssh_named) next
      host = bl_tsv(tolower(ssh_host))
      gsub(SUBSEP, " ", host)
      if (ssh_event(body)) {
        if (ssh_named) named_events++
        else position_events++
      }

      if (body ~ /^Failed (password|keyboard-interactive[^ ]*) for /) {
        failures["sshd", host]++
        native_host[host] = 1
        ip = peer(body, 1)
        if (ip == "") { unparsed_peer++; next }
        split(peer_user, users, " ")
        user = users[1]
        if (peer_user == "root") roots["sshd", host]++
        failure_ips["sshd", host, ip]++
        if (user != "" && user != "invalid") failure_users["sshd", host, user]++
        ssh_ev("fail", "sshd", "")
        next
      }
      if (body ~ /^pam_unix\(sshd(-session|-auth)?:auth\): authentication failure/) {
        failures["pam", host]++
        # Read the first real rhost field before looking at user content.
        ip = ""; user = ""
        if (match(body, / rhost=[^ \t]*/)) {
          user = substr(body, RSTART + RLENGTH)
          if (user !~ /^[ \t]+user=/) user = ""
          else sub(/^[ \t]+user=/, "", user)
          ip = bl_normal_ip(substr(body, RSTART + 7, RLENGTH - 7))
          if (user == "root") roots["pam", host]++
        }
        if (ip == "") { unparsed_peer++; next }
        failure_ips["pam", host, ip]++
        if (user != "") {
          split(user, users, " ")
          failure_users["pam", host, users[1]]++
        }
        ssh_ev("fail", "pam", "")
        next
      }
      if (body ~ /^Invalid user /) {
        invalid++
        split(body, users, " ")
        if (users[3] != "") enum_user[users[3]] = 1
        next
      }
      if (body ~ /^Accepted (password|publickey|keyboard-interactive[^ ]*) for /) {
        accepted++
        ip = peer(body, 0)
        if (ip == "") { unparsed_peer++; next }
        if (ssh_named && body ~ /^Accepted password / && peer_user == "root") root_pw_login++
        if (ssh_named) ssh_ev("accept", "both", peer_user)
        next
      }
      if (body ~ /^Failed (publickey|none) |^Did not receive identification|^Connection (closed|reset) by .*preauth|^Received disconnect/) probes++
      if (body ~ /^pam_unix\(sshd(-session|-auth)?:session\): session opened/) sess_open++
      if (body ~ /^pam_unix\(sshd(-session|-auth)?:session\): session closed/) sess_close++
    }
    END {
      # Choose native failures independently per host, so a native record
      # from one machine cannot erase a PAM-only stream from another.
      for (h in native_host) printf "NATIVE\t%s\n", h
      for (key in failures) {
        split(key, parts, SUBSEP)
        if (parts[1] == "pam" && parts[2] in native_host) {
          pam_dupes += failures[key]
        } else {
          source[parts[1]] = 1
          failed += failures[key]
          root_attempts += roots[key]
        }
      }
      for (key in failure_ips) {
        split(key, parts, SUBSEP)
        if (parts[1] != "pam" || !(parts[2] in native_host))
          by_ip[parts[3]] += failure_ips[key]
      }
      for (key in failure_users) {
        split(key, parts, SUBSEP)
        if (parts[1] != "pam" || !(parts[2] in native_host))
          by_user[parts[3]] += failure_users[key]
      }
      stream = ("pam" in source) ? (("sshd" in source) ? "mixed" : "pam") : "sshd"
      printf "SOURCE\t%s\n", stream
      printf "TOTAL\t%d\n", total
      printf "NAMED\t%d\n", named_events
      printf "POSITION\t%d\n", position_events
      printf "NOTIME\t%d\n", unparsed_time
      printf "NOPEER\t%d\n", unparsed_peer
      printf "FAILED\t%d\n", failed
      printf "PAMDUPES\t%d\n", pam_dupes
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
      for (x in by_ip) printf "FIP\t%d\t%s\n", by_ip[x], x
      for (x in by_user) printf "FUSER\t%d\t%s\n", by_user[x], bl_tsv(x)
    }
  ')

  local total=0 failed=0 invalid=0 accepted=0 root_attempts=0 root_pw=0
  local probes=0 sess_open=0 sess_close=0 enum_users=0 first_ts="" last_ts=""
  local source="sshd" pam_dupes=0
  local named=0 position=0 no_time=0 no_peer=0
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      SOURCE) source=$a ;;
      PAMDUPES) pam_dupes=$a ;;
      TOTAL) total=$a ;;
      NAMED) named=$a ;;
      POSITION) position=$a ;;
      NOPEER) no_peer=$a ;;
      NOTIME) no_time=$a ;;
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
  done < <(printf '%s\n' "$raw" | grep -Ev '^(EV|FIP|FUSER|NATIVE)' || true)

  # Pass 2: per-IP sliding window over the time-sorted failure stream, plus
  # the compromise heuristic (an accept from the same IP soon after a burst).
  # Only events from the authoritative source feed the window, so a log that
  # carries both sshd and PAM lines for one attempt cannot double-count.
  # Fields: EV <source> <epoch> <line> <kind> <ip> <host> <named> [user]
  events=$(printf '%s\n' "$raw" | awk -F'\t' '$1 == "EV" || $1 == "NATIVE"' \
    | sort -t "$(printf '\t')" -k1,1r -k3,3n -k4,4n)
  local windows=""
  if [ -n "$events" ]; then
    windows=$(printf '%s\n' "$events" | awk -F'\t' \
      -v W="$BF_WINDOW" -v T="$BF_THRESHOLD" '
      $1 == "NATIVE" { native[$2] = 1; next }
      $5 == "fail" {
        if ($2 == "pam" && $7 in native) next
        t = $3 + 0
        k = $6 SUBSEP $7
        ip[k] = $6; host[k] = $7
        idx = ++tail[k]
        q[k, idx] = t
        named[k, idx] = $8 + 0
        named_count[k] += named[k, idx]
        while (head[k] < tail[k] && q[k, head[k] + 1] <= t - W) {
          idx = ++head[k]
          named_count[k] -= named[k, idx]
          delete q[k, idx]
          delete named[k, idx]
        }
        size = tail[k] - head[k]
        if (size >= T && size > burst_n[k]) {
          burst_n[k] = size
          burst_span[k] = t - q[k, head[k] + 1]
          burst_named[k] = named_count[k]
        }
        if ($8 && named_count[k] >= T) named_burst[k] = t
      }
      $5 == "accept" {
        t = $3 + 0
        k = $6 SUBSEP $7
        if ((k in named_burst) && t - named_burst[k] <= 600) comp_user[k] = $9
      }
      END {
        for (k in burst_n)
          printf "BURST\t%d\t%s\t%.6f\t%d\t%s\n", burst_n[k], ip[k], burst_span[k], burst_named[k], host[k]
        for (k in comp_user)
          printf "COMPROMISE\t%s\t%s\t%s\n", ip[k], comp_user[k], host[k]
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
  report_metric "named_ssh_events" "$named"
  report_metric "position_only_ssh_events" "$position"
  if [ "$no_time" -gt 0 ]; then report_metric "ssh_events_without_time" "$no_time"; fi
  if [ "$no_peer" -gt 0 ]; then report_metric "ssh_events_without_peer" "$no_peer"; fi
  report_metric "sessions_opened" "$sess_open"
  report_metric "sessions_closed" "$sess_close"
  report_metric "probes_preauth" "$probes"
  if [ -n "$first_ts" ]; then
    report_metric "time_span" "$first_ts -> $last_ts"
  fi

  # Top attacking IPs (count desc, IP asc), max 5, from validated counts.
  local top=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$top" ]; then top="$top, "; fi
    top="$top$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^FIP' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$top" ]; then
    report_metric "top_attacking_ips" "$top"
  fi

  local tusers=""
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
    local d host span
    while IFS=$'\t' read -r kind a b c d host; do
      case "$kind" in
        COMPROMISE)
          report_add critical possible-compromise \
            "successful login for '$b' from $a shortly after an SSH brute-force burst on the same host" \
            "ip=$a" "user=$b" "host=$c"
          ;;
        BURST)
          span=${c%"${c##*[!0]}"}
          span=${span%.}
          report_add high brute-force \
            "$a failed logins from $b within ${span}s (threshold: $BF_THRESHOLD in ${BF_WINDOW}s)" \
            "ip=$b" "count=$a" "burst_seconds=$span" "named_events=$d" "host=$host"
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
