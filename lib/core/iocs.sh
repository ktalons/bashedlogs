# shellcheck shell=bash
# ******************************************************************************
# *Title: IOC Extraction*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Extracts IOCs from log content and defangs them on request.*
# ******************************************************************************

# Domain matching is heuristic: token shape + a file-extension blocklist,
# because a full TLD list would break the zero-dependency rule.

# *--- State ---*

IOC_IPS=()
IOC_DOMAINS=()
IOC_URLS=()
IOC_MD5=()
IOC_SHA1=()
IOC_SHA256=()

# *--- Extraction ---*

extract_iocs() {
  local file=$1 kind value rows
  # shellcheck disable=SC2016  # quoted awk program
  rows=$(awk_log "$file" "$AWK_IP_LIB"'
    function emit_ip(t) {
      t = bl_normal_ip(t)
      if (t == "") return 0
      if (!(("ip" SUBSEP t) in seen)) { seen["ip", t] = 1; printf "IP\t%s\n", t }
      return 1
    }
    function is_ext(tld) {
      return index(",php,html,htm,log,txt,json,xml,zip,bak,css,js,ico,png,jpg,jpeg,gif,svg,md,gz,tar,conf,cfg,ini,py,sh,pl,rb,service,socket,timer,mount,target,local,localdomain,internal,lan,arpa,",
                   "," tld ",") > 0
    }
    {
      # URLs first (full tokens); their hostname is also emitted as a domain
      # so analysts can pivot on the host without re-parsing the URL.
      line = $0
      while (match(line, /[Hh][Tt][Tt][Pp][Ss]?:\/\/[^[:space:]"'\''<>)]+/)) {
        u = substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)
        sub(/[.,;]+$/, "", u)
        if (!(u in seen)) { seen[u] = 1; printf "URL\t%s\n", u }
        h = tolower(u)
        sub(/^https?:\/\//, "", h)
        sub(/[\/?#].*$/, "", h)
        sub(/^[^@]*@/, "", h)
        if (emit_ip(h)) continue
        sub(/:[0-9]+$/, "", h)
        if (h ~ /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/) {
          if (!(("d" SUBSEP h) in seen)) { seen["d", h] = 1; printf "DOM\t%s\n", h }
        }
      }
      # then word-ish tokens
      n = split(tolower($0), toks, /[^a-z0-9._:%\/-]+/)
      for (i = 1; i <= n; i++) {
        t = toks[i]
        gsub(/^[._\/-]+|[._\/-]+$/, "", t)
        if (t == "") continue
        if (emit_ip(t)) continue
        gsub(/^:+|:+$/, "", t)
        if (t == "") continue
        if (t ~ /^[0-9a-f]+$/) {
          if (length(t) == 32 && !(("m" SUBSEP t) in seen)) { seen["m", t] = 1; printf "MD5\t%s\n", t }
          else if (length(t) == 40 && !(("s1" SUBSEP t) in seen)) { seen["s1", t] = 1; printf "SHA1\t%s\n", t }
          else if (length(t) == 64 && !(("s2" SUBSEP t) in seen)) { seen["s2", t] = 1; printf "SHA256\t%s\n", t }
          continue
        }
        if (t ~ /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/ && t !~ /\//) {
          m = split(t, labels, ".")
          tld = labels[m]
          if (length(tld) >= 2 && !is_ext(tld) && tld !~ /^[0-9]/) {
            if (!(("d" SUBSEP t) in seen)) { seen["d", t] = 1; printf "DOM\t%s\n", t }
          }
        }
      }
    }
  ' | sort -t "$(printf '\t')" -k1,1 -k2,2)
  while IFS=$'\t' read -r kind value; do
    case "$kind" in
      IP) IOC_IPS+=("$value") ;;
      DOM) IOC_DOMAINS+=("$value") ;;
      URL) IOC_URLS+=("$value") ;;
      MD5) IOC_MD5+=("$value") ;;
      SHA1) IOC_SHA1+=("$value") ;;
      SHA256) IOC_SHA256+=("$value") ;;
    esac
  done <<< "$rows"
}

# *--- Output Helpers ---*

# Defang dots, HTTP schemes and colons in standalone IPv6 addresses.
maybe_defang() {
  local v=$1
  if [ "$DEFANG" -eq 1 ]; then
    case $v in
      [Hh][Tt][Tt][Pp]://*) v=hxxp://${v:7} ;;
      [Hh][Tt][Tt][Pp][Ss]://*) v=hxxps://${v:8} ;;
      *:*) v=${v//:/[:]} ;;
    esac
    v=${v//./[.]}
  fi
  printf '%s' "$v"
}

ioc_total() {
  echo $(( ${#IOC_IPS[@]} + ${#IOC_DOMAINS[@]} + ${#IOC_URLS[@]} \
        + ${#IOC_MD5[@]} + ${#IOC_SHA1[@]} + ${#IOC_SHA256[@]} ))
}
