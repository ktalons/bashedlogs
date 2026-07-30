# shellcheck shell=bash
# iocs.sh - IOC extraction (--iocs) and defanging (--defang)
# Domain matching is heuristic: token shape + a file-extension blocklist,
# because a full TLD list would break the zero-dependency rule.

IOC_IPS=()
IOC_DOMAINS=()
IOC_URLS=()
IOC_MD5=()
IOC_SHA1=()
IOC_SHA256=()

extract_iocs() {
  local file=$1 kind value

  while IFS=$'\t' read -r kind value; do
    case "$kind" in
      IP) IOC_IPS+=("$value") ;;
      DOM) IOC_DOMAINS+=("$value") ;;
      URL) IOC_URLS+=("$value") ;;
      MD5) IOC_MD5+=("$value") ;;
      SHA1) IOC_SHA1+=("$value") ;;
      SHA256) IOC_SHA256+=("$value") ;;
    esac
  done < <(awk '
    function valid_ip(tok,    parts, j) {
      if (tok !~ /^([0-9]+\.){3}[0-9]+$/) return 0
      split(tok, parts, ".")
      for (j = 1; j <= 4; j++) {
        if (length(parts[j]) > 3 || parts[j] + 0 > 255) return 0
      }
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
      while (match(line, /https?:\/\/[^ "'\''<>)\]]+/)) {
        u = substr(line, RSTART, RLENGTH)
        sub(/[.,;:]+$/, "", u)
        if (!(u in seen)) { seen[u] = 1; printf "URL\t%s\n", u }
        h = tolower(u)
        sub(/^https?:\/\//, "", h)
        sub(/[\/?#].*$/, "", h)
        sub(/^[^@]*@/, "", h)
        sub(/:[0-9]+$/, "", h)
        if (h ~ /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/) {
          if (!(("d" SUBSEP h) in seen)) { seen["d", h] = 1; printf "DOM\t%s\n", h }
        }
        line = substr(line, RSTART + RLENGTH)
      }
      # then word-ish tokens
      n = split(tolower($0), toks, /[^a-z0-9._:\/-]+/)
      for (i = 1; i <= n; i++) {
        t = toks[i]
        gsub(/^[._:\/-]+|[._:\/-]+$/, "", t)
        if (t == "") continue
        if (valid_ip(t)) {
          if (!(("ip" SUBSEP t) in seen)) { seen["ip", t] = 1; printf "IP\t%s\n", t }
          continue
        }
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
  ' "$file" | sort -t "$(printf '\t')" -k1,1 -k2,2)
}

# maybe_defang <value>: dots -> [.] and http -> hxxp when --defang is on.
maybe_defang() {
  local v=$1
  if [ "$DEFANG" -eq 1 ]; then
    v=${v//http:\/\//hxxp://}
    v=${v//https:\/\//hxxps://}
    v=${v//./[.]}
  fi
  printf '%s' "$v"
}

ioc_total() {
  echo $(( ${#IOC_IPS[@]} + ${#IOC_DOMAINS[@]} + ${#IOC_URLS[@]} \
        + ${#IOC_MD5[@]} + ${#IOC_SHA1[@]} + ${#IOC_SHA256[@]} ))
}
