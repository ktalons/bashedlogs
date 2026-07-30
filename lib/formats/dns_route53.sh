# shellcheck shell=bash
# dns_route53.sh - AWS Route53 resolver query logs
# Line shape: version date hosted-zone qname qtype rcode proto edge resolver-ip [edns]
# Tunneling heuristics are length/volume based and labeled as heuristics.

register_format dns_route53 "Route53 DNS query logs (NXDOMAIN rate, tunneling heuristics)"

dns_route53_detect() {
  local hits
  hits=$(printf '%s\n' "$SAMPLE" \
    | grep -cE '^1\.[0-9] [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z? [A-Z0-9]+ [^ ]+ [A-Z]+ [A-Z]+ (UDP|TCP) ' || true)
  if [ "$hits" -ge 2 ]; then
    echo 90
  elif [ "$hits" -ge 1 ]; then
    echo 60
  else
    echo 0
  fi
}

dns_route53_analyze() {
  local file=$1
  local raw kind a b

  raw=$(awk '
    {
      total++
      if (first_ts == "") first_ts = $2
      last_ts = $2
      qname = tolower($4)
      sub(/\.$/, "", qname)
      qnames[qname]++
      qtype[$5]++
      rcode[$6]++
      resolvers[$9]++
      if ($6 == "NXDOMAIN") nx++
      if (length(qname) > 60) { long_q++; if (long_ex == "") long_ex = qname }
      # parent domain = qname minus its first label; child growth per parent
      # is the classic tunneling shape
      p = qname
      if (index(p, ".") > 0) {
        sub(/^[^.]+\./, "", p)
        key = p SUBSEP qname
        if (!(key in seen_child)) { seen_child[key] = 1; children[p]++ }
      }
    }
    END {
      printf "TOTAL\t%d\t-\n", total
      printf "NX\t%d\t-\n", nx
      printf "LONGQ\t%d\t%s\n", long_q, long_ex
      printf "TXT\t%d\t-\n", qtype["TXT"]
      if (first_ts != "") printf "FIRSTTS\t%s\t-\n", first_ts
      if (last_ts != "") printf "LASTTS\t%s\t-\n", last_ts
      nq = 0; for (q in qnames) nq++
      printf "UNIQQ\t%d\t-\n", nq
      nr = 0; for (r in resolvers) nr++
      printf "UNIQRES\t%d\t-\n", nr
      for (q in qnames) printf "QNAME\t%d\t%s\n", qnames[q], q
      for (t in qtype) printf "QTYPE\t%d\t%s\n", qtype[t], t
      for (p in children) printf "CHILDREN\t%d\t%s\n", children[p], p
    }
  ' "$file")

  local total=0 nx=0 long_q=0 long_ex="" txt=0 uniq_q=0 uniq_res=0
  local first_ts="" last_ts=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      NX) nx=$a ;;
      LONGQ) long_q=$a; long_ex=$b ;;
      TXT) txt=$a ;;
      UNIQQ) uniq_q=$a ;;
      UNIQRES) uniq_res=$a ;;
      FIRSTTS) first_ts=$a ;;
      LASTTS) last_ts=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -Ev '^(QNAME|QTYPE|CHILDREN)' || true)

  report_metric "total_queries" "$total"
  report_metric "unique_names" "$uniq_q"
  report_metric "nxdomain" "$nx"
  report_metric "unique_resolvers" "$uniq_res"
  if [ -n "$first_ts" ]; then
    report_metric "time_span" "$first_ts -> $last_ts"
  fi

  local list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^QNAME' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_names" "$list"
  fi

  list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^QTYPE' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "query_types" "$list"
  fi

  if [ "$long_q" -gt 0 ]; then
    report_add high dns-tunneling-length \
      "$long_q quer(ies) with names over 60 chars (tunneling indicator)" \
      "count=$long_q" "example=$long_ex"
  fi

  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ "$a" -ge 30 ]; then
      report_add high dns-tunneling-subdomains \
        "$a unique subdomains under $b (tunneling/DGA indicator)" \
        "parent=$b" "unique_children=$a"
    fi
  done < <(printf '%s\n' "$raw" | grep '^CHILDREN' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -3 || true)

  if [ "$total" -ge 20 ] && [ "$nx" -gt 0 ] && [ $((nx * 5)) -ge "$total" ]; then
    report_add medium nxdomain-rate \
      "high NXDOMAIN rate: $nx of $total queries (DGA/typo indicator)" \
      "nxdomain=$nx" "total=$total"
  fi
  if [ "$total" -ge 10 ] && [ "$txt" -gt 0 ] && [ $((txt * 7)) -ge "$total" ]; then
    report_add medium txt-share \
      "TXT queries are ${txt} of ${total} (tunneling channel indicator)" \
      "txt=$txt" "total=$total"
  fi
}
