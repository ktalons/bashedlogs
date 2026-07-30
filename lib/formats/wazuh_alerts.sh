# shellcheck shell=bash
# wazuh_alerts.sh - Wazuh alerts.json (one alert object per line)
#
# Field extraction is awk string matching, not a real JSON parser, so it has to
# be path-aware: a real alert carries manager.name, agent.name AND decoder.name,
# and a bare search for "name" finds the manager on every line - which silently
# attributed every alert to the Wazuh server instead of the affected host.
# Values are read from within the parent object, and quote scanning respects
# backslash escapes so a description containing \" is not truncated.

register_format wazuh_alerts "Wazuh alerts.json (level histogram, top rules/agents, MITRE mapping)"

wazuh_alerts_detect() {
  local first
  first=$(printf '%s\n' "$SAMPLE" | head -1)
  case "$first" in
    '{'*'"rule"'*'"level"'*) echo 95 ;;
    '{'*'"agent"'*'"rule"'*) echo 80 ;;
    *) echo 0 ;;
  esac
}

wazuh_alerts_analyze() {
  local file=$1
  local raw kind a b

  raw=$(awk "$AWK_IP_LIB"'
    # Read a quoted string value, honoring backslash escapes, so a value like
    # "user said \"hi\"" is returned whole instead of cut at the first \".
    function jstr(line, key,    pat, pos, i, c, out, esc) {
      pat = "\"" key "\":\""
      pos = index(line, pat)
      if (pos == 0) return ""
      i = pos + length(pat)
      out = ""
      esc = 0
      while (i <= length(line)) {
        c = substr(line, i, 1)
        if (esc) {
          # keep the escaped character as-is (\" -> ", \\ -> \)
          out = out c
          esc = 0
        } else if (c == "\\") {
          esc = 1
        } else if (c == "\"") {
          return out
        } else {
          out = out c
        }
        i++
      }
      return out
    }
    function jnum(line, key,    pat, pos, v) {
      pat = "\"" key "\":"
      pos = index(line, pat)
      if (pos == 0) return -1
      v = substr(line, pos + length(pat))
      if (v !~ /^[0-9]/) return -1
      sub(/[^0-9].*$/, "", v)
      return v + 0
    }
    # Return the substring of the object named by key, brace-balanced, so
    # nested lookups cannot leak into a sibling object.
    function jobj(line, key,    pat, pos, i, depth, c, start, instr, esc) {
      pat = "\"" key "\":{"
      pos = index(line, pat)
      if (pos == 0) return ""
      start = pos + length(pat) - 1
      depth = 0; instr = 0; esc = 0
      for (i = start; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (instr) {
          if (esc) esc = 0
          else if (c == "\\") esc = 1
          else if (c == "\"") instr = 0
          continue
        }
        if (c == "\"") { instr = 1; continue }
        if (c == "{") depth++
        else if (c == "}") {
          depth--
          if (depth == 0) return substr(line, start, i - start + 1)
        }
      }
      return ""
    }
    /^\{/ {
      total++
      rule = jobj($0, "rule")
      if (rule == "") rule = $0
      level = jnum(rule, "level")
      desc = jstr(rule, "description")
      if (level >= 0) {
        if (level > max_level) { max_level = level; worst = desc }
        if (level >= 12) crit++
        else if (level >= 8) high++
        else if (level >= 4) mid++
        else low++
      }
      # agent.name specifically - manager.name and decoder.name also exist.
      agentobj = jobj($0, "agent")
      agent = (agentobj != "") ? jstr(agentobj, "name") : ""
      if (agent != "") agents[agent]++
      if (desc != "") { rules[desc]++ }
      dataobj = jobj($0, "data")
      srcip = (dataobj != "") ? jstr(dataobj, "srcip") : jstr($0, "srcip")
      srcip = bl_clean_ip(srcip)
      if (srcip != "" && bl_valid_ip(srcip)) srcips[srcip]++
      if (first_ts == "") first_ts = jstr($0, "timestamp")
      last_ts = jstr($0, "timestamp")
      # MITRE technique ids appear as "id":["T1110",...] inside rule.mitre
      line = $0
      while (match(line, /T1[0-9][0-9][0-9][0-9]?(\.[0-9][0-9][0-9])?/)) {
        mitre[substr(line, RSTART, RLENGTH)] = 1
        line = substr(line, RSTART + RLENGTH)
      }
    }
    END {
      printf "TOTAL\t%d\t-\n", total
      printf "CRIT\t%d\t-\n", crit
      printf "HIGH\t%d\t-\n", high
      printf "MID\t%d\t-\n", mid
      printf "LOW\t%d\t-\n", low
      printf "MAXLEVEL\t%d\t%s\n", max_level, bl_tsv(worst)
      if (first_ts != "") printf "FIRSTTS\t%s\t-\n", first_ts
      if (last_ts != "") printf "LASTTS\t%s\t-\n", last_ts
      m = ""
      for (t in mitre) m = (m == "" ? t : m "," t)
      if (m != "") printf "MITRE\t%s\t-\n", m
      for (x in agents) printf "AGENT\t%d\t%s\n", agents[x], bl_tsv(x)
      for (x in rules) printf "RULE\t%d\t%s\n", rules[x], bl_tsv(x)
      for (x in srcips) printf "SRCIP\t%d\t%s\n", srcips[x], x
    }
  ' "$file")

  local total=0 crit=0 high=0 mid=0 low=0 max_level=0 worst=""
  local first_ts="" last_ts="" mitre=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      CRIT) crit=$a ;;
      HIGH) high=$a ;;
      MID) mid=$a ;;
      LOW) low=$a ;;
      MAXLEVEL) max_level=$a; worst=$b ;;
      FIRSTTS) first_ts=$a ;;
      LASTTS) last_ts=$a ;;
      MITRE) mitre=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -Ev '^(AGENT|RULE|SRCIP)' || true)

  report_metric "total_alerts" "$total"
  report_metric "level_12_plus" "$crit"
  report_metric "level_8_to_11" "$high"
  report_metric "level_4_to_7" "$mid"
  report_metric "level_under_4" "$low"
  report_metric "max_level" "$max_level"
  if [ -n "$first_ts" ]; then
    report_metric "time_span" "$first_ts -> $last_ts"
  fi
  if [ -n "$mitre" ]; then
    report_metric "mitre_techniques" "$mitre"
  fi

  local list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^AGENT' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_agents" "$list"
  fi

  list=""
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ -n "$list" ]; then list="$list, "; fi
    list="$list$b ($a)"
  done < <(printf '%s\n' "$raw" | grep '^RULE' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -5 || true)
  if [ -n "$list" ]; then
    report_metric "top_rules" "$list"
  fi

  if [ "$crit" -gt 0 ]; then
    report_add critical wazuh-critical \
      "$crit alert(s) at level 12+ (worst: level $max_level, '$worst')" \
      "count=$crit" "max_level=$max_level"
  fi
  if [ "$high" -gt 0 ]; then
    report_add high wazuh-high \
      "$high alert(s) at level 8-11" "count=$high"
  fi

  # A source IP concentrating many alerts is worth a look on its own.
  while IFS=$'\t' read -r kind a b; do
    if [ -z "$kind" ]; then continue; fi
    if [ "$a" -ge 10 ]; then
      report_add high alert-cluster \
        "$a alert(s) involve source IP $b" "ip=$b" "count=$a"
    fi
  done < <(printf '%s\n' "$raw" | grep '^SRCIP' | sort -t "$(printf '\t')" -k2,2rn -k3,3 | head -3 || true)
}
