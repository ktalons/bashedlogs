# shellcheck shell=bash
# ******************************************************************************
# *Title: Wazuh Alerts Analyzer*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Summarizes Wazuh alerts.json by level, rule, agent, and MITRE.*
# ******************************************************************************

# *--- Registration ---*

register_format wazuh_alerts "Wazuh alerts.json (level histogram, top rules/agents, MITRE mapping)"

# *--- Detection ---*

wazuh_alerts_detect() {
  printf '%s\n' "$SAMPLE" | awk "$AWK_JSON_LIB"'
    /^[ \t]*\{/ {
      rule = bl_jget(bl_json($0), "rule", "{")
      if (bl_jget(rule, "level", "number")) { found = 1; exit }
    }
    END { print found ? 95 : 0 }
  '
}

# *--- Analysis ---*

wazuh_alerts_analyze() {
  local file=$1
  local raw kind a b

  # shellcheck disable=SC2016  # quoted awk program
  raw=$(awk_log "$file" "$AWK_IP_LIB$AWK_JSON_LIB"'
    {
      root = bl_json($0)
      rule = bl_jget(root, "rule", "{")
      node = bl_jget(rule, "level", "number")
      if (!node || J_value[node] !~ /^([0-9]|1[0-6])$/) { skipped++; next }
      total++
      level = J_value[node] + 0
      desc = bl_jstr(rule, "description")
      if (total == 1 || level > max_level) { max_level = level; worst = desc }
      if (level >= 12) crit++
      else if (level >= 8) high++
      else if (level >= 4) mid++
      else low++

      agent = bl_jstr(bl_jget(root, "agent", "{"), "name")
      if (agent != "") agents[agent]++
      if (desc != "") rules[desc]++
      data = bl_jget(root, "data", "{")
      srcip = data ? bl_jstr(data, "srcip") : bl_jstr(root, "srcip")
      srcip = bl_normal_ip(srcip)
      if (srcip != "") srcips[srcip]++
      ts = bl_jstr(root, "timestamp")
      if (ts != "") {
        if (first_ts == "") first_ts = ts
        last_ts = ts
      }

      ids = bl_jget(bl_jget(rule, "mitre", "{"), "id", "[")
      for (i = 1; (node = bl_jget(ids, i, "")); i++) {
        t = J_value[node]
        if (J_type[node] == "string" && t ~ /^T[0-9]{4}(\.[0-9]{3})?$/) mitre[t] = 1
      }
    }
    END {
      printf "TOTAL\t%d\t-\n", total
      printf "SKIPPED\t%d\t-\n", skipped
      printf "CRIT\t%d\t-\n", crit
      printf "HIGH\t%d\t-\n", high
      printf "MID\t%d\t-\n", mid
      printf "LOW\t%d\t-\n", low
      printf "MAXLEVEL\t%d\t%s\n", max_level, bl_tsv(worst)
      if (first_ts != "") printf "FIRSTTS\t%s\t-\n", bl_tsv(first_ts)
      if (last_ts != "") printf "LASTTS\t%s\t-\n", bl_tsv(last_ts)
      for (t in mitre) printf "MITRE\t%s\n", t
      for (x in agents) printf "AGENT\t%d\t%s\n", agents[x], bl_tsv(x)
      for (x in rules) printf "RULE\t%d\t%s\n", rules[x], bl_tsv(x)
      for (x in srcips) printf "SRCIP\t%d\t%s\n", srcips[x], x
    }
  ')

  local total=0 skipped=0 crit=0 high=0 mid=0 low=0 max_level=0 worst=""
  local first_ts="" last_ts="" mitre=""
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      TOTAL) total=$a ;;
      SKIPPED) skipped=$a ;;
      CRIT) crit=$a ;;
      HIGH) high=$a ;;
      MID) mid=$a ;;
      LOW) low=$a ;;
      MAXLEVEL) max_level=$a; worst=$b ;;
      FIRSTTS) first_ts=$a ;;
      LASTTS) last_ts=$a ;;
    esac
  done < <(printf '%s\n' "$raw" | grep -Ev '^(AGENT|RULE|SRCIP|MITRE)' || true)

  report_metric "total_alerts" "$total"
  if [ "$skipped" -gt 0 ]; then report_metric "unparsed_lines" "$skipped"; fi
  report_metric "level_12_plus" "$crit"
  report_metric "level_8_to_11" "$high"
  report_metric "level_4_to_7" "$mid"
  report_metric "level_under_4" "$low"
  report_metric "max_level" "$max_level"
  if [ -n "$first_ts" ]; then
    report_metric "time_span" "$first_ts -> $last_ts"
  fi
  mitre=$(printf '%s\n' "$raw" | awk -F'\t' '$1 == "MITRE" { print $2 }' | sort | paste -sd, -)
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
