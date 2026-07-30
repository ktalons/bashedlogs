# shellcheck shell=bash
# report.sh - finding and metric accumulation, severity model, threat score
# Sourced by bin/bashedlogs. Pure functions + module state; no side effects on load.

# Findings: parallel arrays, one entry per finding.
R_SEV=()  # severity: info|low|medium|high|critical
R_CAT=()  # short category slug, e.g. brute-force
R_MSG=()  # human message
R_KV=()   # tab-separated key=value pairs (may be empty)

# Metrics: ordered key/value pairs for the stats section.
M_KEY=()
M_VAL=()

# Map severity name to rank (for --fail-level comparison) and weight (score).
sev_rank() {
  case "$1" in
    info) echo 0 ;;
    low) echo 1 ;;
    medium) echo 2 ;;
    high) echo 3 ;;
    critical) echo 4 ;;
    *) echo -1 ;;
  esac
}

sev_weight() {
  case "$1" in
    low) echo 1 ;;
    medium) echo 3 ;;
    high) echo 7 ;;
    critical) echo 15 ;;
    *) echo 0 ;;
  esac
}

# report_add <severity> <category> <message> [key=value ...]
#
# Pairs are stored tab-separated, so a literal tab arriving from log content
# (a URL or user agent can contain one) would split into a bogus extra pair.
# Tabs are folded to spaces at this single choke point instead.
report_add() {
  local sev=$1 cat=$2 msg=$3
  shift 3
  if [ "$(sev_rank "$sev")" = "-1" ]; then
    echo "bashedlogs: internal error: bad severity '$sev'" >&2
    exit 1
  fi
  local kv="" pair
  for pair in "$@"; do
    pair=${pair//$'\t'/ }
    if [ -z "$kv" ]; then kv=$pair; else kv=$kv$'\t'$pair; fi
  done
  msg=${msg//$'\t'/ }
  R_SEV+=("$sev")
  R_CAT+=("$cat")
  R_MSG+=("$msg")
  R_KV+=("$kv")
}

# report_metric <key> <value>
report_metric() {
  M_KEY+=("$1")
  M_VAL+=("$2")
}

# Threat score: weighted sum of findings, capped at 100.
threat_score() {
  local total=0 i
  if [ "${#R_SEV[@]}" -gt 0 ]; then
    for i in "${!R_SEV[@]}"; do
      total=$((total + $(sev_weight "${R_SEV[$i]}")))
    done
  fi
  if [ "$total" -gt 100 ]; then total=100; fi
  echo "$total"
}

threat_level() {
  local score=$1
  if [ "$score" -ge 50 ]; then
    echo critical
  elif [ "$score" -ge 25 ]; then
    echo high
  elif [ "$score" -ge 10 ]; then
    echo medium
  elif [ "$score" -ge 1 ]; then
    echo low
  else
    echo none
  fi
}

# Highest finding severity rank present (or -1 when there are no findings).
max_finding_rank() {
  local max=-1 r i
  if [ "${#R_SEV[@]}" -gt 0 ]; then
    for i in "${!R_SEV[@]}"; do
      r=$(sev_rank "${R_SEV[$i]}")
      if [ "$r" -gt "$max" ]; then max=$r; fi
    done
  fi
  echo "$max"
}
