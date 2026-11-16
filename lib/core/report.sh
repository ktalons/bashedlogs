# shellcheck shell=bash
# ******************************************************************************
# *Title: Report Accumulation*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Collects findings and metrics, then computes the threat score.*
# ******************************************************************************

# Sourced by bin/bashedlogs. Pure functions + module state; no side effects on load.

# *--- State ---*

# Findings: parallel arrays, one entry per finding.
R_SEV=()  # severity: info|low|medium|high|critical
R_CAT=()  # short category slug, e.g. brute-force
R_MSG=()  # human message
R_KV=()   # tab-separated key=value pairs (may be empty)
R_SCORE=0
R_MAX_RANK=-1

# Metrics: ordered key/value pairs for the stats section.
M_KEY=()
M_VAL=()

# *--- Severity Model ---*

# Set the rank used for exit status and weight used for scoring.
severity_values() {
  case "$1" in
    info) SEV_RANK=0; SEV_WEIGHT=0 ;;
    low) SEV_RANK=1; SEV_WEIGHT=1 ;;
    medium) SEV_RANK=2; SEV_WEIGHT=3 ;;
    high) SEV_RANK=3; SEV_WEIGHT=7 ;;
    critical) SEV_RANK=4; SEV_WEIGHT=15 ;;
    *) return 1 ;;
  esac
}

# *--- Accumulation ---*

# report_add <severity> <category> <message> [key=value ...]
#
# Pairs are stored tab-separated, so a literal tab arriving from log content
# (a URL or user agent can contain one) would split into a bogus extra pair.
# Tabs are folded to spaces at this single choke point instead.
report_add() {
  local sev=$1 cat=$2 msg=$3
  shift 3
  local SEV_RANK SEV_WEIGHT
  if ! severity_values "$sev"; then
    echo "bashedlogs: internal error: bad severity '$sev'" >&2
    exit 1
  fi
  R_SCORE=$((R_SCORE + SEV_WEIGHT))
  if [ "$R_SCORE" -gt 100 ]; then R_SCORE=100; fi
  if [ "$SEV_RANK" -gt "$R_MAX_RANK" ]; then R_MAX_RANK=$SEV_RANK; fi
  local kv="" pair
  # A finding with no pairs leaves "$@" empty, which bash 4.0 calls unbound.
  for pair in ${1+"$@"}; do
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

# *--- Threat Scoring ---*

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
