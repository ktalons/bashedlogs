# shellcheck shell=bash
# ******************************************************************************
# *Title: Format Detection*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Format registry and the confidence-scored detection engine.*
# ******************************************************************************

# Each lib/formats/<fmt>.sh calls register_format on source and defines
#   <fmt>_detect   -> prints confidence 0-100, reads the SAMPLE global
#   <fmt>_analyze  -> takes the log file path, emits report_add/report_metric

# *--- Registry State ---*

FORMATS=()
declare -A FORMAT_DESC

DETECT_THRESHOLD=50
SAMPLE=""

# *--- Registry ---*

register_format() {
  FORMATS+=("$1")
  FORMAT_DESC["$1"]=$2
}

# *--- Detection ---*

# NOTE: The sample is loaded once into a variable so detectors never run inside
# a `while read` subshell. That is what makes the v1 return-in-subshell bug
# structurally impossible rather than merely fixed.
# load_sample <file>: up to 200 lines and 256 KiB into SAMPLE. Drop a partial
# last line when the byte cap cuts through a record.
load_sample() {
  local prefix
  prefix=$(head -c 262145 -- "$1" 2>/dev/null | tr '\000' ' ' && printf '.') || return 1
  prefix=${prefix%.}
  if [ "${#prefix}" -gt 262144 ]; then
    prefix=${prefix:0:262144}
    if [[ $prefix == *$'\n'* ]]; then
      prefix=${prefix%$'\n'*}
    else
      prefix=""
    fi
  fi
  # shellcheck disable=SC2034  # SAMPLE is read by the per-format detectors
  SAMPLE=$(printf '%s' "$prefix" | awk 'NR <= 200')
}

# Returns 1 with a generic fallback, 2 on input failure, or 3 on a detector error.
detect_format() {
  local file=$1 best="" best_conf=0 fmt conf
  load_sample "$file" || return 2
  for fmt in "${FORMATS[@]}"; do
    if [ "$fmt" = "generic" ]; then continue; fi
    conf=$("${fmt}_detect" 2>/dev/null) || return 3
    case "$conf" in
      ''|*[!0-9]*) return 3 ;;
    esac
    if [ "$conf" -gt "$best_conf" ]; then
      best_conf=$conf
      best=$fmt
    fi
  done
  if [ "$best_conf" -ge "$DETECT_THRESHOLD" ]; then
    echo "$best"
    return 0
  fi
  echo "generic"
  return 1
}

# *--- Queries ---*

format_registered() {
  local fmt
  for fmt in "${FORMATS[@]}"; do
    if [ "$fmt" = "$1" ]; then return 0; fi
  done
  return 1
}

list_formats() {
  local fmt
  echo "Supported formats:"
  for fmt in "${FORMATS[@]}"; do
    printf '  %-14s %s\n' "$fmt" "${FORMAT_DESC[$fmt]}"
  done
}
