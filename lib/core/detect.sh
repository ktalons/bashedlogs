# shellcheck shell=bash
# detect.sh - format registry and detection engine
# Each lib/formats/<fmt>.sh calls register_format on source and defines
#   <fmt>_detect   -> prints confidence 0-100, reads the SAMPLE global
#   <fmt>_analyze  -> takes the log file path, emits report_add/report_metric
# Detection loads the sample ONCE into a variable, so detectors never pipe
# `while read` subshells (the v1 return-in-subshell bug is structurally gone).

FORMATS=()
declare -A FORMAT_DESC

DETECT_THRESHOLD=50
SAMPLE=""

register_format() {
  FORMATS+=("$1")
  FORMAT_DESC["$1"]=$2
}

# load_sample <file>: first 200 lines into SAMPLE.
load_sample() {
  # shellcheck disable=SC2034  # SAMPLE is read by the per-format detectors
  SAMPLE=$(head -n 200 -- "$1" 2>/dev/null || true)
}

# detect_format <file>: prints best format id, or "generic" when nothing
# clears DETECT_THRESHOLD. Returns 1 in that fallback case so --strict can
# distinguish a real detection from the fallback.
detect_format() {
  local file=$1 best="" best_conf=0 fmt conf
  load_sample "$file"
  for fmt in "${FORMATS[@]}"; do
    if [ "$fmt" = "generic" ]; then continue; fi
    conf=$("${fmt}_detect" 2>/dev/null) || conf=0
    case "$conf" in
      ''|*[!0-9]*) conf=0 ;;
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
