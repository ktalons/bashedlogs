# shellcheck shell=bash
# shellcheck disable=SC2034  # config globals here are consumed by other lib/ modules
# cli.sh - argument parsing, main entry, exit-code contract
#
# Exit codes:
#   0  analysis ran; no findings at/above --fail-level (or no --fail-level)
#   1  usage or runtime error
#   2  input missing/unreadable, or detection fell back to generic under --strict
#   3  findings at or above --fail-level

LOGFILE=""
OUTPUT_MODE="pretty"
COLOR_MODE="auto"
FORMAT_OVERRIDE=""
STRICT=0
FAIL_LEVEL=""
BF_THRESHOLD=10
BF_WINDOW=60
CLEANUP_FILE=""

usage() {
  cat <<'EOF'
bashedlogs - fast security log triage

Usage:
  bashedlogs [options] <logfile>
  cat file.log | bashedlogs [options] -

Options:
  -o, --output MODE     pretty (default), json, or ndjson
      --format FMT      skip detection, analyze as FMT (see --list-formats)
      --list-formats    list registered formats and exit
      --strict          exit 2 instead of falling back to the generic analyzer
      --fail-level LVL  exit 3 when findings reach LVL (low|medium|high|critical)
      --bf-threshold N  brute-force window: alert at N failures (default 10)
      --bf-window SEC   brute-force sliding window in seconds (default 60)
      --no-color        disable colors (NO_COLOR env is also honored)
      --version         print version and exit
  -h, --help            show this help

Exit codes: 0 ok, 1 error, 2 unreadable input or strict-detection failure,
3 findings at/above --fail-level.
EOF
}

die_usage() {
  echo "bashedlogs: $1" >&2
  echo "Try 'bashedlogs --help'." >&2
  exit 1
}

require_arg() {
  if [ "$2" -lt 2 ]; then die_usage "$1 needs a value"; fi
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -o|--output)
        require_arg "$1" "$#"
        case "$2" in
          pretty|json|ndjson) OUTPUT_MODE=$2 ;;
          *) die_usage "unknown output mode '$2' (pretty|json|ndjson)" ;;
        esac
        shift 2 ;;
      --format)
        require_arg "$1" "$#"
        FORMAT_OVERRIDE=$2
        shift 2 ;;
      --list-formats)
        list_formats
        exit 0 ;;
      --strict) STRICT=1; shift ;;
      --fail-level)
        require_arg "$1" "$#"
        case "$2" in
          low|medium|high|critical) FAIL_LEVEL=$2 ;;
          *) die_usage "bad --fail-level '$2' (low|medium|high|critical)" ;;
        esac
        shift 2 ;;
      --bf-threshold)
        require_arg "$1" "$#"
        case "$2" in
          ''|0|*[!0-9]*) die_usage "--bf-threshold needs a positive integer" ;;
          *) BF_THRESHOLD=$2 ;;
        esac
        shift 2 ;;
      --bf-window)
        require_arg "$1" "$#"
        case "$2" in
          ''|0|*[!0-9]*) die_usage "--bf-window needs a positive integer" ;;
          *) BF_WINDOW=$2 ;;
        esac
        shift 2 ;;
      --no-color) COLOR_MODE="off"; shift ;;
      --version)
        echo "bashedlogs $BASHEDLOGS_VERSION"
        exit 0 ;;
      -h|--help)
        usage
        exit 0 ;;
      -)
        if [ -n "$LOGFILE" ]; then die_usage "more than one input given"; fi
        LOGFILE="-"
        shift ;;
      -*)
        die_usage "unknown option '$1'" ;;
      *)
        if [ -n "$LOGFILE" ]; then die_usage "more than one input given"; fi
        LOGFILE=$1
        shift ;;
    esac
  done
  if [ -z "$LOGFILE" ]; then
    usage >&2
    exit 1
  fi
}

cleanup_tmp() {
  if [ -n "$CLEANUP_FILE" ]; then rm -f -- "$CLEANUP_FILE"; fi
}

# prepare_input: analyzers make multiple passes, so stdin is slurped to a
# temp file. Exits 2 when the input is missing or unreadable.
prepare_input() {
  if [ "$LOGFILE" = "-" ]; then
    CLEANUP_FILE=$(mktemp "${TMPDIR:-/tmp}/bashedlogs.XXXXXX")
    trap cleanup_tmp EXIT
    cat > "$CLEANUP_FILE"
    LOGFILE=$CLEANUP_FILE
    DISPLAY_FILE="(stdin)"
  else
    DISPLAY_FILE=$LOGFILE
  fi
  if [ ! -f "$LOGFILE" ] || [ ! -r "$LOGFILE" ]; then
    echo "bashedlogs: cannot read '$DISPLAY_FILE'" >&2
    exit 2
  fi
}

main() {
  parse_args "$@"
  init_colors
  prepare_input

  local fmt detected_ok=0
  if [ -n "$FORMAT_OVERRIDE" ]; then
    if ! format_registered "$FORMAT_OVERRIDE"; then
      die_usage "unknown format '$FORMAT_OVERRIDE' (see --list-formats)"
    fi
    fmt=$FORMAT_OVERRIDE
  else
    if fmt=$(detect_format "$LOGFILE"); then detected_ok=1; fi
    if [ "$detected_ok" -eq 0 ] && [ "$STRICT" -eq 1 ]; then
      echo "bashedlogs: could not confidently detect the format of '$DISPLAY_FILE' (--strict)" >&2
      exit 2
    fi
  fi

  "${fmt}_analyze" "$LOGFILE"
  emit_output "$DISPLAY_FILE" "$fmt"

  if [ -n "$FAIL_LEVEL" ]; then
    local want have
    want=$(sev_rank "$FAIL_LEVEL")
    have=$(max_finding_rank)
    if [ "$have" -ge "$want" ]; then
      exit 3
    fi
  fi
  exit 0
}
