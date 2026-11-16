# shellcheck shell=bash
# shellcheck disable=SC2034  # config globals here are consumed by other lib/ modules
# ******************************************************************************
# *Title: Command-Line Interface*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Handles argument parsing, the entry point, and exit codes.*
# ******************************************************************************

# Exit codes:
#   0  analysis ran; no findings at/above --fail-level (or no --fail-level)
#   1  usage or runtime error
#   2  input missing/unreadable, or detection fell back to generic under --strict
#   3  findings at or above --fail-level

# *--- Configuration ---*

LOGFILE=""
OUTPUT_MODE="pretty"
COLOR_MODE="auto"
FORMAT_OVERRIDE=""
STRICT=0
FAIL_LEVEL=""
BF_THRESHOLD=10
BF_WINDOW=60
SSH_NAMED_ONLY=0
DO_IOCS=0
DEFANG=0
ENRICH_ONLINE=0
MMDB_DIR="${BASHEDLOGS_MMDB_DIR:-}"
CLEANUP_FILE=""

# *--- Usage and Errors ---*

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
      --ssh-named-only  count SSH events from recognized SSH producers only
      --iocs            extract IOCs (IPs, domains, URLs, hashes)
      --defang          defang IOC output (203[.]0[.]113[.]66, hxxp://)
      --mmdb-dir DIR    GeoLite2 .mmdb directory for offline GeoIP/ASN
                        enrichment of IOC IPs (BASHEDLOGS_MMDB_DIR env works too)
      --enrich-online   allow online ASN (Team Cymru) and PTR lookups for IOC
                        IPs; without this flag no network call is ever made
      --no-color        disable colors (NO_COLOR env is also honored)
      --version         print version and exit
  -h, --help            show this help
      --                end options before an input filename beginning with -

Exit codes: 0 ok, 1 error, 2 unreadable input or strict-detection failure,
3 findings at/above --fail-level.
EOF
}

# SECURITY: stderr goes to the same terminal as the report, and a usage
# message can quote an argument, which may be a hostile file name. Each
# message is shown through pretty_safe, as report values are.
die_usage() {
  pretty_safe "$1" 2>/dev/null
  printf 'bashedlogs: %s\n' "$PRETTY_SAFE" >&2
  echo "Try 'bashedlogs --help'." >&2
  exit 1
}

require_arg() {
  if [ "$2" -lt 2 ]; then die_usage "$1 needs a value"; fi
}

positive_integer() {
  local value=$2
  case $value in
    ''|*[!0-9]*) die_usage "$1 needs a positive integer" ;;
  esac
  value=${value#"${value%%[!0]*}"}
  # Stay in the portable signed-int range used by awk printf.
  if [[ -z $value || ${#value} -gt 10 ]] || (( value > 2147483647 )); then
    die_usage "$1 needs an integer from 1 to 2147483647"
  fi
  printf '%s\n' "$value"
}

# *--- Argument Parsing ---*

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
        if ! format_registered "$2"; then
          die_usage "unknown format '$2' (see --list-formats)"
        fi
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
        BF_THRESHOLD=$(positive_integer "$1" "$2")
        shift 2 ;;
      --bf-window)
        require_arg "$1" "$#"
        BF_WINDOW=$(positive_integer "$1" "$2")
        shift 2 ;;
      --ssh-named-only) SSH_NAMED_ONLY=1; shift ;;
      --iocs) DO_IOCS=1; shift ;;
      --defang) DEFANG=1; shift ;;
      --enrich-online) ENRICH_ONLINE=1; shift ;;
      --mmdb-dir)
        require_arg "$1" "$#"
        MMDB_DIR=$2
        shift 2 ;;
      --no-color) COLOR_MODE="off"; shift ;;
      --version)
        echo "bashedlogs $BASHEDLOGS_VERSION"
        exit 0 ;;
      -h|--help)
        usage
        exit 0 ;;
      --)
        shift
        if [ "$#" -ne 1 ] || [ -n "$LOGFILE" ]; then
          die_usage "-- must precede a single input"
        fi
        LOGFILE=$1
        break ;;
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

# *--- Input Handling ---*

cleanup_tmp() {
  if [ -n "$CLEANUP_FILE" ]; then rm -f -- "$CLEANUP_FILE"; fi
}

# prepare_input: analyzers make multiple passes, so stdin is slurped to a
# temp file. Exits 2 when the input is missing or unreadable.
prepare_input() {
  if [ "$LOGFILE" = "-" ]; then
    if ! CLEANUP_FILE=$(mktemp "${TMPDIR:-/tmp}/bashedlogs.XXXXXX" 2>/dev/null); then
      printf 'bashedlogs: could not create temporary input file\n' >&2
      exit 1
    fi
    trap cleanup_tmp EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if ! { cat > "$CLEANUP_FILE"; } 2>/dev/null; then
      printf 'bashedlogs: could not spool stdin\n' >&2
      exit 1
    fi
    LOGFILE=$CLEANUP_FILE
    DISPLAY_FILE="(stdin)"
  else
    DISPLAY_FILE=$LOGFILE
  fi
  if [ ! -f "$LOGFILE" ] || [ ! -r "$LOGFILE" ]; then
    pretty_safe "$DISPLAY_FILE" 2>/dev/null
    printf "bashedlogs: cannot read '%s'\n" "$PRETTY_SAFE" >&2
    exit 2
  fi
}

# SECURITY: awk treats a relative operand such as FS=, as an assignment.
# Open the input with shell redirection and sanitize failures before printing.
awk_log() {
  local file=$1
  shift
  if ! { awk "$@" < "$file"; } 2>/dev/null; then
    pretty_safe "$DISPLAY_FILE" 2>/dev/null
    printf "bashedlogs: analysis failed while reading '%s'\n" "$PRETTY_SAFE" >&2
    return 1
  fi
}

# *--- Entry Point ---*

main() {
  parse_args ${1+"$@"}
  init_colors
  prepare_input

  local fmt detect_status=0
  if [ -n "$FORMAT_OVERRIDE" ]; then
    fmt=$FORMAT_OVERRIDE
  else
    fmt=$(detect_format "$LOGFILE") || detect_status=$?
    if [ "$detect_status" -eq 2 ]; then
      pretty_safe "$DISPLAY_FILE" 2>/dev/null
      printf "bashedlogs: cannot sample '%s'\n" "$PRETTY_SAFE" >&2
      exit 2
    fi
    if [ "$detect_status" -eq 3 ]; then
      printf 'bashedlogs: format detector failed\n' >&2
      exit 1
    fi
    if [ "$detect_status" -eq 1 ] && [ "$STRICT" -eq 1 ]; then
      pretty_safe "$DISPLAY_FILE" 2>/dev/null
      printf "bashedlogs: could not confidently detect the format of '%s' (--strict)\n" "$PRETTY_SAFE" >&2
      exit 2
    fi
  fi

  "${fmt}_analyze" "$LOGFILE"
  if [ "$DO_IOCS" -eq 1 ]; then
    extract_iocs "$LOGFILE"
    enrich_iocs
  fi
  emit_output "$DISPLAY_FILE" "$fmt"

  if [ -n "$FAIL_LEVEL" ]; then
    local SEV_RANK
    severity_values "$FAIL_LEVEL"
    if [ "$R_MAX_RANK" -ge "$SEV_RANK" ]; then exit 3; fi
  fi
  exit 0
}
