# shellcheck shell=bash
# ******************************************************************************
# *Title: Awk Time Library*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Portable timestamp parsing shipped as an awk function library.*
# ******************************************************************************

# Analyzers run inside awk, so this ships awk functions (POSIX awk compatible,
# no gawk strftime/mktime) via the AWK_TIME_LIB variable:
#   awk "$AWK_TIME_LIB"'{ your program }'
# ISO timestamps with explicit offsets are converted to UTC. Classic syslog
# timestamps have no year or offset, so their wall clock is used as-is.

# *--- Library Definition ---*

# shellcheck disable=SC2034  # consumed by format analyzers
AWK_TIME_LIB='
# days since 1970-01-01 for a civil date (Howard Hinnant algorithm, y >= 1970)
function bl_days_from_civil(y, m, d,    era, yoe, doy, doe) {
  if (m <= 2) y -= 1
  era = int(y / 400)
  yoe = y - era * 400
  doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  return era * 146097 + doe - 719468
}

# "Jan" -> 1 ... "Dec" -> 12; 0 when not a month
function bl_month_num(name,    idx) {
  if (length(name) != 3) return 0
  idx = index("JanFebMarAprMayJunJulAugSepOctNovDec", name)
  if (idx == 0 || (idx - 1) % 3 != 0) return 0
  return int((idx + 2) / 3)
}

function bl_valid_date(y, m, d,    days) {
  if (y < 1970 || m < 1 || m > 12 || d < 1) return 0
  if (m == 2) days = 28 + (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))
  else days = m == 4 || m == 6 || m == 9 || m == 11 ? 30 : 31
  return d <= days
}

function bl_hms_seconds(s,    h, m, sec) {
  if (s !~ /^[0-9]{2}:[0-9]{2}:[0-9]{2}$/) return -1
  h = substr(s, 1, 2) + 0
  m = substr(s, 4, 2) + 0
  sec = substr(s, 7, 2) + 0
  return h <= 23 && m <= 59 && sec <= 59 ? 3600 * h + 60 * m + sec : -1
}

function bl_syslog_epoch(mon, day, hms, year,    m, seconds) {
  m = bl_month_num(mon)
  seconds = bl_hms_seconds(hms)
  if (day !~ /^[0-9]{1,2}$/ || !bl_valid_date(year, m, day + 0) || seconds < 0) return -1
  return bl_days_from_civil(year, m, day + 0) * 86400 + seconds
}

function bl_iso_epoch(s,    y, m, d, seconds, suffix, frac, z, h, min, sign) {
  if (s !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}/) return -1
  y = substr(s, 1, 4) + 0
  m = substr(s, 6, 2) + 0
  d = substr(s, 9, 2) + 0
  seconds = bl_hms_seconds(substr(s, 12, 8))
  if (!bl_valid_date(y, m, d) || seconds < 0) return -1
  suffix = substr(s, 20)
  if (match(suffix, /^\.[0-9]+/)) {
    frac = substr(suffix, 1, RLENGTH) + 0
    suffix = substr(suffix, RLENGTH + 1)
  }
  if (suffix != "" && suffix != "Z") {
    if (suffix !~ /^[+-][0-9]{2}:?[0-9]{2}$/) return -1
    sign = substr(suffix, 1, 1) == "+" ? 1 : -1
    z = substr(suffix, 2)
    sub(/:/, "", z)
    h = substr(z, 1, 2) + 0
    min = substr(z, 3, 2) + 0
    if (h > 23 || min > 59) return -1
    seconds -= sign * (3600 * h + 60 * min)
  }
  return bl_days_from_civil(y, m, d) * 86400 + seconds + frac
}

'

# *--- Bash Helper ---*

# bl_epoch_of "<iso timestamp>": bash-side helper, mainly for tests.
bl_epoch_of() {
  printf '%s\n' "$1" | LC_ALL=C awk "$AWK_TIME_LIB"'{ printf "%.15g\n", bl_iso_epoch($0) }'
}
