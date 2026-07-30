# shellcheck shell=bash
# time.sh - portable timestamp parsing as an awk function library
#
# Analyzers run inside awk, so this ships awk functions (POSIX awk compatible,
# no gawk strftime/mktime) via the AWK_TIME_LIB variable:
#   awk "$AWK_TIME_LIB"'{ your program }'
# Epochs are naive (no timezone math): windows and deltas only ever compare
# timestamps from the same log, where a consistent offset cancels out.

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

function bl_civil_to_epoch(y, mo, d, h, mi, s) {
  return bl_days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s
}

# "Jan" -> 1 ... "Dec" -> 12; 0 when not a month
function bl_month_num(name,    idx) {
  idx = index("JanFebMarAprMayJunJulAugSepOctNovDec", name)
  if (idx == 0 || (idx - 1) % 3 != 0) return 0
  return int((idx + 2) / 3)
}

# syslog "Mon DD HH:MM:SS" prefix (fields f1=month f2=day f3=time) with an
# assumed year; year-rollover inside one file is handled by the caller
# noticing a large backwards jump.
function bl_syslog_epoch(mon, day, hms, year,    m, t) {
  m = bl_month_num(mon)
  if (m == 0) return -1
  split(hms, t, ":")
  return bl_civil_to_epoch(year, m, day + 0, t[1] + 0, t[2] + 0, t[3] + 0)
}

# ISO-ish "YYYY-MM-DDTHH:MM:SS..." or "YYYY-MM-DD HH:MM:SS..." prefix.
# Fractions and timezone suffixes are ignored (naive epoch).
function bl_iso_epoch(s,    dpart, tpart, dt, d, t) {
  gsub(/T/, " ", s)
  split(s, dt, " ")
  dpart = dt[1]; tpart = dt[2]
  if (split(dpart, d, "-") != 3) return -1
  split(tpart, t, ":")
  return bl_civil_to_epoch(d[1] + 0, d[2] + 0, d[3] + 0, t[1] + 0, t[2] + 0, int(t[3] + 0))
}
'

# bl_epoch_of "<iso timestamp>": bash-side helper, mainly for tests.
bl_epoch_of() {
  awk "$AWK_TIME_LIB"'BEGIN { print bl_iso_epoch(ARGV[1]) }' "$1"
}
