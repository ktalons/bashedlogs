# shellcheck shell=bash
# ******************************************************************************
# *Title: Awk Function Library*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Shared awk helper functions injected into analyzer programs.*
# ******************************************************************************

# Usage:  awk "$AWK_IP_LIB"'{ ... bl_valid_ip($1) ... }' file

# One definition of "is this an address" for every analyzer. Before this
# existed each format carried its own IPv4-only copy, so an IPv6 brute force
# was counted in the totals but never made it into any per-source detector -
# the tool reported failures and no finding, which is worse than reporting
# nothing at all.

# *--- Library Definition ---*

# shellcheck disable=SC2034  # consumed by lib/formats/*.sh
AWK_IP_LIB='
function bl_valid_ip4(tok,    parts, j) {
  if (tok !~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) return 0
  split(tok, parts, ".")
  for (j = 1; j <= 4; j++) {
    if (parts[j] ~ /^0[0-9]/ || parts[j] + 0 > 255) return 0
  }
  return 1
}

# Expand to eight hextets for validation, then compress the longest run of
# at least two zeroes (leftmost on ties). Treat a dotted IPv4 tail as two
# hextets, and use dotted form for IPv4-mapped addresses.
function bl_ip6(tok,    halves, g, octets, part, n, m, i, j, p, k, h, start, run, best, size, out, groups) {
  if (tok !~ /:/ || tok ~ /[^0-9A-Fa-f:.]/ || tok ~ /:::/) return ""
  if (tok ~ /\./) {
    if (!match(tok, /:[0-9.]+$/)) return ""
    part = substr(tok, RSTART + 1)
    if (!bl_valid_ip4(part)) return ""
    split(part, octets, ".")
    tok = substr(tok, 1, RSTART) sprintf("%x:%x", octets[1] * 256 + octets[2], octets[3] * 256 + octets[4])
  }
  n = split(tok, halves, "::")
  if (n > 2) return ""
  for (p = 1; p <= n; p++) {
    part = halves[p]
    if (part != "") {
      m = split(part, g, ":")
      for (i = 1; i <= m; i++) {
        if (g[i] !~ /^[0-9A-Fa-f]{1,4}$/) return ""
        h = tolower(g[i])
        sub(/^0+/, "", h)
        groups[++k] = h == "" ? "0" : h
      }
    }
    if (p == 1) j = k
  }
  if (n == 1 && k != 8 || n == 2 && k >= 8) return ""
  if (n == 2) {
    for (i = k; i > j; i--) groups[i + 8 - k] = groups[i]
    for (i = j + 1; i <= j + 8 - k; i++) groups[i] = "0"
  }

  for (i = 1; i <= 8; i++) {
    if (groups[i] == "0") {
      if (run == 0) start = i
      if (++run > size) { size = run; best = start }
    } else run = 0
  }
  if (best == 1 && size == 5 && groups[6] == "ffff") {
    i = j = 0
    for (p = 1; p <= length(groups[7]); p++) i = i * 16 + index("0123456789abcdef", substr(groups[7], p, 1)) - 1
    for (p = 1; p <= length(groups[8]); p++) j = j * 16 + index("0123456789abcdef", substr(groups[8], p, 1)) - 1
    return sprintf("::ffff:%d.%d.%d.%d", int(i / 256), i % 256, int(j / 256), j % 256)
  }
  for (i = 1; i <= 8; i++) {
    if (size >= 2 && i == best) {
      out = out "::"
      i += size - 1
    } else {
      if (out != "" && out !~ /:$/) out = out ":"
      out = out groups[i]
    }
  }
  return out
}

function bl_valid_ip6(tok) { return bl_ip6(tok) != "" }
function bl_valid_ip(tok) { return bl_valid_ip4(tok) || bl_valid_ip6(tok) }

# Analyzers hand results back to bash as tab-separated rows, so any free-text
# value taken from a log (a URL, a username, a rule description) must have its
# own tabs and newlines folded first or it splits the row and gets truncated.
function bl_tsv(s,    t) {
  t = s
  gsub(/[\t\r\n]/, " ", t)
  return t
}

# Clean common endpoint decorations. A bare IPv6 final group is never a port.
function bl_clean_ip(tok) {
  sub(/\/[0-9]+$/, "", tok)
  if (tok ~ /^\[[^]]+\](:[0-9]+)?$/) {
    sub(/^\[/, "", tok)
    sub(/\].*$/, "", tok)
  } else if (tok ~ /^[0-9.]+:[0-9]+$/) sub(/:[0-9]+$/, "", tok)
  sub(/%[A-Za-z0-9._-]+$/, "", tok)
  return tok
}

function bl_normal_ip(tok) {
  tok = bl_clean_ip(tok)
  return bl_valid_ip4(tok) ? tok : bl_ip6(tok)
}
'
