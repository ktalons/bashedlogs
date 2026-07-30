# shellcheck shell=bash
# awklib.sh - shared awk helper functions, injected into analyzer programs.
#
# Usage:  awk "$AWK_IP_LIB"'{ ... bl_valid_ip($1) ... }' file
#
# One definition of "is this an address" for every analyzer. Before this
# existed each format carried its own IPv4-only copy, so an IPv6 brute force
# was counted in the totals but never made it into any per-source detector -
# the tool reported failures and no finding, which is worse than reporting
# nothing at all.

# shellcheck disable=SC2034  # consumed by lib/formats/*.sh
AWK_IP_LIB='
function bl_valid_ip4(tok,    parts, j) {
  if (tok !~ /^([0-9]+\.){3}[0-9]+$/) return 0
  split(tok, parts, ".")
  for (j = 1; j <= 4; j++) {
    if (length(parts[j]) > 3 || parts[j] + 0 > 255) return 0
  }
  return 1
}

# Accepts full, compressed (::), and IPv4-mapped IPv6. Rejects tokens with a
# zone id or prefix length, which callers should strip first.
function bl_valid_ip6(tok,    halves, nh, groups, n, i, g, tail, ntail, has4) {
  if (tok !~ /:/) return 0
  if (tok ~ /[^0-9A-Fa-f:.]/) return 0
  if (tok ~ /:::/) return 0

  has4 = 0
  if (tok ~ /\./) {
    # only the last group may be dotted-quad, and it must be a valid IPv4
    ntail = split(tok, tail, ":")
    if (!bl_valid_ip4(tail[ntail])) return 0
    has4 = 1
  }

  nh = split(tok, halves, "::")
  if (nh > 2) return 0

  if (nh == 2) {
    # compressed form: total groups must be under the 8-group budget
    n = bl_count_groups(halves[1]) + bl_count_groups(halves[2]) + (has4 ? 1 : 0)
    if (n > 7) return 0
    return bl_groups_ok(halves[1]) && bl_groups_ok(halves[2])
  }

  # uncompressed: exactly 8 groups (a trailing IPv4 counts as two)
  n = split(tok, groups, ":")
  if (n != (has4 ? 7 : 8)) return 0
  return bl_groups_ok(tok)
}

function bl_count_groups(part,    g, n, i, c) {
  if (part == "") return 0
  n = split(part, g, ":")
  c = 0
  for (i = 1; i <= n; i++) if (g[i] != "") c++
  return c
}

function bl_groups_ok(part,    g, n, i) {
  if (part == "") return 1
  n = split(part, g, ":")
  for (i = 1; i <= n; i++) {
    if (g[i] == "") continue
    if (g[i] ~ /\./) continue        # trailing IPv4 already validated
    if (g[i] !~ /^[0-9A-Fa-f]{1,4}$/) return 0
  }
  return 1
}

function bl_valid_ip(tok) {
  return bl_valid_ip4(tok) || bl_valid_ip6(tok)
}

# Analyzers hand results back to bash as tab-separated rows, so any free-text
# value taken from a log (a URL, a username, a rule description) must have its
# own tabs and newlines folded first or it splits the row and gets truncated.
function bl_tsv(s,    t) {
  t = s
  gsub(/[\t\r\n]/, " ", t)
  return t
}

# Normalize a token that may carry a port, brackets, a zone id, or a prefix.
function bl_clean_ip(tok,    t) {
  t = tok
  gsub(/^\[|\]$/, "", t)
  sub(/%[A-Za-z0-9._-]+$/, "", t)   # zone id
  sub(/\/[0-9]+$/, "", t)           # prefix length
  return t
}
'
